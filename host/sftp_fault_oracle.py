#!/usr/bin/env python3
"""Independent oracle for the Loop #41-M2 fault-injection scenarios.

Written from the SFTP v3 draft and the OpenSSH 8.0p1 server's error
branches, with no reference to `src/sftp`.  Its only job is to be a second
opinion on what the MoonBit console *should* print for each scenario, so a
scenario that passes because the console agrees with itself is caught here.

Every scenario is: an operation script, a list of inbound CHANNEL_DATA
payloads, and an expectation about the requests we emit, the results we
report, and whether the session ended done or failed.
"""

import json
import struct
import sys

# ---- protocol constants (draft-ietf-secsh-filexfer-01.txt) -----------------

FXP_INIT, FXP_REALPATH, FXP_STAT = 1, 16, 17
FXP_OPEN, FXP_CLOSE, FXP_WRITE = 3, 4, 6
FXP_RENAME, FXP_EXTENDED = 18, 200
FXP_STATUS, FXP_HANDLE, FXP_DATA = 101, 102, 103
FXP_NAME, FXP_ATTRS, FXP_VERSION = 104, 105, 2

FX_OK, FX_EOF, FX_NO_SUCH_FILE = 0, 1, 2
FX_FAILURE, FX_OP_UNSUPPORTED = 4, 8

FXF_READ, FXF_WRITE, FXF_CREAT, FXF_TRUNC = 1, 2, 8, 16

ATTR_SIZE, ATTR_PERMISSIONS = 0x1, 0x4

SFTP_MAX_MSG_LENGTH = 262144

EXT_POSIX_RENAME = "posix-rename@openssh.com"


# ---- wire helpers ----------------------------------------------------------


def u32(n):
    return struct.pack(">I", n & 0xFFFFFFFF)


def u64(n):
    return struct.pack(">Q", n & 0xFFFFFFFFFFFFFFFF)


def s(b):
    if isinstance(b, str):
        b = b.encode("latin-1")
    return u32(len(b)) + b


def frame(body):
    return u32(len(body)) + body


def attrs_none():
    return u32(0)


def attrs(size=None, permissions=None):
    flags = 0
    body = b""
    if size is not None:
        flags |= ATTR_SIZE
        body += u64(size)
    if permissions is not None:
        flags |= ATTR_PERMISSIONS
        body += u32(permissions)
    return u32(flags) + body


# ---- reply builders --------------------------------------------------------


def r_version(version=3, extensions=()):
    body = bytes([FXP_VERSION]) + u32(version)
    for name, value in extensions:
        body += s(name) + s(value)
    return frame(body)


def r_status(rid, code, msg=""):
    return frame(
        bytes([FXP_STATUS]) + u32(rid) + u32(code) + s(msg) + s("")
    )


def r_handle(rid, handle="h"):
    return frame(bytes([FXP_HANDLE]) + u32(rid) + s(handle))


def r_data(rid, payload):
    return frame(bytes([FXP_DATA]) + u32(rid) + s(payload))


def r_attrs(rid, size=None, permissions=None):
    return frame(
        bytes([FXP_ATTRS]) + u32(rid) + attrs(size=size, permissions=permissions)
    )


def r_name(rid, entries):
    body = bytes([FXP_NAME]) + u32(rid) + u32(len(entries))
    for fname, lname, a in entries:
        body += s(fname) + s(lname) + a
    return frame(body)


# ---- what the client must emit --------------------------------------------


def q_init():
    return frame(bytes([FXP_INIT]) + u32(3))


def q_realpath(rid, path):
    return frame(bytes([FXP_REALPATH]) + u32(rid) + s(path))


def q_stat(rid, path):
    return frame(bytes([FXP_STAT]) + u32(rid) + s(path))


def q_open(rid, path, pflags):
    return frame(bytes([FXP_OPEN]) + u32(rid) + s(path) + u32(pflags) + attrs_none())


def q_close(rid, handle):
    return frame(bytes([FXP_CLOSE]) + u32(rid) + s(handle))


def q_write(rid, handle, offset, data):
    return frame(
        bytes([FXP_WRITE]) + u32(rid) + s(handle) + u64(offset) + s(data)
    )


def q_rename(rid, old, new):
    return frame(bytes([FXP_RENAME]) + u32(rid) + s(old) + s(new))


def q_extended_posix_rename(rid, old, new):
    return frame(
        bytes([FXP_EXTENDED]) + u32(rid) + s(EXT_POSIX_RENAME) + s(old) + s(new)
    )


# ---- a reference session, mirroring `src/sftp` but written independently ----


class Reject(Exception):
    pass


class Cursor:
    """A strict reader: every read is bounds-checked and the packet must end
    exactly where the format says it does."""

    def __init__(self, body):
        self.b = body
        self.i = 0

    def remaining(self):
        return len(self.b) - self.i

    def u8(self):
        if self.remaining() < 1:
            raise Reject("Truncated")
        v = self.b[self.i]
        self.i += 1
        return v

    def u32(self):
        if self.remaining() < 4:
            raise Reject("Truncated")
        (v,) = struct.unpack(">I", self.b[self.i : self.i + 4])
        self.i += 4
        return v

    def string(self):
        n = self.u32()
        if self.remaining() < n:
            raise Reject("Truncated")
        v = self.b[self.i : self.i + n]
        self.i += n
        return v

    def attrs(self):
        flags = self.u32()
        out = {}
        if flags & ATTR_SIZE:
            out["size"] = self.u64()
        if flags & ATTR_UIDGID:
            self.u32()
            self.u32()
        if flags & ATTR_PERMISSIONS:
            out["permissions"] = self.u32()
        if flags & ATTR_ACMODTIME:
            self.u32()
            self.u32()
        return out

    def u64(self):
        if self.remaining() < 8:
            raise Reject("Truncated")
        (v,) = struct.unpack(">Q", self.b[self.i : self.i + 8])
        self.i += 8
        return v

    def expect_end(self):
        if self.remaining() != 0:
            raise Reject("TrailingData")


ATTR_UIDGID, ATTR_ACMODTIME = 0x2, 0x8


def parse_reply(body):
    """Returns (kind, id, payload).  Raises Reject with the reason name."""
    if len(body) < 1:
        raise Reject("Truncated")
    t = body[0]
    c = Cursor(body)
    c.u8()
    if t == FXP_VERSION:
        v = c.u32()
        names = []
        while c.remaining() > 0:
            names.append(c.string().decode("latin-1"))
            c.string()
        return ("version", -1, (v, names))
    if t == FXP_STATUS:
        rid = c.u32()
        code = c.u32()
        msg = c.string().decode("latin-1")
        c.string()
        c.expect_end()
        return ("status", rid, (code, msg))
    if t == FXP_HANDLE:
        rid = c.u32()
        h = c.string()
        c.expect_end()
        return ("handle", rid, h)
    if t == FXP_DATA:
        rid = c.u32()
        d = c.string()
        c.expect_end()
        return ("data", rid, d)
    if t == FXP_ATTRS:
        rid = c.u32()
        a = c.attrs()
        c.expect_end()
        return ("attrs", rid, a)
    if t == FXP_NAME:
        rid = c.u32()
        count = c.u32()
        if count < 0 or count > 0x100000:
            raise Reject("Unexpected")
        names = []
        for _ in range(count):
            fname = c.string().decode("latin-1")
            c.string()
            c.attrs()
            names.append(fname)
        c.expect_end()
        return ("name", rid, names)
    raise Reject("UnknownType")


class RefSession:
    """A deliberately small SFTP client used only to predict the transcript.

    It follows the same rules the MoonBit state machine does -- strict parse
    first, then attribution by step *and* request id, offset accumulation,
    EXTENDED-vs-RENAME selection by extension *name* -- because those rules
    are the subject of the scenarios.  What is being checked is the *bytes*,
    not the architecture.
    """

    def __init__(self, ops):
        self.ops = list(ops)
        self.version = None
        self.ext_names = []
        self.out = []
        self.results = []
        self.i = 0
        self.next_id = 1
        self.step = None  # (name, id)
        self.handle = None
        self.offset = 0
        self.chunks = []
        self.pending_write = b""
        self.written = 0
        self.failed = None
        self.phase = "version"
        self._buf = b""
        self.out.append(q_init())

    def take_out(self):
        out = self.out
        self.out = []
        return out

    def feed(self, chunk):
        buf = self._buf + chunk
        while len(buf) >= 4:
            (n,) = struct.unpack(">I", buf[:4])
            if n > SFTP_MAX_MSG_LENGTH:
                # Refused before anything is sized from the field. The name is
                # `Unexpected(n)` and not `BadLength`: in this protocol
                # `BadLength` is the cursor's "a length pointed past the end
                # of the buffer", which is a different failure with a
                # different cause.
                self.failed = "framing: Unexpected"
                self.phase = "failed"
                self._buf = buf
                return
            if len(buf) < 4 + n:
                break
            body = buf[4 : 4 + n]
            buf = buf[4 + n :]
            try:
                self._on_packet(body)
            except Reject as e:
                # We no longer know where in the exchange we are.
                self.failed = "unparsable reply: " + str(e)
                self.phase = "failed"
                self._buf = buf
                return
            if self.phase == "failed":
                self._buf = buf
                return
        self._buf = buf

    def _unexpected(self, kind):
        self.results.append(("failed", -1, "unexpected " + kind))
        self._send_close()

    def _on_packet(self, body):
        kind, rid, payload = parse_reply(body)
        if kind == "version":
            self.version, self.ext_names = payload
            self.phase = "running"
            self._begin()
            return
        # Anything before VERSION is ignored (sftp-client.c:474-484).
        if self.phase == "version":
            return
        step = self.step
        name, want = step
        if rid != want:
            # A reply to a request we abandoned is harmless; killing the
            # session over it would turn a benign race into an outage.
            return
        if name == "realpath":
            if kind == "name":
                if not payload:
                    self.results.append(("failed", -1, "realpath returned no name"))
                else:
                    self.results.append(("realpath", payload[0]))
            elif kind == "status":
                self.results.append(("failed", payload[0], payload[1]))
            else:
                self.results.append(("failed", -1, "unexpected " + kind.capitalize()))
            self._next()
        elif name == "stat":
            if kind == "attrs":
                self.results.append(("attrs",))
            elif kind == "status":
                self.results.append(("failed", payload[0], payload[1]))
            else:
                self.results.append(("failed", -1, "unexpected " + kind.capitalize()))
            self._next()
        elif name == "open_write":
            if kind == "handle":
                self.handle = "h"
                self.written = 0
                self._send_write()
            elif kind == "status":
                self.results.append(("failed", payload[0], payload[1]))
                self._next()
            else:
                self.results.append(("failed", -1, "unexpected " + kind.capitalize()))
                self._next()
        elif name == "write":
            if kind == "status":
                if payload[0] == FX_OK:
                    self._send_write()
                else:
                    self.results.append(("failed", payload[0], payload[1]))
                    self._send_close()
            else:
                self._unexpected(kind.capitalize())
        elif name == "close":
            self._next()
        elif name == "simple":
            if kind == "status":
                if payload[0] == FX_OK:
                    self.results.append(("changed",))
                else:
                    self.results.append(("failed", payload[0], payload[1]))
            else:
                # An EXTENDED reply answers with its own message type; none of
                # the extensions used here define a payload, so anything else
                # genuinely proved nothing.
                self.results.append(("failed", -1, "unexpected " + kind.capitalize()))
            self._next()

    def _next(self):
        self.i += 1
        self._begin()

    def _begin(self):
        if self.i >= len(self.ops):
            self.phase = "done"
            return
        op = self.ops[self.i]
        kind = op[0]
        rid = self.next_id
        self.next_id += 1
        if kind == "realpath":
            self.step = ("realpath", rid)
            self.out.append(q_realpath(rid, op[1]))
        elif kind == "stat":
            self.step = ("stat", rid)
            self.out.append(q_stat(rid, op[1]))
        elif kind == "writefile":
            self.step = ("open_write", rid)
            self.pending_write = op[2]
            self.out.append(q_open(rid, op[1], FXF_WRITE | FXF_CREAT | FXF_TRUNC))
        elif kind == "rename":
            self.step = ("simple", rid)
            if EXT_POSIX_RENAME in self.ext_names:
                self.out.append(q_extended_posix_rename(rid, op[1], op[2]))
            else:
                self.out.append(q_rename(rid, op[1], op[2]))

    def _send_read(self):
        rid = self.next_id
        self.next_id += 1
        self.step = ("read", rid)
        self.out.append(
            frame(
                bytes([5])
                + u32(rid)
                + s(self.handle)
                + u64(self.offset)
                + u32(32768)
            )
        )

    def _send_readdir(self):
        rid = self.next_id
        self.next_id += 1
        self.step = ("readdir", rid)
        self.out.append(frame(bytes([12]) + u32(rid) + s(self.handle)))

    def _send_close(self):
        rid = self.next_id
        self.next_id += 1
        self.step = ("close", rid)
        self.out.append(q_close(rid, self.handle))

    def _send_write(self):
        if self.written >= len(self.pending_write):
            self.results.append(("wrote", self.written))
            self.pending_write = b""
            self._send_close()
            return
        rid = self.next_id
        self.next_id += 1
        self.step = ("write", rid)
        chunk = self.pending_write[self.written : self.written + 32768]
        self.out.append(
            q_write(rid, self.handle, self.written, chunk)
        )
        self.written += len(chunk)


# ---- scenarios -------------------------------------------------------------


def hexs(bs):
    return [b.hex() for b in bs]


SCENARIOS = [
    {
        "name": "status_before_version",
        "intent": "A STATUS arriving before VERSION must be ignored, not fatal.",
        "ops": [("realpath", ".")],
        "feeds": [
            r_status(1, FX_NO_SUCH_FILE, "too early"),
            r_version(),
            r_name(1, [("/C:/Users/hp", "", attrs_none())]),
        ],
        "requests": [q_init(), q_realpath(1, ".")],
        "results": [("realpath", "/C:/Users/hp")],
        "done": True,
        "failed": False,
    },
    {
        "name": "wrong_request_id",
        "intent": "A reply to an abandoned request is dropped, and the session "
                  "stays usable.",
        "ops": [("realpath", ".")],
        "feeds": [
            r_version(),
            r_status(99, FX_FAILURE, "not mine"),
            r_name(1, [("/", "", attrs_none())]),
        ],
        "requests": [q_init(), q_realpath(1, ".")],
        "results": [("realpath", "/")],
        "done": True,
        "failed": False,
    },
    {
        "name": "malformed_write_reply",
        "intent": "DATA where a WRITE expects a STATUS: reported as unexpected, "
                  "and the handle is still closed.",
        "ops": [("writefile", "f.txt", b"\xca\xfe")],
        "feeds": [
            r_version(),
            r_handle(1),
            r_data(2, b"\xaa\xbb"),
            r_status(3, FX_OK),
        ],
        "requests": [
            q_init(),
            q_open(1, "f.txt", FXF_WRITE | FXF_CREAT | FXF_TRUNC),
            q_write(2, "h", 0, b"\xca\xfe"),
            q_close(3, "h"),
        ],
        "results": [("failed", -1, "unexpected Data")],
        "done": True,
        "failed": False,
    },
    {
        "name": "write_eof_status",
        "intent": "EOF as the answer to a WRITE is a failure, never a success.",
        "ops": [("writefile", "f.txt", b"\xca\xfe")],
        "feeds": [
            r_version(),
            r_handle(1),
            r_status(2, FX_EOF, "eof"),
            r_status(3, FX_OK),
        ],
        "requests": [
            q_init(),
            q_open(1, "f.txt", FXF_WRITE | FXF_CREAT | FXF_TRUNC),
            q_write(2, "h", 0, b"\xca\xfe"),
            q_close(3, "h"),
        ],
        "results": [("failed", FX_EOF, "eof")],
        "done": True,
        "failed": False,
    },
    {
        "name": "ext_absent_falls_back_to_v3",
        "intent": "Six extensions advertised, none of them the rename one: the "
                  "RENAME that goes out must be FXP_RENAME, not FXP_EXTENDED.",
        "ops": [("rename", "a", "b")],
        "feeds": [
            r_version(
                3,
                [
                    ("statvfs@openssh.com", "2"),
                    ("fstatvfs@openssh.com", "2"),
                    ("hardlink@openssh.com", "1"),
                    ("fsync@openssh.com", "1"),
                    ("lsetstat@openssh.com", "1"),
                    ("limits@openssh.com", "1"),
                ],
            ),
            r_status(1, FX_OK),
        ],
        "requests": [q_init(), q_rename(1, "a", "b")],
        "results": [("changed",)],
        "done": True,
        "failed": False,
    },
    {
        "name": "ext_present_sends_extended",
        "intent": "The rename extension named in VERSION: FXP_EXTENDED carries "
                  "the name, then the two paths and nothing else.",
        "ops": [("rename", "a", "b")],
        "feeds": [
            r_version(3, [(EXT_POSIX_RENAME, "1")]),
            r_status(1, FX_OK),
        ],
        "requests": [
            q_init(),
            q_extended_posix_rename(1, "a", "b"),
        ],
        "results": [("changed",)],
        "done": True,
        "failed": False,
    },
    {
        "name": "ext_unknown_is_op_unsupported",
        "intent": "A server that advertises the extension and then refuses it "
                  "answers UNSUPPORTED; that is a result, not a dead session.",
        "ops": [("rename", "a", "b")],
        "feeds": [
            r_version(3, [(EXT_POSIX_RENAME, "1")]),
            r_status(1, FX_OP_UNSUPPORTED, "Operation unsupported"),
        ],
        "requests": [q_init(), q_extended_posix_rename(1, "a", "b")],
        "results": [("failed", FX_OP_UNSUPPORTED, "Operation unsupported")],
        "done": True,
        "failed": False,
    },
    {
        "name": "oversize_length_prefix",
        "intent": "A length prefix above SFTP_MAX_MSG_LENGTH is refused before "
                  "anything is sized from it.",
        "ops": [("realpath", ".")],
        "feeds": [
            r_version(),
            bytes.fromhex("00100000") + b"\x69\x00\x00\x00\x01" + b"\x00\x00\x00\x00",
        ],
        "requests": [q_init(), q_realpath(1, ".")],
        "results": [],
        "done": False,
        "failed": True,
        # `Unexpected`, not `BadLength`.  In `src/sftp` those are different
        # failures and the distinction is load-bearing: `BadLength` is a
        # *cursor* error meaning "a length field pointed past the end of the
        # buffer" (`proto.mbt`), while the framing check here rejects a length
        # that is out of range before any buffer is sized from it.  The oracle
        # originally wrote `BadLength` here and the console disagreed -- which
        # is the whole reason the expectation lives in a second implementation
        # instead of being copied out of the code under test.
        "failure_reason": "framing: Unexpected",
    },
    {
        "name": "truncated_attrs",
        "intent": "ATTRS claiming a size it does not carry: unparsable, and "
                  "fatal, because we no longer know where we are.",
        "ops": [("stat", "f.txt")],
        "feeds": [
            r_version(),
            # FXP_ATTRS, id 1, flags = ATTR_SIZE, and then nothing.
            frame(bytes([FXP_ATTRS]) + u32(1) + u32(ATTR_SIZE)),
        ],
        "requests": [q_init(), q_stat(1, "f.txt")],
        "results": [],
        "done": False,
        "failed": True,
        "failure_reason": "unparsable reply: Truncated",
    },
    {
        "name": "status_trailing_data",
        "intent": "One byte after the language tag is enough to refuse the whole "
                  "packet rather than accept the fields we happened to read.",
        "ops": [("realpath", ".")],
        "feeds": [
            r_version(),
            frame(
                bytes([FXP_STATUS])
                + u32(1)
                + u32(FX_FAILURE)
                + s("nope")
                + s("")
                + b"\x00"
            ),
        ],
        "requests": [q_init(), q_realpath(1, ".")],
        "results": [],
        "done": False,
        "failed": True,
        "failure_reason": "unparsable reply: TrailingData",
    },
]


def run(scn):
    """Drive the reference session and return what it produced."""
    sess = RefSession(scn["ops"])
    sent = []
    ci = 0
    for _ in range(4000):
        sent.extend(sess.take_out())
        if sess.phase in ("done", "failed"):
            break
        if ci >= len(scn["feeds"]):
            break
        sess.feed(scn["feeds"][ci])
        ci += 1
    sent.extend(sess.take_out())
    return {
        "requests": hexs(sent),
        "results": [list(r) for r in sess.results],
        "done": sess.phase == "done",
        "failed": sess.phase == "failed",
        "failure_reason": sess.failed,
    }


def main():
    out = []
    problems = []
    for scn in SCENARIOS:
        got = run(scn)
        want_requests = [b.hex() for b in scn["requests"]]
        want_results = [list(r) for r in scn["results"]]
        entry = {
            "name": scn["name"],
            "intent": scn["intent"],
            "ops": [
                [o[0], o[1], o[2].hex() if isinstance(o[2], bytes) else o[2]]
                if len(o) > 2
                else [o[0], o[1]]
                for o in scn["ops"]
            ],
            "feeds": [b.hex() for b in scn["feeds"]],
            "requests": want_requests,
            "results": want_results,
            "done": scn["done"],
            "failed": scn["failed"],
            "failure_reason": scn.get("failure_reason", ""),
        }
        # self-check: the oracle must agree with the hand-written expectation
        if got["requests"] != want_requests:
            problems.append(
                f"{scn['name']}: oracle requests != expectation\n"
                f"      oracle      {got['requests']}\n"
                f"      expectation {want_requests}"
            )
        if got["results"] != want_results:
            problems.append(
                f"{scn['name']}: oracle results != expectation\n"
                f"      oracle      {got['results']}\n"
                f"      expectation {want_results}"
            )
        if got["done"] != scn["done"]:
            problems.append(f"{scn['name']}: oracle done={got['done']}")
        if got["failed"] != scn["failed"]:
            problems.append(f"{scn['name']}: oracle failed={got['failed']}")
        if scn.get("failure_reason", "") and got["failure_reason"] != scn["failure_reason"]:
            problems.append(
                f"{scn['name']}: oracle reason={got['failure_reason']!r} "
                f"expected {scn['failure_reason']!r}"
            )
        out.append(entry)

    if problems:
        for p in problems:
            print("ORACLE MISMATCH " + p, file=sys.stderr)
        return 1

    with open(sys.argv[1] if len(sys.argv) > 1 else "fault_vectors.json", "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"oracle self-consistent: {len(out)} scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
