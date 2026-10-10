"""Loop #39 oracle: SFTP v3 framing, attributes, and the scripted session.

An independent implementation of the same rules as `src/sftp`, in Python, for
the KAT in `cmd/sftp_test`.  Nothing here is transcribed by hand from our own
MoonBit; the rules come from the C:

  sftp.h:34-62                 every message number
  sftp-common.h:29             SFTP_MAX_MSG_LENGTH = 256*1024
  sftp-server.c:55             SFTP_MAX_READ_LENGTH = SFTP_MAX_MSG_LENGTH - 1024
  sftp-client.c:151-173        send_msg: the length excludes itself
  sftp-client.c:175-210        get_msg_extended: loop-read, so a packet may be
                               split across channel data, and one channel data
                               may carry several packets
  sftp-server.c:702-731        process_init: VERSION, then extension pairs
  sftp-common.c:104-146        decode_attrib: flags first, then fields in a
                               fixed order, and no get_end -- attributes are
                               mid-packet
  sftp-server.c:1121           process_readdir

And three things it can only learn from a real server, which
`host/sftp_capture.py` recorded:

  1. **The reply numbers are 101..105 in the order STATUS, HANDLE, DATA, NAME,
     ATTRS.**  The grouping in the draft is `101 DATA / 102 HANDLE / 103 NAME /
     104 ATTRS / 105 STATUS` -- which is the same five numbers sorted by name,
     and reads naturally enough to be what an implementer writes down from
     memory.  A parser built on that ordering accepts STATUS where it expects
     DATA and every reply looks superficially plausible: a NAME reply parses
     as ATTRS, an ATTRS reply parses as NAME with a count of its first flag
     word.  This project got it right, but only because the capture was read
     before the KAT was written.

  2. **VERSION carries six extension pairs on OpenSSH 8.0p1**, not the eleven
     newer versions send.  The count is a property of the server, not a
     constant, which is why the session reports it instead of asserting it.

  3. **REALPATH's NAME entry has attribute flags 0.**  The server does not fill
     in attributes for a canonicalised path.  A parser that reads size/uid/…
     unconditionally desynchronises here and then reports a plausible size for
     a path that has none.

And four more that `host/sftp_write_capture.py` established for the write side:

  4. **WRITE offsets are file offsets and they walk.**  `process_write` does
     `lseek(fd, off, SEEK_SET)` before every write (sftp-server.c:865-866),
     so "bytes still to send" is not a harmless alternative encoding: the
     capture shows `0, 8192, 16384, …` strictly increasing, and a client that
     sent the offset twice would overwrite rather than append while the file
     length stayed plausible.

  5. **`FXP_RENAME` and `posix-rename@openssh.com` are different requests.**
     The draft's RENAME is specified to fail when the target exists; the
     extension is `rename(2)` and replaces it.  The capture confirms the
     replacement is accepted (STATUS 0) where the target was known to exist.

  6. **An unknown extension name is a clean `STATUS(SSH2_FX_OP_UNSUPPORTED=8)`**
     (`process_extended`), not a dropped channel.  Treating it as fatal hangs
     the client against any server that lacks the extension.

  7. **MKDIR and SETSTAT carry an attribute block; REMOVE and RMDIR do not.**
     `SSH2_FXP_REMOVE` is 13 and `SSH2_FXP_RMDIR` is 15 — adjacent and easy to
     swap, and swapping them sends a valid-looking message the server will
     reject.

Note on the STATUS body: after the 4-byte code comes the message string and
then a **language tag** (sftp-common.c `send_status`).  Reading the code and
declaring the packet finished desynchronises every later reply.

The generator rewrites exactly one field when it replays a captured reply into
a vector: the 4-byte request id, which is client-chosen and would otherwise
force our session's numbering to be paramiko's.  Everything else -- the
attribute blocks, the longnames, the extension pairs, the DATA payloads -- is
the server's own bytes.

Run:  python host/gen_sftp_vectors.py --capture .loop39/capture.json
"""

import argparse
import json
import os
import struct

# ---- wire numbers (sftp.h:56-62) -------------------------------------------

FXP_INIT = 1
FXP_VERSION = 2
FXP_OPEN = 3
FXP_CLOSE = 4
FXP_READ = 5
FXP_WRITE = 6
FXP_SETSTAT = 9
FXP_FSETSTAT = 10
FXP_OPENDIR = 11
FXP_READDIR = 12
FXP_REMOVE = 13
FXP_MKDIR = 14
FXP_RMDIR = 15
FXP_REALPATH = 16
FXP_STAT = 17
FXP_RENAME = 18

FXP_STATUS = 101
FXP_HANDLE = 102
FXP_DATA = 103
FXP_NAME = 104
FXP_ATTRS = 105
FXP_EXTENDED = 200
FXP_EXTENDED_REPLY = 201

ATTR_SIZE = 0x00000001
ATTR_UIDGID = 0x00000002
ATTR_PERMISSIONS = 0x00000004
ATTR_ACMODTIME = 0x00000008
ATTR_EXTENDED = 0x80000000

FXF_READ = 0x00000001
FXF_WRITE = 0x00000002
FXF_APPEND = 0x00000004
FXF_CREAT = 0x00000008
FXF_TRUNC = 0x00000010
FXF_EXCL = 0x00000020

# The chunk size `src/sftp` asks for.  Kept in one place so the KAT's expected
# request stream and the client's actual behaviour cannot drift: if either
# moves, the KAT stops agreeing with the code and starts agreeing with itself.
WRITE_CHUNK = 32768

SFTP_VERSION = 3
SFTP_MAX_MSG_LENGTH = 256 * 1024
SFTP_MAX_READ_LENGTH = SFTP_MAX_MSG_LENGTH - 1024

FX_EOF = 1
FX_NO_SUCH_FILE = 2
FX_OP_UNSUPPORTED = 8

REPLY_NAMES = {
    FXP_VERSION: "VERSION", FXP_STATUS: "STATUS", FXP_HANDLE: "HANDLE",
    FXP_DATA: "DATA", FXP_NAME: "NAME", FXP_ATTRS: "ATTRS",
}


# ---- encoding --------------------------------------------------------------

def u32(n):
    return struct.pack(">I", n & 0xFFFFFFFF)


def u64(n):
    return struct.pack(">Q", n & 0xFFFFFFFFFFFFFFFF)


def s(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return u32(len(b)) + b


def frame(body):
    """sftp-client.c:151-173 -- the length does not count itself."""
    return u32(len(body)) + body


def pkt(typ, *parts):
    return frame(bytes([typ]) + b"".join(parts))


def f_init(version=SFTP_VERSION):
    """INIT carries no request id (sftp.h:34, and the capture agrees)."""
    return pkt(FXP_INIT, u32(version))


def f_realpath(rid, path):
    return pkt(FXP_REALPATH, u32(rid), s(path))


def f_stat(rid, path):
    return pkt(FXP_STAT, u32(rid), s(path))


def f_opendir(rid, path):
    return pkt(FXP_OPENDIR, u32(rid), s(path))


def f_readdir(rid, handle):
    return pkt(FXP_READDIR, u32(rid), s(handle))


def f_open(rid, path, pflags=FXF_READ, flags=0):
    return pkt(FXP_OPEN, u32(rid), s(path), u32(pflags), u32(flags))


def f_read(rid, handle, offset, length):
    return pkt(FXP_READ, u32(rid), s(handle), u64(offset), u32(length))


def f_close(rid, handle):
    return pkt(FXP_CLOSE, u32(rid), s(handle))


# ---- the write side --------------------------------------------------------

def encode_attrs(size=None, uid=None, gid=None, permissions=None,
                 atime=None, mtime=None, extended=()):
    """sftp-common.c `encode_attrib` -- flags first, then a fixed field order.

    A field is present exactly when its flag is set, so "change nothing" is not
    the empty block but four zero bytes.  Writing an empty attribute block
    where one is expected is a parse failure on the server, not a default.
    """
    flags = 0
    body = b""
    if size is not None:
        flags |= ATTR_SIZE
        body += u64(size)
    if uid is not None and gid is not None:
        flags |= ATTR_UIDGID
        body += u32(uid) + u32(gid)
    if permissions is not None:
        flags |= ATTR_PERMISSIONS
        body += u32(permissions)
    if atime is not None and mtime is not None:
        flags |= ATTR_ACMODTIME
        body += u32(atime) + u32(mtime)
    if extended:
        flags |= ATTR_EXTENDED
        body += u32(len(extended))
        for k, v in extended:
            body += s(k) + s(v)
    return u32(flags) + body


def f_attrs_none():
    return u32(0)


def f_write(rid, handle, offset, data):
    """sftp.h:39.  `offset` is a **file** offset -- see `process_write`'s
    `lseek(fd, off, SEEK_SET)` at sftp-server.c:865-866."""
    return pkt(FXP_WRITE, u32(rid), s(handle), u64(offset), s(data))


def f_setstat(rid, path, attrs):
    return pkt(FXP_SETSTAT, u32(rid), s(path), attrs)


def f_fsetstat(rid, handle, attrs):
    return pkt(FXP_FSETSTAT, u32(rid), s(handle), attrs)


def f_mkdir(rid, path, attrs):
    """sftp.h:48.  MKDIR carries attributes after the path; REMOVE and RMDIR
    do not.  Zero bytes there is a parse failure, not a default."""
    return pkt(FXP_MKDIR, u32(rid), s(path), attrs)


def f_remove(rid, path):
    return pkt(FXP_REMOVE, u32(rid), s(path))


def f_rmdir(rid, path):
    return pkt(FXP_RMDIR, u32(rid), s(path))


def f_rename(rid, old_path, new_path):
    """sftp.h:52.  Specified to fail when the target exists."""
    return pkt(FXP_RENAME, u32(rid), s(old_path), s(new_path))


def f_extended(rid, name, body=b""):
    return pkt(FXP_EXTENDED, u32(rid), s(name), body)


EXT_POSIX_RENAME = "posix-rename@openssh.com"


def f_posix_rename(rid, old_path, new_path):
    """`process_extended_posix_rename`: the name, then two paths, nothing else.

    Unlike FXP_RENAME this *replaces* an existing target, because it is
    `rename(2)` rather than the draft's rule.
    """
    return f_extended(rid, EXT_POSIX_RENAME, s(old_path) + s(new_path))


def write_chunks(payload, chunk=WRITE_CHUNK):
    """The (offset, bytes) pairs a WriteFile sends, in order."""
    out = []
    off = 0
    while off < len(payload):
        out.append((off, payload[off:off + chunk]))
        off += chunk
    return out


# ---- decoding --------------------------------------------------------------

class Buf(object):
    def __init__(self, b):
        self.b = b
        self.i = 0

    def u8(self):
        v = self.b[self.i]
        self.i += 1
        return v

    def u32(self):
        v = struct.unpack(">I", self.b[self.i:self.i + 4])[0]
        self.i += 4
        return v

    def u64(self):
        v = struct.unpack(">Q", self.b[self.i:self.i + 8])[0]
        self.i += 8
        return v

    def s(self):
        n = self.u32()
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def at_end(self):
        return self.i >= len(self.b)


def parse_attrs(buf):
    """sftp-common.c:104-146.  Returns a dict; absent fields are None."""
    flags = buf.u32()
    a = {"flags": flags, "size": None, "uid": None, "gid": None,
         "permissions": None, "atime": None, "mtime": None, "extended": []}
    if flags & ATTR_SIZE:
        a["size"] = buf.u64()
    if flags & ATTR_UIDGID:
        a["uid"] = buf.u32()
        a["gid"] = buf.u32()
    if flags & ATTR_PERMISSIONS:
        a["permissions"] = buf.u32()
    if flags & ATTR_ACMODTIME:
        a["atime"] = buf.u32()
        a["mtime"] = buf.u32()
    if flags & ATTR_EXTENDED:
        count = buf.u32()
        if count > 0x100000:
            raise ValueError("extended count %d over the cap" % count)
        for _ in range(count):
            a["extended"].append((buf.s(), buf.s()))
    return a


def parse_reply(raw):
    """`raw` is one packet's payload (no length prefix).  Returns (type, dict)."""
    typ = raw[0]
    buf = Buf(raw[1:])
    if typ == FXP_VERSION:
        version = buf.u32()
        ext = []
        while not buf.at_end():
            ext.append((buf.s().decode("utf-8", "replace"),
                        buf.s().decode("utf-8", "replace")))
        return typ, {"version": version, "extensions": ext}
    rid = buf.u32()
    if typ == FXP_STATUS:
        # After the code comes the message and then a **language tag**
        # (`send_status`).  A parser that stops after the message treats the
        # language bytes as the start of the next reply.
        code = buf.u32()
        msg = buf.s().decode("utf-8", "replace")
        lang = buf.s().decode("utf-8", "replace") if not buf.at_end() else ""
        return typ, {"id": rid, "code": code, "message": msg, "lang": lang}
    if typ == FXP_HANDLE:
        return typ, {"id": rid, "handle": buf.s()}
    if typ == FXP_DATA:
        return typ, {"id": rid, "data": buf.s()}
    if typ == FXP_ATTRS:
        a = parse_attrs(buf)
        return typ, {"id": rid, "attrs": a}
    if typ == FXP_NAME:
        count = buf.u32()
        entries = []
        for _ in range(count):
            fn = buf.s()
            ln = buf.s()
            entries.append((fn.decode("utf-8", "replace"), ln, parse_attrs(buf)))
        return typ, {"id": rid, "count": count, "entries": entries}
    return typ, {"id": rid, "raw": buf.b[buf.i:]}


def split_stream(stream):
    out = []
    i = 0
    while i + 4 <= len(stream):
        n = struct.unpack(">I", stream[i:i + 4])[0]
        if i + 4 + n > len(stream):
            out.append({"truncated": stream[i:].hex()})
            break
        out.append({"len": n, "raw": stream[i + 4:i + 4 + n].hex()})
        i += 4 + n
    return out


def retag(raw, new_id):
    """Replace the 4-byte request id in a captured reply.  Nothing else."""
    return bytes([raw[0]]) + u32(new_id) + raw[5:]


def attrs_summary(a):
    """The canonical one-line form both implementations must agree on.

    The flag word is deliberately not part of it: `SftpAttrs` keeps only the
    fields that were present, so which fields are there is the fact, and
    restating the flags would be restating our own decoding back at us.
    """
    def opt(v):
        return "-" if v is None else str(v)
    is_dir = (a["permissions"] is not None
              and (a["permissions"] & 0xF000) == 0x4000)
    return "size=%s,uid=%s,gid=%s,perm=%s,isdir=%d" % (
        opt(a["size"]), opt(a["uid"]), opt(a["gid"]),
        opt(a["permissions"]), 1 if is_dir else 0)


# ---- the scripted session, in Python --------------------------------------

def script_requests(ops, read_len=32768, first_read_bytes=11):
    """Requests our `SftpSession` emits, in order, with its id numbering.

    Mirrors `src/sftp/session.mbt`: ids start at 1, operations are serial,
    LISTDIR ends on STATUS(EOF) rather than on a short list, and the READ
    offset accumulates over the whole file.

    `first_read_bytes` is how much the first READ is expected to return.  It
    is not a detail: a non-empty DATA makes the client ask again, so a
    one-READ script is only right for an empty file, and writing the script
    that way would have the KAT assert a request sequence no correct client
    ever sends.
    """
    out = [f_init()]
    rid = 1
    for op in ops:
        kind, path = op[0], op[1]
        if kind == "realpath":
            out.append(f_realpath(rid, path))
            rid += 1
        elif kind == "stat":
            out.append(f_stat(rid, path))
            rid += 1
        elif kind == "listdir":
            out.append(f_opendir(rid, path))
            rid += 1
            out.append(f_readdir(rid, b"\x00\x00\x00\x00"))
            rid += 1
            out.append(f_readdir(rid, b"\x00\x00\x00\x00"))
            rid += 1
            out.append(f_close(rid, b"\x00\x00\x00\x00"))
            rid += 1
        elif kind == "readfile":
            out.append(f_open(rid, path))
            rid += 1
            out.append(f_read(rid, b"\x00\x00\x00\x00", 0, read_len))
            rid += 1
            if first_read_bytes > 0:
                out.append(f_read(rid, b"\x00\x00\x00\x00",
                                  first_read_bytes, read_len))
                rid += 1
            out.append(f_close(rid, b"\x00\x00\x00\x00"))
            rid += 1
        elif kind == "writefile":
            payload = op_payload(op)
            # CREAT and TRUNC together, which is exactly what OpenSSH's own
            # client sends when it renames a file into place
            # (sftp-client.c:2502).  CREAT alone would leave an existing
            # file's contents in front of what we write.
            out.append(f_open(rid, path,
                              FXF_WRITE | FXF_CREAT | FXF_TRUNC))
            rid += 1
            # An empty payload sends **zero** WRITE requests.  One empty WRITE
            # would come back STATUS(OK) -- indistinguishable on the wire from
            # having written a file -- while TRUNC has already destroyed the
            # old contents.
            for off, chunk in write_chunks(payload):
                out.append(f_write(rid, b"\x00\x00\x00\x00", off, chunk))
                rid += 1
            out.append(f_close(rid, b"\x00\x00\x00\x00"))
            rid += 1
        elif kind == "setattrs":
            out.append(f_setstat(rid, path, op_attrs(op)))
            rid += 1
        elif kind == "mkdir":
            out.append(f_mkdir(rid, path, op_attrs(op)))
            rid += 1
        elif kind == "remove":
            out.append(f_remove(rid, path))
            rid += 1
        elif kind == "rmdir":
            out.append(f_rmdir(rid, path))
            rid += 1
        elif kind == "rename":
            # The session picks the extension only when VERSION advertised it;
            # every capture this KAT replays did, so that is the branch under
            # test.  The v3 fallback is a separate case.
            out.append(f_posix_rename(rid, path, op_path2(op)))
            rid += 1
        else:
            raise ValueError(kind)
    return out


# ---- op payload helpers ----------------------------------------------------
#
# Ops are tuples whose length depends on what they need, so reading them in
# three different places must not mean three different ideas about what a
# missing element is.

HANDLE0 = b"\x00\x00\x00\x00"


def op_path2(op):
    return op[2] if len(op) > 2 else ""


def op_payload(op):
    if len(op) > 2 and op[2] != "":
        return bytes.fromhex(op[2])
    return b""


def op_attrs(op):
    """Op tails that are not a payload are an attribute spec.

    `None` means "do not mention it at all" -- an absent flag, which is a
    different request from mentioning it with a value of zero.
    """
    spec = {}
    for part in op[2:]:
        if not isinstance(part, dict):
            continue
        spec.update(part)
    return encode_attrs(**spec)


def expected_results(ops, replies):
    """Render results the way the MoonBit side renders them.

    `replies` are the (already re-tagged) reply packets for this case.
    """
    return replies