#!/usr/bin/env python3
"""Loop #35 oracle: SSH connection protocol channels (RFC 4254).

Two independent things have to agree for a remote command to work:

1. **The bytes.** Every channel message has a fixed field order, and getting
   one field wrong does not close the connection -- it just makes the peer
   ignore the packet. So the builders here are written from the RFC and then
   cross-checked against what paramiko *actually puts on the wire* during a
   real `exec`, captured by patching `Transport._send_user_message`, which is
   the single funnel every channel packet goes through in paramiko
   (channel.py:200/227/254/280/307/360/423/487/512/669/708/756/965/1037/1161/
   1185/1206).

2. **The window arithmetic.** `WINDOW_ADJUST` is not sent "when we've read
   enough" -- OpenSSH sends the *accumulated consumed count*, and only when
   `local_consumed > 0 && (max - cur > maxpacket*3 || cur < max/2)`
   (channels.c:2444-2462). Re-deriving it from the C here and comparing to
   MoonBit is what keeps the two implementations honest; a plausible-looking
   "top the window back up to max" would interoperate and still be wrong.

用��:
    python host/channel_oracle.py --json
    python host/channel_oracle.py --capture --port 22263 [--user hp]
"""

import argparse
import binascii
import json
import os
import struct
import sys
from collections import OrderedDict

# --------------------------------------------------------------------------
# Constants, straight out of the C
# --------------------------------------------------------------------------
# channels.h:231  #define CHAN_SES_PACKET_DEFAULT (32*1024)
# channels.h:232  #define CHAN_SES_WINDOW_DEFAULT (64*CHAN_SES_PACKET_DEFAULT)
CHAN_SES_PACKET_DEFAULT = 32 * 1024
CHAN_SES_WINDOW_DEFAULT = 64 * CHAN_SES_PACKET_DEFAULT

# Message numbers (RFC 4254 §5)
MSG_CHANNEL_OPEN = 90
MSG_CHANNEL_OPEN_CONFIRMATION = 91
MSG_CHANNEL_OPEN_FAILURE = 92
MSG_CHANNEL_WINDOW_ADJUST = 93
MSG_CHANNEL_DATA = 94
MSG_CHANNEL_EXTENDED_DATA = 95
MSG_CHANNEL_EOF = 96
MSG_CHANNEL_CLOSE = 97
MSG_CHANNEL_REQUEST = 98
MSG_CHANNEL_SUCCESS = 99
MSG_CHANNEL_FAILURE = 100

SSH2_EXTENDED_DATA_STDERR = 1

SSH_BOOL_FALSE = b"\x00"
SSH_BOOL_TRUE = b"\x01"


def u32(v):
    return struct.pack(">I", v)


def ssh_string(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return u32(len(b)) + b


# --------------------------------------------------------------------------
# Builders, written from RFC 4254
# --------------------------------------------------------------------------
def chan_open(sender, window, max_packet):
    """CHANNEL_OPEN (RFC 4254 5.1 / channels.c:1171-1175)"""
    return ssh_string("session") + u32(sender) + u32(window) + u32(max_packet)


def chan_request(recipient, rtype, want_reply, extra=b""):
    """CHANNEL_REQUEST (RFC 4254 6.1 / channels.c:1948)"""
    return (
        u32(recipient)
        + ssh_string(rtype)
        + (SSH_BOOL_TRUE if want_reply else SSH_BOOL_FALSE)
        + extra
    )


def chan_exec(recipient, command):
    return chan_request(recipient, "exec", True, ssh_string(command))


def chan_window_adjust(recipient, nbytes):
    return u32(recipient) + u32(nbytes)


def chan_data(recipient, data):
    return u32(recipient) + ssh_string(data)


def chan_extended_data(recipient, code, data):
    return u32(recipient) + u32(code) + ssh_string(data)


def chan_bare(recipient):
    return u32(recipient)


def exit_status_request(recipient, status):
    """What the *server* sends: session.c:2344-2347."""
    return chan_request(recipient, "exit-status", False, u32(status))


# --------------------------------------------------------------------------
# Local window, re-derived from channels.c
# --------------------------------------------------------------------------
class LocalWindow(object):
    """channels.c's local_window / local_window_max / local_consumed."""

    def __init__(self, maximum=CHAN_SES_WINDOW_DEFAULT,
                 max_packet=CHAN_SES_PACKET_DEFAULT):
        self.max = maximum
        self.cur = maximum
        self.consumed = 0
        self.max_packet = max_packet

    def consume(self, n):
        # channels.c:3518-3523 -- saturating, never wraps
        self.cur = 0 if n > self.cur else self.cur - n
        self.consumed += n

    def should_adjust(self):
        # channels.c:2444-2449
        if self.consumed <= 0:
            return False
        return (
            (self.max - self.cur) > (self.max_packet * 3)
            or self.cur < self.max // 2
        )

    def take_adjust(self):
        """Returns the byte count to send, or None."""
        if not self.should_adjust():
            return None
        amount = self.consumed
        self.cur += amount
        self.consumed = 0
        return amount


# --------------------------------------------------------------------------
# paramiko cross-check
# --------------------------------------------------------------------------
def capture_paramiko(port, user, key_hex, command="echo channel-oracle"):
    """Run a real exec through paramiko and record every channel packet it sends.

    Returns a list of (msg_type, payload_hex) in send order, or None.
    """
    try:
        import io as _io

        import paramiko
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except Exception as exc:  # noqa: BLE001
        print("paramiko unavailable: %s" % exc, file=sys.stderr)
        return None

    sk = ec.derive_private_key(int(key_hex, 16), ec.SECP256R1())
    pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key = paramiko.ECDSAKey.from_private_key(_io.StringIO(pem.decode("ascii")))

    sent = []
    orig = paramiko.transport.Transport._send_user_message

    def patched(self, data):
        # _send_user_message is fed a paramiko Message (channel.py builds one via
        # Message()); raw bytes only show up for a few low-level paths.
        raw = data.asbytes() if hasattr(data, "asbytes") else bytes(data)
        if raw:
            sent.append((raw[0], binascii.hexlify(raw[1:]).decode()))
        return orig(self, data)

    paramiko.transport.Transport._send_user_message = patched
    try:
        t = paramiko.Transport(("127.0.0.1", port))
        t.start_client(timeout=15)
        t.auth_publickey(user, key)
        chan = t.open_session(timeout=15)
        chan.settimeout(20)
        chan.exec_command(command)
        while True:
            if chan.recv_ready():
                chan.recv(4096)
            if chan.exit_status_ready():
                break
            if chan.closed:
                break
        t.close()
    except Exception as exc:  # noqa: BLE001
        print("paramiko session failed: %s" % exc, file=sys.stderr)
        return None
    finally:
        paramiko.transport.Transport._send_user_message = orig
    return sent


def compare_with_paramiko(captured, key_hex):
    """Every captured CHANNEL_OPEN / REQUEST exec must equal our construction.

    The open payload carries paramiko's own window and max packet, so we match
    on the *type name and the fixed fields* rather than comparing whole blobs:
    the numbers legitimately differ (paramiko's defaults are not ours).
    """
    problems = []
    saw_open = saw_exec = saw_eof = False
    for msg_type, payload_hex in captured:
        payload = binascii.unhexlify(payload_hex)
        if msg_type == MSG_CHANNEL_OPEN:
            off = 0
            (n,) = struct.unpack(">I", payload[off:off + 4])
            ctype = payload[off + 4:off + 4 + n]
            off += 4 + n
            (sender, window, maxp) = struct.unpack(">III", payload[off:off + 12])
            want = chan_open(sender, window, maxp)
            if ctype != b"session":
                problems.append("channel type %r != b'session'" % ctype)
            elif payload != want:
                problems.append("CHANNEL_OPEN payload differs from our builder")
            else:
                saw_open = True
        elif msg_type == MSG_CHANNEL_REQUEST:
            # RFC 4254 6.1 layout is u32 recipient || string request_type || bool
            # want_reply || ...  -- deliberately NOT parsed like CHANNEL_OPEN,
            # which starts with a string.  Conflating the two made an exec
            # request parse its recipient channel 0 as a zero-length string and
            # silently vanish.
            (recipient,) = struct.unpack(">I", payload[0:4])
            off = 4
            (n,) = struct.unpack(">I", payload[off:off + 4])
            rtype = payload[off + 4:off + 4 + n]
            off += 4 + n
            want_reply = payload[off]
            off += 1
            if rtype != b"exec":
                problems.append("unexpected CHANNEL_REQUEST type %r" % rtype)
                continue
            (ln,) = struct.unpack(">I", payload[off:off + 4])
            off += 4
            cmd = payload[off:off + ln]
            off += ln
            if off != len(payload):
                problems.append("CHANNEL_REQUEST exec has %d trailing bytes"
                                % (len(payload) - off))
            elif not cmd:
                problems.append("exec command is empty")
            elif payload != chan_exec(recipient, cmd):
                problems.append("CHANNEL_REQUEST exec differs from our builder")
            elif want_reply != 1:
                problems.append("exec want_reply is not TRUE")
            else:
                saw_exec = True
        elif msg_type == MSG_CHANNEL_EOF:
            # Verified when it shows up, but not required: paramiko only emits
            # EOF on the close path and skips it when the transport has already
            # gone.  Whether it appeared says nothing about our layout, and a
            # check that goes red for unrelated timing reasons trains people to
            # ignore it.
            if payload != chan_bare(struct.unpack(">I", payload[0:4])[0]):
                problems.append("CHANNEL_EOF differs from our builder")
            else:
                saw_eof = True
    if not saw_open:
        problems.append("no CHANNEL_OPEN captured from paramiko")
    if not saw_exec:
        problems.append("no exec CHANNEL_REQUEST captured from paramiko")
    return problems, saw_eof


# --------------------------------------------------------------------------
# Vectors for the MoonBit KAT
# --------------------------------------------------------------------------
def window_vectors():
    """Window adjustments for a few data patterns.

    The interesting one is the last: 1.5 MiB of output in 32 KiB packets, which
    forces several adjustments and would deadlock against an implementation
    that only tops the window up.
    """
    cases = []
    plans = [
        ("small", [16]),
        ("exact_maxpacket", [CHAN_SES_PACKET_DEFAULT]),
        ("just_under_half", [CHAN_SES_WINDOW_DEFAULT // 2 - 8]),
        ("past_half", [CHAN_SES_WINDOW_DEFAULT // 2 + 8]),
        ("bulk_32k", [CHAN_SES_PACKET_DEFAULT] * 48),
        ("many_small", [1024] * 1100),
    ]
    for name, sizes in plans:
        w = LocalWindow()
        emitted = []
        for n in sizes:
            w.consume(n)
            amt = w.take_adjust()
            if amt is not None:
                emitted.append(
                    {
                        "bytes": amt,
                        "payload_hex": binascii.hexlify(
                            chan_window_adjust(7, amt)
                        ).decode(),
                        "cur_after": w.cur,
                    }
                )
        cases.append(
            OrderedDict(
                [
                    ("name", name),
                    ("sizes", sizes),
                    ("adjusts", emitted),
                    ("final_cur", w.cur),
                    ("final_consumed", w.consumed),
                ]
            )
        )
    return cases


def payload_vectors():
    """Builders, one entry per message type, for a couple of parameter sets."""
    out = []
    for sender, win, maxp in [(0, CHAN_SES_WINDOW_DEFAULT, CHAN_SES_PACKET_DEFAULT),
                              (3, 2097152, 32768)]:
        out.append(
            OrderedDict(
                [
                    ("name", "open_s%d" % sender),
                    ("sender", sender),
                    ("window", win),
                    ("max_packet", maxp),
                    ("open_hex", binascii.hexlify(chan_open(sender, win, maxp)).decode()),
                    ("exec_command", "echo hi"),
                    ("exec_hex", binascii.hexlify(
                        chan_exec(sender, "echo hi")).decode()),
                    ("data_text", "abc"),
                    ("data_hex", binascii.hexlify(
                        chan_data(sender, b"abc")).decode()),
                    ("extdata_code", SSH2_EXTENDED_DATA_STDERR),
                    ("extdata_text", "oops"),
                    ("extdata_hex", binascii.hexlify(
                        chan_extended_data(sender, SSH2_EXTENDED_DATA_STDERR,
                                           b"oops")).decode()),
                    ("adjust_bytes", 65536),
                    ("adjust_hex", binascii.hexlify(
                        chan_window_adjust(sender, 65536)).decode()),
                    ("bare_hex", binascii.hexlify(chan_bare(sender)).decode()),
                    ("exit_status_code", 42),
                    ("exit_status_hex", binascii.hexlify(
                        exit_status_request(sender, 42)).decode()),
                    ("open_failure_reason", 3),
                    ("open_failure_desc", "no such session"),
                    ("open_failure_hex", binascii.hexlify(
                        u32(sender) + u32(3) + ssh_string("no such session")
                        + ssh_string("")).decode()),
                ]
            )
        )
    return out


def session_vectors():
    """Full server -> client transcripts, with the expected client replies.

    These are the cases that actually bite.  `exec_bulk_window` is the one a
    "top the window back up to full" implementation gets wrong, and
    `exec_nonzero_ids` is the one a "the recipient field holds the peer's
    channel id" implementation gets wrong -- both look fine while our own
    channel number and the server's happen to be 0, which is exactly how the
    bug survived in `src/channel/exec.mbt` until this vector existed.
    """
    def open_confirmation(local, remote, win, maxp):
        return u32(local) + u32(remote) + u32(win) + u32(maxp)

    def request(local, rtype, want_reply, extra=b""):
        return u32(local) + ssh_string(rtype) + (
            SSH_BOOL_TRUE if want_reply else SSH_BOOL_FALSE) + extra

    # A transcript with 48 x 32 KiB of DATA is 3 MiB of hex per copy, and the
    # file was landing at 10 MB -- slow to parse on every backend and useless
    # as a diff.  A run of one repeated byte is described instead of spelled out,
    # which keeps the exact length under test while storing ~20 bytes.
    FILL_LIMIT = 4096

    def summarize(data):
        if len(data) <= FILL_LIMIT:
            return OrderedDict([("hex", binascii.hexlify(data).decode()),
                                ("byte", -1), ("len", len(data))])
        if len(set(data)) == 1:
            return OrderedDict([("hex", ""), ("byte", data[0]),
                                ("len", len(data))])
        return OrderedDict([("hex", binascii.hexlify(data).decode()),
                            ("byte", -1), ("len", len(data))])

    def spec_packet(mtype, payload):
        return OrderedDict([("type", mtype),
                            ("payload_hex", binascii.hexlify(payload).decode()),
                            ("fill_byte", -1), ("fill_len", 0), ("fill_code", -1),
                            ("payload_len", len(payload))])

    def fill_packet(mtype, local, code, byte, count):
        if mtype == MSG_CHANNEL_DATA:
            payload_len = 4 + 4 + count
        else:
            payload_len = 4 + 4 + 4 + count
        return OrderedDict([("type", mtype), ("payload_hex", ""),
                            ("fill_byte", byte), ("fill_len", count),
                            ("fill_code", code), ("payload_len", payload_len)])

    def run(name, local, remote, packets, expect_error=None):
        win = LocalWindow()
        replies = []
        stdout = []
        stderr = []
        exit_status = -1
        adjusts = 0
        close_sent = False

        # A big DATA packet is carried as ("FILL", mtype, local, code, byte, n)
        # and expanded here, so the rest of the logic only ever sees bytes.
        # `specs` keeps the compact description for the output while `expanded`
        # holds the real bytes for the state machine.
        expanded = []
        specs = []
        for item in packets:
            if item[0] == "FILL":
                _, mtype, who, code, byte, count = item
                data = bytes(bytearray([byte]) * count)
                if mtype == MSG_CHANNEL_DATA:
                    payload = chan_data(who, data)
                else:
                    payload = chan_extended_data(who, code, data)
                expanded.append((mtype, payload))
                specs.append(fill_packet(mtype, who, code, byte, count))
            else:
                expanded.append(item)
                specs.append(spec_packet(item[0], item[1]))

        for mtype, payload in expanded:
            if mtype == MSG_CHANNEL_DATA:
                who = struct.unpack(">I", payload[0:4])[0]
                assert who == local, "server addressed channel %d, not %d" % (who, local)
                n = struct.unpack(">I", payload[4:8])[0]
                stdout.append(payload[8:8 + n])
                win.consume(n)
                amt = win.take_adjust()
                if amt is not None:
                    replies.append((MSG_CHANNEL_WINDOW_ADJUST,
                                    chan_window_adjust(remote, amt)))
                    adjusts += 1
            elif mtype == MSG_CHANNEL_EXTENDED_DATA:
                code = struct.unpack(">I", payload[4:8])[0]
                n = struct.unpack(">I", payload[8:12])[0]
                if code == SSH2_EXTENDED_DATA_STDERR:
                    stderr.append(payload[12:12 + n])
                    win.consume(n)
                    amt = win.take_adjust()
                    if amt is not None:
                        replies.append((MSG_CHANNEL_WINDOW_ADJUST,
                                        chan_window_adjust(remote, amt)))
                        adjusts += 1
                # channels.c:3585-3590 drops any other tcode before the string
                # is parsed, and touches no window state.
            elif mtype == MSG_CHANNEL_REQUEST:
                n = struct.unpack(">I", payload[4:8])[0]
                rtype = payload[8:8 + n]
                if rtype == b"exit-status":
                    off = 8 + n + 1
                    exit_status = struct.unpack(">I", payload[off:off + 4])[0]
                # exit-signal and friends: want_reply is FALSE, so no reply.
            elif mtype == MSG_CHANNEL_CLOSE:
                if not close_sent:
                    replies.append((MSG_CHANNEL_CLOSE, chan_bare(remote)))
                    close_sent = True
            # OPEN_CONFIRMATION / SUCCESS / EOF carry no client action here.

        return OrderedDict(
            [
                ("name", name),
                ("local_channel", local),
                ("remote_channel", remote),
                ("packets", specs),
                ("replies", [spec_packet(t, p) for t, p in replies]),
                ("stdout", summarize(b"".join(stdout))),
                ("stderr", summarize(b"".join(stderr))),
                ("exit_status", exit_status if exit_status >= 0 else 255),
                ("adjusts_sent", adjusts),
                ("final_cur", win.cur),
                ("error", expect_error),
            ]
        )

    def standard_tail(local, remote, status, extra=()):
        head = [
            (MSG_CHANNEL_OPEN_CONFIRMATION,
             open_confirmation(local, remote, 2097152, 32768)),
            (MSG_CHANNEL_SUCCESS, u32(local)),
        ]
        return head + list(extra) + [
            (MSG_CHANNEL_REQUEST, request(local, "exit-status", False, u32(status))),
            (MSG_CHANNEL_EOF, u32(local)),
            (MSG_CHANNEL_CLOSE, u32(local)),
        ]

    cases = [
        run("exec_ok", 0, 0, standard_tail(
            0, 0, 0, [(MSG_CHANNEL_DATA, chan_data(0, b"hello\n"))])),
        run("exec_nonzero_exit", 0, 0, standard_tail(
            0, 0, 42, [(MSG_CHANNEL_DATA, chan_data(0, b"partial"))])),
        # The recipient field of an inbound packet names *our* channel.  With
        # local != remote, an implementation that compares it against the peer
        # id rejects every packet.
        run("exec_nonzero_ids", 3, 7, standard_tail(
            3, 7, 0, [(MSG_CHANNEL_DATA, chan_data(3, b"hello\n"))])),
        run("exec_stderr", 0, 0, standard_tail(
            0, 0, 3, [
                (MSG_CHANNEL_DATA, chan_data(0, b"out\n")),
                (MSG_CHANNEL_EXTENDED_DATA,
                 chan_extended_data(0, SSH2_EXTENDED_DATA_STDERR, b"err\n")),
            ])),
        # 48 x 32 KiB = 1.5 MiB, well past the 2 MiB window's half point: this
        # is the shape that starves an implementation sending the wrong number.
        run("exec_bulk_window", 0, 0, standard_tail(
            0, 0, 0,
            [("FILL", MSG_CHANNEL_DATA, 0, -1, 0x41, CHAN_SES_PACKET_DEFAULT)]
            * 48)),
        # Our deliberate divergence from channels.c:3606 -- stderr counts
        # towards local_consumed, so a stderr-only flood still gets adjusted.
        run("exec_stderr_window", 0, 0, standard_tail(
            0, 0, 0,
            [("FILL", MSG_CHANNEL_EXTENDED_DATA, 0,
              SSH2_EXTENDED_DATA_STDERR, 0x45, CHAN_SES_WINDOW_DEFAULT // 2 + 8)])),
        run("exec_extdata_other", 0, 0, standard_tail(
            0, 0, 0, [
                (MSG_CHANNEL_DATA, chan_data(0, b"out\n")),
                (MSG_CHANNEL_EXTENDED_DATA, chan_extended_data(0, 2, b"otp\n")),
            ])),
        run("exec_exit_signal", 0, 0, [
            (MSG_CHANNEL_OPEN_CONFIRMATION, open_confirmation(0, 0, 2097152, 32768)),
            (MSG_CHANNEL_SUCCESS, u32(0)),
            (MSG_CHANNEL_DATA, chan_data(0, b"out\n")),
            (MSG_CHANNEL_REQUEST, request(0, "exit-signal", False,
                                          ssh_string("TERM")
                                          + SSH_BOOL_TRUE + ssh_string("bye")
                                          + b"\x00\x00\x00\x00\x00\x00\x00\x00"
                                          + ssh_string(""))),
            (MSG_CHANNEL_EOF, u32(0)),
            (MSG_CHANNEL_CLOSE, u32(0)),
        ]),
        run("exec_no_exit_status", 0, 0, [
            (MSG_CHANNEL_OPEN_CONFIRMATION, open_confirmation(0, 0, 2097152, 32768)),
            (MSG_CHANNEL_SUCCESS, u32(0)),
            (MSG_CHANNEL_DATA, chan_data(0, b"out\n")),
            (MSG_CHANNEL_EOF, u32(0)),
            (MSG_CHANNEL_CLOSE, u32(0)),
        ]),
    ]
    return cases


def build_document():
    """The whole vector set: constants, per-message builders, window plans,
    and full server->client session transcripts.

    `session_vectors` is the important one.  It runs a transcript through this
    file's own channel bookkeeping and records both what the client must send
    back and what it must end up with, so the MoonBit side is checked against a
    second independent implementation of the same rules rather than against
    itself.
    """
    return OrderedDict(
        [
            ("chan_packet_default", CHAN_SES_PACKET_DEFAULT),
            ("chan_window_default", CHAN_SES_WINDOW_DEFAULT),
            ("payloads", payload_vectors()),
            ("windows", window_vectors()),
            ("sessions", session_vectors()),
        ]
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--capture", action="store_true",
                    help="also cross-check against a live paramiko session")
    ap.add_argument("--port", type=int, default=22263)
    ap.add_argument("--user", default="hp")
    ap.add_argument("--key", default=None, help="test private key hex")
    args = ap.parse_args()

    key_hex = args.key
    if key_hex is None:
        for cand in (
            os.environ.get("LOOP_KEY_HEX"),
            "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
        ):
            if cand:
                key_hex = cand
                break

    if args.capture:
        captured = capture_paramiko(args.port, args.user, key_hex)
        if captured is None:
            print("ORACLE: could not capture a paramiko session", file=sys.stderr)
            return 2
        problems, saw_eof = compare_with_paramiko(captured, key_hex)
        if problems:
            print("ORACLE DISAGREEMENT with paramiko on the channel bytes",
                  file=sys.stderr)
            for p in problems:
                print("  " + p, file=sys.stderr)
            return 1
        print("paramiko channel bytes agree: %d packets captured%s"
              % (len(captured), "" if saw_eof else " (no EOF this run)"))

    doc = build_document()

    if args.json:
        print(json.dumps(doc))
        return 0

    print("CHAN_SES_PACKET_DEFAULT %d" % CHAN_SES_PACKET_DEFAULT)
    print("CHAN_SES_WINDOW_DEFAULT  %d" % CHAN_SES_WINDOW_DEFAULT)
    print("--- payloads ---")
    for p in doc["payloads"]:
        print("%-10s open=%s" % (p["name"], p["open_hex"][:60]))
    print("--- window adjustments ---")
    for c in doc["windows"]:
        amounts = [a["bytes"] for a in c["adjusts"]]
        print("%-18s packets=%-5d adjusts=%-3d amounts=%s"
              % (c["name"], len(c["sizes"]), len(amounts),
                 amounts[:8] + (["..."] if len(amounts) > 8 else [])))
    return 0


if __name__ == "__main__":
    sys.exit(main())