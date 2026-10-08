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
# Interactive session: pty-req / shell / window-change
#
# Layout is taken from the *client* side, because that is where it is written:
#   clientloop.c:2735-2748  channel_request_start(..., "pty-req", 1) then
#                           term, ws_col, ws_row, ws_xpixel, ws_ypixel,
#                           ssh_tty_make_modes()
#   clientloop.c:2763+      "shell", want_reply = 1
#   session.c:1847-1851     window-change: col, row, xpixel, ypixel, get_end
#   ttymodes.c:329-333      modes = put_u8(TTY_OP_END) then put_stringb(buf)
#                           -- the string wrapper is easy to forget, and without
#                           it the server reads the 4 length bytes as an opcode.
TTY_OP_END = 0
TTY_OP_ISPEED = 128
TTY_OP_OSPEED = 129

DEFAULT_TERM = "xterm-256color"
DEFAULT_COLS = 80
DEFAULT_ROWS = 24
DEFAULT_BAUD = 38400


def tty_modes(baud=DEFAULT_BAUD, end=True):
    """The modes string, exactly as ssh_tty_make_modes writes it."""
    out = bytearray([TTY_OP_ISPEED]) + struct.pack(">I", baud)
    out += bytearray([TTY_OP_OSPEED]) + struct.pack(">I", baud)
    if end:
        out.append(TTY_OP_END)
    return bytes(out)


def chan_pty_req(recipient, term=DEFAULT_TERM, cols=DEFAULT_COLS,
                 rows=DEFAULT_ROWS, width_px=0, height_px=0,
                 modes=None):
    """CHANNEL_REQUEST "pty-req" (RFC 4254 6.2 / clientloop.c:2735-2748)

    Columns come before rows on the wire.  Writing them the other way round
    still opens a perfectly valid pty with the dimensions transposed, which is
    exactly why the mistake survives review.
    """
    if modes is None:
        modes = tty_modes()
    return chan_request(
        recipient,
        "pty-req",
        True,
        ssh_string(term) + u32(cols) + u32(rows) + u32(width_px)
        + u32(height_px) + ssh_string(modes),
    )


def chan_shell(recipient):
    """CHANNEL_REQUEST "shell" (RFC 4254 6.5) -- no fields past the prefix."""
    return chan_request(recipient, "shell", True, b"")


def chan_window_change(recipient, cols=DEFAULT_COLS, rows=DEFAULT_ROWS,
                       width_px=0, height_px=0):
    """CHANNEL_REQUEST "window-change" (RFC 4254 6.7 / session.c:1847-1851)

    want_reply is FALSE and there is no modes string: the server does
    sshpkt_get_end right after the fourth u32 (:1851), so trailing bytes are a
    protocol error rather than something merely ignored.
    """
    return chan_request(
        recipient,
        "window-change",
        False,
        u32(cols) + u32(rows) + u32(width_px) + u32(height_px),
    )


def capture_paramiko_shell(port, user, key_hex, command="echo loop36\r\n",
                           term=DEFAULT_TERM, cols=DEFAULT_COLS,
                           rows=DEFAULT_ROWS, resize_to=(132, 43)):
    """Run a real pty + shell session through paramiko and record every packet.

    Returns a list of (msg_type, payload_hex) in send order, or None.
    """
    try:
        import io as _io
        import time as _time

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
        raw = data.asbytes() if hasattr(data, "asbytes") else bytes(data)
        if raw:
            sent.append((raw[0], binascii.hexlify(raw[1:]).decode()))
        return orig(self, data)

    paramiko.transport.Transport._send_user_message = patched
    server_took_pty = None
    try:
        t = paramiko.Transport(("127.0.0.1", port))
        t.start_client(timeout=15)
        t.auth_publickey(user, key)
        chan = t.open_session(timeout=15)
        chan.settimeout(20)
        chan.get_pty(term=term, width=cols, height=rows)
        server_took_pty = True
        chan.invoke_shell()
        _time.sleep(0.5)
        chan.resize_pty(width=resize_to[0], height=resize_to[1])
        chan.send(command.encode("ascii"))
        _time.sleep(1.0)
        while chan.recv_ready():
            chan.recv(4096)
        chan.send(b"exit\r\n")
        deadline = _time.time() + 10
        while _time.time() < deadline and not chan.exit_status_ready():
            if chan.recv_ready():
                chan.recv(4096)
            if chan.closed:
                break
        t.close()
    except Exception as exc:  # noqa: BLE001
        print("paramiko pty session failed: %s" % exc, file=sys.stderr)
        return None
    finally:
        paramiko.transport.Transport._send_user_message = orig
    return sent, server_took_pty


def compare_with_paramiko_shell(captured, term=DEFAULT_TERM,
                                cols=DEFAULT_COLS, rows=DEFAULT_ROWS):
    """Check the pty / shell / resize bytes against our own construction.

    pty-req is compared field by field, not blob for blob: paramiko sends an
    *empty* modes string where OpenSSH sends ISPEED/OSPEED/END, and both are
    legal (ttymodes.c:354 returns early on len == 0).  Comparing whole packets
    would have forced us to adopt paramiko's shape for no reason.
    """
    problems = []
    saw_open = saw_pty = saw_shell = saw_resize = False
    for msg_type, payload_hex in captured:
        payload = binascii.unhexlify(payload_hex)
        if msg_type == MSG_CHANNEL_OPEN:
            saw_open = True
        elif msg_type == MSG_CHANNEL_REQUEST:
            recipient = struct.unpack(">I", payload[0:4])[0]
            n = struct.unpack(">I", payload[4:8])[0]
            rtype = payload[8:8 + n]
            off = 8 + n
            want_reply = payload[off]
            off += 1
            if rtype == b"pty-req":
                ln = struct.unpack(">I", payload[off:off + 4])[0]
                got_term = payload[off + 4:off + 4 + ln]
                off += 4 + ln
                got_cols, got_rows, got_wpx, got_hpx = struct.unpack(
                    ">IIII", payload[off:off + 16])
                off += 16
                mlen = struct.unpack(">I", payload[off:off + 4])[0]
                modes = payload[off + 4:off + 4 + mlen]
                off += 4 + mlen
                if got_term != term.encode("ascii"):
                    problems.append("pty-req term %r != %r" % (got_term, term))
                elif (got_cols, got_rows, got_wpx, got_hpx) != (
                        cols, rows, 0, 0):
                    problems.append(
                        "pty-req size %r != %r" % (
                            (got_cols, got_rows, got_wpx, got_hpx),
                            (cols, rows, 0, 0)))
                elif want_reply != 1:
                    problems.append("pty-req want_reply is not TRUE")
                elif off != len(payload):
                    problems.append("pty-req has %d trailing bytes"
                                    % (len(payload) - off))
                elif modes not in (b"", tty_modes()):
                    problems.append("pty-req modes are neither empty nor "
                                    "OpenSSH's ISPEED/OSPEED/END")
                else:
                    saw_pty = True
            elif rtype == b"shell":
                if payload != chan_shell(recipient):
                    problems.append("shell request differs from our builder")
                else:
                    saw_shell = True
            elif rtype == b"window-change":
                c2, r2 = (cols, rows)
                if resize_to := (132, 43):
                    c2, r2 = resize_to
                if payload != chan_window_change(recipient, c2, r2, 0, 0):
                    problems.append("window-change differs from our builder")
                else:
                    saw_resize = True
            elif rtype == b"exec":
                problems.append("unexpected exec request in a shell session")
            else:
                problems.append("unexpected CHANNEL_REQUEST %r" % rtype)
        elif msg_type == MSG_CHANNEL_DATA:
            # stdin. Only echoed back to us, nothing to compare.
            pass
    if not saw_open:
        problems.append("no CHANNEL_OPEN captured from paramiko")
    if not saw_pty:
        problems.append("no pty-req captured from paramiko")
    if not saw_shell:
        problems.append("no shell request captured from paramiko")
    if not saw_resize:
        problems.append("no window-change captured from paramiko")
    return problems


def capture_paramiko_env(port, user, key_hex,
                         envs=(("LOOP37_TEST", "hello-loop37"),
                               ("LANG", "")),
                         stdin_payload=b"", command="echo loop37"):
    """Run a real `env` + stdin + shutdown_write session through paramiko.

    paramiko is the second implementation of these three packets:

      * `Channel.set_environment_variable` puts `MSG_CHANNEL_REQUEST`,
        remote_chanid, "env", **False**, name, value -- the same layout, from
        a codebase that never read our RFC notes.
      * `Channel.shutdown_write` sends `SSH_MSG_CHANNEL_EOF` with just the
        channel id.

    Returns a list of (msg_type, payload_hex) in send order, or None.
    """
    try:
        import io as _io
        import time as _time

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
        chan.update_environment(dict(envs))
        chan.exec_command(command)
        if stdin_payload:
            chan.sendall(stdin_payload)
        chan.shutdown_write()
        deadline = _time.time() + 15
        while _time.time() < deadline:
            if chan.recv_ready():
                chan.recv(65536)
            if chan.recv_stderr_ready():
                chan.recv_stderr(65536)
            if chan.exit_status_ready() or chan.closed:
                break
            _time.sleep(0.05)
        t.close()
    except Exception as exc:  # noqa: BLE001
        print("paramiko env session failed: %s" % exc, file=sys.stderr)
        return None
    finally:
        paramiko.transport.Transport._send_user_message = orig
    return sent


def compare_with_paramiko_env(captured, envs=(("LOOP37_TEST", "hello-loop37"),
                                             ("LANG", ""))):
    """Check env / stdin-data / EOF against our own construction.

    The env request is compared whole, unlike pty-req: there is exactly one
    legal shape for it, so any difference is a difference.  `want_reply` is
    the field that decides whether the server ever answers, and paramiko's own
    docstring calls the rejection "silent ... common client practice" -- a
    third independent source agreeing with RFC 4254 6.4.
    """
    problems = []
    want_envs = [chan_env(0, n, v) for n, v in envs]
    saw_envs = []
    saw_data = saw_eof = saw_exec = False
    for msg_type, payload_hex in captured:
        payload = binascii.unhexlify(payload_hex)
        if msg_type == MSG_CHANNEL_REQUEST:
            recipient = struct.unpack(">I", payload[0:4])[0]
            n = struct.unpack(">I", payload[4:8])[0]
            rtype = payload[8:8 + n]
            off = 8 + n + 1
            if rtype == b"env":
                ln = struct.unpack(">I", payload[off:off + 4])[0]
                name = payload[off + 4:off + 4 + ln]
                voff = off + 4 + ln
                vln = struct.unpack(">I", payload[voff:voff + 4])[0]
                value = payload[voff + 4:voff + 4 + vln]
                tail = voff + 4 + vln
                if tail != len(payload):
                    problems.append("env request has %d trailing bytes"
                                    % (len(payload) - tail))
                elif payload[8 + n] != SSH_BOOL_FALSE[0]:
                    problems.append("paramiko asked for a reply to env")
                else:
                    saw_envs.append((name.decode("utf-8", "replace"),
                                     value.decode("utf-8", "replace"), recipient))
            elif rtype == b"exec":
                saw_exec = True
        elif msg_type == MSG_CHANNEL_DATA:
            saw_data = True
        elif msg_type == MSG_CHANNEL_EOF:
            if payload != u32(struct.unpack(">I", payload[0:4])[0]):
                problems.append("channel EOF payload is not just a channel id")
            saw_eof = True
    got = [(n, v) for n, v, _r in saw_envs]
    if got != [tuple(e) for e in envs]:
        problems.append("paramiko sent env %r, we expected %r"
                        % (got, [tuple(e) for e in envs]))
    if not saw_exec:
        problems.append("no exec request captured from paramiko")
    if not saw_eof:
        problems.append("no CHANNEL_EOF captured from paramiko")
    return problems


def exit_signal_request(recipient, name, core_dumped, message,
                        language_tag=""):
    """What the *server* sends when the command died from a signal.

    RFC 4254 6.10: string signal name || boolean core dumped ||
    string language tag || string error message.  Four fields and no more --
    an extra blob here used to slip through because the client ignored
    exit-signal entirely, and the vector was never parsed by anything.
    """
    return chan_request(
        recipient,
        "exit-signal",
        False,
        ssh_string(name)
        + (SSH_BOOL_TRUE if core_dumped else SSH_BOOL_FALSE)
        + ssh_string(language_tag)
        + ssh_string(message),
    )


def chan_env(recipient, name, value):
    """CHANNEL_REQUEST "env" (RFC 4254 6.4 / clientloop.c:2700-2711)

    Three things have to be right, and all three fail *silently*:

      * `want_reply` is FALSE.  RFC 4254 section 6.4 says "No response is
        returned by the server", and the OpenSSH client sends
        `channel_request_start(ssh, id, "env", 0)` (clientloop.c:2706).  Set it
        to TRUE and the server answers CHANNEL_FAILURE whenever the name is not
        in `AcceptEnv` -- which is the default -- so every connection would
        carry one extra packet for no benefit.
      * The payload is exactly two strings.  `session_env_req` reads name, then
        value, then `sshpkt_get_end` (session.c:2042-2044).  A trailing field is
        a *fatal* parse error there, not something ignored.
      * It has to go out before exec/shell.  `session_input_channel_req` only
        dispatches "env" while `c->type == SSH_CHANNEL_LARVAL` (session.c:2175);
        afterwards the request is dropped without a word.
    """
    return chan_request(recipient, "env", False,
                        ssh_string(name) + ssh_string(value))


# --------------------------------------------------------------------------
# Send-side window clamping (channels.c:3085-3100)
#
#     if (len > c->remote_window)     len = c->remote_window;
#     if (len > c->remote_maxpacket)  len = c->remote_maxpacket;
#     if (len == 0)                    return 0;
#     ... send len bytes ...
#     sshbuf_consume(c->input, len);
#     c->remote_window -= len;
#
# Clamp, not error.  A length of zero is not a failure either -- it means "the
# peer has not made room yet", and the bytes stay in the buffer until a
# CHANNEL_WINDOW_ADJUST arrives.
# --------------------------------------------------------------------------
def run_stdin_plan(name, window, maxp, size, byte, adjusts):
    """Feed `size` bytes through the clamp, resuming on queued WINDOW_ADJUSTs.

    `adjusts` is the list of increments the peer hands back, in order.  They sit
    in a queue and are only consumed once the window runs dry -- which is what
    the real event loop does, since WINDOW_ADJUST arrives on the read path and
    the write path can do nothing but wait.

    Returns the packet sizes we emit plus what we ended up holding.
    """
    remote_window = window
    queue = list(adjusts)
    packets = []
    sent = 0
    stalls = 0
    consumed_adjusts = 0
    guard = 0
    while sent < size:
        n = min(size - sent, remote_window, maxp)
        if n <= 0:
            if queue:
                remote_window += queue.pop(0)
                consumed_adjusts += 1
                continue
            stalls += 1
            break
        packets.append(n)
        remote_window -= n
        sent += n
        guard += 1
        if guard > 1 << 20:
            raise AssertionError("stdin plan did not converge")
    return OrderedDict([
        ("name", name),
        ("window", window),
        ("max_packet", maxp),
        ("size", size),
        ("byte", byte),
        ("adjusts", list(adjusts)),
        ("packets", packets),
        ("sent", sent),
        ("stalls", stalls),
        ("consumed_adjusts", consumed_adjusts),
        ("leftover_adjusts", queue),
        ("eof", sent == size),
        ("final_window", remote_window),
    ])


def stdin_vectors():
    """Window-clamp plans, covering each branch of the clamp.

    The cases that matter:

      * `stdin_fits_one_packet` -- nothing is clamped.  A driver that *always*
        split at max_packet would produce one packet here too, so this case on
        its own cannot tell the two apart; `stdin_clamped_by_maxpacket` can.
      * `stdin_clamped_by_window` -- the window, not the packet limit, is what
        bites.  A client that only clamps to max_packet sends 32 KiB into a
        1000-byte window and gets disconnected by RFC 4254 5.2.
      * `stdin_window_exhausted` -- the resume path; without the WINDOW_ADJUST
        handling this never sends byte 65537.
      * `stdin_no_adjust_stalls` -- the zero-length branch.  It must report a
        stall rather than error out or, worse, "successfully" drop the rest.
      * `stdin_two_mib` -- the shape the real sshd test uses.
    """
    big = CHAN_SES_WINDOW_DEFAULT
    return [
        run_stdin_plan("stdin_empty", big, CHAN_SES_PACKET_DEFAULT, 0, 0x41, []),
        run_stdin_plan("stdin_fits_one_packet", big, CHAN_SES_PACKET_DEFAULT,
                       1000, 0x41, []),
        run_stdin_plan("stdin_exact_packet", big, CHAN_SES_PACKET_DEFAULT,
                       CHAN_SES_PACKET_DEFAULT, 0x41, []),
        run_stdin_plan("stdin_clamped_by_maxpacket", big,
                       CHAN_SES_PACKET_DEFAULT, 100000, 0x42, []),
        run_stdin_plan("stdin_clamped_by_window", 1000,
                       CHAN_SES_PACKET_DEFAULT, 5000, 0x43, []),
        run_stdin_plan("stdin_window_exhausted", 65536,
                       CHAN_SES_PACKET_DEFAULT, 200000, 0x44, [131072]),
        run_stdin_plan("stdin_no_adjust_stalls", 32768,
                       CHAN_SES_PACKET_DEFAULT, 65536, 0x45, []),
        run_stdin_plan("stdin_zero_window", 0, CHAN_SES_PACKET_DEFAULT,
                       100, 0x46, [65536]),
        run_stdin_plan("stdin_two_adjusts", 65536, 4096, 30000, 0x47,
                       [8192, 8192]),
        run_stdin_plan("stdin_two_mib", big, CHAN_SES_PACKET_DEFAULT,
                       3 * 1024 * 1024, 0x48, [2 * 1024 * 1024]),
    ]


def env_payload_vectors():
    """One entry per env request shape, for two channel-number sets.

    `env_want_reply_hex` is the negative control: the same request with
    `want_reply = TRUE`.  The KAT asserts our bytes are *not* that one, so the
    RFC section 6.4 "no response" decision is tested rather than merely asserted
    in a comment.
    """
    out = []
    for recipient in (0, 7):
        out.append(
            OrderedDict(
                [
                    ("name", "env_s%d" % recipient),
                    ("recipient", recipient),
                    ("var_name", "LOOP37_TEST"),
                    ("var_value", "hello-loop37"),
                    ("env_hex", binascii.hexlify(
                        chan_env(recipient, "LOOP37_TEST",
                                 "hello-loop37")).decode()),
                    ("env_want_reply_hex", binascii.hexlify(
                        chan_request(recipient, "env", True,
                                     ssh_string("LOOP37_TEST")
                                     + ssh_string("hello-loop37"))).decode()),
                    ("empty_value_env_hex", binascii.hexlify(
                        chan_env(recipient, "LANG", "")).decode()),
                    ("eof_hex", binascii.hexlify(u32(recipient)).decode()),
                ]
            )
        )
    return out


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


# A transcript with 48 x 32 KiB of DATA is 3 MiB of hex per copy, and the file
# was landing at 10 MB -- slow to parse on every backend and useless as a diff.
# A run of one repeated byte is described instead of spelled out, which keeps the
# exact length under test while storing ~20 bytes.
FILL_LIMIT = 4096


def summarize(data):
    """Describe a byte run: inline hex when small, else "len copies of byte"."""
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


def expand_fills(items):
    """Turn ("FILL", type, who, code, byte, n) entries into real packets.

    Returns (expanded, specs): the bytes the state machine runs on, and the
    compact descriptions that go into the vector file.
    """
    expanded = []
    specs = []
    for item in items:
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
    return expanded, specs


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

    # The compact-description helpers live at module level (summarize,
    # spec_packet, fill_packet, expand_fills) because shell_session_vectors()
    # needs them too.
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
        expanded, specs = expand_fills(packets)

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
                                          + SSH_BOOL_TRUE
                                          + ssh_string("")     # language tag
                                          + ssh_string("bye"))),  # error message
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


def shell_session_vectors():
    """Interactive-session transcripts, with the client's sends timed.

    Loop #35's model only recorded what the *state machine* produced.  An
    interactive session is mostly the opposite: the driver decides when to send
    pty-req, when (after the reply) to send shell, when to type at stdin.  So
    each client send carries the number of server packets it follows, and the
    test replays the script in order instead of only diffing the tail.
    """
    def run_shell(name, local, remote, script, exit_default=255):
        win = LocalWindow()
        replies = []
        client_sends = []
        stdout = []
        stderr = []
        exit_status = -1
        exit_signal = None
        successes = 0
        failures = 0
        adjusts = 0
        close_sent = False
        seen_server = 0
        packets = []

        # Client sends are timed by "how many server packets have I seen by the
        # time this goes out", so the driver under test replays the same order
        # rather than only diffing its tail.
        server_items = []
        for it in script:
            if it[0] == "send":
                continue
            server_items.append(it[1:] if it[0] == "srv" else it)
        expanded, specs = expand_fills(server_items)

        idx = 0
        for item in script:
            if item[0] == "send":
                replies.append((item[1], item[2]))
                client_sends.append(
                    OrderedDict([("after", seen_server),
                                 ("type", item[1]),
                                 ("payload_hex",
                                  binascii.hexlify(item[2]).decode())])
                )
                continue
            mtype, payload = expanded[idx]
            spec = specs[idx]
            idx += 1
            seen_server += 1
            packets.append(spec)
            if mtype == MSG_CHANNEL_DATA:
                who = struct.unpack(">I", payload[0:4])[0]
                assert who == local, "server addressed channel %d" % who
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
            elif mtype == MSG_CHANNEL_REQUEST:
                n = struct.unpack(">I", payload[4:8])[0]
                rtype = payload[8:8 + n]
                if rtype == b"exit-status":
                    off = 8 + n + 1
                    exit_status = struct.unpack(">I", payload[off:off + 4])[0]
                elif rtype == b"exit-signal":
                    # string signal name || boolean core || string lang ||
                    # string msg.  The name is ASCII ("TERM"), not a u32 --
                    # reading the length prefix as a number happened here and
                    # produced a signal "4" for a request that said "TERM".
                    # want_reply sits between the type and the fields, so the
                    # name's length starts one byte later than it looks.
                    off = 8 + n + 1
                    ln = struct.unpack(">I", payload[off:off + 4])[0]
                    exit_signal = payload[
                        off + 4:off + 4 + ln].decode("ascii", "replace")
            elif mtype == MSG_CHANNEL_SUCCESS:
                successes += 1
            elif mtype == MSG_CHANNEL_FAILURE:
                failures += 1
            elif mtype == MSG_CHANNEL_CLOSE:
                if not close_sent:
                    replies.append((MSG_CHANNEL_CLOSE, chan_bare(remote)))
                    close_sent = True

        return OrderedDict(
            [
                ("name", name),
                ("local_channel", local),
                ("remote_channel", remote),
                ("packets", packets),
                ("client_sends", client_sends),
                ("replies", [spec_packet(t, p) for t, p in replies]),
                ("stdout", summarize(b"".join(stdout))),
                ("stderr", summarize(b"".join(stderr))),
                ("exit_status", exit_status if exit_status >= 0
                 else exit_default),
                ("exit_signal", exit_signal),
                # shell_no_pty 只拿到 1 个 SUCCESS(pty 被拒)。把这个数交给
                # 向量,而不是让 KAT 写死 2 —— 写死的那个一开始就是错的。
                ("success_count", successes),
                ("failure_count", failures),
                ("adjusts_sent", adjusts),
                ("final_cur", win.cur),
            ]
        )

    def srv(mtype, payload):
        return ("srv", mtype, payload)

    def snd(mtype, payload):
        return ("send", mtype, payload)

    confirm = lambda l, r: srv(MSG_CHANNEL_OPEN_CONFIRMATION,
                               u32(l) + u32(r) + u32(2097152) + u32(32768))
    success = lambda l: srv(MSG_CHANNEL_SUCCESS, u32(l))
    failure = lambda l: srv(MSG_CHANNEL_FAILURE, u32(l))
    data = lambda l, b: srv(MSG_CHANNEL_DATA, chan_data(l, b))
    exit_status = lambda l, c: srv(
        MSG_CHANNEL_REQUEST, chan_request(l, "exit-status", False, u32(c)))
    exit_signal = lambda l, n, core, msg: srv(
        MSG_CHANNEL_REQUEST, exit_signal_request(l, n, core, msg))
    eof = lambda l: srv(MSG_CHANNEL_EOF, u32(l))
    close = lambda l: srv(MSG_CHANNEL_CLOSE, u32(l))

    def pty_send(l, term=DEFAULT_TERM, cols=DEFAULT_COLS, rows=DEFAULT_ROWS):
        return snd(MSG_CHANNEL_REQUEST,
                   chan_pty_req(l, term, cols, rows))

    def shell_send(l):
        return snd(MSG_CHANNEL_REQUEST, chan_shell(l))

    def stdin_send(l, b):
        return snd(MSG_CHANNEL_DATA, chan_data(l, b))

    def resize_send(l, c, r):
        return snd(MSG_CHANNEL_REQUEST, chan_window_change(l, c, r))

    cases = [
        # The canonical sequence: open, pty-req, wait for its SUCCESS, shell,
        # wait for its SUCCESS, type, read, exit.
        run_shell("shell_pty_ok", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, 2097152, 32768)),
            confirm(0, 0),
            pty_send(0),
            success(0),
            shell_send(0),
            success(0),
            stdin_send(0, b"echo loop36\r\n"),
            data(0, b"loop36\r\n"),
            exit_status(0, 0),
            eof(0),
            close(0),
        ]),
        # The server refuses the pty (no PTY in sshd_config, or -T). The client
        # must still get a shell: OpenSSH clears client_tty and carries on
        # (clientloop.c:2750 sets c->client_tty = 0 after the failed confirm).
        run_shell("shell_no_pty", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, 2097152, 32768)),
            confirm(0, 0),
            pty_send(0),
            failure(0),
            shell_send(0),
            success(0),
            stdin_send(0, b"echo nopty\r\n"),
            data(0, b"nopty\r\n"),
            exit_status(0, 0),
            eof(0),
            close(0),
        ]),
        # window-change gets no reply at all (session.c:1843 returns 1 without
        # writing anything). If the driver waited for a CHANNEL_SUCCESS here it
        # would hang forever, so the transcript simply continues.
        run_shell("shell_resize", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, 2097152, 32768)),
            confirm(0, 0),
            pty_send(0),
            success(0),
            shell_send(0),
            success(0),
            resize_send(0, 132, 43),
            stdin_send(0, b"echo resized\r\n"),
            data(0, b"resized\r\n"),
            exit_status(0, 0),
            eof(0),
            close(0),
        ]),
        # Killed rather than exited: exit-signal, no exit-status. A client that
        # only knows exit-status reports this as 255 with no explanation.
        run_shell("shell_exit_signal", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, 2097152, 32768)),
            confirm(0, 0),
            pty_send(0),
            success(0),
            shell_send(0),
            success(0),
            stdin_send(0, b"kill -TERM $$\r\n"),
            data(0, b"Terminated\r\n"),
            exit_signal(0, "TERM", False, "terminated"),
            eof(0),
            close(0),
        ]),
        # local != remote, same reason as exec_nonzero_ids in Loop #35.
        run_shell("shell_nonzero_ids", 3, 7, [
            snd(MSG_CHANNEL_OPEN, chan_open(3, 2097152, 32768)),
            confirm(3, 7),
            pty_send(3, "xterm", 100, 40),
            success(3),
            shell_send(3),
            success(3),
            stdin_send(3, b"x\r\n"),
            data(3, b"x\r\n"),
            exit_status(3, 0),
            eof(3),
            close(3),
        ]),
        # A pty banner is large and full of escapes, which is what drives the
        # window on an interactive channel.
        run_shell("shell_bulk_banner", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, 2097152, 32768)),
            confirm(0, 0),
            pty_send(0),
            success(0),
            shell_send(0),
            success(0),
            ("FILL", MSG_CHANNEL_DATA, 0, -1, 0x1b,
             CHAN_SES_WINDOW_DEFAULT // 2 + 8),
            exit_status(0, 0),
            eof(0),
            close(0),
        ]),
    ]
    return cases


def io_session_vectors():
    """env + stdin transcripts, with the client's sends timed.

    This is the model the KAT replays, so the order in here *is* the order the
    MoonBit driver must produce:

      1. actions the state machine emitted for the server packet just handled
         (a WINDOW_ADJUST of ours, or a CHANNEL_CLOSE),
      2. driver sends whose `after` has come due (CHANNEL_OPEN, env, exec),
      3. stdin, clamped by the remote window, repeated until it stalls,
      4. CHANNEL_EOF once stdin is drained.

    Step 3 after step 2 and both after step 1 is not a style choice: the
    transcripts differ only in the byte stream when the order changes, and a
    client that opened with EOF-before-data produces a stream the peer accepts
    and silently truncates.
    """
    def run_io(name, local, remote, script, stdin_size, stdin_byte,
               exit_default=255):
        win = LocalWindow()
        replies = []
        client_sends = []
        stdout = []
        stderr = []
        exit_status = -1
        adjusts = 0
        close_sent = False
        seen_server = 0
        packets = []
        successes = 0
        remote_window = 0
        remote_max_packet = 0
        remaining = stdin_size
        stdin_packets = 0
        stdin_sent = 0
        eof_sent = False

        server_items = []
        for it in script:
            if it[0] == "send":
                continue
            server_items.append(it[1:] if it[0] == "srv" else it)
        expanded, specs = expand_fills(server_items)

        # The client's own sends, each timed by how many server packets came
        # before it.  They are *not* emitted where they appear in the script:
        # the script interleaves them for readability ("open, confirm, env,
        # exec"), while on the wire every send due after packet N goes out in
        # one batch before stdin is fed.  Getting this wrong puts EOF between
        # CHANNEL_OPEN and the env request, which a peer accepts and then
        # quietly stops reading.
        scripted_items = []
        before = 0
        for it in script:
            if it[0] == "send":
                scripted_items.append((before, it[1], it[2]))
            else:
                before += 1

        def reply(mtype, payload):
            """Anything the client puts on the wire, in order.

            This is the list the KAT diffs against; it includes both the
            packets the state machine produced and the ones the driver decided
            to send, because the *interleaving* is what is under test.
            """
            replies.append(spec_packet(mtype, payload))

        def stdin_reply(who, byte, n):
            """A stdin CHANNEL_DATA, stored as `n` copies of one byte.

            Same trick the server-side fills use, and for the same reason: the
            window-resume case alone would otherwise put ~130 KB of hex per
            packet into a file that all four backends parse on every run.  What
            stays exact is the packet count, the byte count and the recipient
            channel -- and `payload_len` still pins the full rebuilt length, so
            the case is not quietly weakened.
            """
            replies.append(fill_packet(MSG_CHANNEL_DATA, who, -1, byte, n))

        idx = 0
        sidx = 0
        for item in server_items:
            mtype, payload = expanded[idx]
            spec = specs[idx]
            idx += 1
            seen_server += 1
            packets.append(spec)

            if mtype == MSG_CHANNEL_OPEN_CONFIRMATION:
                remote_window = struct.unpack(">I", payload[8:12])[0]
                remote_max_packet = struct.unpack(">I", payload[12:16])[0]
            elif mtype == MSG_CHANNEL_WINDOW_ADJUST:
                # This is the *peer's* window for our stdin, not our local
                # window.  Getting the two mixed up is the classic way to end
                # up with a client that can neither send nor receive.
                remote_window += struct.unpack(">I", payload[4:8])[0]
            elif mtype == MSG_CHANNEL_DATA:
                who = struct.unpack(">I", payload[0:4])[0]
                assert who == local, "server addressed channel %d" % who
                n = struct.unpack(">I", payload[4:8])[0]
                stdout.append(payload[8:8 + n])
                win.consume(n)
                amt = win.take_adjust()
                if amt is not None:
                    reply(MSG_CHANNEL_WINDOW_ADJUST,
                          chan_window_adjust(remote, amt))
                    adjusts += 1
            elif mtype == MSG_CHANNEL_EXTENDED_DATA:
                code = struct.unpack(">I", payload[4:8])[0]
                n = struct.unpack(">I", payload[8:12])[0]
                if code == SSH2_EXTENDED_DATA_STDERR:
                    stderr.append(payload[12:12 + n])
                    win.consume(n)
                    amt = win.take_adjust()
                    if amt is not None:
                        reply(MSG_CHANNEL_WINDOW_ADJUST,
                              chan_window_adjust(remote, amt))
                        adjusts += 1
            elif mtype == MSG_CHANNEL_REQUEST:
                n = struct.unpack(">I", payload[4:8])[0]
                rtype = payload[8:8 + n]
                if rtype == b"exit-status":
                    off = 8 + n + 1
                    exit_status = struct.unpack(">I", payload[off:off + 4])[0]
            elif mtype == MSG_CHANNEL_SUCCESS:
                successes += 1
            elif mtype == MSG_CHANNEL_CLOSE:
                if not close_sent:
                    reply(MSG_CHANNEL_CLOSE, chan_bare(remote))
                    close_sent = True

            # Step 2: every driver send that came due after this packet, in
            # the order it was scripted.
            while sidx < len(scripted_items) and scripted_items[sidx][0] <= seen_server:
                _after, stype, spayload = scripted_items[sidx]
                reply(stype, spayload)
                client_sends.append(
                    OrderedDict([("after", seen_server), ("type", stype),
                                 ("payload_hex",
                                  binascii.hexlify(spayload).decode())]))
                sidx += 1

            # Step 3: feed stdin, clamped.  A zero-length clamp just stops the
            # loop -- the bytes stay put until a later WINDOW_ADJUST.
            while remaining > 0:
                n = min(remaining, remote_window, remote_max_packet)
                if n <= 0:
                    break
                stdin_reply(remote, stdin_byte, n)
                remote_window -= n
                remaining -= n
                stdin_packets += 1
                stdin_sent += n
            # Step 4: EOF only once nothing is left buffered.
            if remaining == 0 and not eof_sent:
                reply(MSG_CHANNEL_EOF, u32(remote))
                eof_sent = True

        return OrderedDict(
            [
                ("name", name),
                ("local_channel", local),
                ("remote_channel", remote),
                ("packets", packets),
                ("client_sends", client_sends),
                ("replies", replies),
                ("stdin_size", stdin_size),
                ("stdin_byte", stdin_byte),
                ("stdin_packets", stdin_packets),
                ("stdin_sent", stdin_sent),
                ("stdin_remaining", remaining),
                ("eof_sent", eof_sent),
                ("stdout", summarize(b"".join(stdout))),
                ("stderr", summarize(b"".join(stderr))),
                ("exit_status", exit_status if exit_status >= 0
                 else exit_default),
                ("success_count", successes),
                ("adjusts_sent", adjusts),
                ("final_cur", win.cur),
                ("final_remote_window", remote_window),
            ]
        )

    def srv(mtype, payload):
        return ("srv", mtype, payload)

    def snd(mtype, payload):
        return ("send", mtype, payload)

    def confirm(l, r, win, maxp):
        return srv(MSG_CHANNEL_OPEN_CONFIRMATION,
                   u32(l) + u32(r) + u32(win) + u32(maxp))

    def success(l):
        return srv(MSG_CHANNEL_SUCCESS, u32(l))

    def adjust(l, n):
        return srv(MSG_CHANNEL_WINDOW_ADJUST, chan_window_adjust(l, n))

    def data(l, b):
        return srv(MSG_CHANNEL_DATA, chan_data(l, b))

    def exit_status(l, c):
        return srv(MSG_CHANNEL_REQUEST,
                   chan_request(l, "exit-status", False, u32(c)))

    def eof(l):
        return srv(MSG_CHANNEL_EOF, u32(l))

    def close(l):
        return srv(MSG_CHANNEL_CLOSE, u32(l))

    def env_send(l, name, value):
        return snd(MSG_CHANNEL_REQUEST, chan_env(l, name, value))

    big = CHAN_SES_WINDOW_DEFAULT
    maxp = CHAN_SES_PACKET_DEFAULT

    cases = [
        # The plain path: one env, no stdin, EOF straight away.  success_count
        # is 1, not 2: env carries want_reply=FALSE so the peer never answers
        # it.  A driver that waited for an env confirmation would hang here.
        run_io("io_env_no_stdin", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, big, maxp)),
            confirm(0, 0, big, maxp),
            env_send(0, "LOOP37_TEST", "hello-loop37"),
            snd(MSG_CHANNEL_REQUEST, chan_exec(0, "cat")),
            success(0),
            exit_status(0, 0),
            eof(0),
            close(0),
        ], 0, 0x41),
        # Two envs, in order, both before exec.  Catches a driver that sends
        # them after the exec request (the server drops those silently).
        run_io("io_env_two_vars", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, big, maxp)),
            confirm(0, 0, big, maxp),
            env_send(0, "LOOP37_TEST", "hello-loop37"),
            env_send(0, "LANG", ""),
            snd(MSG_CHANNEL_REQUEST, chan_exec(0, "cat")),
            success(0),
            exit_status(0, 0),
            eof(0),
            close(0),
        ], 0, 0x41),
        # local != remote, so every outbound recipient field is 7.
        run_io("io_env_nonzero_ids", 3, 7, [
            snd(MSG_CHANNEL_OPEN, chan_open(3, big, maxp)),
            confirm(3, 7, big, maxp),
            env_send(7, "LOOP37_TEST", "hello-loop37"),
            snd(MSG_CHANNEL_REQUEST, chan_exec(7, "cat")),
            success(3),
            exit_status(3, 0),
            eof(3),
            close(3),
        ], 0, 0x41),
        # Stdin that fits in the window: one packet, then EOF, then the output.
        run_io("io_stdin_small", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, big, maxp)),
            confirm(0, 0, big, maxp),
            snd(MSG_CHANNEL_REQUEST, chan_exec(0, "cat")),
            success(0),
            data(0, b"hello-loop37\n"),
            exit_status(0, 0),
            eof(0),
            close(0),
        ], 11, 0x41),
        # Window runs dry mid-stream.  The peer only tops it up after its first
        # WINDOW_ADJUST, so this is the case a client that sends one packet and
        # gives up on gets wrong.
        run_io("io_stdin_window_resume", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, big, maxp)),
            confirm(0, 0, 65536, maxp),
            snd(MSG_CHANNEL_REQUEST, chan_exec(0, "cat")),
            success(0),
            adjust(0, 65536),
            data(0, b"one\n"),
            exit_status(0, 0),
            eof(0),
            close(0),
        ], 100000, 0x42),
        # The peer advertises a zero window and only opens it after its first
        # packet.  The very first stdin_take must return nothing at all.
        run_io("io_stdin_zero_window", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, big, maxp)),
            confirm(0, 0, 0, maxp),
            snd(MSG_CHANNEL_REQUEST, chan_exec(0, "cat")),
            success(0),
            adjust(0, 4096),
            data(0, b"zero\n"),
            exit_status(0, 0),
            eof(0),
            close(0),
        ], 1000, 0x43),
        # The peer never tops the window up: stdin stalls with bytes still
        # buffered.  The session must still finish cleanly -- and the report
        # must show the shortfall rather than pretend everything went out.
        run_io("io_stdin_stalls", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, big, maxp)),
            confirm(0, 0, 1024, maxp),
            snd(MSG_CHANNEL_REQUEST, chan_exec(0, "cat")),
            success(0),
            data(0, b"partial\n"),
            exit_status(0, 0),
            eof(0),
            close(0),
        ], 5000, 0x44),
        # Full duplex in the other direction: the server fills *our* window with
        # more than one WINDOW_ADJUST's worth while our stdin is also flowing.
        # The trailing server chunk is the same byte as the fill on purpose --
        # a differently-shaped tail makes `summarize` fall back to inlining a
        # megabyte of hex, and the case is about the window, not the payload.
        run_io("io_stdin_and_bulk_output", 0, 0, [
            snd(MSG_CHANNEL_OPEN, chan_open(0, big, maxp)),
            confirm(0, 0, big, maxp),
            snd(MSG_CHANNEL_REQUEST, chan_exec(0, "cat")),
            success(0),
            ("FILL", MSG_CHANNEL_DATA, 0, -1, 0x1b, big // 2 + 8),
            adjust(0, big),
            ("FILL", MSG_CHANNEL_DATA, 0, -1, 0x1b, 64),
            exit_status(0, 0),
            eof(0),
            close(0),
        ], 4096, 0x45),
    ]
    return cases


def shell_payload_vectors():
    """One entry per interactive message, for two channel-number sets."""
    out = []
    for recipient in (0, 7):
        out.append(
            OrderedDict(
                [
                    ("name", "pty_s%d" % recipient),
                    ("recipient", recipient),
                    ("term", DEFAULT_TERM),
                    ("cols", DEFAULT_COLS),
                    ("rows", DEFAULT_ROWS),
                    ("width_px", 0),
                    ("height_px", 0),
                    ("modes_hex", binascii.hexlify(tty_modes()).decode()),
                    ("pty_req_hex", binascii.hexlify(
                        chan_pty_req(recipient)).decode()),
                    ("shell_hex", binascii.hexlify(
                        chan_shell(recipient)).decode()),
                    ("resize_cols", 132),
                    ("resize_rows", 43),
                    ("window_change_hex", binascii.hexlify(
                        chan_window_change(recipient, 132, 43)).decode()),
                    ("stdin_hex", binascii.hexlify(
                        chan_data(recipient, b"x\r\n")).decode()),
                    ("exit_signal_name", "TERM"),
                    ("exit_signal_core", False),
                    ("exit_signal_message", "terminated"),
                    ("exit_signal_hex", binascii.hexlify(
                        exit_signal_request(recipient, "TERM", False,
                                            "terminated")).decode()),
                ]
            )
        )
    return out


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
            ("shell_payloads", shell_payload_vectors()),
            ("shell_sessions", shell_session_vectors()),
            ("env_payloads", env_payload_vectors()),
            ("stdin_plans", stdin_vectors()),
            ("io_sessions", io_session_vectors()),
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

        pty = capture_paramiko_shell(args.port, args.user, key_hex)
        if pty is None:
            print("ORACLE: could not capture a paramiko pty session",
                  file=sys.stderr)
            return 2
        pty_sent, server_took_pty = pty
        if not server_took_pty:
            print("ORACLE: this sshd refused pty-req; the interactive "
                  "cross-check cannot run here", file=sys.stderr)
            return 2
        shell_problems = compare_with_paramiko_shell(pty_sent)
        if shell_problems:
            print("ORACLE DISAGREEMENT with paramiko on the pty/shell bytes",
                  file=sys.stderr)
            for p in shell_problems:
                print("  " + p, file=sys.stderr)
            return 1
        print("paramiko pty/shell bytes agree: %d packets captured"
              % len(pty_sent))

        envcap = capture_paramiko_env(args.port, args.user, key_hex)
        if envcap is None:
            print("ORACLE: could not capture a paramiko env session",
                  file=sys.stderr)
            return 2
        env_problems = compare_with_paramiko_env(envcap)
        if env_problems:
            print("ORACLE DISAGREEMENT with paramiko on the env/stdin bytes",
                  file=sys.stderr)
            for p in env_problems:
                print("  " + p, file=sys.stderr)
            return 1
        print("paramiko env/stdin bytes agree: %d packets captured"
              % len(envcap))

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