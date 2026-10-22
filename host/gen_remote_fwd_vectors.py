#!/usr/bin/env python3
"""Reference vectors for the `ssh -R` half of the forwarding protocol.

Loop #78 implements three things on the wire, and this file is the
**independent** account of what those three things must look like:

  1. the "tcpip-forward" GLOBAL_REQUEST payload,
  2. the CHANNEL_OPEN_CONFIRMATION payload (we answer the server's open),
  3. the CHANNEL_OPEN_FAILURE payload (we refuse one),
  4. how an inbound "forwarded-tcpip" CHANNEL_OPEN decodes.

Every byte here is produced by **paramiko's own encoder** (`paramiko.message.Message`),
and every decode is **paramiko's own decoder** (`Message.get_text` /
`get_int`). Paramiko shares no code with this repository, so agreement
between the two is evidence about the wire format rather than about our
encoder agreeing with itself.

The one vector that matters most is P1: it is the **exact payload a real
Win32-OpenSSH 8.0p1 server sent** (captured by `host/remote_fwd_capture.py`),
not something this file made up. It is the one that settles the question the
RFC leaves open -- the u32 in a forwarded-tcpip open is the **listening**
port, not the ephemeral port of the accepted connection.

Usage:
    python host/gen_remote_fwd_vectors.py
"""

import os
import sys

import paramiko
from paramiko.message import Message

# The exact bytes a real OpenSSH 8.0p1 server sent for a "forwarded-tcpip"
# channel open, on a forward the client had asked for with port 0.  The
# server allocated port 65113 (0xfe59) and the probe that triggered it came
# from 127.0.0.1:65114 (0xfe5a).
REAL_FORWARDED_TCPIP_OPEN = bytes.fromhex(
    "0000000f666f727761726465642d7463706970"  # string "forwarded-tcpip"
    "00000002"                                # uint32 sender channel = 2
    "00200000"                                # uint32 initial window = 2 MiB
    "00008000"                                # uint32 max packet = 32 KiB
    "00000000"                                # string host = "" (listen address)
    "0000fe59"                                # uint32 port = 65113 (the LISTEN port)
    "000000093132372e302e302e31"              # string originator ip = "127.0.0.1"
    "0000fe5a"                                # uint32 originator port = 65114
)

# A "direct-tcpip" open, for the other direction of the same layout.
DIRECT_TCPIP_OPEN = bytes.fromhex(
    "0000000c6469726563742d7463706970"        # string "direct-tcpip"
    "00000000"                                # uint32 sender channel = 0
    "00200000"                                # uint32 initial window
    "00008000"                                # uint32 max packet
    "0000000b6578616d706c652e636f6d"        # string host = "example.com"
    "0000c350"                                # uint32 port = 50000
    "0000000831302e302e302e31"                # string originator ip = "10.0.0.1"
    "00003039"                                # uint32 originator port = 12345
)

# A "session" open: no type-specific fields at all.
SESSION_OPEN = bytes.fromhex(
    "0000000773657373696f6e"                  # string "session"
    "00000000"                                # uint32 sender channel
    "00200000"                                # uint32 initial window
    "00008000"                                # uint32 max packet
)


def req(listen_host, listen_port):
    m = Message()
    m.add_string("tcpip-forward")
    m.add_boolean(True)
    m.add_string(listen_host)
    m.add_int(listen_port)
    return m.asbytes()


def confirm(recipient, sender, window, max_packet):
    m = Message()
    m.add_int(recipient)
    m.add_int(sender)
    m.add_int(window)
    m.add_int(max_packet)
    return m.asbytes()


def failure(recipient, reason, description, language):
    m = Message()
    m.add_int(recipient)
    m.add_int(reason)
    m.add_string(description)
    m.add_string(language)
    return m.asbytes()


def decode_open(raw):
    m = Message(raw)
    ctype = m.get_text()
    sender = m.get_int()
    window = m.get_int()
    max_packet = m.get_int()
    host = ""
    port = 0
    oip = ""
    oport = 0
    if ctype in ("forwarded-tcpip", "direct-tcpip"):
        host = m.get_text()
        port = m.get_int()
        oip = m.get_text()
        oport = m.get_int()
    return (ctype, sender, window, max_packet, host, port, oip, oport)


def main():
    out = []

    # The request. R1 asks for port 0 -- the case where the server's reply
    # carries an allocated port. R2 names a port, and R3 names an address.
    for label, host, port in (
        ("R1", "", 0),
        ("R2", "localhost", 23456),
        ("R3", "127.0.0.1", 65535),
    ):
        out.append("REQ %s %s" % (label, req(host, port).hex()))

    # The confirmation. C1 is the shape this client actually sends when the
    # server opens a channel: the recipient is the server's channel number and
    # the sender is ours.
    for label, r, s, w, mp in (
        ("C1", 2, 0, 2097152, 32768),
        ("C2", 0, 7, 64, 32),
        # 4294967295 encodes as 0xffffffff -- the "all ones" channel number.
        # The MoonBit side cannot write that literal (it is out of Int32
        # range) and uses -1 instead; reinterpret_as_uint turns -1 into
        # 0xffffffff, so the two encoders agree on the bytes.
        ("C3", 4294967295, 1, 0, 0),
    ):
        out.append("CONFIRM %s %s" % (label, confirm(r, s, w, mp).hex()))

    # The refusal. F1 is the message this client sends when the server opens a
    # channel it did not ask for.
    for label, r, reason, desc, lang in (
        ("F1", 2, 1, "unsupported channel type: x11", ""),
        ("F2", 0, 1, "forwarded channel does not match the requested listener", ""),
    ):
        out.append("FAIL %s %s" % (label, failure(r, reason, desc, lang).hex()))

    # The decode. P1 is the real server's bytes; P2 and P3 cover the other two
    # channel types with the same layout.
    for label, raw in (
        ("P1", REAL_FORWARDED_TCPIP_OPEN),
        ("P2", DIRECT_TCPIP_OPEN),
        ("P3", SESSION_OPEN),
    ):
        ctype, sender, window, max_packet, host, port, oip, oport = decode_open(raw)
        out.append(
            "PARSE %s %s %d %d %d %s %d %s %d"
            % (label, ctype, sender, window, max_packet, host, port, oip, oport)
        )

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
