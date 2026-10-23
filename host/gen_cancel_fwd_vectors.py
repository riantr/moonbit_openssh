#!/usr/bin/env python3
"""Reference vectors for the "cancel-tcpip-forward" request.

Loop #81 implements the third global request of the forwarding family, and
this file is the **independent** account of what it must look like on the
wire:

  1. the "tcpip-forward" GLOBAL_REQUEST payload (the thing being cancelled),
  2. the "cancel-tcpip-forward" GLOBAL_REQUEST payload,
  3. the bind-address normalisation both of them go through.

Every byte here is produced by **paramiko's own encoder**
(`paramiko.message.Message`), which shares no code with this repository, so
agreement between the two is evidence about the wire format rather than about
our encoder agreeing with itself.

The shape is taken from OpenSSH itself, not from the RFC alone:

  * `channels.c` sends "cancel-tcpip-forward" with `sshpkt_put_u8(ssh, 0)`
    -- the comment next to that line literally reads `/* want reply */` --
    followed by the bind address and the port.  Case C1 is that shape.
  * `channels.c` normalises the bind address through `channel_rfwd_bind_host`
    before sending: "" and "*" both become the empty string.

Usage:
    python host/gen_cancel_fwd_vectors.py
"""

import os
import sys

import paramiko
from paramiko.message import Message


def req(listen_host, listen_port):
    m = Message()
    m.add_string("tcpip-forward")
    m.add_boolean(True)
    m.add_string(listen_host)
    m.add_int(listen_port)
    return m.asbytes()


def cancel(listen_host, listen_port, want_reply):
    m = Message()
    m.add_string("cancel-tcpip-forward")
    m.add_boolean(want_reply)
    m.add_string(listen_host)
    m.add_int(listen_port)
    return m.asbytes()


def bind_host(listen_host):
    """OpenSSH's `channel_rfwd_bind_host`."""
    if listen_host is None:
        return "localhost"
    if listen_host == "" or listen_host == "*":
        return ""
    return listen_host


def main():
    out = []

    for label, host, port in (
        ("R1", "", 0),
        ("R2", "127.0.0.1", 0),
        ("R3", "127.0.0.1", 64337),
    ):
        out.append("REQ %s %s" % (label, req(host, port).hex()))

    # C1 is what OpenSSH's own client sends: want_reply = 0, so the server
    # answers with nothing at all.  C3/C4 cancel the forward R3 asked for.
    for label, host, port, want_reply in (
        ("C1", "", 0, False),
        ("C2", "", 0, True),
        ("C3", "127.0.0.1", 64337, False),
        ("C4", "127.0.0.1", 64337, True),
        ("C5", "localhost", 23456, True),
    ):
        out.append("CANC %s %s" % (label, cancel(host, port, want_reply).hex()))

    for label, host in (
        ("H1", ""),
        ("H2", "*"),
        ("H3", "127.0.0.1"),
    ):
        out.append("HOST %s %s" % (label, bind_host(host)))

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
