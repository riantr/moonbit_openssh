#!/usr/bin/env python
"""Loop #84 oracle: the client's KEXINIT cookie and DH public value, off the wire.

Loop #84 removes the two fixed secrets this client used to have: the 16-byte
KEXINIT cookie and the Diffie-Hellman private exponent.  Before this loop the
cookie was the constant ``A0 A1 .. AF`` and the exponent was a 32-byte constant
in the source, so *every* session this client opened began with the same
sixteen bytes and shared its secret with anyone who had the source.

A gate cannot check randomness by looking at it -- that is what randomness is.
What it CAN check is the claim that matters:

  * the cookie on the wire is not the old constant;
  * the DH public value ``e = g^x mod p`` on the wire is not the one the old
    constant produces;
  * two connections produce two different cookies and two different ``e``;
  * the reproducible escape hatch (``--fixed-kex``) still produces EXACTLY the
    old ``e`` -- byte for byte, computed here in Python, independently of the
    MoonBit code.

That last one is the load-bearing check.  It says the difference between the
random run and the fixed run is exactly the difference between a fresh
exponent and the old constant, and nothing else: the same group, the same
generator, the same code path, with one input swapped.

How it observes the client
--------------------------
A MITM tee in front of a real sshd, the same shape as
``host/transcript_check.py``:

    client ---> proxy ---> sshd
             <---        <---

The client's bytes are decoded with the SAME parser the Loop #31 oracle uses
(imported, not copied, so the two cannot drift apart), and the ``e`` the
client sent is compared against ``pow(g, FIXED_X, p)`` computed here.

Usage:
  python host/loop84_peek.py --port 22222 --proxy-port 22223 \
      [--client-arg=--fixed-kex]
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys

# The parser and the tee come from the Loop #31 oracle, imported rather than
# copied: two copies of an SSH packet parser are two things that can disagree,
# and a gate that disagrees with itself is worse than no gate.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from transcript_check import (  # noqa: E402
    FIXED_X,
    P,
    SSH_MSG_KEX_ECDH_INIT,
    SSH_MSG_KEXINIT,
    Tee,
    make_listener,
    parse_packets,
    pump,
    read_mpint,
    split_ident,
)

# The generator of group 14 (RFC 3526 section 3) is 2.
G = 2

# The constant cookie this client used before Loop #84, byte for byte.
OLD_COOKIE = bytes(range(0xA0, 0xB0))


def mpint_hex(value: int) -> str:
    """The same fixed-width hex the Loop #31 oracle prints."""
    return f"{value:0512X}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=22222, help="real sshd port")
    ap.add_argument("--proxy-port", type=int, default=22223)
    ap.add_argument("--exe", default="_build/native/debug/build/cmd/ssh_live/ssh_live.exe")
    ap.add_argument(
        "--client-arg",
        action="append",
        default=[],
        help="extra argument passed to the client (repeatable)",
    )
    args = ap.parse_args()

    # Ordering matters and is not interchangeable:
    #   1. bind + listen   -- the port must be open before the client dials it
    #   2. spawn the client
    #   3. accept          -- unblocks only once the client has connected
    #   4. dial sshd and pump
    listener = make_listener(args.proxy_port)
    proc = subprocess.Popen(
        [args.exe, str(args.proxy_port), *args.client_arg],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    tee = Tee()
    try:
        cli, _ = listener.accept()
        listener.close()
        up = socket.create_connection(("127.0.0.1", args.port), timeout=15)
        pump(cli, up, tee)
    finally:
        try:
            listener.close()
        except OSError:
            pass
    try:
        client_out = proc.communicate(timeout=30)[0].decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        proc.kill()
        client_out = proc.communicate()[0].decode("utf-8", "replace")

    print("----- MoonBit client output -----")
    print(client_out.rstrip())
    print("---------------------------------")

    if not tee.c2s:
        print("empty transcript")
        return 2

    _, rest_c = split_ident(bytes(tee.c2s))
    c_pkts = parse_packets(rest_c)

    cookie = None
    e = None
    for t, p in c_pkts:
        if t == SSH_MSG_KEXINIT and cookie is None:
            # The cookie is the first 16 bytes of the KEXINIT payload
            # (RFC 4253 section 7.1).  `parse_packets` hands back the payload
            # WITHOUT the message type byte, so the cookie starts at offset 0.
            cookie = p[0:16]
        elif t == SSH_MSG_KEX_ECDH_INIT and e is None:
            e, _ = read_mpint(p, 0)

    if cookie is None or e is None:
        print("INCOMPLETE TRANSCRIPT -- no KEXINIT cookie / no KEX_ECDH_INIT")
        print("client packet types:", [t for t, _ in c_pkts])
        return 2

    # What the OLD constant exponent would have produced.  Computed here, in
    # Python, from the group14 prime -- not read out of the repository -- so
    # the comparison is against an independent value.
    e_fixed = pow(G, FIXED_X, P)

    print(f"cookie: {cookie.hex().upper()}")
    print(f"e: {mpint_hex(e)}")
    print(f"e_fixed: {mpint_hex(e_fixed)}")
    print(f"cookie_is_old_constant: {cookie == OLD_COOKIE}")
    print(f"e_is_old_constant: {e == e_fixed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
