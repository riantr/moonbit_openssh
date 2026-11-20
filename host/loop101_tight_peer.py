#!/usr/bin/env python3
"""Loop #101's second witness: a peer with a TIGHT window and a TIGHT maximum
packet, so that the rule "the data is cut to the peer's limits" has something
to bite on.

## Why this exists

The rule the forward loop has to follow is RFC 4254 section 5.2: a server may
not send a peer more than the peer's window allows, and not in a packet bigger
than the peer's maximum packet.  The real `ssh.exe` advertises 2097152 and
32768 -- and this repository's own server cuts its packets at exactly the same
place, because `sd_chunk_size` clamps at 32768.  So against the real client
the rule is UNOBSERVABLE: a server that ignored the peer's maximum packet
would still send packets of at most 32768 bytes, and 32768 is what the real
client allows.

A gate that cannot see a rule cannot protect it.  So this script is a peer
that asks for LESS: paramiko lets the caller set the window and the maximum
packet of the channel it opens, and its lower bounds are 32768 and 4096.  With
a maximum packet of 4096, a server that honours the rule cuts its packets at
4096 and a server that ignores it sends whatever it read -- up to 32768 bytes
in one packet -- and the difference is visible in the bytes on the wire.

## What is measured

The size of every CHANNEL_DATA packet the server sends, taken from the
packets themselves: paramiko hands each one to `Channel._feed`, and the
remaining bytes of that message are the data of exactly one packet.  The
measurement is therefore a measurement of the wire, not of anything the server
says about itself.

The real server is measured the same way, with the same peer and the same
payload, so the two can be compared: the server this repository ships has to
cut its packets the way the real one does.

## Usage

    python host/loop101_tight_peer.py --port P --dest-port D \
        --key PATH --out-json OUT [--window N] [--max-packet N] [--bytes N]
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import paramiko

from ssh_user import ssh_user

# The sizes of the CHANNEL_DATA packets the server sent, in order.
#
# paramiko strips the channel number out of the message before handing it to
# `Channel._feed`, so what is left in the message is the string that carries
# the data: four bytes of length followed by the data itself.  `get_remainder`
# reads the bytes and puts the position back, so measuring here does not
# consume what the original handler is about to read.
PACKET_SIZES = []


_ORIGINAL_FEED = paramiko.Channel._feed


def _measure_feed(self, m):
    if isinstance(m, bytes):
        n = len(m)
    else:
        n = len(m.get_remainder())
    # What is left of the message is the STRING of the CHANNEL_DATA payload:
    # four bytes of length followed by the data.  The length prefix is not
    # data -- the peer's maximum packet is about the DATA, so the four bytes
    # are taken off before the size is compared with it.
    PACKET_SIZES.append(n - 4 if n >= 4 else n)
    return _ORIGINAL_FEED(self, m)


# Patching `Channel._feed` alone is NOT enough: paramiko's transport keeps a
# table of handlers that was built when the class body ran, and it holds the
# ORIGINAL function object -- so the patch would be measured by nobody and the
# count would come out zero.  The table is what the transport actually calls,
# so the table is what has to be replaced.
paramiko.Transport._channel_handler_table[paramiko.common.MSG_CHANNEL_DATA] = (
    _measure_feed
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--user", default=ssh_user())
    ap.add_argument("--dest-host", default="127.0.0.1")
    ap.add_argument("--dest-port", type=int, required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--out-json", required=True)
    ap.add_argument("--window", type=int, default=32768)
    ap.add_argument("--max-packet", type=int, default=4096)
    ap.add_argument("--bytes", type=int, default=100000)
    args = ap.parse_args()

    payload = bytes((i * 31 + 7) % 256 for i in range(args.bytes))

    transport = paramiko.Transport(("127.0.0.1", args.port))
    transport.connect(
        username=args.user,
        pkey=paramiko.ECDSAKey.from_private_key_file(args.key),
    )
    try:
        chan = transport.open_channel(
            "direct-tcpip",
            dest_addr=(args.dest_host, args.dest_port),
            src_addr=("127.0.0.1", 0),
            window_size=args.window,
            max_packet_size=args.max_packet,
            timeout=60,
        )
        # What the peer ACTUALLY asked for.  paramiko clamps both numbers to
        # its own lower bounds, and the clamped values are the ones that went
        # on the wire -- so the gate compares against what was really sent,
        # not against what was asked for.
        allowed = {
            "window": chan.in_window_size,
            "max_packet": chan.in_max_packet_size,
        }
        chan.settimeout(60)
        chan.sendall(payload)
        chan.shutdown_write()
        got = b""
        # The target echoes, so the number of bytes that come back is known:
        # read exactly that many and then close.  Reading until EOF would
        # wait for ever, because the target does not close its side -- the
        # server waits for the peer to close the channel, and the peer waits
        # for the server.
        while len(got) < len(payload):
            chunk = chan.recv(65536)
            if not chunk:
                break
            got += chunk
        chan.close()
    finally:
        transport.close()

    doc = {
        "port": args.port,
        "dest_port": args.dest_port,
        "sent": len(payload),
        "received": len(got),
        "sha256": hashlib.sha256(got).hexdigest(),
        "want_sha256": hashlib.sha256(payload).hexdigest(),
        "identical": got == payload,
        "allowed": allowed,
        "packets": PACKET_SIZES,
        "packet_count": len(PACKET_SIZES),
        "largest_packet": max(PACKET_SIZES) if PACKET_SIZES else 0,
    }
    with open(args.out_json, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1)
    print(
        "tight peer: sent=%d received=%d packets=%d largest=%d allowed=%d"
        % (
            doc["sent"],
            doc["received"],
            doc["packet_count"],
            doc["largest_packet"],
            allowed["max_packet"],
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
