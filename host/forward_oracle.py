#!/usr/bin/env python3
"""The second implementation for Loop #76: paramiko does the same direct-tcpip
transfer the MoonBit client does, through the same server, to the same target.

Why a second implementation at all: the MoonBit client and this script could
both be wrong in the same way, and a test that only compares them proves
nothing. What makes the comparison meaningful is that **paramiko is a
different implementation** of the same protocol -- its own encoder, its own
channel state machine, its own idea of what a direct-tcpip open looks like.
If both of them make the same request of the same server and get the same
bytes back, the request cannot be malformed in a way that only we share.

The key is the RFC 6979 A.2.5 test key, the same one `cmd/ssh_live` signs
with, derived here from the published scalar rather than read from a file.
It is a public key: RFC 6979 prints it in the clear. It must never be used
against anything but the loop's throwaway sshd.

Usage:
    python host/forward_oracle.py --port P --dest-host H --dest-port D \
        --payload-file F --out-json OUT
"""

import argparse
import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import paramiko

# RFC 6979 A.2.5 -- NIST P-256, published in the RFC.
D_HEX = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"


def test_private_key():
    priv = ec.derive_private_key(int(D_HEX, 16), ec.SECP256R1())
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--user", default="hp")
    ap.add_argument("--dest-host", default="127.0.0.1")
    ap.add_argument("--dest-port", type=int, required=True)
    ap.add_argument("--payload-file", required=True)
    ap.add_argument("--out-json", required=True)
    args = ap.parse_args()

    with open(args.payload_file, "rb") as fh:
        payload = fh.read()

    key_path = os.path.join(
        os.path.dirname(os.path.abspath(args.out_json)), "oracle_key"
    )
    with open(key_path, "wb") as fh:
        fh.write(test_private_key())

    transport = paramiko.Transport(("127.0.0.1", args.port))
    transport.connect(username=args.user, pkey=paramiko.ECDSAKey.from_private_key_file(key_path))
    try:
        chan = transport.open_channel(
            "direct-tcpip",
            dest_addr=(args.dest_host, args.dest_port),
            src_addr=("127.0.0.1", 0),
        )
        chan.sendall(payload)
        chan.shutdown_write()
        got = b""
        while True:
            chunk = chan.recv(65536)
            if not chunk:
                break
            got += chunk
        chan.close()
    finally:
        transport.close()

    doc = {
        "dest_host": args.dest_host,
        "dest_port": args.dest_port,
        "sent": len(payload),
        "received": len(got),
        "sha256": hashlib.sha256(got).hexdigest(),
        "hex": got.hex(),
        "identical": got == payload,
    }
    with open(args.out_json, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, indent=1)
    print("oracle: sent=%d received=%d sha256=%s" % (
        doc["sent"], doc["received"], doc["sha256"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
