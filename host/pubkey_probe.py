#!/usr/bin/env python3
"""Authenticate to the loop's sshd with paramiko, using the same test key.

Purpose: isolate *whose* fault a USERAUTH_FAILURE is. If paramiko succeeds
with the key in authorized_keys, the sshd side is proven correct and any
failure on the MoonBit side is in the bytes we sign.

Also dumps the exact signed blob paramiko constructs, so it can be diffed
against the MoonBit one field by field.

Usage: python host/pubkey_probe.py --port 22259 [--user hp]
"""

import argparse
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import paramiko
from paramiko.auth_handler import AuthHandler

D_HEX = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"


def private_pem():
    sk = ec.derive_private_key(int(D_HEX, 16), ec.SECP256R1())
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def dump_signed_blob():
    """Capture the bytes paramiko signs for a publickey request."""
    captured = {}
    orig = AuthHandler._finalize_pubkey_algorithm

    def patched(self, data):
        msg = paramiko.Message()
        msg.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
        msg.add_string(self.username)
        msg.add_string(self.transport.get_username() and "ssh-connection" or "")
        msg.add_string("publickey")
        msg.add_boolean(True)
        msg.add_string("ecdsa-sha2-nistp256")
        msg.add_string(data)
        captured["blob"] = msg.asbytes()
        return orig(self, data)

    AuthHandler._finalize_pubkey_algorithm = patched
    return captured


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=22259)
    ap.add_argument("--user", default=os.environ.get("USERNAME", "hp"))
    ap.add_argument("--dump", help="write the captured signed blob here as hex")
    args = ap.parse_args()

    pem = private_pem()
    captured = dump_signed_blob()

    t = paramiko.Transport(("127.0.0.1", args.port))
    t.start_client(timeout=15)
    try:
        # paramiko 5.x reads the PEM in text mode (its BEGIN_TAG is a str
        # pattern), so raw bytes fail with a confusing TypeError deep inside
        # pkey._read_private_key.
        import io

        key = paramiko.ECDSAKey.from_private_key(io.StringIO(pem.decode("ascii")))
        t.auth_publickey(args.user, key)
        print("paramiko auth: SUCCESS as %s" % args.user)
        ok = True
    except paramiko.AuthenticationException as e:
        print("paramiko auth: FAILED %s" % e)
        ok = False
    finally:
        t.close()

    if "blob" in captured:
        print("paramiko signed_blob: %s" % captured["blob"].hex())
        if args.dump:
            with open(args.dump, "w", encoding="ascii") as f:
                f.write(captured["blob"].hex())
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
