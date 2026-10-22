#!/usr/bin/env python3
"""Verify an SSH ECDSA signature blob against the public key in the request.

The agent path never signs anything itself: it carries a signature from the
agent to the server. That makes the signature the one piece of the agent path
that has to be judged by somebody other than us -- if the client put the
wrong bytes in front of the signature, the server would say "no" and the
client would report "publickey rejected", which is exactly what a client
that got the *key* wrong also reports.

So the gate does not ask the server to be the judge. It takes three hex
strings -- the bytes that were signed, the signature blob, and the public key
blob -- and checks the signature with `cryptography`, an implementation that
shares no code with this repository.

    python host/agent_sig_verify.py <signed_hex> <sig_hex> <pubkey_hex>

Exit code 0 and "OK" on success; non-zero and a reason on failure.
"""

import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)


def ssh_string(b):
    return len(b).to_bytes(4, "big") + b


class Reader(object):
    def __init__(self, buf):
        self.buf = buf
        self.off = 0

    def str(self, label):
        if self.off + 4 > len(self.buf):
            raise ValueError("%s: truncated length" % label)
        n = int.from_bytes(self.buf[self.off:self.off + 4], "big")
        self.off += 4
        if self.off + n > len(self.buf):
            raise ValueError("%s: truncated body" % label)
        out = self.buf[self.off:self.off + n]
        self.off += n
        return out

    def done(self, label):
        if self.off != len(self.buf):
            raise ValueError("%s: %d bytes left over" % (label, len(self.buf) - self.off))


def parse_pubkey(blob):
    """RFC 5656 section 3.1: string alg, string curve, string Q."""
    r = Reader(blob)
    alg = r.str("alg").decode("ascii")
    curve = r.str("curve").decode("ascii")
    point = r.str("Q")
    r.done("pubkey_blob")
    if alg != "ecdsa-sha2-nistp256":
        raise ValueError("unsupported key type %s" % alg)
    if curve != "nistp256":
        raise ValueError("unsupported curve %s" % curve)
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def parse_sig_blob(blob):
    """RFC 5656 section 3.1.2: string alg, string (mpint r || mpint s)."""
    r = Reader(blob)
    alg = r.str("alg").decode("ascii")
    inner = r.str("signature_blob")
    r.done("sig_blob")
    ir = Reader(inner)
    rb = ir.str("r")
    sb = ir.str("s")
    ir.done("signature_blob(inner)")
    # The mpint bodies are two's-complement big-endian with an optional sign
    # pad, so a leading 0x00 has to come off before they become integers.
    if rb[:1] == b"\x00":
        rb = rb[1:]
    if sb[:1] == b"\x00":
        sb = sb[1:]
    if not rb or not sb:
        raise ValueError("empty r or s")
    return alg, int.from_bytes(rb, "big"), int.from_bytes(sb, "big")


def main():
    if len(sys.argv) != 4:
        print("usage: agent_sig_verify.py <signed_hex> <sig_hex> <pubkey_hex>")
        return 2
    signed = bytes.fromhex(sys.argv[1])
    sig_blob = bytes.fromhex(sys.argv[2])
    pubkey_blob = bytes.fromhex(sys.argv[3])
    try:
        alg, r, s = parse_sig_blob(sig_blob)
        pub = parse_pubkey(pubkey_blob)
    except ValueError as exc:
        print("FAIL: %s" % exc)
        return 1
    if alg != "ecdsa-sha2-nistp256":
        print("FAIL: signature algorithm is %s" % alg)
        return 1
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        print("FAIL: the signature does not verify over the signed bytes (%s)" % exc)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
