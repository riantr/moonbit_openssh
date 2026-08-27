#!/usr/bin/env python3
"""Triple-blind cross-check: Python (cryptography lib) vs C and MoonBit.

For each RFC 8032 KAT vector:
  1. Derive keypair from seed
  2. Sign the message
  3. Print pk/sig hex for byte-exact comparison
"""
import sys
import subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

VECTORS = [
    {
        "name": "KAT0",
        "seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "pk_hex":   "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "msg_hex":  "",
        "sig_hex":  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "name": "KAT1",
        "seed_hex": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pk_hex":   "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "msg_hex":  "72",
        "sig_hex":  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "name": "KAT2",
        "seed_hex": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "pk_hex":   "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "msg_hex":  "af82",
        "sig_hex":  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
]


def python_keypair_from_seed(seed: bytes):
    """Replicate ed25519 seed->sk->pk derivation per RFC 8032 sec 5.1.6."""
    import hashlib
    h = hashlib.sha512(seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0]  &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    sk_bytes = bytes(seed) + bytes(a_bytes)  # 64-byte expanded sk
    # Build cryptography lib key from the 32-byte clamped scalar
    priv = Ed25519PrivateKey.from_private_bytes(bytes(a_bytes))
    pk = priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return sk_bytes, pk


def main():
    all_ok = True
    print("=== Python (cryptography library) RFC 8032 KAT verification ===")
    for v in VECTORS:
        seed = bytes.fromhex(v["seed_hex"])
        msg = bytes.fromhex(v["msg_hex"]) if v["msg_hex"] else b""

        # cryptography library: from_private_bytes() takes the raw 32-byte seed
        # and internally does SHA-512 + clamping + scalarmult_base.
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pk = priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        sig = priv.sign(msg)

        pk_hex = pk.hex()
        sig_hex = sig.hex()
        pk_ok = (pk_hex == v["pk_hex"])
        sig_ok = (sig_hex == v["sig_hex"])
        all_ok = all_ok and pk_ok and sig_ok
        print(f"{v['name']} pk={'OK' if pk_ok else 'MISMATCH'} sig={'OK' if sig_ok else 'MISMATCH'}")
        print(f"  Py_pk ={pk_hex}")
        print(f"  Py_sig={sig_hex}")

    print(f"PY_ALL_{'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
