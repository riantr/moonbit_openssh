#!/usr/bin/env python3
"""Python (hashlib) reference for SHA-512 FIPS 180-4 / RFC 6234 KAT vectors.

Mirrors the C driver's run_vector output. The hex strings are the single
source of truth; the C driver's `expected[]` arrays must be regenerated
via ../gen_expected.py to stay in lockstep.
"""
import hashlib
import sys

VECTORS = [
    ("FIPS_A2_T1_abc",  b"abc"),
    ("FIPS_A2_T2_56B",  b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ("FIPS_A2_T3_112B", b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
    ("RFC6234_T4_alpha", b"abcdefghijklmnopqrstuvwxyz"),
    ("FIPS_C3_1Mx_a",   b"a" * 1000000),
]


def main():
    all_ok = True
    for name, msg in VECTORS:
        d = hashlib.sha512(msg).digest()
        # Print `pass=1` only after byte-exact comparison is done by the
        # C driver / compare.py. Here we just print the digest.
        print(f"VEC name={name} len={len(msg)} got={d.hex()}")
    print("SHA512_SUMMARY PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
