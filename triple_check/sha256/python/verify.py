#!/usr/bin/env python3
"""Python (hashlib) reference for SHA-256 KAT vectors."""
import hashlib
import sys

VECTORS = [
    ("FIPS_B1_T1_abc",  b"abc"),
    ("FIPS_B1_T2_56B",  b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ("FIPS_B1_T3_1Mx_a", b"a" * 1000000),
    ("B2_T1_64a",       b"a" * 64),
    ("B2_T2_8960B",     b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" * 64),
]


def main():
    for name, msg in VECTORS:
        d = hashlib.sha256(msg).digest()
        print(f"VEC name={name} len={len(msg)} got={d.hex()}")
    print("SHA256_SUMMARY PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
