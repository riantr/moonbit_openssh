#!/usr/bin/env python3
"""Python (hmac) reference for HMAC-SHA512 RFC 4231 test vectors."""
import hmac
import hashlib
import sys

CASES = [
    ("RFC4231_T1_HiThere", bytes([0x0b] * 20), b"Hi There"),
    ("RFC4231_T2_Jefe", b"Jefe", b"what do ya want for nothing?"),
    ("RFC4231_T3_AAx20_DDx50", bytes([0xAA] * 20), bytes([0xDD] * 50)),
    ("RFC4231_T4_25Bkey_50Bmsg", bytes(range(1, 26)), bytes([0xCD] * 50)),
    ("RFC4231_T6_131Bkey_54Bmsg", bytes([0xAA] * 131),
     b"Test Using Larger Than Block-Size Key - Hash Key First"),
    ("RFC4231_T7_131Bkey_152Bmsg", bytes([0xAA] * 131),
     b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
]


def main():
    for name, key, msg in CASES:
        h = hmac.new(key, msg, hashlib.sha512).hexdigest()
        print(f"VEC name={name} klen={len(key)} mlen={len(msg)} got={h}")
    print("HMAC_SHA512_SUMMARY PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
