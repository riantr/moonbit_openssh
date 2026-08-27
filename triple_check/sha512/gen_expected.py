"""Generate C expected[64] byte arrays for SHA-512 KAT vectors.

Single source of truth: hashlib.sha512(...).digest().

Run: python gen_expected.py
Output: prints the C initializer expressions for the four FIPS / RFC vectors
        + the FIPS C.3 1M 'a' vector.
"""
import hashlib

VECTORS = [
    (b"abc",
     "abc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "56B"),
    (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "112B"),
    (b"abcdefghijklmnopqrstuvwxyz",
     "alpha"),
    (b"a" * 1000000,
     "1Mx_a"),
]


def c_bytes(digest: bytes) -> str:
    return ",".join(f"0x{b:02x}" for b in digest)


for msg, name in VECTORS:
    d = hashlib.sha512(msg).digest()
    print(f"// SHA512({name!r}) len={len(msg)}")
    print(f"// {d.hex()}")
    print(f"{{ {c_bytes(d)} }},")
    print()
