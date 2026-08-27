"""Generate C expected[32] byte arrays for SHA-256 KAT vectors.

Single source of truth: hashlib.sha256(...).digest().
"""
import hashlib

VECTORS = [
    (b"abc", "FIPS_B1_T1_abc"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "FIPS_B1_T2_56B"),
    (b"a" * 1000000, "FIPS_B1_T3_1Mx_a"),
    (b"a" * 64, "B2_T1_64a"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" * 64, "B2_T2_8960B"),
]


def c_bytes(digest: bytes) -> str:
    return ",".join(f"0x{b:02x}" for b in digest)


for msg, name in VECTORS:
    d = hashlib.sha256(msg).digest()
    print(f"// SHA256({name!r}) len={len(msg)}")
    print(f"// {d.hex()}")
    print(f"{{ {c_bytes(d)} }},")
    print()
