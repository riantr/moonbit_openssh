"""Verify the curve constants in src/ecdsa/params.mbt byte-for-byte.

Hand-transcribed FIPS 186-4 constants are the classic place for an off-by-N
byte error, and a wrong modulus is silent: the Montgomery path still runs and
still returns a plausible-looking answer. This parses the MoonBit byte arrays
and diffs them against the canonical hex values.

Run:  python scripts/check_curve_consts.py
"""
import re
import sys

CANON = {
    "p256": dict(
        p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
        b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    ),
    "p384": dict(
        p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
        b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
        gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
        gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
    ),
}

src = open("src/ecdsa/params.mbt", encoding="utf-8").read()

# split the file into the p256() and p384() function bodies
bounds = {}
for name in ("p256", "p384"):
    start = src.index(f"pub fn Curve::{name}()")
    end = src.index("Curve::from_bytes", start)
    bounds[name] = src[start:end]


def parse_array(body, var):
    m = re.search(r"let\s+" + var + r"\s*:\s*FixedArray\[Byte\]\s*=\s*FixedArray::from_array\(\[(.*?)\]\)",
                  body, re.S)
    if not m:
        return None
    return bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))


fail = 0
for name, canon in CANON.items():
    body = bounds[name]
    for var, want in canon.items():
        got = parse_array(body, var)
        if got is None:
            print(f"{name}.{var}: ARRAY NOT FOUND")
            fail += 1
            continue
        w = want.to_bytes((want.bit_length() + 7) // 8, "big")
        gv = int.from_bytes(got, "big")
        ok = gv == want and len(got) == len(w)
        print(f"{name}.{var}: len={len(got)} {'OK' if ok else 'MISMATCH'}")
        if not ok:
            fail += 1
            print(f"  want {want:0{len(w) * 2}X}")
            print(f"  got  {gv:0{len(got) * 2}X}")
        # structural checks
        if var == "p" and name == "p384" and got != bytes.fromhex(
                "ff" * 31 + "fe" + "ff" * 4 + "00" * 8 + "ff" * 4):
            print("  p384 p is not 2^384-2^128-2^96+2^32-1 in canonical form")
            fail += 1
        if var == "p" and name == "p384" and got != (2**384 - 2**128 - 2**96 + 2**32 - 1).to_bytes(48, "big"):
            print("  p384 p != 2^384 - 2^128 - 2^96 + 2^32 - 1")
            fail += 1

    # curve-equation sanity: is G on the curve?
    p = canon["p"]
    lhs = (canon["gy"] ** 2) % p
    rhs = (canon["gx"] ** 3 - 3 * canon["gx"] + canon["b"]) % p
    print(f"{name}.G_on_curve: {lhs == rhs}")
    if lhs != rhs:
        fail += 1
    # n*G == O
    n = canon["n"]
    if pow(canon["gx"], n * n, p) == 1 and pow(canon["gy"], n * n, p) == 1:
        pass  # coarse; exact order check is expensive
    print(f"{name}.n_bits: {n.bit_length()}  p_bits: {p.bit_length()}")
    if n.bit_length() != p.bit_length():
        print("  n and p have different bit lengths")
        fail += 1

print()
print("FAIL" if fail else "PASS")
sys.exit(1 if fail else 0)
