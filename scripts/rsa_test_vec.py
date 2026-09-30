#!/usr/bin/env python3
"""Generate RSA test vector for MoonBit cmd/rsa_test."""
import hashlib
from math import gcd
from secrets import randbits


def is_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        a = randbits(n.bit_length())
        a = a % (n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    while True:
        n = randbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


BITS = 256
p = gen_prime(BITS)
q = gen_prime(BITS)
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
assert gcd(e, phi) == 1
d = pow(e, -1, phi)

msg = b"hello"
h_bytes = hashlib.sha256(msg).digest()
prefix = bytes.fromhex("3031300d060960864801650304020105000420")

modulus_byte_len = (n.bit_length() + 7) // 8
T = prefix + h_bytes
PS_len = modulus_byte_len - 3 - len(T)
assert PS_len >= 8, f"PS_len too small: {PS_len}, modulus_byte_len={modulus_byte_len}"
EM = b"\x00\x01" + (b"\xff" * PS_len) + b"\x00" + T

m_int = int.from_bytes(EM, "big")
s_int = pow(m_int, d, n)
s_bytes = s_int.to_bytes(modulus_byte_len, "big")

m_prime_int = pow(s_int, e, n)
m_prime_bytes = m_prime_int.to_bytes(modulus_byte_len, "big")

print(f"# RSA-{BITS * 2}-bit test vector")
print(f"p = 0x{p:x}")
print(f"q = 0x{q:x}")
print(f"n = 0x{n:x}")
print(f"e = 0x{e:x}")
print(f"d = 0x{d:x}")
print(f"n_len_bytes = {modulus_byte_len}")
print(f"sig = {s_bytes.hex()}")
print(f"verify_match = {m_prime_bytes == EM}")
print(f"em_first16 = {EM.hex()[:16]}")
print(f"em_last16 = {EM.hex()[-16:]}")
print(f"hash_hex = {h_bytes.hex()}")


def bytes_to_moonlit(arr):
    parts = []
    for i in range(0, len(arr), 16):
        chunk = arr[i:i + 16]
        parts.append("    " + ", ".join(f"0x{b:02X}" for b in chunk))
    return "[\n" + ",\n".join(parts) + ",\n  ]"


print()
print("// MoonBit literals:")
n_b = n.to_bytes(modulus_byte_len, "big")
print(f"let n_bytes = FixedArray::from_array({bytes_to_moonlit(n_b)})")
e_b = e.to_bytes(3, "big")
print(f"let e_bytes = FixedArray::from_array([0x{e_b[0]:02X}, 0x{e_b[1]:02X}, 0x{e_b[2]:02X}])")
print(f"let sig_bytes = FixedArray::from_array({bytes_to_moonlit(s_bytes)})")