"""Triple-blind verification: MoonBit Ed25519 vs Python cryptography.

Runs the same test vectors through Python's cryptography (libsodium/OpenSSL-backed)
and prints hex values that can be compared byte-exact with MoonBit output.
Covers:
  1. RFC 8032 § 7.1 Tests 1-3 (same as OpenSSH regress tests)
  2. Random-ish message sign/verify roundtrip
  3. Tampered message rejection
  4. Wrong key rejection
"""
import binascii
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

def hx(b):
    return binascii.hexlify(b).decode()

def unhex(s):
    return binascii.unhexlify(s)

print("===== RFC 8032 SS 7.1 Test Vectors =====")
vectors = [
    ("Test 1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     ""),
    ("Test 2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "72"),
    ("Test 3", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "af82"),
]
for name, seed_hex, msg_hex in vectors:
    seed = unhex(seed_hex)
    msg = unhex(msg_hex) if msg_hex else b""
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes_raw()
    sig = sk.sign(msg)
    # verify roundtrip
    Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
    print(f"{name}:")
    print(f"  seed     = {seed_hex}")
    print(f"  pk       = {hx(pk)}")
    print(f"  msg      = {msg_hex or '(empty)'}")
    print(f"  sig      = {hx(sig)}")
    print(f"  verified = True")

print()
print("===== Tampered Message Rejection =====")
seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
sk = Ed25519PrivateKey.from_private_bytes(seed)
pk = sk.public_key().public_bytes_raw()

msg = bytes.fromhex("68656c6c6f20776f726c64")       # "hello world"
tampered = bytes.fromhex("68656c6c6f20576f726c64")  # "hello World"
sig = sk.sign(msg)
try:
    Ed25519PublicKey.from_public_bytes(pk).verify(sig, tampered)
    print("UNEXPECTED: tampered msg accepted")
except Exception:
    print("OK: tampered msg rejected")
print(f"  msg      = {hx(msg)}")
print(f"  tampered = {hx(tampered)}")
print(f"  sig      = {hx(sig)}")

print()
print("===== Wrong Public Key Rejection =====")
seed1 = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
seed2 = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
sk1 = Ed25519PrivateKey.from_private_bytes(seed1)
sk2 = Ed25519PrivateKey.from_private_bytes(seed2)
pk1 = sk1.public_key().public_bytes_raw()
pk2 = sk2.public_key().public_bytes_raw()
m2 = bytes.fromhex("68656c6c6f")  # "hello"
sig1 = sk1.sign(m2)
try:
    Ed25519PublicKey.from_public_bytes(pk2).verify(sig1, m2)
    print("UNEXPECTED: wrong pk accepted")
except Exception:
    print("OK: wrong pk rejected")
Ed25519PublicKey.from_public_bytes(pk1).verify(sig1, m2)
print("OK: correct pk accepted")
print(f"  pk1      = {hx(pk1)}")
print(f"  pk2      = {hx(pk2)}")

print()
print("===== Large Message (1024 bytes pattern 00..FF repeated) =====")
big = bytes(i & 0xFF for i in range(1024))
sks = Ed25519PrivateKey.from_private_bytes(seed)
sig_big = sks.sign(big)
Ed25519PublicKey.from_public_bytes(pk).verify(sig_big, big)
print(f"  sig(1024B) = {hx(sig_big)}")
print(f"  verified   = True")

print()
print("ALL PYTHON REFERENCE CHECKS PASS")
