#!/usr/bin/env python3
"""Pure-Python ChaCha20 (Bernstein/OpenSSH form) — reference for triple-blind.

Imports chacha20_ref.py (a 100-line pure-Python implementation of the
Bernstein chacha20 with OpenSSH state layout) and emits keystream for
the same KAT vectors as the C driver in main.c.

State layout (16 u32 words):
  state[0..3]   = constants ("expand 32-byte k" or "expand 16-byte k")
  state[4..11]  = key (256-bit = 8 words, 128-bit = 4 words + repeat)
  state[12..13] = counter (8B LE: low u32 @12, high u32 @13)
  state[14..15] = iv (8B LE: low u32 @14, high u32 @15)
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from chacha20_ref import chacha20_keystream  # noqa: E402


def main():
    cases = [
        # (name, key, kbits, iv, counter, n_bytes)
        ("K1_zero256_64B",     bytes(32), 256, bytes(8), bytes(8), 64),
        ("K2_0to31_64B",       bytes(range(32)), 256, bytes(8), bytes(8), 64),
        ("K3_128bit_iv55_16B",
         bytes((0xFF - i) for i in range(16)), 128,
         bytes([0x55] * 8), bytes(8), 16),
        # K4: counter as 8 LE bytes: low=0x00000001 (LE: 01 00 00 00), high=0
        ("K4_0to31_iv1_ctr1_16B",
         bytes(range(32)), 256,
         bytes([0, 0, 0, 0, 0, 0, 0, 1]),
         bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
         16),
        ("K5_AAx32_64B",       bytes([0xAA] * 32), 256, bytes(8), bytes(8), 64),
    ]
    for name, key, kbits, iv, ctr, n in cases:
        ks = chacha20_keystream(key, iv, ctr, n)
        print(f"VEC name={name} kbits={kbits} n={n} got={ks.hex()}")
    print("CHACHA20_SUMMARY OUTPUT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
