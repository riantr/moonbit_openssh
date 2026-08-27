#!/usr/bin/env python3
"""
Loop #8 triple-blind reference generator (ChaCha20-Poly1305 AEAD).

Sections:
  A) RFC 8439 section 2.8.2 official KAT inputs -> ct/tag expected values,
     cross-checked against cryptography's own ChaCha20Poly1305 AEAD.
  B) OpenSSH chacha20-poly1305@openssh.com wrapper vectors:
     two-key layout, IV = BE64(seqnr), payload counter starts at 1,
     MAC input = hdr_ct || pay_ct (no pad16 / length suffixes).
     Emulated here with raw ChaCha20 (OpenSSL 16-byte-IV form) + Poly1305;
     MoonBit and the C harness must reproduce byte-for-byte.

All expected outputs are COMPUTED HERE (Loop #5/#6 rule: never hand-copy
expected values from RFC prose). Inputs may be quoted from specs.
"""
import hmac
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# ---------------------------------------------------------------- primitives

def chacha20_block_openssl(key32: bytes, ctr32: int, nonce12: bytes) -> bytes:
    """One ChaCha20 block via OpenSSL layout: iv16 = LE32(ctr32) || nonce12."""
    nonce16 = struct.pack('<I', ctr32 & 0xFFFFFFFF) + nonce12
    enc = Cipher(algorithms.ChaCha20(key32, nonce16), mode=None).encryptor()
    return enc.update(b'\x00' * 64)


def chacha20_xor_rfc(key32: bytes, nonce12: bytes, start_ctr: int, data: bytes) -> bytes:
    """RFC 8439 stream: 32-bit block counter starting at start_ctr."""
    out = bytearray()
    ctr = start_ctr
    for pos in range(0, len(data), 64):
        ks = chacha20_block_openssl(key32, ctr, nonce12)
        chunk = data[pos:pos + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr += 1
    return bytes(out)


def poly1305(key32: bytes, msg: bytes) -> bytes:
    # Poly1305 is HMAC-like one-time auth; implement inline to avoid
    # depending on the optional poly1305 module availability.
    # RFC 8439 section 2.5 reference implementation.
    P = (1 << 130) - 5

    def clamp(r):
        return r & 0x0ffffffc0ffffffc0ffffffc0fffffff

    r = int.from_bytes(key32[:16], 'little')
    r = clamp(r)
    s = int.from_bytes(key32[16:], 'little')
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b'\x01', 'little')
        acc = ((acc + n) * r) % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')


# sanity: our poly1305 must agree with cryptography's if importable
try:
    from cryptography.hazmat.primitives.poly1305 import Poly1305 as _CPoly
    _k = bytes(range(32))
    _m = b'the quick brown fox jumps over the lazy dog'
    _p = _CPoly(_k)
    _p.update(_m)
    assert _p.finalize() == poly1305(_k, _m), "poly1305 self-check failed"
    print("[self-check] inline poly1305 == cryptography.Poly1305 : OK")
except ImportError:
    print("[self-check] cryptography.Poly1305 unavailable, inline impl unverified "
          "(still validated against MoonBit/C)")


# ------------------------------------------------- A) RFC 8439 core AEAD

def pad16(data: bytes) -> bytes:
    r = len(data) % 16
    return b'\x00' * ((16 - r) if r else 0)


def aead_mac_data(aad: bytes, ct: bytes) -> bytes:
    return (aad + pad16(aad) + ct + pad16(ct)
            + struct.pack('<QQ', len(aad), len(ct)))


def aead_poly_key(key32: bytes, nonce12: bytes) -> bytes:
    # RFC 8439 2.6: one-time Poly1305 key = ChaCha20 block counter 0
    return chacha20_block_openssl(key32, 0, nonce12)[:32]


def rfc8439_encrypt(key32, nonce12, aad, pt):
    pk = aead_poly_key(key32, nonce12)
    ct = chacha20_xor_rfc(key32, nonce12, 1, pt)
    tag = poly1305(pk, aead_mac_data(aad, ct))
    return ct, tag


def rfc8439_decrypt(key32, nonce12, aad, ct, tag):
    pk = aead_poly_key(key32, nonce12)
    expect = poly1305(pk, aead_mac_data(aad, ct))
    if not hmac.compare_digest(expect, tag):
        return None
    return chacha20_xor_rfc(key32, nonce12, 1, ct)


def emit_section_a():
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex('070000004041424344454647')
    aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
          b"only one tip for the future, sunscreen would be it.")

    ct, tag = rfc8439_encrypt(key, nonce, aad, pt)

    # independent cross-check against cryptography's AEAD
    ref = ChaCha20Poly1305(key).encrypt(nonce, pt, aad)
    assert ref == ct + tag, "RFC8439 emulation disagrees with cryptography AEAD!"
    assert tag.hex() != '', 'sanity'
    # roundtrip self-test
    assert rfc8439_decrypt(key, nonce, aad, ct, tag) == pt
    # tamper self-test
    bad = bytearray(ct); bad[0] ^= 1
    assert rfc8439_decrypt(key, nonce, aad, bytes(bad), tag) is None
    print("[self-check] RFC8439 emulation == cryptography.ChaCha20Poly1305 : OK")

    print('---- SECTION A: RFC 8439 2.8.2 ----')
    print('A.key      =', key.hex())
    print('A.nonce    =', nonce.hex())
    print('A.aad      =', aad.hex())
    print('A.pt       =', pt.hex())
    print('A.ct       =', ct.hex())
    print('A.tag      =', tag.hex())

    # extra core-AEAD edge vectors (empty plaintext, empty aad)
    for name, aad2, pt2 in [
        ('A2', b'', pt),
        ('A3', aad, b''),
        ('A4', b'', b''),
    ]:
        ct2, tag2 = rfc8439_encrypt(key, nonce, aad2, pt2)
        ref2 = ChaCha20Poly1305(key).encrypt(nonce, pt2, aad2)
        assert ref2 == ct2 + tag2
        print(f'{name}.aad      =', aad2.hex())
        print(f'{name}.pt       =', pt2.hex())
        print(f'{name}.ct       =', ct2.hex())
        print(f'{name}.tag      =', tag2.hex())


# ------------------------------------- B) OpenSSH wire-format wrapper

def ssh_chacha_block(key32: bytes, seqnr: int, ctr64: int) -> bytes:
    """OpenSSH chacha.c state: IV=BE64(seqnr) at words [14..15],
    64-bit LE counter at [12..13]. Mapped onto OpenSSL iv16 form:
    state[13]=0, nonce12 = 00000000 || BE64(seqnr), ctr32 = low word."""
    seqbuf = struct.pack('>Q', seqnr)
    return chacha20_block_openssl(key32, ctr64 & 0xFFFFFFFF,
                                  b'\x00\x00\x00\x00' + seqbuf)


def ssh_xor_stream(key32: bytes, seqnr: int, start_ctr: int, data: bytes) -> bytes:
    out = bytearray()
    ctr = start_ctr
    for pos in range(0, len(data), 64):
        ks = ssh_chacha_block(key32, seqnr, ctr)
        chunk = data[pos:pos + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr += 1
    return bytes(out)


def ssh_poly_key(kmain: bytes, seqnr: int) -> bytes:
    """ChaCha20(K_main, IV=seqbuf, ctr=0) applied to 32 zero bytes."""
    return ssh_xor_stream(kmain, seqnr, 0, b'\x00' * 32)


def ssh_wrap_encrypt(key64: bytes, seqnr: int, header4: bytes, payload: bytes):
    kmain, khead = key64[:32], key64[32:]
    pk = ssh_poly_key(kmain, seqnr)
    hdr_ct = ssh_xor_stream(khead, seqnr, 0, header4)
    pay_ct = ssh_xor_stream(kmain, seqnr, 1, payload)
    tag = poly1305(pk, hdr_ct + pay_ct)
    return hdr_ct + pay_ct + tag


def ssh_wrap_decrypt(key64: bytes, seqnr: int, wrapped: bytes):
    kmain, khead = key64[:32], key64[32:]
    pk = ssh_poly_key(kmain, seqnr)
    body, tag = wrapped[:-16], wrapped[-16:]
    if not hmac.compare_digest(poly1305(pk, body), tag):
        return None
    hdr_pt = ssh_xor_stream(khead, seqnr, 0, body[:4])
    pay_pt = ssh_xor_stream(kmain, seqnr, 1, body[4:])
    return hdr_pt + pay_pt


def emit_section_b():
    print('---- SECTION B: OpenSSH chacha20-poly1305@openssh.com wrapper ----')
    key64 = bytes(range(64))  # 0x00..0x3F

    cases = [
        ('B1', 0,            b'\xde\xad\xbe\xef',
         b'hello chachapoly wrapper!'),
        ('B2', 0x11223344,   struct.pack('>I', 0x00000100),
         bytes((i * 7 + 11) & 0xFF for i in range(100))),  # crosses 64B blocks
        ('B3', 0xFFFFFFFF,   struct.pack('>I', 28),
         b'A' * 4),                                        # minimal payload
    ]
    for name, seqnr, hdr, payload in cases:
        wrapped = ssh_wrap_encrypt(key64, seqnr, hdr, payload)
        # roundtrip + tamper self-tests
        assert ssh_wrap_decrypt(key64, seqnr, wrapped) == hdr + payload
        bad = bytearray(wrapped); bad[len(wrapped) // 2] ^= 0x80
        assert ssh_wrap_decrypt(key64, seqnr, bytes(bad)) is None
        wrong_seq = ssh_wrap_encrypt(key64, seqnr ^ 1, hdr, payload)
        assert ssh_wrap_decrypt(key64, seqnr, wrong_seq) is None

        print(f'{name}.key64     =', key64.hex())
        print(f'{name}.seqnr     = {seqnr:#010x}')
        print(f'{name}.header4   =', hdr.hex())
        print(f'{name}.payload   =', payload.hex())
        print(f'{name}.wrapped   =', wrapped.hex())


if __name__ == '__main__':
    print('=== Loop #8 AEAD triple-blind reference (python/cryptography) ===')
    emit_section_a()
    emit_section_b()
    print('=== ALL SELF-CHECKS PASSED ===')
