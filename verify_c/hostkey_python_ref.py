#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop #11 — Hostkey 解析与签名验证 三盲参考(Python 侧)

Ed25519:cryptography 库固定 seed 生成(RFC 8032 确定性签名,向量可复现)。
wire 组包/解析独立实现(RFC 4251 string/mpint 规则),验签与库交叉。
RSA:手工构造良构 mpint(parse-only 用途,非真实密钥——如实注明)。
指纹:hashlib.sha256 + base64 nopad,对照 OpenSSH "SHA256:xxx" 形态。

输出:_hostkey_ref_out.txt(V1-V6),MoonBit 测试与 C harness 共同引用。
"""
import base64
import hashlib
import struct
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

MAX_SIGN_DATA_SIZE = 1 << 20
RSA_MIN_BITS = 1024
MAX_BIGNUM = 2048

# ---------------------------------------------------------------- wire 原语

def w_string(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b


def r_string(buf: bytes, off: int):
    (n,) = struct.unpack_from('>I', buf, off)
    if off + 4 + n > len(buf):
        raise ValueError('InvalidFormat')
    return buf[off + 4:off + 4 + n], off + 4 + n


def w_mpint(v: bytes) -> bytes:
    """v 为大端无符号值字节(已 trim);MSB set 时前缀 0x00(RFC 4251)。"""
    if v and (v[0] & 0x80):
        v = b'\x00' + v
    return w_string(v)


def trim_leading(v: bytes) -> bytes:
    i = 0
    while i < len(v) and v[i] == 0:
        i += 1
    return v[i:]


def bit_length_be(v: bytes) -> int:
    if not v:
        return 0
    return (len(v) - 1) * 8 + v[0].bit_length()


# ---------------------------------------------------------------- 密钥材料

SEED_A = bytes((0x11 * (i + 1)) & 0xFF for i in range(32))
SEED_B = bytes((0xA7 + 3 * i) & 0xFF for i in range(32))


def ed25519_keypair(seed: bytes):
    """cryptography 无直接 from_seed API;seed 即私钥标量。
    Ed25519PrivateKey.from_private_bytes(seed) 接受 32 字节 seed。"""
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes_raw()
    return pk, sk


PK_A, SK_A = ed25519_keypair(SEED_A)
PK_B, SK_B = ed25519_keypair(SEED_B)

MSG_MAIN = b'MoonBit Loop #11 hostkey verification probe'
SIG_A = SK_A.sign(MSG_MAIN)
# cryptography 的 Ed25519PublicKey.verify 失败时 raise InvalidSignature
try:
    Ed25519PublicKey.from_public_bytes(PK_A).verify(SIG_A, MSG_MAIN)
    _sig_ok = True
except Exception:
    _sig_ok = False
assert _sig_ok


def blob_ed25519(pk: bytes) -> bytes:
    assert len(pk) == 32
    return w_string(b'ssh-ed25519') + w_string(pk)


def sig_blob_ed25519(rs: bytes) -> bytes:
    return w_string(b'ssh-ed25519') + w_string(rs)


BLOB_A = blob_ed25519(PK_A)
BLOB_B = blob_ed25519(PK_B)
SIG_BLOB_A = sig_blob_ed25519(SIG_A)


def fingerprint_text(blob: bytes) -> str:
    dg = hashlib.sha256(blob).digest()
    return 'SHA256:' + base64.b64encode(dg).decode().rstrip('=')

# ---------------------------------------------------------------- RSA 构造
# parse-only:数值取自确定性伪随机流,保证 MSB 形态可控;非真实密钥。

def pseudo_bytes(n: int, tag: int) -> bytes:
    out = bytearray()
    x = tag * 2654435761 & 0xFFFFFFFF
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


N_2048 = bytes([0xC7]) + pseudo_bytes(255, 7)      # 2048-bit,MSB set → wire 需 0x00 前缀
E_65537 = b'\x01\x00\x01'
N_1024 = bytes([0xBF]) + pseudo_bytes(127, 9)      # 1024-bit 恰好合法
N_1023 = N_1024[1:]                                # 1016-bit(<1024,拒)
assert bit_length_be(N_2048) == 2048
assert bit_length_be(N_1024) == 1024
assert bit_length_be(N_1023) < 1024

BLOB_RSA_OK = w_string(b'ssh-rsa') + w_mpint(E_65537) + w_mpint(N_2048)
BLOB_RSA_1024 = w_string(b'ssh-rsa') + w_mpint(E_65537) + w_mpint(N_1024)
BLOB_RSA_SHORT = w_string(b'ssh-rsa') + w_mpint(E_65537) + w_mpint(N_1023)
BLOB_RSA_NEG = (w_string(b'ssh-rsa') + w_string(E_65537) +
                w_string(bytes([0x80]) + pseudo_bytes(200, 3)))   # MSB set 无前缀 → 负数拒
OVERLONG_N = b'\x00' + pseudo_bytes(2050 - 1, 11)  # raw_len==2050 > 2049 → TooLarge
BLOB_RSA_OVERLONG = (w_string(b'ssh-rsa') + w_string(E_65537) +
                     w_string(OVERLONG_N))
BLOB_RSA_2049ZERO = (w_string(b'ssh-rsa') + w_string(E_65537) +
                     w_string(b'\x00' + b'\x00' * 2048))           # ==2049 且首为 0 → 合法,trim 后空(n=0→too short)

# ---------------------------------------------------------------- 自检

CHECKS = []


def ok(name, cond):
    CHECKS.append((name, cond))
    print(('pass ' if cond else 'FAIL ') + name)


def selfcheck():
    # P1 独立解析器 round-trip
    name, rest_off = None, 0
    name, off = r_string(BLOB_A, 0)
    pk, off = r_string(BLOB_A, off)
    ok('P1a parse blob', name == b'ssh-ed25519' and pk == PK_A and off == len(BLOB_A))
    alg, off2 = r_string(SIG_BLOB_A, 0)
    rs, off2 = r_string(SIG_BLOB_A, off2)
    ok('P1b parse sig', alg == b'ssh-ed25519' and rs == SIG_A and off2 == len(SIG_BLOB_A))
    # P2 库级验签 + 篡改必败
    try:
        Ed25519PublicKey.from_public_bytes(PK_A).verify(SIG_A, MSG_MAIN)
        good = True
    except Exception:
        good = False
    bad_sig = bytearray(SIG_A)
    bad_sig[10] ^= 1
    try:
        Ed25519PublicKey.from_public_bytes(PK_A).verify(bytes(bad_sig), MSG_MAIN)
        bad_ok = False
    except Exception:
        bad_ok = True
    ok('P2 verify cross', good and bad_ok)
    # P3 mpint 往返:n_2048 wire 带 0x00 前缀
    rsa_name, o = r_string(BLOB_RSA_OK, 0)
    e_raw, o = r_string(BLOB_RSA_OK, o)
    n_raw, o = r_string(BLOB_RSA_OK, o)
    ok('P3a rsa e first + 257-byte wire n',
       rsa_name == b'ssh-rsa' and e_raw == b'\x00\x01\x00\x01'[:0] + E_65537 and
       len(n_raw) == 257 and n_raw[0] == 0 and bit_length_be(trim_leading(n_raw)) == 2048)
    ok('P3b short rejected by rule', bit_length_be(trim_leading(w_string(N_1023)[4:] )) < 1024)
    # P4 指纹形态:64+ 字符 base64 nopad
    fp = fingerprint_text(BLOB_A)
    ok('P4 fingerprint form', fp.startswith('SHA256:') and '=' not in fp and
       len(fp) == len('SHA256:') + 43)
    npass = sum(1 for _, c in CHECKS if c)
    print(f'\nSELF-CHECK: {npass}/{len(CHECKS)} passed')
    return npass == len(CHECKS)

# ---------------------------------------------------------------- KAT 输出


def emit_kats():
    L = []
    L.append('[V1 ed25519 key A]')
    L.append('blob_hex=' + BLOB_A.hex())
    L.append('pk_hex=' + PK_A.hex())
    L.append('fp_text=' + fingerprint_text(BLOB_A))
    L.append('')
    L.append('[V2 signature A over MSG_MAIN]')
    L.append('msg_hex=' + MSG_MAIN.hex())
    L.append('sigblob_hex=' + SIG_BLOB_A.hex())
    L.append('rs_hex=' + SIG_A.hex())
    L.append('')
    L.append('[V3 tampered variants of V2]')
    t_msg = bytearray(MSG_MAIN); t_msg[3] ^= 0x40
    t_rs = bytearray(SIG_A); t_rs[50] ^= 0x01
    L.append('msg_flip_hex=' + bytes(t_msg).hex() + ' expect=SignatureInvalid')
    L.append('rs_flip_hex=' + sig_blob_ed25519(bytes(t_rs)).hex() +
             ' expect=SignatureInvalid')
    L.append('wrongkey_hex=' + sig_blob_ed25519(SK_B.sign(MSG_MAIN)).hex() +
             ' note=signed by B, verify against A expect=SignatureInvalid')
    L.append('')
    L.append('[V4 malformed blobs]')
    L.append('empty: hex= expect=InvalidFormat')
    trunc = BLOB_A[:-3]
    L.append(f'truncated: hex={trunc.hex()} expect=InvalidFormat')
    nul_name = w_string(b'ssh-\x00ed25519')[:len(b'ssh-\x00ed25519')+3] + w_string(PK_A)
    # 直接构造:string(b'ssh-\x00ed25519') + string(pk)
    nul_name = w_string(b'ssh-\x00ed25519') + w_string(PK_A)
    L.append(f'nul_in_name: hex={nul_name.hex()} expect=InvalidFormat')
    L.append(f'unknown_type: hex={(w_string(b"foo-bar-baz") + w_string(PK_A)).hex()} '
             f'expect=UnsupportedType')
    L.append(f'cert_name: hex={(w_string(b"ssh-ed25519-cert-v01@openssh.com") + w_string(PK_A)).hex()} '
             f'expect=CertNotAllowed')
    L.append(f'ecdsa_name: hex={(w_string(b"ecdsa-sha2-nistp256") ).hex()} '
             f'expect=UnsupportedType')
    L.append(f'sk_name: hex={(w_string(b"sk-ssh-ed25519@openssh.com") + w_string(PK_A)).hex()} '
             f'expect=UnsupportedType')
    L.append(f'pk31: hex={(w_string(b"ssh-ed25519") + w_string(PK_A[:31])).hex()} '
             f'expect=InvalidFormat')
    L.append(f'pk33: hex={(w_string(b"ssh-ed25519") + w_string(PK_A + b"\x01")).hex()} '
             f'expect=InvalidFormat')
    L.append(f'trailing: hex={(BLOB_A + b"\xde\xad").hex()} expect=TrailingData')
    L.append('')
    L.append('[V5 rsa parse-only vectors]')
    L.append('rsa_ok: hex=' + BLOB_RSA_OK.hex() +
             f' e_hex={E_65537.hex()} nbits=2048')
    L.append('rsa_1024: hex=' + BLOB_RSA_1024.hex() + ' expect=Parsed')
    L.append('rsa_short: hex=' + BLOB_RSA_SHORT.hex() + ' expect=RsaModulusTooShort')
    L.append('rsa_negative: hex=' + BLOB_RSA_NEG.hex() + ' expect=BigNumNegative')
    L.append('rsa_overlong: hex=' + BLOB_RSA_OVERLONG.hex() + ' expect=BigNumTooLarge')
    L.append('rsa_2049zero: hex=' + BLOB_RSA_2049ZERO.hex() +
             ' expect=RsaModulusTooShort note=trim 后空 → 0 bits')
    L.append('')
    L.append('[V6 second key pair B]')
    L.append('blob_b_hex=' + BLOB_B.hex())
    L.append('sig_b_over_main_hex=' + sig_blob_ed25519(SK_B.sign(MSG_MAIN)).hex())
    L.append('fp_b_text=' + fingerprint_text(BLOB_B))

    out = '\n'.join(L) + '\n'
    with open(r'E:\src\moon\openssh_moonbit\verify_c\_hostkey_ref_out.txt',
              'w', encoding='utf-8') as fh:
        fh.write(out)
    print('KAT written to _hostkey_ref_out.txt')
    print(out)


if __name__ == '__main__':
    if not selfcheck():
        sys.exit(1)
    print()
    emit_kats()
