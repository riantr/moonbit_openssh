#!/usr/bin/env python3
"""
Loop #9 triple-blind reference generator (curve25519-sha256@libssh.org KEX).

Generates:
  1. Shared-secret vectors (RFC 7748 section 6.1 Alice/Bob scalars)
     - both mpint branches: shared[0] >= 0x80 (prepend) and < 0x80
  2. Exchange hash H over fixed V_C/V_S/I_C/I_S/K_S/e/f/K
  3. Six derived session keys (KDF per OpenSSH kex.c derive_key)
  4. An ssh-ed25519 signature blob over H (cryptography Ed25519PrivateKey)
  5. The full REPLY wire packet (string(K_S)||string(f)||string(sig))

Rules followed verbatim from OpenSSH C sources:
  - sshbuf_put_bignum2_bytes: strip leading zeros; prepend 0x00 if MSB set;
    u32(len) big-endian prefix; all-zero -> empty (u32(0))
  - kex_gen_hash (kexgen.c): string(V_C)||string(V_S)||
    u32(|I_C|+1)||u8(20)||I_C || same for I_S ||
    string(K_S)||string(e)||string(f)|| K(mpint raw append) -> SHA256
  - derive_key (kex.c): K1 = H(K||H||letter||session_id);
    Kn = H(K||H||K1..Kn-1); take we_need bytes

All expected outputs COMPUTED here - nothing hand-copied.
"""
import hashlib
import struct

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

# RFC 7748 section 6.1 test scalars (hex, little-endian byte order as wire)
ALICE_SK = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
ALICE_PK = bytes.fromhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
BOB_SK   = bytes.fromhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
BOB_PK   = bytes.fromhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
SHARED   = bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')

assert not (SHARED[0] & 0x80), 'RFC7748 ss should exercise the no-prepend branch'


def x25519(sk: bytes, pk: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(sk)
    pub = X25519PublicKey.from_public_bytes(pk)
    return priv.exchange(pub)


def self_check_x25519():
    assert x25519(ALICE_SK, BOB_PK) == SHARED
    assert x25519(BOB_SK, ALICE_PK) == SHARED
    print('[self-check] X25519 == cryptography : OK')


# ------------------------------------------------------------ SSH wire bits

def put_u32(v: int) -> bytes:
    return struct.pack('>I', v)


def s_string(b: bytes) -> bytes:
    return put_u32(len(b)) + b


def mpint(v: bytes) -> bytes:
    """sshbuf_put_bignum2_bytes semantics."""
    i = 0
    while i < len(v) and v[i] == 0:
        i += 1
    stripped = v[i:]
    prepend = bool(stripped) and (stripped[0] & 0x80) != 0
    return put_u32(len(stripped) + (1 if prepend else 0)) + \
        (b'\x00' if prepend else b'') + stripped


def kex_gen_hash(vc, vs, ic, is_, ks_blob, e, f, ss_mpint) -> bytes:
    """kexgen.c:48 kex_gen_hash with SHA-256."""
    h = hashlib.sha256()
    h.update(s_string(vc))
    h.update(s_string(vs))
    # fake header: length covers the type byte itself (+1), type=20
    h.update(put_u32(len(ic) + 1))
    h.update(bytes([20]))
    h.update(ic)
    h.update(put_u32(len(is_) + 1))
    h.update(bytes([20]))
    h.update(is_)
    h.update(s_string(ks_blob))
    h.update(s_string(e))
    h.update(s_string(f))
    h.update(ss_mpint)          # raw append of encoded K buffer
    return h.digest()


def derive_key(letter: int, need: int, h: bytes, ss_mpint: bytes,
               session_id: bytes) -> bytes:
    """OpenSSH kex.c derive_key."""
    def sha(b):
        return hashlib.sha256(b).digest()
    k1 = sha(ss_mpint + h + bytes([letter]) + session_id)
    out = bytearray(k1)
    have = len(k1)
    while have < need:
        kn = sha(ss_mpint + h + bytes(out[:have]))
        out += kn
        have += len(kn)
    return bytes(out[:need])


def derive_all(h, ss_mpint, we_need, session_id=None):
    sid = session_id if session_id is not None else h
    return {
        'session_id': sid,
        'iv_ctos': derive_key(ord('A'), we_need, h, ss_mpint, sid),
        'iv_stoc': derive_key(ord('B'), we_need, h, ss_mpint, sid),
        'enc_ctos': derive_key(ord('C'), we_need, h, ss_mpint, sid),
        'enc_stoc': derive_key(ord('D'), we_need, h, ss_mpint, sid),
        'mac_ctos': derive_key(ord('E'), we_need, h, ss_mpint, sid),
        'mac_stoc': derive_key(ord('F'), we_need, h, ss_mpint, sid),
    }


# --------------------------------------------------------------- test data

V_C = b'SSH-2.0-MoonBitPort_1.0\r\n'      # 版本串含 CRLF(与真实协议一致)
V_S = b'SSH-2.0-OpenSSH_10.0\r\n'
# kexinit payload:type 字节之后的内容(C 里 kex->my/peer 的边界)
I_C = (b'\x00\x00\x00\x04curve25519-sha256\x00\x00\x00\x15ssh-ed25519,'
       b'ssh-rsa\x00\x00\x00\x41chacha20-poly1305@openssh.com,aes128-ctr')
I_S = I_S_VAL = (b'\x00\x00\x00\x04curve25519-sha256\x00\x00\x00\x15ssh-ed25519,'
                 b'ssh-rsa\x00\x00\x00\x41chacha20-poly1305@openssh.com,aes256-gcm@openssh.com')


def ed25519_hostkey(seed32: bytes):
    """返回 (pubkey_blob_KS, private_obj)。blob = string("ssh-ed25519")+string(pk)"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(seed32)
    pk = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    blob = s_string(b'ssh-ed25519') + s_string(pk)
    return blob, key


def emit_section_a():
    print('---- SECTION A: shared secrets ----')
    # A1: RFC 7748 6.1 (ss 首字节 0x4a 高位为 0 → mpint 无前置分支)
    assert x25519(ALICE_SK, BOB_PK) == SHARED
    print('A.tag       = rfc7748_6_1_alice_bob')
    print('A.e         =', ALICE_PK.hex())
    print('A.f         =', BOB_PK.hex())
    print('A.ss_raw    =', SHARED.hex())
    print('A.ss_mpint  =', mpint(SHARED).hex())
    # A2: 构造首字节高位为 1 的共享密钥(prepend 分支):
    # 固定搜索保证可复现;保持标量合法(clamp 由库处理)
    found = False
    for tweak in range(256):
        sk = bytearray(BOB_SK)
        sk[31] ^= tweak          # 翻转低位域比特改变结果点
        sk[0] |= 248             # 保持 RFC 7748 clamp 高三位
        sk[31] &= 127            # clamp 最高位
        sk = bytes(sk)
        try:
            ss = x25519(sk, ALICE_PK)
        except Exception:
            continue
        if (ss[0] & 0x80) != 0 and any(ss):
            print('A2.sk_bob   =', sk.hex())
            print('A2.f_alice  =', ALICE_PK.hex())
            print('A2.ss_raw   =', ss.hex())
            print('A2.ss_mpint =', mpint(ss).hex())
            print('A2.note     = prepend branch')
            found = True
            break
    assert found, 'no prepend-branch vector found'
    # A3: 全零共享密钥(X25519(any, zero_pub) == 0)→ 必须被拒绝
    # cryptography 在库层直接 raise(点校验失败)——同样是"拒绝"语义;
    # MoonBit/C 的 X25519 会算出全零再由 shared_key 层拒绝,路径不同结论相同。
    zero_pub = bytes(32)
    try:
        ss_zero = x25519(ALICE_SK, zero_pub)
        assert not any(ss_zero), 'zero pub must give zero ss'
    except ValueError:
        pass
    print('A3.zero_pk  =', zero_pub.hex())
    print('A3.sk       =', ALICE_SK.hex())
    print('A3.expect   = REJECT')


def emit_section_b():
    print('---- SECTION B: exchange hash + KDF (we_need=64) ----')
    host_seed = bytes(range(32))
    ks_blob, host_key = ed25519_hostkey(host_seed)
    e, f = ALICE_PK, BOB_PK
    ss_mpint = mpint(SHARED)

    h = kex_gen_hash(V_C, V_S, I_C, I_S, ks_blob, e, f, ss_mpint)
    keys = derive_all(h, ss_mpint, 64)

    print('B.vc        =', V_C.hex())
    print('B.vs        =', V_S.hex())
    print('B.ic        =', I_C.hex())
    print('B.is        =', I_S.hex())
    print('B.ks_blob   =', ks_blob.hex())
    print('B.e         =', e.hex())
    print('B.f         =', f.hex())
    print('B.ss_mpint  =', ss_mpint.hex())
    print('B.H         =', h.hex())
    for tag in ('session_id', 'iv_ctos', 'iv_stoc',
                'enc_ctos', 'enc_stoc', 'mac_ctos', 'mac_stoc'):
        print(f'B.{tag:<11} =', keys[tag].hex())

    # 变体:I_C 差一个字节 → H 必须不同(防输入漏字段)
    ic_mut = bytearray(I_C)
    ic_mut[-1] ^= 1
    h_mut = kex_gen_hash(V_C, V_S, bytes(ic_mut), I_S, ks_blob, e, f, ss_mpint)
    assert h_mut != h, 'mutating I_C must change H'
    print('[self-check] I_C mutation changes H : OK')

    # SECTION C:REPLY 包 + 签名
    print('---- SECTION C: reply packet + ssh-ed25519 signature ----')
    sig_raw = host_key.sign(h)             # 64B R||S over H
    sig_blob = s_string(b'ssh-ed25519') + s_string(sig_raw)
    reply = s_string(ks_blob) + s_string(f) + s_string(sig_blob)
    print('C.sig_raw   =', sig_raw.hex())
    print('C.sig_blob  =', sig_blob.hex())
    print('C.reply     =', reply.hex())

    # 坏形态:rs 截断成 63 字节 → parse 应拒绝
    bad_sig_blob = s_string(b'ssh-ed25519') + s_string(sig_raw[:-1])
    bad_reply = s_string(ks_blob) + s_string(f) + s_string(bad_sig_blob)
    print('C.bad_reply =', bad_reply.hex())


if __name__ == '__main__':
    print('=== Loop #9 KEX c25519 triple-blind reference ===')
    self_check_x25519()
    emit_section_a()
    emit_section_b()
    print('=== ALL SELF-CHECKS PASSED ===')
