#!/usr/bin/env python3
"""独立校验 MoonBit 发出的 (r,s) 是否真的签了那段 signed_blob。

用法: python host/check_sig.py <signed_blob_hex> <sig_blob_hex>

这一步把「ECDSA 算术/哈希错了」和「session_id 与服务端不一致」彻底分开:
如果 cryptography 能验过,说明签名本身合法,问题就只可能在
「服务端用的 session_id 跟我们用的不是同一段字节」或者「签的字节序不同」。
"""
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature

# RFC 6979 A.2.5 / NIST P-256
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def read_string(buf: bytes, off: int):
    if off + 4 > len(buf):
        raise ValueError("truncated length")
    n = int.from_bytes(buf[off:off + 4], "big")
    off += 4
    if off + n > len(buf):
        raise ValueError("truncated body")
    return buf[off:off + n], off + n


def split_sig_blob(blob: bytes):
    """按 SSH ECDSA 签名 blob 的**正确**布局拆分:

        string key_type
        string (mpint r, mpint s)

    外层第二段是一整个 string 的包装,不是三个平级字段。少包一层时
    服务端会把 r 的长度前缀读成 r 本身,然后读 s 越界——失败点只表现为
    一个笼统的 "signature unverified"。
    """
    alg, o = read_string(blob, 0)
    body, o = read_string(blob, o)
    if o != len(blob):
        raise ValueError(
            f"sig blob has trailing data: consumed {o} of {len(blob)} bytes"
        )
    rb, ro = read_string(body, 0)
    sb, so = read_string(body, ro)
    if so != len(body):
        raise ValueError(
            f"inner signature_blob not fully consumed: {so} of {len(body)}"
        )
    return alg, int.from_bytes(rb, "big"), int.from_bytes(sb, "big")


def split_sig_blob_legacy(blob: bytes):
    """Loop #34 一度写成的样子:三个平级字段。留着是为了能给出明确报错。"""
    alg, o = read_string(blob, 0)
    rb, o = read_string(blob, o)
    sb, o = read_string(blob, o)
    if o == len(blob):
        raise ValueError("ok")
    return alg, int.from_bytes(rb, "big"), int.from_bytes(sb, "big")


def split_pubkey_blob(blob: bytes):
    kt, o = read_string(blob, 0)
    cn, o = read_string(blob, o)
    q, o = read_string(blob, o)
    assert o == len(blob)
    return kt, cn, q


def split_signed_blob(blob: bytes):
    """把 RFC 4252 §7 的签名输入拆成字段,便于逐项核对。"""
    sid, o = read_string(blob, 0)
    msg_type = blob[o]
    o += 1
    user, o = read_string(blob, o)
    svc, o = read_string(blob, o)
    method, o = read_string(blob, o)
    have_sig = blob[o]
    o += 1
    pkalg, o = read_string(blob, o)
    pkblob, o = read_string(blob, o)
    assert o == len(blob), f"signed blob trailing: {o} != {len(blob)}"
    return dict(session_id=sid, msg_type=msg_type, user=user, service=svc,
                method=method, have_sig=have_sig, pkalg=pkalg, pkblob=pkblob)


def point_on_curve(x: int, y: int) -> bool:
    return (y * y - (x * x * x + A * x + B)) % P == 0


def main() -> int:
    signed_hex = sys.argv[1]
    sig_hex = sys.argv[2]
    signed = bytes.fromhex(signed_hex)
    sigb = bytes.fromhex(sig_hex)

    fields = split_signed_blob(signed)
    print("=== signed_blob fields ===")
    print("  session_id :", fields["session_id"].hex(), f"({len(fields['session_id'])}B)")
    print("  msg_type   :", fields["msg_type"])
    print("  user       :", fields["user"])
    print("  service    :", fields["service"])
    print("  method     :", fields["method"])
    print("  have_sig   :", fields["have_sig"])
    print("  pkalg      :", fields["pkalg"])
    kt, cn, qb = split_pubkey_blob(fields["pkblob"])
    print("  pkblob.type:", kt)
    print("  pkblob.curv:", cn)
    print("  pkblob.Q   :", qb.hex())
    if qb[0] != 0x04 or len(qb) != 65:
        print("  !! Q 不是合法的 SEC1 未压缩点")
        return 2
    qx = int.from_bytes(qb[1:33], "big")
    qy = int.from_bytes(qb[33:65], "big")
    print("  Q on curve :", point_on_curve(qx, qy))

    alg, r, s = split_sig_blob(sigb)
    print("=== sig_blob ===")
    print("  alg        :", alg)
    print("  r          :", hex(r))
    print("  s          :", hex(s))
    print("  r,s < n   :", r < N and s < N)

    # 用 cryptography 验:MoonBit 声称的 Q 对 MoonBit 声称的签名、声称的字节。
    pub = ec.EllipticCurvePublicNumbers(qx, qy, ec.SECP256R1()).public_key()
    print("=== verify over raw to_sign bytes (no re-hash) ===")
    try:
        pub.verify(utils.encode_dss_signature(r, s), signed,
                   ec.ECDSA(hashes.SHA256()))
        print("  VERIFY OK  (hash = SHA256(to_sign))")
        ok = True
    except InvalidSignature:
        print("  VERIFY FAIL")
        ok = False

    print("=== verify over SHA256(to_sign) prehashed ===")
    import hashlib
    try:
        pub.verify(utils.encode_dss_signature(r, s),
                   hashlib.sha256(signed).digest(),
                   ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print("  VERIFY OK  (hash = SHA256(SHA256(to_sign)))")
    except InvalidSignature:
        print("  VERIFY FAIL")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())