#!/usr/bin/env python3
"""抓 paramiko 在**真实成功认证**中签的那串字节,用于和 MoonBit 端逐字段 diff。

host/pubkey_probe.py 里那份 dump 是在 AuthHandler._finalize_pubkey_algorithm 上
自己拼的 Message,pkblob 拼错了(只塞了 key type),不能当证据。本脚本改在
paramiko 真正组包的那一层 Transport._get_session_blob 上截获。

用法: python host/paramiko_blob_capture.py --port 22259 --user hp
"""
import argparse
import binascii
import io
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import paramiko

# RFC 6979 A.2.5 的 P-256 私钥
D_HEX = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"


def private_pem() -> bytes:
    sk = ec.derive_private_key(int(D_HEX, 16), ec.SECP256R1())
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def take_str(buf: bytes, off: int):
    n = int.from_bytes(buf[off:off + 4], "big")
    return buf[off + 4:off + 4 + n], off + 4 + n


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=22259)
    ap.add_argument("--user", default="hp")
    args = ap.parse_args()

    captured = {}

    orig = paramiko.auth_handler.AuthHandler._get_session_blob

    def patched(self, key, service, username, algorithm):
        blob = orig(self, key, service, username, algorithm)
        captured["session_id"] = bytes(self.transport.session_id)
        captured["signed_blob"] = bytes(blob)
        captured["keytype"] = algorithm
        captured["keyblob"] = key.asbytes()
        captured["service"] = service
        captured["user"] = username
        return blob

    paramiko.auth_handler.AuthHandler._get_session_blob = patched

    # 截签名:ECDSAKey.sign_ssh_data 的产物就是最终发出去的那个 string
    orig_sign = paramiko.ecdsakey.ECDSAKey.sign_ssh_data

    def patched_sign(self, data, algorithm=None):
        sig = orig_sign(self, data, algorithm)
        captured["sig_blob"] = bytes(sig)
        return sig

    paramiko.ecdsakey.ECDSAKey.sign_ssh_data = patched_sign

    pem = private_pem()
    key = paramiko.ECDSAKey.from_private_key(io.StringIO(pem.decode("ascii")))

    sock = None
    try:
        sock = __import__("socket").create_connection((args.host, args.port))
        t = paramiko.Transport(sock)
        t.start_client(timeout=15)
        t.auth_publickey(args.user, key)
        print("AUTH:", "SUCCESS" if t.is_authenticated() else "FAILED")
    except Exception as exc:  # noqa: BLE001 - 诊断脚本,异常也是证据
        print("AUTH: EXCEPTION", type(exc).__name__, exc)
        return 2
    finally:
        try:
            if sock is not None:
                sock.close()
        except Exception:  # noqa: BLE001
            pass

    sb = captured["signed_blob"]
    print("session_id :", binascii.hexlify(captured["session_id"]).decode())
    print("signed_blob:", binascii.hexlify(sb).decode())
    print("sig_blob   :", binascii.hexlify(captured["sig_blob"]).decode())
    print("keyblob    :", binascii.hexlify(captured["keyblob"]).decode())

    off = 0
    sid, off = take_str(sb, off)
    msg_type = sb[off]
    off += 1
    u, off = take_str(sb, off)
    svc, off = take_str(sb, off)
    method, off = take_str(sb, off)
    have_sig = sb[off]
    off += 1
    pkalg, off = take_str(sb, off)
    pkblob, off = take_str(sb, off)
    print("--- parsed ---")
    print("session_id == prefix :", sid == captured["session_id"], f"({len(sid)}B)")
    print("msg_type             :", msg_type)
    print("user                 :", u)
    print("service              :", svc)
    print("method               :", method)
    print("have_sig             :", have_sig)
    print("pkalg                :", pkalg)
    print("pkblob == keyblob    :", pkblob == captured["keyblob"])
    print("consumed / total     :", off, "/", len(sb))
    return 0


if __name__ == "__main__":
    sys.exit(main())