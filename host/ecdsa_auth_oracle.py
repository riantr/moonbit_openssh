#!/usr/bin/env python3
"""Loop #34 KAT oracle: RFC 4252 section 7 publickey auth, ECDSA P-256.

Reference implementation for the client-auth path. MoonBit is checked against
this, so the constants here were never copied out of the MoonBit side.

Three independent opinions are reconciled before anything is emitted:

  1. RFC 6979 A.2.5 publishes, for NIST P-256 with SHA-256, the private key
     `x` *and* the resulting public point (Ux, Uy). That is an authoritative
     third source which knows nothing about either implementation here.
  2. `cryptography`'s ECDSA, which signs with an RFC 6979 deterministic nonce
     -- so the signature must be bit-identical to a correct RFC 6979
     implementation, not merely a valid one.
  3. MoonBit's `src/ecdsa`, via `cmd/userauth_test`.

Usage:
    python host/ecdsa_auth_oracle.py                # human-readable
    python host/ecdsa_auth_oracle.py --json         # JSON for the verifier
    python host/ecdsa_auth_oracle.py --authorized-keys OUT
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
from collections import OrderedDict

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

# RFC 6979 A.2.5 -- "Mysterious Curve" / NIST P-256, SHA-256.
# The RFC gives x, Ux and Uy. Using its own key means point derivation and
# RFC 6979 nonce generation are both checked against a published vector
# instead of against our own arithmetic.
D_HEX = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
UX_HEX = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
UY_HEX = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"

KEY_TYPE = b"ecdsa-sha2-nistp256"
CURVE_NAME = b"nistp256"

# A fixed session identifier so the signed blob is reproducible. In a real
# session this is H from the key exchange (kex.c:1137-1146).
SESSION_ID = bytes(range(0xA0, 0xC0))
USER = b"loop34"
SERVICE = b"ssh-connection"
SSH_MSG_USERAUTH_REQUEST = 0x32


def ssh_string(b):
    return len(b).to_bytes(4, "big") + b


def mpint(v):
    """SSH mpint (RFC 4251 section 5): two's complement, big-endian."""
    if v == 0:
        return b""
    raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return raw


def private_key():
    d = int(D_HEX, 16)
    return ec.derive_private_key(d, ec.SECP256R1())


def public_point():
    sk = private_key()
    nums = sk.public_key().public_numbers()
    return nums.x, nums.y


def pubkey_blob():
    """RFC 5656 section 3.1 public key blob.

        string  "ecdsa-sha2-nistp256"
        string  "nistp256"
        string  Q            <- ONE SEC1 octet string: 0x04 || X || Y

    Q is a single fixed-length string holding the uncompressed point, NOT two
    separate coordinate strings and NOT a pair of mpints. r/s in the signature
    blob are mpints; the public point is not. Getting this wrong produces a key
    that some servers accept and others reject with a bare "curve mismatch".

    Cross-checked against paramiko's ECDSAKey.asbytes() in check_against_paramiko.
    """
    x, y = public_point()
    point = b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return ssh_string(KEY_TYPE) + ssh_string(CURVE_NAME) + ssh_string(point)


def paramiko_blob():
    """The same blob, produced by paramiko -- an unrelated SSH implementation."""
    import io

    from paramiko import ECDSAKey

    sk = private_key()
    # TraditionalOpenSSL gives "BEGIN EC PRIVATE KEY" (SEC1, RFC 5915).
    # PKCS8 gives "BEGIN PRIVATE KEY", which paramiko 5.x's _read_private_key
    # does not recognise -- it only matches the algorithm-specific tag.
    pem = sk.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=NoEncryption(),
    )
    # paramiko 5.x's from_private_key matches its BEGIN_TAG against str, so the
    # PEM has to be handed over as text -- BytesIO fails with "cannot use a
    # string pattern on a bytes-like object".
    return ECDSAKey.from_private_key(io.StringIO(pem.decode("ascii"))).asbytes()


def signed_blob(session_id, user=USER):
    """RFC 4252 section 7: the data the client actually signs.

    Note this is session_id followed by the request *minus* the signature
    field -- the signature cannot be part of its own input.
    """
    return (
        ssh_string(session_id)
        + bytes([SSH_MSG_USERAUTH_REQUEST])
        + ssh_string(user)
        + ssh_string(SERVICE)
        + ssh_string(b"publickey")
        + b"\x01"  # boolean TRUE: the signature follows
        + ssh_string(KEY_TYPE)
        + ssh_string(pubkey_blob())
    )


def bits2int(b, qlen):
    x = int.from_bytes(b, "big")
    blen = len(b) * 8
    if blen > qlen:
        x >>= (blen - qlen)
    return x


def int2octets(v, rolen):
    return v.to_bytes(rolen, "big")


def bits2octets(b, q, qlen, rolen):
    z1 = bits2int(b, qlen)
    z2 = z1 - q
    return int2octets(z1 if z2 < 0 else z2, rolen)


def rfc6979_k(q, qlen, x, h1, hashfn, hlen):
    """RFC 6979 section 3.2 deterministic nonce.

    Written out here rather than delegated, because the whole point is to have
    an implementation that shares no code with the MoonBit side.

    This exists at all because `cryptography`'s ECDSA signer uses a RANDOM
    nonce -- three consecutive runs of this script produce three different (and
    equally valid) signatures for the same message. Comparing our signature to
    that byte for byte is therefore meaningless: every value is "correct" and
    none is reproducible. RFC 6979 determinism is what makes a signature
    comparable at all, and it has to be checked against the RFC's own published
    vectors plus an independent implementation of the algorithm.
    """
    rolen = (qlen + 7) // 8
    bx = int2octets(x, rolen)
    bh = bits2octets(h1, q, qlen, rolen)
    V = b"\x01" * hlen
    K = b"\x00" * hlen
    K = hmac.new(K, V + b"\x00" + bx + bh, hashfn).digest()
    V = hmac.new(K, V, hashfn).digest()
    K = hmac.new(K, V + b"\x01" + bx + bh, hashfn).digest()
    V = hmac.new(K, V, hashfn).digest()
    while True:
        T = b""
        while len(T) * 8 < qlen:
            V = hmac.new(K, V, hashfn).digest()
            T += V
        k = bits2int(T, qlen)
        if 1 <= k < q:
            return k
        K = hmac.new(K, V + b"\x00", hashfn).digest()
        V = hmac.new(K, V, hashfn).digest()


# NIST P-256 domain parameters, written out so point arithmetic below does not
# lean on any library's curve table.
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_A = P256_P - 3
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)


def pt_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0] and (p1[1] + p2[1]) % P256_P == 0:
        return None
    if p1 == p2:
        l = (3 * p1[0] * p1[0] + P256_A) * pow(2 * p1[1], P256_P - 2, P256_P) % P256_P
    else:
        l = (p2[1] - p1[1]) * pow(p2[0] - p1[0], P256_P - 2, P256_P) % P256_P
    x = (l * l - p1[0] - p2[0]) % P256_P
    return (x, (l * (p1[0] - x) - p1[1]) % P256_P)


def pt_mul(k, p):
    r = None
    while k:
        if k & 1:
            r = pt_add(r, p)
        p = pt_add(p, p)
        k >>= 1
    return r


def rfc6979_sign(msg, d):
    """Return (k, r, s) for ECDSA/SHA-256 over `msg` with private key `d`."""
    h1 = hashlib.sha256(msg).digest()
    qlen = 256
    k = rfc6979_k(P256_N, qlen, d, h1, hashlib.sha256, 32)
    R = pt_mul(k, P256_G)
    r = R[0] % P256_N
    z = bits2int(h1, qlen)
    s = pow(k, P256_N - 2, P256_N) * (z + r * d) % P256_N
    return k, r, s


def sign(msg):
    """RFC 6979 deterministic (r, s) as DER, via the arithmetic above."""
    _, r, s = rfc6979_sign(msg, int(D_HEX, 16))
    return encode_dss_signature(r, s)


def check_python_against_library(msg):
    """Our hand-rolled ECDSA must verify under `cryptography`.

    Without this the oracle is just a second implementation agreeing with the
    first -- two implementations of the same misunderstanding still agree. Let
    an unrelated library adjudicate the arithmetic, and keep RFC 6979 for the
    determinism.
    """
    sk = private_key()
    _, r, s = rfc6979_sign(msg, int(D_HEX, 16))
    der = encode_dss_signature(r, s)
    try:
        sk.public_key().verify(der, msg, ec.ECDSA(hashes.SHA256()))
    except Exception as exc:  # InvalidSignature and anything else
        raise SystemExit(
            "ORACLE DISAGREEMENT: our ECDSA does not verify under cryptography: %s" % exc
        )


def sig_blob(sig_der):
    """RFC 5656 section 3.1.2 signature blob.

    布局是**两个** string,第二个 string 里装 mpint r 和 mpint s:

        string key_type
        string signature_blob     (mpint r || mpint s)

    少包外面那层是最容易犯也最难查的错:mpint 的 wire 形式本身就是
    "长度前缀 + 字节",所以少了包装之后前 4 个字节会被对端当成 r 的长度,
    r 读成一坨巨数,再读 s 时缓冲已空。服务端只回一句
    "publickey ... signature unverified",和"公钥不在 authorized_keys 里"
    完全无法区分。

    权威依据:
      * ssh-ecdsa.c:431-432 ``sshbuf_get_cstring(b,&ktype) || sshbuf_froms(b,&sigbuf)``
      * paramiko ECDSAKey.sign_ssh_data: add_string(key_type) 之后
        add_string(self._sigencode(r, s)),而 _sigencode 才是两个 mpint
      * 本仓 src/hostkey/sig_verify.mbt:71-88(验主机签名,已对真 sshd 通过)
    """
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(sig_der)
    inner = ssh_string(mpint(r)) + ssh_string(mpint(s))
    return ssh_string(KEY_TYPE) + ssh_string(inner)


def request_payload(session_id, user=USER):
    """The full SSH_MSG_USERAUTH_REQUEST payload (with the signature)."""
    sig = sign(signed_blob(session_id, user))
    return (
        ssh_string(user)
        + ssh_string(SERVICE)
        + ssh_string(b"publickey")
        + b"\x01"
        + ssh_string(KEY_TYPE)
        + ssh_string(pubkey_blob())
        + ssh_string(sig_blob(sig))
    )


def mpint_needs_pad(v):
    """Does this mpint need a leading 0x00 to stay positive?

    r and s are ~256 bits wide, so roughly half of them have bit 255 set and
    need the prefix. A single test vector has a 25% chance of missing both,
    and the resulting signature still *verifies* against a lenient parser
    while being wrong on the wire -- so the cases below are chosen to cover it.
    """
    return v.bit_length() % 8 == 0 and (v >> (v.bit_length() - 1)) & 1 == 1


def build_cases():
    """Several session ids, so at least one signature exercises mpint padding."""
    cases = []
    for i in range(6):
        sid = bytes([(0xA0 + i + j) & 0xFF for j in range(32)])
        cases.append(OrderedDict([
            ("name", "sid%d" % i),
            ("session_id_hex", sid.hex()),
            ("signed_blob_hex", signed_blob(sid).hex()),
            ("sig_blob_hex", sig_blob(sign(signed_blob(sid))).hex()),
            ("request_payload_hex", request_payload(sid).hex()),
        ]))
    return cases


def check_against_paramiko():
    """Our blob layout must match an independent SSH implementation byte for byte.

    This is the check that stops the blob format being taken on faith from a
    reading of RFC 5656. An earlier draft encoded Q as two separate coordinate
    strings; that is wrong, and only paramiko disagrees caught it.
    """
    if pubkey_blob() != paramiko_blob():
        raise SystemExit(
            "ORACLE DISAGREEMENT with paramiko on the public key blob\n"
            f"  ours     = {pubkey_blob().hex()}\n"
            f"  paramiko = {paramiko_blob().hex()}"
        )


def check_against_rfc():
    """Point derivation and RFC 6979 nonce must match what RFC 6979 A.2.5 publishes.

    The RFC publishes the key, the resulting public point, and the (k, r, s)
    for the message "sample". Pinning all five is what makes this a real
    third-party check: a wrong bits2int, a bits2octets that forgets to reduce
    mod the order, or a wrong hlen would leave the point derivation intact and
    only move the nonce.
    """
    x, y = public_point()
    if f"{x:064x}" != UX_HEX or f"{y:064x}" != UY_HEX:
        raise SystemExit(
            "ORACLE DISAGREEMENT: derived point does not match RFC 6979 A.2.5\n"
            f"  derived Ux = {x:064x}\n  RFC 6979  = {UX_HEX}\n"
            f"  derived Uy = {y:064x}\n  RFC 6979  = {UY_HEX}"
        )
    k, r, s = rfc6979_sign(b"sample", int(D_HEX, 16))
    want = {
        "k": "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60",
        "r": "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
        "s": "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
    }
    got = {"k": f"{k:064x}", "r": f"{r:064x}", "s": f"{s:064x}"}
    for name in ("k", "r", "s"):
        if got[name] != want[name]:
            raise SystemExit(
                "ORACLE DISAGREEMENT with RFC 6979 A.2.5 on %s\n"
                "  ours = %s\n  RFC  = %s" % (name, got[name], want[name])
            )


def mpint_pad_coverage():
    """How many of the cases produce an r or s needing the 0x00 prefix."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    hit = 0
    for i in range(6):
        sid = bytes([(0xA0 + i + j) & 0xFF for j in range(32)])
        r, s = decode_dss_signature(sign(signed_blob(sid)))
        if mpint_needs_pad(r) or mpint_needs_pad(s):
            hit += 1
    return hit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--authorized-keys", help="write an authorized_keys line here")
    args = ap.parse_args()

    check_against_rfc()
    check_against_paramiko()
    check_python_against_library(SESSION_ID)

    if args.authorized_keys:
        line = "%s %s\n" % (KEY_TYPE.decode(), base64.b64encode(pubkey_blob()).decode())
        with open(args.authorized_keys, "w", encoding="utf-8", newline="\n") as f:
            f.write(line)
        print("wrote %s" % args.authorized_keys)
        return 0

    doc = OrderedDict([
        ("d_hex", D_HEX),
        ("key_type", KEY_TYPE.decode()),
        ("curve_name", CURVE_NAME.decode()),
        ("ux_hex", UX_HEX),
        ("uy_hex", UY_HEX),
        ("session_id_hex", SESSION_ID.hex()),
        ("user", USER.decode()),
        ("service", SERVICE.decode()),
        ("pubkey_blob_hex", pubkey_blob().hex()),
        ("signed_blob_hex", signed_blob(SESSION_ID).hex()),
        ("sig_blob_hex", sig_blob(sign(signed_blob(SESSION_ID))).hex()),
        ("request_payload_hex", request_payload(SESSION_ID).hex()),
        ("cases", build_cases()),
        ("mpint_pad_cases", mpint_pad_coverage()),
        ("authorized_keys", "%s %s" % (KEY_TYPE.decode(), base64.b64encode(pubkey_blob()).decode())),
    ])

    if args.json:
        print(json.dumps(doc, indent=1))
        return 0

    print("RFC 4252 section 7 publickey auth -- ecdsa-sha2-nistp256")
    print("d   = %s" % D_HEX)
    print("Ux  = %s" % UX_HEX)
    print("Uy  = %s" % UY_HEX)
    print("")
    print("point derivation matches RFC 6979 A.2.5: OK")
    print("")
    print("pubkey_blob   %s" % doc["pubkey_blob_hex"])
    print("signed_blob   %s" % doc["signed_blob_hex"])
    print("sig_blob      %s" % doc["sig_blob_hex"])
    print("request       %s" % doc["request_payload_hex"])
    print("")
    print("mpint-padding coverage: %d/6 cases have an r or s with the high bit set"
          % doc["mpint_pad_cases"])
    print("")
    print("authorized_keys %s" % doc["authorized_keys"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
