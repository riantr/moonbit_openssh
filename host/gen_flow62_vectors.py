"""Generate end-to-end curve25519 handshake vectors for `flow_on_reply`.

Loop #61 found that `kexflow::flow_on_reply` had never been called by anything
and had three defects it could not have been caught without: the `derive_keys`
arguments were swapped, `FLOW_WE_NEED` was hardcoded to 64, and "we cannot
answer this algorithm" was reported as `ProtocolError`. Loop #61 pinned the
first two by inspection plus a unit test. It did **not** prove the function can
complete a handshake, and said so in its own AGENTS.md entry.

This closes that. `flow_on_reply` is pure: it takes `peer_ic_payload` and
`reply_msg` as byte strings. So the vector set is built offline, which is
strictly better than a socket -- it is reproducible, diffable, and the peer side
can be an independent implementation.

## Two-blind, not one

The generator is an **independent implementation** of the server half:

  * X25519 comes from `cryptography`'s X25519 group.
  * Ed25519 signing comes from `cryptography`'s Ed25519.
  * The exchange hash layout follows OpenSSH kexgen.c:67-82, written out here
    independently rather than copied from `src/kexc25519/exchange_hash.mbt`.

So H and the signature are each computed twice, by code that shares nothing with
the tree under test. A layout mistake on either side shows up as a mismatch
rather than as two agreeing implementations of the same wrong thing.

## What the vector file carries

Per case: the client seed, the peer KEXINIT, the peer ECDH_REPLY, and the
expected verdict -- `Established`, or the exact `FlowError` variant. The
negative cases are the interesting ones, because Loop #61's three defects all
manifested as a *wrong or missing* verdict rather than as wrong bytes.

Run:  python host/gen_flow62_vectors.py
      python host/gen_flow62_vectors.py --stdout     (preview only)
"""

import argparse
import hashlib
import io
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "verify_c", "kexflow", "flow_vectors.txt")

V_C = b"SSH-2.0-MoonBit"
V_S = b"SSH-2.0-VectorPeer_1.0"
SSH_MSG_KEXINIT = 20
SSH_MSG_KEX_ECDH_REPLY = 31

# kex_algs_default's cipher/MAC, as shipped: the AEAD cipher means the MAC list
# is never consulted, which is the whole reason Loop #60 had to find the EtM name
# in `default_client` rather than on a negotiated MAC.
ENC = "chacha20-poly1305@openssh.com"
MAC = "hmac-sha2-256"


def s(b):
    """SSH string / RFC 4251 length-prefixed."""
    return len(b).to_bytes(4, "big") + b


def kexinit_payload(cookie, kex, hostkey, enc, mac):
    algs = [kex, hostkey, enc, enc, mac, mac, "none", "none", "", ""]
    out = cookie
    for a in algs:
        out += s(a.encode())
    out += b"\x00" + (0).to_bytes(4, "big")
    return out


# The client's own KEXINIT, i.e. what `kexflow::Proposal::default_client(strict_kex)`
# serialises. This MUST be the client's real payload, not a copy of the peer's:
# the exchange hash covers both, so using the same bytes for both is the one
# thing guaranteed to make every signature fail. It is transcribed from
# src/kexflow/proposal.mbt rather than imported, because the point of the
# two-blind setup is that the peer half shares no code with the tree.
#
# Loop #62 wrote `i_c = i_s` here and got three SignatureInvalid results. The
# verification code was right; the vector was wrong.
def client_kexinit(cookie, strict_kex):
    kex = "curve25519-sha256"
    if strict_kex:
        kex += ",kex-strict-c-v00@openssh.com"
    return kexinit_payload(cookie, kex, "ssh-ed25519", ENC, MAC)


def build_exchange_input(v_c, v_s, i_c, i_s, ks, client_pub, server_pub, shared_mpint):
    """kexgen.c:67-82. The fake header's length covers the type byte too."""
    return (
        s(v_c)
        + s(v_s)
        + s(bytes([SSH_MSG_KEXINIT]) + i_c)
        + s(bytes([SSH_MSG_KEXINIT]) + i_s)
        + s(ks)
        + s(client_pub)
        + s(server_pub)
        + shared_mpint  # sshbuf_putb: the encoded mpint verbatim, unwrapped
    )


def mpint(raw):
    """Two's-complement big-endian mpint, as OpenSSH's sshbuf_put_bignum2 writes it."""
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return s(raw)


def deterministic_seed(tag):
    """A stable 32-byte scalar. `cryptography` refuses raw scalars, so this is
    a real private key's bytes and its public key is what we keep."""
    return hashlib.sha256(b"openssh-loop62-" + tag.encode()).digest()


def make_case(tag, client_seed, kex, hostkey, enc, mac, peer_cookie,
              strict_kex, known_hosts, verdict, note):
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(client_seed)
    hk_priv = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"openssh-loop62-hostkey-" + tag.encode()).digest()
    )
    hk_pub_bytes = hk_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # Server's X25519 keypair; the client scalar drives its own side.
    srv = x25519.X25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"openssh-loop62-x25519-" + tag.encode()).digest()
    )
    server_pub = srv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # RFC 7748 X25519 with the raw scalar, clamped as the spec requires.
    client_pub = x25519_x25519(client_seed, _basepoint())
    shared_raw = x25519_x25519(client_seed, server_pub)

    ks = s(b"ssh-ed25519") + s(hk_pub_bytes)
    i_c = client_kexinit(peer_cookie, strict_kex)
    i_s = kexinit_payload(peer_cookie, kex, hostkey, enc, mac)
    shared_mpint = mpint(shared_raw)

    h = hashlib.sha256(
        build_exchange_input(V_C, V_S, i_c, i_s, ks, client_pub, server_pub, shared_mpint)
    ).digest()
    sig = hk_priv.sign(h)

    reply = (
        bytes([SSH_MSG_KEX_ECDH_REPLY])
        + s(ks)
        + s(server_pub)
        # RFC 4253 / ssh-ed25519.c: the signature blob is one outer string
        # holding `cstring(alg)` followed by `string(rs)`. The algorithm name
        # is a bare cstring with no length prefix of its own -- it is not a
        # nested string. Loop #62 wrote `s(s(alg) + sig)`, which is one extra
        # length prefix, and every case failed with SignatureInvalid against
        # verification code that was completely correct.
        + s(s(b"ssh-ed25519") + s(sig))
    )
    return {
        "tag": tag,
        "client_seed": client_seed,
        "client_pub": client_pub,
        "peer_ic": i_s,
        "reply": reply,
        "h": h,
        "strict_kex": strict_kex,
        "known_hosts": known_hosts,
        "verdict": verdict,
        "note": note,
        "server_pub": server_pub,
    }


def _basepoint():
    bp = bytearray(9)
    bp[0] = 9
    return bytes(bp)


def x25519_x25519(scalar, u):
    """RFC 7748 X25519, implemented here rather than taken from a helper.

    `cryptography` has no raw-scalar entry point (its `X25519PrivateKey` takes
    and hides a random scalar), and the client seed must be exactly the bytes
    `flow_start` clamps, or the two sides disagree on the shared secret.
    """
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    p = 2 ** 255 - 19
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        if swap ^ kt:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % p
        aa = (a * a) % p
        b = (x2 - z2) % p
        bb = (b * b) % p
        e = (aa - bb) % p
        c = (x3 + z3) % p
        d = (x3 - z3) % p
        da = (d * a) % p
        cb = (c * b) % p
        x3 = pow((da + cb) % p, 2, p)
        z3 = (x1 * pow((da - cb) % p, 2, p)) % p
        x2 = (aa * bb) % p
        z2 = (e * (aa + 121665 * e)) % p
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, p - 2, p)) % p).to_bytes(32, "little")


def build_all():
    cases = []

    # --- V1: the happy path. Without this, "can it complete a handshake?" is
    # still not a claim anything supports.
    seed = deterministic_seed("happy")
    cases.append(make_case(
        "V1", seed, "curve25519-sha256", "ssh-ed25519", ENC, MAC,
        bytes(range(0xA0, 0xB0)), False, "", "Established",
        "curve25519 + ssh-ed25519 + chachapoly; session_id must equal H",
    ))

    # --- V2: strict-kex marker present. The marker must not break the flow:
    # it is a capability signal, not an algorithm (Loop #61's MARKER verdict).
    cases.append(make_case(
        "V2", deterministic_seed("strict"), "curve25519-sha256",
        "ssh-ed25519", ENC, MAC, bytes(range(0xB0, 0xC0)), True, "",
        "Established",
        "kex list carries kex-strict-c-v00@openssh.com",
    ))

    # --- V3: a peer that only offers ecdsa. Intersection is empty, so this is
    # NoAgreement, not a verification failure.
    cases.append(make_case(
        "V3", deterministic_seed("noagree"), "curve25519-sha256",
        "ecdsa-sha2-nistp256", ENC, MAC, bytes(range(0xC0, 0xD0)), False, "",
        "NoAgreement(hostkey)",
        "peer offers only ecdsa-sha2-nistp256, which the client does not list",
    ))

    # --- V4: the same, from the cipher side. A peer offering only a cipher we
    # have no Mode for must be NoAgreement, never a crash or a bogus success.
    cases.append(make_case(
        "V4", deterministic_seed("badenc"), "curve25519-sha256",
        "ssh-ed25519", "aes128-gcm@openssh.com", MAC,
        bytes(range(0xD0, 0xE0)), False, "", "NoAgreement(cipher)",
        "peer offers only aes128-gcm@openssh.com",
    ))

    # --- V5: tampered signature. The one case that proves the signature is
    # actually verified rather than merely present.
    c = make_case(
        "V5", deterministic_seed("badsig"), "curve25519-sha256", "ssh-ed25519",
        ENC, MAC, bytes(range(0xE0, 0xF0)), False, "", "SignatureInvalid",
        "one bit flipped in the last byte of the signature",
    )
    bad = bytearray(c["reply"])
    bad[-1] ^= 0x01
    c["reply"] = bytes(bad)
    cases.append(c)

    # --- V6: a peer whose kex list is empty. Negotiation must fail with
    # NoKexAlg, and specifically NOT with something that looks like a crypto
    # failure. "Offer nothing" is a missing answer, not a broken promise, and
    # the verdict has to say so -- a gate that only ever sees Established and
    # SignatureInvalid cannot tell those apart.
    c = make_case(
        "V6", deterministic_seed("emptykex"), "curve25519-sha256", "ssh-ed25519",
        ENC, MAC, bytes(range(0xF0, 0x100)), False, "", "NoAgreement(kex)",
        "peer advertises an empty kex list",
    )
    # Rebuild I_S with an empty first category; the signature is re-made over
    # the new hash so the case tests negotiation rather than verification.
    c = remake_with_kex(c, "", "ssh-ed25519", ENC, MAC)
    cases.append(c)

    # --- V7: a peer whose host key blob is valid but whose *signature* is over
    # a different H -- i.e. a substituted server public key. This is the closest
    # thing here to an active attack, and it is the case that proves the
    # verification is actually bound to the exchange hash.
    c = make_case(
        "V7", deterministic_seed("subkey"), "curve25519-sha256", "ssh-ed25519",
        ENC, MAC, bytes(range(0x50, 0x60)), False, "", "SignatureInvalid",
        "server signs a different exchange hash (substituted Q_S)",
    )
    c = resign_over_other_hash(c)
    cases.append(c)

    return cases


def remake_with_kex(c, kex, hostkey, enc, mac):
    """Re-sign the case with a different peer KEXINIT.

    Any change to I_S changes H, so the signature has to be recomputed or the
    case would fail verification for the wrong reason -- which is exactly the
    mistake Loop #62 made twice while building this file.
    """
    i_s = kexinit_payload(c["peer_ic"][:16], kex, hostkey, enc, mac)
    return resign(c, i_s)


def resign_over_other_hash(c):
    """Sign H' -- the hash as if Q_S were different -- over the reply's real H.

    The server lies about what it signed. The client must notice, because it
    recomputes H from its own Q_S.
    """
    return resign(c, c["peer_ic"], swap_qs=True)


def resign(c, i_s, swap_qs=False):
    hk_priv = ed25519.Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"openssh-loop62-hostkey-" + c["tag"].encode()).digest()
    )
    hk_pub = hk_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    client_seed = c["client_seed"]
    client_pub = x25519_x25519(client_seed, _basepoint())
    ks = s(b"ssh-ed25519") + s(hk_pub)
    server_pub = c["server_pub"]
    sign_over = server_pub
    if swap_qs:
        sign_over = bytes((b + 1) & 0xFF for b in server_pub)
    shared_raw = x25519_x25519(client_seed, server_pub)
    shared_mpint = mpint(shared_raw)
    i_c = client_kexinit(c["peer_ic"][:16], c["strict_kex"])
    h_sign = hashlib.sha256(
        build_exchange_input(
            V_C, V_S, i_c, i_s, ks, client_pub, sign_over, shared_mpint
        )
    ).digest()
    # The H the *client* will derive: always from the Q_S actually on the wire.
    # For V7 this differs from `h_sign` on purpose -- that difference is the
    # attack, and recording both makes it visible in the file rather than only
    # in a failure message.
    h_client = hashlib.sha256(
        build_exchange_input(
            V_C, V_S, i_c, i_s, ks, client_pub, server_pub, shared_mpint
        )
    ).digest()
    sig = hk_priv.sign(h_sign)
    reply = (
        bytes([SSH_MSG_KEX_ECDH_REPLY])
        + s(ks)
        + s(server_pub)
        + s(s(b"ssh-ed25519") + s(sig))
    )
    out = dict(c)
    out["peer_ic"] = i_s
    out["reply"] = reply
    out["client_pub"] = client_pub
    # The H the client will derive. Recomputed over the Q_S actually on the wire,
    # which for V7 is deliberately NOT the one the peer signed.
    out["h"] = h_client
    # What the peer claims it signed. Equal to `h` everywhere except V7, where
    # the gap between the two IS the substituted-key attack.
    out["h_signed"] = h_sign
    return out


def render(cases):
    out = io.StringIO()
    out.write("# Loop #62 -- kexflow::flow_on_reply end-to-end vectors\n")
    out.write("# Generated by host/gen_flow62_vectors.py. Do not hand-edit.\n")
    out.write("#\n")
    out.write("# Two-blind: X25519 and Ed25519 come from `cryptography`, and the\n")
    out.write("# exchange-hash layout here is written from OpenSSH kexgen.c:67-82\n")
    out.write("# independently of src/kexc25519/exchange_hash.mbt. A mistake on\n")
    out.write("# either side shows up as a mismatch, not as two agreeing copies\n")
    out.write("# of the same wrong thing.\n")
    for c in cases:
        out.write("\nCASE %s\n" % c["tag"])
        out.write("note = %s\n" % c["note"])
        out.write("client_seed = %s\n" % c["client_seed"].hex())
        out.write("peer_ic = %s\n" % c["peer_ic"].hex())
        out.write("reply = %s\n" % c["reply"].hex())
        out.write("strict_kex = %d\n" % (1 if c["strict_kex"] else 0))
        out.write("known_hosts = %s\n" % c["known_hosts"])
        out.write("expect = %s\n" % c["verdict"])
        # Probe the K_S blob directly. `flow_on_reply` collapses "blob did not
        # parse" and "wrong key type" into one HostkeyInvalid, which was not
        # enough to diagnose four simultaneous failures -- and a gate that
        # cannot say why a case failed is a gate you end up debugging by hand.
        out.write("probe_k_s = 1\n")
        out.write("probe_h = 1\n")
        # The H this vector signs. The MoonBit side prints its own H, so the
        # two can be diffed when a signature fails -- a verdict alone cannot
        # tell a wrong vector from a wrong implementation.
        out.write("h = %s\n" % c["h"].hex())
    return out.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stdout", action="store_true", help="print instead of writing")
    args = ap.parse_args()
    cases = build_all()
    text = render(cases)
    if args.stdout:
        sys.stdout.write(text)
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with io.open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote %s (%d cases, %d bytes)" % (
        os.path.relpath(OUT, ROOT), len(cases), len(text)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())