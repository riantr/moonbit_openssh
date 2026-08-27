#!/usr/bin/env python3
"""
Loop #12 triple-blind reference: deterministic OpenSSH CURVE25519 KEX server.

Generates V1-V5 golden vectors for MoonBit and C harness validation.
All cryptographic operations computed here; no hand-copying.

V1 = client KEXINIT payload (hex + parsed strings)
V2 = client ECDH INIT body (e pubkey hex)
V3 = H(session_id) + server ephemeral pubkey + shared secret + derived keys A-F
V4 = first AEAD wire frame (header4 ‖ ct ‖ tag, seq=0)
V5 = tampered variants (bad K_S / bad sig / zero shared secret)

Cross-checks:
  - x25519 shared secret via cryptography hazmat
  - kex_gen_hash via hashlib SHA256 (matching OpenSSH byte order)
  - ssh_wrap_encrypt/ssh_wrap_decrypt (verbatim from aead_python_ref.py)
  - ed25519 sign/verify via cryptography hazmat
"""
import hashlib
import hmac
import struct
import sys

# ============================================================ AEAD (from aead_python_ref.py)

def chacha20_block_openssl(key32: bytes, ctr32: int, nonce12: bytes) -> bytes:
    nonce16 = struct.pack('<I', ctr32 & 0xFFFFFFFF) + nonce12
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    enc = Cipher(algorithms.ChaCha20(key32, nonce16), mode=None).encryptor()
    return enc.update(b'\x00' * 64)

def chacha20_xor_rfc(key32: bytes, nonce12: bytes, start_ctr: int, data: bytes) -> bytes:
    out = bytearray()
    ctr = start_ctr
    for pos in range(0, len(data), 64):
        ks = chacha20_block_openssl(key32, ctr, nonce12)
        chunk = data[pos:pos + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
        ctr += 1
    return bytes(out)

def poly1305(key32: bytes, msg: bytes) -> bytes:
    P = (1 << 130) - 5
    def clamp(r):
        return r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    r = int.from_bytes(key32[:16], 'little'); r = clamp(r)
    s = int.from_bytes(key32[16:], 'little')
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b'\x01', 'little')
        acc = ((acc + n) * r) % P
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, 'little')

def ssh_chacha_block(key32: bytes, seqnr: int, ctr64: int) -> bytes:
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
    return ssh_xor_stream(kmain, seqnr, 0, b'\x00' * 32)

def ssh_wrap_encrypt(key64: bytes, seqnr: int, header4: bytes, payload: bytes) -> bytes:
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

# ============================================================ x25519

def x25519_scalar_clamp(s: bytearray) -> None:
    s[0] &= 248; s[31] &= 127; s[31] |= 64

def x25519_python(sk: bytes, pk: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    priv = X25519PrivateKey.from_private_bytes(sk)
    pub = X25519PublicKey.from_public_bytes(pk)
    return priv.exchange(pub)

# ============================================================ ed25519

def ed25519_public_from_seed(seed32: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    sk = Ed25519PrivateKey.from_private_bytes(seed32)
    return sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

def ed25519_sign(seed32: bytes, msg: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(seed32)
    return sk.sign(msg)

def ed25519_verify(pk32: bytes, msg: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        pk = Ed25519PublicKey.from_public_bytes(pk32)
        pk.verify(sig, msg)
        return True
    except Exception:
        return False

# ============================================================ SSH primitives

def ssh_put_string(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b

def ssh_put_mpint(b: bytes) -> bytes:
    return struct.pack('>I', len(b)) + b

def ssh_put_u32(v: int) -> bytes:
    return struct.pack('>I', v)

def ssh_put_u8(v: int) -> bytes:
    return bytes([v & 0xff])

# ============================================================ proposal helpers

SERVER_KEX = "curve25519-sha256"
SERVER_HOSTKEY = "ssh-ed25519"
SERVER_ENC = "chacha20-poly1305@openssh.com"
SERVER_MAC = "hmac-sha2-256-etm@openssh.com,hmac-sha2-256"
SERVER_COMP = "none"

def parse_proposal_fields(payload: bytes) -> dict:
    """Parse RFC 4251 string fields from a kexinit payload (starting at cookie)."""
    off = 0
    def read_str() -> bytes:
        nonlocal off
        l = struct.unpack('>I', payload[off:off+4])[0]; off += 4
        s = payload[off:off+l]; off += l
        return s
    cookie = payload[off:off+16]; off += 16
    fields = {}
    for name in ['kex_algs','hostkey_algs','enc_ctos','enc_stoc',
                 'mac_ctos','mac_stoc','comp_ctos','comp_stoc',
                 'lang_ctos','lang_stoc']:
        fields[name] = read_str()
    return {'cookie': cookie, **fields}

def make_proposal_payload(cookie: bytes) -> bytes:
    """Build server-side kexinit payload matching kex_prop2buf layout."""
    fields = [
        SERVER_KEX, SERVER_HOSTKEY,
        SERVER_ENC, SERVER_ENC,
        SERVER_MAC, SERVER_MAC,
        SERVER_COMP, SERVER_COMP, "", ""
    ]
    parts = [cookie]
    for f in fields:
        b = f.encode('ascii') if f else b''
        parts.append(ssh_put_string(b))
    parts.append(ssh_put_u8(0))
    parts.append(ssh_put_u32(0))
    return b''.join(parts)

# ============================================================ match_list (first-match)

def match_list(client: str, server: str) -> str:
    if not server:
        return ""
    srv = server.split(',')
    for c in client.split(','):
        if c in srv:
            return c
    return ""

# ============================================================ kex_gen_hash (kexgen.c:62-65)

def kex_gen_hash(
    V_C: bytes, V_S: bytes,
    I_C: bytes, I_S: bytes,   # full payloads (starting at cookie)
    K_S: bytes,
    e: bytes, f: bytes,
    K: bytes,
) -> bytes:
    """
    kexgen.c kex_gen_hash:
    H = SHA256(
      V_C || V_S || I_C || I_S || K_S || e || f || K
    )
    where each item is RFC 4251 string: u32(len) || data.
    """
    h = hashlib.sha256()
    for item in [V_C, V_S, I_C, I_S, K_S, e, f, K]:
        h.update(struct.pack('>I', len(item)))
        h.update(item)
    return h.digest()

# ============================================================ derive_keys (kex.c:1132-1177)

def derive_keys(K: bytes, H: bytes, session_id: bytes, need: int) -> dict:
    """
    kex.c kex_derive_keys:
      K1 = SHA256(K || H || 'A' || session_id)
      Kn = SHA256(K || H || K1 || ... || Kn-1 || letter || session_id)
    Returns {A,B,C,D,E,F} bytes (each truncated to `need`).
    """
    letters = [b'A', b'B', b'C', b'D', b'E', b'F']
    prev = b''
    result = {}
    for letter in letters:
        chunk = K + H + prev + letter + session_id
        ki = hashlib.sha256(chunk).digest()[:need]
        result[letter.decode()] = ki
        prev = ki
    return result

# ============================================================ build sig blob

def build_sig_blob(sig_raw: bytes) -> bytes:
    return ssh_put_string(b'ssh-ed25519') + ssh_put_string(sig_raw)

# ============================================================ main reference

def run_reference(
    V_C: bytes,
    V_S: bytes,
    client_seed: bytes,   # x25519 scalar
    client_e: bytes,     # x25519 ephemeral pubkey
    server_seed: bytes,  # x25519 scalar
    hostkey_seed: bytes, # ed25519 seed
) -> dict:
    """
    Deterministic KEX server: parse client I_C, negotiate,
    respond with ECDH reply. Returns V1-V5 vectors.
    """
    # ------------------------------------------------------------------ derive server ephemeral
    clamped = bytearray(server_seed)
    x25519_scalar_clamp(clamped)
    clamped_bytes = bytes(clamped)

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    srv_priv = X25519PrivateKey.from_private_bytes(clamped_bytes)
    f_pub = srv_priv.public_key().public_bytes(
        encoding=__import__('cryptography.hazmat.primitives',
                            fromlist=['serialization']).Encoding.Raw,
        format=__import__('cryptography.hazmat.primitives',
                          fromlist=['serialization']).PublicFormat.Raw)
    K = x25519_python(clamped_bytes, client_e)

    # ------------------------------------------------------------------ build server KEXINIT
    srv_cookie = b'\x01' * 16
    I_S = make_proposal_payload(srv_cookie)

    # ------------------------------------------------------------------ hostkey
    hk_pk = ed25519_public_from_seed(hostkey_seed)
    K_S = ssh_put_string(b'ssh-ed25519') + ssh_put_string(hk_pk)

    # ------------------------------------------------------------------ hash
    # client_kexinit_payload is reconstructed in emit_vectors() and passed in
    # Here we just record what we need for the final hash call
    # (The caller must pass the full client I_C payload)
    # We return H after it's computed with the full payload
    # For now, return the partial results for sanity checking
    # The actual H computation is done in emit_vectors where we have I_C
    return {
        'K': K,
        'f_pub': f_pub,
        'K_S': K_S,
        'hk_pk': hk_pk,
        'srv_cookie': srv_cookie,
        'I_S': I_S,
    }

def emit_vectors(out=sys.stdout):
    print('=== Loop #12 KEX Flow triple-blind reference ===', file=out)

    # --- deterministic inputs
    V_C = b'SSH-2.0-OpenSSH_8.9'
    V_S = b'SSH-2.0-OpenSSH_9.5'
    client_seed = bytes(range(32, 64))    # 0x20..0x3f
    client_cookie = bytes(range(16))       # 0x00..0x0f
    server_seed = bytes(range(64, 96))    # 0x40..0x5f  (32 bytes)
    hostkey_seed = bytes(range(96, 128))  # 0x60..0x7f

    # --- derive client ephemeral
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives import serialization
    c_priv = X25519PrivateKey.from_private_bytes(client_seed)
    client_e = c_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    # --- build client KEXINIT payload
    c_fields = [
        b'curve25519-sha256',
        b'ssh-ed25519',
        b'chacha20-poly1305@openssh.com',
        b'chacha20-poly1305@openssh.com',
        b'hmac-sha2-256-etm@openssh.com,hmac-sha2-256',
        b'hmac-sha2-256-etm@openssh.com,hmac-sha2-256',
        b'none', b'none', b'', b'',
    ]
    c_parts = [client_cookie]
    for f in c_fields:
        c_parts.append(ssh_put_string(f))
    c_parts.append(ssh_put_u8(0))
    c_parts.append(ssh_put_u32(0))
    I_C = b''.join(c_parts)  # full payload starting at cookie

    # --- V1: client KEXINIT
    p = parse_proposal_fields(I_C)
    print(f'V1_IC_payload_hex = {I_C.hex()}', file=out)
    print(f'V1_cookie_hex = {p["cookie"].hex()}', file=out)
    print(f'V1_kex_algs = {p["kex_algs"].decode("ascii")}', file=out)
    print(f'V1_hostkey_algs = {p["hostkey_algs"].decode("ascii")}', file=out)
    print(f'V1_enc_ctos = {p["enc_ctos"].decode("ascii")}', file=out)
    print(f'V1_mac_ctos = {p["mac_ctos"].decode("ascii")}', file=out)

    # --- negotiate (first-match)
    kex_alg = match_list(p['kex_algs'].decode('ascii'), SERVER_KEX)
    hk_alg  = match_list(p['hostkey_algs'].decode('ascii'), SERVER_HOSTKEY)
    enc_alg = match_list(p['enc_ctos'].decode('ascii'), SERVER_ENC)
    print(f'V1_negotiated_kex = {kex_alg}', file=out)
    print(f'V1_negotiated_hostkey = {hk_alg}', file=out)
    print(f'V1_negotiated_enc = {enc_alg}', file=out)

    # --- V2: client ECDH INIT e pubkey
    print(f'V2_client_e_hex = {client_e.hex()}', file=out)
    # client ECDH INIT body: string(e)
    client_init_body = ssh_put_string(client_e)
    print(f'V2_init_body_hex = {client_init_body.hex()}', file=out)

    # --- server ephemeral + shared secret
    clamped_srv = bytearray(server_seed)
    x25519_scalar_clamp(clamped_srv)
    srv_clamped = bytes(clamped_srv)
    srv_priv = X25519PrivateKey.from_private_bytes(srv_clamped)
    f_pub = srv_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    K = x25519_python(srv_clamped, client_e)

    # --- server KEXINIT payload
    srv_cookie = b'\x01' * 16
    I_S = make_proposal_payload(srv_cookie)

    # --- hostkey blob
    hk_pk = ed25519_public_from_seed(hostkey_seed)
    K_S = ssh_put_string(b'ssh-ed25519') + ssh_put_string(hk_pk)

    # --- H = kex_gen_hash
    H = kex_gen_hash(V_C, V_S, I_C, I_S, K_S, client_e, f_pub, K)
    session_id = H  # initial kex

    # --- sign H
    sig_raw = ed25519_sign(hostkey_seed, H)
    sig_blob = build_sig_blob(sig_raw)

    # --- build ECDH REPLY (type 31)
    reply_body = ssh_put_string(K_S) + ssh_put_string(f_pub) + ssh_put_string(sig_blob)
    reply_msg = bytes([0x1f]) + reply_body

    # --- V3
    print(f'V3_H_hex = {H.hex()}', file=out)
    print(f'V3_session_id_hex = {session_id.hex()}', file=out)
    print(f'V3_server_f_hex = {f_pub.hex()}', file=out)
    print(f'V3_K_hex = {K.hex()}', file=out)
    print(f'V3_sig_blob_hex = {sig_blob.hex()}', file=out)
    print(f'V3_reply_msg_hex = {reply_msg.hex()}', file=out)

    # --- derive keys (MoonBit kexc25519 layout: A/B=IV, C/D=enc, E/F=MAC)
    # Each key is 64 bytes (we_need=64 for chacha20-poly1305)
    # For chacha20-poly1305 AEAD: key64 = enc_key (64B = main[0..32] + header[32..64])
    keys = derive_keys(K, H, session_id, 64)
    key64_ctos = keys['C']  # enc_key_ctos, 64B: main_key(0..32) || header_key(32..64)
    key64_stoc = keys['D']  # enc_key_stoc, 64B

    print(f'V3_iv_ctos_A_hex = {keys["A"].hex()}', file=out)
    print(f'V3_iv_stoc_B_hex = {keys["B"].hex()}', file=out)
    print(f'V3_enc_key_ctos_C_hex = {keys["C"].hex()}', file=out)
    print(f'V3_enc_key_stoc_D_hex = {keys["D"].hex()}', file=out)
    print(f'V3_mac_key_ctos_E_hex = {keys["E"].hex()}', file=out)
    print(f'V3_mac_key_stoc_F_hex = {keys["F"].hex()}', file=out)
    print(f'V3_key64_ctos_hex = {key64_ctos.hex()}', file=out)
    print(f'V3_key64_stoc_hex = {key64_stoc.hex()}', file=out)

    # --- V4: AEAD first frame (seq=0, client→server)
    test_hdr = struct.pack('>I', 0xDEADBEEF)
    test_pld = b'ping'
    v4_wire = ssh_wrap_encrypt(key64_ctos, 0, test_hdr, test_pld)
    dec = ssh_wrap_decrypt(key64_ctos, 0, v4_wire)
    assert dec == test_hdr + test_pld, f"V4 roundtrip failed: {dec!r}"
    print(f'V4_key64_ctos_hex = {key64_ctos.hex()}', file=out)
    print(f'V4_header4_hex = {test_hdr.hex()}', file=out)
    print(f'V4_plaintext_hex = {test_pld.hex()}', file=out)
    print(f'V4_aead_wire_hex = {v4_wire.hex()}', file=out)

    # --- V5: tampered variants
    # V5a: reply with truncated K_S
    bad_ks = K_S[:-4]
    H_bad = kex_gen_hash(V_C, V_S, I_C, I_S, bad_ks, client_e, f_pub, K)
    sig_bad = ed25519_sign(hostkey_seed, H_bad)
    sig_blob_bad = build_sig_blob(sig_bad)
    reply_bad_ks = bytes([0x1f]) + (
        ssh_put_string(bad_ks) + ssh_put_string(f_pub) + ssh_put_string(sig_blob_bad))
    print(f'V5_bad_ks_reply_hex = {reply_bad_ks.hex()}', file=out)

    # V5b: reply with wrong sig (signed wrong message)
    sig_bad2 = ed25519_sign(hostkey_seed, b'\xAA' * 32)
    sig_blob_bad2 = build_sig_blob(sig_bad2)
    reply_bad_sig = bytes([0x1f]) + (
        ssh_put_string(K_S) + ssh_put_string(f_pub) + ssh_put_string(sig_blob_bad2))
    print(f'V5_bad_sig_reply_hex = {reply_bad_sig.hex()}', file=out)

    # V5c: zero shared secret (must be rejected by c25519_shared_key_mpint)
    print(f'V5_zero_K_hex = {"00" * 32}', file=out)

    # --- self-check: verify the sig on H with the derived pk
    ok = ed25519_verify(hk_pk, H, sig_raw)
    assert ok, "ed25519 self-check: signature verify failed"
    print(f'V1_selfcheck_sig_ok = True', file=out)

    print('=== SELF-CHECK PASSED ===', file=out)

if __name__ == '__main__':
    emit_vectors()
