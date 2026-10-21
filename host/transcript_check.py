#!/usr/bin/env python
"""Loop #31 transcript checker: MITM tee in front of sshd, independent of MoonBit.

Runs the MoonBit client through a byte tee so both directions of the SSH
transcript are captured, then recomputes the transport exchange hash and
verifies the server's ECDSA host key signature *in Python*.  That separates the
two possible causes of a SignatureInvalid:

  * the MoonBit hash code is wrong  -> Python's H differs from the client's H
  * the bytes on the wire are wrong -> Python's H also fails to verify

The hash layout is the one proven by host/paramiko_oracle.py against a live
paramiko session_id: all eight fields length-prefixed, K included.

Usage:
  python host/transcript_check.py --port 22222 --proxy-port 22223
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import subprocess
import sys
import threading

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature,
)

# The group14 prime, RFC 3526 section 3.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC740"
    "20BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)

# The fixed DH exponent baked into cmd/ssh_live, so K is reproducible.
FIXED_X = int(
    "5A17C39E44B26DF108A735CC912E60D374189FE250B7C63D810AF52964C87B1E", 16
)

SSH_MSG_KEXINIT = 20
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31


# ------------------------------------------------------------------ parsing --


def split_ident(buf: bytes) -> tuple[bytes, bytes]:
    """Split the identification phase off; return (ident_line, rest)."""
    idx = buf.find(b"\r\n")
    if idx < 0:
        return b"", buf
    return buf[:idx], buf[idx + 2 :]


def parse_packets(buf: bytes, first_unencrypted: bool = True) -> list[tuple[int, bytes]]:
    """Decode a plaintext SSH binary-packet stream into (type, payload)."""
    out = []
    i = 0
    n = len(buf)
    while i + 5 <= n:
        pkt_len = int.from_bytes(buf[i : i + 4], "big")
        if pkt_len < 8 or pkt_len % 8 != 4:
            break
        if i + 4 + pkt_len > n:
            break
        pad_len = buf[i + 4]
        # [4-byte len][1-byte pad_len][payload][padding]
        payload = buf[i + 5 : i + 4 + pkt_len - pad_len]
        if payload:
            out.append((payload[0], payload[1:]))
        i += 4 + pkt_len
    return out


def read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    ln = int.from_bytes(buf[off : off + 4], "big")
    return buf[off + 4 : off + 4 + ln], off + 4 + ln


def read_mpint(buf: bytes, off: int) -> tuple[int, int]:
    s, off = read_string(buf, off)
    return int.from_bytes(s, "big"), off


def mpint_bytes(z: int) -> bytes:
    if z == 0:
        return b""
    b = z.to_bytes((z.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def ssh_string(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def exchange_hash(v_c, v_s, i_c, i_s, k_s, e, f, k) -> bytes:
    buf = b"".join(
        [
            ssh_string(v_c),
            ssh_string(v_s),
            ssh_string(i_c),
            ssh_string(i_s),
            ssh_string(k_s),
            ssh_string(mpint_bytes(e)),
            ssh_string(mpint_bytes(f)),
            ssh_string(mpint_bytes(k)),
        ]
    )
    return hashlib.sha256(buf).digest()


# ----------------------------------------------------------------- verifier --


def verify_ecdsa(k_s: bytes, h: bytes, sig_blob: bytes) -> tuple[bool, str]:
    """Verify an SSH ECDSA signature blob. Returns (ok, detail)."""
    alg, off = read_string(sig_blob, 0)
    alg = alg.decode()
    # The outer string is the full key algorithm name, e.g. "ecdsa-sha2-nistp256";
    # the curve is its last dash-separated component.
    curve_name = alg.rsplit("-", 1)[-1]
    name = {
        "nistp256": ec.SECP256R1(),
        "nistp384": ec.SECP384R1(),
        "nistp521": ec.SECP521R1(),
    }[curve_name]
    inner, _ = read_string(sig_blob, off)  # string( mpint r || mpint s )
    r, o2 = read_mpint(inner, 0)
    s, _ = read_mpint(inner, o2)

    # host key blob: string(alg) string(curve) string(point)
    halg, o = read_string(k_s, 0)
    curve, o = read_string(k_s, o)
    point, o = read_string(k_s, o)
    if halg != b"ecdsa-sha2-" + curve_name.encode():
        return False, f"host key alg mismatch {halg!r}"
    if point[0] != 0x04:
        return False, f"not an uncompressed point (0x{point[0]:02x})"
    size = (name.key_size + 7) // 8
    x = int.from_bytes(point[1 : 1 + size], "big")
    y = int.from_bytes(point[1 + size : 1 + 2 * size], "big")
    pub = ec.EllipticCurvePublicNumbers(x, y, name).public_key()
    digest = {256: hashes.SHA256, 384: hashes.SHA384, 521: hashes.SHA512}[name.key_size]
    try:
        pub.verify(encode_dss_signature(r, s), h, ec.ECDSA(digest()))
        return True, f"verified (curve={curve.decode()}, alg={alg}, {digest().name})"
    except InvalidSignature:
        return False, f"signature does NOT verify (curve={curve.decode()})"


# --------------------------------------------------------------------- tee ---


class Tee:
    def __init__(self):
        self.c2s = bytearray()
        self.s2c = bytearray()
        self.lock = threading.Lock()

    def add(self, to_server: bool, data: bytes) -> None:
        with self.lock:
            (self.c2s if to_server else self.s2c).extend(data)


def relay(a: socket.socket, b: socket.socket, tee: Tee, to_b: bool) -> None:
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            tee.add(to_b, data)
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def make_listener(port: int) -> socket.socket:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(60)
    return srv


def pump(cli: socket.socket, up: socket.socket, tee: Tee) -> None:
    """Relay both directions until both halves close, teeing as we go."""
    t1 = threading.Thread(target=relay, args=(cli, up, tee, True), daemon=True)
    t2 = threading.Thread(target=relay, args=(up, cli, tee, False), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=25)
    t2.join(timeout=25)
    for s in (cli, up):
        try:
            s.close()
        except OSError:
            pass


# -------------------------------------------------------------------- main ---


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=22222, help="real sshd port")
    ap.add_argument("--proxy-port", type=int, default=22223)
    ap.add_argument("--exe", default="_build/native/debug/build/cmd/ssh_live/ssh_live.exe")
    ap.add_argument("--moonbit-h", default="", help="expected H hex from the client")
    ap.add_argument(
        "--client-arg",
        action="append",
        default=[],
        help="extra argument passed to the client (repeatable)",
    )
    args = ap.parse_args()

    # Ordering matters and is not interchangeable:
    #   1. bind + listen   -- the port must be open before the client dials it
    #   2. spawn the client
    #   3. accept          -- unblocks only once the client has connected
    #   4. dial sshd and pump
    # Doing 3 before 2 deadlocks, and so does accepting on a helper thread
    # that is started before the client exists.
    listener = make_listener(args.proxy_port)
    proc = subprocess.Popen(
        [args.exe, str(args.proxy_port), *args.client_arg],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    tee = Tee()
    try:
        cli, _ = listener.accept()
        listener.close()
        up = socket.create_connection(("127.0.0.1", args.port), timeout=15)
        pump(cli, up, tee)
    finally:
        try:
            listener.close()
        except OSError:
            pass
    try:
        client_out = proc.communicate(timeout=30)[0].decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        proc.kill()
        client_out = proc.communicate()[0].decode("utf-8", "replace")
    print("----- MoonBit client output -----")
    print(client_out.rstrip())
    print("---------------------------------")
    if not tee.c2s or not tee.s2c:
        print("empty transcript")
        return 2

    v_c_raw, rest_c = split_ident(bytes(tee.c2s))
    v_s_raw, rest_s = split_ident(bytes(tee.s2c))
    print(f"V_C: {v_c_raw!r}")
    print(f"V_S: {v_s_raw!r}")

    c_pkts = parse_packets(rest_c)
    s_pkts = parse_packets(rest_s)
    print("client packet types:", [t for t, _ in c_pkts])
    print("server packet types:", [t for t, _ in s_pkts])

    i_c_body = None
    e = None
    for t, p in c_pkts:
        if t == SSH_MSG_KEXINIT and i_c_body is None:
            i_c_body = p
        elif t == SSH_MSG_KEX_ECDH_INIT and e is None:
            e, _ = read_mpint(p, 0)

    i_s_body = None
    k_s = f = sig = None
    for t, p in s_pkts:
        if t == SSH_MSG_KEXINIT and i_s_body is None:
            i_s_body = p
        elif t == SSH_MSG_KEX_ECDH_REPLY and k_s is None:
            k_s, off = read_string(p, 0)
            f, off = read_mpint(p, off)
            sig, off = read_string(p, off)

    if None in (i_c_body, i_s_body, e, f, k_s, sig):
        print("INCOMPLETE TRANSCRIPT -- could not find every handshake field")
        return 2

    i_c = bytes([SSH_MSG_KEXINIT]) + i_c_body
    i_s = bytes([SSH_MSG_KEXINIT]) + i_s_body
    k = pow(f, FIXED_X, P)
    h = exchange_hash(v_c_raw, v_s_raw, i_c, i_s, k_s, e, f, k)

    print(f"I_C len: {len(i_c)}   I_S len: {len(i_s)}")
    fields = [
        ("vc", ssh_string(v_c_raw)),
        ("vs", ssh_string(v_s_raw)),
        ("ic", ssh_string(i_c)),
        ("is", ssh_string(i_s)),
        ("ks", ssh_string(k_s)),
        ("e ", ssh_string(mpint_bytes(e))),
        ("f ", ssh_string(mpint_bytes(f))),
        ("k ", ssh_string(mpint_bytes(k))),
    ]
    for name, val in fields:
        print(f"DBG {name}={val[:24].hex().upper()}")
    print("DBG lens " + " ".join(f"{n.strip()}={len(v)}" for n, v in fields))
    print(f"e: {e:0512X}")
    print(f"f: {f:0512X}")
    print(f"K: {k:0512X}")
    print(f"H_python:    {h.hex()}")
    # The server's f is fresh on every connection, so H changes per run; the
    # client's own H has to be read out of THIS run's stdout to be comparable.
    m = re.search(r"^exchange_hash:\s*([0-9A-Fa-f]{64})\s*$", client_out, re.M)
    if m:
        mb = m.group(1).lower()
        print(f"H_moonbit:   {mb}")
        print(f"H_match:     {h.hex() == mb}")
    else:
        print("H_moonbit:   <not printed>")

    ok, detail = verify_ecdsa(k_s, h, sig)
    print(f"sig_verified: {'PASS' if ok else 'FAIL'} ({detail})")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
