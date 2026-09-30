#!/usr/bin/env python
"""Loop #31 oracle: a *successful* paramiko handshake against the local sshd.

Dumps the ground truth of every byte that feeds the SSH transport exchange hash
H, then recomputes H with the layout taken verbatim from OpenSSH's
kex_gen_hash() (kexgen.c:47-96) and checks it against paramiko's own
session_id.  If they agree, the layout is proven and any remaining mismatch is
on the MoonBit side.

Ground truth captured:
  transport.local_version / remote_version   (no CR LF)
  transport.local_kex_init / remote_kex_init (full payload, type byte 0x14 included)
  kex.x, kex.e, kex.f                         (fixed K, so H is reproducible)
  transport.session_id                        (== H)
  host key blob + raw signature blob

Usage:  python host/paramiko_oracle.py --port 22222 [--out .loop31/oracle.json]
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time

import paramiko
from paramiko import kex_group14, transport as tmod
from paramiko.message import Message

# ---------------------------------------------------------------- capture ---

CAP: dict = {}


def _patch():
    """Instrument paramiko so we can read every input to the exchange hash."""

    orig_gen_x = kex_group14.KexGroup14SHA256._generate_x

    def gen_x(self):
        orig_gen_x(self)
        CAP["x"] = hex(self.x)

    kex_group14.KexGroup14SHA256._generate_x = gen_x

    orig_reply = kex_group14.KexGroup14SHA256._parse_kexdh_reply

    def reply(self, m):
        # Snapshot the transcript *before* paramiko consumes the message.
        CAP["kex_host_key"] = m.get_string().hex()
        CAP["kex_e"] = hex(self.e)  # set in start_kex, already valid here
        CAP["kex_f"] = hex(m.get_mpint())
        CAP["kex_sig"] = m.get_binary().hex()
        m.rewind()
        CAP["reply_payload"] = m.get_so_far().hex()
        return orig_reply(self, m)

    kex_group14.KexGroup14SHA256._parse_kexdh_reply = reply

    orig_send = tmod.Transport._send_kex_init

    def send(self):
        orig_send(self)
        CAP["local_kex_init"] = self.local_kex_init.hex()

    tmod.Transport._send_kex_init = send

    orig_parse = tmod.Transport._parse_kex_init

    def parse(self, m):
        orig_parse(self, m)
        CAP["remote_kex_init"] = self.remote_kex_init.hex()

    tmod.Transport._parse_kex_init = parse


class RecordingSocket:
    """Transparent socket wrapper that tees both directions to a file."""

    def __init__(self, sock: socket.socket, path: str):
        self._s = sock
        self._f = open(path, "wb")

    def _log(self, tag: bytes, data: bytes) -> None:
        self._f.write(tag)
        self._f.write(len(data).to_bytes(4, "big"))
        self._f.write(data)
        self._f.flush()

    def send(self, data, *a, **k):
        self._log(b"\x00\x00\x00\x01", bytes(data))
        return self._s.send(data, *a, **k)

    def sendall(self, data, *a, **k):
        self._log(b"\x00\x00\x00\x01", bytes(data))
        return self._s.sendall(data, *a, **k)

    def recv(self, n, *a, **k):
        d = self._s.recv(n, *a, **k)
        if d:
            self._log(b"\x00\x00\x00\x02", d)
        return d

    def recv_into(self, buf, *a, **k):
        n = self._s.recv_into(buf, *a, **k)
        if n:
            self._log(b"\x00\x00\x00\x02", bytes(buf[:n]))
        return n

    def __getattr__(self, name):
        return getattr(self._s, name)

    def close(self):
        try:
            self._f.close()
        finally:
            self._s.close()


# ------------------------------------------------------------------- hash ---
# Layout copied verbatim from OpenSSH kex_gen_hash() (kexgen.c:47-96):
#   string(V_C) string(V_S) string(I_C) string(I_S) string(K_S)
#   string(e) string(f) <shared_secret raw>
# I_C / I_S are the full SSH_MSG_KEXINIT payloads (type byte 0x14 included),
# which is exactly what paramiko's local_kex_init / remote_kex_init hold.
# e / f are mpints (u32 length + sign-padded big-endian).
# The shared secret K is appended *raw*, with no length prefix.


def ssh_string(b: bytes) -> bytes:
    b = to_bytes(b)
    return len(b).to_bytes(4, "big") + b


def to_bytes(x) -> bytes:
    """paramiko 5.x keeps version strings as str; Message.add_string utf-8 encodes."""
    return x if isinstance(x, bytes) else x.encode("utf-8")


def mpint_bytes(n: int) -> bytes:
    if n == 0:
        return b""
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b


def exchange_hash(v_c, v_s, i_c, i_s, k_s, e, f, k) -> bytes:
    """H = SHA256(string(V_C) || string(V_S) || string(I_C) || string(I_S)
               || string(K_S) || string(mpint(e)) || string(mpint(f))
               || string(mpint(K)))

    Every field is length-prefixed, K included:
      * kex_gen_hash() (kexgen.c:67-79) wraps V_C/V_S/I_C/I_S/K_S/e/f with
        sshbuf_put_stringb, and writes shared_secret with sshbuf_putb.
      * kex_dh_compute_key() (kexdh.c:105) stores the shared secret with
        sshbuf_put_bignum2, i.e. it already carries its own u32 length.
      * I_C/I_S get a "fake header": u32(len+1) || 0x14 || payload-without-type,
        which is byte-identical to the full KEXINIT payload incl. the type byte.
    """
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
    import hashlib

    return hashlib.sha256(buf).digest()


def hash_variants(v_c, v_s, i_c, i_s, k_s, e, f, k) -> dict:
    """Sweep the three ambiguous encodings against the ground-truth session_id."""
    import hashlib

    def wrap(b, prefixed: bool) -> bytes:
        return ssh_string(b) if prefixed else to_bytes(b)

    variants = {}
    for v_pref in (True, False):
        for i_pref in (True, False):
            for ef_pref in (True, False):
                for k_pref in (True, False):
                    buf = b"".join(
                        [
                            wrap(v_c, v_pref),
                            wrap(v_s, v_pref),
                            wrap(i_c, i_pref),
                            wrap(i_s, i_pref),
                            ssh_string(k_s),
                            wrap(mpint_bytes(e), ef_pref),
                            wrap(mpint_bytes(f), ef_pref),
                            wrap(mpint_bytes(k), k_pref),
                        ]
                    )
                    name = f"V{int(v_pref)}I{int(i_pref)}E{int(ef_pref)}K{int(k_pref)}"
                    variants[name] = hashlib.sha256(buf).digest()
    return variants


# ------------------------------------------------------------------- main ---


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=22222)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--out", default=".loop31/oracle.json")
    args = ap.parse_args()

    _patch()

    raw = socket.create_connection((args.host, args.port), timeout=15)
    sock = RecordingSocket(raw, os.path.join(".loop31", "oracle_stream.bin"))

    t = paramiko.Transport(sock)
    t.start_client(timeout=20)

    ok = False
    for _ in range(100):
        if t.is_authenticated() or not t.is_active():
            break
        if getattr(t, "kex_done", False):
            ok = True
            break
        time.sleep(0.1)

    out: dict = {"handshake_ok": bool(ok or t.is_active())}

    if t.session_id is not None:
        v_c = t.local_version
        v_s = t.remote_version
        i_c = bytes.fromhex(CAP["local_kex_init"])
        i_s = bytes.fromhex(CAP["remote_kex_init"])
        k_s = bytes.fromhex(CAP["kex_host_key"])
        x = int(CAP["x"], 16)
        e = int(CAP["kex_e"], 16) if "kex_e" in CAP else None
        f = int(CAP["kex_f"], 16)

        P = kex_group14.KexGroup14SHA256.P
        K = pow(f, x, P)

        import hashlib

        h = exchange_hash(v_c, v_s, i_c, i_s, k_s, e, f, K)
        out.update(
            {
                "local_version": repr(v_c),
                "remote_version": repr(v_s),
                "i_c_len": len(i_c),
                "i_s_len": len(i_s),
                "i_c_sha256": hashlib.sha256(i_c).hexdigest(),
                "i_s_sha256": hashlib.sha256(i_s).hexdigest(),
                "k_s_hex": k_s.hex(),
                "e_hex": "%0256X" % e if e is not None else None,
                "f_hex": "%0256X" % f,
                "K_hex": "%0256X" % K,
                "x_hex": "%0256X" % x,
                "H_recomputed": h.hex(),
                "H_paramiko_session_id": t.session_id.hex(),
                "H_match": h == t.session_id,
                "H_matching_variants": [
                    name
                    for name, digest in hash_variants(
                        v_c, v_s, i_c, i_s, k_s, e, f, K
                    ).items()
                    if digest == t.session_id
                ],
            }
        )

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)

    for k, v in out.items():
        print(f"{k}: {v}")

    t.close()
    return 0 if out.get("H_match") else 1


if __name__ == "__main__":
    sys.exit(main())
