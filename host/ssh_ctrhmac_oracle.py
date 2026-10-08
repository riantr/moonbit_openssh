#!/usr/bin/env python3
"""Loop #33 KAT oracle: SSH aes128-ctr + hmac-sha2-256 packet wire format.

Produces byte-exact wire vectors for `src/bpacket`'s `Mode::MacEncrypt` so the
MoonBit encrypt-and-MAC path can be checked against something other than itself.

Three independent opinions are reconciled here:

  A. `spec_packet` -- written directly from the OpenSSH semantics established in
     this loop's research (block=16, MAC over the *plaintext* frame, MAC appended
     after the ciphertext, 32-byte hmac-sha2-256).
  B. paramiko's `Packetizer.send_message` -- a complete, unrelated SSH
     implementation. Zero padding is forced by patching `os.urandom`, since
     padding content is arbitrary but must be reproducible for a byte diff.
  C. The MoonBit emitter, via `cmd/ctrmac_test`.

A and B must agree before any vector is emitted; if they ever disagree the
assertion fires and no vectors are printed, because that means one of the two is
wrong and publishing a vector from it would launder the bug into a "golden" file.

Usage:
    python host/ssh_ctrhmac_oracle.py            # human-readable + JSON
    python host/ssh_ctrhmac_oracle.py --json     # JSON only (for the verifier)
"""

import argparse
import hashlib
import hmac
import json
import os
import struct
import sys
from collections import OrderedDict

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import paramiko
from paramiko.packet import Packetizer
from paramiko.message import Message

BLOCK_SIZE = 16          # cipher.c:93 aes128-ctr block_size
MAC_LEN = 32             # mac.c:62 hmac-sha2-256 truncatebits = 0
KEY_LEN = 16
IV_LEN = 16              # cipher_ivlen() falls back to block_size when 0


# ---------------------------------------------------------------------------
# A. Independent implementation, written from the OpenSSH semantics
# ---------------------------------------------------------------------------

class SpecCipher:
    """aes128-ctr with an explicit, persistent counter block.

    The counter has to live across packets: OpenSSH calls `aesctr_ivsetup` once
    at NEWKEYS and lets `aesctr_encrypt_bytes` advance it for the life of the
    connection (cipher.c:280-281, 355-360). Re-seeding a fresh counter per
    packet -- the obvious mistake here -- would still produce byte-correct
    *first* packets, so it survives casual testing and only breaks the second
    packet onwards.
    """

    def __init__(self, key, iv):
        assert len(key) == KEY_LEN and len(iv) == IV_LEN
        self.key = key
        self.ctr = bytearray(iv)

    def crypt(self, data):
        enc = Cipher(algorithms.AES(self.key), modes.CTR(bytes(self.ctr))).encryptor()
        out = enc.update(data) + enc.finalize()
        blocks = (len(data) + BLOCK_SIZE - 1) // BLOCK_SIZE
        for _ in range(blocks):
            n = int.from_bytes(self.ctr, "big") + 1
            self.ctr = n.to_bytes(IV_LEN, "big")
        return out


def spec_packet(cipher, msg_type, payload, seqnr, mac_key, pad_byte=0):
    """Build one SSH aes128-ctr + hmac-sha2-256 packet.

    Layout on the wire (RFC 4253 section 6, encrypt-and-MAC):

        uint32 packet_length      (encrypted)
        byte   padding_length     (encrypted)
        byte   message type       (encrypted)
        byte[] payload            (encrypted)
        byte[] padding            (encrypted, >= 4)
        byte[] mac                (32 bytes, PLAINTEXT)

    with (4 + packet_length) a multiple of the 16-byte block size.
    """
    unpadded = 2 + len(payload)
    pad = BLOCK_SIZE - ((unpadded + 4) % BLOCK_SIZE)
    if pad < 4:
        pad += BLOCK_SIZE
    packet_length = unpadded + pad

    frame = struct.pack(">IB", packet_length, pad)
    frame += bytes([msg_type]) + payload + bytes([pad_byte]) * pad

    ciphertext = cipher.crypt(frame)

    digest = hmac.new(mac_key, struct.pack(">I", seqnr) + frame, hashlib.sha256).digest()
    return frame, ciphertext + digest[:MAC_LEN]


# ---------------------------------------------------------------------------
# B. paramiko's own Packetizer, driven through its public API
# ---------------------------------------------------------------------------

class _FakeSocket:
    """Minimal socket sink for paramiko's Packetizer.

    `Packetizer.write_all` (packet.py:348-386) calls `socket.send` and treats a
    `None` return as -1, so `send` must return the byte count. Any other
    exception is swallowed into EOFError by the bare `except Exception` on
    line 365, which turns a typo in this class into a baffling EOFError
    three frames away.
    """

    def __init__(self):
        self.buf = b""

    def send(self, data):
        self.buf += data
        return len(data)

    def settimeout(self, timeout):
        pass

    def close(self):
        pass


def paramiko_packets(msg_type, payload, count, key, iv, mac_key):
    """Emit `count` packets through paramiko, returning each wire blob.

    Fresh Packetizer per call, so seqnr starts at 0. Only the public
    `send_message` path is used -- no poking at private attributes.

    paramiko fills padding from `os.urandom` for non-SDCTR ciphers
    (packet.py `_build_packet`). Padding content is arbitrary on the wire, but
    a byte diff needs it pinned, so `os.urandom` is forced to zeros for the
    duration -- which is also exactly what MoonBit gets via a zero `pad_src`.
    """
    sock = _FakeSocket()
    p = Packetizer(sock)
    engine = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    p.set_outbound_cipher(
        block_engine=engine,
        block_size=BLOCK_SIZE,
        mac_engine=hashlib.sha256,
        mac_size=MAC_LEN,
        mac_key=mac_key,
        etm=False,
        aead=False,
        sdctr=False,
    )
    out = []
    real_urandom = os.urandom
    os.urandom = lambda n: b"\x00" * n
    try:
        for _ in range(count):
            before = len(sock.buf)
            m = Message()
            m.add_byte(bytes([msg_type]))
            m.add_bytes(payload)
            p.send_message(m)
            out.append(sock.buf[before:])
    finally:
        os.urandom = real_urandom
    return out


# ---------------------------------------------------------------------------
# Vector construction
# ---------------------------------------------------------------------------

def _hex(b):
    return b.hex()


def _unhex(s):
    return bytes.fromhex(s)


# Deterministic key material. Not secret -- these are test vectors, and
# reproducibility is the entire point. Real keys come out of the KDF in
# `src/kexc25519/derive_keys.mbt` at runtime.
KEY = bytes(range(0x10, 0x10 + KEY_LEN))     # 10 11 12 ... 1f
IV_CTOS = bytes(range(0x20, 0x20 + IV_LEN))
IV_STOC = bytes(range(0x30, 0x30 + IV_LEN))
MAC_KEY = bytes(range(0x40, 0x40 + MAC_LEN))

# (case name, msg_type, payload length, packet count)
CASES = [
    ("svc_request", 0x05, 13, 3),   # SSH_MSG_SERVICE_REQUEST "ssh-userauth"
    ("empty", 0x21, 0, 2),          # no payload at all
    ("long", 0x94, 100, 2),         # spans several 16-byte blocks
    ("boundary16", 0x1E, 16, 2),    # payload exactly one block
]


def build_vectors():
    cases = []
    for name, msg_type, plen, count in CASES:
        payload = bytes((i * 7 + 3) & 0xFF for i in range(plen))

        cipher = SpecCipher(KEY, IV_CTOS)
        mine = [spec_packet(cipher, msg_type, payload, i, MAC_KEY)
                for i in range(count)]
        theirs = paramiko_packets(msg_type, payload, count, KEY, IV_CTOS, MAC_KEY)

        for i in range(count):
            frame, wire = mine[i]
            if wire != theirs[i]:
                raise SystemExit(
                    "ORACLE DISAGREEMENT in case %s packet %d\n"
                    "  spec_packet : %s\n  paramiko    : %s"
                    % (name, i, _hex(wire), _hex(theirs[i]))
                )
            if len(frame) % BLOCK_SIZE != 0:
                raise SystemExit("frame not block-aligned in case %s" % name)
            if (4 + struct.unpack(">I", frame[:4])[0]) % BLOCK_SIZE != 0:
                raise SystemExit("packet_length misaligned in case %s" % name)

        cases.append(OrderedDict([
            ("name", name),
            ("msg_type", msg_type),
            ("payload", _hex(payload)),
            ("count", count),
            ("frames", [_hex(f) for f, _ in mine]),
            ("wires", [_hex(w) for _, w in mine]),
        ]))
    return cases


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="JSON only")
    args = ap.parse_args()

    cases = build_vectors()
    doc = OrderedDict([
        ("block_size", BLOCK_SIZE),
        ("mac_len", MAC_LEN),
        ("key", _hex(KEY)),
        ("iv_ctos", _hex(IV_CTOS)),
        ("iv_stoc", _hex(IV_STOC)),
        ("mac_key", _hex(MAC_KEY)),
        ("cases", cases),
    ])

    if args.json:
        print(json.dumps(doc, indent=1))
        return 0

    print("aes128-ctr + hmac-sha2-256  (block=%d, mac=%d)"
          % (BLOCK_SIZE, MAC_LEN))
    print("key     = %s" % _hex(KEY))
    print("iv ctos = %s" % _hex(IV_CTOS))
    print("mac key = %s" % _hex(MAC_KEY))
    print("")
    for c in cases:
        print("[%s] msg=0x%02x payload=%d bytes, %d packets"
              % (c["name"], c["msg_type"], len(c["payload"]) // 2, c["count"]))
        for i, (f, w) in enumerate(zip(c["frames"], c["wires"])):
            pl = struct.unpack(">I", _unhex(f)[:4])[0]
            print("  seqnr=%d packlen=%d padlen=%d frame=%d wire=%d"
                  % (i, pl, _unhex(f)[4], len(_unhex(f)), len(_unhex(w))))
            print("    frame %s" % f)
            print("    wire  %s" % w)
    print("")
    print("A/B agreement: OK (spec_packet == paramiko for every packet)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
