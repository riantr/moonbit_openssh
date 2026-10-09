"""Capture real OpenSSH host-key signatures and the exchange hashes they cover.

This is the part of the oracle that no amount of re-derivation can replace: the
bytes below are what an actual sshd put on the wire, over a message an actual
sshd computed.  Everything else in `hostkey_oracle.py` is us agreeing with
paramiko about what the format should look like; this is a server disagreeing
if we got it wrong.

Three things it settles that a spec reading does not:

  1. `string signature` in KEXDH_REPLY holds `string algorithm-name ||
     string signature-blob` -- a 4-byte length prefix, not a NUL.  paramiko
     writes the same layout, so its blobs are directly usable; had it written
     a cstring they would differ by three bytes and every KAT vector built
     from them would be testing a framing no server sends.

  2. Under RFC 8332 the name inside the signature blob is the *negotiated*
     name (`rsa-sha2-512`), not the key type (`ssh-rsa`).  Visible directly in
     the first bytes of each capture below.

  3. An `ssh-rsa` host key still signs as `rsa-sha2-512` by default, and the
     signature blob is 276 bytes -- 12 + 4 + 4 + 256 -- with no sign of SHA-1.

Needs a running test sshd.  `node host/sshd_setup.mjs --port <P>` provides one.

Run:  python host/hostkey_capture.py <port> <out.json>
"""

import json
import sys

import paramiko

CAP = {}
_orig_verify = paramiko.Transport._verify_key
_orig_setkh = paramiko.Transport._set_K_H

# The three algorithms this client advertises that the test sshd can produce.
WANTED = ["ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"]


def _spy_verify(self, *a):
    # paramiko hands the raw signature in as bytes; the host key arrives as a
    # PKey object, so the two are told apart by type rather than by length
    # (an RSA signature and an RSA host key blob are within a few bytes of
    # each other, and guessing by length silently swapped them once).
    for x in a:
        if isinstance(x, bytes) and len(x) > 60:
            CAP["sig"] = x.hex()
    return _orig_verify(self, *a)


def _spy_setkh(self, K, h):
    if isinstance(h, bytes):
        CAP["hash"] = h.hex()
    return _orig_setkh(self, K, h)


paramiko.Transport._set_K_H = _spy_setkh
paramiko.Transport._verify_key = _spy_verify


def capture(port, only=None, timeout=15):
    """One handshake, optionally forced onto a single host key algorithm."""
    CAP.clear()
    saved = paramiko.Transport._preferred_keys
    if only:
        # narrow the client's own offer to one algorithm, which is the same
        # lever as OpenSSH's HostKeyAlgorithms from the other side
        paramiko.Transport._preferred_keys = (only,)
    try:
        t = paramiko.Transport(("127.0.0.1", port))
        t.start_client(timeout=timeout)
        key = t.get_remote_server_key()
        try:
            t.auth_none("hp")
        except Exception:
            pass
        t.close()
    finally:
        paramiko.Transport._preferred_keys = saved
    CAP["hostkey"] = key.get_name()
    CAP["bits"] = key.get_bits()
    CAP["alg"] = only
    CAP["key_blob"] = key.asbytes().hex()
    return dict(CAP)


def capture_all(port):
    out = {}
    for alg in WANTED:
        cap = capture(port, alg)
        if "sig" not in cap or "hash" not in cap:
            print("%-14s NOT CAPTURED (%s)" % (alg, sorted(cap)))
            continue
        out[alg] = cap
        print("%-14s key=%-13s bits=%-5d H=%2dB sig=%3dB  head=%s"
              % (alg, cap["hostkey"], cap["bits"],
                 len(cap["hash"]) // 2, len(cap["sig"]) // 2, cap["sig"][:32]))
    return out


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    port = int(sys.argv[1])
    out = sys.argv[2] if len(sys.argv) > 2 else None
    caps = capture_all(port)
    if out:
        with open(out, "w") as fh:
            json.dump(caps, fh, indent=2, sort_keys=True)
        print("wrote", out)
    return 0 if len(caps) == len(WANTED) else 1


if __name__ == "__main__":
    sys.exit(main())
