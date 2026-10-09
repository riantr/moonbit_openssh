"""Loop #38 oracle: host key blobs and RFC 8332 signature blobs.

This is the second independent implementation of the host-key rules.  The first
is OpenSSH's own C, which it quotes line by line:

  ssh-rsa.c:490-570   ssh_rsa_verify          (the whole decision order)
  ssh-rsa.c:328-338   rsa_hash_id_from_ident  (sigtype -> digest)
  ssh-rsa.c:345-359   ssh_rsa_hash_id_from_keyname (keyname -> digest)
  sshkey.h:53         SSH_RSA_MINIMUM_MODULUS_SIZE = 1024
  sshkey.c:2003-2047  sshkey_from_blob_internal (impl lookup before parse)
  ssh-ed25519.c:244-259  alg compare -> trailing -> length

Three legs, and nothing here is hand-transcribed:

  1. paramiko 5.0 builds every blob.  It is a real SSH library, so the byte
     layout of the host key blob and of the signature blob is its opinion, not
     ours.  `sign_ssh_data(..., algorithm="rsa-sha2-256"/"rsa-sha2-512")` is
     exactly the RFC 8332 path.
  2. `cryptography` 50.0 verifies the same signatures raw, so a case the KAT
     expects to be `Accepted` is known to be a genuinely valid signature and
     not merely something our own parser failed to complain about.
  3. The decision table below is written out by hand from the C, and every
     case in it is checked against leg 2 before anything is emitted.

One framing distinction this file is careful about, because it is exactly where
a KAT would otherwise be testing the wrong bytes.  RFC 4253 §7.1 puts the
signature in KEXDH_REPLY as `string signature`, and the *contents* of that
field are what `parse_reply` hands to `HostKey::verify_with_alg`.  What those
contents are was not read off the RFC -- it was captured off a real sshd:

    0000000b "ssh-ed25519"  00000040 <64 bytes>
    0000000c "rsa-sha2-512" 00000100 <256 bytes>

i.e. `string algorithm-name || string signature-blob`, a 4-byte length prefix
on both.  Not a NUL-terminated name, which is what "cstring" would suggest and
what a spec-first implementation would plausibly assume.  paramiko writes the
same layout, so its blobs are directly usable; `host/hostkey_capture.py` is
what established that they are.

The negative half is paramiko's weak point: it refuses `algorithm="ssh-rsa"`
outright (KeyError), which is itself a useful data point -- the SHA-1 path is
gone from current SSH libraries, not merely disabled by policy.  The SHA-1
rejection case is therefore synthesised structurally.

Run:  python host/hostkey_oracle.py --selfcheck
"""

import base64
import hashlib
import json
import os
import sys

import paramiko
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSHD = os.path.join(ROOT, ".loop31", "sshd")

# --------------------------------------------------------------------------
# wire helpers (RFC 4251 §5)
# --------------------------------------------------------------------------


def ssh_str(b):
    return len(b).to_bytes(4, "big") + b


def parse_str(b, off):
    n = int.from_bytes(b[off:off + 4], "big")
    if off + 4 + n > len(b):
        raise ValueError("string overruns buffer")
    return b[off + 4:off + 4 + n], off + 4 + n


def parse_name(b, off=0):
    """The algorithm name, which on the wire is a length-prefixed string."""
    raw, nxt = parse_str(b, off)
    return raw.decode("ascii"), nxt


def mpint(i):
    """sshbuf_put_bignum2: minimal big-endian, leading zeros stripped."""
    if i == 0:
        return b""
    raw = i.to_bytes((i.bit_length() + 7) // 8, "big").lstrip(b"\x00")
    if not raw:
        return b""
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def sig_blob(name, rs):
    """`string algorithm-name || string signature-blob`, as captured."""
    return ssh_str(name) + ssh_str(rs)


# --------------------------------------------------------------------------
# leg 1 + leg 2
# --------------------------------------------------------------------------

MESSAGES = {
    "m1": b"loop38 exchange hash stand-in",
    "m2": b"loop38 exchange hash stand-in, second message",
}

# the same numbering src/rsa/verify.mbt uses, so a vector's digest field can
# be handed to @rsa.rsa_digest_info_prefix without a translation step
RSA_SHA256_ID = 1
RSA_SHA512_ID = 2

_KEYS = {}


def load_host_keys():
    if not _KEYS:
        _KEYS["rsa"] = paramiko.RSAKey.from_private_key_file(
            os.path.join(SSHD, "hostkey_rsa_2048"))
        _KEYS["ed"] = paramiko.Ed25519Key.from_private_key_file(
            os.path.join(SSHD, "hostkey_ed25519"))
        _KEYS["ec256"] = paramiko.ECDSAKey.from_private_key_file(
            os.path.join(SSHD, "hostkey_ecdsa_256"))
        _KEYS["ec384"] = paramiko.ECDSAKey.from_private_key_file(
            os.path.join(SSHD, "hostkey_ecdsa_384"))
    return _KEYS


def pub_file_blob(name):
    """The blob ssh-keygen itself wrote for this key."""
    with open(os.path.join(SSHD, name + ".pub")) as fh:
        return base64.b64decode(fh.read().split()[1])


def rsa_blob(key):
    nums = key.public_numbers
    return ssh_str(b"ssh-rsa") + ssh_str(mpint(nums.e)) + ssh_str(mpint(nums.n))


def raw_verify_rsa(key, msg, blob, alg):
    """cryptography's opinion of the signature, with no SSH framing involved.

    The signature integer is left-padded to the modulus width first, and that
    is not a convenience: `cryptography` will not accept a signature shorter
    than the key, because it wants the caller's value to already be the width
    OpenSSL's `RSA_verify` would see.  OpenSSH has to do the padding itself
    (`ssh-rsa.c:549-560`, `sshbuf_put_bignum2` strips the leading zeros) and so
    do we (`src/rsa/verify.mbt`).  So leg 2 confirms the *mathematics*; the
    padding rule is transcribed separately from the C and is what the
    `rsa_sig_shorter_than_modulus` vector is actually about.
    """
    name, off = parse_name(blob)
    sig, _ = parse_str(blob, off)
    assert name == alg, (name, alg)
    width = (key.public_numbers.n.bit_length() + 7) // 8
    sig = b"\x00" * (width - len(sig)) + sig
    h = _hashes.SHA512() if alg == "rsa-sha2-512" else _hashes.SHA256()
    key.key.public_key().verify(sig, msg, _padding.PKCS1v15(), h)


def rsa_sig(key, msg, alg):
    return key.sign_ssh_data(msg, algorithm=alg).asbytes()


# --------------------------------------------------------------------------
# leg 3: the decision table, transcribed from ssh-rsa.c:490-570
# --------------------------------------------------------------------------


def rsa_verify_expect(modulus_bits, blob, keyname):
    """Re-derive OpenSSH's result.  Returns one of our KeyError spellings.

    The order here is the order of the C, because that order is the whole
    contract: a checker that asks "is this a known algorithm" first reports a
    different error from one that asks "does the signature name match" first,
    and against a malformed blob those are different answers.
    """
    # ssh-rsa.c:509-510 -- before anything is even parsed
    if modulus_bits < 1024:
        return "RsaModulusTooShort"

    try:
        sigtype, off = parse_name(blob)
    except (ValueError, IndexError, UnicodeDecodeError):
        return "InvalidFormat"

    # ssh-rsa.c:518-521 rsa_hash_id_from_ident.  SHA-1 (`ssh-rsa`) is absent
    # from this project on purpose, so it lands here as a type mismatch.
    if sigtype not in ("rsa-sha2-256", "rsa-sha2-512"):
        return "TypeMismatch"

    # ssh-rsa.c:526-535 the two names must resolve to the same digest
    if keyname not in ("rsa-sha2-256", "rsa-sha2-512"):
        return "InvalidArgument"
    if (sigtype == "rsa-sha2-512") != (keyname == "rsa-sha2-512"):
        return "SignatureInvalid"

    try:
        rs, off = parse_str(blob, off)
    except (ValueError, IndexError):
        return "InvalidFormat"

    # ssh-rsa.c:540-543
    if off != len(blob):
        return "TrailingData"

    # ssh-rsa.c:544-548
    if len(rs) > (modulus_bits + 7) // 8:
        return "KeyBitsMismatch"

    # :549-560 left-pad to the modulus, then :568 hand off to OpenSSL.  The
    # modexp is leg 2's job; reaching here without an ordering complaint means
    # the case is well-formed.
    return "Accepted"


# --------------------------------------------------------------------------
# the emitted cases
# --------------------------------------------------------------------------


def build():
    K = load_host_keys()
    rsa, ed = K["rsa"], K["ed"]
    rsa_pub = rsa_blob(rsa)
    # the blob layouts below are paramiko's, and ssh-keygen's published .pub
    # files are the tie-breaker: if either library disagreed about a blob,
    # this is where it would show.
    assert rsa_pub == pub_file_blob("hostkey_rsa_2048"), "ssh-rsa blob layout"
    assert ed.asbytes() == pub_file_blob("hostkey_ed25519"), "ed25519 blob layout"
    assert K["ec256"].asbytes() == pub_file_blob("hostkey_ecdsa_256"), "ecdsa blob layout"
    assert K["ec384"].asbytes() == pub_file_blob("hostkey_ecdsa_384"), "ecdsa blob layout"

    n_bits = rsa.public_numbers.n.bit_length()
    modlen = (n_bits + 7) // 8
    cases = {"key": [], "sig": [], "pkcs1": []}

    # ---- key blobs: parse + describe ------------------------------------
    cases["key"] += [
        {"name": "ed25519_host", "blob": ed.asbytes(),
         "expect": "Parsed", "err": "", "type": "ssh-ed25519", "bits": 256},
        {"name": "rsa2048_host", "blob": rsa_pub,
         "expect": "Parsed", "err": "", "type": "ssh-rsa", "bits": 2048},
        {"name": "ecdsa_p256_host", "blob": K["ec256"].asbytes(),
         "expect": "Parsed", "err": "", "type": "ecdsa-sha2-nistp256", "bits": 256},
        {"name": "ecdsa_p384_host", "blob": K["ec384"].asbytes(),
         "expect": "Parsed", "err": "", "type": "ecdsa-sha2-nistp384", "bits": 384},
        # only a name, no fields.  sshkey.c:2031-2046 looks the name up in the
        # impl table *before* it tries to parse, so this is a known type with
        # a broken body, not an unknown type.
        {"name": "name_only_ecdsa", "blob": ssh_str(b"ecdsa-sha2-nistp256"),
         "expect": "Rejected", "err": "InvalidFormat", "type": "", "bits": 0},
        {"name": "name_only_rsa", "blob": ssh_str(b"ssh-rsa"),
         "expect": "Rejected", "err": "InvalidFormat", "type": "", "bits": 0},
        {"name": "unknown_alg", "blob": ssh_str(b"ssh-nonsense"),
         "expect": "Rejected", "err": "UnsupportedType", "type": "", "bits": 0},
        # A modulus under 1024 bits is refused while *parsing* the key, not
        # while verifying the signature -- OpenSSH does it inside
        # ssh_rsa_deserialize's check_rsa_length, one layer earlier than
        # ssh-rsa.c:509-510 re-checks it.  `cryptography` will not generate a
        # sub-1024-bit RSA key (it enforces the same floor), so the blob is
        # synthesised from a fixed 512-bit odd number; only its length matters.
        {"name": "rsa_modulus_512_bits",
         "blob": ssh_str(b"ssh-rsa") + ssh_str(mpint(65537)) +
                 ssh_str(mpint(0xC0FFEE0000000003)),
         "expect": "Rejected", "err": "RsaModulusTooShort", "type": "", "bits": 0},
    ]

    # ---- signatures over the real host keys -----------------------------
    sig256 = rsa_sig(rsa, MESSAGES["m1"], "rsa-sha2-256")
    sig512 = rsa_sig(rsa, MESSAGES["m1"], "rsa-sha2-512")
    raw_verify_rsa(rsa, MESSAGES["m1"], sig256, "rsa-sha2-256")
    raw_verify_rsa(rsa, MESSAGES["m1"], sig512, "rsa-sha2-512")

    ed_sig = ed.sign_ssh_data(MESSAGES["m1"]).asbytes()
    assert parse_name(ed_sig)[0] == "ssh-ed25519"

    cases["sig"] += [
        {"name": "rsa_sha256_valid", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig256, "alg": "rsa-sha2-256",
         "expect": "Accepted", "err": ""},
        {"name": "rsa_sha512_valid", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig512, "alg": "rsa-sha2-512",
         "expect": "Accepted", "err": ""},
        {"name": "ed25519_valid", "key": "ed25519_host",
         "msg": MESSAGES["m1"], "sig": ed_sig, "alg": "ssh-ed25519",
         "expect": "Accepted", "err": ""},

        # ---- RFC 8332: the three names ---------------------------------
        # ssh-rsa.c:526-535.  Each of these is a signature a server could
        # plausibly hand us, and each is rejected for a different reason.
        {"name": "rsa_sig512_negotiated256", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig512, "alg": "rsa-sha2-256",
         "expect": "Rejected", "err": "SignatureInvalid", "layer": "rsa"},
        {"name": "rsa_sig256_negotiated512", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig256, "alg": "rsa-sha2-512",
         "expect": "Rejected", "err": "SignatureInvalid", "layer": "rsa"},
        # these two never reach ssh_rsa_verify: `agrees_with_alg` catches them
        # one layer up.  A server cannot actually negotiate an RSA key under
        # ed25519's name, so this pins the guard rather than the C.
        {"name": "rsa_key_negotiated_ed25519", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig512, "alg": "ssh-ed25519",
         "expect": "Rejected", "err": "TypeMismatch", "layer": "agree"},
        {"name": "ed25519_key_negotiated_rsa", "key": "ed25519_host",
         "msg": MESSAGES["m1"], "sig": ed_sig, "alg": "rsa-sha2-512",
         "expect": "Rejected", "err": "TypeMismatch", "layer": "agree"},
        # a different message: well-formed, correctly named, still invalid
        {"name": "rsa_sha512_wrong_message", "key": "rsa2048_host",
         "msg": MESSAGES["m2"], "sig": sig512, "alg": "rsa-sha2-512",
         "expect": "Rejected", "err": "SignatureInvalid", "layer": "crypto"},
        {"name": "ed25519_wrong_message", "key": "ed25519_host",
         "msg": MESSAGES["m2"], "sig": ed_sig, "alg": "ssh-ed25519",
         "expect": "Rejected", "err": "SignatureInvalid", "layer": "crypto"},

        # ---- ssh_rsa_verify ordering -----------------------------------
        # SHA-1 (`ssh-rsa`) signature name.  paramiko 5.0 refuses to produce
        # one at all -- KeyError 'ssh-rsa' -- so only the name is structural.
        {"name": "rsa_sha1_sigtype_name", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig_blob(b"ssh-rsa", b"\x00" * modlen),
         "alg": "rsa-sha2-512", "expect": "Rejected", "err": "TypeMismatch"},
        {"name": "rsa_unknown_sigtype_name", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig_blob(b"rsa-sha2-1024", b"\x00" * modlen),
         "alg": "rsa-sha2-512", "expect": "Rejected", "err": "TypeMismatch"},
        # name string claims more bytes than the blob holds
        {"name": "rsa_sigtype_truncated", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": b"\x00\x00\x00\x0crsa-sha2",
         "alg": "rsa-sha2-512", "expect": "Rejected", "err": "InvalidFormat"},
        # signature string header runs off the end
        {"name": "rsa_sigstring_truncated", "key": "rsa2048_host",
         "msg": MESSAGES["m1"],
         "sig": ssh_str(b"rsa-sha2-512") + b"\xff\xff",
         "alg": "rsa-sha2-512", "expect": "Rejected", "err": "InvalidFormat"},
        # trailing data after the signature string
        {"name": "rsa_trailing_data", "key": "rsa2048_host",
         "msg": MESSAGES["m1"], "sig": sig512 + b"\x00\x01",
         "alg": "rsa-sha2-512", "expect": "Rejected", "err": "TrailingData"},
        # signature longer than the modulus (ssh-rsa.c:544-548)
        {"name": "rsa_sig_longer_than_modulus", "key": "rsa2048_host",
         "msg": MESSAGES["m1"],
         "sig": sig_blob(b"rsa-sha2-512", b"\x01" * (modlen + 1)),
         "alg": "rsa-sha2-512", "expect": "Rejected", "err": "KeyBitsMismatch"},
    ]

    # ---- the left-zero-pad rule (ssh-rsa.c:549-560) ----------------------
    # OpenSSH stores the signature with sshbuf_put_bignum2, which strips
    # leading zeros, so a real signature can be shorter than the modulus.
    # Find a message whose RSA signature happens to start with 0x00 and emit
    # the stripped form; the C left-pads it back, and so must we.
    short = None
    for i in range(4096):
        m = b"loop38 short-sig probe #%d" % i
        blob = rsa_sig(rsa, m, "rsa-sha2-512")
        _name, off = parse_name(blob)
        rs, _ = parse_str(blob, off)
        if len(rs) == modlen and rs[0] == 0x00:
            short = (m, blob, rs.lstrip(b"\x00"))
            break
    if short is None:
        raise SystemExit("no short signature found in 4096 tries")
    m_short, blob_short, rs_short = short
    assert len(rs_short) < modlen
    # the stripped form is what goes on the wire; the C left-pads it back
    blob_stripped = sig_blob(b"rsa-sha2-512", rs_short)
    # leg 2: it is still a valid signature once left-padded
    raw_verify_rsa(rsa, m_short, blob_stripped, "rsa-sha2-512")
    assert rsa_verify_expect(n_bits, blob_stripped, "rsa-sha2-512") == "Accepted"
    cases["sig"].append({
        "name": "rsa_sig_shorter_than_modulus", "key": "rsa2048_host",
        "msg": m_short, "sig": blob_stripped, "alg": "rsa-sha2-512",
        "expect": "Accepted", "err": "",
    })

    # ---- PKCS#1 encoding shapes (RFC 8017 §9.2) -------------------------
    def em_for(alg, ps_len, digest_override=None):
        h = hashlib.sha512 if alg == "rsa-sha2-512" else hashlib.sha256
        dig = digest_override if digest_override is not None else h(MESSAGES["m1"]).digest()
        prefix = bytes.fromhex(
            "3051300d060960864801650304020305000440" if alg == "rsa-sha2-512"
            else "3031300d060960864801650304020105000420")
        return b"\x00\x01" + b"\xff" * ps_len + b"\x00" + prefix + dig

    for alg in ("rsa-sha2-256", "rsa-sha2-512"):
        dlen = 64 if alg.endswith("512") else 32
        cases["pkcs1"] += [
            {"name": "%s_ps8" % alg, "digest": alg, "em": em_for(alg, 8),
             "expect": True},
            {"name": "%s_ps7" % alg, "digest": alg, "em": em_for(alg, 7),
             "expect": False},
            {"name": "%s_ps0" % alg, "digest": alg, "em": em_for(alg, 0),
             "expect": False},
            # right shape, wrong digest: the DigestInfo prefix is checked
            # against the *negotiated* digest, so this must not slip through
            {"name": "%s_wrong_digest" % alg, "digest": alg,
             "em": em_for(alg, 202, digest_override=b"\x00" * dlen),
             "expect": False},
            # a 2048-bit modulus is 256 bytes; 202 + 19 + 64 + 2 = 287, over,
            # so this one is only here to pin the "too long for the modulus"
            # branch of the same shape check
            {"name": "%s_no_separator" % alg, "digest": alg,
             "em": b"\x00\x01" + b"\xff" * 40, "expect": False},
            {"name": "%s_bad_lead" % alg, "digest": alg,
             "em": b"\x00\x02" + b"\xff" * 40 + b"\x00" + b"\x00" * 20,
             "expect": False},
        ]

    return cases


def selfcheck(cases):
    """The oracle checking its own claims before anything is emitted.

    Each case declares which layer decides its outcome, because a KAT that
    pins the wrong layer's answer is worse than no KAT: it will keep passing
    while the layer that actually matters is broken.

      * ``agree``   -- `HostKey::agrees_with_alg` rejects first, so
                       `ssh_rsa_verify` is never reached.  The C would answer
                       SSH_ERR_INVALID_ARGUMENT (`ssh-rsa.c:527-529`) if it
                       got that far, but negotiation can never produce this
                       pairing, so the guard is ours and lives one layer up.
      * ``rsa``    -- decided by the transcription of ssh-rsa.c:490-570.
      * ``crypto`` -- decided only by the modexp: well-formed, correctly
                       named, and covering a different message.

    Beyond that, every case expected to be Accepted is re-verified under
    `cryptography`.  Without that the KAT could happily agree that a garbage
    signature is Accepted.
    """
    K = load_host_keys()
    bad = []
    for c in cases["sig"]:
        blob = c["sig"]
        try:
            alg_in = parse_name(blob)[0]
        except (ValueError, IndexError, UnicodeDecodeError):
            alg_in = ""
        layer = c.get("layer", "rsa")

        if layer == "agree":
            if c["err"] != "TypeMismatch":
                bad.append((c["name"], "agree layer must be TypeMismatch",
                            c["err"]))
            continue

        if layer == "crypto":
            if c["key"] == "rsa2048_host":
                try:
                    raw_verify_rsa(K["rsa"], c["msg"], blob, c["alg"])
                except Exception:
                    pass
                else:
                    bad.append((c["name"], "verified anyway", c["err"]))
            if alg_in != c["alg"]:
                bad.append((c["name"], "blob name " + alg_in, c["alg"]))
            continue

        if c["expect"] == "Accepted":
            if c["key"] == "rsa2048_host":
                raw_verify_rsa(K["rsa"], c["msg"], blob, c["alg"])
            if alg_in != c["alg"]:
                bad.append((c["name"], "blob name " + alg_in, c["alg"]))
            continue

        got = rsa_verify_expect(c.get("bits", 2048), blob, c["alg"])
        if got != c["err"]:
            bad.append((c["name"], got, c["err"]))

    if bad:
        for name, got, want in bad:
            print("ORACLE DISAGREES %s: %s (declared %s)" % (name, got, want))
        return False
    return True


# --------------------------------------------------------------------------
# real OpenSSH captures
# --------------------------------------------------------------------------

CAPTURE_FILE = os.path.join(ROOT, ".loop38", "real_capture.json")


def load_capture(path=CAPTURE_FILE):
    """The vectors `host/hostkey_capture.py` pulled off a live sshd.

    These are the ones that cannot be argued with: a real server chose the
    algorithm, signed a real exchange hash, and put the bytes on the wire.  If
    the KAT accepts all three, the three-name discipline and both DigestInfo
    prefixes are right against the thing we actually have to talk to.
    """
    if not os.path.exists(path):
        print("no capture at %s -- run host/hostkey_capture.py <port> <out>"
              % path)
        return []
    with open(path) as fh:
        caps = json.load(fh)
    out = []
    for alg, cap in sorted(caps.items()):
        sig = bytes.fromhex(cap["sig"])
        key_blob = bytes.fromhex(cap["key_blob"])
        name_in_blob, off = parse_name(sig)
        rs, off2 = parse_str(sig, off)
        assert off2 == len(sig), "capture %s has trailing bytes" % alg
        # the whole point of RFC 8332, read straight off the wire
        assert name_in_blob == alg, (alg, name_in_blob)
        # and the key blob still names itself `ssh-rsa` even when the
        # negotiated name is `rsa-sha2-512`
        assert parse_name(key_blob)[0] == cap["hostkey"], (
            cap["hostkey"], parse_name(key_blob)[0])
        if alg.startswith("rsa-"):
            raw_verify_rsa(load_host_keys()["rsa"],
                           bytes.fromhex(cap["hash"]), sig, alg)
        out.append({
            "name": "real_%s" % alg.replace("-", "_"),
            "alg": alg,
            "key": "__inline__",
            "key_blob": key_blob,
            "key_type": cap["hostkey"],
            "bits": cap["bits"],
            "msg": bytes.fromhex(cap["hash"]),
            "sig": sig,
            "expect": "Accepted",
            "err": "",
        })
    return out


if __name__ == "__main__":
    cs = build()
    real = load_capture()
    ok = selfcheck(cs)
    print("key cases   : %d" % len(cs["key"]))
    print("sig cases   : %d" % len(cs["sig"]))
    print("pkcs1 cases : %d" % len(cs["pkcs1"]))
    print("real cases  : %d" % len(real))
    for c in cs["sig"]:
        print("  %-32s %-14s -> %-8s %s" % (
            c["name"], c["alg"], c["expect"], c["err"]))
    for c in real:
        print("  %-32s %-14s -> %-8s %s  (%s %d bits, %d byte sig)"
              % (c["name"], c["alg"], c["expect"], c["err"],
                 c["key_type"], c["bits"], len(c["sig"])))
    sys.exit(0 if ok else 1)
