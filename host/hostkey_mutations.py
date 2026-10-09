"""Mutation check: every Loop #38 defect must turn the KAT red.

Each mutation below is one of the bugs that actually existed in src/hostkey or
src/rsa while Loop #38 was being written, or one of the wrong turns the RFC
8332 work invites.  A KAT that stays green under all of them is not testing
anything, so this script is part of the loop's evidence rather than a one-off.

Run:  python host/hostkey_mutations.py
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = [
    os.path.join(ROOT, "src", "hostkey", "sig_verify.mbt"),
    os.path.join(ROOT, "src", "rsa", "verify.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    # ---- the RFC 8332 name discipline ----------------------------------
    (
        "require the signature name to equal the key type, the pre-8332 shape",
        "  if sig_digest != want_digest {\n    return Rejected(SignatureInvalid)\n  }",
        "  if sigtype != \"ssh-rsa\" {\n    return Rejected(SignatureInvalid)\n  }",
        "chk_sig_verify",
    ),
    (
        "compare the two names as strings instead of as digests",
        "  if sig_digest != want_digest {",
        "  if false {",
        "chk_sig_verify",
    ),
    (
        "accept an RSA key under any negotiated name at all",
        "    RsaKey(_, _) =>\n      match rsa_digest_of_keyname(alg) {\n        Some(_) => true\n        None => false\n      }",
        "    RsaKey(_, _) => true",
        "chk_agreement",
    ),
    (
        "let an ed25519 key satisfy an RSA algorithm name",
        "    Ed25519Key(_) => alg == \"ssh-ed25519\"",
        "    Ed25519Key(_) => true",
        "chk_agreement",
    ),
    (
        "add SHA-1 (`ssh-rsa`) to the sigtype table",
        "  if sigtype == \"rsa-sha2-256\" {\n    Some(@rsa.RSA_DIGEST_SHA256)",
        "  if sigtype == \"ssh-rsa\" {\n    Some(@rsa.RSA_DIGEST_SHA256)\n  } else if sigtype == \"rsa-sha2-256\" {\n    Some(@rsa.RSA_DIGEST_SHA256)",
        "chk_digest_tables",
    ),
    (
        "map rsa-sha2-512 to the SHA-256 digest",
        "  } else if sigtype == \"rsa-sha2-512\" {\n    Some(@rsa.RSA_DIGEST_SHA512)",
        "  } else if sigtype == \"rsa-sha2-512\" {\n    Some(@rsa.RSA_DIGEST_SHA256)",
        "chk_digest_tables",
    ),

    # ---- ssh_rsa_verify ordering ---------------------------------------
    (
        "check the signature length before the trailing-data check",
        "  // :540-543\n  if cur.remaining() != 0 {\n    return Rejected(TrailingData)\n  }",
        "  // :540-543\n  if false {\n    return Rejected(TrailingData)\n  }",
        "chk_sig_verify",
    ),
    (
        "accept a signature longer than the modulus",
        "  if rs.length() > modlen {\n    return Rejected(KeyBitsMismatch)\n  }",
        "  if false {\n    return Rejected(KeyBitsMismatch)\n  }",
        "chk_sig_verify",
    ),
    (
        "drop the left-zero-pad for short signatures",
        "  let off = modlen - rs.length()\n  for i = 0; i < rs.length(); i = i + 1 {\n    padded[off + i] = rs[i]\n  }",
        "  for i = 0; i < rs.length(); i = i + 1 {\n    padded[i] = rs[i]\n  }",
        "chk_sig_verify",
    ),
    (
        "check the negotiated name before the signature name",
        "  let sig_digest = match rsa_digest_of_sigtype(sigtype) {\n    None => return Rejected(TypeMismatch)\n    Some(d) => d\n  }",
        "  let sig_digest = @rsa.RSA_DIGEST_SHA256\n  if false {\n    return Rejected(TypeMismatch)\n  }",
        "chk_sig_verify",
    ),

    # ---- PKCS#1 v1.5 shapes (RFC 8017 §9.2) ----------------------------
    (
        "count the 0x00 separator as a padding byte, which the fix removed",
        "      if i - 2 < RSA_PKCS1_MIN_FF {\n        return false\n      }",
        "      if i - 3 < RSA_PKCS1_MIN_FF {\n        return false\n      }",
        "chk_pkcs1_shapes",
    ),
    (
        "drop the minimum padding-string length entirely",
        "      if i - 2 < RSA_PKCS1_MIN_FF {\n        return false\n      }",
        "      if false {\n        return false\n      }",
        "chk_pkcs1_shapes",
    ),
    (
        "let SHA-512 reuse the SHA-256 DigestInfo prefix",
        "let sha512_digest_info_prefix : FixedArray[Byte] = FixedArray::from_array([\n"
        "  0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,\n"
        "  0x00, 0x04, 0x40,\n"
        "])",
        "let sha512_digest_info_prefix : FixedArray[Byte] = FixedArray::from_array([\n"
        "  0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,\n"
        "  0x00, 0x04, 0x20,\n"
        "])",
        "chk_pkcs1_shapes",
    ),
    (
        "let SHA-512 reuse the SHA-256 digest function",
        "  if digest == RSA_DIGEST_SHA512 {\n    Some(@sha512.sha512(msg))",
        "  if digest == RSA_DIGEST_SHA512 {\n    Some(@sha256.sha256(msg))",
        "chk_pkcs1_shapes",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_kat():
    # moon echoes the CJK in this package's own warnings back on stderr, and
    # the Windows locale codec is not UTF-8, so decoding has to be explicit or
    # the harness dies on a byte instead of on a mutation.
    r = subprocess.run(
        ["moon", "run", "cmd/hostkey_test", "--target", "native"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    return (r.stdout or "") + (r.stderr or ""), r.returncode


def main():
    original = read()
    failures = []
    try:
        for label, old, new, must_fail in MUTATIONS:
            target = None
            for p, text in original.items():
                if text.count(old) == 1:
                    target = p
                    break
            if target is None:
                counts = {os.path.basename(p): t.count(old)
                          for p, t in original.items()}
                print("SKIP  %s -- anchor count %s" % (label, counts))
                failures.append(label)
                continue
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            out, code = run_kat()
            # A mutation that makes the KAT *crash* has still been caught --
            # and some of them can only do that.  Dropping the
            # longer-than-modulus check makes the left-pad offset negative, so
            # the process panics on an out-of-bounds write before it ever gets
            # to compare a verdict.  That is a real detection, not a gap.
            caught = ("%s: FAIL" % must_fail) in out or code != 0
            how = "FAIL" if ("%s: FAIL" % must_fail) in out else (
                "crash rc=%d" % code if code != 0 else "nothing")
            print("%s  %-58s [%s]" % ("CAUGHT" if caught else "MISSED",
                                      label, how))
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if "hostkey_fail" in line:
                        print("        " + line.strip())
    finally:
        write(original)

    print()
    if failures:
        print("MUTATION CHECK FAILED: %d of %d not caught"
              % (len(failures), len(MUTATIONS)))
        return 1
    print("all %d mutations turned the KAT red" % len(MUTATIONS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
