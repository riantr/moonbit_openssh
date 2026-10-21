#!/usr/bin/env python3
"""Generate cmd/userauth_test/vectors.mbt from the RFC 4252 auth oracle.

Same reasoning as host/gen_ctrmac_vectors.py: the hex strings are long, they
are load-bearing, and hand-copying them buys nothing. Run:

    python host/gen_userauth_vectors.py
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "cmd", "userauth_test", "vectors.mbt")


def format_in_place(path):
    """Put the generated file through the formatter.

    The generated file is a SOURCE file in the repository, and the repository
    is formatter-clean -- `moon fmt --check` over the whole tree is a gate
    (Loop #67). So the generator has to produce what the formatter produces,
    or the file it writes is not the file the repository is supposed to hold.

    That is not a cosmetic difference. Loop #34's gate regenerates this file
    and requires the committed copy to be unchanged, and the two used to
    differ by exactly the formatter's line wrapping -- so the check could
    never pass, and the regenerated copy was left in the working tree, where
    it made every later `git diff` non-empty.

    `moon fmt` is run through `cmd /c` because that is how every other
    harness in this repository invokes the toolchain on Windows.
    """
    res = subprocess.run(
        ["cmd", "/c", "moon", "fmt", path],
        capture_output=True,
    )
    if res.returncode != 0:
        sys.stderr.write("moon fmt failed on the file %s\n%s\n%s\n"
                         % (path,
                            res.stdout.decode("utf-8", "replace"),
                            res.stderr.decode("utf-8", "replace")))
        raise SystemExit(res.returncode)
    return res.stdout.decode("utf-8", "replace")


def main():
    raw = subprocess.run(
        [sys.executable, os.path.join(HERE, "ecdsa_auth_oracle.py"), "--json"],
        capture_output=True, check=True,
    ).stdout.decode("utf-8")
    doc = json.loads(raw)

    L = []
    a = L.append
    a("///| GENERATED FILE -- do not edit by hand.")
    a("///| Regenerate with: python host/gen_userauth_vectors.py")
    a("///|")
    a("///| Source: host/ecdsa_auth_oracle.py, which refuses to emit unless its")
    a("///| point derivation reproduces the public point published in RFC 6979")
    a("///| A.2.5. `sign` there uses RFC 6979 deterministic nonces, so these are")
    a("///| not merely *valid* signatures -- they are the only correct ones.")
    a("")
    a("///| RFC 6979 A.2.5 private key (NIST P-256, SHA-256)")
    a('pub const KAT_D_HEX : String = "%s"' % doc["d_hex"])
    a("")
    a("///| The public point RFC 6979 publishes for that key")
    a('pub const KAT_UX_HEX : String = "%s"' % doc["ux_hex"])
    a('pub const KAT_UY_HEX : String = "%s"' % doc["uy_hex"])
    a("")
    a('pub const KAT_KEY_TYPE : String = "%s"' % doc["key_type"])
    a('pub const KAT_CURVE_NAME : String = "%s"' % doc["curve_name"])
    a('pub const KAT_USER : String = "%s"' % doc["user"])
    a('pub const KAT_SERVICE : String = "%s"' % doc["service"])
    a("")
    a("///| One session id and everything derived from it")
    a("///|")
    a("///| `signed_blob` is what gets signed (RFC 4252 section 7: the session id")
    a("///| followed by the request *without* its signature field);")
    a("///| `request_payload` is the same request *with* the signature appended.")
    a("///| The test rebuilds both from `session_id` rather than comparing the")
    a("///| stored blobs, so the layout itself is under test.")
    a("pub(all) struct AuthCase {")
    a("  name : String")
    a("  session_id_hex : String")
    a("  signed_blob_hex : String")
    a("  sig_blob_hex : String")
    a("  request_payload_hex : String")
    a("}")
    a("")
    a("pub fn AuthCase::new(")
    a("  name : String,")
    a("  session_id_hex : String,")
    a("  signed_blob_hex : String,")
    a("  sig_blob_hex : String,")
    a("  request_payload_hex : String,")
    a(") -> AuthCase {")
    a("  { name, session_id_hex, signed_blob_hex, sig_blob_hex, request_payload_hex, }")
    a("}")
    a("")
    a("///| All auth cases")
    a("pub fn auth_cases() -> Array[AuthCase] {")
    a("  [")
    for c in doc["cases"]:
        a("    AuthCase::new(")
        a('      "%s",' % c["name"])
        a('      "%s",' % c["session_id_hex"])
        a('      "%s",' % c["signed_blob_hex"])
        a('      "%s",' % c["sig_blob_hex"])
        a('      "%s",' % c["request_payload_hex"])
        a("    ),")
    a("  ]")
    a("}")
    a("")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L))
    format_in_place(OUT)
    print("wrote %s (%d cases, %d bytes)"
          % (os.path.relpath(OUT, ROOT), len(doc["cases"]), os.path.getsize(OUT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
