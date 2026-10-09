"""Emit cmd/hostkey_test/vectors.mbt from host/hostkey_oracle.py.

Run:  python host/gen_hostkey_vectors.py

Nothing here is hand-transcribed.  The oracle builds every blob with paramiko
and re-derives every expected outcome from OpenSSH's C; this file only formats
its output as MoonBit.

Errors are emitted as the *name* of the `KeyError` variant rather than as its
constructor index.  An index would keep compiling -- and keep silently
comparing the wrong thing -- if the enum ever gained a variant; a name has to
be resolved by an exhaustive match on the KAT side, so a new variant turns
the KAT red instead of quietly shifting everything.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import hostkey_oracle as O  # noqa: E402

OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "cmd", "hostkey_test", "vectors.mbt",
)

HEADER = '''///| GENERATED FILE -- do not edit by hand.
///| Regenerate with: python host/gen_hostkey_vectors.py
///|
///| Source: host/hostkey_oracle.py plus host/hostkey_capture.py.
///|
///| Three independent origins, and the distinction matters:
///
///|   * `real_*` cases are bytes an actual OpenSSH 8.0p1 sshd put on the wire
///|     over an actual exchange hash it computed.  They are the only vectors
///|     that cannot be argued with.
///|   * the rest are blobs paramiko 5.0 built, with the expected outcome
///|     re-derived from ssh-rsa.c:490-570 line by line.
///|   * every case expected to be `Accepted` was additionally verified raw by
///|     `cryptography` 50.0 before being written here, so the KAT cannot agree
///|     that a garbage signature is valid.
///
///| `err` is the *name* of a `KeyError` variant, not its index.

///|
///| One host key blob and what parsing it should yield.
pub(all) struct KeyCase {
  name : String
  blob_hex : String
  expect_parsed : Bool
  err : String
  type_name : String
  bits : Int
}

///|
///| One signature over one message, checked against one negotiated algorithm.
pub(all) struct SigCase {
  name : String
  key_blob_hex : String
  msg_hex : String
  sig_hex : String
  alg : String
  expect_accepted : Bool
  err : String
}

///|
///| One PKCS#1 v1.5 encoded-message shape, parsed without any RSA maths.
pub(all) struct Pkcs1Case {
  name : String
  digest : Int
  msg_hex : String
  em_hex : String
  expect_ok : Bool
}

'''

DIGEST_NAME = {"rsa-sha2-256": O.RSA_SHA256_ID, "rsa-sha2-512": O.RSA_SHA512_ID}


def mstr(s):
    return '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"')


def hexlit(b):
    """Render bytes as a MoonBit string, wrapped so the file stays readable."""
    h = b.hex()
    if len(h) <= 96:
        return '"%s"' % h
    chunks = [h[i:i + 96] for i in range(0, len(h), 96)]
    return " +\n    ".join('"%s"' % c for c in chunks)


def main():
    cases = O.build()
    real = O.load_capture()
    if not O.selfcheck(cases):
        print("oracle self-check failed; refusing to write vectors")
        return 1
    if not real:
        print("no real capture found; run host/hostkey_capture.py first")
        return 1

    keys = {c["name"]: c for c in cases["key"]}
    out = [HEADER]

    out.append("pub let kat_key_cases : Array[KeyCase] = [\n")
    for c in cases["key"]:
        out.append(
            "  { name: %s, blob_hex: %s, expect_parsed: %s, err: %s, "
            "type_name: %s, bits: %d },\n"
            % (mstr(c["name"]), hexlit(c["blob"]),
               "true" if c["expect"] == "Parsed" else "false",
               mstr(c["err"]), mstr(c["type"]), c["bits"])
        )
    out.append("]\n\n")

    # the real captures reference the same host keys by name
    out.append("pub let kat_sig_cases : Array[SigCase] = [\n")
    for c in cases["sig"] + real:
        if c["key"] == "__inline__":
            blob = c["key_blob"]
        else:
            blob = keys[c["key"]]["blob"]
        out.append(
            "  { name: %s, key_blob_hex: %s, msg_hex: %s, sig_hex: %s,\n"
            "    alg: %s, expect_accepted: %s, err: %s },\n"
            % (mstr(c["name"]), hexlit(blob), hexlit(c["msg"]), hexlit(c["sig"]),
               mstr(c["alg"]),
               "true" if c["expect"] == "Accepted" else "false",
               mstr(c["err"]))
        )
    out.append("]\n\n")

    out.append("pub let kat_pkcs1_cases : Array[Pkcs1Case] = [\n")
    for c in cases["pkcs1"]:
        out.append(
            "  { name: %s, digest: %d, msg_hex: %s, em_hex: %s, expect_ok: %s },\n"
            % (mstr(c["name"]), DIGEST_NAME[c["digest"]],
               hexlit(O.MESSAGES["m1"]), hexlit(c["em"]),
               "true" if c["expect"] else "false")
        )
    out.append("]\n\n")

    out.append(
        "///| How many vectors came off a real sshd rather than off paramiko.\n"
        "pub let kat_real_capture_count : Int = %d\n" % len(real)
    )

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("".join(out))
    print("wrote %s (%d bytes)" % (OUT, os.path.getsize(OUT)))
    print("  key=%d sig=%d pkcs1=%d real=%d"
          % (len(cases["key"]), len(cases["sig"]), len(cases["pkcs1"]), len(real)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
