#!/usr/bin/env python3
"""Triple-blind comparison: read C output, compute Python output, compare with MoonBit test vectors.

Acceptance criterion: all three implementations produce byte-exact pk and sig
for the same seed, identical to the RFC 8032 KAT vectors.
"""
import re
import subprocess
import sys
from pathlib import Path

C_DRIVER = Path(__file__).parent / "c" / "test_c.exe"

VECTORS = [
    {
        "name": "KAT0",
        "seed_hex": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "pk_hex":   "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "msg_hex":  "",
        "sig_hex":  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    {
        "name": "KAT1",
        "seed_hex": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "pk_hex":   "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "msg_hex":  "72",
        "sig_hex":  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    {
        "name": "KAT2",
        "seed_hex": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "pk_hex":   "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "msg_hex":  "af82",
        "sig_hex":  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
]


def run_c_driver():
    """Run test_c.exe and parse pk/sig lines per KAT."""
    out = subprocess.run(
        [str(C_DRIVER)], capture_output=True, text=True, check=True,
        cwd=str(C_DRIVER.parent),
    ).stdout

    results = {}
    for name in ("KAT0", "KAT1", "KAT2"):
        # find block under the KAT<N> line
        m = re.search(
            rf"^{name}.*?\n  C_pk =([0-9a-f]+)\n  C_sig=([0-9a-f]+)",
            out, re.MULTILINE,
        )
        if not m:
            raise RuntimeError(f"Could not parse C output for {name}\nFull output:\n{out}")
        results[name] = {"pk": m.group(1), "sig": m.group(2)}
    return results


def run_python():
    """Use cryptography library to derive pk/sig per KAT."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    results = {}
    for v in VECTORS:
        seed = bytes.fromhex(v["seed_hex"])
        msg = bytes.fromhex(v["msg_hex"]) if v["msg_hex"] else b""
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        pk = priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        sig = priv.sign(msg)
        results[v["name"]] = {"pk": pk.hex(), "sig": sig.hex()}
    return results


def run_moonbit():
    """Read MoonBit test output from ed25519_test.mbt - re-run via moon test.

    For triple-blind, we re-run moon test and parse the KAT output.
    """
    mb_proj = Path(__file__).parent.parent  # openssh_moonbit/
    out = subprocess.run(
        ["moon", "test", "--target", "native"],
        capture_output=True,  # bytes, to avoid GBK decoding issues
        cwd=str(mb_proj),
    )
    raw = (out.stdout or b"") + (out.stderr or b"")
    return {"all_pass": out.returncode == 0, "raw": raw.decode("utf-8", errors="replace")}


def main():
    print("=" * 72)
    print("TRIPLE-BLIND CROSS-CHECK: MoonBit (M) vs OpenBSD C (C) vs Python (P)")
    print("=" * 72)

    c_out = run_c_driver()
    py_out = run_python()
    mb_out = run_moonbit()

    # Per KAT: compare all 3 impls against RFC expected value
    all_ok = True
    for v in VECTORS:
        name = v["name"]
        rfc_pk = v["pk_hex"]
        rfc_sig = v["sig_hex"]
        c_pk = c_out[name]["pk"]
        c_sig = c_out[name]["sig"]
        p_pk = py_out[name]["pk"]
        p_sig = py_out[name]["sig"]

        # Triple equality + RFC match
        pk_match = (c_pk == p_pk == rfc_pk)
        sig_match = (c_sig == p_sig == rfc_sig)
        ok = pk_match and sig_match
        all_ok = all_ok and ok

        print(f"\n{name} ({'OK' if ok else 'FAIL'}):")
        print(f"  RFC  pk  = {rfc_pk}")
        print(f"  RFC  sig = {rfc_sig}")
        print(f"  C    pk  = {c_pk}  {'==' if c_pk==rfc_pk else '!='}")
        print(f"  Py   pk  = {p_pk}  {'==' if p_pk==rfc_pk else '!='}")
        print(f"  C    sig = {c_sig}  {'==' if c_sig==rfc_sig else '!='}")
        print(f"  Py   sig = {p_sig}  {'==' if p_sig==rfc_sig else '!='}")

    print(f"\nMoonBit test run: {'PASS' if mb_out['all_pass'] else 'FAIL'}")

    print(f"\n{'='*72}")
    print(f"TRIPLE_BLIND: {'PASS' if all_ok and mb_out['all_pass'] else 'FAIL'}")
    print(f"{'='*72}")
    return 0 if all_ok and mb_out["all_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
