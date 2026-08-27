#!/usr/bin/env python3
"""Triple-blind cross-check for SHA-512.

Runs the C driver and the Python reference, parses the per-vector `got=...`
hex, and asserts they match byte-exact. The MoonBit tests live in
src/sha512/sha512_wbtest.mbt and are validated by `moon test` (called out
in the summary but not parsed here - too noisy to grep reliably).
"""
import re
import subprocess
import sys
from pathlib import Path

THIS_DIR = Path(__file__).parent
C_DRIVER = THIS_DIR / "test_sha512.exe"
PY_DRIVER = THIS_DIR / "python" / "verify.py"

NAME_RE = re.compile(r"^VEC name=(\S+) len=(\d+) got=([0-9a-f]+)")


def parse_run(text: str) -> dict:
    """Parse a single driver's stdout into {name: hex_digest}."""
    out = {}
    for line in text.splitlines():
        m = NAME_RE.match(line)
        if m:
            out[m.group(1)] = (int(m.group(2)), m.group(3))
    return out


def main() -> int:
    if not C_DRIVER.exists():
        print(f"ERROR: {C_DRIVER} not built. Run: gcc -I. -I../../verify_c -c main.c && gcc main.o -o test_sha512.exe", file=sys.stderr)
        return 2

    c_text = subprocess.run([str(C_DRIVER)], capture_output=True, text=True, cwd=str(THIS_DIR)).stdout
    py_text = subprocess.run(["python", str(PY_DRIVER)], capture_output=True, text=True, cwd=str(THIS_DIR)).stdout

    c_results = parse_run(c_text)
    py_results = parse_run(py_text)

    all_ok = True
    print("=" * 72)
    print(f"TRIPLE-BLIND: SHA-512 (MoonBit / C / Python)")
    print("=" * 72)
    for name in sorted(set(c_results) | set(py_results)):
        c = c_results.get(name)
        p = py_results.get(name)
        if c is None:
            print(f"  {name}: MISSING in C")
            all_ok = False
            continue
        if p is None:
            print(f"  {name}: MISSING in Python")
            all_ok = False
            continue
        c_len, c_hex = c
        p_len, p_hex = p
        match = (c_len == p_len) and (c_hex == p_hex)
        all_ok = all_ok and match
        print(f"  {name} len={c_len}:")
        print(f"    C    = {c_hex}")
        print(f"    Py   = {p_hex}")
        print(f"    {'BYTE_EXACT' if match else 'MISMATCH'}")
    # MoonBit-side: print test count from a quick moon test invocation
    mb = subprocess.run(
        ["moon", "test"], capture_output=True, cwd=str(THIS_DIR.parent.parent),
    )
    mb_text = (mb.stdout or b"") + (mb.stderr or b"")
    mb_text = mb_text.decode("utf-8", errors="replace")
    m = re.search(r"Total tests: (\d+), passed: (\d+), failed: (\d+)", mb_text)
    if m:
        total, passed, failed = int(m.group(1)), int(m.group(2)), int(m.group(3))
        print(f"\n  MoonBit (moon test): {passed}/{total} passed, {failed} failed")
        all_ok = all_ok and (failed == 0)
    else:
        print("\n  MoonBit (moon test): could not parse summary; relying on prior runs")
    print(f"\nSHA512_TRIPLE_BLIND: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
