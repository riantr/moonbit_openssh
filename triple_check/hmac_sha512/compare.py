#!/usr/bin/env python3
"""Triple-blind cross-check for HMAC-SHA512 (RFC 4231 § 4)."""
import re
import subprocess
import sys
from pathlib import Path

THIS_DIR = Path(__file__).parent
C_DRIVER = THIS_DIR / "test_hmac_sha512.exe"
PY_DRIVER = THIS_DIR / "python" / "verify.py"

NAME_RE = re.compile(r"^VEC name=(\S+) klen=(\d+) mlen=(\d+) got=([0-9a-f]+)")


def parse_run(text):
    out = {}
    for line in text.splitlines():
        m = NAME_RE.match(line)
        if m:
            out[m.group(1)] = (int(m.group(2)), int(m.group(3)), m.group(4))
    return out


def main():
    if not C_DRIVER.exists():
        print(f"ERROR: {C_DRIVER} not built.", file=sys.stderr)
        return 2
    c_text = subprocess.run([str(C_DRIVER)], capture_output=True, text=True, cwd=str(THIS_DIR)).stdout
    py_text = subprocess.run(["python", str(PY_DRIVER)], capture_output=True, text=True, cwd=str(THIS_DIR)).stdout
    c_results = parse_run(c_text)
    py_results = parse_run(py_text)
    all_ok = True
    print("=" * 72)
    print("TRIPLE-BLIND: HMAC-SHA512 (MoonBit / C / Python)")
    print("=" * 72)
    for name in sorted(set(c_results) | set(py_results)):
        c = c_results.get(name)
        p = py_results.get(name)
        if c is None or p is None:
            all_ok = False
            print(f"  {name}: MISSING (c={c} p={p})")
            continue
        c_k, c_m, c_h = c
        p_k, p_m, p_h = p
        match = (c_k == p_k) and (c_m == p_m) and (c_h == p_h)
        all_ok = all_ok and match
        print(f"  {name} klen={c_k} mlen={c_m}:")
        print(f"    C  = {c_h}")
        print(f"    Py = {p_h}")
        print(f"    {'BYTE_EXACT' if match else 'MISMATCH'}")
    mb = subprocess.run(["moon", "test"], capture_output=True, cwd=str(THIS_DIR.parent.parent))
    mb_text = ((mb.stdout or b"") + (mb.stderr or b"")).decode("utf-8", errors="replace")
    m = re.search(r"Total tests: (\d+), passed: (\d+), failed: (\d+)", mb_text)
    if m:
        total, passed, failed = int(m.group(1)), int(m.group(2)), int(m.group(3))
        print(f"\n  MoonBit (moon test): {passed}/{total} passed, {failed} failed")
        all_ok = all_ok and (failed == 0)
    print(f"\nHMAC_SHA512_TRIPLE_BLIND: {'PASS' if all_ok else 'FAIL'}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
