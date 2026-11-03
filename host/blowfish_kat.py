"""Check the committed test vectors against the C oracle.

`verify_c/blowfish_harness.c` prints one record per line: a name, a space,
and the answer in hex.  This script reads those records and then checks
the committed MoonBit test files against them, in the direction that
catches mistakes: every constant the tests assert is looked up in the
C oracle's output.

The point is that nobody types a hex string by hand.  Hand-transcription
is how a test ends up asserting the wrong thing: a hex string of 144
characters is easy to split in the wrong place, and a vector that is off
by one word looks exactly like a vector that is right.  This script found
three such mistakes in this loop's first draft.

Usage:
    python host/blowfish_kat.py              # print the C oracle's records
    python host/blowfish_kat.py --check      # the committed tests match them
"""

import io
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "verify_c", "blowfish_kat.exe")

BLOWFISH_TEST = os.path.join(ROOT, "src", "blowfish", "blowfish_test.mbt")
BCRYPT_TEST = os.path.join(ROOT, "src", "bcrypt_pbkdf", "bcrypt_pbkdf_test.mbt")

WORD_RE = re.compile(r"0x([0-9a-f]{8})U\b")
WORD64_RE = re.compile(r"0x([0-9a-f]{16})UL\b")
STRING_RE = re.compile(r'"([0-9a-f]*)"')


def run_harness():
    if not os.path.exists(HARNESS):
        raise SystemExit(
            "%s is not there -- build it with verify_c/build_blowfish.bat" % HARNESS)
    out = subprocess.check_output([HARNESS], cwd=os.path.join(ROOT, "verify_c"))
    recs = {}
    for line in out.decode("ascii").splitlines():
        if not line.strip():
            continue
        name, _, rest = line.partition(" ")
        recs[name] = rest.strip()
    return recs


def read(path):
    with io.open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def hex_words(hexstr):
    return [hexstr[i:i + 8] for i in range(0, len(hexstr), 8)]


def check(recs):
    bad = 0

    # --- the Blowfish test -----------------------------------------------
    text = read(BLOWFISH_TEST)
    words = set(WORD_RE.findall(text))
    words64 = set(WORD64_RE.findall(text))

    for tag in ("PI_P", "EXPANDSTATE_P", "EXPAND0_P"):
        for w in hex_words(recs[tag]):
            if w not in words:
                print("MISSING: %s has no 0x%sU" % (BLOWFISH_TEST, w))
                bad += 1
    for w in hex_words(recs["ECB_BLOWFISH"]):
        if w not in words:
            print("MISSING: %s has no 0x%sU" % (BLOWFISH_TEST, w))
            bad += 1
    for tag in ("PI_S_FNV", "EXPANDSTATE_S_FNV", "EXPAND0_S_FNV"):
        hi, lo = recs[tag].split()
        if (hi + lo) not in words64:
            print("MISSING: %s has no 0x%sUL" % (BLOWFISH_TEST, hi + lo))
            bad += 1

    # --- the bcrypt_pbkdf test -------------------------------------------
    text = read(BCRYPT_TEST)
    # A hex string in the test may be split over several lines with `+`,
    # so the strings are joined before they are looked for.
    joined = "".join(STRING_RE.findall(text))
    for tag in ("BCRYPT_1", "BCRYPT_2", "BCRYPT_3", "BCRYPT_4"):
        if recs[tag] not in joined:
            print("MISSING: %s does not hold %s" % (BCRYPT_TEST, tag))
            bad += 1

    if bad:
        print("%d vector(s) do not match the C oracle" % bad)
        return 1
    print("OK  every vector in the tests matches the C oracle")
    return 0


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--print"
    recs = run_harness()
    if mode == "--check":
        return check(recs)
    for name in sorted(recs):
        print("%-20s %s" % (name, recs[name]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
