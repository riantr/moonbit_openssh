"""Find which coverage dump keys disagree, and how.

Loop #68, second diagnostic. The first guess -- "a package with two test drivers
emits two incompatible dumps" -- is REFUTED by this repo's own data: src/aead,
src/chacha, src/ed25519, src/sha256, src/sha512, src/poly1305, src/x25519,
src/kexc25519 and src/hmac_sha512 all have a blackbox AND a whitebox driver, so
the shape cannot be what decides it.

(src/bpacket and src/hmac did fail this way while this was being written, and
that turned out to be a stale instrumented `_build` rather than anything about
the drivers -- see host/cov_probe.py. The comparison above still holds, and for
a stronger reason than it did at the time.)

So this script does not guess a cause. It reports the fact: for every key that
appears in more than one dump, whether the arrays are identical, and if not how
their lengths differ. Whatever the pattern is, it is in the output.

Usage: python host/cov_conflict.py <package>
"""
from __future__ import annotations

import glob
import io
import os
import re
import sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_RE = re.compile(r'"(openssh/[^"]+)"\s*:\s*(\[[^\]]*\])')


def parse(path):
    raw = io.open(path, encoding="utf-8").read()
    body = raw.split("----- BEGIN MOONBIT COVERAGE -----", 1)[-1]
    body = body.split("----- END MOONBIT COVERAGE -----", 1)[0].strip().rstrip(",")
    return dict(KEY_RE.findall(body)) if body else {}


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else "src/hmac"
    dumps = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "_build", "moonbit_coverage_*.txt"))):
        dumps[os.path.basename(path)] = parse(path)
    print("dumps: %d" % len(dumps))

    owners = defaultdict(list)
    for name, table in dumps.items():
        for key in table:
            owners[key].append(name)

    prefix = "openssh/openssh_moonbit/" + want + "$"
    mine = {k: v for k, v in owners.items() if k.startswith(prefix)}
    if not mine:
        print("no key for %s in any dump" % want)
        return 1

    multi = {k: v for k, v in mine.items() if len(v) > 1}
    print("%s keys: %d, of which in >1 dump: %d" % (want, len(mine), len(multi)))

    bad = []
    for key, names in sorted(multi.items()):
        vals = [dumps[n].get(key) for n in names]
        uniq = {v for v in vals}
        if len(uniq) > 1:
            bad.append(key)
    print("keys whose VALUE differs between dumps: %d" % len(bad))
    for key in bad[:10]:
        names = mine[key]
        print("\n  %s" % key)
        for n in names:
            v = dumps[n].get(key)
            print("    len=%-5d %s" % (len(v.split(",")) if v else -1, n))
    if not bad:
        print("\n  (all shared keys are byte-identical across dumps)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
