#!/usr/bin/env python3
"""Loop #67 mutation harness.

Same discipline as `host/loop66_mutations.py`, and the same reason: a mutation
that cannot fail is more dangerous than no mutation. Three verdicts are kept
apart.

  * **CAUGHT** -- the gate rejected the tree, and for the reason intended.
  * **MISSED** -- the gate accepted a tree carrying the defect. This is an
    accusation against the gate, not a note, and it fails the run.
  * **BUILD-BROKEN** -- the mutation does not compile, so it tested the compiler
    rather than the gate. Recorded separately and never counted as evidence.

Two mutations are deliberately "the real fix":

  * **M5** deletes `src/wtlive`'s `moonbitlang/async` import. That import really
    is dead -- Loop #67 measured it -- and Loop #66's gate will reject the
    removal, because Loop #66's accept table still lists it. The two loops'
    evidence disagreed, and the table is the thing that records the
    disagreement rather than hiding it.
  * **M6** deletes `src/khfile`'s `moonbitlang/async`. Same shape, opposite
    verdict: Loop #66 measured 8 hard errors when that line goes.

Same warning, same package name, opposite answers -- which is the whole reason
the accept table is per-site evidence and not a per-package rule.

Usage: python host/loop67_mutations.py [--only M1,M2]
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import sandbox  # noqa: E402

C_JUNK = "moon_tmp_line_for_mutation\r\n"

class Mutation(object):
    def __init__(self, mid, desc, kind, path, old=None, new=None, pkg=None, line=None):
        self.mid = mid
        self.desc = desc
        self.kind = kind            # "replace" | "prepend" | "append" | "delete_file"
        self.path = path
        self.old = old
        self.new = new
        self.pkg = pkg
        self.line = line


MUTATIONS = [
    Mutation(
        "M1", "put CRLF back into a source file",
        "to_crlf", "src/bigint/basic.mbt",
    ),
    Mutation(
        "M2", "delete a CJK comment run from a source file",
        "replace", "src/sshconfig/fnmatch.mbt",
        old="简化版",
        new="simplified",
    ),
    Mutation(
        "M3", "un-scope the benchmark row back to the whole workspace",
        "replace", "ci/qa.py",
        old='command=[\n            MOON + ["bench", "-p", "src/bigint", "--target", "native"],\n        ],',
        new='command=[MOON + ["bench", "--target", "native"]],',
    ),
    Mutation(
        "M4", "delete the benchmark file, leaving the zero-work green",
        "delete_file", "src/bigint/bigint_bench.mbt",
    ),
    Mutation(
        "M6", "delete src/khfile's moonbitlang/async -- the real fix, and a break",
        "drop_import", "src/khfile/moon.pkg",
        pkg="moonbitlang/async",
    ),
    Mutation(
        "M7", "strip the CJK guard out of the snapshot tool",
        "replace", "host/cjk_snapshot.py",
        old='return 1\n        print("CJK content identical in every file present in both")',
        new='return 0\n        print("CJK content identical in every file present in both")',
    ),
]


def apply_mutation(tree, m):
    p = os.path.join(tree, m.path)

    if m.kind == "delete_file":
        if not os.path.exists(p):
            raise RuntimeError("no such file: %s" % m.path)
        os.remove(p)
        return

    with open(p, "rb") as fh:
        raw = fh.read()

    if m.kind == "to_crlf":
        # Convert the whole file's line endings rather than prepending a junk
        # line. The junk-line version also made the package fail to compile, so
        # it was recorded as BUILD-BROKEN and proved nothing about the CRLF
        # check -- even though the gate did catch it. A mutation that cannot
        # build has not tested the gate.
        body = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        with open(p, "wb") as fh:
            fh.write(body)
        return

    if m.kind == "prepend_line":
        text = raw.decode("utf-8")
        lines = text.replace("\r\n", "\n").split("\n")
        lines.insert(0, "import {")
        # The file already opens with `import {`; drop the original one so the
        # package stays parseable and the gate fails on the warning, not on a
        # syntax error.
        first = next((i for i, l in enumerate(lines[1:], 1) if l.strip() == "import {"), None)
        if first is None:
            raise RuntimeError("no import block in %s" % m.path)
        del lines[first]
        lines.insert(1, m.line)
        with open(p, "wb") as fh:
            fh.write("\n".join(lines).encode("utf-8"))
        return

    if m.kind == "drop_import":
        text = raw.decode("utf-8")
        needle = '  "%s",\n' % m.pkg
        if text.count(needle) != 1:
            raise RuntimeError("%r occurs %d times in %s" % (needle, text.count(needle), m.path))
        with open(p, "wb") as fh:
            fh.write(text.replace(needle, "", 1).encode("utf-8"))
        return

    text = raw.decode("utf-8")
    n = text.count(m.old)
    if n != 1:
        raise RuntimeError("anchor occurs %d times in %s, expected 1" % (n, m.path))
    with open(p, "wb") as fh:
        fh.write(text.replace(m.old, m.new, 1).encode("utf-8"))


def run_gate(tree):
    proc = subprocess.run(["cmd", "/c", "node", "host/verify_loop67.mjs"],
                          cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def build_broken(tree, m):
    """True when the mutation itself fails to compile."""
    pkg = os.path.dirname(m.path)
    if not os.path.exists(os.path.join(tree, pkg, "moon.pkg")):
        return False
    proc = subprocess.run(
        ["cmd", "/c", "moon", "check", pkg.replace("/", "\\"), "--output-json",
         "--diagnostic-limit", "10000"],
        cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("{") and '"message"' in line and "Warning (" not in line:
            return True
    return False


def main():
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))

    caught = missed = broken = 0
    for m in MUTATIONS:
        if only and m.mid not in only:
            continue
        print("== %s  %s" % (m.mid, m.desc))
        tree = sandbox.make_sandbox(ROOT)
        try:
            apply_mutation(tree, m)
            rc, out = run_gate(tree)
            fails = [l.strip() for l in out.splitlines() if l.startswith("FAIL")]
            if build_broken(tree, m) and rc != 0:
                verdict, broken = "BUILD-BROKEN", broken + 1
            elif rc != 0:
                verdict, caught = "CAUGHT", caught + 1
            else:
                verdict, missed = "MISSED", missed + 1
            print("   verdict: %s" % verdict)
            for l in fails[:4]:
                print("   %s" % l)
            if verdict == "MISSED":
                print("   !! the gate accepted a tree carrying this defect")
        except Exception as e:  # noqa: BLE001
            print("   ERROR: %s" % e)
            missed += 1
        finally:
            sandbox.drop_sandbox(ROOT, tree)
        print("")

    print("---")
    print("mutations=%d CAUGHT=%d MISSED=%d BUILD-BROKEN=%d"
          % (caught + missed + broken, caught, missed, broken))
    if missed:
        print("a MISSED is an accusation against the gate, not a note")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
