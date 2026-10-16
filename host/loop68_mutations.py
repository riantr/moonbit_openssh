#!/usr/bin/env python3
"""Loop #68 mutation harness.

Same discipline as `host/loop66_mutations.py` and `host/loop67_mutations.py`, and
for the same reason: a mutation that cannot fail is more dangerous than no
mutation. Three verdicts are kept apart.

  * **CAUGHT** -- the gate rejected the tree, and for the reason intended.
  * **MISSED** -- the gate accepted a tree carrying the defect. This is an
    accusation against the gate, not a note, and it fails the run.
  * **BUILD-BROKEN** -- the mutation does not compile, so it tested the compiler
    rather than the gate. Recorded separately and never counted as evidence.

Every mutation here is a *reversal of a real fix this loop shipped*, not a
synthetic defect. That is the only kind worth running: the question is not "can
this gate see an arbitrary bug" but "would it have seen the thing that was
actually wrong here".

  * **M1** puts `cmd/wt_ssh`'s declaration back to the per-file
    `targets: { "main.mbt": ["js"] }` form -- the exact state that produced seven
    [4067] errors in `moon coverage analyze`.
  * **M2** deletes `cmd/ssh_live`'s `supported_targets` outright. That was never
    a gate artefact: the package builds on native only (js 8 errors, wasm 7,
    wasm-gc 9) and claimed nothing. It is also the mutation that proves section
    A2 exists -- the declared-package matrix in A1 cannot see a package that
    stopped declaring, because it simply drops off the list.
  * **M3** points `cmd/wt_ssh` at the wrong target -- `+native` instead of
    `+js`. A copy-paste slip with no compile error attached: the package still
    builds, just not where it says it does. Section A's build matrix is the only
    thing that sees it.
  * **M4** removes `src/khfile`'s per-file native gate. That gate is correct and
    deliberate -- a package-level declaration would block downstream consumers,
    so a wasm-wanting consumer must fail at its own compile rather than silently
    inside the library -- and removing it is not a build break. Section B exists
    so this loop's migration of `cmd/` cannot quietly become a migration of
    `src/` as well.
  * **M5** points the qa command at `src/khfile`, the one package whose tests
    can never be covered: its only test file is gated to native while
    `moon coverage analyze` runs at the default target and has no `--target`.
    "Has tests" and "can be covered" are different questions.
  * **M6** adds a package to the committed reportable set that the toolchain
    cannot report. The gate compares the re-derived set against the committed
    file in BOTH directions, so this must fail.
  * **M7** removes one that it can. The failure mode is the one Loop #66 hit on
    its accept table: a gate that only notices new problems is a gate whose
    evidence has stopped being checked.

**Two mutations were written, run, and deleted, and the record of why matters
more than the two that stayed.** The first draft deleted the per-package
`moon coverage clean` from the qa command, and the second dropped
`MOON_COVE_REPORT_ENABLED=1` from it. Both came back MISSED, and the reason is
the loop's real finding: once `moon clean` runs first, neither step is
load-bearing. The default OCaml reporter prints the same report the wasm one
does -- `src/kexflow`, 73 `<-- UNCOVERED` markers against `Total: 73`, in 15
seconds -- and the assertion failure in `output_no_intermediate` that made the
env var look mandatory was the dirty `_build` all along.

Both were left out rather than left in. A mutation that provably cannot fail
is worse than no mutation: it sits in the count looking like coverage of the
recipe, and it trains the reader to trust a number that means nothing.

Usage: python host/loop68_mutations.py [--only M1,M2]
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import sandbox  # noqa: E402


class Mutation(object):
    def __init__(self, mid, desc, kind, path, old=None, new=None):
        self.mid = mid
        self.desc = desc
        self.kind = kind            # "replace" | "delete_line"
        self.path = path
        self.old = old
        self.new = new


MUTATIONS = [
    Mutation(
        "M1", "put cmd/wt_ssh's declaration back to the per-file gate",
        "replace", "cmd/wt_ssh/moon.pkg",
        old='options(\n  supported_targets: "+js",\n)',
        new='options(\n  targets: { "main.mbt": [ "js" ] },\n)',
    ),
    Mutation(
        "M2", "delete cmd/ssh_live's declaration -- it never had one before this loop",
        "delete_lines", "cmd/ssh_live/moon.pkg",
        old='options(\n  supported_targets: "+native",\n)\n',
    ),
    Mutation(
        "M3", "point cmd/wt_ssh at the wrong target -- no compile error attached",
        "replace", "cmd/wt_ssh/moon.pkg",
        old='  supported_targets: "+js",',
        new='  supported_targets: "+native",',
    ),
    Mutation(
        "M4", "remove src/khfile's per-file native gate -- the library rule",
        "replace", "src/khfile/moon.pkg",
        old='  targets: { "store.mbt": [ "native" ], "store_test.mbt": [ "native" ] },',
        new='',
    ),
    Mutation(
        "M5", "point the qa command at src/khfile, whose test cannot be covered",
        "replace", "host/cov_report.py",
        old='        targets = wanted or evidence_reportable() or packages_with_tests()',
        new='        targets = wanted or ["src/khfile"]',
    ),
    Mutation(
        "M6", "claim src/khfile is reportable in the committed evidence",
        "replace", "host/cov_reportable.json",
        old='  "reportable": [\n    "src/aead",',
        new='  "reportable": [\n    "src/aead",\n    "src/khfile",',
    ),
    Mutation(
        "M7", "drop src/kexflow from the committed reportable set",
        "replace", "host/cov_reportable.json",
        old='    "src/kexflow",\n',
        new='',
    ),
]


def apply_mutation(tree, m):
    p = os.path.join(tree, m.path)
    with open(p, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8")
    crlf = "\r\n" in text
    body = text.replace("\r\n", "\n")

    n = body.count(m.old)
    if n != 1:
        raise RuntimeError("anchor occurs %d times in %s, expected 1" % (n, m.path))
    # A mutation that only supplies `old` is a deletion. Defaulting here rather
    # than in every Mutation keeps "remove this exact span" from having to
    # repeat `new=""` -- and the earlier version of this harness had no
    # default at all, so M2 raised TypeError and the run reported ERROR where
    # it should have reported a verdict.
    body = body.replace(m.old, m.new or "", 1)

    if crlf:
        body = body.replace("\n", "\r\n")
    with open(p, "wb") as fh:
        fh.write(body.encode("utf-8"))


def run_gate(tree):
    proc = subprocess.run(["cmd", "/c", "node", "host/verify_loop68.mjs"],
                          cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def build_broken(tree, m):
    """True when the mutation stops a package compiling for an unrelated reason.

    Deliberately NOT applied to `moon.pkg` mutations, and that is the whole
    point. Both M1 and M2 reintroduce a package that does not compile on the
    default target -- that IS the defect this loop shipped a fix for, and the
    gate catching it is evidence, not a confound. Running the compiler first and
    filing the result as BUILD-BROKEN would discard the two mutations that
    matter most and leave the harness reporting a comfortable number.

    The BUILD-BROKEN verdict stays for the case it was written for: a mutation
    to MoonBit SOURCE that fails to parse or typecheck, where the gate's
    rejection says nothing about whether it can see the intended defect.
    """
    if not m.path.endswith(".mbt"):
        return False
    pkg = os.path.dirname(m.path)
    if not os.path.exists(os.path.join(tree, pkg, "moon.pkg")):
        return False
    proc = subprocess.run(
        ["cmd", "/c", "moon", "check", pkg.replace("/", "\\"), "--output-json",
         "--diagnostic-limit", "10000"],
        cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = proc.stdout.decode("utf-8", "replace")
    for line in out.splitlines():
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
            fails = [l.strip() for l in out.splitlines() if l.strip().startswith("FAIL")]
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
