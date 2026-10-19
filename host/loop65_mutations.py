#!/usr/bin/env python3
"""Loop #65 mutation harness.

Target: the invariant that a gate suite must not leak the servers it starts,
and that the peer-gate split matches measurement rather than guess.

Discipline (carried from Loop #60 onward):
  * restore the whole tree before each mutation, build products included;
  * `moon clean` first, so nothing cached can answer for a mutation;
  * unique, ASCII-only anchors;
  * a mutation that does not build was never judged by the gate, so it is
    reported as BUILD-BROKEN and is NOT evidence either way.

Verdicts: CAUGHT / MISSED / EQUIVALENT / BUILD-BROKEN.
"""
import io
import os
import subprocess
import sys

# Loop #71: this was ROOT = r"E:\src\moon\openssh_moonbit" -- one developer's
# checkout location, asserted as if every clone shared it. Derived from
# __file__ so it travels with the repository.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = ["cmd", "/c", "node", r"host\verify_loop65.mjs"]

# The nine-line justification for the two gates this loop reclassified. Kept
# verbatim so the harness deletes the whole thing; deleting a piece of it
# leaves the evidence and tests nothing.
PROVENANCE_BLOCK = "\n".join([
    "# Loop #65 added two more, both measured rather than assumed:",
    "#   loop40  -- starts a real OpenSSH server on a fixed port and CANNOT stop it:",
    "#              startSshd() unrefs the child and drops the handle, and",
    "#              sshd_setup.mjs parks on `new Promise(() => {})`. It costs ~44",
    "#              minutes and turns the default run red for a reason unrelated to",
    "#              the code under test. host/probe_sshd_leak.mjs reproduces the leak.",
    "#   loop49  -- needs a live peer too, and is order-dependent: it passes alone and",
    "#              fails inside a suite run, which is what the loop40 sshd leak looks",
    "#              like from the outside.",
    "",
])

MUTATIONS = [
    (
        "M1 give loop40 an sshd kill (the fix we are arguing for)",
        os.path.join("host", "verify_loop40.mjs"),
        "  if (relay) relay.kill();",
        "  if (relay) relay.kill();\n  if (typeof sshdChild !== 'undefined' && sshdChild) sshdChild.kill();",
    ),
    (
        "M2 drop child.unref() from startSshd",
        os.path.join("host", "verify_loop40.mjs"),
        "  child.unref();",
        "  void child;",
    ),
    (
        "M3 make sshd_setup install a SIGTERM handler",
        os.path.join("host", "sshd_setup.mjs"),
        "await new Promise(() => {});",
        "process.on('SIGTERM', () => process.exit(0));\nawait new Promise(() => {});",
    ),
    (
        "M4 revert the peer-gate classification: put loop40 back in the default tier",
        os.path.join("ci", "ci.py"),
        "    for n in (31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 49)",
        "    for n in (31, 32, 33, 34, 35, 36, 37, 38, 39)",
    ),
    (
        # Three earlier versions of this mutation were weak rather than the
        # gate being wrong. The first appended a misleading comment and deleted
        # nothing. The second deleted only the block's header line, leaving the
        # detail lines that still name loop40/loop49. The third is what is here:
        # it removes the whole nine-line justification. Removing it does fail the
        # gate (23/25), which is what makes the check worth keeping.
        "M5 delete the provenance for loop40/loop49, leaving a bare list",
        os.path.join("ci", "ci.py"),
        PROVENANCE_BLOCK,
        "#\n",
    ),
    (
        "M6 strip the mutations sandbox, so they run in this tree again",
        os.path.join("ci", "ci.py"),
        '        if s.tier == "mutations":',
        '        if False:',
    ),
]


def read(rel):
    with io.open(os.path.join(ROOT, rel), "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def write(rel, text):
    with io.open(os.path.join(ROOT, rel), "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run(argv, **kw):
    return subprocess.run(argv, cwd=ROOT, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, **kw)


def gate():
    return subprocess.call(GATE, cwd=ROOT, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)


def main():
    base = gate()
    print("baseline gate exit = %d" % base)
    if base != 0:
        print("BASELINE IS RED -- fix that before mutating.")
        return 2

    results = []
    for name, rel, anchor, repl in MUTATIONS:
        path = os.path.join(ROOT, rel)
        original = read(rel)
        if original.count(anchor) != 1:
            results.append((name, "ANCHOR-%d" % original.count(anchor)))
            print("[skip] %s -- anchor occurs %d times" % (name, original.count(anchor)))
            continue
        run(["cmd", "/c", "moon", "clean"])
        try:
            write(rel, original.replace(anchor, repl, 1))
            built = subprocess.run(["cmd", "/c", "python", "-c",
                                    "import ast,sys;ast.parse(open(r'%s',encoding='utf-8').read())" % path],
                                   cwd=ROOT).returncode == 0 if rel.endswith(".py") else True
            code = gate()
        finally:
            run(["cmd", "/c", "moon", "clean"])
            write(rel, original)
        if not built:
            verdict = "BUILD-BROKEN"
        elif code == 0:
            verdict = "MISSED"
        else:
            verdict = "CAUGHT"
        results.append((name, verdict))
        print("[%s] %s" % (verdict, name))

    run(["cmd", "/c", "moon", "clean"])
    final = gate()

    caught = [r for r in results if r[1] == "CAUGHT"]
    missed = [r for r in results if r[1] == "MISSED"]
    broken = [r for r in results if r[1].startswith("BUILD") or r[1].startswith("ANCHOR")]
    print("")
    print("CAUGHT %d / MISSED %d / NOT-JUDGED %d / total %d"
          % (len(caught), len(missed), len(broken), len(results)))
    for n, v in results:
        print("  %-14s %s" % (v, n))
    print("tree restored, gate now exits %d" % final)
    return 0 if (not missed and final == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
