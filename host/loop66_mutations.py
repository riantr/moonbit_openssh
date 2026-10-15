#!/usr/bin/env python3
"""Loop #66 mutation harness.

Each mutation reintroduces a defect the gate is supposed to catch, in an
isolated `git worktree` copy (ci/sandbox.py), and the gate is run there. The
developer's tree is only ever read.

Discipline this file keeps, and why:

  * **MISSED and EQUIVALENT are different columns.** A MISSED is an accusation:
    the gate should have failed and did not, so the gate is weak. An
    EQUIVALENT is a discovery: the gate failed, but for a reason that is not the
    one intended -- usually the mutation failed to compile. A mutation caught by
    a compile error is **not evidence that the gate works**; it is reported as
    BUILD-BROKEN and counted separately.

  * **Every anchor is unique and ASCII-only.** The `edit` tool cannot round-trip
    CJK, and a non-unique anchor silently edits the wrong site.

  * **M3 is the true fix, and the gate must still reject it.** `moonbitlang/async`
    really is unused in `src/khfile` by every textual measure; deleting it is
    what a future reader will try, and it breaks eight tests. Loop #65 found the
    same shape -- a mutation that *is* the fix, which a gate must not accept.
    A harness that cannot fail is more dangerous than no harness.

Usage: python host/loop66_mutations.py [--only M1,M2]
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import sandbox  # noqa: E402


class Mutation(object):
    def __init__(self, mid, desc, path, old, new, live=False):
        self.mid = mid
        self.desc = desc
        self.path = path
        self.old = old
        self.new = new
        self.live = live


MUTATIONS = [
    Mutation(
        "M1", "re-add the dead moonbitlang/core/bytes import to src/tcp",
        "src/tcp/moon.pkg",
        "options(",
        'import {\n  "moonbitlang/core/bytes",\n}\n\noptions(',
    ),
    Mutation(
        "M2", "re-add the src/tcp dependency to src/sshclient",
        "src/sshclient/moon.pkg",
        '  "openssh/openssh_moonbit/src/transport",',
        '  "openssh/openssh_moonbit/src/transport",\n  "openssh/openssh_moonbit/src/tcp",',
    ),
    Mutation(
        "M3", "delete src/khfile's moonbitlang/async -- the true fix, and a break",
        "src/khfile/moon.pkg",
        '  "moonbitlang/async",\n',
        "",
    ),
    Mutation(
        "M4", "re-introduce the write-only in_section in parse_ssh_config",
        "src/sshconfig/parser.mbt",
        "  let mut saw_any = false",
        "  let mut in_section = false\n  let mut saw_any = false",
    ),
    Mutation(
        "M5", "make cmd/ssh_live read r.method again",
        "cmd/ssh_live/main.mbt",
        '"method: " + r.auth_method',
        '"method: " + r.method',
    ),
    Mutation(
        "M6", "drop the deliberate justification from src/khfile's moon.pkg",
        "src/khfile/moon.pkg",
        "  // back. Do not \"clean it up\".\n",
        "",
    ),
    Mutation(
        "M7", "delete an accept-table entry that still occurs",
        "host/collect_warnings.py",
        '    ("src/khfile/moon.pkg", "13"): (',
        '    ("src/khfile/moon.pkg", "99"): (',
        live=True,
    ),
    Mutation(
        "M8", "add a genuinely dead import so the live equality must break",
        "cmd/aes_test/moon.pkg",
        "import {",
        'import {\n  "openssh/openssh_moonbit/src/sshwire",',
        live=True,
    ),
]


def apply_mutation(tree, m):
    p = os.path.join(tree, m.path)
    with open(p, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    n = text.count(m.old)
    if n != 1:
        raise RuntimeError("anchor in %s occurs %d times, expected 1"
                           % (m.path, n))
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(text.replace(m.old, m.new, 1))


def run_gate(tree, live):
    argv = ["cmd", "/c", "node", "host/verify_loop66.mjs"]
    if not live:
        argv.append("--skip-live")
    proc = subprocess.run(argv, cwd=tree, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    out = proc.stdout.decode("utf-8", "replace")
    return proc.returncode, out


def build_broken(tree, m):
    """True when the mutation itself does not compile.

    Run against `moon check` on the touched package. A mutation that cannot
    build has not tested the gate -- it tested the compiler.
    """
    pkg = os.path.dirname(m.path)
    proc = subprocess.run(
        ["cmd", "/c", "moon", "check", pkg, "--output-json",
         "--diagnostic-limit", "10000"],
        cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    raw = proc.stdout.decode("utf-8", "replace")
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        if '"message"' in line and "Warning (" not in line:
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
            rc, out = run_gate(tree, m.live)
            names = [l for l in out.splitlines()
                     if l.startswith("FAIL") or l.startswith("SKIP")]
            if build_broken(tree, m) and rc != 0:
                verdict = "BUILD-BROKEN"
                broken += 1
            elif rc != 0:
                verdict = "CAUGHT"
                caught += 1
            else:
                verdict = "MISSED"
                missed += 1
            print("   verdict: %s" % verdict)
            for l in names[:6]:
                print("   %s" % l.strip())
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
