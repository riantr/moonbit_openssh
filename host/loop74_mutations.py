#!/usr/bin/env python3
"""Loop #74 mutation harness.

Same discipline as `host/loop68_mutations.py`, and for the same reason: a
mutation that cannot fail is worse than no mutation.

  * **M1** puts the `-b` splice back to the literal index that shipped the bug,
    `args.splice(3, 0, '-b', String(bits))`, which inserts `-b <bits>` BETWEEN
    `-f` and its filename. This one is unusual and worth explaining.

Every other mutation harness in this repository edits MoonBit source or a
declaration, and runs a gate that inspects the tree. M1 edits the *helper the
gate spawns*, and the gate runs that helper for real against an empty directory.

That is possible only because of what Loop #74 added to
`host/sshd_setup.mjs`: `--dir <path>` and `--keys-only`. Before them there was no
way to ask "does this code work on a machine that has never run it?" without
starting a server and binding a port -- and, more to the point, no way to ask it
on a machine where the answer was already `true` for the wrong reason. The four
host keys on a developer machine date from 2026-09-30, so
`if (!existsSync(priv))` had not executed since the line was written.

**M1 is therefore the first mutation here that is guaranteed to fail, and it
fails for the intended reason**: the helper exits non-zero, the gate's section A
turns red, and the message carries ssh-keygen's own `Too many arguments`. It was
verified CAUGHT before this harness was written; if you are reading this while
the mutation comes back MISSED, something about the sandbox or the flag parsing
changed, not about the gate.

What is deliberately NOT here:

  * A mutation of `verify_loop74.mjs` itself. The gate spawns
    `host/sshd_setup.mjs` by path, so a mutation that renames or disables that
    call would make the gate exit 0 having checked nothing -- a MISSED that is
    indistinguishable from a pass. The Loop #71 rule applies: a gate that is
    excluded from its own checking must say so, and here the honest answer is
    that such a mutation cannot be written as one that is supposed to be caught.
  * A mutation for the `-C 'loop31 test host key'` comment (section D of the
    gate). Rebuilding the argument array as a single string would break it, but
    that rewrite changes the code's shape rather than reversing a fix this loop
    shipped, and it would be caught by section A first -- for the same reason,
    not for its own.

Usage: python host/loop74_mutations.py [--only M1]
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))
import sandbox  # noqa: E402


MUTATIONS = [
    {
        "mid": "M1",
        "desc": "put the -b splice back to the literal index that shipped the bug",
        "path": "host/sshd_setup.mjs",
        "old": "if (bits !== null) args.splice(args.indexOf(priv) + 1, 0, '-b', String(bits));",
        "new": "if (bits !== null) args.splice(3, 0, '-b', String(bits));",
    },
]


def apply_mutation(tree, m):
    p = os.path.join(tree, m["path"])
    with open(p, "rb") as fh:
        raw = fh.read()
    text = raw.decode("utf-8")
    crlf = "\r\n" in text
    body = text.replace("\r\n", "\n")
    n = body.count(m["old"])
    if n != 1:
        raise RuntimeError("anchor occurs %d times in %s, expected 1" % (n, m["path"]))
    body = body.replace(m["old"], m["new"], 1)
    if crlf:
        body = body.replace("\n", "\r\n")
    with open(p, "wb") as fh:
        fh.write(body.encode("utf-8"))


def run_gate(tree):
    proc = subprocess.run(["cmd", "/c", "node", "host/verify_loop74.mjs"],
                          cwd=tree, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def main():
    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))

    caught = missed = 0
    for m in MUTATIONS:
        if only and m["mid"] not in only:
            continue
        print("== %s  %s" % (m["mid"], m["desc"]))
        tree = sandbox.make_sandbox(ROOT)
        try:
            apply_mutation(tree, m)
            rc, out = run_gate(tree)
            fails = [l.strip() for l in out.splitlines() if l.strip().startswith("FAIL")]
            verdict = "CAUGHT" if rc != 0 else "MISSED"
            if rc != 0:
                caught += 1
            else:
                missed += 1
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
    print("mutations=%d CAUGHT=%d MISSED=%d"
          % (caught + missed, caught, missed))
    if missed:
        print("a MISSED is an accusation against the gate, not a note")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
