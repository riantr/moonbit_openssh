"""Mutation check: Loop #50's default must fail *closed*, and the gate must notice.

A gate that stays green under every mutation is not testing anything.  Loop #48
and #47 both mutated their decisions; this loop mutates something narrower and,
for this particular loop, more dangerous.

Loop #50's default did not work three times in a row.  Each attempt was
correct, `moon check` passed, and a client with nothing configured kept
authenticating.  The cause was one line in `KnownHostsPolicy::verify` that
returned early when `entries` was empty, a state `decide` read as "nothing to
object to".  Nothing caught it, and the reason is structural: **a fail-open
default is invisible to every test that connects to a real peer**, because the
peer does not care what our default is.  The gate has to assert the *absence* of
credentials, and only then does a fail-open default look different from a fail-
closed one.

So these mutations are all the same bug wearing different clothes -- the default
quietly stops refusing:

  * **A: the native driver's default stops being strict.**
    `cmd/ssh_live` computes `strict` from `--kh-tofu`.  Turning it off restores
    Loop #48's unsafe default without touching the rule.

  * **B: the rule stops applying strict at all.**
    `decide` sees `Unknown` and ignores `self.strict`.  Both drivers are correct,
    both pass every one of their own arguments through faithfully, and the layer
    below quietly stops refusing.

  * **C: the browser driver's default stops being strict.**
    The same mistake as A, on the other transport.  Kept separate from A so that
    a run reports *which* side stopped refusing; a single mutation touching both
    drivers would prove only that something, somewhere, changed.

Mutation B is the one that matters most.  A and C are a wrong constant at a call
site and read as such when you see the diff.  B is the rule itself losing the
property, with every caller still passing the right arguments -- which is exactly
the shape of Loop #50's original bug.

**Undo with the snapshot below, never with `git checkout`.**  See the long note in
`host/loop48_mutations.py`: a hand-applied `git checkout -- <file>` there silently
undid a whole loop's uncommitted work in the same file, and the loss was invisible
because the file still compiled.  A mutation is never a thing to undo with git
unless it was committed first.

Four verdicts, not two: `NOBUILD` (the mutated source did not compile -- nothing
was proven either way, and reporting MISSED would point at the gate), `CRASH` (it
compiled and blew up), `CAUGHT` (a named check went FAIL) and `MISSED` (it ran and
everything still passed).

Run:  python host/loop50_mutations.py
"""

import io
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file this loop's mutations can touch, snapshotted and restored together.
FILES = [
    os.path.join(ROOT, "src", "knownhosts", "policy.mbt"),
    os.path.join(ROOT, "cmd", "ssh_live", "main.mbt"),
    os.path.join(ROOT, "cmd", "wt_ssh", "main.mbt"),
]

GATE = os.path.join(ROOT, "host", "verify_loop50.mjs")

MUTATIONS = [
    (
        "A: the native driver's default stops being strict",
        os.path.join(ROOT, "cmd", "ssh_live", "main.mbt"),
        '  let strict = !has_switch(argv, "--kh-tofu")',
        "  let strict = false",
    ),
    (
        "B: the rule ignores strict when it sees an unpinned host",
        os.path.join(ROOT, "src", "knownhosts", "policy.mbt"),
        "    Unknown =>\n      if self.strict {",
        "    Unknown =>\n      if false {",
    ),
    (
        "C: the browser driver's default stops being strict",
        os.path.join(ROOT, "cmd", "wt_ssh", "main.mbt"),
        '    return @knownhosts.KnownHostsPolicy::from_text("", host, 0, !tofu)',
        '    return @knownhosts.KnownHostsPolicy::from_text("", host, 0, false)',
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_gate():
    # `moon clean` first, every time.  This is not cargo cult here: Loop #50 spent
    # three attempts convinced its default had failed to take effect, and the
    # reason it looked that way was a stale binary reported as "no work to do".
    # A mutation that fails to show up because nothing was rebuilt would read as
    # a MISSED mutation, which points at the gate rather than at the tree.
    subprocess.run(
        ["cmd", "/c", "moon", "clean"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=900,
    )
    return subprocess.run(
        ["node", GATE],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        timeout=3600,
    )


def fails_for(out):
    """The failing check labels, in order, deduplicated.

    `verify_loop50.mjs` prints each failure twice -- once inline (indented) and
    once in its closing summary (not indented).  Only the summary lines count, so
    that one check which failed once is not reported as two failures.
    """
    labels = []
    for line in (out or "").split("\n"):
        if line.startswith("FAIL ") and line.strip() not in labels:
            labels.append(line.strip())
    return labels


def main():
    originals = {p: read(p) for p in FILES}
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0}
    try:
        for label, path, frm, to in MUTATIONS:
            # Restore the whole tree before each mutation, not just the file this
            # one touches.  The first version did not, and the cost was silent:
            # mutation B edits `src/knownhosts/policy.mbt` and mutation C edits
            # `cmd/wt_ssh`, so C ran on top of B and reported the *native* client
            # failing under a mutation that never touched it -- which invents a
            # dependency edge between the two drivers and sends the next person
            # looking for it in moon.pkg.  Attribution is the entire product here;
            # a mutation that cannot be attributed proves nothing about what it
            # seemed to prove.
            for p in FILES:
                write(p, originals[p])

            src = originals[path]
            if frm not in src:
                print("SKIP  %s -- anchor not found in %s" % (label, path))
                counts["NOBUILD"] += 1
                continue
            # An anchor that appears more than once is worse than a missing one:
            # `str.replace` rewrites *every* occurrence, so the mutation silently
            # becomes a different mutation and then reports a confident verdict
            # about it. Loop #52 lost three attempts to exactly this and called it
            # MISSED, which pointed at the gate.
            hits = src.count(frm)
            if hits != 1:
                print(
                    "NOBUILD  %s -- anchor appears %d times in %s; replace would "
                    "mutate more than intended" % (label, hits, path)
                )
                counts["NOBUILD"] += 1
                continue
            write(path, src.replace(frm, to))

            proc = run_gate()
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile" % label)
                counts["NOBUILD"] += 1
                continue
            if proc.returncode == 0:
                print("MISSED  %s -- the gate still reported ALL PASS" % label)
                counts["MISSED"] += 1
                continue
            fails = fails_for(out)
            if not fails and ("Panic" in out or "harness:" in out):
                print("CRASH  %s -- %s" % (label, out.strip().split("\n")[0][:160]))
                counts["CRASH"] += 1
                continue
            print("CAUGHT  %s" % label)
            # Which transport caught it, separated out.  A mutation in the native
            # driver must not be reported as if it had also broken the browser
            # half -- that would invent a dependency edge between the two and send
            # the next person looking for it in moon.pkg.
            for client in ("native", "browser"):
                caught_here = [f for f in fails if f.startswith("FAIL " + client + " ")]
                if caught_here:
                    print("        %-8s %s" % (client + ":", ", ".join(
                        f.split()[2] for f in caught_here
                    )))
            for f in fails:
                print("          " + f[:170])
            counts["CAUGHT"] += 1
    finally:
        # Restored together, and verified.  A mutation driver that leaves the tree
        # mutated is worse than no mutation driver, because the next run measures
        # whatever it left behind.
        for path, text in originals.items():
            write(path, text)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d NOBUILD, %d CRASH (of %d mutations)"
        % (
            counts["CAUGHT"],
            counts["MISSED"],
            counts["NOBUILD"],
            counts["CRASH"],
            len(MUTATIONS),
        )
    )
    with io.open(os.path.join(ROOT, ".loop50", "mutations.json"), "w", encoding="utf-8") as fh:
        json.dump(counts, fh, indent=2)
    return 0 if counts["MISSED"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
