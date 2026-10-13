"""Mutation check: Loop #48's pinning decision must turn the gate red.

A gate that stays green under every mutation is not testing anything.  These
mutate exactly the decisions `host/verify_loop48.mjs` exists to cover -- the
comparison itself, and the adapters' refusal to act on its answer.

  * **a mismatch reported as a match.**  `KnownHostsPolicy::verify` computes the
    comparison and then throws the verdict away.  The code still *looks* like it
    pins, which is exactly why it has to be mutated rather than eyeballed.

  * **`src/sshclient` discarding the verdict.**  The rule lives in one place, so
    one adapter could read it and ignore it.  The browser half is not mutated:
    leaving one of the two standing is what makes the next mutation say
    something about the other.

    The anchor moved in Loop #50.  The adapters used to pattern-match
    `kh.verify`'s verdict themselves; they now call `kh.decide` and match on
    `PinFailure`.  Same decision, one place instead of two -- but an anchor that
    names the old shape would have reported SKIP, and a SKIP looks exactly like a
    gate that has nothing left to catch.

Only the pinning comparison is mutated, never the signature check above it: a
self-consistent peer passes that check by construction, so mutating it would
only re-test Loop #47.

Four verdicts, not two.  `NOBUILD` (the mutated source did not compile -- nothing
was proven either way, and calling it MISSED would point at the gate), `CRASH`
(it compiled and blew up), `CAUGHT` (a named check went FAIL) and `MISSED` (it
ran and everything still passed).  Under a two-valued scheme a `PanicError` and
"no output at all" are indistinguishable and both get reported as MISSED.

**Undo with the backup below, never with `git checkout`.**  The first version of
this driver was debugged by hand with `git checkout -- src/sshclient/live.mbt`,
and because the loop's own uncommitted changes sat in that same file it silently
undid the work as well -- an hour lost, and the loss was invisible because the
file still compiled.  This driver snapshots every file it may touch and restores
from the snapshot; a mutation is never a thing to undo with git unless it was
committed first.

**The same mistake, subtler.**  While chasing a hunch that a mutation in
`src/sshclient` was leaking into the browser half, a hand-applied `git checkout`
wiped the loop's work out of a *second* file, and repeated manual
mutation/restore cycles left the tree in a state no single run had described.
For a while the driver reported `browser mismatch` failing under a mutation that
touches only the native adapter -- an apparently impossible result.  It was not
impossible; the tree was not what was believed.  A single-process diagnostic
(baseline / A / B / baseline, restoring from memory) settled it and showed the
browser half behaving correctly throughout.  The lesson is the first one again:
when a result is impossible, suspect the tree before suspecting the code.

Run:  python host/loop48_mutations.py
"""

import io
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file this loop's gate can reach through, restored together.
FILES = [
    os.path.join(ROOT, "src", "knownhosts", "policy.mbt"),
    os.path.join(ROOT, "src", "sshclient", "live.mbt"),
]

GATE = os.path.join(ROOT, "host", "verify_loop48.mjs")

MUTATIONS = [
    (
        "A: a pinned mismatch is reported as a match",
        os.path.join(ROOT, "src", "knownhosts", "policy.mbt"),
        "    Mismatch => Mismatch",
        "    Mismatch => Accept",
    ),
    (
        "B: src/sshclient discards the pinning verdict",
        os.path.join(ROOT, "src", "sshclient", "live.mbt"),
        "    Some(@knownhosts.PinFailure::Mismatch(h)) => return (Failed(HostkeyMismatch(h)), None)",
        "    Some(@knownhosts.PinFailure::Mismatch(h)) => ()",
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_gate():
    # `moon clean` first, every time. moon's build cache is keyed on content, so
    # a mutation that was reverted byte-for-byte before the next one is *not*
    # the problem -- but a stale js artifact is, and it looks exactly like the
    # mutation leaking into a client that was not touched. This gate rebuilds
    # both halves anyway, so the clean costs seconds and removes the question.
    subprocess.run(
        ["cmd", "/c", "moon", "clean"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=600,
    )
    return subprocess.run(
        ["node", GATE],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        timeout=1800,
    )


def fails_for(out):
    """The failing check labels, in order, without the gate's own duplicate.

    `verify_loop48.mjs` prints each failure twice -- once inline as it happens
    (indented) and once in its closing summary (not indented). Two mistakes came
    out of that:

      * counting both copies, which read as "two clients caught it";
      * and worse, taking *both* copies of a check that only failed once, which
        made a mutation confined to `src/sshclient` look as though it had also
        broken the browser half. It had not -- `src/wtlive` calls `kh.verify` at
        its own site. The second mistake is the dangerous one: it invents a
        dependency edge between the two adapters that does not exist, and the
        natural next step is to go looking for it in `moon.pkg`.

    So: the summary lines only, which is one per distinct failing check.
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
            # one touches.  Mutation A edits `src/knownhosts/policy.mbt` and
            # mutation B edits `src/sshclient/live.mbt`, so without this B ran on
            # top of A -- and the per-client breakdown then attributed a policy
            # mutation to the adapter.  The summary below already warns about
            # inventing dependency edges between the two clients; leaving the
            # mutations stacked is how that mistake gets made for real.
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
                "errors." in out and "ALL PASS" not in out and proc.returncode != 0
                and "  FAIL " not in out
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
            # Which clients caught it, separated out: this gate runs the same
            # cases over TCP and in a browser, and a mutation in one adapter
            # must not be reported as if it had been caught by both. Reading
            # "browser mismatch" under a mutation that only touched
            # `src/sshclient` is exactly the kind of thing that sends you
            # looking for a dependency edge that does not exist -- `moon clean`
            # was run first, so it is not a stale artifact either.
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
        # Restored together, and verified: a mutation driver that leaves the tree
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
    with io.open(os.path.join(ROOT, ".loop48", "mutations.json"), "w", encoding="utf-8") as fh:
        json.dump(counts, fh, indent=2)
    return 0 if counts["MISSED"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())