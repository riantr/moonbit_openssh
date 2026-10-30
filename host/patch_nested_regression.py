"""Loop #85 follow-up: stop the nested regression chains from multiplying.

What this changes
-----------------

Five gates -- loop81 through loop85 -- each run a "regression" section that
re-runs the gates before them:

    loop81 -> loop78, loop79, loop80
    loop82 -> loop78, loop79, loop80, loop81
    loop83 -> loop78, loop79, loop80, loop81, loop82
    loop84 -> loop79, loop80, loop81, loop82, loop83
    loop85 -> loop79, loop80, loop81, loop82, loop83, loop84

The members were spawned WITHOUT `--skip-regression`, so each member ran its
OWN chain as well.  The result is not a chain, it is a tree: loop85 re-runs
loop84, which re-runs loop83, which re-runs loop82, ...

Measured on this machine (the local CI's own timings, 2026-10-30):

    verify_loop78.mjs     8.2s
    verify_loop79.mjs    23.4s
    verify_loop80.mjs    48.7s
    verify_loop81.mjs    85.5s
    verify_loop82.mjs   176.9s
    verify_loop83.mjs   391.1s
    verify_loop84.mjs   644.3s
    verify_loop85.mjs  1181.6s   <- the whole gates tier, nearly half

and the GitHub Actions `gates` job took 58m24s against a 60-minute cap.
One more loop would have taken it over.

The fix
-------

Spawn each member WITH `--skip-regression`, so the chain is one level deep
instead of a tree.  The coverage is not lost, and it is worth being precise
about why:

* Every member of every chain is ALSO a gate the CI engine runs directly
  (`ci/ci.py --tiers gates` runs every `host/verify_loop*.mjs` that is not a
  peer gate), so nothing stops being checked.
* The reason the nested run exists -- a gate that leaves state behind that
  breaks an EARLIER gate -- is preserved: the members still run AFTER the
  parent gate has finished its own work.  What is lost is only the
  re-checking of the members' own members, which is the same work the engine
  does anyway.

This is not a new idea in this repository: `verify_loop36.mjs`, `37` and `38`
already spawn their nested scripts with `--skip-regression` (loop36.mjs:409,
loop37.mjs:499, loop38.mjs:401).  The gates tier just never learned the
convention.

Usage:  python host/patch_nested_regression.py --check   # report, change nothing
        python host/patch_nested_regression.py --apply   # make the change
"""

import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOST = os.path.join(ROOT, "host")

# The five gates whose regression section spawns other gates.
TARGETS = ["81", "82", "83", "84", "85"]

# The single-line form used by loop81..loop84.
ONE_LINE_OLD = (
    'const r = spawnSync("node", [`host/verify_${label}.mjs`], '
    '{ cwd: ROOT, encoding: "utf8", errors: "replace" });'
)
ONE_LINE_NEW = (
    'const r = spawnSync("node", [`host/verify_${label}.mjs`, "--skip-regression"], '
    '{ cwd: ROOT, encoding: "utf8", errors: "replace" });'
)

# The wrapped form used by loop85, which gives the spawn a timeout.
WRAPPED_OLD = (
    'const r = spawnSync("node", [`host/verify_${label}.mjs`], {\n'
    '        cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 1800000,\n'
    '      });'
)
WRAPPED_NEW = (
    'const r = spawnSync("node", [`host/verify_${label}.mjs`, "--skip-regression"], {\n'
    '        cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 1800000,\n'
    '      });'
)

# The comment that says WHY, placed just above the loop.
NOTE = (
    "  // The members are spawned with `--skip-regression`, so this chain is one\n"
    "  // level deep instead of a tree.  Without it, each member ran its own chain\n"
    "  // as well: loop85 re-ran loop84, which re-ran loop83, and so on, and the\n"
    "  // gates tier grew exponentially -- 1181.6s for loop85 alone, against a\n"
    "  // 60-minute job cap that the whole tier was using up.  Nothing is lost:\n"
    "  // every member is also a gate the CI engine runs directly, and the members\n"
    "  // still run AFTER this gate's own work, so a gate that leaves state behind\n"
    "  // that breaks an earlier gate is still caught.  verify_loop36/37/38 have\n"
    "  // always done it this way.\n"
)


def read(path):
    with io.open(path, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def patch(text):
    """Apply the change.  Returns (new_text, notes)."""
    notes = []
    if ONE_LINE_OLD in text:
        text = text.replace(ONE_LINE_OLD, ONE_LINE_NEW)
        notes.append("one-line form")
    if WRAPPED_OLD in text:
        text = text.replace(WRAPPED_OLD, WRAPPED_NEW)
        notes.append("wrapped form")
    # The note goes immediately above the `for (const label of [` line.
    anchor = "  for (const label of ["
    if anchor in text and NOTE not in text:
        text = text.replace(anchor, NOTE + anchor, 1)
        notes.append("note")
    return text, notes


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "--check"
    changed = 0
    for n in TARGETS:
        path = os.path.join(HOST, "verify_loop%s.mjs" % n)
        before = read(path)
        after, notes = patch(before)
        if after == before:
            print("  %-22s already done" % os.path.basename(path))
            continue
        if mode == "--apply":
            write(path, after)
            changed += 1
            print("  %-22s patched (%s)" % (os.path.basename(path), ", ".join(notes)))
        else:
            print("  %-22s WOULD patch (%s)" % (os.path.basename(path), ", ".join(notes)))
    if mode == "--apply":
        print("patched %d file(s)" % changed)
    else:
        print("dry run; nothing written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
