"""Mutation check: every Loop #90 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.  Each entry
is one of the ways this code could plausibly be wrong, and each names the
`host/verify_loop90.mjs` check that has to go red because of it.

Three rules, all inherited from the earlier loops because all three were
learned the hard way:

  * **A compile failure is not evidence.**  A mutation that does not build
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.

  * **The anchor has to hit exactly once, in exactly one file.**  A drifted
    anchor is reported as SKIP and counted as not caught -- which points at
    the gate rather than at the thing that actually moved.

  * **The check name is matched EXACTLY, not as a prefix.**  Several checks
    here start with one another's words ("-r upload" and "-r upload onto an
    existing dir"), and a prefix match would credit one for the other.

What this list is about
-----------------------

`scp`'s observable behaviour is mostly *ordering and shape*, so the mutations
below are mostly ordering and shape too: which destination a source gets,
which side of a failure prints a second line, whether the target directory is
made before or after a source is known to exist, and whether a time travels
before or after the children that would move it.

The one that is a direct record of a real defect is #5: this repository's
first version of the multi-source pre-flight created the remote target
directory *before* looking at the sources, and the gate caught it as
"two MISSING sources leave no target dir".

Run:
    python host/loop90_mutations.py                  # all of them
    python host/loop90_mutations.py --only 4,5       # a few, after a cancel
    python host/loop90_mutations.py --restore        # put back a killed run
"""
import os
import re
import sys
import json
import time
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "scp", "copy.mbt"),
    os.path.join(ROOT, "src", "scp", "engine.mbt"),
    os.path.join(ROOT, "src", "scp", "run.mbt"),
    os.path.join(ROOT, "src", "scp", "msg.mbt"),
    os.path.join(ROOT, "src", "scp", "args.mbt"),
]

BACKUP = os.path.join(ROOT, ".loop90", "mutation_backup.json")

# Output of `verify_loop90.mjs` that means "the tree did not build".
#
# **Only the build check belongs here.**  An earlier version of this script
# also treated a failing `src/scp's tests pass on <target>` line as
# "did not build", and that mislabelled six perfectly good mutations as
# INVALID: a mutation aimed at a rule the unit tests already pin makes the
# tests red *and* the gate red, and the verdict was decided by whichever
# marker matched first.  The named gate check has to be consulted first.
INVALID_MARKERS = (
    "FAIL  cmd/scp builds",
)


MUTATIONS = [
    (
        # A directory source keeps its own name only when it lands INSIDE a
        # directory.  Always keeping it is the classic `cp -r` mistake, and
        # it is invisible unless the gate compares the tree.
        "a directory source always keeps its name",
        "    if target_is_dir {\n"
        "      remote_join(target, source_basename)\n"
        "    } else {\n"
        "      target\n"
        "    }\n",
        "    if true {\n"
        "      remote_join(target, source_basename)\n"
        "    } else {\n"
        "      target\n"
        "    }\n",
        "-r upload",
    ),
    (
        # The tool maps a status CODE to an errno sentence; the server's own
        # text is only a fallback.  Dropping the mapping makes the message
        # the peer's shorter spelling.
        "the status code stops being mapped to its sentence",
        "  if code == 2 {\n    reason_no_such_file()\n",
        "  if code == 202 {\n    reason_no_such_file()\n",
        "a missing remote source",
    ),
    (
        # `download <path>/: not a regular file` -- the trailing slash is
        # part of the measured sentence.
        "the remote-dir refusal loses its trailing slash",
        '"download " + path + "/: not a regular file"',
        '"download " + path + ": not a regular file"',
        "a remote dir without -r is refused",
    ),
    (
        # A missing local SOURCE is fatal (255); a refused operation is a
        # per-file failure (1).  Answering 1 for both is the most common
        # mistake there is.
        "a missing local source is downgraded to a per-file failure",
        "    StatLocal(_, _) => Fatal\n",
        "    StatLocal(_, _) => Failure\n",
        "a missing local source is fatal",
    ),
    (
        # The defect the gate actually caught: creating the multi-source
        # remote target BEFORE the sources are known.  With two sources that
        # do not exist, the real tool leaves no directory behind.
        "the multi-source target is created before the sources are checked",
        "          ctx.needs_target_dir = true\n"
        "          true\n",
        "          let _ = e.ensure_remote_dir(ctx.target_path)\n"
        "          ctx.needs_target_dir = true\n"
        "          true\n",
        "two MISSING sources leave no target dir",
    ),
    (
        # `-p` on an upload sets the remote times from the local ones.
        # The anchor carries the comment line because the same `setstat`
        # statement also appears in the tree walker, and an anchor that
        # hits twice is not a mutation.
        "an upload stops preserving the time",
        "  if preserve {\n"
        "    // `-p` on the upload side sets the remote times from the local ones.\n",
        "  if false {\n"
        "    // `-p` on the upload side sets the remote times from the local ones.\n",
        "-p upload",
    ),
    (
        # A directory's time is written AFTER its children, because writing
        # a child moves the parent's mtime.  Never writing it at all makes
        # the recursive `-p` check disagree.
        "a tree upload stops setting the directory's time",
        "  if preserve && !report.fatal {\n"
        "    let _ = self.drive.setstat(rpath, attrs_with_time(self.mtime_of(lpath)))\n"
        "  }\n",
        "  if preserve && !report.fatal && false {\n"
        "    let _ = self.drive.setstat(rpath, attrs_with_time(self.mtime_of(lpath)))\n"
        "  }\n",
        "-p -r upload keeps directory times",
    ),
    (
        # The C runtime turns every `\n` into `\r\n`; so must this, exactly
        # once.  Doing nothing leaves bare newlines the real tool never
        # prints.
        "the newline is never translated",
        "    if text[i] == '\\n' {\n",
        "    if text[i] == '\\x00' {\n",
        "no arguments prints the usage block",
    ),
    (
        # The usage block is quoted, not composed.
        "the usage block loses an option letter",
        "[-346ABCOpqRrsTv] [-c cipher]",
        "[-346ABCOpqRrsT] [-c cipher]",
        "one positional prints the usage block",
    ),
    (
        # A directory given without `-r` prints TWO lines on the upload
        # side: the refusal and the failed-to-upload that names the target.
        "the upload refusal loses its second line",
        "    report.push(NotARegularFile(src))\n"
        "    report.push(TransferFailed(direction_upload(), src, ctx.target_path))\n",
        "    report.push(NotARegularFile(src))\n",
        "a local dir without -r is refused",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def save_backup(state):
    with open(BACKUP, "w", encoding="utf-8", newline="") as fh:
        json.dump(state, fh)


def restore_leftovers():
    """Put back a tree that a killed run left mutated.

    A run that is cancelled never reaches its `finally`, so the working
    tree can be left with one mutation applied.  This is its own command
    (`--restore`) for the same reason it is in Loop #89: a second full run
    would write its own backup over the good one first.
    """
    if not os.path.exists(BACKUP):
        return []
    with open(BACKUP, "r", encoding="utf-8", newline="") as fh:
        state = json.load(fh)
    restored = []
    current = read()
    for p, text in state.items():
        if current.get(p) != text:
            restored.append(os.path.relpath(p, ROOT))
    write(state)
    os.remove(BACKUP)
    return restored


def run_gate():
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop90.mjs")],
        cwd=ROOT, capture_output=True,
        # Decoding with the locale codec (cp936 here) would raise inside the
        # batch loop on one box-drawing character and look like "everything
        # missed, no traceback".
        encoding="utf-8", errors="replace", text=True,
        timeout=3600,
    )
    return r.stdout + r.stderr


def selected():
    if len(sys.argv) >= 2 and sys.argv[1] == "--restore":
        return None
    if len(sys.argv) < 3 or sys.argv[1] != "--only":
        return list(enumerate(MUTATIONS))
    picked = []
    for part in sys.argv[2].split(","):
        part = part.strip()
        if not part:
            continue
        idx = int(part)
        if idx < 0 or idx >= len(MUTATIONS):
            raise SystemExit("no mutation %d (there are %d)" % (idx, len(MUTATIONS)))
        picked.append((idx, MUTATIONS[idx]))
    return picked


def check_failed(out, name):
    """Whether the gate reported THIS check as failed, whole line only."""
    pattern = re.compile(r"^\s*FAIL\s+" + re.escape(name) + r"\s*$", re.MULTILINE)
    return pattern.search(out) is not None


def main():
    restored = restore_leftovers()
    if restored:
        print("RESTORED  a previous run was interrupted; put back: %s"
              % ", ".join(restored), flush=True)
    chosen = selected()
    if chosen is None:
        print("nothing to run; the tree is as it was")
        return 0
    original = read()
    caught, missed, invalid, skipped = [], [], [], []
    save_backup(original)
    try:
        for idx, (label, old, new, must_fail) in chosen:
            hits = {os.path.relpath(p, ROOT): t.count(old)
                    for p, t in original.items() if t.count(old)}
            targets = [p for p, t in original.items() if t.count(old) == 1]
            if len(targets) != 1 or sum(hits.values()) != 1:
                print("SKIP  %d %s -- anchor hits %s" % (idx, label, hits), flush=True)
                skipped.append(label)
                continue
            target = targets[0]
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            started = time.time()
            out = run_gate()
            elapsed = time.time() - started
            if check_failed(out, must_fail):
                # The named gate check is the evidence this loop is after,
                # so it is consulted before anything else.  A mutation can
                # also turn a unit test red; that is worth saying out loud
                # but it does not change the verdict.
                extra = " (+ unit tests)" if "src/scp's tests pass on" in out and \
                    re.search(r"^\s*FAIL\s+src/scp's tests pass on", out, re.MULTILINE) else ""
                print("CAUGHT   %d %s -> %s%s (%.0fs)"
                      % (idx, label, must_fail, extra, elapsed), flush=True)
                caught.append(label)
            elif any(marker in out for marker in INVALID_MARKERS):
                print("INVALID  %d %s -- the tree did not build (%.0fs)"
                      % (idx, label, elapsed), flush=True)
                invalid.append(label)
            else:
                print("MISSED   %d %s -- `%s` stayed green (%.0fs)"
                      % (idx, label, must_fail, elapsed), flush=True)
                missed.append(label)
            write(original)
    finally:
        write(original)
        if os.path.exists(BACKUP):
            os.remove(BACKUP)

    print("")
    print("---")
    print("loop90 mutations: %d caught, %d missed, %d invalid, %d skipped"
          % (len(caught), len(missed), len(invalid), len(skipped)))
    if missed:
        for label in missed:
            print("  MISSED  %s" % label)
    if invalid:
        for label in invalid:
            print("  INVALID %s" % label)
    if skipped:
        for label in skipped:
            print("  SKIP    %s" % label)
    if missed or invalid or skipped:
        return 1
    print("ALL CAUGHT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
