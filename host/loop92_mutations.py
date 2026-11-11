"""Mutation check: every Loop #92 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.  Each entry
is one of the ways this code could plausibly be wrong, and each names the
`host/verify_loop92.mjs` check that has to go red because of it.

Three rules, all inherited from earlier loops because all three were learned
the hard way:

  * **A compile failure is not evidence.**  A mutation that does not build
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.

  * **The anchor has to hit exactly once, in exactly one file.**  A drifted
    anchor is reported as SKIP and counted as not caught -- which points at
    the gate rather than at the thing that actually moved.

  * **The check name is matched EXACTLY, not as a prefix.**

What this list is about
-----------------------

Four of the mutations below exist because of defects this loop found while
writing the gate, and they are the interesting ones:

  * The `longname` had SEVEN spaces too few between the group column and
    the size.  Every listing differs by seven characters, and nothing else
    in the gate would have noticed.

  * The permission word's "other" field was a constant.  It is the access
    control list's, and it is the difference between `0o100600` and
    `0o100607` -- so a constant is right in one directory and wrong in
    every other one.  The gate found it because the bed sits on a drive
    whose ACL grants "everybody" more than the temp directory's does.

  * The real server answers 4096 for a directory's size in a STAT and 0 in
    a listing.  Two different questions, two different answers, and the
    first version of this code answered 0 in both.

  * The `C` file had never been compiled: `moon check` does not build the
    native stub, only `moon test` and `moon build` do.  It had a struct
    type that does not exist and an uninitialised pointer in it.

Run:
    python host/loop92_mutations.py                  # all of them
    python host/loop92_mutations.py --only 0,1       # a few, after a cancel
    python host/loop92_mutations.py --restore        # put back a killed run
"""
import os
import re
import sys
import json
import time
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "sftpserver", "longname.mbt"),
    os.path.join(ROOT, "src", "sftpserver", "session.mbt"),
    os.path.join(ROOT, "src", "sftpserver", "localfs.c"),
]

BACKUP = os.path.join(ROOT, ".loop92", "mutation_backup.json")

# Output of `verify_loop92.mjs` that means "the server did not build".
#
# **Only the build check belongs here.**  A mutation aimed at a rule the
# unit tests already pin makes both red, and the verdict must be decided by
# the named gate check first.
#
# **The build failure has to be spelled the way the gate spells it.**  The
# gate stops at `FAIL  cmd/sftp_server does not build` when the tree does
# not compile, and that string -- not the name of the check that follows it
# -- is what has to be here, or a mutation that breaks the build is
# reported as MISSED instead of INVALID.
INVALID_MARKERS = (
    "FAIL  cmd/sftp_server does not build",
    "FAIL  our server built",
)

MUTATIONS = [
    (
        # The gap between the group column and the size.  Seven spaces too
        # few puts the size seven columns to the left of where the real
        # server puts it, and every listing differs.
        "the longname's gap before the size column is one space",
        '  " -        -" +\n  "        " +',
        '  " -        -" +\n  " " +',
        "OPENDIR, READDIR, READDIR again, CLOSE",
    ),
    (
        # The date's switch moves far enough that a half-year-old file is
        # still "recent", and the date column changes form.
        "the date switches form at the wrong age",
        "pub const HALF_YEAR_SECONDS : Int64 = 15768000L",
        "pub const HALF_YEAR_SECONDS : Int64 = 999999999L",
        "OPENDIR, READDIR, READDIR again, CLOSE",
    ),
    (
        # STAT's word becomes FSTAT's.  The two are measured to be
        # different, and a client that prints the number would see it.
        "STAT reports FSTAT's permission word",
        "else { 33152 }",
        "else { 33206 }",
        "STAT of a file and of a missing path",
    ),
    (
        # The ACL's "other" bits are thrown away, which is what the first
        # version of this code did -- and it is right in one directory and
        # wrong in every other one.
        "the access control list's bits are ignored",
        "  let other = if is_readonly { other_bits & 5 } else { other_bits & 7 }",
        "  let other = 0",
        "STAT of a file and of a missing path",
    ),
    (
        # `posix-rename` REPLACES the target, which the draft's RENAME
        # refuses to do.  Without the replace flag the rename fails when
        # the target is there.
        "posix-rename does not replace the target",
        "MOVEFILE_REPLACE_EXISTING",
        "0",
        "posix-rename moves a file over another one",
    ),
    (
        # The read cap.  The real server never returns more than 65536
        # bytes however much was asked for.
        "the READ answer is not capped",
        "      let want = if len > READ_MAX { READ_MAX } else { len }",
        "      let want = len",
        "a READ never returns more than 65536 bytes",
    ),
    (
        # An unknown request TYPE gets no reply at all -- measured, and a
        # difference the client sees.
        "an unknown request type is answered with a failure",
        "    Unknown(_) => None",
        "    Unknown(_) => Some(reply_status(0, FX_FAILURE))",
        "an unknown request TYPE is answered with nothing",
    ),
    (
        # The batch size of a listing.  The real server answers a hundred
        # entries at a time.
        "a listing is not cut into batches of a hundred",
        "pub const READDIR_BATCH : Int32 = 100",
        "pub const READDIR_BATCH : Int32 = 1000",
        "OPENDIR the directory with a hundred and fifty files",
    ),
    (
        # The handle is a SLOT: closing one frees it, and the next open
        # takes it again.
        "a closed handle does not free its slot",
        "\th->in_use = 0;",
        "\th->in_use = 1;",
        "a handle number is reused after a close",
    ),
    (
        # The permission word the server reports for an OPEN file, which is
        # FSTAT's and not STAT's.  The read-only file's answer is 33060, and
        # it is a different number -- so the gate has to FSTAT a read-only
        # file to reach that branch at all.
        "FSTAT reports STAT's permission word",
        "pub fn fstat_perm_word(is_readonly : Bool) -> Int32 {\n  if is_readonly {\n    33060",
        "pub fn fstat_perm_word(is_readonly : Bool) -> Int32 {\n  if is_readonly {\n    33024",
        "FSTAT of a read-only file",
    ),
    (
        # The read-only file's STAT word is built on 33024, not on 33152.
        # The gate stats a writable file AND a read-only one for exactly
        # this reason.
        "a read-only file is given the writable file's permission word",
        "else if is_readonly { 33024 }",
        "else if is_readonly { 33152 }",
        "STAT of a file and of a missing path",
    ),
    (
        # The write bit is taken off the ACL's answer for a read-only file:
        # the ACL grants 7 and the read-only file answers 5.
        "a read-only file keeps the ACL's write bit",
        "let other = if is_readonly { other_bits & 5 } else { other_bits & 7 }",
        "let other = if is_readonly { other_bits & 7 } else { other_bits & 7 }",
        "STAT of a file and of a missing path",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read()
            for p in FILES if os.path.exists(p)}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def save_backup(state):
    os.makedirs(os.path.dirname(BACKUP), exist_ok=True)
    with open(BACKUP, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def restore_leftovers():
    """Put back a run that was cancelled before its `finally`.

    A run that is cancelled never reaches its `finally`, so the working
    tree can be left with one mutation applied.  This is its own command
    (`--restore`) because a second full run would write its own backup over
    the good one first.
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
        ["node", os.path.join("host", "verify_loop92.mjs")],
        cwd=ROOT, capture_output=True,
        # Decoding with the locale codec would raise inside the batch loop
        # on one box-drawing character and look like "everything missed, no
        # traceback".
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
                # so it is consulted before anything else.
                print("CAUGHT   %d %s -> %s (%.0fs)"
                      % (idx, label, must_fail, elapsed), flush=True)
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
    print("loop92 mutations: %d caught, %d missed, %d invalid, %d skipped"
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
