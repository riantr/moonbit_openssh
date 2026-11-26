#!/usr/bin/env python3
"""Loop #103's mutation suite: does `host/verify_loop103.mjs` actually notice?

Each mutation breaks ONE rule the gate claims to protect, re-runs the gate,
and requires a NAMED check to go red.  A mutation that leaves the gate green
is MISSED; one that breaks the build is INVALID; one whose anchor has drifted
is SKIP, which counts as not caught.

The check name is matched as a WHOLE LINE in the gate's output, and the named
check is looked for BEFORE the build result -- a mutation that breaks the
build must not be allowed to claim credit for a check it never reached.

The mutation harness edits the working tree and restores it in a `finally`.
Run it alone: it runs `moon build` for every mutation, and this file's own
record (Loop #93, and AGENTS.md before it) is that concurrent moon runs
produce failures that look like gate failures.

    python host/loop103_mutations.py
"""

import io
import os
import shutil
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "host", "verify_loop103.mjs")

# The files a mutation may touch.  Everything a mutation anchors on has to be
# here: an anchor in a file the harness does not restore is a mutation that
# corrupts the tree instead of testing it.
FILES = [
    os.path.join(ROOT, "src", "sshcopyid", "msg.mbt"),
    os.path.join(ROOT, "src", "sshcopyid", "install.mbt"),
    os.path.join(ROOT, "src", "sshcopyid", "flow.mbt"),
    os.path.join(ROOT, "cmd", "ssh_copy_id", "main.mbt"),
]

# (label, old, new, the check that must go red)
MUTATIONS = [
    (
        # Upstream's closing sentence repeats the `-o` and `-F` options it
        # was given: they live in one list (`OPTS_oF`) and that list is
        # printed with the target.  A closing sentence without them is a
        # sentence that tells the user to run a command with fewer options
        # than the one that was just used.
        "the closing sentence drops the -o options",
        '    s = s + "-" + a.flag + " \'" + quote_of(a.value) + "\' "\n',
        '    s = s + ""\n',
        "our stdout is upstream's closing block, byte for byte",
    ),
    (
        # The space after `-p` is upstream's: the template is
        # `"${SFTP:-ssh} ${SEEN_OPT_I:+...}${SSH_PORT:+-${PORT_OPT:-p} $SSH_PORT }"`,
        # and `$SSH_PORT ` carries the space.  Without it the hint says
        # `-p22273`, which is a different command.
        "the closing sentence loses the space after -p",
        '    s = s + "-" + flag + " " + o.port.to_string() + " "\n',
        '    s = s + "-" + flag + o.port.to_string() + " "\n',
        "our stdout is upstream's closing block, byte for byte",
    ),
    (
        # The POSIX command is upstream's own bytes, captured from the real
        # script's argv.  One space is the whole difference between "the
        # same command" and "a command that looks like it".
        "the posix command loses a space",
        '"exec sh -c \' cd; umask 077; AUTH_KEY_FILE=\\"" +\n',
        '"exec sh -c \' cd;umask 077; AUTH_KEY_FILE=\\"" +\n',
        "the command our source builds is upstream's own bytes, byte for byte",
    ),
    (
        # The Windows script's first step is upstream's `mkdir -p`: without
        # it the install fails on a server whose directory is not there yet.
        "the windows script stops making the directory",
        '  "if(-not(Test-Path $d)){[IO.Directory]::CreateDirectory($d)|Out-Null}\\n" +\n',
        '  "" +\n',
        "the script the source builds makes the directory first",
    ),
    (
        # The last step is upstream's `cat >> "${AUTH_KEY_FILE}"`: the key
        # arrives on stdin and is appended.  Anything else appends
        # something that is not the key.
        "the windows script stops appending stdin",
        '  "[IO.File]::AppendAllText($p,[Console]::In.ReadToEnd())\\n"\n',
        '  "[IO.File]::AppendAllText($p,\\"x\\")\\n"\n',
        "the script the source builds ends by appending stdin to the file",
    ),
    (
        # Upstream counts the keys with `printf '%s\\n' "$NEW_IDS" | wc -l`,
        # so a file with one key in it is ONE key and not zero.  Counting
        # the newlines alone reports "0 key(s) remain" for a file with a
        # key in it.
        "the key count forgets the last line",
        "  if text[n - 1] == '\\n' {\n    count\n  } else {\n    count + 1\n  }\n",
        "  if text[n - 1] == '\\n' {\n    count\n  } else {\n    count\n  }\n",
        "our stderr is upstream's three INFO lines, byte for byte",
    ),
    (
        # The answer "the server accepted this key" is the only thing that
        # makes the tool say "all keys were skipped".  Reading it as a
        # refusal turns the second run into a second install.
        "an accepted key is read as a refused one",
        "    @sshclient.Authenticated(_) => @sshcopyid.CopyIdAuth::Accepted\n",
        '    @sshclient.Authenticated(_) => @sshcopyid.CopyIdAuth::Rejected("no")\n',
        "our stderr is upstream's 'already installed' block, byte for byte",
    ),
    (
        # The dry run must change nothing.  A dry run that falls through to
        # the install writes the key -- and then the file says the key was
        # installed by a command that promised it would not.
        "the dry run installs the key anyway",
        "      if o.dry_run {\n",
        "      if o.dry_run && o.force {\n",
        "authorized_keys did not grow",
    ),
]


def read_all():
    out = {}
    for p in FILES:
        if os.path.exists(p):
            with io.open(p, "r", encoding="utf-8", newline="") as fh:
                out[p] = fh.read()
    return out


def restore(saved):
    for p, text in saved.items():
        with io.open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


# ---------------------------------------------------------------- the backup
#
# The harness edits the working tree.  If it is killed half way through, the
# tree is left mutated -- and a tree that is left mutated is a tree that the
# next `git diff` blames on the next person.
#
# So the originals are copied aside before anything is touched, and the copy
# is marked DONE when the run ends cleanly.  A copy that is NOT marked DONE
# is the debris of an interrupted run, and the next run restores it before it
# starts.  Nothing is deleted: the copies are in `.loop103/`, which is
# ignored, and one directory per run is cheap.
BACKUP_ROOT = os.path.join(ROOT, ".loop103")


def backup_dir():
    return os.path.join(BACKUP_ROOT, "mutation_backup_%d" % int(time.time() * 1000))


def rescue_interrupted():
    """Restore the tree from an interrupted run's backup, if there is one."""
    if not os.path.isdir(BACKUP_ROOT):
        return
    for name in sorted(os.listdir(BACKUP_ROOT)):
        if not name.startswith("mutation_backup_"):
            continue
        d = os.path.join(BACKUP_ROOT, name)
        if not os.path.isdir(d):
            continue
        done = os.path.join(d, "DONE")
        if os.path.exists(done):
            continue
        restored = []
        for p in FILES:
            copy = os.path.join(d, os.path.basename(p))
            if os.path.exists(copy):
                shutil.copyfile(copy, p)
                restored.append(os.path.basename(p))
        with io.open(done, "w", encoding="utf-8") as fh:
            fh.write("restored by a later run\n")
        if restored:
            print("NOTE  restored %s from an interrupted run (%s)"
                  % (", ".join(restored), name), flush=True)


def make_backup(saved):
    d = backup_dir()
    os.makedirs(d, exist_ok=True)
    for p in FILES:
        if os.path.exists(p):
            shutil.copyfile(p, os.path.join(d, os.path.basename(p)))
    return d


def mark_done(d):
    with io.open(os.path.join(d, "DONE"), "w", encoding="utf-8") as fh:
        fh.write("the run finished\n")


# ------------------------------------------------------------------- the run
def run_gate():
    """Run the gate and return (exit code, output).

    The gate takes minutes, and this process may sit silent for most of
    them.  A run that says nothing for a minute looks like a run that died,
    so a heartbeat is printed while the gate works, and the gate's own
    output is streamed rather than collected.
    """
    proc = subprocess.Popen(
        ["node", GATE],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        errors="replace",
    )
    collected = []
    stop = threading.Event()

    def pump():
        for line in proc.stdout:
            collected.append(line)
            sys.stdout.write("      | " + line)
            sys.stdout.flush()

    def heartbeat():
        waited = 0
        while not stop.wait(20):
            waited += 20
            print("      | ... the gate is still running (%d s)" % waited, flush=True)

    t1 = threading.Thread(target=pump, daemon=True)
    t2 = threading.Thread(target=heartbeat, daemon=True)
    t1.start()
    t2.start()
    code = proc.wait()
    stop.set()
    t1.join(timeout=10)
    return code, "".join(collected)


# The gate's own name for "this tree does not build".
#
# A mutation that breaks the BUILD is INVALID: the gate never got far enough
# to judge the claim, so its silence is not evidence about the claim either
# way.
BUILD_SENTINEL = "FAIL  the tool builds"


def main():
    rescue_interrupted()
    saved = read_all()
    results = []
    backup = make_backup(saved)
    try:
        for idx, (label, old, new, check) in enumerate(MUTATIONS):
            hits = 0
            target = None
            for p, text in saved.items():
                n = text.count(old)
                if n:
                    hits += n
                    target = p
            if hits != 1:
                print("SKIP  %d %s -- anchor hits %d" % (idx, label, hits), flush=True)
                results.append(("skip", label, check))
                continue
            mutated = saved[target].replace(old, new, 1)
            with io.open(target, "w", encoding="utf-8", newline="") as fh:
                fh.write(mutated)
            print("MUTATE %d %s -- %s" % (idx, label, check), flush=True)
            try:
                code, out = run_gate()
            finally:
                restore(saved)
            named = ("FAIL  %s" % check) in out
            # The named check is consulted FIRST.  A mutation that turns its
            # own check red has been caught, whatever else went red with it.
            if named:
                print("CAUGHT %3d %s -> %s" % (idx, label, check), flush=True)
                results.append(("caught", label, check))
            elif BUILD_SENTINEL in out:
                print("INVALID%3d %s -- the tree did not build" % (idx, label), flush=True)
                results.append(("invalid", label, check))
            else:
                print("MISSED %3d %s -- `%s` stayed green" % (idx, label, check), flush=True)
                results.append(("missed", label, check))
    finally:
        restore(saved)
        mark_done(backup)

    caught = [r for r in results if r[0] == "caught"]
    missed = [r for r in results if r[0] == "missed"]
    invalid = [r for r in results if r[0] == "invalid"]
    skipped = [r for r in results if r[0] == "skip"]
    print("")
    print("---")
    print("loop103 mutations: %d caught, %d missed, %d invalid, %d skipped"
          % (len(caught), len(missed), len(invalid), len(skipped)))
    for kind, rows in (("MISSED", missed), ("INVALID", invalid), ("SKIP", skipped)):
        for _, label, check in rows:
            print("  %-8s %s -> %s" % (kind, label, check))
    if missed or invalid or skipped:
        return 1
    print("ALL CAUGHT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
