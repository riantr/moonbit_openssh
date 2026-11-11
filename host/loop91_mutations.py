"""Mutation check: every Loop #91 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.  Each entry
is one of the ways this code could plausibly be wrong, and each names the
`host/verify_loop91.mjs` check that has to go red because of it.

Three rules, all inherited from earlier loops because all three were learned
the hard way:

  * **A compile failure is not evidence.**  A mutation that does not build
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.

  * **The anchor has to hit exactly once, in exactly one file.**  A drifted
    anchor is reported as SKIP and counted as not caught -- which points at
    the gate rather than at the thing that actually moved.

  * **The check name is matched EXACTLY, not as a prefix.**  Two of the
    section-B checks are literally the same sentence with a different key
    ("upload signed with the top-bit-set (mpint) key" and "upload signed with
    the P-384 key"), and a prefix match would credit one for the other.

What this list is about
-----------------------

Two of the mutations below exist because of a weakness this loop found in its
OWN gate, and they are the interesting ones:

  * Section A compares `ssh-keygen -y` output, which is built from the public
    POINT.  A reader that takes the wrong bytes out of the `d` field prints
    the right line and passes every check in section A.  So the scalar is
    only observable in a signature, and `#0` mutates exactly that -- it goes
    red on "upload signed with the top-bit-set (mpint) key", not on `-y`.
  * The same is true of the curve: signing a P-384 key as P-256 produces a
    key of the wrong type and the server says no.  `#1` is that mutation.

Without those two cases in the gate, both mutations would have been MISSED
while every `-y` check stayed green -- which is precisely the failure mode
this script exists to catch.

Run:
    python host/loop91_mutations.py                  # all of them
    python host/loop91_mutations.py --only 0,1       # a few, after a cancel
    python host/loop91_mutations.py --restore        # put back a killed run
"""
import os
import re
import sys
import json
import time
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "keyfile", "ecdsa.mbt"),
    os.path.join(ROOT, "src", "keyfile", "encode.mbt"),
    os.path.join(ROOT, "src", "sshclient", "link.mbt"),
    os.path.join(ROOT, "cmd", "scp", "ssh.mbt"),
    os.path.join(ROOT, "cmd", "scp", "main.mbt"),
]

BACKUP = os.path.join(ROOT, ".loop91", "mutation_backup.json")

# Output of `verify_loop91.mjs` that means "the tree did not build".
#
# **Only the build check belongs here.**  An earlier loop's script also
# treated a failing unit-test line as "did not build", and that mislabelled
# six perfectly good mutations as INVALID: a mutation aimed at a rule the
# unit tests already pin makes both red, and the verdict was decided by
# whichever marker matched first.  The named gate check has to be consulted
# first.
INVALID_MARKERS = (
    "FAIL  both drivers built",
)

MUTATIONS = [
    (
        # The mpint strip takes the wrong byte.  A key whose scalar is above
        # 2^255 (the `mpint` zero is really there) then signs with a
        # different number, and the SERVER is what notices.
        "the mpint leading zero is stripped off by one",
        "      out[i] = raw[i + 1]",
        "      out[i] = raw[i]",
        "upload signed with the top-bit-set (mpint) key",
    ),
    (
        # Every key signs as P-256.  The P-384 file still reads, still
        # prints the right public line, and is refused by the server for
        # being the wrong key type.
        "the curve of the key file is ignored and P-256 is always used",
        "@ecdsa.Curve::p384())",
        "@ecdsa.Curve::p256())",
        "upload signed with the P-384 key",
    ),
    (
        # One width for all three curves.  P-384's point is 97 bytes, so a
        # reader that says 65 refuses the file as malformed.
        "P-384's point width is the P-256 one",
        "    97",
        "    65",
        "-y k384 (P-384, 49-byte mpint scalar) is byte for byte ssh-keygen's",
    ),
    (
        # The base64 padding is stripped again -- the defect Loop #91 found
        # in this repository.  ed25519 cannot see it; ECDSA can.
        "the public line strips the base64 padding again",
        '  let b64 = @base64.encode(Bytes::from_array(blob))\n  if comment == "" {',
        '  let b64 = strip_padding(@base64.encode(Bytes::from_array(blob)))\n  if comment == "" {',
        "-y k256 (P-256, ordinary) is byte for byte ssh-keygen's",
    ),
    (
        # A subsystem name with one letter wrong.  The server refuses the
        # request, and the refusal is the only signal -- which is why the
        # link waits for CHANNEL_SUCCESS rather than assuming it.
        "the subsystem name is misspelled",
        '"sftp",',
        '"sftq",',
        "upload: one file to the host",
    ),
    (
        # `-P` parsed and then ignored.  Every case then dials 22, where
        # this machine's real server is, and nothing matches.
        "the -P port is parsed and then ignored",
        "port: if o.port_given { o.port } else { 22 }",
        "port: if o.port_given { 22 } else { 22 }",
        "upload: one file to the host",
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
        ["node", os.path.join("host", "verify_loop91.mjs")],
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
    print("loop91 mutations: %d caught, %d missed, %d invalid, %d skipped"
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
