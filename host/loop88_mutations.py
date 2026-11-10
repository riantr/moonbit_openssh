"""Mutation check: every Loop #88 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Three rules this script keeps, all learned elsewhere in this repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.  A *warning* counts the same
    way: the build prints a warning and the gate's own build check turns
    red, so a mutation that leaves a variable unused cannot even be measured.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

  * **A mutation that cannot fail is not evidence either.**  A mutation whose
    check never goes red is worse than no mutation at all, because it looks
    like coverage.

**The check name is matched EXACTLY, not as a prefix.**  The gate has checks
whose names start with one another's ("-p on an unencrypted key" and "-p on an
encrypted key without -P refuses"), and a prefix match would call the second
one a hit for the first.  A mutation that is caught by the wrong check is a
mutation whose evidence says less than it appears to, so the matcher here is
a whole-line regular expression.

What this list is actually about
--------------------------------

Loop #88 makes a key file REWRITABLE: `ssh-keygen -p` (a new passphrase)
and `ssh-keygen -c` (a new comment).  The ways that can be wrong are not all
the same kind of wrong:

  * **The stdout of a rewrite says very little.**  "Key has comment 'x' /
    Your identification has been saved with the new passphrase." is the same
    whether the salt was drawn afresh or not, whether the round count is 24
    or 1, and whether the comment was written into the file at all.  So the
    gate has to look at the FILE -- at the salt at offset 47, the round count
    at 63, the check word at 98 and the cipher name at 15 -- and not only at
    the output.  A gate that only compared the output would call a rewrite
    that wrote the wrong file correct.

  * **An empty passphrase means an UNENCRYPTED file.**  That is OpenSSH's
    rule (`sshkey_private_to_blob2`), and it is the rule that makes
    `ssh-keygen -p -N ""` a way to take the passphrase OFF a key.  A writer
    that got it backwards would quietly encipher a key nobody asked to
    encipher.

  * **The salt and the check word are drawn afresh.**  The same salt and the
    same passphrase derive the same key, so a file that reuses its salt is a
    file whose old passphrase is still worth something.

  * **The round count of a rewrite is the DEFAULT, not the one the old file
    had.**  OpenSSH's `ssh-keygen` has ONE global `rounds`, which is 0
    unless `-a` was given, and `sshkey_private_to_blob2` turns a 0 into
    `DEFAULT_ROUNDS`.

  * **The two failure messages are different messages.**  `-p` says
    `Failed to load key %s` and `-c` says `Cannot load private key "%s"`.
    The difference is in OpenSSH's source, and it is one pair of quotes.

  * **A failure exits with 255 and says why on stderr.**  A tool that fails
    with 0 is a tool whose failure a script cannot see.

  * **A rewrite that keeps the old comment is a rewrite that did nothing.**
    And a rewrite that drops the passphrase when only the comment was asked
    about is a rewrite that took the passphrase off a key.

Run:  python host/loop88_mutations.py            # all of them
      python host/loop88_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch.  They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "keyfile", "rewrite.mbt"),
    os.path.join(ROOT, "src", "keyfile", "pair.mbt"),
    os.path.join(ROOT, "src", "keyfile", "encrypt.mbt"),
    os.path.join(ROOT, "cmd", "ssh_keygen", "main.mbt"),
]

# A run that is killed -- a timeout, a Ctrl-C, a runner that goes away --
# never reaches the `finally` at the bottom, and the tree is left MUTATED.
# The pristine state is therefore written to disk before anything is
# changed, and a run that finds its predecessor's leftovers puts them back
# before it starts.
#
# The backup lives under .loop88/, which is gitignored.
BACKUP_DIR = os.path.join(ROOT, ".loop88", "mutation_backup")
RUNNING = "RUNNING"


def _backup_path(name):
    return os.path.join(BACKUP_DIR, name)


def save_backup(state):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    for p, text in state.items():
        with open(_backup_path(os.path.basename(p)), "w", encoding="utf-8",
                  newline="") as fh:
            fh.write(text)
    with open(_backup_path(RUNNING), "w", encoding="utf-8", newline="") as fh:
        fh.write("a mutation run was interrupted\n")


def drop_backup():
    if not os.path.isdir(BACKUP_DIR):
        return
    for name in os.listdir(BACKUP_DIR):
        try:
            os.remove(os.path.join(BACKUP_DIR, name))
        except OSError:
            pass
    try:
        os.rmdir(BACKUP_DIR)
    except OSError:
        pass


def restore_leftovers():
    """Put back a tree that a killed run left mutated."""
    marker = _backup_path(RUNNING)
    if not os.path.exists(marker):
        return []
    restored = []
    for p in FILES:
        b = _backup_path(os.path.basename(p))
        if os.path.exists(b):
            with open(b, "r", encoding="utf-8", newline="") as fh:
                text = fh.read()
            with open(p, "w", encoding="utf-8", newline="") as fh:
                fh.write(text)
            restored.append(os.path.basename(p))
    drop_backup()
    return restored


MUTATIONS = [
    (
        # An empty passphrase means an UNENCRYPTED file.  That is
        # OpenSSH's rule (`sshkey_private_to_blob2`, sshkey.c:2850) and
        # it is the rule that makes `ssh-keygen -p -N ""` a way to take
        # the passphrase OFF a key.
        #
        # Getting it backwards breaks the OTHER end: an empty
        # passphrase goes down the enciphered path, the KDF refuses an
        # empty passphrase, and there is then no file to write.  So
        # `-p -N ""` -- which is how a passphrase is taken OFF a key --
        # writes nothing at all, and the tool says "the passphrase
        # could not be used".
        "an empty passphrase writes an enciphered file",
        '  if passphrase == "" {\n    // The unencrypted file.',
        '  if passphrase != "" {\n    // The unencrypted file.',
        "-p with an empty new passphrase",
    ),
    (
        # The salt is drawn afresh, every time.  The same salt and the
        # same passphrase derive the same key, so a file that reuses its
        # salt is a file whose old passphrase is still worth something.
        #
        # **This one is invisible in the output.**  The stdout of a
        # rewrite says that a passphrase was saved and says nothing
        # about the salt, so the check that catches it has to look at the
        # salt in the file.
        "the salt of a rewrite is not drawn afresh",
        "pub fn random_salt() -> FixedArray[Byte] {\n"
        "  @rng.bytes(SALT_LEN)\n"
        "}",
        "pub fn random_salt() -> FixedArray[Byte] {\n"
        "  let out : FixedArray[Byte] = FixedArray::make(SALT_LEN, b'\\x00')\n"
        "  out\n"
        "}",
        "two rewrites of the same key have DIFFERENT salts",
    ),
    (
        # The check word is drawn afresh too.  It is the tag that says
        # "this file was deciphered with the passphrase it thinks it
        # was", and OpenSSH draws it afresh (`check = arc4random()`).
        #
        # Like the salt, it is invisible in the output: it is in the
        # file, and only in an UNENCRYPTED file.
        "the check word of a rewrite is not drawn afresh",
        "pub fn random_check_word() -> UInt32 {\n"
        "  let b = random_check_bytes()\n"
        "  ((b[0].to_uint() << 24) & 0xFF000000U) |\n"
        "  ((b[1].to_uint() << 16) & 0x00FF0000U) |\n"
        "  ((b[2].to_uint() << 8) & 0x0000FF00U) |\n"
        "  (b[3].to_uint() & 0x000000FFU)\n"
        "}",
        "pub fn random_check_word() -> UInt32 {\n"
        "  0U\n"
        "}",
        "two rewrites of the same key have DIFFERENT check words",
    ),
    (
        # The round count of a rewrite is the DEFAULT when the caller
        # does not name one.  `ssh-keygen`'s own `rounds` is 0 unless
        # `-a` was given, and `sshkey_private_to_blob2` turns a 0 into
        # `DEFAULT_ROUNDS` (24).
        #
        # **This rule lives in `src/keyfile`, and the check that sees
        # it is the UNIT TEST** -- because the driver never passes a
        # round count of 0: it passes the default, or the number `-a`
        # gave it.  So the rule is not on the driver's path, and a
        # mutation here is caught by the test and not by a rewrite
        # case.  That is worth saying out loud: a mutation caught by a
        # different check than the one it names is still evidence, but
        # the check has to be the one that can see it.
        "the round count of a rewrite is not the default",
        "  let n = if rounds < 1 { DEFAULT_ROUNDS } else { rounds }",
        "  let n = if rounds < 1 { 1 } else { rounds }",
        "src/keyfile's tests pass on native",
    ),
    (
        # **The default round count is OpenSSH's default.**  This is
        # the rule the rewrite path really runs on: the driver passes
        # `DEFAULT_ROUNDS` when no `-a` was given, and the file has to
        # say 24 -- the number OpenSSH's own file says.
        #
        # One round more would be a file that can be opened a billion
        # times sooner, and the cost of guessing the passphrase is the
        # whole point of the KDF.
        "the default round count is not OpenSSH's default",
        "  let mut rounds = @keyfile.DEFAULT_ROUNDS\n",
        "  let mut rounds = @keyfile.DEFAULT_ROUNDS + 1\n",
        "the round count of our rewritten file is 24",
    ),
    (
        # The comparison is of the COMMENT, and the comment of a key
        # with no comment is an EMPTY comment and not an absent one.
        # OpenSSH's rule is a plain `strcmp` (ssh-keygen.c:1545).
        #
        # Inverted, the tool rewrites a file whose comment has not
        # changed and says "Comment 'x' applied" where OpenSSH says
        # "No change to comment".
        "the comment comparison is inverted",
        "  old_comment == new_comment",
        "  old_comment != new_comment",
        "-c with the same comment",
    ),
    (
        # The comment goes into the file that is written.  A rewrite
        # that dropped it would leave a key with no comment, and the
        # real tool would say so.
        #
        # **The unencrypted branch and the enciphered branch are two
        # branches**, and they are exercised by two different cases:
        # `-p -N ""` on an encrypted key writes through the unencrypted
        # one, and `-p -N <pass>` writes through the enciphered one.
        # The check that catches this one reads the comment back with
        # `-y`, which is the only mode that reads the comment out of
        # the PRIVATE block.
        "the unencrypted rewrite loses the comment",
        "    return private_file_text(pair, comment, check)",
        '    return private_file_text(pair, "", check)',
        "the comment of an unencrypted rewrite is kept",
    ),
    (
        # The same for the enciphered file, which is the one that
        # matters: the comment lives INSIDE the enciphered block there.
        "the enciphered rewrite loses the comment",
        "    pair,\n    comment,\n    check,\n    passphrase,\n",
        '    pair,\n    "",\n    check,\n    passphrase,\n',
        "the comment survived an enciphered rewrite",
    ),
    (
        # The line OpenSSH prints before it writes anything.  It is
        # `mprintf("Key has comment '%s'\n", comment)`, and the comment
        # of a key with no comment is an EMPTY comment -- so the line
        # reads `Key has comment ''`.
        "-p prints the wrong sentence",
        "    println(\"Key has comment '\" + comment + \"'\")",
        "    println(\"Key has comment \" + comment)",
        "-p on an unencrypted key",
    ),
    (
        # The NEW passphrase is the one that is saved.  Saving the OLD
        # one instead is the quiet direction: the tool says the
        # passphrase was changed and the file says otherwise.
        #
        # The real tool opens an UNENCRYPTED key with any passphrase at
        # all, so the round trip cannot see this one -- the cipher name
        # in the file's header can.
        "-p saves the OLD passphrase",
        "      req.new_passphrase,\n      req.rounds,",
        "      req.old_passphrase,\n      req.rounds,",
        "the re-enciphered key is REALLY enciphered",
    ),
    (
        # `-c` saves the file with the NEW comment.  Saving the old one
        # is a rewrite that changed nothing and said that it did.
        "-c writes the private file with the OLD comment",
        "  let text = @keyfile.private_file_text_with_passphrase(\n"
        "    pair,\n"
        "    req.new_comment,\n"
        "    opening,\n"
        "    req.rounds,\n"
        "  )",
        "  let text = @keyfile.private_file_text_with_passphrase(\n"
        "    pair,\n"
        "    comment,\n"
        "    opening,\n"
        "    req.rounds,\n"
        "  )",
        "the real tool reads the comment we changed",
    ),
    (
        # The `.pub` file is rewritten with the new comment too
        # (ssh-keygen.c:1568).  A `.pub` file with the old comment is a
        # file that says something different from the private one.
        "-c writes the .pub file with the OLD comment",
        "    @keyfile.public_file_text(pair, req.new_comment),",
        "    @keyfile.public_file_text(pair, comment),",
        "the .pub file carries the new comment",
    ),
    (
        # The two failure messages are DIFFERENT messages, and the
        # difference is in OpenSSH's source: `Failed to load key %s`
        # (ssh-keygen.c:1397) and `Cannot load private key "%s"`
        # (ssh-keygen.c:1515).  One has no quotes and the other has
        # them.
        "the failure message for -p is the -c one",
        '  if req.change_passphrase {\n    "Failed to load key "',
        '  if !req.change_passphrase {\n    "Failed to load key "',
        "the message for -p says 'Failed to load key'",
    ),
    (
        # The status of a failure is 255.  A tool that fails with
        # another number is a tool whose failure a script has to guess
        # at.
        "the exit status of a failure is not 255",
        "fn[T] fail_with(message : String) -> T {\n"
        "  eprintln(message)\n"
        "  @env.exit(255)\n"
        "}",
        "fn[T] fail_with(message : String) -> T {\n"
        "  eprintln(message)\n"
        "  @env.exit(1)\n"
        "}",
        "our tool fails with 255: -p with the wrong old passphrase",
    ),
    (
        # The file is written.  A rewrite that says it wrote a file and
        # did not is the worst kind of quiet: the tool says "Your
        # identification has been saved with the new passphrase." and
        # the key on disk still has the old one.
        #
        # The stdout cannot see this one -- it is the same either way --
        # so the check that catches it looks at the file.
        "the file is not written",
        '    if !save_private(path, text) {\n      return\n    }\n'
        '    println("Your identification has been saved with the new passphrase.")',
        '    if !save_private(path + ".bak", text) {\n      return\n    }\n'
        '    println("Your identification has been saved with the new passphrase.")',
        "the re-enciphered key is REALLY enciphered",
    ),
    (
        # Changing the comment does NOT change the passphrase: the file
        # is saved with the passphrase it was OPENED with
        # (ssh-keygen.c:1554).  A rewrite that saved it with an empty
        # passphrase would take the passphrase off the key while saying
        # that it changed a comment.
        "-c takes the passphrase off the key",
        "    req.new_comment,\n    opening,\n    req.rounds,\n",
        '    req.new_comment,\n    "",\n    req.rounds,\n',
        "the rewritten key is STILL enciphered",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop88.mjs")],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would
        # die after the last flushed line, looking exactly like "0 caught,
        # 16 missed" with no traceback in the captured stderr.  Explicit
        # utf-8 with replacement cannot raise, whatever the gate prints.
        encoding="utf-8", errors="replace", text=True,
        timeout=3600,
    )
    return r.stdout + r.stderr


def selected():
    """The mutations to run, in order.

    `--only N` runs a single one.  That is not a convenience: this list
    went through a round where the author's expectation and the
    measurement disagreed, and the way to settle such a disagreement is
    to run that one mutation and read the gate's output, not to re-run
    the whole batch and hope.
    """
    if len(sys.argv) < 3 or sys.argv[1] != "--only":
        return list(enumerate(MUTATIONS))
    idx = int(sys.argv[2])
    if idx < 0 or idx >= len(MUTATIONS):
        print("--only takes 0..%d" % (len(MUTATIONS) - 1))
        sys.exit(2)
    return [(idx, MUTATIONS[idx])]


# The checks that mean "the tree did not build" -- a mutation that lands on
# one of these is INVALID rather than caught or missed.
BUILD_FAILURES = [
    "FAIL  src/keyfile compiles on native",
    "FAIL  cmd/ssh_keygen compiles on native",
    "FAIL  cmd/ssh_keygen builds",
    "FAIL  the built ssh_keygen is there",
]


def check_failed(out, name):
    """Whether the gate reported THIS check as failed.

    The whole line, and not a prefix: the gate has checks whose names
    start with one another's ("-p on an unencrypted key" and "-p on an
    encrypted key without -P refuses"), and a prefix match would call
    the second one a hit for the first.
    """
    pattern = re.compile(r"^\s*FAIL\s+" + re.escape(name) + r"\s*(--.*)?$",
                         re.MULTILINE)
    return pattern.search(out) is not None


def main():
    # A run that was killed leaves the tree mutated.  Put it back before
    # anything else, and say so loudly -- a tree that is quietly wrong
    # measures nothing.
    restored = restore_leftovers()
    if restored:
        print("RESTORED  a previous run was interrupted; put back: %s"
              % ", ".join(restored), flush=True)
    original = read()
    failures = []
    chosen = selected()
    save_backup(original)
    try:
        for idx, (label, old, new, must_fail) in chosen:
            # The file that contains the anchor -- and it has to contain it
            # EXACTLY once, in exactly one file.  An anchor that appears
            # twice is a mutation that might hit the wrong place.
            hits = {os.path.basename(p): t.count(old) for p, t in original.items()}
            targets = [p for p, t in original.items() if t.count(old) == 1]
            if len(targets) != 1 or sum(hits.values()) != 1:
                print("SKIP  %s -- anchor hits %s" % (label, hits), flush=True)
                failures.append(label)
                continue
            target = targets[0]
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            started = time.time()
            out = run_gate()
            elapsed = time.time() - started
            if any(f in out for f in BUILD_FAILURES):
                # A mutation that does not build proves nothing about the
                # gate.  It is neither caught nor missed; it is a broken
                # mutation, and it has to be fixed.
                #
                # "does not build" covers a warning as well as an error:
                # the gate's own build check turns red on a warning, so a
                # mutation that leaves a variable unused cannot even be
                # measured.
                print("INVALID  %s -- the mutation does not build cleanly" % label, flush=True)
                failures.append(label)
                continue
            caught = check_failed(out, must_fail)
            print("%s  [%d] %s  (%.0fs)"
                  % ("CAUGHT" if caught else "MISSED", idx, label, elapsed),
                  flush=True)
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if line.startswith("  FAIL"):
                        print("        " + line.strip(), flush=True)
    finally:
        write(original)
        drop_backup()

    print()
    if failures:
        print("MUTATION CHECK FAILED: %d of %d not caught"
              % (len(failures), len(chosen)))
        return 1
    print("all %d mutations turned the gate red" % len(chosen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
