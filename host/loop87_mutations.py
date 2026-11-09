"""Mutation check: every Loop #87 defect must turn the gate red.

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
called "-l on a private key" and "-l on a private key whose comment is empty",
and a prefix match would call the second one a hit for the first.  A mutation
that is caught by the wrong check is a mutation whose evidence says less than
it appears to, so the matcher here is a whole-line regular expression.

What this list is actually about
--------------------------------

Loop #87 lets the tool READ a key.  The ways that can be wrong are not all the
same kind of wrong:

  * **The two rules for an absent comment are different rules.**  OpenSSH has
    one for a `.pub` FILE (the file's name becomes the comment, authfile.c:238)
    and one for a `.pub` LINE (nothing becomes the comment,
    ssh-keygen.c:989).  They disagree, and `ssh-keygen -l -f key` and
    `ssh-keygen -l -f key.pub` really do print different things for the same
    key.  A reader that applies the wrong one is wrong in a way that looks
    right: the fingerprint is right and only the comment is off.

  * **`no comment` is not the empty comment.**  The first leaves one space in
    the line and the second leaves two.  The two are different strings in
    OpenSSH too, and the difference is a space.

  * **The public blob of an encrypted key is in the clear.**  That is why
    `ssh-keygen -l` prints the fingerprint of an encrypted key without asking
    for anything -- and why the COMMENT of that key cannot be read at all,
    because the comment lives in the enciphered block.

  * **The base64 of a fingerprint is unpadded.**  The private key file's
    base64 IS padded.  A fingerprint with the padding left on is the right
    fingerprint in the wrong spelling.

  * **The key type is checked before the blob is read.**  A reader that
    accepts any type and then looks at the bytes either reads another key's
    blob or reads past the end of one.

  * **A `known_hosts` line has a word in front of the key.**  OpenSSH skips
    it and reads the key behind it.  Skipping two words would be a guess, and
    a guess that finds a key in the wrong place is worse than a refusal.

  * **Every message OpenSSH prints is escaped.**  `strnvis` with
    `VIS_SAFE|VIS_OCTAL` (log.c:69) doubles the backslashes in a path and
    writes the control characters in octal.  A message that is not escaped is
    a message that can never be compared with OpenSSH's byte for byte.

  * **A failure exits with 255 and says why on stderr.**  A tool that fails
    with 0 is a tool whose failure a script cannot see, and a tool that says
    why on stdout is a tool whose output cannot be told apart from a key.

  * **An algorithm this repository does not have is refused, not faked.**  A
    fingerprint in the wrong form is worse than no fingerprint.

Run:  python host/loop87_mutations.py            # all of them
      python host/loop87_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch.  They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "keyfile", "public.mbt"),
    os.path.join(ROOT, "src", "keyfile", "log.mbt"),
    os.path.join(ROOT, "src", "keyfile", "pair.mbt"),
    os.path.join(ROOT, "cmd", "ssh_keygen", "main.mbt"),
]

# A run that is killed -- a timeout, a Ctrl-C, a runner that goes away --
# never reaches the `finally` at the bottom, and the tree is left MUTATED.
# The pristine state is therefore written to disk before anything is
# changed, and a run that finds its predecessor's leftovers puts them back
# before it starts.
#
# The backup lives under .loop87/, which is gitignored.
BACKUP_DIR = os.path.join(ROOT, ".loop87", "mutation_backup")
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
        # The bit count is what the fingerprint line opens with.  A wrong
        # one is a line that looks right and is not: the fingerprint in it
        # is the right fingerprint.
        "the bit count is not 256",
        "pub const ED25519_BITS : Int32 = 256",
        "pub const ED25519_BITS : Int32 = 128",
        "-l on a private key",
    ),
    (
        # OpenSSH prints the SHORT name in parentheses, not the ssh name
        # that appears in the key line.  The two are different strings in
        # OpenSSH, and confusing them changes every fingerprint line.
        "the short name is the ssh name",
        'pub const ED25519_SHORT_NAME : String = "ED25519"',
        'pub const ED25519_SHORT_NAME : String = "ssh-ed25519"',
        "-l on a private key",
    ),
    (
        # `no comment` and an empty comment are DIFFERENT strings, and the
        # difference is a space.  Printing an empty comment where OpenSSH
        # prints the word leaves one space too few.
        "no comment is printed as an empty comment",
        '    None => "no comment"',
        '    None => ""',
        "-l on the .pub file whose comment is empty",
    ),
    (
        # The base64 of a fingerprint is unpadded.  The private key file's
        # base64 IS padded, and a reader that reuses that habit prints the
        # right fingerprint in the wrong spelling.
        "the fingerprint keeps the base64 padding",
        '  "SHA256:" + strip_padding(padded)',
        '  "SHA256:" + padded',
        "-l on a private key",
    ),
    (
        # The key type is checked before the blob is read.  A reader that
        # accepts every type reads another key's blob, or reads past the
        # end of one.
        #
        # The check that goes red is the one on the `.pub` FILE and not
        # the one on the private key file, and the reason is worth
        # recording: with the type check inverted, the reader stops
        # understanding the `.pub` file, and the driver then falls back
        # to the PRIVATE file -- which still holds the same public key
        # and the same comment, so the private-key line comes out right
        # anyway.  A mutation that only the fallback hides is exactly
        # the kind that makes a gate look stronger than it is.
        "the key type check is inverted",
        "  if ktype == KEY_TYPE {",
        "  if ktype != KEY_TYPE {",
        "-l on the .pub file",
    ),
    (
        # The blob is 4 + 11 + 4 + 32 bytes and the lengths are checked
        # rather than assumed: a blob of the right size but the wrong shape
        # is a blob some other tool wrote.
        "the blob length check is off by one",
        "  if blob.length() != 4 + 11 + 4 + 32 {",
        "  if blob.length() != 4 + 11 + 4 + 31 {",
        "-l on a private key",
    ),
    (
        # A `known_hosts` line has the host name in front of the key.
        # OpenSSH skips one word and reads the key behind it; skipping two
        # would be a guess, and a guess that finds a key in the wrong
        # place is worse than a refusal.
        "the one-word skip is gone",
        '      if next > rest && line[rest:next].to_owned() == KEY_TYPE {',
        '      if next > rest && line[rest:next].to_owned() == KEY_TYPE + "x" {',
        "-l on a known_hosts line",
    ),
    (
        # The parser reports the FACT: the comment that is in the line, or
        # nothing.  An empty comment and an absent comment are different
        # facts, and OpenSSH's two rules treat them differently.
        "an empty comment is reported as an absent one",
        '      let c : String? = if comment == "" { None } else { Some(comment) }',
        '      let c : String? = if comment == "" { Some("") } else { Some(comment) }',
        "-l on the .pub file whose comment is empty",
    ),
    (
        # The comment of an ENCRYPTED key lives in the enciphered block.
        # There is nothing to read without the passphrase, and OpenSSH
        # prints `no comment` for it.
        "the comment of an encrypted key is read anyway",
        "    Some((pk, None))",
        '    Some((pk, Some("")))',
        "-l on an encrypted key with no .pub",
    ),
    (
        # The `.pub` file beside a private key decides the comment when it
        # has one, and the file's NAME when it has none
        # (authfile.c:238).  Dropping the name leaves the empty comment
        # behind, and the two are a space apart.
        "the .pub file does not decide the comment",
        '              None => path + ".pub"',
        '              None => ""',
        "-l on a private key whose comment is empty",
    ),
    (
        # Every message OpenSSH prints goes through `strnvis`, and a
        # backslash comes out doubled.  A message that is not escaped can
        # never be compared with OpenSSH's byte for byte.
        "the log escaping does not double the backslashes",
        '      out.write_string("\\\\\\\\")',
        "      out.write_char('\\\\')",
        "-l on a missing file",
    ),
    (
        # The exit status of a failure is 255.  A tool that fails with
        # another number is a tool whose failure a script has to guess at.
        "the exit status is not 255",
        "  @env.exit(255)",
        "  @env.exit(1)",
        "our tool fails with 255: -l on a missing file",
    ),
    (
        # The errors go to stderr, so that a script can tell the key from
        # the complaint about the key.
        "the error goes to stdout",
        "  eprintln(message)",
        "  println(message)",
        "our tool says nothing on stdout when it fails: -l on a missing file",
    ),
    (
        # The digest algorithm is checked before anything is done, the way
        # OpenSSH checks it.  An algorithm nobody knows is refused with
        # OpenSSH's own words.
        "the digest is not checked",
        '  if digest != "sha256" {',
        '  if digest != "sha256" && digest == "sha256" {',
        "-l -E bogus",
    ),
    (
        # `-E md5` is refused because this repository has no MD5.  The
        # refusal has to say THAT; refusing it with "invalid hash
        # algorithm" would be a different and wrong claim.
        "md5 is refused with the wrong words",
        '    if digest == "md5" || digest == "sha384" || digest == "sha512" {',
        '    if digest == "md5" && digest != "md5" {',
        "-E md5 says why",
    ),
    (
        # The printed line gets its newline from the print.  A line that
        # already had one ends with two, and a file that ends with two
        # newlines is a file with a blank line in it.
        #
        # The slice is `0 .. length` rather than the whole string on
        # purpose: the mutation has to COMPILE, and a mutation that does
        # not compile is INVALID rather than caught -- it proves nothing
        # about the gate either way.
        "the public line keeps its newline",
        "  text[0:text.length() - 1].to_owned()",
        "  text[0:text.length()].to_owned()",
        "-y on a private key",
    ),
    (
        # A file whose first line holds "PRIVATE KEY" is a private key
        # file, and a private key file is read as one.  Reading it as a
        # public key file finds no key in it.
        "a private key file is read as a public key file",
        "async fn fingerprint_of(path : String, text : String) -> (String, String?)? {\n"
        "  if is_private_key_file(text) {",
        "async fn fingerprint_of(path : String, text : String) -> (String, String?)? {\n"
        "  if is_private_key_file(text) && text.length() < 0 {",
        "-l on a private key",
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
        ["node", os.path.join("host", "verify_loop87.mjs")],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 17
        # missed" with no traceback in the captured stderr.  Explicit utf-8
        # with replacement cannot raise, whatever the gate prints.
        encoding="utf-8", errors="replace", text=True,
        timeout=3600,
    )
    return r.stdout + r.stderr


def selected():
    """The mutations to run, in order.

    `--only N` runs a single one.  That is not a convenience: this list went
    through a round where the author's expectation and the measurement
    disagreed, and the way to settle such a disagreement is to run that one
    mutation and read the gate's output, not to re-run the whole batch and
    hope.
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
    start with one another's ("-l on a private key" and "-l on a private
    key whose comment is empty"), and a prefix match would call the
    second one a hit for the first.
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
            out = run_gate()
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
            print("%s  [%d] %s" % ("CAUGHT" if caught else "MISSED", idx, label),
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
