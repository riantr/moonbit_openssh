"""Mutation check: every Loop #85 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Three rules this script keeps, all learned elsewhere in this repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.  A *warning* counts the same
    way: `moon run` exits non-zero when the build prints a warning, so a
    mutation that leaves a variable unused cannot even be measured.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

  * **A mutation that cannot fail is not evidence either.**  A mutation whose
    check never goes red is worse than no mutation at all, because it looks
    like coverage.

What this list is actually about
--------------------------------

Loop #85 gave the client the ability to MAKE a key, and the ways that can be
wrong are not all the same kind of wrong:

  * **The format is one byte off.**  `openssh-key-v1` is a format with a
    published layout, and the natural mistake is to read OpenSSH's "cstring"
    as "a NUL-terminated string" when it means "a string with no NUL inside".
    That mistake costs one byte per field and produces a file that no reader
    accepts -- including our own reader, and including OpenSSH's.

  * **The file says one thing and means another.**  The public key blob is
    inside the private file AND in the `.pub` file.  If those two disagree,
    the file is claiming two different keys, and a reader that trusts one of
    them is wrong.

  * **The check words are not the same word twice.**  They exist so that a
    wrong passphrase decrypts to something that is almost never equal to
    itself.  Here there is no passphrase, so the words are only ever equal to
    themselves -- and a writer that puts two different words in is producing a
    file that OpenSSH calls a "checkint mismatch".

  * **The tool says no and then does the thing anyway.**  This is the
    dangerous one, and it is why the driver refuses a passphrase rather than
    ignoring it: a tool that accepts `-N secret` and writes an UNENCRYPTED
    key loses a secret quietly.  A refusal that prints a message and then
    writes the file anyway is exactly that failure with an extra sentence in
    front of it.

  * **The file is not actually private.**  On Windows a new file inherits the
    directory's ACL, which normally lets "Authenticated Users" read it, and
    OpenSSH refuses to use a key file like that.  So there are two ways to
    get this wrong that are both invisible from the MoonBit side: installing
    an ACL that lets somebody else in, and reporting success without
    installing one at all.

  * **The reader stops reading.**  A writer with no reader is a writer nobody
    can check.  The reader is also the only thing that turns a file back into
    a usable key, so a reader that takes the wrong half of the secret key for
    the seed produces a file that opens and yields a DIFFERENT key.

Run:  python host/loop85_mutations.py            # all of them
      python host/loop85_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch.  They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "keyfile", "keyfile.mbt"),
    os.path.join(ROOT, "src", "keyfile", "blob.mbt"),
    os.path.join(ROOT, "src", "keyfile", "encode.mbt"),
    os.path.join(ROOT, "src", "keyfile", "pair.mbt"),
    os.path.join(ROOT, "src", "keyfile", "parse.mbt"),
    os.path.join(ROOT, "src", "keyperm", "keyperm.c"),
    os.path.join(ROOT, "src", "keyperm", "keyperm_native.mbt"),
    os.path.join(ROOT, "src", "keyperm", "keyperm_stub.mbt"),
    os.path.join(ROOT, "cmd", "ssh_keygen", "main.mbt"),
]

# A run that is killed -- a timeout, a Ctrl-C, a runner that goes away --
# never reaches the `finally` at the bottom, and the tree is left MUTATED.
# The pristine state is therefore written to disk before anything is
# changed, and a run that finds its predecessor's leftovers puts them back
# before it starts.
#
# The backup lives under .loop85/, which is gitignored.
BACKUP_DIR = os.path.join(ROOT, ".loop85", "mutation_backup")
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
        os.remove(os.path.join(BACKUP_DIR, name))
    os.rmdir(BACKUP_DIR)


def restore_leftovers():
    """Undo a run that was killed before it could restore the tree.

    Returns the list of files it put back, or an empty list when there was
    nothing to undo.  It only acts when the marker of an interrupted run is
    there, so a normal run never overwrites edits made between runs.
    """
    if not os.path.exists(_backup_path(RUNNING)):
        return []
    restored = []
    for p in FILES:
        b = _backup_path(os.path.basename(p))
        if not os.path.exists(b):
            continue
        with open(b, "r", encoding="utf-8", newline="") as fh:
            text = fh.read()
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        restored.append(os.path.relpath(p, ROOT))
    drop_backup()
    return restored


# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        # OpenSSH's AUTH_MAGIC is written with `sizeof(AUTH_MAGIC)`, so the
        # NUL terminator is part of the bytes on the wire: fifteen bytes, not
        # fourteen.  Dropping it is the single most likely way to get this
        # format wrong, because the name reads like a string and the NUL is
        # invisible in a hex dump at the end.
        "the magic loses its NUL terminator",
        "    0x31, 0x00,\n",
        "    0x31, 0x01,\n",
        "our blob starts with the same magic",
    ),
    (
        # The cipher name says what happened to the private block.  With no
        # passphrase it is "none", and the block is stored in the clear.
        # Anything else claims the file is encrypted when it is not -- and a
        # reader that believes the claim will try to decrypt it.
        "the cipher name claims the key is encrypted",
        'pub const CIPHER_NONE : String = "none"',
        'pub const CIPHER_NONE : String = "aes256-ctr"',
        "src/keyfile's tests pass on native",
    ),
    (
        # The two check words are the same word twice.  They are there so
        # that a wrong passphrase decrypts to something that is almost never
        # equal to itself, and OpenSSH refuses a file whose two words differ
        # ("checkint mismatch").  Here there is no passphrase, so the only
        # thing the words can be is equal to themselves.
        "the two check words are not the same word",
        "    @sshwire.write_u32(check),\n    @sshwire.write_u32(check),\n",
        "    @sshwire.write_u32(check),\n    @sshwire.write_u32(check ^ 1U),\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # The secret key is `seed || pk` -- 64 bytes, which is what OpenSSH
        # stores (ED25519_SK_SZ).  Writing the public key there instead
        # makes the file 32 bytes shorter than every other key file, and
        # makes it a file about a key that has no secret.
        "the private block stores the public key instead of the secret key",
        "    @sshwire.write_ssh_string(sk),\n",
        "    @sshwire.write_ssh_string(pk),\n",
        "our blob is 242 bytes",
    ),
    (
        # OpenSSH's padding is 1, 2, 3, ... in order, so that a reader can
        # tell how much padding there was by looking at the last byte.  The
        # bytes are still the right COUNT, so the file is still 242 bytes and
        # still looks plausible -- and every reader that checks them refuses
        # it.
        "the padding bytes are not 1, 2, 3, ...",
        "    out[body.length() + i] = (i + 1).to_byte()\n",
        "    out[body.length() + i] = (i).to_byte()\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # OpenSSH's writer breaks the base64 line after every 70 characters
        # (`sshbuf_dtob64` with wrap=1).  A reader tolerates any wrapping, so
        # this is the kind of difference that only shows up when somebody
        # diffs our file against OpenSSH's -- which is exactly what the gate
        # does.
        "the base64 is wrapped at 64 columns instead of 70",
        "pub const LINE_WIDTH : Int32 = 70",
        "pub const LINE_WIDTH : Int32 = 64",
        "we wrap the base64 at 70 columns",
    ),
    (
        # The `authorized_keys` line is UNPADDED and the private key file's
        # base64 is PADDED.  That is not an inconsistency: OpenSSH writes
        # the one with `b64_ntop` and the padding stripped and the other
        # with it kept.
        #
        # The first version of this mutation was "the .pub line keeps the
        # base64 padding" -- and it was **equivalent**, which is worth
        # saying out loud: an ed25519 public key blob is 51 bytes (15 for
        # the key type, 4 + 32 for the key), and 51 is a multiple of 3, so
        # its base64 never has a '=' in it at all.  There is nothing to
        # strip on that line, for this key type.
        #
        # So the padding rule is caught where it DOES bite: the
        # fingerprint, whose SHA-256 is 32 bytes -- 32 is not a multiple of
        # 3, so its base64 ends in one '=' that has to go.
        "the base64 padding is not stripped",
        "  while end > 0 && b64[end - 1] == '=' {\n",
        "  while end > 0 && b64[end - 1] == '!' {\n",
        "the fingerprint OpenSSH prints is the one our tool printed",
    ),
    (
        # The fingerprint is the SHA-256 of the PUBLIC key blob.  Computing
        # it over something else -- the seed, say -- produces a perfectly
        # well-formed fingerprint of the wrong thing, and it is the one
        # number a user compares against another machine's number.
        "the fingerprint is computed over the seed instead of the public key",
        "  let blob = ed25519_public_blob(pair.pk)\n"
        "  let digest = @sha256.sha256(blob)\n",
        "  let blob = ed25519_public_blob(pair.seed)\n"
        "  let digest = @sha256.sha256(blob)\n",
        "the fingerprint OpenSSH prints is the one our tool printed",
    ),
    (
        # The reader has to be able to say "no" as well as "yes".  Comparing
        # the two check words the wrong way round says "no" to every good
        # file and "yes" to every corrupt one -- which is the reader
        # backwards.
        "the reader compares the two check words the wrong way round",
        "  if c1 != c2 {\n",
        "  if c1 == c2 {\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # The secret key is the seed followed by the public key, so the seed
        # is the FIRST half of it.  Taking the second half instead produces
        # a file that opens cleanly and yields a DIFFERENT key -- the kind of
        # failure that shows up much later, as a key that does not match.
        "the reader takes the public half of the secret key for the seed",
        "                    seed[i] = sk[i]\n",
        "                    seed[i] = sk[32 + i]\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # The dangerous one on the Windows side.  The ACL is NOT installed --
        # the call is short-circuited away by a condition that is never
        # true -- and the function still returns 0.  So the caller is told
        # the key is private, the `.pub` file is written, and the private
        # key file is sitting there with the directory's inherited ACL:
        # "Authenticated Users" can read it, and OpenSSH refuses to use it.
        #
        # (The first version of this mutation inverted the `if` instead,
        # and that was a DIFFERENT defect: the ACL was installed correctly
        # and the caller was told it had failed.  That one is caught by
        # "our ssh_keygen wrote a .pub file" -- the driver stops before
        # writing it.  This one is the dangerous direction, and only the
        # ACL check and OpenSSH itself can see it.)
        "the ACL is never installed, but the caller is told it was",
        "    if (!SetFileSecurityW(wpath, DACL_SECURITY_INFORMATION, new_sd)) {\n"
        "        result = -5;\n"
        "        goto done;\n"
        "    }\n",
        "    if (wpath == NULL) {\n"
        "        result = -5;\n"
        "        goto done;\n"
        "    }\n",
        "the private key file is readable by its owner only",
    ),
    (
        # The DACL is built from an SDDL string, and the string is one
        # character away from granting everybody else access as well.  This
        # is the mistake a copied-from-the-internet ACL makes, and it is
        # invisible from the MoonBit side: the call succeeds, the file
        # exists, and the key is readable by every process on the machine.
        "the DACL also grants Authenticated Users",
        '        wcscat(sddl, sid_string);\n        wcscat(sddl, L")");\n',
        '        wcscat(sddl, sid_string);\n        wcscat(sddl, L")(A;;FA;;;AU)");\n',
        "the private key file is readable by its owner only",
    ),
    (
        # The refusal has to REFUSE.  A driver that prints "a passphrase is
        # not supported" and then writes the key anyway is the exact failure
        # this loop exists to avoid: the user asked for a passphrase, the
        # tool said it could not do that, and the file on disk is not
        # encrypted at all.
        "the driver says the passphrase is unsupported and writes the key anyway",
        '  if passphrase != "" && passphrase != "\\"\\"" {\n'
        "    println(\n"
        '      "ssh_keygen: a passphrase is not supported; the key would not be encrypted",\n'
        "    )\n"
        "    return\n"
        "  }\n",
        '  if passphrase != "" && passphrase != "\\"\\"" {\n'
        "    println(\n"
        '      "ssh_keygen: a passphrase is not supported; the key would not be encrypted",\n'
        "    )\n"
        "  }\n",
        "no private key was written for the refused passphrase",
    ),
    (
        # An existing private key is never silently replaced.  The mode that
        # does not replace it is `CreateNew`; `CreateOrTruncate` writes over
        # whatever was there, which is how a key gets destroyed by running
        # the tool twice.
        "the driver overwrites an existing private key",
        "    @fs.write_file(path, text, create_mode=@fs.CreateMode::CreateNew)\n",
        "    @fs.write_file(path, text, create_mode=@fs.CreateMode::CreateOrTruncate)\n",
        "the existing private key was left alone",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    # The regression section is skipped: it runs the gates of Loop #79 to
    # #84, which take minutes and cannot be affected by a change to the key
    # file code.  What is left is the part this loop is about.
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop85.mjs"), "--skip-regression"],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 14
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
    "FAIL  src/keyfile compiles on js",
    "FAIL  src/keyfile compiles on wasm",
    "FAIL  src/keyfile compiles on wasm-gc",
    "FAIL  src/keyperm compiles on native",
    "FAIL  cmd/ssh_keygen compiles on native",
]


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
                # `moon run` exits non-zero when the build prints a warning,
                # so a mutation that leaves a variable unused cannot even be
                # measured.
                print("INVALID  %s -- the mutation does not build cleanly" % label, flush=True)
                failures.append(label)
                continue
            caught = ("FAIL  %s" % must_fail) in out
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
