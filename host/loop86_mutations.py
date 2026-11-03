"""Mutation check: every Loop #86 defect must turn the gate red.

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

Loop #85 refused a passphrase because there was no `bcrypt_pbkdf` here.  Loop
#86 adds the missing pieces -- Blowfish, `bcrypt_pbkdf`, and the AES-256-CTR
layer -- and the refusal becomes an encryption.  The ways that can be wrong
are not all the same kind of wrong:

  * **The constants are not pi.**  Blowfish's P-array and S-boxes are the
    hexadecimal expansion of pi, and `host/blowfish_pi.py` proves it against
    pi computed to 8336 hex digits.  A word that is off by one is a cipher
    that decrypts nothing, and nothing in the file says so.

  * **The cursor is in the wrong place.**  `Blowfish_stream2word`'s cursor is
    a position in the key stream that is then reused for the salt stream.
    It is reset between the key phase and the salt phase and NOT reset
    before the S-boxes, so the S-boxes are salted starting at offset 8.  A
    port that "tidies up" the cursor produces a schedule that is subtly
    wrong and never matches anything -- and there is no error message,
    just a key that does not open.

  * **The round parity is flipped.**  In encryption an odd round XORs into
    the right half and an even round into the left; in decryption it is the
    other way round.  Flipping one of them gives a cipher whose two halves
    are not mirrors of each other.

  * **The KDF is linear.**  OpenSSH deliberately scatters the key material
    instead of writing it out in order, so that an attacker who wants two
    subkeys has to compute all of it.  A KDF that scatters linearly is
    still a KDF, still produces a file, and is still read back correctly --
    it is just weaker, and nothing about the file says so.

  * **The rounds are the wrong number.**  One round too few or too many
    derives a different key.  The file is still a well-formed file.

  * **The passphrase is not the passphrase.**  The passphrase is hashed as
    BYTES, and a passphrase that is not ASCII has to be encoded the same
    way on both sides.  Truncating it to one byte per character, or to one
    byte altogether, produces a key file that opens with one particular
    passphrase and no other -- and the file gives no hint which.

  * **The KDF options are in the wrong order.**  The salt comes first and
    the round count second.  Swapping them produces a file that is the
    right SIZE and the wrong CONTENT, and no reader accepts it.

  * **The file says it is encrypted and is not.**  The cipher name in the
    header is what tells a reader the private block is enciphered.  A file
    that says "none" and holds enciphered bytes, or says "aes256-ctr" and
    holds plain ones, is a file that means two things at once.

  * **The tool says no and then does the thing anyway.**  The dangerous
    one: a driver that takes a passphrase and writes an UNENCRYPTED key
    loses a secret quietly.  That is exactly the failure Loop #85 refused
    to risk and Loop #86 has to be careful not to introduce.

Run:  python host/loop86_mutations.py            # all of them
      python host/loop86_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch.  They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "blowfish", "pi.mbt"),
    os.path.join(ROOT, "src", "blowfish", "cipher.mbt"),
    os.path.join(ROOT, "src", "bcrypt_pbkdf", "pbkdf.mbt"),
    os.path.join(ROOT, "src", "keyfile", "encrypt.mbt"),
    os.path.join(ROOT, "src", "keyfile", "blob.mbt"),
    os.path.join(ROOT, "src", "keyfile", "parse.mbt"),
    os.path.join(ROOT, "src", "keyfile", "pair.mbt"),
    os.path.join(ROOT, "cmd", "ssh_keygen", "main.mbt"),
]

# A run that is killed -- a timeout, a Ctrl-C, a runner that goes away --
# never reaches the `finally` at the bottom, and the tree is left MUTATED.
# The pristine state is therefore written to disk before anything is
# changed, and a run that finds its predecessor's leftovers puts them back
# before it starts.
#
# The backup lives under .loop86/, which is gitignored.
BACKUP_DIR = os.path.join(ROOT, ".loop86", "mutation_backup")
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
        # The P-array and the S-boxes are pi.  One word being off by one is
        # a cipher that decrypts nothing at all, and the file gives no sign
        # of it: the key is still a key, it just is not the key.
        "one word of pi is wrong",
        "0x243f6a88U,",
        "0x243f6a89U,",
        "src/blowfish's tests pass on native",
    ),
    (
        # In encryption an odd round XORs into the right half and an even
        # round into the left half.  Flipping the parity gives a cipher
        # whose two halves are not mirrors of each other, so decryption
        # does not invert encryption.
        "the round parity is flipped in encipher",
        "    if n % 2 == 1 {\n",
        "    if n % 2 == 0 {\n",
        "src/blowfish's tests pass on native",
    ),
    (
        # The cursor is reset between the key phase and the salt phase, and
        # NOT reset before the S-boxes -- so the S-boxes are salted with
        # the salt starting at offset 8.  Resetting it is the "tidy up" that
        # breaks the schedule, and it breaks it silently.
        "the cursor is reset before the S-boxes",
        "  // step 2 -- this is the part that is easy to get wrong.\n"
        "  for box = 0; box < S_BOXES; box = box + 1 {\n",
        "  // step 2 -- this is the part that is easy to get wrong.\n"
        "  cursor = 0\n"
        "  for box = 0; box < S_BOXES; box = box + 1 {\n",
        "src/blowfish's tests pass on native",
    ),
    (
        # The other half of the same subtlety: the cursor IS reset between
        # the key phase and the salt phase.  Without the reset the salt
        # stream starts in the middle of the salt.
        "the cursor is not reset between the key phase and the salt phase",
        "  // Step 2: the salt, into the P-array.  The cursor starts over here.\n"
        "  cursor = 0\n",
        "  // Step 2: the salt, into the P-array.  The cursor starts over here.\n",
        "src/blowfish's tests pass on native",
    ),
    (
        # The keystream word is BIG-endian.  Everything else in this KDF is
        # little-endian, which is exactly why this one is easy to get wrong.
        "the keystream word is little-endian",
        "    temp = (temp << 8) | data[j].to_uint()\n",
        "    temp = (temp >> 8) | (data[j].to_uint() << 24)\n",
        "src/blowfish's tests pass on native",
    ),
    (
        # The magic string is what the bcrypt hash enciphers.  One
        # character off and the hash is a different hash, and the derived
        # key is a different key -- with a file that looks fine.
        "the magic string is one character off",
        '  let s = "OxychromaticBlowfishSwatDynamite"\n',
        '  let s = "OxychromaticBlowfishSwatDynamitf"\n',
        "src/bcrypt_pbkdf's tests pass on native",
    ),
    (
        # The key expansion is 64 rounds.  Sixty-three derives a different
        # key from the same passphrase and salt.
        "the key expansion does one round fewer",
        "  let mut round = 0\n"
        "  while round < 64 {\n"
        "    @blowfish.expand0_state(state, sha2salt)\n",
        "  let mut round = 0\n"
        "  while round < 63 {\n"
        "    @blowfish.expand0_state(state, sha2salt)\n",
        "src/bcrypt_pbkdf's tests pass on native",
    ),
    (
        # OpenSSH deliberately scatters the key material, so that an
        # attacker who wants two subkeys has to compute all of it.  A KDF
        # that writes it out in order is still a KDF and still produces a
        # file that opens -- it is just the weakness OpenSSH removed.
        "the key material is scattered linearly",
        "      let dest = i * stride + (count - 1)\n",
        "      let dest = i\n",
        "src/bcrypt_pbkdf's tests pass on native",
    ),
    (
        # The hash output goes out little-endian, four bytes per word.
        "the hash output is written big-endian",
        "    out[4 * i] = (cdata[i] & 0xFFU).to_byte()\n",
        "    out[4 * i] = ((cdata[i] >> 24) & 0xFFU).to_byte()\n",
        "src/bcrypt_pbkdf's tests pass on native",
    ),
    (
        # The IV is the LAST sixteen bytes of the key material; the key is
        # the first thirty-two.  Taking the IV from the front gives a file
        # that is enciphered under the wrong counter, so nothing reads it.
        "the IV is taken from the wrong end of the key material",
        "    out[i] = material[AES_KEY_LEN + i]\n",
        "    out[i] = material[i]\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # The passphrase is hashed as BYTES.  Truncating it to one byte
        # gives a key file that opens with one particular passphrase -- and
        # with no other, and the file does not say which.
        "the passphrase is truncated to one byte",
        """pub fn passphrase_bytes(passphrase : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(passphrase)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}
""",
        """pub fn passphrase_bytes(passphrase : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(passphrase)
  let out : FixedArray[Byte] = FixedArray::make(1, b'\\x00')
  out[0] = raw[0]
  out
}
""",
        "src/keyfile's tests pass on native",
    ),
    (
        # The KDF options are the salt and then the round count.  Swapping
        # them produces a file of exactly the right size and exactly the
        # wrong content, and no reader accepts it.
        "the KDF options put the rounds before the salt",
        "    @sshwire.write_ssh_string(salt),\n"
        "    @sshwire.write_u32(rounds.reinterpret_as_uint()),\n",
        "    @sshwire.write_u32(rounds.reinterpret_as_uint()),\n"
        "    @sshwire.write_ssh_string(salt),\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # The cipher name in the header is what tells a reader the private
        # block is enciphered.  A file that says "none" and holds
        # enciphered bytes is a file that means two things at once.
        "the encrypted file claims to be unencrypted",
        "    @sshwire.write_ssh_string(utf8_bytes(CIPHER_AES256_CTR)),\n",
        "    @sshwire.write_ssh_string(utf8_bytes(CIPHER_NONE)),\n",
        "both files name the same cipher",
    ),
    (
        # The dangerous one on the driver side.  A tool that takes a
        # passphrase and writes an UNENCRYPTED key loses a secret quietly
        # -- exactly the failure Loop #85 refused to risk and this loop
        # has to be careful not to introduce.
        "the driver writes an unencrypted key when given a passphrase",
        '  let priv_text = if passphrase == "" {\n',
        '  let priv_text = if passphrase != "" {\n',
        "both files name the same cipher",
    ),
    (
        # The salt is random.  A salt that repeats means two key files
        # with the same passphrase derive the same key, which is not what
        # anybody wants and not what the file should quietly allow.
        "the salt is not random",
        "pub fn random_salt() -> FixedArray[Byte] {\n"
        "  @rng.bytes(SALT_LEN)\n"
        "}\n",
        "pub fn random_salt() -> FixedArray[Byte] {\n"
        "  let out : FixedArray[Byte] = FixedArray::make(SALT_LEN, b'\\x00')\n"
        "  out\n"
        "}\n",
        "the two keys have different salts",
    ),
    (
        # The check words are the same word twice, and they are the tag.
        # Comparing them the wrong way round says "no" to every good file
        # and "yes" to every corrupt one.
        "the reader compares the two check words the wrong way round",
        "  if c1 != c2 {\n",
        "  if c1 == c2 {\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # The round cap is there to keep a four-byte field from stopping
        # the reader.  A cap BELOW the round count OpenSSH writes by
        # default is a cap that refuses ordinary files, and that is the
        # other end of the same mistake: a reader that refuses a file
        # OpenSSH wrote is a reader that cannot read anything.
        "the round cap is smaller than the round count OpenSSH writes",
        "pub const MAX_ROUNDS : Int32 = 256\n",
        "pub const MAX_ROUNDS : Int32 = 16\n",
        "src/keyfile's tests pass on native",
    ),
    (
        # The reader's own half of the cap.  Without it the round count in
        # the file is obeyed, and a file is four bytes to write.
        "the reader does not cap the round count",
        """                      if rounds > MAX_ROUNDS.reinterpret_as_uint() {
                        return Parsed::Malformed(
                          "the file asks for " +
                          rounds.to_string() +
                          " KDF rounds, and this reader will not do more than " +
                          MAX_ROUNDS.to_string(),
                        )
                      }
""",
        "",
        "src/keyfile's tests pass on native",
    ),
    (
        # The derivation's half of the cap.  The reader's check is the one
        # that sees a file; this one is what stands between a number from
        # anywhere and a computation that never finishes.
        "the derivation does not cap the round count",
        """  if rounds < 1 || rounds > MAX_ROUNDS {
    return FixedArray::make(0, b'\\x00')
  }
""",
        """  if rounds < 1 {
    return FixedArray::make(0, b'\\x00')
  }
""",
        "src/keyfile's tests pass on native",
    ),
    (
        # The comment is text.  Writing it one byte per character is right
        # for ASCII and wrong for everything else, and it is wrong in the
        # quiet way: the file still opens, with a comment that is not the
        # comment anybody typed.
        "the comment is written one byte per character",
        """  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
""",
        """  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = s[i].to_byte()
  }
""",
        "src/keyfile's tests pass on native",
    ),
    (
        # And the reader's half of the same thing: one byte per character
        # on the way back.  A file written as UTF-8 and read as one byte
        # per character comes back as different characters, and the two
        # halves have to agree.
        "the reader decodes the comment one byte at a time",
        """fn bytes_to_string(raw : FixedArray[Byte]) -> String {
  @utf8.decode_lossy(Bytes::from_array(raw))
}
""",
        """fn bytes_to_string(raw : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < raw.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(raw[i].to_int()))
  }
  sb.to_string()
}
""",
        "src/keyfile's tests pass on native",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    # The regression section is skipped: this gate has none, and the flag
    # is here so that the CI engine's nested-regression convention has a
    # spelling for it.
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop86.mjs"), "--skip-regression"],
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
BUILD_FAILURES = []
for _pkg in ("src/blowfish", "src/bcrypt_pbkdf", "src/keyfile"):
    for _tgt in ("native", "js", "wasm", "wasm-gc"):
        BUILD_FAILURES.append("FAIL  %s compiles on %s" % (_pkg, _tgt))
BUILD_FAILURES.append("FAIL  cmd/ssh_keygen compiles on native")


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
