"""Mutation check: every Loop #84 defect must turn the gate red.

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

Loop #84 gave the client a random source, and the ways that can be wrong are
not all the same kind of wrong:

  * **The source is not random.**  A backend that returns a constant, or the
    same bytes twice, is not a CSPRNG.  The contract tests and the two
    on-the-wire comparisons (two cookies, two DH public values) are what
    catch it.

  * **The failure is papered over.**  This is the dangerous one.  A backend
    that cannot reach the platform and a wrapper that turns that into zeros
    produce a client that encrypts with a key everybody knows.  Nothing about
    the *successful* path can catch it, so it is caught from the OUTSIDE: a
    wasm build of `cmd/wasm_rng_probe` has to PANIC, not print bytes.  A unit
    test cannot watch an abort from the inside, which is why that half of
    the claim lives in the gate.

  * **The shape of the exponent is wrong.**  `e = g^x mod p` goes on the
    wire; `x` does not.  A 256-bit exponent in a 2048-bit group produces an
    `e` that is indistinguishable from a 2047-bit one's, and the exchange it
    protects is breakable in seconds.  So the size and the shape of `x` are
    asserted on `x`.

  * **The client quietly falls back to the old constants.**  The two fixed
    values are still in the tree, on purpose, for the one oracle that needs
    a known exponent.  A client that used them by default would have no
    forward secrecy at all -- which is the very thing this loop removes.

  * **The escape hatch stops working.**  `host/transcript_check.py` can only
    recompute the exchange hash if it knows the exponent, so it asks for the
    fixed one by name.  A flag that is accepted and ignored would leave that
    oracle computing a hash over a secret it does not have.

Run:  python host/loop84_mutations.py            # all of them
      python host/loop84_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch.  They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "rng", "api.mbt"),
    os.path.join(ROOT, "src", "rng", "rng.c"),
    os.path.join(ROOT, "src", "rng", "rng_js.mbt"),
    os.path.join(ROOT, "src", "rng", "rng_wasm.mbt"),
    os.path.join(ROOT, "src", "kexdh", "privkey.mbt"),
    os.path.join(ROOT, "src", "sshclient", "secrets.mbt"),
    os.path.join(ROOT, "src", "sshclient", "live.mbt"),
    os.path.join(ROOT, "cmd", "ssh_live", "main.mbt"),
]

# A run that is killed -- a timeout, a Ctrl-C, a runner that goes away --
# never reaches the `finally` at the bottom, and the tree is left MUTATED.
# That happened here once: the runner was stopped in the middle of the
# batch, the next build compiled the mutation as if it were the code, and the
# gate that followed was measuring the wrong thing.  The pristine state is
# therefore written to disk before anything is changed, and a run that finds
# its predecessor's leftovers puts them back before it starts.
#
# The backup lives under .loop84/, which is gitignored.
BACKUP_DIR = os.path.join(ROOT, ".loop84", "mutation_backup")
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
        # The wrapper reads the bytes back from the buffer the platform
        # filled.  Returning something else -- a constant, say -- makes every
        # draw identical, and the whole package stops being a random source
        # while still returning the right LENGTH, which is the mistake a
        # length-only check would miss.
        "the wrapper returns a constant instead of the platform's bytes",
        "  for i = 0; i < n; i = i + 1 {\n    out[i] = buf[i]\n  }",
        "  for i = 0; i < n; i = i + 1 {\n    out[i] = b'\\x5A'\n  }",
        "two draws are not the same bytes",
    ),
    (
        # The dangerous one.  The platform call can fail -- on the wasm
        # backends it ALWAYS fails, because there is no entropy source there
        # at all -- and the failure has to stop the client, not turn into a
        # key of zeros.  A zero key is not a key: everybody who recorded the
        # exchange can read it.
        #
        # The check that catches this is the wasm probe, run from OUTSIDE the
        # process: a build that turns the failure into bytes prints a second
        # line and exits 0, and the gate sees that.
        "a platform failure is turned into zeros instead of stopping the client",
        "  if mb_rng_fill(buf, n) != 0 {\n"
        "    abort(\"rng.bytes: the platform entropy source failed\")\n"
        "  }",
        "  if mb_rng_fill(buf, n) > 0 {\n"
        "    abort(\"rng.bytes: the platform entropy source failed\")\n"
        "  }",
        "the wasm draw PANICS instead of returning bytes",
    ),
    (
        # A CSPRNG that fills only the first half of the buffer looks
        # random: the bytes it did write are random, and the bytes it did
        # not are whatever was in the buffer.  The structural claim is the
        # one that catches it -- two halves of a real CSPRNG output are equal
        # with probability 2^-16384, and two halves of a half-filled buffer
        # are equal ALWAYS.
        "only half of the requested buffer is filled",
        "  if mb_rng_fill(buf, n) != 0 {",
        "  if mb_rng_fill(buf, n / 2) != 0 {",
        "the WHOLE 4096-byte buffer was written",
    ),
    (
        # The native backend's job is to ask the platform and report what
        # happened.  A backend that always reports failure is a client that
        # never starts -- which is at least loud.  The mutation is here
        # because the honest version of this code has to be distinguishable
        # from a broken one, and only a mutation says so.
        "the native backend always reports failure",
        "    st = BCryptGenRandom(NULL, buf, (ULONG)len,\n"
        "                         BCRYPT_USE_SYSTEM_PREFERRED_RNG);\n"
        "    return st == 0 ? 0 : -1;",
        "    st = BCryptGenRandom(NULL, buf, (ULONG)len,\n"
        "                         BCRYPT_USE_SYSTEM_PREFERRED_RNG);\n"
        "    (void)st;\n"
        "    return -1;",
        "native: every contract test passes",
    ),
    (
        # The js backend is the browser's Web Crypto API.  If it fills the
        # buffer with a constant instead, the browser path is no longer a
        # random source -- and the browser is where this client is meant to
        # run.
        "the js backend fills the buffer with a constant",
        "c.getRandomValues(_b.subarray(off, off + n));",
        "_b.fill(0x5a, off, off + n);",
        "js: every contract test passes",
    ),
    (
        # The wasm backends have no entropy source, and the honest answer to
        # that is to say so.  A backend that returns success hands the caller
        # a buffer of zeros and calls them random -- which is the exact lie
        # this package exists to avoid.
        "the wasm backend pretends to have an entropy source",
        "  ignore(buf)\n  ignore(len)\n  -1",
        "  ignore(buf)\n  ignore(len)\n  0",
        "wasm: the one test that can hold there passes",
    ),
    (
        # The exponent is a SECRET, and its size is a security property: a
        # 256-bit exponent in a 2048-bit group is not a weaker DH, it is a
        # broken one.  Nothing on the wire can show this -- `e = g^x mod p`
        # looks the same either way -- so it is asserted on the exponent.
        #
        # The number of bytes is halved rather than the draw, so that the
        # array and the index that reaches its last byte still agree: a
        # mutation that made the index reach past the end of the array would
        # crash rather than fail, and a crash is a different kind of answer.
        "the private exponent is half the group's size",
        "  let nbytes = pbits / 8",
        "  let nbytes = (pbits / 8) / 2",
        "the exponent keeps the group's size and shape",
    ),
    (
        # OpenSSL's `BN_RAND_TOP_ONE, BN_RAND_TOP_ONE`: the top two bits are
        # set, so the exponent really has the length that was asked for and
        # the Pollard rho attack (O(sqrt(n))) has to work for all of it.
        "the private exponent does not have its top two bits set",
        "  bytes[0] = ((top & 0x7FUL) | 0x60UL).to_byte()",
        "  bytes[0] = ((top & 0x3FUL) | 0x30UL).to_byte()",
        "the exponent keeps the group's size and shape",
    ),
    (
        # OpenSSL's `BN_RAND_TOP_ONE` on the bottom bit: the exponent is odd.
        # An even exponent is `2y`, which makes `g^x = (g^y)^2` and halves
        # the work of the same attack.
        "the private exponent may be even",
        "  bytes[nbytes - 1] = (last | 0x01UL).to_byte()",
        "  bytes[nbytes - 1] = (last & 0xFEUL).to_byte()",
        "the exponent keeps the group's size and shape",
    ),
    (
        # The old constant is still in the tree -- deliberately, for the one
        # oracle that needs a known exponent.  A client that reached for it
        # by DEFAULT would have no forward secrecy at all, and the two
        # on-the-wire comparisons are what say so.
        "the client falls back to the fixed DH exponent",
        "pub fn random_dh_priv() -> @bigint.BigNat {\n"
        "  @kexdh.dh_private_exponent(@kexdh.group14_prime_bit_length())\n"
        "}",
        "pub fn random_dh_priv() -> @bigint.BigNat {\n"
        "  fixed_dh_priv()\n"
        "}",
        "the two DH public values are different",
    ),
    (
        # The same for the cookie.  A fixed cookie says "this is the same
        # client that was here yesterday" to anyone reading the transcript.
        #
        # The mutation is at the CALL SITE, not inside `random_cookie`: a
        # mutation that made `random_cookie` stop calling `@rng` would leave
        # the `src/rng` import unused, and an unused import is a warning --
        # and a warning is a build that "does not build cleanly", which
        # would make this mutation INVALID instead of CAUGHT.
        "the client falls back to the fixed KEXINIT cookie",
        "  let ic_payload = @kexflow.kexinit_payload(random_cookie(), my)",
        "  let ic_payload = @kexflow.kexinit_payload(fixed_cookie(), my)",
        "the two cookies are different",
    ),
    (
        # The escape hatch.  `host/transcript_check.py` recomputes the
        # exchange hash in Python from the bytes on the wire, and it can only
        # do that if it knows the client's private exponent -- which it
        # cannot learn from the wire, because recovering it from `e = g^x`
        # is the discrete logarithm.  So the oracle asks for the fixed
        # exponent by name, and a flag that is accepted and ignored leaves
        # that oracle checking a secret it does not have.
        "the --fixed-kex flag is accepted and ignored",
        '    if argv[i] == "--fixed-kex" {\n      return true\n    }',
        '    if argv[i] == "--fixed-kex" {\n      return false\n    }',
        "the fixed-KEX DH public value is the old constant's, byte for byte",
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
    # #83, which take minutes and cannot be affected by a change to the
    # randomness code.  What is left is the part this loop is about.
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop84.mjs"), "--skip-regression"],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 12
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
            if "FAIL  cmd/ssh_live builds for native" in out or \
               "FAIL  the whole tree type-checks" in out:
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
