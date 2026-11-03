"""Where the OpenSSH source tree is -- probed, not asserted.

Two scripts need OpenSSH's own C: `blowfish_pi.py`, which reads the
constants out of `blowfish.c` to compare them with pi, and
`blowfish_ref.py`, which copies `blowfish.c` and `bcrypt_pbkdf.c` into
`verify_c/` as the oracle.

The tree is not on every machine, and a script that names one
developer's checkout works on exactly one machine and fails everywhere
else -- and it fails at the point where the failure is least explicable,
which is the worst place for it to fail.  So the location is a LIST of
candidates, probed in order, and when none of them exists the failure
names every one of them.

`OPENSSH_SRC` comes first and overrides the list: it is the only way to
point at a tree on a path nobody guessed.

The candidates below are a PROBE, not a claim.  `verify_loop71.mjs`
refuses any tracked file that names a machine-specific absolute path,
because a path written into code is a promise that the code only works
on the machine it was written on.  These two paths are the opposite of
that: nothing asserts they exist, each is tried in turn, and the error
message lists all of them.  The marker below says so, in the file, with
a reason attached -- which is the form the gate accepts.
"""

import os
import sys

# machine-path-exempt: each entry below is a CANDIDATE location, probed in
# order until one exists.  None of them is asserted to exist, and when none
# does, the failure names every one of them -- "the tree is not here" is not
# an explanation, "the tree is not here, and here is everywhere I looked" is.
# verify_loop71.mjs flags drive-letter paths in tracked files; this marker
# says these paths are a probe rather than a claim, and it is an obligation
# to say why, not a mute button.
CANDIDATES = [
    r"E:\src\moon\openssh-C",
    r"C:\src\openssh-C",
]

# The file that decides whether a directory is an OpenSSH source tree.
# It is in every OpenSSH tree and in nothing else.
MARKER = os.path.join("openbsd-compat", "blowfish.c")


def candidates():
    """Every place the tree might be, in the order they are tried."""
    env = os.environ.get("OPENSSH_SRC")
    if env:
        return [env] + list(CANDIDATES)
    return list(CANDIDATES)


def find():
    """The OpenSSH source root, or None."""
    for c in candidates():
        if os.path.isfile(os.path.join(c, MARKER)):
            return c
    return None


def find_or_die(what):
    """The OpenSSH source root, or a failure that says where it looked.

    The exit code is 3, deliberately distinct from 1: the callers' gates
    treat "the tree is not here" as SKIP (this check cannot be made on
    this machine) and "the copies do not match" as FAIL.  A gate that
    cannot tell those apart reports a machine's absence as a defect, or
    -- worse -- reports a real mismatch as "nothing to check here".
    """
    root = find()
    if root:
        return root
    sys.stderr.write(
        "%s needs the OpenSSH source tree and it is not here.\n"
        "Looked for %s in:\n" % (what, MARKER))
    for c in candidates():
        sys.stderr.write("  %s\n" % c)
    sys.stderr.write(
        "Set OPENSSH_SRC to the directory that holds openbsd-compat/.\n")
    raise SystemExit(3)
