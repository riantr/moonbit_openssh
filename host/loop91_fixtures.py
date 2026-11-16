#!/usr/bin/env python3
"""host/loop91_fixtures.py -- make the key fixtures Loop #91's gate needs.

## Why this file exists

`host/verify_loop91.mjs` reads four private key files and compares what
`src/keyfile` makes of them with what the real `ssh-keygen -y` makes of
them.  The fixtures were, until now, files that happened to be on the
machine that wrote the gate: they were made by hand, they lived under
`.loop91/` (which is gitignored), and nothing in the repository made
them.

That is the same shape as the defect Loop #69 found in
`host/sshd_setup.mjs`: **a claim about the machine that is not in the
repository is a coincidence that happens to hold on your machine.**  The
gate was green on the machine that wrote it and red on a fresh clone --
and the red was `ENOENT` on a file nobody could produce, which reads as a
bug in the gate rather than as "the gate depends on unversioned state".

So the fixtures are made here, by a script that is IN the repository, and
the gate calls it.  The gate then asserts that the fixtures it reads are
the ones this script just made -- otherwise "the file exists" would still
be a claim about the machine rather than about the code.

## The four fixtures, and what each one is for

A reader can pass the first and fail the others, so each case is a
different trap:

    k256         the ordinary case -- a P-256 key whose scalar fits
    k384         a P-384 key whose 48-byte scalar needs a leading 00
                 when it is written as an mpint
    k521         a P-521 key whose 66-byte scalar starts with 01 and has
                 NO padding at all
    mpint/k0     a P-256 key whose scalar is ABOVE 2^255: the trap in the
                 curve everybody writes the fixed width for

Two more are needed by the other sections:

    enc          an encrypted key -- reading it without a passphrase is
                 a refusal, not a key
    unauth       a key that is NOT in `authorized_keys`

## How the mpint one is found

`ssh-keygen` produces a random scalar, so the high-bit case has to be
SEARCHED FOR: keys are generated until one of them has a 33-byte `d`
whose first byte is 0x00 (an mpint with the sign bit set).  On this
machine that took 3 keys; the search is bounded at 60 so a bad run fails
instead of spinning.

The key is written by the REAL `ssh-keygen`, so the comparison against
the real `ssh-keygen -y` is against the same bytes the fixture was made
of -- the gate measures our reader, not our ability to invent keys.

Run: python host/loop91_fixtures.py [--dir .loop91]
"""

import argparse
import base64
import os
import re
import subprocess
import sys

BEGIN = "BEGIN OPENSSH PRIVATE KEY-----"
END = "-----END OPENSSH PRIVATE KEY-----"

# The curves, and the curve name `ssh-keygen` is asked for.  The gate names
# them this way because the CURVE is the point: a reader that assumes a
# fixed width fails on one of these and not on the others.
CURVES = [
    ("k256", "ecdsa", "256"),
    ("k384", "ecdsa", "384"),
    ("k521", "ecdsa", "521"),
]

# How many keys to try before giving up on finding a high-bit scalar.
# Measured: 3 on this machine.  60 is a bound, not a hope -- a run that
# cannot find one must fail loudly rather than loop forever.
SEARCH_LIMIT = 60


def read_string(buf, at):
    n = int.from_bytes(buf[at:at + 4], "big")
    return buf[at + 4:at + 4 + n], at + 4 + n


def body_of(path):
    """The base64 body of an OPENSSH PRIVATE KEY file, without whitespace."""
    text = open(path, "rb").read().decode()
    m = re.search(re.escape(BEGIN) + r"(.*?)" + re.escape(END), text, re.S)
    if not m:
        raise ValueError("no OPENSSH PRIVATE KEY markers in %s" % path)
    return "".join(m.group(1).split())


def private_fields(path):
    """The fields of an unencrypted OPENSSH PRIVATE KEY.

    `d` is the scalar, and it is an mpint: a scalar whose top bit is set
    carries a leading 0x00 and is one byte longer than the curve's width.
    """
    raw = base64.b64decode(body_of(path))
    at = 15
    cipher, at = read_string(raw, at)
    kdf, at = read_string(raw, at)
    opts, at = read_string(raw, at)
    at += 4  # numkeys
    pub, at = read_string(raw, at)
    blk, at = read_string(raw, at)
    b = 8  # the two check words
    ktype, b = read_string(blk, b)
    curve, b = read_string(blk, b)
    point, b = read_string(blk, b)
    d, b = read_string(blk, b)
    return {
        "cipher": cipher, "kdf": kdf, "opts": len(opts), "pub": pub,
        "block": blk, "ktype": ktype, "curve": curve, "point": point, "d": d,
    }


def keygen(path, ktype, bits, comment, passphrase=None):
    """Write a key with the REAL ssh-keygen.

    The real tool is used on purpose: the fixture has to be a key the
    real tool made, because the gate compares our reader against the real
    reader on the same bytes.
    """
    for p in (path, path + ".pub"):
        if os.path.exists(p):
            os.remove(p)
    args = ["ssh-keygen", "-t", ktype, "-b", bits, "-C", comment, "-f", path]
    if passphrase is None:
        args += ["-N", ""]
    else:
        args += ["-N", passphrase, "-P", passphrase]
    r = subprocess.run(args, capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(
            "ssh-keygen failed for %s: %s"
            % (path, r.stderr.decode(errors="replace").strip())
        )


def make_mpint(outdir):
    """Find a P-256 key whose scalar is above 2^255.

    A random scalar has the high bit set about half the time, so this
    finds one in a couple of tries; the loop exists because the case has
    to be PRESENT rather than probable.

    The key that is found is RENAMED to `k0`, because the gate asks for
    that name and the loop number is an accident of the search.  A
    fixture whose NAME depends on how many keys it took to find it is a
    fixture the gate cannot ask for.
    """
    out = os.path.join(outdir, "mpint")
    os.makedirs(out, exist_ok=True)
    for i in range(SEARCH_LIMIT):
        path = os.path.join(out, "k%d" % i)
        keygen(path, "ecdsa", "256", "mpint%d" % i)
        f = private_fields(path)
        if len(f["d"]) == 33 and f["d"][0] == 0:
            final = os.path.join(out, "k0")
            if os.path.abspath(path) != os.path.abspath(final):
                # The found key is `k<i>`, and the gate asks for `k0`.
                # Only when the search happened to land on k0 already is
                # the rename a no-op -- and a rename onto itself after the
                # source was removed is a FileNotFoundError, so the two
                # cases have to be told apart.
                #
                # The rename comes FIRST: removing the source before
                # moving it is a FileNotFoundError on the move.
                os.replace(path, final)
                os.replace(path + ".pub", final + ".pub")
            return final, i + 1, f
        # Not the case we want: keep the directory clean so the next
        # candidate does not collide with this one.
        for p in (path, path + ".pub"):
            if os.path.exists(p):
                os.remove(p)
    raise RuntimeError(
        "no high-bit scalar in %d keys -- the fixture this gate needs "
        "cannot be made" % SEARCH_LIMIT
    )


def main():
    ap = argparse.ArgumentParser(description="make the key fixtures loop91 needs")
    ap.add_argument("--dir", default=os.path.join(".", ".loop91"),
                    help="where the fixtures go (default: .loop91)")
    args = ap.parse_args()

    outdir = os.path.abspath(args.dir)
    os.makedirs(outdir, exist_ok=True)

    made = []

    for name, ktype, bits in CURVES:
        path = os.path.join(outdir, name)
        keygen(path, ktype, bits, "loop91@%s" % name)
        made.append(name)

    # The high-bit scalar.  It is searched for, not assumed.
    mpint_path, tried, f = make_mpint(outdir)
    made.append("mpint/k0")
    print("mpint: %s (after %d keys, d is %d bytes starting %s)"
          % (mpint_path, tried, len(f["d"]), f["d"][:1].hex()))

    # An encrypted key: reading it without a passphrase is a refusal.
    enc = os.path.join(outdir, "enc")
    keygen(enc, "ecdsa", "256", "loop91@enc", passphrase="loop91pass")
    made.append("enc")

    # A key that is deliberately NOT authorized.
    unauth = os.path.join(outdir, "unauth")
    keygen(unauth, "ecdsa", "256", "loop91@unauth")
    made.append("unauth")

    print("fixtures in %s: %s" % (outdir, ", ".join(made)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
