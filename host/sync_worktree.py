"""Resync the working tree with the committed blobs, byte for byte.

Why this script exists
----------------------
`git add --renormalize .` rewrote 9 blobs from CRLF to LF, and the commit is
correct. But the WORKING TREE still holds CRLF, and git will never fix it on
its own: with `text=auto`, git normalises the worktree file before comparing,
so a CRLF file and an LF blob compare equal. `git status` says clean,
`git restore --worktree` does nothing, and `git checkout-index -a -f` does
nothing.

That matters here because verify_loop67 reads the working tree. It would keep
reporting the 9 files as CRLF on a machine whose committed state is already
correct, and the check would stop meaning anything.

So: for each file, compare the worktree bytes to the HEAD blob, and write the
blob's bytes when they differ. Not a "strip CR" transformation -- the blob is
the authority, so this cannot disagree with what is committed.

Refuses to touch a file whose difference is anything other than line endings,
because that would mean something else changed underneath us and silently
discarding it would be exactly the kind of quiet overwrite this repository
keeps paying for.

    python host/sync_worktree.py [--dry-run]
"""

import io
import subprocess
import sys

# The files Loop #70 renormalised: committed as CRLF before .gitattributes.
RENORMALISED = [
    "ed25519_base_table.json",
    "scripts/ecdsa_kat_expected.txt",
    "scripts/gen_ecdsa_driver.py",
    "scripts/u128_kat_expected.txt",
    "triple_check/c/tables.h",
    "verify_c/bpacket_harness.c",
    "verify_c/ed25519_harness.c",
    "verify_c/ed25519_ref.c",
    "verify_c/sha2.c",
]


def blob(rev, path):
    p = subprocess.run(
        ["git", "cat-file", "-p", "%s:%s" % (rev, path)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return p.stdout if p.returncode == 0 else None


def only_line_endings(a, b):
    """True when a and b differ only in CR at end of line."""
    return a.replace(b"\r\n", b"\n") == b.replace(b"\r\n", b"\n")


def main(argv):
    dry = "--dry-run" in argv
    changed = skipped = refused = 0
    for path in RENORMALISED:
        want = blob("HEAD", path)
        if want is None:
            print("  %-40s not in HEAD, left alone" % path)
            refused += 1
            continue
        try:
            have = io.open(path, "rb").read()
        except IOError as exc:
            print("  %-40s unreadable: %s" % (path, exc))
            refused += 1
            continue
        if have == want:
            print("  %-40s already matches" % path)
            skipped += 1
            continue
        if not only_line_endings(have, want):
            print("  %-40s DIFFERS BY MORE THAN LINE ENDINGS -- refused" % path)
            refused += 1
            continue
        if dry:
            print("  %-40s would write %d CRLF -> 0" % (
                path, have.count(b"\r\n")))
            changed += 1
            continue
        io.open(path, "wb").write(want)
        print("  %-40s wrote %d CRLF -> %d" % (
            path, have.count(b"\r\n"), want.count(b"\r\n")))
        changed += 1
    print("sync_worktree: %d written, %d already correct, %d refused%s"
          % (changed, skipped, refused, " (dry run)" if dry else ""))
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
