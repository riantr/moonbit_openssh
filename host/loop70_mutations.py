"""Mutation: prove the widened CRLF guard in verify_loop67 can actually fail.

Loop #70 widened that guard from 342 files (the ones `moon fmt` owns) to all
765 tracked files. A widened guard that cannot fail is decoration.

So: pick a file the ORIGINAL guard would never have looked at -- one of the 9
that were committed as CRLF, e.g. verify_c/ed25519_ref.c -- give it CRLF in
the working tree, run the gate, and require it to go red. Then restore the
blob and require green again.

Two mutations, because they fail for different reasons and only together do
they cover the guard:

  M1  a `.c` file with CRLF. The old guard did not look at `.c` at all, so
      this is the mutation that justifies the widening.
  M2  a `.bat` file with LF. The `.bat` exception exists because
      build_poly1305.bat uses `goto :check`, so forcing one to LF must NOT be
      reported -- otherwise the exception list is a bug that hides a real one.

Both must be reported the way the gate reports things: a FAIL line naming the
file, and a non-zero exit.

    python host/loop70_mutations.py [--dry-run]
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "host", "verify_loop67.mjs")

# M1: a file the pre-Loop-70 guard could not see.
C_FILE = "verify_c/ed25519_ref.c"
# M2: a file .gitattributes exempts on purpose.
BAT_FILE = "verify_c/build_poly1305.bat"


def blob_bytes(path):
    p = subprocess.run(
        ["git", "cat-file", "-p", "HEAD:" + path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT,
    )
    if p.returncode != 0:
        raise SystemExit("cannot read HEAD:%s: %s" % (path, p.stderr.decode()))
    return p.stdout


def write(path, data):
    io.open(os.path.join(ROOT, path), "wb").write(data)


def run_gate():
    p = subprocess.run(
        ["cmd", "/c", "node", "host\\verify_loop67.mjs"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return p.returncode, p.stdout.decode("utf-8", "replace")


def verdict(label, want_red, path, mutate, expect_name_in_fail):
    original = blob_bytes(path)
    try:
        mutate(original)
        code, out = run_gate()
        red = code != 0
        named = path in out
        ok = (red == want_red) and (named or not expect_name_in_fail)
        detail = []
        detail.append("exit %d" % code)
        detail.append("named the file: %s" % ("yes" if named else "NO"))
        for line in out.splitlines():
            if line.startswith("FAIL") or line.startswith("loop67:"):
                detail.append(line.strip()[:150])
        print("%-6s %-52s %s" % ("CAUGHT" if ok else "MISSED", label,
                                 " | ".join(detail[:4])))
        return ok
    finally:
        write(path, original)


def main(argv):
    if "--dry-run" in argv:
        print("would run 2 mutations against", os.path.relpath(GATE, ROOT))
        return 0
    print("Loop #70 mutations: the widened CRLF guard, and its .bat exception")
    results = []

    results.append(verdict(
        "M1 CRLF in a .c file (invisible to the old guard)",
        True, C_FILE,
        lambda b: write(C_FILE, b.replace(b"\n", b"\r\n")),
        True))

    results.append(verdict(
        "M2 LF in a .bat file (the declared exception must hold)",
        False, BAT_FILE,
        lambda b: write(BAT_FILE, b.replace(b"\r\n", b"\n")),
        False))

    caught = sum(1 for r in results if r)
    missed = len(results) - caught
    print("loop70 mutations: %d CAUGHT, %d MISSED" % (caught, missed))
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
