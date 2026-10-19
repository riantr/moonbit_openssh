"""Mutations for verify_loop71: the machine-path gate must be able to fail.

Loop #71 replaced 16 files' worth of hardcoded machine paths. A gate that
reports zero hits after you have just fixed everything is exactly the shape of
a gate that would have reported zero hits before you fixed anything, and there
is no way to tell those two apart except by breaking something on purpose.

Three mutations, each aimed at a different way this gate could go soft:

  M1  a hardcoded compiler path comes back into a build_*.bat -- the exact
      shape that made loop55 fail on CI, put back where it was found.
  M2  a bare `machine-path-exempt` with no reason -- the escape hatch used as a
      mute button instead of a declaration.
  M3  a declared probe list, correctly justified -- must stay GREEN, or the
      exemption mechanism is broken in the other direction.

M3 is not optional. Without it, "passes everything" is equally consistent with
"flags everything", and the first two mutations would prove nothing about the
steady state.

    python host/loop71_mutations.py [--dry-run]
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = "verify_loop71.mjs"

M1_FILE = "verify_c/build_aead.bat"
M1_ANCHOR = "if defined GCC goto :cc_ready"
M1_REPLACEMENT = (
    "set GCC=D:\\llvm-mingw\\llvm-mingw-20260602-ucrt-x86_64\\bin\\gcc.exe\r\n"
    + M1_ANCHOR
)

M2_FILE = "verify_loop60_probe_mutation.py"
M2_BODY = (
    "# scratch file created by loop71_mutations, deleted afterwards\r\n"
    "# machine-path-exempt\r\n"
    "P = ['C:\\\\Only\\\\On\\\\One\\\\Machine']\r\n"
)


def run_gate():
    p = subprocess.run(
        ["cmd", "/c", "node", "host\\" + GATE],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    return p.returncode, p.stdout.decode("utf-8", "replace")


def read(rel):
    return io.open(os.path.join(ROOT, rel), "rb").read()


def write(rel, data):
    io.open(os.path.join(ROOT, rel), "wb").write(data)


def mutation(label, want_red, apply_change, undo, expect_named=None):
    try:
        apply_change()
        code, out = run_gate()
        red = code != 0
        named = expect_named in out if expect_named else True
        ok = (red == want_red) and named
        first_fail = ""
        for line in out.splitlines():
            if line.strip().startswith("FAIL"):
                first_fail = line.strip()[:120]
                break
        print("%-6s %-56s exit %d  %s" % (
            "CAUGHT" if ok else "MISSED", label, code, first_fail))
        return ok
    finally:
        undo()


def m1():
    original = read(M1_FILE)
    return (lambda: write(M1_FILE, original.replace(
                M1_ANCHOR.encode(), M1_REPLACEMENT.encode(), 1)),
            lambda: write(M1_FILE, original))


def m2():
    # The scratch file has to be `git add --intent-to-add`ed, or the gate never
    # sees it: the file list comes from `git ls-files`, which by design does not
    # include untracked files. The first version of this mutation forgot that
    # and reported MISSED for a reason that had nothing to do with the rule --
    # a file the gate was never asked about. A mutation that fails to set up its
    # own preconditions is not evidence about the thing under test.
    path = os.path.join(ROOT, M2_FILE)

    def apply():
        write(M2_FILE, M2_BODY.encode())
        subprocess.run(["git", "add", "--intent-to-add", M2_FILE],
                       cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def undo():
        if os.path.exists(path):
            os.remove(path)
        subprocess.run(["git", "reset", "--", M2_FILE], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return (apply, undo)


def m3():
    # A correctly justified probe list, in a scratch file that is tracked for
    # the duration of the mutation so `git ls-files` can see it.
    original = read(M2_FILE) if os.path.exists(os.path.join(ROOT, M2_FILE)) else None
    body = (
        "# scratch file created by loop71_mutations, deleted afterwards\r\n"
        "# machine-path-exempt: each entry is probed in order, none is asserted\r\n"
        "DIRS = ['C:\\\\Program Files\\\\One', 'C:\\\\Program Files\\\\Two']\r\n"
    )
    rel = "verify_loop71_probe_mutation.py"

    def apply():
        write(rel, body.encode())
        subprocess.run(["git", "add", "--intent-to-add", rel],
                       cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def undo():
        if os.path.exists(os.path.join(ROOT, rel)):
            os.remove(os.path.join(ROOT, rel))
        subprocess.run(["git", "reset", "--", rel], cwd=ROOT,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    return (apply, undo)


def main(argv):
    if "--dry-run" in argv:
        print("would run 3 mutations against host/" + GATE)
        return 0
    print("Loop #71 mutations: the machine-path gate, and its escape hatch")
    results = []

    a, u = m1()
    results.append(mutation(
        "M1 a hardcoded gcc path returns to build_aead.bat",
        True, a, u, expect_named=M1_FILE))

    a, u = m2()
    results.append(mutation(
        "M2 a bare machine-path-exempt with no reason",
        True, a, u, expect_named="no reason"))

    a, u = m3()
    results.append(mutation(
        "M3 a justified probe list stays green",
        False, a, u))

    caught = sum(1 for r in results if r)
    missed = len(results) - caught
    print("loop71 mutations: %d CAUGHT, %d MISSED" % (caught, missed))
    return 1 if missed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
