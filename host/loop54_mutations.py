"""Mutation check: the write-back has to land, land *additively*, and say so
when it does not.

Three mutations, each aimed at one of the three ways a write-back can be
present in the source and absent from the disk. They are deliberately spread
across two files, because a mutation set that only touches one of them proves
only that that one is load-bearing:

  * **A: the append silently does nothing.**  `append` returns `Appended`
    without writing. This is the failure Loop #54 exists to remove, and it is
    the one every existing gate was blind to: Loop #49's gate greps the printed
    `tofu:` line, which this mutation leaves completely intact. Step 2 is what
    sees it -- a separate process, `--kh-file` only, and nothing to carry over
    but the file.

  * **B: the append truncates instead of appending.**  `OpenOrCreate` becomes
    `CreateOrTruncate`. This is the real footgun in `moonbitlang/async/fs`:
    `write_file`'s `create_mode` defaults to `CreateOrTruncate` while `append`
    defaults to `false`, and those two defaults are safe *together*. Change one
    and the file is emptied and then one line appended to nothing -- with no
    error anywhere. Step 1's three "preserved:" assertions are what see it, and
    the "exactly one line added" count does not: a truncate-then-append adds
    exactly one line too.

  * **C: a failed write is reported as a success.**  `Failed(why)` is rendered
    as the success line. Everything else still works, the connection still
    authenticates, and the pin still does not land -- so the only observable
    difference is a user who believes they are pinned. This is the one that most
    looks like a pass, and it is why step 3 exists as its own step.

**Undo with the snapshot below, never with `git checkout`.**  A mutation is never
something to undo with git unless it was committed first.

The whole tree is restored before each mutation, not in `finally` alone: B and C
edit different places and without that C would run on top of A and report a
failure that the mutation under test never caused. Attribution is the entire
product here.

Anchors must be unique. `str.replace` rewrites *every* occurrence, so an anchor
that appears twice turns the mutation into a different mutation and then reports
a confident verdict about it.

Four verdicts: `NOBUILD` (nothing proven either way), `CRASH`, `CAUGHT` (a named
check went FAIL), `MISSED` (everything still passed).

Run:  python host/loop54_mutations.py
"""

import io
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FILES = [
    os.path.join(ROOT, "src", "khfile", "store.mbt"),
    os.path.join(ROOT, "cmd", "ssh_live", "main.mbt"),
]

GATE = os.path.join(ROOT, "host", "verify_loop54.mjs")

MUTATIONS = [
    (
        "A: the append silently does nothing (every previous gate was blind to this)",
        os.path.join(ROOT, "src", "khfile", "store.mbt"),
        "    @fs.write_file(\n      path,\n      chunk,\n      append=true,",
        "    if true {\n      return AppendResult::Appended\n    }\n"
        "    @fs.write_file(\n      path,\n      chunk,\n      append=true,",
    ),
    (
        "B: the append truncates instead of appending (write_file's own default)",
        os.path.join(ROOT, "src", "khfile", "store.mbt"),
        "      create_mode=@fs.CreateMode::OpenOrCreate,",
        "      create_mode=@fs.CreateMode::CreateOrTruncate,",
    ),
    (
        "C: a failed write is reported as a success",
        os.path.join(ROOT, "cmd", "ssh_live", "main.mbt"),
        "    @khfile.AppendResult::Failed(why) => {",
        "    @khfile.AppendResult::Failed(why) => {\n"
        "      if true {\n        println(\"tofu: written to \" + kh.file)\n        return\n      }",
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_gate():
    # `moon clean` every time. A mutation that fails to show up because nothing
    # was rebuilt reads as MISSED, which points at the gate instead of the rule.
    subprocess.run(
        ["cmd", "/c", "moon", "clean"],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900,
    )
    return subprocess.run(
        ["node", GATE],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        encoding="utf-8", errors="replace", timeout=3600,
    )


def fails_for(out):
    labels = []
    for line in (out or "").split("\n"):
        if line.startswith("  FAIL ") and line.strip() not in labels:
            labels.append(line.strip())
    return labels


def main():
    originals = {p: read(p) for p in FILES}
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0}
    try:
        for label, path, frm, to in MUTATIONS:
            for p in FILES:
                write(p, originals[p])

            src = originals[path]
            if frm not in src:
                print("NOBUILD  %s -- anchor not found in %s" % (label, path))
                counts["NOBUILD"] += 1
                continue
            hits = src.count(frm)
            if hits != 1:
                print(
                    "NOBUILD  %s -- anchor appears %d times in %s; replace would "
                    "mutate more than intended" % (label, hits, path)
                )
                counts["NOBUILD"] += 1
                continue
            write(path, src.replace(frm, to))

            proc = run_gate()
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile" % label)
                counts["NOBUILD"] += 1
                continue
            if proc.returncode == 0:
                print("MISSED  %s -- the gate still reported ALL PASS" % label)
                counts["MISSED"] += 1
                continue
            fails = fails_for(out)
            if not fails and ("PanicError" in out or "gate crashed" in out):
                print("CRASH  %s -- %s" % (label, out.strip().split("\n")[0][:160]))
                counts["CRASH"] += 1
                continue
            print("CAUGHT  %s" % label)
            for f in fails:
                print("          " + f[:180])
            counts["CAUGHT"] += 1
    finally:
        for path, text in originals.items():
            write(path, text)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d NOBUILD, %d CRASH (of %d mutations)"
        % (counts["CAUGHT"], counts["MISSED"], counts["NOBUILD"], counts["CRASH"], len(MUTATIONS))
    )
    return 0 if counts["MISSED"] == 0 and counts["CRASH"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
