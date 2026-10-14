"""Mutation check: Loop #56's three-way comparison has to actually cross-check.

Six mutations, aimed at the ways this gate could be theatre.

  * **A: MoonBit's `@cert-authority` exclusion is removed** (`src/knownhosts/
    check.mbt`, back to the Loop #14 rule where a CA entry takes part in
    last-match-wins). C3 -- presenting the CA entry's *own* key -- comes back `Ok`,
    which is the fail-open Loop #51 fixed and Loop #53 wrote down. Nothing in the
    pre-#56 vector set could see this, because the pre-#56 vector set had no CA
    vector. This is the mutation that justifies C1-C3 existing.

  * **B: the same exclusion removed in the C harness.** Proves the C side carries
    the rule too, rather than agreeing with MoonBit because it never had a case
    that could disagree.

  * **C: the same exclusion removed in the Python reference.** Same argument for
    the third side.

  * **D: a generated file is edited by hand.** `knownhosts_test.mbt` is generated
    by `gen_knownhosts_test.py`; editing it proves the drift check is load-bearing.
    Without the drift check the tree looks fine until someone regenerates and the
    edit vanishes -- or, worse, does not and the file is quietly wrong.

  * **E: the C3 row is deleted from *both* case tables, and the emitters' own
    coverage guard is switched off with it.** This is the one that is easy to get
    wrong by reasoning. Deleting the row from one table would be caught trivially
    -- the emitters' key sets stop matching, and `assert_full_coverage` in
    cmd/knownhosts_kat aborts the run. Deleting it from **both** keeps the two
    implementations in agreement with each other, so every "do MoonBit and Python
    describe the same cases?" check still passes, while one case stops being
    decided at all. The only thing left that can catch it is the gate reading
    `_knownhosts_ref_out.txt` itself -- a file neither emitter gets to curate --
    which is why the guard is disabled in the same mutation. Without that last
    edit this mutation is caught by the emitter, and the gate-side check is never
    shown to be load-bearing.

  * **F: an equivalent mutant.** Dropping the `line.startsWith("=")` guard from
    the gate's own `parseKeyed`. No line either emitter prints begins with `=`, so
    the gate still reports ALL PASS -- and it provably cannot be observed here.
    Recorded as **EQUIVALENT**, which is a finding rather than a failure. The
    claim is bounded: *on these outputs*, not "the guard is useless".

**Undo with the snapshot below, never with `git checkout`.**  A mutation is never
something to undo with git unless it was committed first.

Anchors must be unique. `str.replace` rewrites *every* occurrence, so an anchor
that appears twice turns the mutation into a different mutation and then reports a
confident verdict about it.

Anchors must also be **ASCII-only**. The `edit` tool in this workspace could not
round-trip CJK in `old_string`, and a mutation script that silently fails to match
an anchor because of an encoding round-trip reports `NOBUILD`, which reads as
"nothing proven" rather than "the script is broken".

Five verdicts: `NOBUILD` (nothing proven either way), `CRASH`, `CAUGHT` (a named
check went FAIL), `MISSED` (a real change, still reported ALL PASS), and
`EQUIVALENT` (the gate still reported ALL PASS *and* the mutation provably cannot
be observed on these vectors). `MISSED` is an accusation and `EQUIVALENT` is a
finding; conflating them makes both useless, which is why the distinction is a
verdict rather than a comment.

Run:  python host/loop56_mutations.py
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHECK_MBT = os.path.join(ROOT, "src", "knownhosts", "check.mbt")
C_HARNESS = os.path.join(ROOT, "verify_c", "knownhosts_harness.c")
PY_REF = os.path.join(ROOT, "verify_c", "knownhosts_python_ref.py")
MBT_EMITTER = os.path.join(ROOT, "cmd", "knownhosts_kat", "main.mbt")
GENERATED_MBT = os.path.join(ROOT, "src", "knownhosts", "knownhosts_test.mbt")
GATE_MJS = os.path.join(ROOT, "host", "verify_loop56.mjs")

FILES = [CHECK_MBT, C_HARNESS, PY_REF, MBT_EMITTER, GENERATED_MBT, GATE_MJS]

GATE = os.path.join(ROOT, "host", "verify_loop56.mjs")

# The C3 row, spelled once. Used verbatim in both case tables -- they are meant to
# be the same statement made twice, so a mutation that removes it from both has to
# remove the same bytes from both.
C3_ROW_MBT = ('  ("C3", "key:C3_knownhosts_line", "key:C3_presented_blob_hex", '
              '"key:C3_host", "key:C3_port", false, ""),\n')
C3_ROW_PY = ("    ('C3', 'key:C3_knownhosts_line', 'key:C3_presented_blob_hex',\n"
             "     'key:C3_host', 'key:C3_port', False, ''),\n")

# (label, [(path, from, to), ...], expected_verdict)
MUTATIONS = [
    (
        "A: MoonBit lets @cert-authority entries take part in last-match-wins "
        "again (C3 becomes Ok -- the Loop #51 fail-open)",
        [(CHECK_MBT,
          "    if e.marker == Marker::None && entry_matches_spec(e, host_only, port_caller) {",
          "    if entry_matches_spec(e, host_only, port_caller) {")],
        "caught",
    ),
    (
        "B: the C harness stops treating a CA entry as 'not a pin'",
        [(C_HARNESS,
          "            else found = i;",
          "            found = i;")],
        "caught",
    ),
    (
        "C: the Python reference stops treating a CA entry as 'not a pin'",
        [(PY_REF,
          "        if e['marker'] is not None:",
          "        if e['marker'] == '@revoked':")],
        "caught",
    ),
    (
        "D: a generated file is edited by hand (drift check must notice)",
        [(GENERATED_MBT,
          "///| Loop #13",
          "///| HAND EDITED -- must be caught as drift\n///| Loop #13")],
        "caught",
    ),
    (
        "E: the C3 row is deleted from BOTH case tables and the emitters' "
        "coverage guard is switched off (only the vector file can catch this)",
        [(MBT_EMITTER, C3_ROW_MBT, ""),
         (PY_REF, C3_ROW_PY, ""),
         (MBT_EMITTER, "  assert_full_coverage(kv)",
          "  // assert_full_coverage(kv) -- disabled by mutation E")],
        "caught",
    ),
    (
        "F: the gate's parseKeyed drops its '=' line guard (equivalent mutant)",
        [(GATE_MJS,
          '    if (!line || line.startsWith("[") || line.startsWith("#") || line.startsWith("=")) continue;',
          '    if (!line || line.startsWith("[") || line.startsWith("#")) continue;')],
        "equivalent",
    ),
]


def read(path):
    with io.open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def restore(originals):
    for p, text in originals.items():
        write(p, text)


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
        s = line.strip()
        if s.startswith("FAIL ") and s not in labels:
            labels.append(s)
    return labels


def main():
    originals = {p: read(p) for p in FILES}
    # `python host/loop56_mutations.py E` runs one mutation by label prefix. Useful
    # when a full run reports something that does not add up: re-running a single
    # case in isolation is the only way to tell "this mutation misbehaves" from
    # "state leaked in from the one before it".
    only = sys.argv[1:] or None
    chosen = [m for m in MUTATIONS
              if only is None or any(m[0].startswith(pfx) for pfx in only)]
    if only and not chosen:
        print("no mutation matches %r" % (only,))
        return 1
    counts = {"CAUGHT": 0, "MISSED": 0, "NOBUILD": 0, "CRASH": 0, "EQUIVALENT": 0}
    try:
        for label, edits, expect in chosen:
            restore(originals)

            # Every anchor is checked for uniqueness *before* anything is written,
            # and on the pristine text, so a bad anchor cannot leave the tree in a
            # half-mutated state that the next iteration inherits.
            broken = None
            for path, frm, to in edits:
                src = originals[path]
                if frm not in src:
                    broken = "anchor not found in %s" % os.path.relpath(path, ROOT)
                    break
                hits = src.count(frm)
                if hits != 1:
                    broken = ("anchor appears %d times in %s; replace would mutate "
                              "more than intended" % (hits, os.path.relpath(path, ROOT)))
                    break
            if broken:
                print("NOBUILD  %s -- %s" % (label, broken))
                counts["NOBUILD"] += 1
                continue
            for path, frm, to in edits:
                # Read what is on disk now, not `originals[path]`. Two edits to the
                # same file must compose. Writing each one from the pristine text
                # makes the later edit silently undo the earlier one -- which is
                # what happened the first time this ran: mutation E claimed to
                # delete the C3 row from both tables, but the second edit to
                # main.mbt restored it, so the mutation tested "disable the
                # coverage guard" instead and reported a confident, wrong verdict
                # about it. A mutation harness that measures the wrong thing is
                # worse than no harness, because the number looks like evidence.
                write(path, read(path).replace(frm, to))

            proc = run_gate()
            out = proc.stdout or ""

            if "failed when checking project" in out or (
                proc.returncode != 0 and "ALL PASS" not in out and "  FAIL " not in out
            ):
                print("NOBUILD  %s -- the mutated source did not compile" % label)
                counts["NOBUILD"] += 1
                continue
            if proc.returncode == 0:
                if expect == "equivalent":
                    print("EQUIVALENT  %s -- gate still ALL PASS, and this change "
                          "provably cannot be observed on these outputs" % label)
                    counts["EQUIVALENT"] += 1
                else:
                    print("MISSED  %s -- the gate still reported ALL PASS" % label)
                    counts["MISSED"] += 1
                continue
            fails = fails_for(out)
            if not fails and ("gate crashed" in out or "Traceback" in out):
                print("CRASH  %s -- %s" % (label, out.strip().split("\n")[0][:160]))
                counts["CRASH"] += 1
                continue
            print("CAUGHT  %s" % label)
            for f in fails[:4]:
                print("          " + f[:180])
            counts["CAUGHT"] += 1
    finally:
        restore(originals)
        drifted = [p for p in FILES if read(p) != originals[p]]
        if drifted:
            print("\nWARNING: not restored byte for byte: %s" % ", ".join(drifted))
            return 1

    print(
        "\n%d CAUGHT, %d MISSED, %d EQUIVALENT, %d NOBUILD, %d CRASH (of %d mutations)"
        % (counts["CAUGHT"], counts["MISSED"], counts["EQUIVALENT"],
           counts["NOBUILD"], counts["CRASH"], len(chosen))
    )
    return 0 if counts["MISSED"] == 0 and counts["CRASH"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())