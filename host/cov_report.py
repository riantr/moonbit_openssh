"""Measure test coverage and print what was actually measured.

This is the command behind the `test-coverage` qa category. It exists as a script
rather than a bare `moon coverage analyze` for one reason: the recipe needs a
`moon clean` before it, and a bare command line cannot run one thing and then
another without a shell in between.

That clean is the entire recipe. It is worth saying why, because the obvious
answers are all wrong and each of them cost Loop #68 real time:

  * Running a separate `moon test --enable-coverage` first is not merely
    redundant. `moon coverage analyze` runs the tests itself -- the
    subcommand's own description is "Run test with instrumentation and report
    coverage" -- and 28 dump files had accumulated in this repo's `_build` by
    the time anyone looked.
  * `MOON_COVE_REPORT_ENABLED=1` routes to `bin/moon_cove.wasm` instead of the
    OCaml `moon_cove_report`. It looks necessary because the OCaml reporter
    dies on an assertion inside `output_no_intermediate`
    (`moon_cove_report.ml:220291`). It is not: against a clean `_build` the
    default reporter exits 0 and prints the same report.
  * `moon coverage clean` between packages looks necessary for the same
    reason. It is not -- `moon clean` has already done everything it does.

Deleting either of the last two steps anyway, one at a time, changed nothing
measurable: both mutations came back MISSED, which is the correct verdict for a
step that nothing depends on. That is recorded in host/loop68_mutations.py
rather than quietly dropped, because a mutation that cannot fail is worse than
no mutation -- it looks like coverage of the recipe and is not.

Usage:
  python host/cov_report.py                  # the qa command: the committed set
  python host/cov_report.py --derive --all   # ignore the evidence, sweep the tree
  python host/cov_report.py src/kexflow      # just one
  python host/cov_report.py --all            # include the ones that fail, for evidence

`--derive` is what makes the sweep independent of `host/cov_reportable.json`.
Without it the default target list comes FROM the evidence file, so a run can
only ever re-confirm the evidence. The gate uses `--derive` and then compares,
which is the only arrangement in which the comparison can fail.

Exit 0 only when every package attempted produced a real, self-consistent
report -- unless `--all` was passed, in which case the ones that cannot report
are printed with their measured reason and left for the caller to judge. "Self-
consistent" means the number of `<-- UNCOVERED` markers on the annotated source
equals the `Total: N uncovered line(s)` the reporter claims -- if those ever
diverge, a number on its own would not notice.
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = os.environ
TOTAL_RE = re.compile(
    r"^Total:\s+(\d+)\s+uncovered line\(s\)\s+in\s+(\d+)\s+file\(s\)", re.M)
# The reason a package cannot report is inside the OCaml reporter's failure
# payload, not on the last line of its backtrace.
#
# This is not a stylistic point. `moon coverage analyze -p src/khfile` prints a
# three-frame backtrace whose FINAL line is always
#
#   Called from Moon_cove_report in file "moon_cove_report.ml", line 223726, ...
#
# which says nothing at all -- it is the reporter's own `main` calling itself.
# The sentence that actually explains the failure is the first line:
#
#   Fatal error: exception Failure("Error: No coverage source data found, ...")
#
# Taking the tail of the output (which both this script and section C of
# host/verify_loop68.mjs used to do, independently) therefore reported the same
# opaque string for two completely different situations: a package whose tests
# cannot be instrumented, and a package whose instrumentation build happened to
# fail on that particular run. That conflation is what turned a transient
# failure into a changed verdict about the repository. See ANALYZE_ATTEMPTS.
FAILURE_RE = re.compile(r"Fatal error: exception \w+\(\"(?P<why>[^\"]*)\"", re.S)

# One retry, and the reason is that a single analyze is not deterministic.
#
# Measured on a full local CI run: the --derive sweep classified 14 of 17
# packages as reportable because `src/aead` printed the no-source-data failure,
# and section D -- the very next command on the very same tree -- reported
# 15/15 including `src/aead`. The committed set was right all along; the
# measurement was not reproducible.
#
# A retry does not paper over a package that genuinely cannot report: those
# fail identically every time and cost ~3s each to re-confirm. What it stops is
# a one-off build failure being written down as a fact about the package, which
# is the failure mode this repository keeps meeting in a new costume.
ANALYZE_ATTEMPTS = 2


def reason_from(out):
    """The sentence that explains a failure, not the last line that printed one.

    Falls back to the tail only when there is no failure payload to find, so an
    unexpected failure shape is still reported rather than swallowed.
    """
    m = FAILURE_RE.search(out)
    if m:
        return " ".join(m.group("why").replace("\\n", " ").split())
    tail = [l for l in out.strip().splitlines() if l.strip()]
    return tail[-1].strip() if tail else "no output"


argv = sys.argv[1:]
show_all = "--all" in argv
derive = "--derive" in argv
wanted = [a for a in argv if not a.startswith("-")]


def moon(args, env=None):
    proc = subprocess.run(["moon"] + args, cwd=ROOT, env=env or os.environ,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout or ""


def packages_with_tests():
    out = []
    src = os.path.join(ROOT, "src")
    for name in sorted(os.listdir(src)):
        pkg = os.path.join(src, name)
        if not os.path.isdir(pkg):
            continue
        if any(f.endswith(("_test.mbt", "_wbtest.mbt"))
               for f in os.listdir(pkg)):
            out.append("src/" + name)
    return out


def evidence_reportable():
    path = os.path.join(ROOT, "host", "cov_reportable.json")
    if os.path.exists(path):
        with io.open(path, encoding="utf-8") as fh:
            return json.load(fh).get("reportable", [])
    return []


def main():
    if derive:
        # Deliberately ignores host/cov_reportable.json. A sweep whose target
        # list came out of the evidence file can only ever confirm that file.
        targets = wanted or packages_with_tests()
    else:
        targets = wanted or evidence_reportable() or packages_with_tests()
    if not targets:
        sys.stderr.write("no packages to report on\n")
        return 1

    rows, problems = [], []
    # `moon clean` is the WHOLE recipe, and it took most of Loop #68 to find out
    # that the other two steps people reach for are not needed.
    #
    # The dirty state it removes produces two errors that read like toolchain
    # limitations and are not. `conflicting trace metadata` -- three packages'
    # worth of "this can never be reported" -- and an OCaml assertion failure
    # inside `moon_cove_report`'s `output_no_intermediate`. Both disappear the
    # moment _build is wiped, and both were spent as evidence until three
    # unrelated mutations turned up with the same single failure line.
    #
    # Measured on this tree, immediately after `moon clean`, with the DEFAULT
    # reporter and no per-package clean at all: `moon coverage analyze -p
    # src/kexflow` exits 0 in 15s with `Total: 73 uncovered line(s) in 3
    # file(s)` and 73 UNCOVERED markers -- byte-for-byte the same report the
    # wasm reporter under MOON_COVE_REPORT_ENABLED=1 produced, in a third of
    # the time. So this script sets no environment variable and issues no
    # per-package clean. host/loop68_mutations.py records what happened when
    # each of those two steps was deleted anyway: both were MISSED, which is
    # the correct verdict for a step nothing depends on.
    moon(["clean"])
    healed = []
    for pkg in targets:
        attempts = 0
        while True:
            attempts += 1
            code, out = moon(["coverage", "analyze", "-p", pkg], ENV)
            m = TOTAL_RE.search(out)
            if (code == 0 and m) or attempts >= ANALYZE_ATTEMPTS:
                break
            healed.append(pkg)
        if code == 0 and m:
            marks = out.count("<-- UNCOVERED")
            claimed = int(m.group(1))
            files = int(m.group(2))
            if marks != claimed:
                problems.append("%s: report not self-consistent -- %d markers "
                                "vs Total: %d" % (pkg, marks, claimed))
            rows.append((pkg, claimed, files, marks, "ok"))
        else:
            why = reason_from(out)
            rows.append((pkg, None, None, None, why))
            if not show_all:
                problems.append("%s: no coverage report after %d attempt(s) -- %s"
                                % (pkg, attempts, why[:100]))

    print("")
    print("  %-20s %10s %8s %10s  %s"
          % ("package", "uncovered", "files", "markers", "status"))
    print("  " + "-" * 72)
    for pkg, unc, files, marks, status in rows:
        print("  %-20s %10s %8s %10s  %s"
              % (pkg,
                 "-" if unc is None else unc,
                 "-" if files is None else files,
                 "-" if marks is None else marks,
                 "ok" if status == "ok" else status[:44]))
    measured = sum(1 for r in rows if r[4] == "ok")
    print("  " + "-" * 72)
    print("  %d/%d packages reported; %d uncovered line(s) measured in total"
          % (measured, len(rows), sum(r[1] or 0 for r in rows)))
    if healed:
        # Printed, not hidden. A package that only reported on the second
        # attempt is a fact about this run and belongs in the log next to the
        # totals -- it is the same fact that made the gate red before, one
        # level up.
        print("  (recovered on retry: %s)" % ", ".join(healed))
    print("")

    for p in problems:
        print("  PROBLEM: %s" % p)
    if problems:
        print("")
        # Deliberately NOT relying on the CI engine's tail-of-output capture.
        # That keeps the last 12 lines, and the table above can be longer than
        # that on its own -- so when this step went red in a full CI run, every
        # line naming the actual failure was cut off and the log showed only a
        # table of successes and the word "exit 1". A failure whose cause does
        # not appear in its own log is a failure that costs an hour to
        # reproduce. The reason is also on stderr, which survives a pipe.
        for p in problems:
            sys.stderr.write("coverage PROBLEM: %s\n" % p)
        return 1
    if measured == 0:
        print("  PROBLEM: coverage was measured for nothing\n")
        sys.stderr.write("coverage PROBLEM: measured for nothing\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
