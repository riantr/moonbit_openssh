"""Sweep every src package that has tests and record whether the toolchain can
actually produce a coverage report for it.

This is the tool that produces `host/cov_reportable.json`, the measurement the
gate re-derives and compares against. The working set is therefore MEASURED,
never hand-listed: a package appears in that file because a run of this script
produced a report for it.

One instruction that this file used to carry has been removed, and the reason is
the loop's most expensive lesson. It said:

    a package with TWO test drivers -- a blackbox `<pkg>_test.mbt` and a
    whitebox `<pkg>_wbtest.mbt` -- makes each write its own coverage dump, and
    the combine refuses them with `conflicting trace metadata`.

That reads well and it is false. Nine of the fifteen packages that DO report
have exactly that shape. The real cause of that error is a stale instrumented
`_build`, which is why this script -- and `host/cov_report.py`, and section C of
`host/verify_loop68.mjs` -- all begin with `moon clean`. With the clean in place
`src/bpacket`, whose 25 tests all pass under `moon test` and which has a
blackbox and a whitebox driver, reports 66 uncovered lines across 11 files in
31 seconds. The two packages still left are explained elsewhere, and neither is
a driver-count effect.

`moon coverage clean` is not a substitute for `moon clean` here: it removes the
dump files and leaves the conflict exactly where it was. That was measured too,
after the obvious theories had been refuted.

Usage: python host/cov_probe.py [--json out.json]
"""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, MOON_COVE_REPORT_ENABLED="1")
TOTAL_RE = re.compile(r"^Total:\s+(\d+)\s+uncovered line\(s\)\s+in\s+(\d+)\s+file\(s\)",
                      re.M)


def run(args):
    return subprocess.run(args, cwd=ROOT, env=ENV, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding="utf-8",
                          errors="replace")


def candidates():
    out = []
    src = os.path.join(ROOT, "src")
    for name in sorted(os.listdir(src)):
        pkg = os.path.join(src, name)
        if not os.path.isdir(pkg):
            continue
        files = os.listdir(pkg)
        tests = [f for f in files
                 if f.endswith("_test.mbt") or f.endswith("_wbtest.mbt")]
        if tests:
            out.append(("src/" + name, sorted(tests)))
    return out


def main():
    argv = sys.argv[1:]
    dest = None
    if "--json" in argv:
        dest = argv[argv.index("--json") + 1]

    rows = []
    # `moon clean` FIRST, and this is not hygiene -- it is what makes the answer
    # a property of the repository instead of a property of whoever ran it.
    # Measured in Loop #68: on a tree whose _build had been through dozens of
    # builds, `moon coverage analyze -p src/bpacket` failed with `conflicting
    # trace metadata`, which reads exactly like a toolchain limitation. It was
    # not one. The same command exits 0 with "Total: 66 uncovered line(s) in 11
    # file(s)" immediately after `moon clean`, in 31 seconds, and in a sandbox
    # that never has a _build at all. The conflict is stale instrumented build
    # output; `moon coverage clean` does not touch it, `moon clean` does.
    run(["moon", "clean"])
    for pkg, tests in candidates():
        run(["moon", "coverage", "clean"])
        proc = run(["moon", "coverage", "analyze", "-p", pkg])
        out = proc.stdout or ""
        m = TOTAL_RE.search(out)
        row = {
            "package": pkg,
            "test_files": tests,
            "exit": proc.returncode,
            "uncovered_lines": int(m.group(1)) if m else None,
            "files_reported": int(m.group(2)) if m else None,
            "report": bool(m),
        }
        if not m:
            tail = [l for l in out.strip().splitlines() if l.strip()][-1:]
            row["error"] = tail[0].strip()[:160] if tail else "no output"
        rows.append(row)
        print("%-18s exit=%-3s %s" % (
            pkg, proc.returncode,
            ("%d uncovered in %d files" % (row["uncovered_lines"], row["files_reported"]))
            if m else row.get("error", "?")))

    ok = [r for r in rows if r["report"]]
    print("\n%d/%d src packages with tests can be reported" % (len(ok), len(rows)))
    if dest:
        with io.open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"rows": rows, "reportable": [r["package"] for r in ok]},
                                indent=2, ensure_ascii=False) + "\n")
        print("wrote %s" % dest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
