#!/usr/bin/env python3
"""ci/ci.py -- the one CI engine for this repository.

## Why this exists as a script and not as a workflow file

A GitHub Actions workflow and a local shell loop are two different pieces of
code that will drift. This project already had 40 verification gates and 20
mutation harnesses being run by hand, and the hand-written loop got it wrong
inside a single session: PowerShell 5.1 evaluates `.Count` on a *scalar* as
`$null`, so a run with one failing gate printed `11 - $null = 11`, i.e.
"11/11 PASS" while the process exited 1. A summary line that can disagree with
the exit status is not a summary.

So the work lives here, and `.github/workflows/ci.yml` is a thin shell that
calls this file. Local and remote run the same accounting, so they cannot
disagree about what passed.

## Usage

    python ci/ci.py --list                 # show the discovered steps
    python ci/ci.py                        # env + build + gates
    python ci/ci.py --tiers gates          # one tier
    python ci/ci.py --tiers qa             # the QA category matrix (slow, red today)
    python ci/ci.py --tiers mutations      # slow, mutates the tree
    python ci/ci.py --only loop61 loop64   # specific gates
    python ci/ci.py --fail-fast
    python ci/ci.py --json ci/artifacts/ci.json
    python ci/ci.py --self-check           # verify this file's own bookkeeping

## Tiers

    env         tool versions. Cheap, and the first thing to paste into a bug
                report -- "it used to pass" is usually a toolchain delta, and
                MoonBit moves fast enough that the version is evidence.
    build       compile the protocol packages on all four targets.
    gates       host/verify_loop*.mjs that need nothing but this repository.
    peer-gates  host/verify_loop*.mjs that drive a live SSH peer and/or a
                browser Worker. loop31--loop39, 40, 41, 45, 46 are in here,
                discovered from their own source rather than a hand-kept list.
                They are real gates; they are excluded from the default tier
                only because the cumulative set does not finish inside an
                hour, and a CI run that always times out reports nothing.
    mutations   host/loop*_mutations.py. These edit the working tree, run
                `moon clean`, and restore it. They are opt-in because each
                one is many full gate runs. Never run them concurrently with
                anything else in this tree.
    qa          the QA category matrix from ci/qa.py -- every `implemented`
                category that can run here. NOT in the default tier: several
                of these commands are slow, and three of them are red today
                for understood reasons (moon fmt --check, moon check
                --deny-warn, moon coverage analyze). Opt in with
                `--tiers qa` and read the matrix it prints.
"""

import argparse
import io
import json
import os
import re
import subprocess
import sys
import time

# The console on this machine is cp936. A failing gate's tail routinely contains
# characters the gate author chose (check marks, box drawing), and printing them
# raised UnicodeEncodeError *while reporting a failure* -- so the engine died on
# the very step it was supposed to explain, and the failure looked like a crash
# in CI rather than a red gate. Decode with "replace" (already done in
# run_step) and encode the other end with "replace" too.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover - very old interpreters
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACT_DIR = os.path.join(ROOT, "ci", "artifacts")

# The QA category registry lives in ci/qa.py so this file stays an engine and
# the matrix stays data. When ci.py is run as a script, sys.path[0] is already
# ci/, but an explicit insert keeps `import ci.qa` working from elsewhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import qa  # noqa: E402  -- must follow the sys.path insert above
import release as rel  # noqa: E402
import sandbox  # noqa: E402

# Packages the project treats as protocol-bearing, compiled on every target.
# src/sshclient is native-only in practice (see AGENTS.md, Loop #54), so it is
# built for native only -- listing it for wasm would make CI red for a reason
# that has been understood and documented for loops.
MULTI_TARGET_PACKAGES = ["src\\bpacket", "src\\kexflow"]
NATIVE_ONLY_PACKAGES = ["src\\sshclient", "src\\transport", "src\\knownhosts"]
TARGETS = ["native", "js", "wasm", "wasm-gc"]

GATE_RE = re.compile(r"verify_loop(\d+)\.mjs$")
SUMMARY_RE = re.compile(r"(\d+)/(\d+) checks passed")
FAIL_LINE_RE = re.compile(r"^\s*FAIL\b", re.M)

# A tool that exits 0 having run nothing is not a pass. `moon test -p src/channel`
# and `moon bench cmd/bench_cached` both do exactly this on this repository: exit
# 0, "Total tests: 0, passed: 0, failed: 0", "Warning: no test entry found."
#
# This guard is OPT-IN (set on the step) rather than global. Turning it on
# globally would change how the existing 45 default-tier gates are judged, and
# silently changing the verdict of gates that were already green is exactly the
# kind of surprise this engine exists to prevent.
ZERO_WORK_RE = re.compile(r"Total tests:\s*0\b")

# Gates that need something this repository cannot provide for itself: a live
# SSH peer and/or a browser Worker.
#
# This list is a MEASUREMENT, not a heuristic. Classifying by keyword was tried
# and discarded: loop53 passes in seconds yet mentions playwright/Worker/browser,
# and loop60 mentions sshd, because these gates *assert things about* the browser
# path rather than requiring one. Mentioning a peer is not needing one, so the
# keyword scan put the fast green regression set into the slow tier -- the exact
# opposite of the intent, and the dangerous direction to be wrong in.
#
# Measured on a pristine `git worktree` of HEAD (59145fb), Loop #64:
#   loop31..loop39  -- every one fails there, needs a peer + browser Worker,
#                      1.5--22 minutes each, and the chain is cumulative
#                      (loop35's failures are mostly "loop33 harness still
#                      green"). loop30 also fails there, for a different
#                      reason, and is therefore NOT in this list.
#
# Anything not measured stays in the default tier, where it is at least visible.
# A gate wrongly placed in peer-gates is skipped in silence, so the engine prints
# the skipped count on every default run.
# Loop #65 added two more, both measured rather than assumed:
#   loop40  -- starts a real OpenSSH server on a fixed port and CANNOT stop it:
#              startSshd() unrefs the child and drops the handle, and
#              sshd_setup.mjs parks on `new Promise(() => {})`. It costs ~44
#              minutes and turns the default run red for a reason unrelated to
#              the code under test. host/probe_sshd_leak.mjs reproduces the leak.
#   loop49  -- needs a live peer too, and is order-dependent: it passes alone and
#              fails inside a suite run, which is what the loop40 sshd leak looks
#              like from the outside.
PEER_GATES = frozenset(
    "verify_loop%d.mjs" % n
    for n in (31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 49)
)

TIERS = ("env", "build", "gates", "peer-gates", "mutations", "qa")

DEFAULT_TIMEOUT = 3600


class Step(object):
    def __init__(self, tier, name, argv, timeout=DEFAULT_TIMEOUT, cwd=None,
                 argvs=None, zero_work_guard=False):
        self.tier = tier
        self.name = name
        self.argv = argv
        # A QA category may be a SEQUENCE of commands (e.g. `moon test
        # --enable-coverage` then `moon coverage analyze`). All of them must
        # exit 0; the first failure stops the sequence and fails the step.
        self.argvs = argvs if argvs is not None else [argv]
        self.timeout = timeout
        self.cwd = cwd or ROOT
        self.zero_work_guard = zero_work_guard
        self.status = "skipped"
        self.detail = ""
        self.seconds = 0.0
        self.exit_code = None
        self.tail = ""
        self.log = ""

    def as_dict(self):
        d = {
            "tier": self.tier,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "seconds": round(self.seconds, 1),
            "exit_code": self.exit_code,
        }
        if self.log:
            d["full_log"] = "steps/" + self.log
        return d


def _run_argv(argv, cwd, timeout):
    """Run one argv. Returns (exit_code, combined_output_text)."""
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return proc.returncode, (proc.stdout or b"").decode("utf-8", "replace")
    except FileNotFoundError as exc:
        return 127, "command not found: %s (%s)" % (argv[0], exc)
    except subprocess.TimeoutExpired as exc:
        out = "timed out after %ss" % timeout
        if exc.output:
            out += "\n" + exc.output.decode("utf-8", "replace")
        return 124, out


def _safe_log_name(step):
    """A step name is a file name like `verify_loop47.mjs` or `build src\\x`.
    Windows rejects `\\ : * ? " < > |` in a path component, and the build
    steps carry backslashes, so the name is reduced to a conservative set
    rather than to whatever `name` happens to be this month."""
    keep = []
    for ch in step.name:
        keep.append(ch if (ch.isalnum() or ch in "._-") else "_")
    out = "".join(keep).strip("._") or "step"
    return out[:120] + ".log"


def _keep_full_output(step, out):
    """Persist a failing step's ENTIRE stdout, not just the 12-line tail.

    Why this exists: the tail is what the console gets, and it is the right
    size for a human reading a green-ish run. It is the wrong size for
    diagnosing a red one -- measured on GitHub run 39194939821, `verify_loop45`
    burned 928.7s and the 12 lines that survived showed `import paramiko` as
    the final line, with the 900 seconds before it thrown away. Every
    follow-up question about that step ("which module, which fixture, did it
    build?") needed a fact the log no longer had, and the only way to get it
    was another 25-minute run.

    So the summary stays short and the full transcript goes to disk, where
    the workflow uploads it as an artifact. Steps that PASS write nothing:
    an artifact full of green noise is an artifact nobody opens.
    """
    step.log = _safe_log_name(step)
    directory = os.path.join(ARTIFACT_DIR, "steps")
    try:
        if not os.path.isdir(directory):
            os.makedirs(directory)
        with io.open(os.path.join(directory, step.log), "w",
                     encoding="utf-8", errors="replace") as fh:
            fh.write(out)
    except OSError as exc:
        # Losing the log must not lose the run. Say so and carry on -- a
        # step that failed for a real reason still fails for that reason.
        sys.stderr.write("could not keep full output for %s: %s\n"
                         % (step.name, exc))
        step.log = ""


def run_step(step):
    start = time.time()
    chunks = []
    code = 0
    for argv in step.argvs:
        code, chunk = _run_argv(argv, step.cwd, step.timeout)
        chunks.append("$ " + " ".join(argv))
        chunks.append(chunk)
        if code != 0:
            break
    out = "\n".join(chunks)
    step.seconds = time.time() - start
    step.exit_code = code

    lines = [ln for ln in out.splitlines() if ln.strip()]
    step.tail = "\n".join(lines[-12:])

    if code != 0:
        step.status = "failed"
        step.detail = "exit %d" % code
        _keep_full_output(step, out)
        return False

    # A gate that exits 0 while printing FAIL is a broken gate. Believing the
    # exit code alone would let that ship silently.
    if FAIL_LINE_RE.search(out):
        step.status = "failed"
        first = FAIL_LINE_RE.search(out).group(0).strip()
        step.detail = "exit 0 but the gate printed FAIL"
        _keep_full_output(step, out)
        return False

    # Exit 0 having done nothing is the same lie, wearing a different hat.
    if step.zero_work_guard and ZERO_WORK_RE.search(out):
        step.status = "failed"
        step.detail = "vacuous pass: ran 0 test/bench entries"
        _keep_full_output(step, out)
        return False

    m = None
    for m2 in SUMMARY_RE.finditer(out):
        m = m2
    if m:
        step.detail = "%s/%s checks" % (m.group(1), m.group(2))
        if m.group(1) != m.group(2):
            step.status = "failed"
            step.detail += " (but exit 0)"
            _keep_full_output(step, out)
            return False
    else:
        step.detail = "ok"
    step.status = "passed"
    return True



def gate_steps():
    host = os.path.join(ROOT, "host")
    names = []
    for fname in os.listdir(host):
        m = GATE_RE.search(fname)
        if m:
            names.append((int(m.group(1)), fname))
    # Numeric sort: "verify_loop9" must not sort after "verify_loop63".
    names.sort(key=lambda t: (t[0], t[1]))
    steps = []
    for _, fname in names:
        path = os.path.join("host", fname)
        needs_peer = fname in PEER_GATES
        steps.append(Step("peer-gates" if needs_peer else "gates", fname,
                          ["node", path]))
    return steps


def mutation_steps():
    host = os.path.join(ROOT, "host")
    names = sorted(f for f in os.listdir(host) if f.endswith("_mutations.py"))
    return [Step("mutations", fname, ["python", os.path.join("host", fname)], timeout=14400)
            for fname in names]


def build_steps():
    steps = []
    for pkg in MULTI_TARGET_PACKAGES:
        for tgt in TARGETS:
            steps.append(Step("build", "build %s [%s]" % (pkg, tgt),
                              ["cmd", "/c", "moon", "build", pkg, "--target", tgt]))
    for pkg in NATIVE_ONLY_PACKAGES:
        steps.append(Step("build", "build %s [native]" % pkg,
                          ["cmd", "/c", "moon", "build", pkg, "--target", "native"]))
    return steps


def env_steps():
    return [
        Step("env", "moon version", ["cmd", "/c", "moon", "version", "--all"], timeout=300),
        Step("env", "node version", ["cmd", "/c", "node", "--version"], timeout=120),
        Step("env", "python version", ["cmd", "/c", "python", "--version"], timeout=120),
    ]


def read_text(rel):
    with io.open(os.path.join(ROOT, rel), "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _invokes_moon(cat, subcommands):
    """True if any argv in the category calls `moon <subcommand>`."""
    for argv in cat.command or []:
        # argv is ["cmd", "/c", "moon", subcommand, ...]
        if len(argv) >= 4 and argv[0] == "cmd" and argv[2] == "moon" \
                and argv[3] in subcommands:
            return True
    return False


def qa_steps():
    """One step per QA category that can actually run in this tier."""
    steps = []
    for cat in qa.QA_CATEGORIES:
        if not cat.runs_in_qa:
            continue
        # `moon test` and `moon bench` are the two commands in this toolchain
        # that exit 0 while running nothing. Everything else (node gates, moon
        # fmt/check/tree/coverage, `moon run` drivers) either reports its own
        # work or is judged by its own exit code.
        guard = _invokes_moon(cat, ("test", "bench"))
        steps.append(Step("qa", "qa/%s" % cat.id, cat.command[0],
                          timeout=cat.timeout, argvs=list(cat.command),
                          zero_work_guard=guard))
    return steps


def collect(tiers, only):
    steps = []
    if "env" in tiers:
        steps += env_steps()
    if "build" in tiers:
        steps += build_steps()
    if "gates" in tiers or "peer-gates" in tiers:
        wanted = {t for t in ("gates", "peer-gates") if t in tiers}
        steps += [s for s in gate_steps()
                  if s.tier in wanted and (not only or any(o in s.name for o in only))]
    if "mutations" in tiers:
        steps += [s for s in mutation_steps() if not only or any(o in s.name for o in only)]
    if "qa" in tiers:
        steps += [s for s in qa_steps() if not only or any(o in s.name for o in only)]
    return steps


STATUS_ICON = {"passed": "PASS", "failed": "FAIL", "skipped": "SKIP"}


def qa_results(steps, tier):
    """Map every declared QA category id to what actually happened to it.

    The invariant this function exists to hold: every id in qa.QA_CATEGORIES
    gets an entry. A category that was never selected is NOT RUN, which is
    visibly different from a category that ran and failed -- and visibly
    different again from one that cannot run at all.
    """
    by_name = {}
    for s in steps:
        if s.tier == "qa" and s.name.startswith("qa/"):
            by_name[s.name[3:]] = s

    results = {}
    for cat in qa.QA_CATEGORIES:
        if cat.status == "not_available":
            result = qa.RESULT_NA
        elif cat.status == "needs_external":
            result = qa.RESULT_EXT
        elif cat.id == "quality-metrics":
            # Computed from this run, printed below; not a pass/fail gate.
            result = qa.RESULT_COMPUTED
        elif cat.id in by_name:
            step = by_name[cat.id]
            if step.status == "passed":
                result = qa.RESULT_PASS
            elif step.status == "failed":
                result = qa.RESULT_FAIL
            else:
                result = qa.RESULT_NOTRUN
        else:
            result = qa.RESULT_NOTRUN
        results[cat.id] = {
            "result": result,
            "seconds": by_name[cat.id].seconds if cat.id in by_name else None,
            "detail": by_name[cat.id].detail if cat.id in by_name else "",
            "status": cat.status,
        }
    return results


def main():
    ap = argparse.ArgumentParser(description="openssh_moonbit local CI")
    ap.add_argument("--tiers", default="env,build,gates",
                    help="comma separated: " + ",".join(TIERS))
    ap.add_argument("--only", default="",
                    help="comma separated substrings to filter step names")
    ap.add_argument("--fail-fast", action="store_true")
    ap.add_argument("--json", default="", help="write a JSON report here")
    ap.add_argument("--list", action="store_true", help="list steps and exit")
    ap.add_argument("--self-check", action="store_true",
                    help="verify this engine's own pass/fail accounting")
    ap.add_argument("--tag", action="store_true",
                    help="create the next tag, but only if every step passed")
    ap.add_argument("--check-release", action="store_true",
                    help="report whether a tag would be allowed, and change nothing")
    args = ap.parse_args()

    if args.self_check:
        return self_check()

    tiers = [t.strip() for t in args.tiers.split(",") if t.strip()]
    unknown = [t for t in tiers if t not in TIERS]
    if unknown:
        sys.stderr.write("unknown tier(s): %s\n" % ", ".join(unknown))
        return 2

    only = [s for s in args.only.split(",") if s]
    steps = collect(tiers, only)
    if not steps:
        sys.stderr.write("no steps matched\n")
        return 2

    print("steps: %d   tiers: %s" % (len(steps), ",".join(tiers)))
    if args.list:
        for s in steps:
            print("  %-11s %s" % (s.tier, s.name))
        skipped = sorted(PEER_GATES) if "peer-gates" not in tiers else []
        if skipped:
            print("")
            print("not run (need a live SSH peer / browser Worker): %d" % len(skipped))
            print("  %s" % ", ".join(skipped))
            print("  run them with: python ci/ci.py --tiers peer-gates")
        return 0

    if "mutations" in tiers:
        print("")
        print("!! mutations edit the working tree and run `moon clean`;")
        print("!! do not run anything else in this tree at the same time.")

    start = time.time()
    failed = []
    # Mutation harnesses edit the tree and restore it in a `finally`, which does
    # not run when the process is killed -- and this engine kills on timeout.
    # That already happened once: verify_loop40 was interrupted at 44 minutes
    # and left src/channel/channel.mbt with a swapped name/value pair. So the
    # mutations tier runs against a throwaway `git worktree` copy instead, and
    # the tree that matters is never written to.
    sandboxes = {}
    for s in steps:
        cwd = ROOT
        if s.tier == "mutations":
            if "mutations" not in sandboxes:
                try:
                    sandboxes["mutations"] = sandbox.make_sandbox(ROOT)
                    print("  sandbox: %s" % sandboxes["mutations"])
                except Exception as exc:  # noqa: BLE001
                    print("  sandbox: FAILED -- %s" % exc)
                    sandboxes["mutations"] = None
            if sandboxes.get("mutations"):
                cwd = sandboxes["mutations"]
                s.cwd = cwd
        ok = run_step(s)
        # Restore the step's cwd so a later report of this run cannot point a
        # reader at a directory that is about to be deleted.
        s.cwd = ROOT
        print("  %-4s %-9s %-34s %-22s %6.1fs"
              % (STATUS_ICON[s.status], s.tier, s.name, s.detail, s.seconds))
        sys.stdout.flush()
        if not ok:
            failed.append(s)
            print("")
            print(s.tail)
            print("")
            if args.fail_fast:
                break

    for target in sandboxes.values():
        if target:
            sandbox.drop_sandbox(ROOT, target)

    elapsed = time.time() - start
    ran = [s for s in steps if s.status != "skipped"]
    passed = [s for s in ran if s.status == "passed"]

    print("")
    print("=" * 72)
    print("CI %s: %d/%d steps passed in %.1fs"
          % ("PASS" if not failed else "FAIL", len(passed), len(ran), elapsed))
    if failed:
        for s in failed:
            print("  FAIL %s/%s -- %s" % (s.tier, s.name, s.detail))
    not_run = sorted(PEER_GATES) if "peer-gates" not in tiers else []
    if not_run:
        print("  NOT RUN %d peer-gates (need a live SSH peer / browser Worker)"
              % len(not_run))
        print("          %s" % ", ".join(n.replace("verify_loop", "").replace(".mjs", "")
                                       for n in not_run))
        print("          python ci/ci.py --tiers peer-gates")

    # quality-metrics: a real arithmetic result over THIS run, not a constant.
    results = qa_results(steps, tiers)
    counts = qa.tally(results)
    step_rate = (100.0 * len(passed) / len(ran)) if ran else 0.0
    impl_ran = counts[qa.RESULT_PASS] + counts[qa.RESULT_FAIL]
    impl_rate = (100.0 * counts[qa.RESULT_PASS] / impl_ran) if impl_ran else 0.0
    metric_detail = (
        "step pass rate %.1f%% (%d/%d)  |  implemented QA categories passing "
        "%.1f%% (%d/%d)  |  not_available %d  needs_external %d  not_run %d"
        % (step_rate, len(passed), len(ran), impl_rate,
           counts[qa.RESULT_PASS], impl_ran,
           counts[qa.RESULT_NA], counts[qa.RESULT_EXT], counts[qa.RESULT_NOTRUN])
    )
    results["quality-metrics"]["detail"] = metric_detail
    results["quality-metrics"]["seconds"] = round(elapsed, 1)
    results["qa-flow"]["detail"] = (
        "this engine; tiers requested: %s" % ",".join(tiers))

    print("")
    for line in qa.render_matrix(results):
        print(line)
    merged = [(c.label, c.merged_from) for c in qa.QA_CATEGORIES if c.merged_from]
    if merged:
        print("  merges (shipped as ONE row each, not two copies of one fact):")
        for label, srcs in merged:
            print("    %-30s absorbed %s" % (label, ", ".join(srcs)))
    print("  run the runnable ones with: python ci/ci.py --tiers qa")
    print("=" * 72)

    if args.json:
        if not os.path.isdir(ARTIFACT_DIR):
            os.makedirs(ARTIFACT_DIR)
        target = args.json if os.path.isabs(args.json) else os.path.join(ROOT, args.json)
        report = {
            "verdict": "PASS" if not failed else "FAIL",
            "tiers": tiers,
            "total": len(ran),
            "passed": len(passed),
            "failed": len(failed),
            "seconds": round(elapsed, 1),
            "steps": [s.as_dict() for s in ran],
            "quality_metrics": {
                "step_pass_rate_pct": round(step_rate, 2),
                "implemented_categories_passing_pct": round(impl_rate, 2),
                "counts": counts,
            },
            "qa_categories": [dict(qa.BY_ID[k].as_dict(), **results[k])
                              for k in sorted(results)],
        }
        with io.open(target, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(report, indent=2, ensure_ascii=False))
        print("report: %s" % os.path.relpath(target, ROOT))

    # The one line this file exists to make trustworthy.
    rc = 0 if not failed else 1

    if args.tag or args.check_release:
        rc = release_gate(failed, ran, tiers, args)
    return rc


def release_gate(failed, ran, tiers, args):
    """The tag gate. Refuses unless every step that ran passed.

    The owner's instruction, verbatim: no tag before the local CI is green,
    "即便是我要求的" -- including when they ask for it directly. This
    function is the reason that promise is kept: it does not know who is
    asking, and the tag is produced by `git tag`, not by an agent's judgement
    that the run was green enough.
    """
    print("")
    print("=" * 72)
    print("RELEASE GATE")
    print("=" * 72)

    remotes = subprocess.run(["git", "remote", "-v"], cwd=ROOT,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL).stdout.decode(
                                 "utf-8", "replace")
    have_github = "github.com" in remotes
    print("  gitee  : may be pushed at any time")
    print("  github : only after a green run AND a tag"
          + ("" if have_github else "  (no GitHub remote configured -- policy only)"))

    skipped = [t for t in ("peer-gates", "mutations") if t not in tiers]
    if skipped:
        # Not hidden: a green that quietly ignored half the suite is not green.
        print("  excluded from the tag decision: %s" % ", ".join(skipped))

    tags = subprocess.run(["git", "tag", "-l"], cwd=ROOT,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL).stdout.decode(
                              "utf-8", "replace").split()
    try:
        want = rel.next_tag(tags)
    except rel.TagError as exc:
        print("  tag    : CANNOT DETERMINE -- %s" % exc)
        return 1
    print("  newest tag : %s" % (max(tags) if tags else "(none)"))
    print("  next  tag  : %s" % want)

    try:
        rel.assert_tag_allowed(failed, ran, skipped)
    except rel.TagError as exc:
        print("")
        print("  REFUSED: %s" % exc)
        print("  no tag was created. This holds even when asked for explicitly:")
        print("  a tag asserts 'this exact tree was verified', so it is the last")
        print("  thing produced, never an exception.")
        return 1

    print("  green : every step that ran passed")
    if args.check_release:
        print("")
        print("  READY. Re-run with --tag to create %s." % want)
        return 0

    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL).stdout.decode(
                               "utf-8", "replace").strip()
    if dirty:
        print("")
        print("  REFUSED: the working tree is dirty; a tag would not name a")
        print("  reproducible state.")
        for line in dirty.splitlines()[:10]:
            print("    %s" % line)
        return 1

    rc = subprocess.run(["git", "tag", want], cwd=ROOT)
    if rc.returncode != 0:
        print("")
        print("  REFUSED: `git tag %s` failed." % want)
        return 1
    print("")
    print("  TAGGED %s at %s" % (want, subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"], cwd=ROOT,
        stdout=subprocess.PIPE).stdout.decode("utf-8", "replace").strip()))
    print("  push policy: gitee now; github only if a GitHub remote is added.")
    return 0


def release_self_check():
    """The tag gate is the one promise that must hold against the owner.

    These cases are pure functions, so they run here with no repository, no
    tag and no network -- and they are the reason the gate can be trusted to
    refuse later.
    """
    bad = []

    def want(name, got, expected):
        if got != expected:
            bad.append("%s: got %r, wanted %r" % (name, got, expected))

    # Only the final component moves.
    want("v0.1.0 -> v0.1.1", rel.next_tag(["v0.1.0"]), "v0.1.1")
    want("v0.1.9 -> v0.1.10", rel.next_tag(["v0.1.9"]), "v0.1.10")
    want("v1.2.3 -> v1.2.4", rel.next_tag(["v1.2.3"]), "v1.2.4")
    # Zero padding of the component being replaced is preserved.
    want("v1.09 -> v1.10", rel.next_tag(["v1.09"]), "v1.10")
    want("v1.09 -> keeps width", rel.next_tag(["v1.09", "v1.10"]), "v1.11")
    # The newest tag is the one that moves, not the last created.
    want("newest wins", rel.next_tag(["v0.1.5", "v0.1.9", "v0.1.2"]), "v0.1.10")
    # A date-shaped tag follows the same rule: only the trailing number moves.
    # An earlier version of this file documented these as refusals and the
    # self-check caught the contradiction -- the implementation was right and
    # the promise was wrong.
    want("date-shaped tag", rel.next_tag(["release-2026-10"]), "release-2026-11")
    # Refusing to invent a scheme beats guessing one.
    for name, tags in (("no tags", []), ("no trailing digits", ["nightly"])):
        try:
            rel.next_tag(tags)
            bad.append("%s: should have refused" % name)
        except rel.TagError:
            pass
    # The core promise: a failed step blocks the tag, always.
    ok_step = Step("self", "ok", ["cmd", "/c", "exit", "0"])
    run_step(ok_step)
    bad_step = Step("self", "bad", ["cmd", "/c", "exit", "1"])
    run_step(bad_step)
    try:
        rel.assert_tag_allowed([bad_step], [ok_step, bad_step], [])
        bad.append("failed step did not block the tag")
    except rel.TagError:
        pass
    # An empty run verifies nothing, so it cannot green-light a tag.
    try:
        rel.assert_tag_allowed([], [], [])
        bad.append("empty run did not block the tag")
    except rel.TagError:
        pass
    # All green, with an excluded tier reported rather than hidden.
    try:
        rel.assert_tag_allowed([], [ok_step], ["peer-gates"])
    except rel.TagError as exc:
        bad.append("green run was refused: %s" % exc)

    return bad


release_self_check_count = 12


def qa_self_check():
    """The QA matrix must not be able to hide a category or fake a pass."""
    bad = []
    ids = [c.id for c in qa.QA_CATEGORIES]
    if len(ids) != len(set(ids)):
        bad.append("duplicate category ids")
    for c in qa.QA_CATEGORIES:
        if c.status == "implemented" and not c.command:
            bad.append("%s: implemented but has no command" % c.id)
        if c.status == "not_available" and not c.evidence:
            bad.append("%s: not_available but carries no evidence" % c.id)
    text = qa.render_matrix({})
    for cid in ids:
        if cid not in text:
            bad.append("%s missing from the rendered matrix" % cid)
    return bad


qa_self_check_count = 4


def self_check():
    """The engine must not be able to disagree with itself.

    Every real CI bug this repository has hit came from the summary disagreeing
    with the process status, so the summary is what gets tested. These cases run
    in-process; nothing touches the working tree.
    """
    failures = []

    steps_dir = os.path.join(ARTIFACT_DIR, "steps")
    try:
        preexisting = set(os.listdir(steps_dir))
    except OSError:
        preexisting = set()

    # Every probe below is a step that fails ON PURPOSE, so every probe now
    # leaves a log under ci/artifacts/steps/ behind it. This function's own
    # docstring says "nothing touches the working tree", and a leftover log
    # from the last self-check is exactly the kind of thing that sends the
    # next person looking for a failure that is not there. Collected and
    # removed once, at the end, rather than cleaned up per probe -- so a
    # probe that crashes still gets swept.
    probe_steps = []

    def case(name, step, want_status, want_return):
        probe_steps.append(step)
        ok = run_step(step)
        if step.status != want_status:
            failures.append("%s: status %s, wanted %s" % (name, step.status, want_status))
            return
        passed = [s for s in [step] if s.status == "passed"]
        want_rc = 0 if want_status == "passed" else 1
        if want_rc != want_return:
            failures.append("%s: return-code mapping wrong" % name)

    # A command that exits 0 and prints nothing is a pass.
    case("silent success", Step("self", "ok", ["cmd", "/c", "exit", "0"]), "passed", 0)
    # A command that exits non-zero is a failure, whatever it printed.
    case("nonzero exit", Step("self", "bad", ["cmd", "/c", "exit", "1"]), "failed", 1)
    # The PowerShell 5.1 trap in the shape it actually appears: one failing
    # step inside a list must not be counted as zero failures.
    one_bad = Step("self", "bad", ["cmd", "/c", "exit", "1"])
    probe_steps.append(one_bad)
    run_step(one_bad)
    got = len([s for s in [one_bad] if s.status == "failed"])
    if got != 1:
        failures.append("single-element failed list counted as %d" % got)
    # A missing command is a failure, not a crash.
    case("missing command", Step("self", "ghost", ["definitely-not-a-command-xyz"]),
         "failed", 1)

    # The full-output capture, exercised on the case it exists for: a step
    # that fails AFTER printing more than the 12 lines the tail keeps. If the
    # first line is not on disk afterwards, a red CI step is undiagnosable
    # again -- which is the situation this was written to end.
    long_step = Step("self", "selfcheck-probe",
                     ["cmd", "/c", "for /L %i in (1,1,30) do @echo PROBE_LINE%i & exit /b 1"])
    probe_steps.append(long_step)
    run_step(long_step)
    probe_path = os.path.join(ARTIFACT_DIR, "steps", long_step.log)
    kept = ""
    if os.path.isfile(probe_path):
        with io.open(probe_path, encoding="utf-8", errors="replace") as fh:
            kept = fh.read()
        # Leave the tree exactly as it was found: this is a self-check, not a
        # build, and a stray log under ci/artifacts is someone's next puzzle.
        os.remove(probe_path)
    else:
        failures.append("full output: no log file for a failing step")
    if "PROBE_LINE1" not in kept:
        failures.append("full output: the line the 12-line tail drops is not "
                        "in the kept log")
    if long_step.log not in (long_step.as_dict().get("full_log") or ""):
        failures.append("full output: as_dict does not point at the log")

    total = 6
    failures.extend(qa_self_check())
    total += qa_self_check_count
    failures.extend(release_self_check())
    total += release_self_check_count
    try:
        sandbox_problems = sandbox.self_check(ROOT)
    except Exception as exc:  # noqa: BLE001
        sandbox_problems = ["sandbox self-check raised: %s" % exc]
    failures.extend(sandbox_problems)
    total += 1

    print("self-check: %d/%d cases passed" % (total - len(failures), total))
    for f in failures:
        print("  FAIL %s" % f)

    # Sweep only what this invocation created. Snapshot-then-delete rather
    # than "empty the directory": a self-check run right after a real CI run
    # must not throw away that run's evidence on its way out.
    try:
        for name in set(os.listdir(steps_dir)) - preexisting:
            os.remove(os.path.join(steps_dir, name))
    except OSError as exc:
        sys.stderr.write("self-check could not sweep %s: %s\n" % (steps_dir, exc))

    if failures:
        print("ENGINE SELF-CHECK FAILED -- do not trust a CI run from this build")
        return 1
    print("ENGINE SELF-CHECK OK")
    return 0


# Counted here so the existing print() line above can stay the single place that
# decides how many cases there were.
qa_self_check_count = 0


def qa_self_check():
    """The QA matrix must not be able to overstate what happened.

    Four properties, each of which has a way of quietly lying:

      a) a category whose command exits 0 is accounted PASS;
      b) a category whose command exits non-zero is accounted FAIL;
      c) a `not_available` category counts as neither pass nor fail AND is still
         printed -- the failure mode this file exists to kill is a row that
         disappears when it cannot run;
      d) the printed table contains all 20 category ids, always.
    """
    global qa_self_check_count
    qa_self_check_count = 5
    bad = []

    # (a) and (b): drive qa_results() with real Step objects, as a real qa run
    # would, and read back what the matrix says.
    def synthetic(cat_id, exit_code):
        argv = ["cmd", "/c", "exit", str(exit_code)]
        step = Step("qa", "qa/%s" % cat_id, argv, argvs=[argv])
        run_step(step)
        return [step]

    # (e) the zero-work guard: exit 0 having run nothing is not a pass.
    # This is the `moon bench` case on this repo, and `moon test -p src/channel`
    # is the other, so the guard is load-bearing rather than theoretical.
    zero_argv = ["cmd", "/c", "echo Total tests: 0, passed: 0, failed: 0."]
    vac = Step("qa", "vacuous", zero_argv, argvs=[zero_argv], zero_work_guard=True)
    run_step(vac)
    if vac.status != "failed":
        bad.append("zero-work guard: exit 0 with 'Total tests: 0' reported %s"
                   % vac.status)
    honest = Step("qa", "honest", zero_argv, argvs=[zero_argv])
    run_step(honest)
    if honest.status != "passed":
        bad.append("zero-work guard misfired on a step that did not opt in (%s)"
                   % honest.status)

    for cat_id, code, want in (("format-check", 0, qa.RESULT_PASS),
                               ("format-check", 1, qa.RESULT_FAIL)):
        res = qa_results(synthetic(cat_id, code), ["qa"])
        got = res[cat_id]["result"]
        if got != want:
            bad.append("qa/%s exit %d accounted %s, wanted %s"
                       % (cat_id, code, got, want))

    # (c) a not_available category is neither pass nor fail, and is still printed.
    na = [c for c in qa.QA_CATEGORIES if c.status == "not_available"]
    ext = [c for c in qa.QA_CATEGORIES if c.status == "needs_external"]
    if not na:
        bad.append("registry declares no not_available category; the matrix lost its teeth")
    res = qa_results([], ["qa"])
    counts = qa.tally(res)
    for c in na + ext:
        want = qa.RESULT_NA if c.status == "not_available" else qa.RESULT_EXT
        if res[c.id]["result"] != want:
            bad.append("%s reported %s, wanted %s"
                       % (c.id, res[c.id]["result"], want))
        if res[c.id]["result"] in (qa.RESULT_PASS, qa.RESULT_FAIL):
            bad.append("%s counted as a pass/fail" % c.id)
    if counts[qa.RESULT_PASS] != 0 or counts[qa.RESULT_FAIL] != 0:
        bad.append("a run that executed nothing still tallied pass=%d fail=%d"
                   % (counts[qa.RESULT_PASS], counts[qa.RESULT_FAIL]))
    if counts[qa.RESULT_NA] != len(na):
        bad.append("tally says %d not_available, registry has %d"
                   % (counts[qa.RESULT_NA], len(na)))

    # (d) the printed table always contains every declared id.
    if len(qa.QA_CATEGORIES) != qa.EXPECTED_COUNT:
        bad.append("registry holds %d categories, expected %d"
                   % (len(qa.QA_CATEGORIES), qa.EXPECTED_COUNT))
    lines = qa.render_matrix(res)
    printed = "\n".join(lines)
    for cat in qa.QA_CATEGORIES:
        if cat.label not in printed:
            bad.append("category %s missing from the printed matrix" % cat.label)
    # ...and the evidence for the rows that cannot run travels with them.
    for c in na + ext:
        if c.evidence[:40] not in printed:
            bad.append("%s printed without its probe evidence" % c.id)

    return bad



if __name__ == "__main__":
    sys.exit(main())
