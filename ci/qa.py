#!/usr/bin/env python3
"""ci/qa.py -- the QA category matrix for this repository.

## Why the categories live in data, not in prose

Between Loop #57 and #64 this repository accumulated a series of gates that were
*green while asserting something false*. The recurring shape: a thing that
cannot actually run in this toolchain was quietly left out of a run, and the
run reported PASS. A summary that can omit a check is the same failure mode as
a summary that can disagree with the exit code -- it is just quieter.

So the 20 QA categories are a **declared registry**, and the summary prints every
single one of them on every run, including the ones that cannot run. A category
is only ever allowed to reach PASS because a command was executed and returned
exit code 0. Nothing is inferred.

## Status vocabulary (exactly three values)

    implemented      a real command exists and runs in this toolchain.
                     It may still be FAILING today -- that is reported, not hidden.
    not_available    this toolchain/repository has no way to run it at all.
                     `evidence` must cite the probe that proves the absence.
    needs_external   the command is real but needs something outside the repo
                     (a live SSH peer, a browser Worker, a deployment).

`not_available` and `needs_external` are counted as **neither pass nor fail**.
They are still printed. That distinction is load-bearing: a category that cannot
run is not a red gate, and pretending otherwise trains people to ignore red.

## Provenance of the "not available" verdicts

Every `not_available` entry below cites a probe that was actually executed on
this machine against `moon 0.1.20261012`. Two of them contradict what the task
brief asserted, and the probe won -- see `gherkin-test` and `security-scan-dast`.
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# On Windows the engine shells out through cmd.exe, exactly as ci.py already
# does for every build step. Same convention, same quoting behaviour.
MOON = ["cmd", "/c", "moon"]
NODE = ["cmd", "/c", "node"]
PY = ["cmd", "/c", "python"]

MOON_VERSION = "0.1.20261012"


class QaCategory(object):
    """One row of the matrix.

    `command` is either None (no runnable command in this tier -- the category is
    computed, process-level, or owned by another tier) or a list of argv lists,
    each of which is a subprocess. Every element must exit 0 for the category to
    be PASS; the first non-zero stops the sequence and fails the category.
    """

    __slots__ = ("id", "name_en", "name_zh", "status", "command", "tier",
                 "evidence", "merged_from", "timeout")

    def __init__(self, id, name_en, name_zh, status, command, tier, evidence,
                 merged_from=None, timeout=3600):
        self.id = id
        self.name_en = name_en
        self.name_zh = name_zh
        self.status = status
        self.command = command
        self.tier = tier
        self.evidence = evidence
        self.merged_from = merged_from or []
        self.timeout = timeout

    @property
    def runs_in_qa(self):
        return self.tier == "qa" and self.status == "implemented" and self.command

    @property
    def label(self):
        return self.id + (" (+" + "+".join(self.merged_from) + ")" if self.merged_from else "")

    def command_text(self):
        if not self.command:
            return "(no command)"
        return "  &&  ".join(" ".join(argv) for argv in self.command)

    def as_dict(self):
        return {
            "id": self.id,
            "label": self.label,
            "name_en": self.name_en,
            "name_zh": self.name_zh,
            "status": self.status,
            "tier": self.tier,
            "command": self.command_text(),
            "evidence": self.evidence,
            "merged_from": list(self.merged_from),
        }


# ---------------------------------------------------------------------------
# The 20 categories.
#
# Grouping note the output repeats: ids 2 and 15 each absorbed one extra id the
# brief listed separately (`static-code-check`, `contract-test`). Shipping two
# copies of one fact is how they drift, so each merge is recorded in
# `merged_from` and printed rather than quietly dropped.
# ---------------------------------------------------------------------------

QA_CATEGORIES = [
    QaCategory(
        id="format-check",
        name_en="format check",
        name_zh="格式检查",
        status="implemented",
        command=[MOON + ["fmt", "--check"]],
        tier="qa",
        evidence=(
            "Solved in Loop #67. `moon fmt --check` exits 0 over the whole tree. "
            "The standing warning that `moon fmt` write mode corrupts CJK "
            "comments did NOT reproduce and was removed: on moon 0.1.20261012 "
            "the formatter's own output in _build/<target>/release/format/ "
            "already matches the source CJK byte for byte (366 runs in "
            "cmd/channel_test/main.mbt), and a whole-tree format left all "
            "12,840 CJK runs across 226 files identical -- verified by "
            "host/cjk_snapshot.py, which snapshots before and checks after and "
            "is now the standing guard. Two findings worth keeping: `moon fmt "
            "--check` reported only 10 files before that change and 20 "
            "afterwards, with no overlap, so like `moon check --deny-warn` it "
            "reports a partial set rather than a total; and of the 10 it named "
            "first, 2 were line-ending-only (CRLF source against an LF "
            "formatter) with identical content, so a whole-file diff can be "
            "zero real changes."
        ),
    ),
    QaCategory(
        id="static-analysis-sast-code",
        name_en="static analysis / SAST (code)",
        name_zh="静态分析（代码级 SAST）",
        status="implemented",
        command=[NODE + [os.path.join("host", "verify_loop66.mjs")]],
        tier="qa",
        evidence=(
            "Loop #66 moved this row off `moon check --deny-warn` and onto a "
            "real gate, for three reasons that were measured rather than "
            "argued. (1) `moon check` with no path checks ONE package, not the "
            "module: the old probe called it once and reported the result as a "
            "repository-wide total, and three runs all said '7 files, 59 "
            "diagnostics' and looked stable when each had simply visited a "
            "different subset. (2) The diagnostic set is not stable under "
            "repair -- `src/hostkey` reported 15 `deprecated` while `cert.mbt` "
            "still had one, and 105 `test_unqualified_package` immediately after "
            "it was fixed, so one correct measurement is a floor, not a total. "
            "Loop #66 measured 318 sites, then 62, then 12, then 3, fixing one "
            "layer at a time. (3) `unused_package` cannot be gated on a single "
            "target: six packages gate files per target, and an import used "
            "only by gated files looks unused everywhere except the target it "
            "gates for, so the collector intersects across all four. Three "
            "survivors remain, and `src/khfile`'s `moonbitlang/async` is one of "
            "them even after the intersection because the compiler's `async "
            "test` expansion consumes it with no source text to find -- deleting "
            "it produces 8 hard errors, one per `async test` block. They are an "
            "accept table whose entries each carry their evidence, and the gate "
            "asserts the reported set EQUALS the table, so a new warning fails "
            "and a fixed one fails too. Probed: `node host/verify_loop66.mjs` "
            "exit 0 'loop66: 14/14'. MERGED with the brief's "
            "`static-code-check`: there is no second code-level static check in "
            "MoonBit, and two rows running one command would drift."
        ),
        merged_from=["static-code-check"],
    ),
    QaCategory(
        id="duplicate-code-detection",
        name_en="duplicate code detection",
        name_zh="重复代码检测",
        status="not_available",
        command=None,
        tier=None,
        evidence=(
            "Probed: `moon --help` on %s lists new build check prove run "
            "runwasm test clean fmt doc explain info bench add remove install "
            "tree fetch search view work login whoami register publish package "
            "deprecate update coverage generate-build-matrix upgrade "
            "shell-completion version. No audit, no lint, no dup subcommand. "
            "No third-party tool was added (moon.mod is frozen by task rule)."
            % MOON_VERSION
        ),
    ),
    QaCategory(
        id="dependency-check",
        name_en="dependency check",
        name_zh="依赖检查",
        status="implemented",
        command=[MOON + ["tree"]],
        tier="qa",
        evidence=(
            "Probed: `moon tree` exits 0 and prints the full module graph "
            "(proton@0.3.4, proton_config, proton_contract, proton_ffi, "
            "proton_rsa, proton_updater, sqlite3@0.2.2, async@0.22.4, "
            "lexer@0.4.0, x@0.5.5, xlog@0.4.2). PRECISE SPLIT: the dependency "
            "*graph* is implemented. A vulnerable-dependency scan is "
            "NOT AVAILABLE -- moon has no advisory/vulnerability database "
            "command, and no database is consulted anywhere in the toolchain."
        ),
    ),
    QaCategory(
        id="unit-test",
        name_en="unit test",
        name_zh="单元测试",
        status="implemented",
        command=[
            MOON + ["test", "-p", "src/sha256", "--target", "native"],
            MOON + ["test", "-p", "src/hmac", "--target", "native"],
            MOON + ["test", "-p", "src/chacha", "--target", "native"],
        ],
        tier="qa",
        evidence=(
            "Probed `moon test -p <pkg> --target native`: exit 0 with a non-zero "
            "'Total tests: N, passed: N' -- src/sha256 13/13, src/hmac 32/32, "
            "src/chacha 10/10. Leaf packages only -- composite packages are the "
            "component-test row."
        ),
    ),
    QaCategory(
        id="gherkin-test",
        name_en="Gherkin / BDD test",
        name_zh="Gherkin / BDD 测试",
        status="not_available",
        command=None,
        tier=None,
        evidence=(
            "PROBE CONTRADICTS THE BRIEF, and the probe wins. `moon search "
            "gherkin` exits 0 and finds moonrockz/gherkin@0.5.1 (a Gherkin "
            "parser with DOM/visitor/fold/SAX APIs); `moon search cucumber` "
            "finds moonrockz/cucumber-expressions@0.6.1. So the ecosystem DOES "
            "exist. It is not_available FOR THIS REPOSITORY, not for MoonBit: "
            "neither package is declared in moon.mod, the repo contains zero "
            "*.feature / *.feature.md files, and adding a third-party dependency "
            "is forbidden by the task's own constraints."
        ),
    ),
    QaCategory(
        id="qa-flow",
        name_en="QA flow / process",
        name_zh="QA 流程",
        status="implemented",
        command=None,
        tier="process",
        evidence=(
            "Process category, deliberately with no command. The flow IS "
            "ci/ci.py: one engine, tiers env/build/gates/peer-gates/mutations/qa, "
            "one exit code, and .github/workflows/ci.yml as a thin shell that "
            "calls it so the step list cannot drift. Verified: the default tier "
            "discovers 45 steps and `python ci/ci.py --self-check` passes."
        ),
    ),
    QaCategory(
        id="load-stress-test",
        name_en="load / stress test",
        name_zh="负载 / 压力测试",
        status="not_available",
        command=None,
        tier=None,
        evidence=(
            "Classified from the code, not the directory names. Read "
            "cmd/sftp_fault, cmd/sftp_mitm, cmd/sftp_test, cmd/wt_ssh and "
            "cmd/wt_net: sftp_fault drives 10 malformed scenarios x 5 cut points "
            "through ChanState -- that is fault injection into parsers (see "
            "fuzz-test), not load. cmd/wt_* need a browser Worker. "
            "cmd/probe_async_wall is a setTimeout race probe, not a load driver. "
            "A repo-wide grep for load|stress|soak|throughput|rps|concurren|"
            "flood matched 4 files, none of them a load harness. No concurrent "
            "session generator, no rate driver, no soak test exists."
        ),
    ),
    QaCategory(
        id="quality-metrics",
        name_en="quality metrics",
        name_zh="质量指标",
        status="implemented",
        command=None,
        tier="summary",
        evidence=(
            "Computed by ci/ci.py from THIS run's measured results -- the step "
            "pass rate and the implemented-category pass rate, both real "
            "arithmetic over observed exit codes, never a constant. Line coverage "
            "is deliberately NOT folded in: `moon coverage analyze` produces no "
            "number in this repo (see test-coverage), and a metric sourced from "
            "a command that always fails would be decoration."
        ),
    ),
    QaCategory(
        id="performance-test",
        name_en="performance test",
        name_zh="性能测试",
        status="implemented",
        command=[NODE + [os.path.join("host", "bench_modpow.mjs")]],
        tier="qa",
        evidence=(
            "Probed: `node host/bench_modpow.mjs` builds cmd/bench_slow, "
            "bench_fast and bench_cached in release and times 50 x 2048-bit "
            "modexp per program by running the native .exe directly, so the "
            "number is compute cost and not toolchain startup. Exit 0, and the "
            "three implementations agree byte-exact on the same value. This is "
            "the comparative regression signal; the `benchmark` row is the "
            "toolchain's own facility."
        ),
    ),
    QaCategory(
        id="mutation-test",
        name_en="mutation test",
        name_zh="变异测试",
        status="implemented",
        command=None,
        tier="mutations",
        evidence=(
            "host/loop*_mutations.py: 20 harnesses that edit the working tree, "
            "run `moon clean`, re-run the gate that owns the decision, and "
            "restore. Owned by the mutations tier and NOT in the qa tier on "
            "purpose: each one is many full gate runs and they mutate the tree, "
            "so they must never run concurrently with anything else here. "
            "Invoke with `python ci/ci.py --tiers mutations`."
        ),
    ),
    QaCategory(
        id="fuzz-test",
        name_en="fuzz test (fault injection)",
        name_zh="模糊测试（故障注入）",
        status="implemented",
        command=[MOON + ["run", "cmd/sftp_fault", "--target", "native"]],
        tier="qa",
        evidence=(
            "No fuzzer exists in the toolchain (`moon --help` has none), but "
            "cmd/sftp_fault IS fault injection and was classified by reading "
            "main.mbt: its own header says it pushes malformed packets through "
            "`chan_step`/`ChanState`, re-slicing the vectors at 5 cut points to "
            "prove the state machine. Probed: exit 0, 'ALL PASS (50/50 runs, 10 "
            "scenarios x 5 cut points)'. Deterministic vectors, not random "
            "generation -- honest name is fault-injection fuzzing."
        ),
    ),
    QaCategory(
        id="test-coverage",
        name_en="test coverage",
        name_zh="测试覆盖率",
        status="implemented",
        command=[
            MOON + ["test", "--enable-coverage", "-p", "src/bpacket", "--target", "native"],
            MOON + ["coverage", "analyze"],
        ],
        tier="qa",
        evidence=(
            "Probed, and it FAILS today -- reported, not hidden. `moon test "
            "--enable-coverage -p src/bpacket --target native` exits 0 (25/25), "
            "but `moon coverage analyze` then exits 2 with Failure('No coverage "
            "output data found') after error [4067] 'Missing main function in the "
            "main package' for cmd/wt_probe and cmd/wt_ssh -- the browser Worker "
            "mains break the workspace-wide combine step. Loop #67 pinned the "
            "mechanism down and it is structural, not a flag that was missed. "
            "`combine_coverages` walks the whole workspace and builds every "
            "package for the DEFAULT target; a package gated to js has no main "
            "there and fails [4067]. `moon coverage analyze --help` lists only "
            "-p and --target-dir: there is NO --target, so the combine cannot be "
            "pointed at js, and `-p` limits which coverage is REPORTED, not "
            "which packages are BUILT -- verified, `-p src/bpacket` fails "
            "identically. An attempt to declare the two entry points differently "
            "(`options(is_main: [...])`) was reverted: the key takes a boolean, "
            "and `git diff` confirmed the revert before moving on. "
            "Reproduced identically with -p and from inside src/bpacket."
        ),
    ),
    QaCategory(
        id="integration-test",
        name_en="integration test",
        name_zh="集成测试",
        status="implemented",
        command=[
            MOON + ["run", "cmd/kexdh_test", "--target", "native"],
            MOON + ["run", "cmd/channel_test", "--target", "native"],
            MOON + ["run", "cmd/sftp_test", "--target", "native"],
            MOON + ["run", "cmd/userauth_test", "--target", "native"],
        ],
        tier="qa",
        evidence=(
            "These drive several src packages together through a real protocol "
            "conversation rather than one package's unit tests. Probed: "
            "`moon run cmd/kexdh_test --target native` exit 0 "
            "'dh14_consistency: MATCH'; cmd/channel_test exit 0 "
            "'chan_io_coverage: PASS'; cmd/sftp_test exit 0 'ALL PASS (24 "
            "session cases, 7 inbuf cases)'; cmd/userauth_test exit 0. They need "
            "no SSH peer -- the peer-shaped ones are the e2e-test row."
        ),
    ),
    QaCategory(
        id="api-interface-contract-test",
        name_en="API / interface contract test",
        name_zh="接口契约测试",
        status="implemented",
        command=[
            MOON + ["run", "cmd/ed25519_kat", "--target", "native"],
            MOON + ["run", "cmd/knownhosts_kat", "--target", "native", "--",
                    "verify_c/_knownhosts_ref_out.txt"],
            MOON + ["run", "cmd/proposal_kat", "--target", "native"],
        ],
        tier="qa",
        evidence=(
            "A contract test here means: MoonBit's answer must equal an "
            "INDEPENDENT implementation's answer, byte for byte. The Python/C "
            "oracles under scripts/, host/ and verify_c/ generate the .mbt "
            "vectors that cmd/*_kat replay. Probed: `moon run cmd/ed25519_kat "
            "--target native` exits 0 'ALL PASS'; `cmd/knownhosts_kat` exits 0 "
            "'ALL PASS' WHEN GIVEN ITS VECTOR FILE (without the argument it "
            "panics on a usage message and aborts 0xC0000409 -- it is a "
            "file-reading driver, not a bare KAT); `cmd/proposal_kat` exits 0. "
            "MERGED with the brief's `contract-test`: same command, same "
            "evidence. Two rows differing only in a label are the duplication "
            "this project has already been burned by."
        ),
        merged_from=["contract-test"],
    ),
    QaCategory(
        id="e2e-test",
        name_en="end-to-end test",
        name_zh="端到端测试",
        status="needs_external",
        command=None,
        tier="peer-gates",
        evidence=(
            "Real gates, excluded from the default tier because they need a live "
            "SSH peer and/or a browser Worker. cmd/wt_ssh's own header: 'result: "
            "ESTABLISHED' means a real OpenSSH server accepted the handshake "
            "inside a browser Worker. ci/ci.py keeps the MEASURED exclusion list "
            "(PEER_GATES = verify_loop31..39) rather than a keyword scan, because "
            "loop53 mentions playwright yet runs in seconds."
        ),
    ),
    QaCategory(
        id="component-test",
        name_en="component test",
        name_zh="组件测试",
        status="implemented",
        command=[
            MOON + ["test", "-p", "src/bpacket", "--target", "native"],
            MOON + ["test", "-p", "src/kexflow", "--target", "native"],
        ],
        tier="qa",
        evidence=(
            "`moon test src/<pkg>` over the composite packages, as distinct from "
            "the unit-test row's leaf packages. Probed: src/bpacket exit 0 "
            "'Total tests: 25, passed: 25, failed: 0'; src/kexflow exit 0 "
            "'Total tests: 15, passed: 15, failed: 0'. src/channel is "
            "deliberately NOT listed: it has no *_test.mbt, and "
            "`moon test -p src/channel` exits 0 while printing 'Total tests: 0' "
            "and 'Warning: no test entry found' -- a green that ran nothing. Its "
            "coverage comes from cmd/channel_test under integration-test."
        ),
    ),
    QaCategory(
        id="benchmark",
        name_en="benchmark",
        name_zh="基准测试",
        status="implemented",
        command=[
            MOON + ["bench", "-p", "src/bigint", "--target", "native"],
        ],
        tier="qa",
        evidence=(
            "Green as of Loop #67, after two changes that were both needed. "
            "First, scope: `moon bench` with no package benchmarks the current "
            "package, so the row inherited the whole workspace and died on the "
            "js-only Worker mains ([4156] extern wasm against native) and on "
            "their unused_package noise. `-p src/bigint` is the Loop #66 "
            "lesson one level up -- never judge a multi-target workspace from "
            "one target. Second, content: the repository had ZERO benchmark "
            "blocks, and `moon bench` on a package with none exits 0 while "
            "printing 'Total tests: 0, passed: 0, failed: 0' and 'Warning: no "
            "test entry found'. An exit-code-only check would have reported a "
            "PASS having measured nothing, which is why the zero-work guard in "
            "ci.py exists and why verify_loop67 asserts on that text. "
            "src/bigint/bigint_bench.mbt now carries five. A MoonBit benchmark "
            "is a test block taking a `@bench.T`, not a `bench \"{}\" {}` "
            "block, and `b.keep()` is what stops the optimiser deleting the "
            "computation -- `ignore(x)` and `let _ = x` do not parse inside "
            "one. Measured on this machine: mod_pow 2048-bit e=65537 schoolbook "
            "4.86 ms +- 52 us, the same via the cached Montgomery context "
            "173.96 us +- 2.23 us -- a 28x gap, which is Loop #29's "
            "optimisation finally quantified rather than asserted -- and "
            "mod_mul 237.80 ns, mpint_encode 329.05 ns, bytes round trip "
            "486.26 ns. The modulus is RFC 3526 group 14 derived from "
            "2^2048 - 189 rather than pasted as 256 bytes nothing in this "
            "repository could check."
        ),
    ),
    QaCategory(
        id="security-scan-sast",
        name_en="security scan (SAST equivalent)",
        name_zh="安全扫描（SAST 等价）",
        status="implemented",
        command=[
            NODE + [os.path.join("host", "verify_loop60.mjs")],
            NODE + [os.path.join("host", "verify_loop61.mjs")],
        ],
        tier="qa",
        evidence=(
            "No SAST product exists for MoonBit. The closest real thing is "
            "targeted at the vulnerability class this project actually hit: "
            "'declared runnable != actually runnable'. Loop #59 shipped a "
            "proposal naming hmac-sha2-256-etm@openssh.com, which src/bpacket "
            "cannot run, and nothing failed for loops. src/bpacket/runnable.mbt "
            "(Loop #60) and src/kexflow/runnable.mbt (Loop #61) enforce the "
            "allow-lists, and verify_loop60/61.mjs assert them. Probed: "
            "`node host/verify_loop60.mjs` exit 0 '78/78 checks passed', "
            "`node host/verify_loop61.mjs` exit 0 '62/62 checks passed'. "
            "Deliberately NOT the same command as the static-analysis row -- "
            "this is a domain-specific rule, not a compiler diagnostic."
        ),
    ),
    QaCategory(
        id="security-scan-dast",
        name_en="security scan (DAST)",
        name_zh="安全扫描（DAST）",
        status="not_available",
        command=None,
        tier=None,
        evidence=(
            "PROBE CONTRADICTS THE BRIEF, and the probe wins. The brief listed "
            "DAST as simply absent; the real blocker is sharper. No DAST tool "
            "for MoonBit exists, AND DAST requires a running deployment to aim "
            "at -- this repository ships a client library, not a service. "
            "`moon --help` on %s offers no security/scanner subcommand of any "
            "kind. The peer-gates tier (e2e-test) is as close as this project "
            "gets, because those gates drive a real OpenSSH server."
            % MOON_VERSION
        ),
    ),
]

BY_ID = dict((c.id, c) for c in QA_CATEGORIES)

# The brief's original 21 numbers minus 2 documented merges plus 1 deliberate
# split (security-scan -> SAST + DAST) must land on exactly 20.
EXPECTED_COUNT = 20

assert len(QA_CATEGORIES) == EXPECTED_COUNT, (
    "the matrix must declare exactly %d categories, found %d"
    % (EXPECTED_COUNT, len(QA_CATEGORIES))
)


# ---------------------------------------------------------------------------
# Rendering.
#
# Returns the lines it printed rather than printing directly, so --self-check can
# assert on them. Every category gets a row on EVERY run, including the ones
# that cannot run. A matrix row that can silently disappear is the failure mode
# this file exists to prevent.
# ---------------------------------------------------------------------------

RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_NA = "NOT AVAILABLE"
RESULT_EXT = "NEEDS EXTERNAL"
RESULT_NOTRUN = "NOT RUN"
RESULT_COMPUTED = "COMPUTED"

# Categories whose whole point is to be visible even when they cannot run.
ALWAYS_EVIDENCE = (RESULT_NA, RESULT_EXT)


def render_matrix(results, indent="  "):
    """Print the 20-row matrix. `results` maps category id -> result dict.

    A result dict is {"result": str, "seconds": float|None, "detail": str}.
    Missing or unusable entries degrade to RESULT_NOTRUN -- never to a row that
    is quietly left out.
    """
    lines = []
    lines.append("%sQA CATEGORY MATRIX -- %d categories, none omitted"
                 % (indent, len(QA_CATEGORIES)))
    lines.append(indent + "=" * 78)
    for cat in QA_CATEGORIES:
        r = results.get(cat.id) or {}
        result = r.get("result") or RESULT_NOTRUN
        seconds = r.get("seconds")
        timing = ("%6.1fs" % seconds) if isinstance(seconds, float) else " " * 7
        lines.append("%s%-16s %-28s %-14s %s"
                     % (indent, result, cat.label, cat.name_zh, timing))
        detail = r.get("detail") or ""
        if detail:
            lines.append("%s    -> %s" % (indent, detail))
        lines.append("%s    cmd: %s" % (indent, cat.command_text()))
        # Evidence is printed for everything that did not run, so a reader can
        # never see "NOT AVAILABLE" without the probe that proves it.
        if result in ALWAYS_EVIDENCE or result == RESULT_NOTRUN:
            for chunk in _wrap(cat.evidence, 74):
                lines.append("%s    %s" % (indent, chunk))
    lines.append(indent + "=" * 78)
    return lines


def _wrap(text, width):
    words = text.split()
    out, cur = [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            out.append(cur)
            cur = w
        else:
            cur = (cur + " " + w) if cur else w
    if cur:
        out.append(cur)
    return out


def tally(results):
    """Count a results dict. `not_available` / `needs_external` count as neither.

    This is the accounting the --self-check cases assert on, kept here next to
    the registry so the definition of "pass" has exactly one home.
    """
    counts = {RESULT_PASS: 0, RESULT_FAIL: 0, RESULT_NA: 0,
              RESULT_EXT: 0, RESULT_NOTRUN: 0, RESULT_COMPUTED: 0}
    for value in results.values():
        counts[value.get("result") or RESULT_NOTRUN] += 1
    return counts

