#!/usr/bin/env node
// Loop #68 gate.
//
// This loop went after the last red qa category, `test-coverage`, and the
// blocker turned out to be four separate things stacked on top of each other,
// none of which was visible until the first three were removed:
//
//   1. Seven executables under cmd/ gated their only source file with
//      `options(targets: { "main.mbt": ["js"] })`. That is a FILE filter, so on
//      the default target the package still exists with no main.mbt and the
//      compiler answers [4067] "Missing main function".
//   2. `cmd/ssh_live` declared no target at all while building on native only.
//      Seven real [4021]/[4024] errors, every one of them true.
//   3. `moon coverage analyze` has no `--target`, so it builds the whole
//      workspace at the DEFAULT target -- which is not native (Loop #67) and is
//      not js (or the js-only mains would be the ones complaining).
//   4. The default reporter, `moon_cove_report`, dies on an OCaml assertion in
//      `output_no_intermediate`. `MOON_COVE_REPORT_ENABLED=1` routes to
//      `bin/moon_cove.wasm` instead, which works.
//
// `moon coverage analyze` also runs the tests itself, so a separate
// `moon test --enable-coverage` before it is not just redundant -- it leaves a
// second set of dumps behind and the combine then refuses them with
// "conflicting trace metadata". `moon coverage clean` is mandatory, not hygiene.
//
// What this gate asserts is intent, not literal text. It does NOT keep a list
// of which packages are expected to be reportable: it re-derives that set by
// running the toolchain, and compares against the committed measurement. A new
// package that becomes reportable is a red gate until the evidence file is
// refreshed; a package that stops being reportable is a red gate too, because
// the committed file would then be claiming something untrue.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const TARGETS = ["native", "js", "wasm", "wasm-gc"];
const SKIP_LIVE = process.argv.includes("--skip-live");

// One retry per package. See the section C comment: a single
// `moon coverage analyze` is not a reproducible measurement, and the committed
// evidence file is only trustworthy if the thing that re-derives it can
// survive the run that happened to be unlucky.
const ANALYZE_ATTEMPTS = 2;

// The sentence that explains a failure. `moon coverage analyze` prints an
// OCaml backtrace on failure, and its last line is the reporter's `main`
// calling itself:
//
//   Called from Moon_cove_report in file "moon_cove_report.ml", line 223726
//
// That string is the same for every failure the reporter can raise, which
// makes it useless as a reason. The payload of the `Failure(...)` on the first
// line is the reason. Falling back to the tail keeps an unrecognised failure
// shape visible instead of silent.
const describeFailure = (out) => {
  const m = out.match(/Fatal error: exception \w+\("([^"]*)"/s);
  if (m) return m[1].replace(/\\n/g, " ").split(/\s+/).join(" ").trim();
  const tail = out.trim().split("\n").filter((l) => l.trim()).pop() || "";
  return tail.trim();
};

let failures = 0;
let checks = 0;
const section = (t) => console.log(`\n${t}`);
const expect = (name, ok, detail = "") => {
  checks++;
  if (!ok) failures++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
  return ok;
};

// `cmd /c` on Windows, per house style: PowerShell mangles the toolchain's
// box-drawing diagnostics and a bare `moon` is not always resolvable as an
// argv[0] here.
const moon = (args, env = process.env) => {
  const r = execFileSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"], env,
  });
  return r;
};

// Never throws: this gate needs the OUTPUT of a failing build, not an exception.
const moonTry = (args, env = process.env) => {
  try {
    return { ok: true, out: moon(args, env) };
  } catch (e) {
    return { ok: false, out: (e.stdout || "") + (e.stderr || "") };
  }
};

// ---------------------------------------------------------------------------
section("A. every cmd executable declares the target it actually builds on");
{
  // Derived, not listed: whatever declares `supported_targets` must be exactly
  // as buildable as it claims, on all four targets, measured.
  const cmdDir = path.join(ROOT, "cmd");
  const declared = [];
  for (const name of readdirSync(cmdDir)) {
    const pkg = path.join(cmdDir, name, "moon.pkg");
    if (!existsSync(pkg)) continue;
    const m = readFileSync(pkg, "utf8").match(/supported_targets:\s*"\+([a-z-]+)"/);
    if (m) declared.push([`cmd/${name}`, m[1]]);
  }
  expect("at least the loop's eight packages declare a target", declared.length >= 8,
         `${declared.length} declaring`);

  if (SKIP_LIVE) {
    console.log("  SKIP  live build matrix (--skip-live)");
  } else {
    for (const [pkg, target] of declared) {
      const built = TARGETS.filter((t) => moonTry(["check", "--target", t, "-p", pkg]).ok);
      expect(`${pkg} declares ${target} and builds on it alone`,
             built.length === 1 && built[0] === target,
             `builds on [${built.join(",") || "nothing"}]`);
    }

    // The loop above only inspects packages that ALREADY declare something, so
    // it cannot see a package that stopped declaring: remove ssh_live's
    // `+native` and it simply drops off the list. This is the check that closes
    // that hole, and it is the same observation that found the bug --
    // `moon coverage analyze` walking the workspace at the default target and
    // hitting seven real [4021]/[4024] errors nobody had declared.
    //
    // Asserted on `Error: [NNNN]` lines, NOT on the exit code: a package that
    // correctly refuses an unsupported target exits non-zero with no
    // diagnostics at all (cmd/proton_gui does exactly that on js), so an
    // exit-code assertion would demand the workspace build on the target it
    // was told it cannot support. Silence is the healthy state here -- this is
    // the same lesson as the collector's `evidence_targets` in Loop #67, where
    // a package that failed to compile was being read as a clean one.
    const ws = moonTry(["check"]);
    const hard = (ws.out.match(/^Error: \[\d+\]/gm) || []).length;
    expect("whole-workspace check reports no hard error at the default target",
           hard === 0, `${hard} hard error(s); exit ${ws.ok ? 0 : 1}`);
  }
}

// ---------------------------------------------------------------------------
section("B. no cmd executable hides a target restriction in a per-file gate");
{
  // The `targets: { "main.mbt": [...] }` form is correct for the LIBRARY
  // packages under src/ -- src/khstore/moon.pkg and src/khfile/moon.pkg both
  // document why: a package-level declaration would block downstream consumers
  // so a wasm-wanting consumer fails at its own compile instead of silently.
  // cmd/ packages are leaves; nothing imports them, so the reason does not
  // apply and the file form buys nothing but a [4067] for every other target.
  const cmdDir = path.join(ROOT, "cmd");
  const offenders = [];
  for (const name of readdirSync(cmdDir)) {
    const pkg = path.join(cmdDir, name, "moon.pkg");
    if (!existsSync(pkg)) continue;
    const src = readFileSync(pkg, "utf8");
    if (/^\s*targets:\s*\{/m.test(src)) offenders.push(`cmd/${name}`);
  }
  expect("no cmd/*/moon.pkg uses a per-file targets: gate", offenders.length === 0,
         offenders.join(", "));

  // The lib-side rule must still be intact, or this loop quietly relaxed it.
  const kh = readFileSync(path.join(ROOT, "src", "khfile", "moon.pkg"), "utf8");
  expect("src/khfile keeps its per-file native gate (library rule untouched)",
         /targets:\s*\{[^}]*"store\.mbt"\s*:\s*\[\s*"native"/.test(kh));
}

// ---------------------------------------------------------------------------
section("C. the coverage pipeline produces a real report, re-derived");
{
  // Discover the same set host/cov_probe.py discovers: every src package with a
  // test driver. Then actually run the toolchain on each.
  const srcDir = path.join(ROOT, "src");
  const withTests = readdirSync(srcDir).filter((name) => {
    const dir = path.join(srcDir, name);
    if (!statSync(dir).isDirectory()) return false;
    return readdirSync(dir).some(
      (f) => f.endsWith("_test.mbt") || f.endsWith("_wbtest.mbt"));
  }).map((name) => `src/${name}`);

  expect("found src packages with test drivers", withTests.length > 0,
         `${withTests.length} packages`);

  const reportable = [];
  const notReportable = [];

  if (SKIP_LIVE) {
    console.log("  SKIP  live coverage runs (--skip-live)");
  } else {
    // `moon clean` before the sweep, and this is the load-bearing line of the
    // whole section. Measured: on a tree whose _build had been through dozens of
    // builds, `moon coverage analyze -p src/bpacket` and `-p src/hmac` both
    // failed with `conflicting trace metadata` -- a signature that reads like a
    // toolchain limitation and is not one. The same commands exit 0 right after
    // `moon clean` (bpacket: "Total: 66 uncovered line(s) in 11 file(s)", 31s)
    // and in a sandbox that has no _build at all. `moon coverage clean` removes
    // the dump files and leaves the conflict exactly where it was.
    //
    // So without this line the gate is not measuring the repository. It is
    // measuring whichever builds happened to be lying around, and it will
    // disagree with itself depending on who ran it last.
    moonTry(["clean"]);

    for (const pkg of withTests) {
      // No per-package `moon coverage clean` and no MOON_COVE_REPORT_ENABLED
      // here, because `moon clean` above has already done the work of both.
      // That is not an assumption: each was deleted from host/cov_report.py one
      // at a time and both mutations came back MISSED, and the default OCaml
      // reporter was measured printing the same report as the wasm one
      // (src/kexflow, 73 markers against Total: 73, 15s) against a clean
      // _build. See the "What it measures" section of AGENTS.md, Loop #68.
      // Retry once before concluding anything. A single `moon coverage
      // analyze` is not a reproducible measurement: the same command on the
      // same clean tree reported 15/15 thirty seconds after a run that reported
      // 14/17. Re-running costs ~3s for the two packages that fail for real
      // (src/khfile, src/test_nested -- native-only test drivers that
      // `coverage analyze` cannot instrument, which is why the committed set
      // has 15 entries and not 17) and turns a one-off build failure back into
      // the transient it was. host/cov_report.py carries the same retry for
      // the same reason.
      let r, m, attempts = 0;
      for (;;) {
        attempts += 1;
        r = moonTry(["coverage", "analyze", "-p", pkg]);
        m = (r.out || "").match(/^Total:\s+(\d+)\s+uncovered line\(s\)\s+in\s+(\d+)\s+file\(s\)/m);
        if ((r.ok && m) || attempts >= ANALYZE_ATTEMPTS) break;
        console.log(`    ${pkg}: no report on attempt ${attempts} (${describeFailure(r.out || "")}) -- retrying`);
      }
      if (r.ok && m) {
        // Self-consistency: the marker count on the annotated source must equal
        // the number the reporter claims. If they ever diverge the report is
        // dropping or duplicating lines, and "Total:" alone would not notice.
        const marks = ((r.out.match(/<-- UNCOVERED/g) || []).length);
        reportable.push(pkg);
        expect(`${pkg} report is self-consistent`, marks === Number(m[1]),
               `${marks} markers vs Total: ${m[1]}, ${m[2]} file(s)`);
      } else {
        notReportable.push([pkg, describeFailure(r.out || "")]);
      }
    }

    // A reason that names what happened is worth keeping; one that names a
    // frame in the reporter's own source is not. This is an assertion about
    // the measurement, not about the packages: `moon coverage analyze` prints
    // an OCaml backtrace whose LAST line is always the same string --
    //
    //   Called from Moon_cove_report in file "moon_cove_report.ml", line 223726
    //
    // regardless of why it failed. Taking the tail (which this section used to
    // do, alongside host/cov_report.py) therefore reported that same opaque
    // line for src/khfile, whose tests genuinely cannot be instrumented, and
    // for src/aead, which merely lost one instrumented build to a transient.
    // The second case then rewrote the committed reportable set, which is how
    // a full CI run went red on a package that section D -- the next command on
    // the next line -- reported successfully.
    //
    // Two packages fail here and both must keep failing: they are the reason
    // the committed set has 15 entries and not 17. Their reasons have to be
    // readable, or this gate is one bad day away from failing to explain
    // itself.
    const opaque = [];
    for (const [pkg, why] of notReportable) {
      if (/^(Called from |Raised at )/.test(why)) opaque.push(`${pkg}  --  ${why}`);
    }
    expect(`every non-reportable package has a readable reason (${notReportable.length})`,
           opaque.length === 0,
           opaque.length ? opaque.join(" | ") : notReportable.map(([p, w]) => `${p}: ${w.slice(0, 60)}`).join(" | "));
  }

  console.log(`  reportable: ${reportable.length}/${withTests.length}`);
  for (const [pkg, why] of notReportable) console.log(`    not reportable: ${pkg}  --  ${why}`);

  if (!SKIP_LIVE) {
    expect("coverage is actually measured for at least one package",
           reportable.length > 0, `${reportable.length} reportable`);

    // Compare against the committed measurement. Both directions matter: a
    // package that silently stopped being reportable must not be papered over.
    const evidencePath = path.join(ROOT, "host", "cov_reportable.json");
    expect("host/cov_reportable.json exists", existsSync(evidencePath));
    if (existsSync(evidencePath) && reportable.length) {
      const evidence = JSON.parse(readFileSync(evidencePath, "utf8")).reportable.slice().sort();
      const now = reportable.slice().sort();
      const added = now.filter((p) => !evidence.includes(p));
      const lost = evidence.filter((p) => !now.includes(p));
      expect("committed reportable set matches what the toolchain does now",
             added.length === 0 && lost.length === 0,
             added.length ? `newly reportable: ${added.join(",")}` :
             lost.length ? `no longer reportable: ${lost.join(",")}` : "");
    }
  }
}

// ---------------------------------------------------------------------------
section("D. the gate's own recipe, asserted by running it");
{
  // The one step the recipe actually depends on. Listed as a check rather than
  // assumed: if `moon clean` were ever renamed or dropped, every number in this
  // section would quietly become a statement about whatever happened to be in
  // _build, and nothing else here would notice.
  expect("moon clean exists as a subcommand", moonTry(["clean", "--help"]).ok);

  if (SKIP_LIVE) {
    console.log("  SKIP  live cov_report run (--skip-live)");
  } else {
    // No arguments, deliberately: this is the exact argv ci/qa.py runs, so a
    // step deleted from the command -- the target list it defaults to, the
    // clean, the reporter -- is caught by running the gate rather than by
    // reading it. With an explicit package argument the default target list is
    // bypassed entirely and a mutation there becomes invisible. Section C
    // establishes breadth by sweeping independently of the evidence file; this
    // establishes that the command CI actually executes still works.
    let out = "", ok = false;
    try {
      out = execFileSync("cmd", ["/c", "python", "host/cov_report.py"], {
        cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024,
        stdio: ["ignore", "pipe", "pipe"],
      });
      ok = true;
    } catch (e) {
      out = (e.stdout || "") + (e.stderr || "");
    }
    expect("host/cov_report.py -- the qa command -- exits 0", ok,
           (out || "").trim().split("\n").filter((l) => l.trim()).pop() || "");
    expect("that command measured a non-zero number of lines",
           /uncovered line\(s\) measured in total/.test(out) &&
           !/ 0 uncovered line\(s\) measured/.test(out));
  }
}

// The "N/M checks passed" line is what ci/ci.py greps for (SUMMARY_RE) to
// report a count instead of a bare "ok", and what it compares the two halves of
// to catch a gate that exits 0 while printing FAIL.
console.log(`\nloop68: ${checks - failures}/${checks} checks passed` +
            (SKIP_LIVE ? "  (structural only -- live checks skipped)" : ""));
process.exit(failures === 0 ? 0 : 1);
