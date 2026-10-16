#!/usr/bin/env node
// Loop #67 gate.
//
// Loop #66 closed the static-analysis row. This gate covers the rows Loop #67
// closed, and -- more importantly -- covers the *reasons* they were believed to
// be impossible.
//
// The standing project rule is that a gate asserts intent, not literal text
// (loop24's gate was hardcoded to "23/23" and stayed red for three loops;
// loop63's grepped for a string that also appeared in a comment). So:
//
//   * "the tree is formatted" is asserted by running the formatter in check
//     mode, not by counting files.
//   * "the formatter does not eat CJK" is asserted by comparing CJK *content*
//     against a snapshot, not by a line count, because reformatting is allowed
//     to move lines.
//   * "the benchmark measured something" is asserted by requiring real work in
//     the output, because `moon bench` exits 0 having done nothing when a
//     package has no benchmarks. That zero-work green is the failure mode this
//     gate exists to make impossible.

import { readFileSync, existsSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(path.join(ROOT, p), "utf8");
const results = [];
const check = (name, fn) => {
  try {
    const detail = fn();
    results.push({ name, ok: true, detail: detail || "" });
  } catch (e) {
    if (e.message === "SKIPPED") results.push({ name, ok: true, skipped: true, detail: "" });
    else results.push({ name, ok: false, detail: e.message });
  }
};
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};
const skipAll = process.argv.includes("--skip-live");

const run = (argv, opts = {}) => {
  try {
    const out = execFileSync("cmd", ["/c", ...argv], {
      cwd: ROOT, encoding: "utf8", maxBuffer: 128 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"], ...opts,
    });
    return { code: 0, out };
  } catch (e) {
    return {
      code: e.status === undefined ? -1 : e.status,
      out: `${e.stdout || ""}${e.stderr || ""}`,
    };
  }
};

// ------------------------------------------------------------ format check

check("moon fmt --check is clean over the whole tree", () => {
  if (skipAll) throw new Error("SKIPPED");
  const r = run(["moon", "fmt", "--check"]);
  assert(
    r.code === 0,
    `moon fmt --check exited ${r.code}. It reports a PARTIAL set, so this is ` +
    `not a count to compare against -- re-run it after any format to see the ` +
    `next batch.`
  );
  return "exit 0";
});

check("no source file is CRLF where the formatter emits LF", () => {
  // Loop #67 finding: 2 of the 10 files `moon fmt --check` first named had
  // byte-identical content and differed only in line endings, which renders as
  // a whole-file delete-and-readd diff -- a diff that looks catastrophic and
  // contains no change at all. The formatter emits LF, so this asserts it.
  const listed = run(["git", "ls-files", "*.mbt", "*.pkg", "*.moon"]);
  const files = listed.out.split("\n").map((s) => s.trim()).filter(Boolean);
  const crlf = [];
  for (const f of files) {
    const b = readFileSync(path.join(ROOT, f));
    if (b.includes(Buffer.from("\r\n"))) crlf.push(f);
  }
  assert(crlf.length === 0, `CRLF files remain: ${crlf.join(", ")}`);
  return `${files.length} source files, all LF`;
});

// ---------------------------------------------------------------- CJK guard

check("the CJK snapshot guard is present and wired up", () => {
  const src = read("host/cjk_snapshot.py");
  assert(src.includes("def collect()"), "collector removed");
  assert(src.includes('sys.exit(1)') || src.includes("return 1"),
         "the guard no longer fails on a difference");
  assert(existsSync(path.join(ROOT, "host/cjk_snapshot.py")),
         "host/cjk_snapshot.py is missing");
  return "host/cjk_snapshot.py snapshots and checks";
});

check("CJK content in the tree still matches the committed snapshot", () => {
  if (skipAll) throw new Error("SKIPPED");
  const snap = path.join(ROOT, ".cjk_snapshot.json");
  assert(existsSync(snap), ".cjk_snapshot.json is missing; run cjk_snapshot.py save");
  const r = run(["python", "host/cjk_snapshot.py", "check", ".cjk_snapshot.json"]);
  assert(r.code === 0, `CJK content changed:\n${r.out.trim()}`);
  return r.out.trim().split("\n").pop();
});

// -------------------------------------------------------------- benchmark

check("moon bench runs real work in a package that builds on native", () => {
  if (skipAll) throw new Error("SKIPPED");
  const r = run(["moon", "bench", "-p", "src/bigint", "--target", "native"]);
  assert(r.code === 0, `moon bench -p src/bigint exited ${r.code}:\n${r.out.slice(-800)}`);
  // The zero-work guard. `moon bench` on a package with no benchmarks exits 0
  // and prints "Total tests: 0, passed: 0, failed: 0" plus "no test entry
  // found". A row that only checked the exit code would have reported PASS
  // having measured nothing -- which is the entire reason this category was
  // classified as implemented-with-a-known-defect.
  const out = r.out;
  assert(!/Total tests:\s*0/.test(out), "moon bench measured nothing (Total tests: 0)");
  assert(!/no test entry found/i.test(out), "moon bench found no benchmark entry");
  const m = out.match(/(\d+)\s+benchmarks?\s+run|benchmark.*?(\d+)/i);
  return m ? m[0].trim() : "benchmarks ran, output non-empty";
});

check("the benchmark category is scoped to a native-buildable package", () => {
  const qa = read("ci/qa.py");
  const block = qa.slice(qa.indexOf('id="benchmark"'));
  const cmd = block.slice(0, block.indexOf("evidence="));
  assert(cmd.includes("-p") || cmd.includes("--package"),
         "the benchmark row runs `moon bench` with no package, so it inherits " +
         "the whole workspace and the js-only Worker mains");
  assert(!cmd.includes('["bench", "--target", "native"]'),
         "the unscoped `moon bench --target native` command is back");
  return cmd.match(/command=\[([^\]]*)\]/)?.[1].trim() || "scoped";
});

// ------------------------------------------------------------- test coverage

// The evidence block of one QaCategory, as the string Python builds it.
//
// Adjacent string literals concatenate implicitly, so `"a " "b"` is the string
// `a b`. Reading the source text and searching it directly looks for `a b` in
// `a " " b`, misses, and reports a claim that is present and correct as missing.
const joinLiterals = (src) =>
  src.replace(/"\s*(?:\\.|[^"\\])*"\s*"/g, (m) => m.replace(/"\s+"/g, ""));

check("test-coverage records why the workspace combine cannot run", () => {
  const qa = read("ci/qa.py");
  const start = qa.indexOf('id="test-coverage"');
  assert(start !== -1, "the test-coverage row is missing from ci/qa.py");
  // Bound by the next row rather than by a `),` search: the evidence text is
  // free prose and an earlier version of this check sliced it at the first
  // `),`, which lands wherever the prose happens to put a closing paren.
  const rest = qa.slice(start);
  const next = rest.indexOf("QaCategory(");
  const sourceBlock = next === -1 ? rest : rest.slice(0, next);
  // Read the evidence as the value it is, not as the source text that spells
  // it. ci/qa.py builds each evidence block by concatenating adjacent string
  // literals, so the SOURCE reads
  //
  //     "...has no "
  //     "--target, and src/test_nested..."
  //
  // and any literal search for `no --target` misses, because in the source text
  // those two halves are separated by `" "`. Loop #68 rewrote this evidence and
  // the assertion broke on the wrapping rather than on the meaning.
  //
  // The fix is to join the literals the way Python does before looking for
  // anything. Stripping comments and quotes is not enough -- a search has to
  // see the same string the interpreter would build.
  const ev = joinLiterals(sourceBlock);
  assert(ev.length > 400, `evidence block is only ${ev.length} chars -- a stub`);
  // The mechanism, named, so the note cannot rot into a vague "it fails".
  assert(/4067/.test(ev), "the evidence no longer names error [4067]");
  assert(/no --target/.test(ev),
         "the evidence does not say that analyze has no --target flag, which " +
         "is the reason this is structural rather than a missed flag");
  // Loop #68 removed the third of these three assertions, and the reason is
  // worth keeping: this check used to require the literal string
  // `combine_coverages`, the OCaml function inside the reporter whose source
  // line had been read to find the failure. Loop #68 fixed the blocker, the
  // evidence stopped naming that function, and the check went red on a row
  // that is now GREEN -- a stale assertion, not a regression.
  //
  // What survives is the part that is still load-bearing: the row must say the
  // mechanism is a workspace-wide build at the default target, because that is
  // the part of the story that has not changed. Asserting the name of a
  // function inside someone else's implementation would have meant the fix had
  // to keep quoting it forever.
  assert(/whole workspace|workspace-wide|every package in the module|walks every package/i.test(ev),
         "the evidence no longer says the combine walks the whole workspace");
  return "records the structural blocker by name";
});

// --------------------------------------------------------------------- gate

check("the Loop #66 gate still passes", () => {
  if (skipAll) throw new Error("SKIPPED");
  const r = run(["node", "host/verify_loop66.mjs", "--skip-live"]);
  assert(r.code === 0, `verify_loop66.mjs failed:\n${r.out.slice(-800)}`);
  return r.out.trim().split("\n").pop();
});

// --------------------------------------------------------------------- report

let failed = 0;
let skipped = 0;
for (const r of results) {
  if (r.skipped) { skipped++; console.log(`SKIP  ${r.name}`); continue; }
  if (!r.ok) failed++;
  console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}`);
  if (r.detail) console.log(`      ${r.detail}`);
}
console.log(`---`);
console.log(`loop67: ${results.length - failed - skipped}/${results.length - skipped}` +
            (skipped ? ` (${skipped} skipped)` : ""));
process.exit(failed === 0 ? 0 : 1);
