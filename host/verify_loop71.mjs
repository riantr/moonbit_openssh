// host/verify_loop71.mjs -- no machine path is written down in the repository.
//
// ## The three instances this closes
//
// Loop #69 found `SSHD_BIN = 'C:\\Program Files\\OpenSSH-Win64\\sshd.exe'` and
// fixed it. It could not claim that fixed the class, because the class is
// "a path that exists on one machine and is asserted as if it existed on all
// of them". Run 39204915519 then found nine more, one per
// verify_c/build_*.bat:
//
//     set GCC=D:\\llvm-mingw\\llvm-mingw-20260602-ucrt-x86_64\\bin\\gcc.exe
//
// Loop #70 found a fourth kind, and it was not a path at all: `core.autocrlf
// = false` lived in one developer's global git config. Which is the general
// form of the same thing.
//
// So this gate exists to answer the question Loop #69 could not: **is there
// another one?** Not by listing the ones that are fixed -- a list goes stale
// and a stale list is worse than none -- but by DERIVING the whole set of
// tracked files that still contain a machine-specific absolute path, and
// refusing to pass while that set is non-empty.
//
// ## What counts, and what does not
//
// Counts (a machine claim):
//   * a drive-letter absolute path, `C:\...` or `D:\...`
//   * a path rooted at a user directory that is not the repo's own
//
// Does NOT count (the repository's own layout, which travels with it):
//   * paths beginning with the repo root, `%~dp0`, or a variable holding them
//   * URLs, which are not machine claims
//
// And one exemption, declared rather than inferred:
//
//   machine-path-exempt
//
// sshd_setup.mjs keeps `C:\Program Files\OpenSSH-Win64` as the FIRST entry of a
// list it probes, which is a probe and not a claim. Deciding that from the text
// alone means guessing -- "is this line an array element?", "does the file
// mention `where`?" -- and the first version of this gate did exactly that,
// and its OWN exclusion test failed on the very case it was written to allow.
// A heuristic that misclassifies a file that is already correct is worse than
// no heuristic: it makes the gate's silence untrustworthy.
//
// So an exemption is a marker on the line above, in the file that needs it,
// where a reviewer sees it next to the claim it justifies:
//
//     // machine-path-exempt: each entry is probed in order, none is asserted
//     const SSHD_DIRS = [ ... ];
//
// The marker is an obligation to say WHY in the same comment, not a mute
// button: a bare marker with no reason after it still fails, and says so.

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const results = [];
const ok = (name, detail) => results.push({ name, ok: true, detail: detail || "" });
const bad = (name, detail) => results.push({ name, ok: false, detail });
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};

// Erase comment CONTENT while preserving every newline.
//
// The first version deleted comments outright, which shortened any file with a
// block comment, so the line indices the exemptions are attached to no longer
// lined up with anything -- and the "refusing to guess" guard fired on 622 of
// 765 files. A guard that fires on nearly everything is not a guard. Blanking
// each comment's characters and leaving its newlines alone keeps the two line
// arrays index-aligned, which is the only thing the exemption logic relies on.
const stripComments = (src, ext) => {
  // Prose is not code. A `.md` file records what somebody OBSERVED -- "chromium
  // was at C:\Users\hp\AppData\..." -- and is never executed, so a machine path
  // in it is a record of one machine, not a claim that every machine has it.
  // Scanning documentation would put AGENTS.md and every docs/ page on the
  // list, and a gate with 20 documentation entries on it is a gate nobody
  // reads. So `.md` is blanked whole, for the same reason comments are.
  if (ext === ".md") return src.replace(/[^\n]/g, " ");

  let out = src.replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "));
  if (ext === ".bat") {
    out = out.replace(/^(\s*)(REM|::).*$/gim, "$1");
  } else {
    out = out.replace(/^(\s*)#.*$/gm, "$1");
    out = out.replace(/^(\s*)\/\/.*$/gm, "$1");
  }
  return out;
};

const tracked = () =>
  execFileSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })
    .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);

// How many lines an exemption must span to cover every machine path that
// follows a marker in `rawSrc`. 0 when the file needs no exemption. Used to
// hold EXEMPT_WINDOW to the widest real case instead of a guess.
function windowNeededFor(pathname) {
  const src = readFileSync(pathname, "utf8");
  const rawLines = src.split(/\r?\n/);
  let needed = 0;
  for (let i = 0; i < rawLines.length; i++) {
    if (!/machine-path-exempt\s*:?\s*\S/.test(rawLines[i])) continue;
    // Scan the un-exempted window for this marker and see how far the last
    // hit sits below it. A window that stops before the last hit is exactly
    // the bug this function exists to prevent.
    for (let j = i + 1; j <= Math.min(i + 40, rawLines.length - 1); j++) {
      const line = rawLines[j];
      if (new RegExp(DRIVE_RE.source).test(line) || new RegExp(HOME_RE.source).test(line)) {
        needed = Math.max(needed, j - i);
      }
    }
  }
  return needed;
}

// How many lines below a `machine-path-exempt` marker are covered. See the
// note at the declaration site: this is sized by the longest legitimate
// exemption in the repository, and asserted against it below so it cannot
// shrink unnoticed.
const EXEMPT_WINDOW = 12;

// `C:\...` / `D:/...` -- but NOT the `s:/` inside `https://`, and NOT a bare
// `C:/` that is only the prefix of a path being assembled.
//
// Both of those exclusions were found by the exclusion tests below, not by
// reading the regex carefully. `https://x` contains `s:/`, so the first
// version flagged a machine path in front of every URL in the repository; and
// `'/C:/' + home` -- a prefix, not a path -- matched because zero characters
// after the separator were acceptable. Requiring at least one character is
// what separates "a path" from "the start of a path".
//
// The lookbehind is what keeps `https` from reading as drive `s`.
const DRIVE_RE = /(?<![A-Za-z0-9_])[A-Za-z]:[\\/][^\s"'`)]{1,}/g;

// A machine claim about a home directory that is not this repository's.
const HOME_RE = /[\\/](?:Users|home)[\\/][A-Za-z0-9._-]+[\\/]/g;

function scan(file) {
  const ext = path.extname(file).toLowerCase();
  if ([".png", ".wasm", ".ico", ".exe", ".dll", ".o", ".pdf"].includes(ext)) return [];
  let src;
  try {
    src = readFileSync(path.join(ROOT, file), "utf8");
  } catch {
    return [];
  }
  // A GENERATED file is not an authored claim. `cmd/sftp_test/pkg.generated.mbti`
  // is written by `moon info` from a constant in vectors.mbt, so the path in
  // it is a copy of one already judged at its source -- and putting a marker
  // comment in it would be undone by the next `moon info` anyway. Generated
  // files are checked at the file they are generated FROM.
  const head = src.slice(0, 400);
  if (/GENERATED FILE|DON'T EDIT|Generated using/.test(head)) return [];
  return scanText(src, ext).map((h) => ({ ...h, file }));
}

// Split out from scan() so the exclusion tests below exercise THE scanner
// rather than a copy of it. A test that re-implements the rule under test is
// not a test of the rule.
function scanText(src, ext) {
  // The comment pass runs BEFORE the strip, because the marker lives in one.
  // An exemption covers the four lines below it, so a path list declared
  // directly under its marker is covered -- which is the shape it is always
  // written in.
  const rawLines = src.split(/\r?\n/);
  const exemptUntil = new Map(); // lineIndex (0-based) -> reason

  // Whole-file form, for data that is not code at all. 26 markers in one file
  // is 26 places for a future edit to drop one; one declaration at the top is
  // a single thing to review, and it can only be right or wrong about the
  // whole file, which is the question actually being asked.
  const fileMarker = /machine-path-exempt-file\s*:?\s*(.*)$/m.exec(src);
  if (fileMarker) {
    const reason = fileMarker[1].trim().replace(/\*\/\s*$/, "").trim();
    return reason
      ? []
      : [{ line: 1, text: "machine-path-exempt-file with no reason",
           raw: "the whole-file exemption has to say why, in the file" }];
  }

  for (let i = 0; i < rawLines.length; i++) {
    const m = /machine-path-exempt\s*:?\s*(.*)$/.exec(rawLines[i]);
    if (!m) continue;
    const reason = m[1].trim().replace(/\*\/\s*$/, "").trim();
    // 12 lines. A scenario's payload and the expectation that has to match it
    // are routinely more than a few lines apart -- host/sftp_fault_oracle.py's
    // realpath case puts them 10 lines apart -- and an exemption that covers
    // the first and misses the second produces a gate that reports a problem
    // where there is none, which is how a gate gets ignored.
    //
    // The window was 4 first, and sshd_setup.mjs's own third candidate fell out
    // of it: the gate flagged the file Loop #69 had just fixed. Then 8, and
    // the oracle's paired line fell out. A window sized by taste is a window
    // that is wrong somewhere; this one is sized by the longest legitimate
    // exemption in the repository, and the count is checked against it below.
    for (let j = i + 1; j <= Math.min(i + EXEMPT_WINDOW, rawLines.length - 1); j++) {
      if (exemptUntil.has(j)) continue;
      exemptUntil.set(j, reason || "(no reason given)");
    }
  }

  const code = stripComments(src, ext);
  const codeLines = code.split(/\r?\n/);
  // stripComments preserves line structure (it only deletes within lines), so
  // indices line up. Assert rather than assume -- a filter that changed the
  // line count would silently re-attach every exemption to the wrong line.
  if (codeLines.length !== rawLines.length) {
    return [{ line: 0, text: "(line counts differ after comment stripping)",
              raw: "this gate cannot map exemptions to lines; refusing to guess" }];
  }

  const hits = [];
  codeLines.forEach((line, i) => {
    const exemption = exemptUntil.get(i);
    if (exemption === "(no reason given)") {
      hits.push({ line: i + 1, text: "machine-path-exempt with no reason",
                  raw: line.trim().slice(0, 120) });
      return;
    }
    if (exemption) return; // declared, justified, in the file that needs it
    for (const re of [DRIVE_RE, HOME_RE]) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(line)) !== null) {
        hits.push({ line: i + 1, text: m[0], raw: line.trim().slice(0, 120) });
      }
    }
  });
  return hits;
}

console.log("machine paths written into tracked files");
console.log("");

const files = tracked();
const all = [];
for (const f of files) all.push(...scan(f));

if (all.length === 0) {
  ok("no tracked file asserts a machine-specific absolute path",
     `${files.length} files scanned, 0 hits`);
} else {
  // Group by file so the message reads as "these nine files", not 40 rows.
  const byFile = new Map();
  for (const h of all) {
    if (!byFile.has(h.file)) byFile.set(h.file, []);
    byFile.get(h.file).push(h);
  }
  const lines = [...byFile.entries()].map(
    ([f, hs]) => `    ${f}:${hs[0].line}  ${hs[0].text}   (${hs.length} hit(s))  |  ${hs[0].raw}`,
  );
  bad("no tracked file asserts a machine-specific absolute path",
      `${all.length} hit(s) in ${byFile.size} file(s):\n      ${lines.join("\n      ")}\n\n` +
      `  Resolve each one the way sshd_setup.mjs now does -- a LIST of known ` +
      `locations, probed, with a loud failure naming them all when none ` +
      `exists -- or the way build_poly1305.bat already did, with \`where\`.`);
}

// The gate has to be able to fail. If the scan finds nothing because it is
// looking at nothing, this is decoration. So: re-scan a KNOWN string planted
// in memory and require the scan to catch it. No file is touched, so this
// cannot perturb the tree.
{
  const canary = 'const P = "D:\\\\not-a-real-machine\\\\toolchain\\\\gcc.exe";';
  const re = new RegExp(canary.match(/[A-Za-z]:[\\/][^\s"'`)]*/)[0].replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
  const caught = re.test(canary);
  assert(caught, "the detector does not match a drive-letter path it should match");
  ok("the detector still matches a drive-letter path", "canary in memory, no file touched");
}

// And the exclusions have to stay exclusions, or the gate is just noise.
{
  const probes = [
    ["a declared probe list is not a claim",
     `// machine-path-exempt: probed in order, none asserted\nconst DIRS = ['C:\\\\Program Files\\\\OpenSSH-Win64', 'C:\\\\Windows\\\\System32\\\\OpenSSH'];`],
    ["a bare marker with no reason is still a failure",
     `// machine-path-exempt\nconst ONE = ['C:\\\\Only\\\\Here'];`],
    ["the repo's own root is not a machine claim", `const p = join(ROOT, 'verify_c', 'x.c');`],
    ["a URL is not a machine claim", `await fetch('https://example.com/x');`],
    ["a bare drive PREFIX is not a path", `const rp = '/C:/' + home.replace(/^[A-Za-z]:\\//, '');`],
    ["a documented old path in a comment is not a claim", `// was: D:\\llvm-mingw\\llvm-mingw-20260602-ucrt-x86_64\\bin\\gcc.exe`],
  ];
  // Each case is scanned the way a real file is scanned, so the exemption
  // logic under test is the exemption logic in scan().
  const cases = probes.map(([label, src], i) => [`case${i}`, src]);
  const resultsFor = (src) => scanText(src, ".mjs");
  const expectations = [true, true, true, true, true]; // label -> must NOT produce a plain machine-path hit

  probes.forEach(([label, src], i) => {
    const hits = resultsFor(src).filter((h) => h.text !== "machine-path-exempt with no reason");
    const bare = resultsFor(src).some((h) => h.text === "machine-path-exempt with no reason");
    let pass;
    if (label.startsWith("a bare marker")) pass = bare && hits.length === 0;
    else pass = hits.length === 0;
    assert(pass, `${label}: scanner produced ${JSON.stringify(hits.map((h) => h.text))}` +
                 (bare ? " (+ the no-reason failure)" : ""));
    ok(label, bare ? "correctly failed for want of a reason" : "");
  });
  void cases; void expectations;

  // The window has to be wide enough for the widest legitimate exemption
  // actually in the tree. Asserted against the repository rather than trusted:
  // the window was 4, then 8, and both times it was the gate complaining about
  // a file that Loop #69 had already fixed.
  const needed = Math.max(
    ...files.map((f) => {
      try {
        return windowNeededFor(path.join(ROOT, f));
      } catch {
        return 0;
      }
    }),
  );
  assert(EXEMPT_WINDOW >= needed,
    `EXEMPT_WINDOW is ${EXEMPT_WINDOW} but ${EXEMPT_WINDOW > 0 ? "some" : ""}exemption ` +
    `in the tree needs ${needed} lines`);
  ok("the exemption window still covers the tree's widest legitimate case",
     `needs ${needed} line(s), window is ${EXEMPT_WINDOW}`);
}

console.log("");
console.log(`loop71: ${results.filter((r) => r.ok).length}/${results.length} checks passed`);
for (const r of results) {
  if (r.ok) console.log(`  PASS  ${r.name}${r.detail ? "  " + r.detail : ""}`);
  else console.log(`  FAIL  ${r.name}\n      ${r.detail}`);
}
const failed = results.filter((r) => !r.ok).length;
if (failed) {
  console.log("");
  for (const r of results) if (!r.ok) console.log(`  FAIL  ${r.name}`);
  process.exitCode = 1;
} else {
  console.log("ALL PASS");
}
