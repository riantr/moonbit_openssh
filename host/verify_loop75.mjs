#!/usr/bin/env node
// host/verify_loop75.mjs -- the C harness must not depend on what the stack
// happened to contain.
//
// ## The defect this gate exists for
//
// On GitHub run 39236194074 the `knownhosts` C harness reported 12 of 28
// assertions failing, and the same source passed 28/28 on the developer
// machine. The difference was not the code: it was the *uninitialised bytes*
// that happened to be on the stack.
//
// `verify_c/knownhosts_harness.c` had, in its base64 decoder:
//
//     char padded[1024];
//     memcpy(padded, s, slen);
//     if (slen % 4 != 0) { while (strlen(padded) % 4 != 0) padded[strlen(padded)] = '='; }
//     padded[strlen(padded)] = '\0';
//
// Two separate undefined behaviours:
//
//   1. `padded` was never NUL-terminated after the `memcpy`, so the very first
//      `strlen(padded)` read past `slen` into whatever the stack held.
//   2. The padding loop measured the string with `strlen` *after* overwriting
//      the terminator it had just measured, so each iteration could walk
//      further into the uninitialised region.
//
// An ed25519 public key blob is exactly 68 base64 characters, and 68 % 4 == 0,
// so the `if` branch was skipped and the decoder went straight to the
// unterminated `strlen`. Every ed25519-key assertion in the harness was
// reading uninitialised memory. Locally that memory happened to be zero; on
// the CI runner it was not.
//
// ## Why a gate and not a comment
//
// The fix is three lines. But "we fixed it" is not the same as "it cannot
// come back", and this repository has already paid for the difference once.
// The gate here is the check that makes the fix permanent: it rebuilds the
// harness with the compiler's own uninitialised-stack poisoning and requires
// the SAME number of passing assertions as the normal build.
//
//     clang -O2 -ftrivial-auto-var-init=pattern
//     gcc   -O2 -ftrivial-auto-var-init=pattern
//
// The poisoning flag is the point. A build that only ever runs on a stack that
// happens to be zero cannot tell a correct decoder from a lucky one. The
// poisoned build can.
//
// ## What it does NOT do
//
// It does not replace the normal build. The normal build is what CI runs, and
// it is what proves the harness still agrees with the MoonBit implementation
// byte for byte. This gate runs alongside it and asks a different question:
// does the harness still pass when the stack is full of garbage?

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VERIFY_C = path.join(ROOT, "verify_c");
const HARNESS = path.join(VERIFY_C, "knownhosts_harness.c");
const OUT = path.join(VERIFY_C, "loop75_poisoned.exe");

let failures = 0;
let checks = 0;
const section = (t) => console.log(`\n${t}`);
const ok = (name, cond, detail = "") => {
  checks++;
  if (!cond) failures++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};

// The same discovery the build scripts use, and the same rule: never a
// hardcoded machine path. `where` first (PATH), then the well-known install
// prefixes, and if none works the gate says so by name.
function findCompilers() {
  const found = [];
  const probe = (cmd) => {
    try {
      const out = execFileSync("cmd", ["/c", `where ${cmd}`], {
        encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
      });
      for (const line of out.split(/\r?\n/)) {
        const p = line.trim();
        if (p && !found.some((f) => f.path.toLowerCase() === p.toLowerCase())) {
          found.push({ name: cmd, path: p });
        }
      }
    } catch {
      /* not on PATH */
    }
  };
  probe("clang");
  probe("gcc");
  return found;
}

section("A. the harness source no longer reads an unterminated buffer");
{
  const src = readFileSync(HARNESS, "utf8");
  // The specific shape that was there: a `memcpy` into a fixed buffer with no
  // terminator, followed by a `strlen` of that buffer.
  const body = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
  const hasUnterminated = /char\s+padded\s*\[\s*\d+\s*\];[\s\S]{0,400}?memcpy\(\s*padded[^;]*;[\s\S]{0,200}?strlen\(\s*padded\s*\)/.test(body);
  ok("no unterminated memcpy-then-strlen of a stack buffer", !hasUnterminated);

  // The fix must terminate the buffer *and* compute the padding arithmetically.
  ok("the buffer is NUL-terminated right after the memcpy",
     /memcpy\(\s*padded[^;]*;\s*padded\[\s*slen\s*\]\s*=\s*'\\0'\s*;/.test(body));
  ok("the padding count is computed, not re-measured with strlen",
     /int\s+pad\s*=\s*4\s*-\s*r\s*;/.test(body) &&
     !/while\s*\(\s*\(int\)\s*strlen\(\s*padded/.test(body));
  // The group-commit half: the byte count must be derived from how many
  // sextets the group really holds, not fixed at three.
  ok("the byte count follows the sextets in the group, not a fixed three",
     /int\s+nbytes\s*=\s*\(\s*got\s*\*\s*6\s*\)\s*\/\s*8\s*;/.test(body) &&
     !/if\s*\(\s*\(size_t\)n_out\s*\+\s*3\s*>\s*out_max\s*\)/.test(body));
  ok("the salt/hash length is asserted, not patched by truncation",
     !/if\s*\(\s*salt_n\s*==\s*21\s*\)/.test(body) &&
     !/if\s*\(\s*hash_n\s*==\s*21\s*\)/.test(body));
}

section("B. the harness passes with the stack poisoned");
const compilers = findCompilers();
if (!compilers.length) {
  ok("a C compiler is available", false, "neither clang nor gcc is on PATH");
} else {
  console.log(`  compilers: ${compilers.map((c) => c.name).join(", ")}`);
  const results = [];
  for (const cc of compilers) {
    if (existsSync(OUT)) rmSync(OUT, { force: true });
    const build = spawnSync(cc.path, [
      "-O2", "-ftrivial-auto-var-init=pattern",
      "-o", OUT, HARNESS, "-lm",
    ], { cwd: VERIFY_C, encoding: "utf8", errors: "replace" });
    if (build.status !== 0) {
      // Not every toolchain has the flag (MSVC's clang in particular does not
      // support -ftrivial-auto-var-init). That is a skip, not a failure: the
      // point is to have at least ONE poisoned build that runs.
      const msg = `${(build.stderr || "").split("\n").filter(Boolean).slice(-1)[0] || ""}`.slice(0, 120);
      console.log(`  SKIP  ${cc.name}: does not support -ftrivial-auto-var-init (${msg})`);
      continue;
    }
    const run = spawnSync(OUT, [], { cwd: VERIFY_C, encoding: "utf8", errors: "replace" });
    const out = `${run.stdout || ""}${run.stderr || ""}`;
    const m = out.match(/Total:\s*(\d+)\/(\d+)\s+passed/);
    const pass = m ? Number(m[1]) : -1;
    const total = m ? Number(m[2]) : -1;
    const failedLines = out.split(/\r?\n/).filter((l) => l.startsWith("FAIL "));
    results.push({ name: cc.name, pass, total, failedLines });
    ok(`${cc.name} (poisoned stack) passes every assertion`,
       pass > 0 && pass === total,
       failedLines.length ? `${failedLines.length} failed, first: ${failedLines[0]}` : `${pass}/${total}`);
    if (failedLines.length) {
      for (const l of failedLines.slice(0, 14)) console.log(`        ${l}`);
    }
  }
  if (results.length) {
    ok("at least one compiler produced a poisoned build", true,
       results.map((r) => `${r.name}: ${r.pass}/${r.total}`).join(", "));
  } else {
    ok("at least one compiler produced a poisoned build", false,
       "no toolchain here supports -ftrivial-auto-var-init=pattern");
  }
}

if (existsSync(OUT)) rmSync(OUT, { force: true });

console.log("");
console.log(`loop75: ${checks - failures}/${checks} checks passed`);
if (failures) {
  process.exitCode = 1;
} else {
  console.log("ALL PASS");
}
