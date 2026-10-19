// host/verify_loop55.mjs -- Loop #55: a second pair of eyes, runnable.
//
// `verify_c/` has held nine C harnesses and seven Python references since the
// early loops. Every one of them was run by hand, by a person, and the results
// went into a document. Nothing ran them again. `scripts/compare_kat.mjs`
// exists and works; nothing invokes it. The `build_*.bat` scripts are named in
// `docs/` and nowhere else.
//
// That is the state this loop ends. Ed25519, AEAD and the binary packet layer
// are the three components where a wrong answer is silent -- a verifier that
// accepts a forged signature, an AEAD that accepts a tampered ciphertext, a
// length prefix that is off by four -- and all three were being checked only
// against constants this repository also wrote. That is the same shape Loop #53
// was written against, where a fixture and a verifier shared one mistake and the
// whole thing came out green.
//
// What is compared here, and why it is three sides:
//
//   MoonBit   src/ed25519, via cmd/ed25519_kat -- the thing under test
//   C         OpenSSH's original ed25519.c, via verify_c/ed25519_harness.c
//   Python    `cryptography` (libsodium/OpenSSL-backed), via
//             verify_c/ed25519_python_ref.py
//
// The RFC 8032 constants are a *published authority*, not a second opinion, so
// all three sides are checked against them **and** against each other. Two
// implementations agreeing with a standard is evidence; two implementations
// agreeing with each other because both were written from the same misreading
// is not, and nothing here can rule that out -- which is why the malleability
// check is asserted separately rather than folded into the byte comparison.
//
// AEAD and bpacket are covered as regressions in their own right: their MoonBit
// KATs cannot be compared against a shared vector file yet (the C and Python
// sides use *different, independently generated* case sets -- `C1a` versus
// `S1a` -- so there is nothing to line up), but the C harnesses still have to
// build and pass, and until a loop gives them a common vector file, that is the
// most a gate can honestly claim. It is written down rather than papered over.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { keep } from "./keep_output.mjs";

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VC = join(root, "verify_c");
const MOON_KAT = join(root, "_build", "native", "debug", "build", "cmd", "ed25519_kat", "ed25519_kat.exe");

const failures = [];
let checks = 0;

function ok(label, detail) {
  checks += 1;
  console.log(`  PASS  ${label}${detail ? "  " + detail : ""}`);
}
function bad(label, detail) {
  checks += 1;
  failures.push(`${label}${detail ? "  " + detail : ""}`);
  console.log(`  FAIL  ${label}${detail ? "  " + detail : ""}`);
}
const hex = (s) => String(s || "").trim().toLowerCase();

// ---- the C harness's own verdict ------------------------------------------
//
// Asked before anything else, and reported separately: if the C side says FAIL
// then "MoonBit matched it" is not good news, and a gate that only compared
// values would print a cheerful match.
function cVerdict(text) {
  const passes = (text.match(/\bPASS\b/g) || []).length;
  const summary = /=====\s*Ed25519 SUMMARY:\s*([A-Z ]+?)\s*=====/.exec(text);
  return {
    allPass: !!summary && /ALL PASS/.test(summary[1]),
    anyFail: /\bFAIL\b/.test(text),
    malleable: /s==L reject:\s*(\w+)/.exec(text),
    passes,
  };
}

// ---- extract the vectors each side printed ---------------------------------
//
// Each side prints the same six facts in a different shape, so the gate parses
// into a map keyed by vector name rather than demanding the three agree on a
// line format. A shared text format would have been cosmetic and would have
// broken the first time one side's banner changed.

// MoonBit / Python: `Test N:` then indented `key = value` lines.
//
// Two rules that were both learned the hard way on the first run:
//
//   1. A `=====` banner ends the section. The Python reference prints its RFC
//      vectors, then a "Tampered Message Rejection" section that *also* has a
//      `sig =` line. Without resetting here, that second `sig` silently
//      overwrote Test 3's -- and the gate reported "Python disagrees with C and
//      MoonBit", which pointed at the reference instead of at the parser.
//   2. A key is never overwritten. A parser that can silently replace a value it
//      already has will, given a reference with more than one section, report a
//      confident wrong answer. That is the same shape as the bug this whole
//      loop exists to catch, one level up.
function parseKeyed(text) {
  const out = {};
  let current = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("=====")) {
      // Section boundary. Keep whatever the section already produced.
      current = null;
      continue;
    }
    const head = /^(Test\s+\d+):$/.exec(line);
    if (head) {
      current = head[1].replace(/\s+/g, " ");
      if (!out[current]) out[current] = {};
      continue;
    }
    const kv = /^([a-z-]+)\s*=\s*(.+)$/.exec(line);
    if (kv && current) {
      if (Object.prototype.hasOwnProperty.call(out[current], kv[1])) {
        throw new Error(
          `parseKeyed: ${current}.${kv[1]} appeared twice in one block -- ` +
          `refusing to overwrite the first with "${kv[2]}"`,
        );
      }
      out[current][kv[1]] = kv[2].trim();
    }
  }
  return out;
}

// C: `===== RFC 8032 Test N (...) =====` then `got pk <hex>` / `got sig <hex>`.
// The test number here is 1-based and matches the other sides' names.
function parseC(text) {
  const out = {};
  let current = null;
  for (const raw of text.split(/\r?\n/)) {
    const head = /=====\s*RFC 8032 Test (\d+)/.exec(raw);
    if (head) {
      current = `Test ${head[1]}`;
      out[current] = {};
      continue;
    }
    const got = /^got\s+(pk|sig)\s+([0-9a-fA-F]+)\s*$/.exec(raw.trim());
    if (got && current) out[current][got[1]] = got[2].toLowerCase();
  }
  return out;
}

function runCmd(argv, opts = {}) {
  const r = spawnSync(argv[0], argv.slice(1), {
    cwd: opts.cwd || root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: opts.timeout || 600000,
    shell: !!opts.shell,
  });
  return {
    text: `${r.stdout || ""}${r.stderr || ""}`,
    status: r.status,
    error: r.error ? String(r.error.message || r.error) : "",
  };
}

function main() {
  console.log("build cmd/ed25519_kat (native)");
  const b = runCmd(["cmd", "/c", "moon", "build", "cmd\\ed25519_kat", "--target", "native"], { shell: true });
  if (b.status !== 0 || !existsSync(MOON_KAT)) {
    bad("build cmd/ed25519_kat (native)", b.text.trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/ed25519_kat (native)");

  // ---- side 1: the C reference -------------------------------------------
  console.log("");
  console.log("side 1: OpenSSH's original ed25519.c");
  // The build script deletes the previous .exe first (Loop #55). Without that,
  // a harness left over from an earlier run would answer for a tree that was
  // never compiled -- the Loop #47 failure, one level down.
  const c = runCmd([join(VC, "build_ed25519.bat")], { cwd: VC, shell: true });
  const cv = cVerdict(c.text);
  if (c.error || c.status === null) {
    bad("c harness", `did not run: ${c.error || `exit ${c.status}`}`);
  } else if (cv.anyFail || !cv.allPass) {
    bad("c harness", `the C reference itself did not pass: ${c.text.trim().split("\n").slice(-6).join(" | ")}`);
  } else {
    ok("c harness", `ALL PASS, ${cv.passes} PASS lines`);
  }
  if (cv.malleable && cv.malleable[1] !== "PASS") {
    bad("c malleability", `s == L was ${cv.malleable[1]} -- the C side accepted a malleable signature`);
  } else {
    ok("c malleability", "s == L rejected");
  }

  // ---- side 2: Python, via `cryptography` --------------------------------
  console.log("");
  console.log("side 2: Python cryptography (libsodium/OpenSSL-backed)");
  const py = runCmd(["python", join(VC, "ed25519_python_ref.py")], { cwd: VC });
  if (py.status !== 0) {
    bad("python reference", py.text.trim().split("\n").slice(0, 6).join("\n      "));
    return finish();
  }
  // Its own negative sections, not just "it produced some output". The
  // reference is only a second opinion if it is also *rejecting* the same
  // things we reject.
  if (!/ALL PYTHON REFERENCE CHECKS PASS/.test(py.text)) {
    bad("python reference", "the reference did not report ALL PASS: " + py.text.trim().split("\n").slice(-3).join(" | "));
  } else {
    ok("python reference", "ALL PYTHON REFERENCE CHECKS PASS");
  }
  for (const [label, re] of [
    ["tampered message rejected", /OK:\s*tampered msg rejected/],
    ["wrong public key rejected", /OK:\s*wrong pk rejected/],
    ["large message round-trips", /verified\s*=\s*True/],
  ]) {
    if (re.test(py.text)) ok(`python: ${label}`);
    else bad(`python: ${label}`, "no such line in the reference output");
  }

  // ---- side 3: MoonBit -----------------------------------------------------
  console.log("");
  console.log("side 3: MoonBit src/ed25519");
  const mb = runCmd([MOON_KAT]);
  if (mb.status !== 0) {
    bad("moonbit", `did not run: ${mb.error || `exit ${mb.status}`} ${mb.text.slice(0, 200)}`);
    return finish();
  }
  if (!/ALL PASS/.test(mb.text)) {
    bad("moonbit", "the emitter did not report ALL PASS: " + mb.text.trim().split("\n").slice(-3).join(" | "));
  } else {
    ok("moonbit", "ran, and its own negative cases passed");
  }

  // ---- the comparison ------------------------------------------------------
  //
  // Every pk and sig, from all three, against each other. Not "the count
  // matched" -- the values.
  console.log("");
  console.log("three-way byte comparison");
  const P = parseKeyed(py.text);
  const M = parseKeyed(mb.text);
  const C = parseC(c.text);
  const names = ["Test 1", "Test 2", "Test 3"];
  for (const n of names) {
    if (!C[n]) { bad(`vector ${n}`, `the C harness printed nothing for ${n}`); continue; }
    if (!P[n]) { bad(`vector ${n}`, `the Python reference printed nothing for ${n}`); continue; }
    if (!M[n]) { bad(`vector ${n}`, `MoonBit printed nothing for ${n}`); continue; }
    const problems = [];
    for (const field of ["pk", "sig"]) {
      const cvv = hex(C[n][field]);
      const pv = hex(P[n][field]);
      const mv = hex(M[n][field]);
      if (!cvv || !pv || !mv) {
        problems.push(`${field}: missing a value (c=${!!cvv} py=${!!pv} mb=${!!mv})`);
      } else if (cvv !== pv) {
        problems.push(`${field}: C and Python disagree\n      c  = ${cvv.slice(0, 48)}\n      py = ${pv.slice(0, 48)}`);
      } else if (cvv !== mv) {
        problems.push(`${field}: MoonBit differs from the reference\n      ref = ${cvv.slice(0, 48)}\n      mb  = ${mv.slice(0, 48)}`);
      }
    }
    if (problems.length) bad(`vector ${n} pk+sig agree across C / Python / MoonBit`, problems.join("\n      "));
    else ok(`vector ${n} pk+sig agree across C / Python / MoonBit`);
  }

  // ---- negative cases, asserted rather than assumed ------------------------
  //
  // A verifier that accepts everything agrees with all three sides on every
  // positive vector and is completely broken. These are the checks that catch
  // it, so they are compared against what MoonBit *reports*, not left implicit
  // in an exit code.
  console.log("");
  console.log("negative cases (a verifier that accepts everything passes the vectors above)");
  const neg = [
    ["tampered message rejected", "tamper-rejected"],
    ["wrong key rejected", "wrongkey-rejected"],
  ];
  for (const [label, field] of neg) {
    const bads = names.filter((n) => M[n] && hex(M[n][field]) !== "true");
    if (bads.length === 0) ok(`moonbit: ${label}`, "all 3 vectors");
    else bad(`moonbit: ${label}`, `not rejected for ${bads.join(", ")}`);
  }
  if (/s\+L reject: PASS/.test(mb.text) && /s orig accept: PASS/.test(mb.text)) {
    ok("moonbit: s + L (malleability) rejected");
  } else {
    const lines = mb.text.split(/\r?\n/).filter((l) => /s\+L|s orig/.test(l));
    bad("moonbit: s + L (malleability) rejected", lines.join(" | ") || "no such lines");
  }
  // The carry line is the vector's own self-check: if `s + L` overflowed 32
  // bytes it would have wrapped back into range and stopped being malleable,
  // and the test would silently stop testing.
  if (/s\+L carry: ok/.test(mb.text)) ok("moonbit: s + L did not overflow (the vector is still malleable)");
  else bad("moonbit: s + L did not overflow", "the vector wrapped; it is not a malleability test any more");

  // ---- regressions on the other two C harnesses ---------------------------
  //
  // Not a substitute for a three-way comparison -- they cannot have one yet,
  // because the C and Python case sets are independently generated and share no
  // identifiers. What this does catch is a harness that stopped building, which
  // is the failure mode that has no other detector.
  console.log("");
  console.log("regression: the other two C harnesses still build and pass");
  for (const [label, script] of [["aead", "build_aead.bat"], ["bpacket", "build_bpacket.bat"]]) {
    const r = runCmd([join(VC, script)], { cwd: VC, shell: true });
    const failed = (r.text.match(/^\s*FAIL\b/gm) || []).length;
    if (r.error || r.status === null) bad(`c harness ${label}`, `did not run: ${r.error || `exit ${r.status}`}`);
    else if (/BUILD FAILED/.test(r.text)) {
      // `Building ed25519_kat.exe ...` / `BUILD FAILED` / `The system cannot
      // find the path specified.` is what the first EIGHT lines of this batch
      // gave on GitHub run 39200128854 -- and the middle line is the batch's
      // own echo, not the compiler's error. Three harnesses, the same one
      // useful line each, and the reason was only findable by reading
      // build_ed25519.bat by hand. The transcript keeps the compiler's words.
      bad(`c harness ${label}`, keep(`loop55-${label}`, r.text, 240));
    }
    else if (failed > 0) bad(`c harness ${label}`, `${failed} FAIL line(s)`);
    else ok(`c harness ${label}`, "built and reported no failures");
  }

  // ---- and the MoonBit unit tests still agree ------------------------------
  console.log("");
  console.log("regression: moon test src/ed25519");
  const t = runCmd(["cmd", "/c", "moon", "test", "src\\ed25519"], { shell: true });
  const total = /Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/.exec(t.text);
  if (!total) bad("moon test src/ed25519", t.text.trim().split("\n").slice(-6).join("\n      "));
  else if (total[3] !== "0") bad("moon test src/ed25519", `${total[2]}/${total[1]} passed, ${total[3]} failed`);
  else ok("moon test src/ed25519", `${total[1]}/${total[1]} passed`);

  return finish();
}

function finish() {
  console.log("");
  console.log(`loop55: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

main();
