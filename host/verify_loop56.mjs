// host/verify_loop56.mjs -- Loop #56: known_hosts, three sides plus a drift check.
//
// The known_hosts chain in `verify_c/` is the oldest in the repository, and until
// this loop nothing ran any of it automatically:
//
//   knownhosts_python_ref.py   42 self-checks against hashlib / hmac
//         |                    -> writes _knownhosts_ref_out.txt   (the vector file)
//         v
//   gen_knownhosts_test.py     sanity-checks against FIPS 180-4 and RFC 2202
//                              -> emits src/knownhosts/knownhosts_test.mbt
//                              -> emits verify_c/_knownhosts_kat.h
//         |
//         v
//   knownhosts_harness.c       28 assertions, built by build_knownhosts.bat
//
// `knownhosts_test.mbt` asserting against vectors that the generator wrote from a
// file that Python wrote is a closed loop: a mistake anywhere in it is invisible
// to it. Two things are done here that nothing did before.
//
// **One. Verdicts, not just bytes.** Both the MoonBit emitter (cmd/knownhosts_kat)
// and the Python reference now print the *decision* each side reaches for every
// vector -- `0=Ok 1=Mismatch 2=Unknown 3=Invalid 4=CertAuthority` -- in the vector
// file's own `key = value` shape. A disagreement about what a pinning rule
// *means* shows up here; a disagreement about SHA-1 arithmetic would not be the
// interesting one, and there are published constants for that.
//
// **Two. Drift as an assertion.** The two generated files are compared byte for
// byte against what the generator produces right now. They were regenerated once
// by hand and then left alone; a generator change that nobody re-ran would
// otherwise sit there looking fine.
//
// What this loop found, and it is the reason the C1-C3 vectors exist: the C
// harness and the Python reference had both been sitting on the Loop #14
// semantics, where `@cert-authority` entries take part in last-match-wins. Only
// `src/knownhosts` had the Loop #51/#53 fix. Comparing a CA entry's blob against
// the presented host key is meaningless, and **equal is fail-open**: a peer
// presenting the CA's own public key as its host key used to be accepted. Neither
// reference side had a single CA vector to notice, because the vector set predated
// the fix. Both are fixed here and the case is now asserted on all three sides.
//
// Note what the C side can and cannot contribute: `knownhosts_harness.c` asserts
// `s == V*_STATUS`, so it yields a boolean, not a verdict. MoonBit and Python are
// compared on values; C is compared on whether it agreed with the pinned number.
// That asymmetry is the harness's, not this gate's, and pretending otherwise
// would overstate what was checked.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, copyFileSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const VC = join(root, "verify_c");
const SNAP = join(root, ".loop-logs");
const KAT_EXE = join(root, "_build", "native", "debug", "build", "cmd", "knownhosts_kat", "knownhosts_kat.exe");
const VEC_FILE = join(VC, "_knownhosts_ref_out.txt");
const GENERATED = [
  join(root, "src", "knownhosts", "knownhosts_test.mbt"),
  join(VC, "_knownhosts_kat.h"),
];

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

// ---- `key = value` out of an emitter ----------------------------------------
//
// Both emitters print the vector file's own shape, so one parser serves both.
// A key is never overwritten: a parser that silently replaces a value it already
// has will, given a reference with more than one section, report a confident
// wrong answer -- which is the exact failure this loop exists to catch, one level
// down. Duplicates are refused loudly instead. (V10 legitimately emits
// `V10_expected_status` once per sub-case, which is why the emitter was changed
// not to repeat `V10_got_status` as well.)
function parseKeyed(text) {
  const out = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("[") || line.startsWith("#") || line.startsWith("=")) continue;
    const kv = /^([A-Za-z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!kv) continue;
    const [, k, v] = kv;
    if (Object.prototype.hasOwnProperty.call(out, k)) {
      throw new Error(`parseKeyed: key "${k}" printed twice with "${v}"`);
    }
    out[k] = v.trim();
  }
  return out;
}

function describeDiff(a, b, an, bn) {
  const lines = [];
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  for (const k of keys) {
    const av = Object.prototype.hasOwnProperty.call(a, k) ? a[k] : "<absent>";
    const bv = Object.prototype.hasOwnProperty.call(b, k) ? b[k] : "<absent>";
    if (av !== bv) lines.push(`      ${k}: ${an}=${av}  ${bn}=${bv}`);
  }
  return lines.slice(0, 24).join("\n") + (lines.length > 24 ? `\n      ... and ${lines.length - 24} more` : "");
}

function main() {
  // ---- the generated files, before anything overwrites them ---------------
  //
  // The generator writes in place, so the "before" bytes have to be taken first.
  // This is the drift check; without the snapshot the gate could only ever
  // confirm that the generator is deterministic, which is the weaker half.
  for (const f of GENERATED) {
    if (!existsSync(f)) {
      bad("generated files present", `missing ${path.relative(root, f)}`);
      return finish();
    }
  }
  const before = GENERATED.map((f) => readFileSync(f));

  console.log("side 1: Python reference (hashlib / hmac backed)");
  const py = runCmd(["python", join(VC, "knownhosts_python_ref.py")], { cwd: VC });
  if (py.status !== 0) {
    bad("python reference", py.text.trim().split("\n").slice(0, 8).join("\n      "));
    return finish();
  }
  const selfcheck = /SELF-CHECK:\s*(\d+)\/(\d+)\s+passed/.exec(py.text);
  if (!selfcheck || selfcheck[1] !== selfcheck[2]) {
    bad("python self-check", selfcheck ? `${selfcheck[1]}/${selfcheck[2]}` : "no SELF-CHECK line");
  } else {
    ok("python self-check", `${selfcheck[1]}/${selfcheck[2]}`);
  }

  console.log("");
  console.log("the generator, and whether the committed files still match it");
  const gen = runCmd(["python", join(VC, "gen_knownhosts_test.py")], { cwd: VC });
  if (gen.status !== 0) {
    bad("gen_knownhosts_test.py", gen.text.trim().split("\n").slice(-8).join("\n      "));
    return finish();
  }
  ok("gen_knownhosts_test.py", "ran");
  GENERATED.forEach((f, i) => {
    const now = readFileSync(f);
    if (Buffer.compare(now, before[i]) === 0) {
      ok(`no drift: ${path.basename(f)}`, `${now.length} bytes`);
    } else {
      copyFileSync(f, join(SNAP, path.basename(f) + ".drifted"));
      bad(
        `no drift: ${path.relative(root, f)}`,
        `the generator produced something different (${before[i].length} -> ${now.length} bytes). ` +
          `The regenerated copy is in .loop-logs/${path.basename(f)}.drifted; re-run the generator and commit.`,
      );
    }
  });

  console.log("");
  console.log("side 2: MoonBit src/knownhosts via cmd/knownhosts_kat");
  const b = runCmd(["cmd", "/c", "moon", "build", "cmd\\knownhosts_kat", "--target", "native"], { shell: true });
  if (b.status !== 0 || !existsSync(KAT_EXE)) {
    bad("build cmd/knownhosts_kat", b.text.trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/knownhosts_kat (native)");
  const mb = runCmd([KAT_EXE, VEC_FILE]);
  if (mb.status !== 0) {
    bad("moonbit emitter", `did not run: ${mb.error || `exit ${mb.status}`} ${mb.text.slice(0, 300)}`);
    return finish();
  }
  if (!/ALL PASS/.test(mb.text)) {
    bad("moonbit emitter", "did not report ALL PASS: " + mb.text.trim().split("\n").slice(-3).join(" | "));
  } else {
    ok("moonbit emitter", "ran");
  }

  console.log("");
  console.log("side 3: the C harness");
  const c = runCmd([join(VC, "build_knownhosts.bat")], { cwd: VC, shell: true });
  // Case-insensitive on purpose: the harness prints `FAIL` in caps, and a
  // case-sensitive `fail` counter here is always zero, i.e. dead code that looks
  // like a working second opinion. The `Total:` line is the real check; this is
  // the one that names which assertion broke.
  const cFail = (c.text.match(/^\s*fail\b/gim) || []).length;
  const cTotal = /Total:\s*(\d+)\/(\d+)\s+passed/.exec(c.text);
  if (c.error || c.status === null) {
    bad("c harness", `did not run: ${c.error || `exit ${c.status}`}`);
  } else if (cFail > 0 || !cTotal || cTotal[1] !== cTotal[2]) {
    bad("c harness", `${cFail} fail line(s); ` + c.text.trim().split("\n").slice(-5).join(" | "));
  } else {
    ok("c harness", `${cTotal[1]}/${cTotal[2]} passed`);
  }
  // The four C1-C3 blocks are the point of this loop's C-side work, so they are
  // named rather than left inside the total.
  for (const label of [
    "C56 C1 CA covers host, no direct entry -> CertAuthority",
    "C56 C2 direct entry wins over CA -> Ok",
    "C56 C3 presenting the CA's own key must NOT be Ok",
    "C56 C3 ... and must be CertAuthority",
  ]) {
    if (new RegExp(`^pass ${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*$`, "m").test(c.text)) {
      ok(`c: ${label}`);
    } else {
      bad(`c: ${label}`, "not reported as passing");
    }
  }

  // ---- the comparison ------------------------------------------------------
  console.log("");
  console.log("MoonBit vs Python, verdict by verdict");
  let P, M;
  try {
    P = parseKeyed(py.text);
    M = parseKeyed(mb.text);
  } catch (e) {
    bad("parse emitter output", String(e.message));
    return finish();
  }

  const gotKeys = Object.keys(M).filter((k) => k.endsWith("_got_status"));
  if (gotKeys.length === 0) {
    bad("moonbit emitter", "printed no _got_status rows");
    return finish();
  }
  ok("moonbit emitter", `${gotKeys.length} verdicts`);

  // `V10a` / `V10b` are sub-cases of `V10`; the vector file carries one pinned
  // number for the pair. Declared before the coverage check, which needs it.
  const baseOf = (id) => (/[ab]$/.test(id) ? id.slice(0, -1) : id);

  // Key-set equality first. A case that exists on one side only is the quiet
  // failure this whole loop is about: it does not error, it just stops checking.
  const pk = new Set(Object.keys(P));
  const mk = new Set(Object.keys(M));
  const onlyP = [...pk].filter((k) => !mk.has(k));
  const onlyM = [...mk].filter((k) => !pk.has(k));
  if (onlyP.length || onlyM.length) {
    bad("emitters describe the same cases", describeDiff(P, M, "py", "mb"));
  } else {
    ok("emitters describe the same cases", `${mk.size} keys, identical sets`);
  }

  // Coverage, from the vector file's side. The emitters both have an
  // `assert_full_coverage` of their own, but two implementations that are wrong
  // in the same way check each other perfectly -- delete a row from *both* case
  // tables and their key sets stay identical while one case quietly stops being
  // decided at all. Reading the vector file breaks that symmetry: it is the one
  // thing neither emitter gets to curate.
  const vec = parseKeyed(existsSync(VEC_FILE) ? readFileSync(VEC_FILE, "utf-8") : "");
  const vecIds = Object.keys(vec)
    .filter((k) => k.endsWith("_expected_status"))
    .map((k) => k.slice(0, -"_expected_status".length))
    .sort();
  const decided = new Set(gotKeys.map((k) => baseOf(k.slice(0, -"_got_status".length))));
  const undecided = vecIds.filter((id) => !decided.has(id));
  if (vecIds.length === 0) {
    bad("vector file readable", "no *_expected_status keys in " + path.relative(root, VEC_FILE));
  } else if (undecided.length) {
    bad("every vector in the file gets a verdict", `not decided: ${undecided.join(", ")}`);
  } else {
    ok("every vector in the file gets a verdict", `${vecIds.length} of ${vecIds.length}`);
  }

  // Every verdict against the vector file's own pinned expectation, and against
  // the other implementation.
  // E1 (empty entries) has no key in the vector file: the C harness checks it
  // against a bare literal, so there is nothing to read. Pinned here rather than
  // skipped -- an unpinned row that silently stops being checked is the failure
  // mode this gate is built around.
  const NO_VECTOR_KEY = "2";
  let disagree = 0;
  let wrongExpectation = 0;
  for (const key of gotKeys) {
    const id = key.slice(0, -"_got_status".length);
    const base = baseOf(id);
    const hasExp = Object.prototype.hasOwnProperty.call(M, `${base}_expected_status`);
    const exp = hasExp ? M[`${base}_expected_status`] : NO_VECTOR_KEY;
    const source = hasExp ? `expected ${exp}` : `no vector key; pinned to ${NO_VECTOR_KEY} here`;
    if (P[key] !== M[key]) {
      bad(`case ${id} agrees across MoonBit / Python`, `moonbit=${M[key]} python=${P[key]}`);
      disagree += 1;
      continue;
    }
    if (M[key] !== exp) {
      bad(`case ${id} matches its expectation`, `got ${M[key]}, ${source}`);
      wrongExpectation += 1;
      continue;
    }
    ok(`case ${id}`, `= ${M[key]}${hasExp ? "" : " (no vector key)"}`);
  }

  // ---- the values that are not verdicts ------------------------------------
  console.log("");
  console.log("primitives and markers, MoonBit vs Python");
  const scalarKeys = Object.keys(M).filter(
    (k) => !k.endsWith("_got_status") && !k.endsWith("_expected_status"),
  );
  for (const k of scalarKeys) {
    if (P[k] === M[k]) ok(k, `= ${String(M[k]).slice(0, 56)}`);
    else bad(k, `moonbit=${M[k]} python=${P[k]}`);
  }

  console.log("");
  console.log(`verdicts: ${disagree} disagreement(s), ${wrongExpectation} off-expectation`);

  // ---- regression: the generated MoonBit tests -----------------------------
  console.log("");
  console.log("regression: moon test src/knownhosts");
  const t = runCmd(["cmd", "/c", "moon", "test", "src\\knownhosts"], { shell: true });
  const total = /Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/.exec(t.text);
  if (!total) bad("moon test src/knownhosts", t.text.trim().split("\n").slice(-6).join("\n      "));
  else if (total[3] !== "0") bad("moon test src/knownhosts", `${total[2]}/${total[1]} passed, ${total[3]} failed`);
  else ok("moon test src/knownhosts", `${total[1]}/${total[1]} passed`);

  return finish();
}

function finish() {
  console.log("");
  console.log(`loop56: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

main();