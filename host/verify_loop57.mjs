// host/verify_loop57.mjs -- Loop #57: ssh_config resolution, diffed against
// OpenSSH's own `ssh -G`.
//
// `src/sshconfig` has existed since Loop #24 with a parser, an fnmatch, and a
// `match_host_option` -- and nothing outside `cmd/sshconfig_test` has ever called
// it. This loop did not start by auditing it; it started from a survey of which
// `src/` packages have no production importer, and `sshconfig` was one of four.
//
// It then turned out the package was not merely unused, it was **wrong**, in the
// way that only a real resolver can expose:
//
//   Host web1
//     User deploy
//   Host *
//     Port 2222
//
// `ssh -G web1` answers `user deploy` **and** `port 2222`. `match_host_option`
// searched only the first matching block, so for Port it answered "no such
// option" -- silently, because nothing called it. `Host *` at the end of a file is
// the most common thing in every `~/.ssh/config` on earth.
//
// The authority here is runnable, which is the whole reason this loop is
// affordable: OpenSSH_for_Windows_9.5p2 is on this machine and `ssh -G` prints
// the resolved configuration. That is not a second opinion to be weighed against
// a spec -- it *is* the implementation, so there is nothing to re-derive from
// memory and nothing to argue with.
//
// Two-sided on purpose. Loop #55 needed three because the authority was a
// published constant that two sides could both misread. Here the authority
// executes; a third leg would only be able to agree with one of the two.
//
// Two rules, and the second is the one that matters:
//
//   1. VALUE. Every keyword MoonBit resolves must equal what `ssh -G -F <fixture>`
//      reports for it.
//   2. COMPLETENESS. Every keyword where the fixture *changed* OpenSSH's answer
//      relative to an empty config must be resolved by MoonBit too.
//
// Rule 1 alone passes for a resolver that silently drops half the file -- it
// compares only what it chose to answer. Rule 2 is what turns "I found User" into
// "I found Port too, two blocks down", which is the bug this loop exists for. The
// completeness set comes from diffing `ssh -G` with and without the fixture, so
// OpenSSH decides what counts as changed rather than this gate.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONF = join(root, "verify_c", "sshconfig");
const KAT_EXE = join(root, "_build", "native", "debug", "build", "cmd", "sshconfig_kat", "sshconfig_kat.exe");
const CASES = join(CONF, "cases.txt");
const EMPTY = join(CONF, "empty.conf");

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

function run(argv, opts = {}) {
  const r = spawnSync(argv[0], argv.slice(1), {
    cwd: opts.cwd || root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: opts.timeout || 300000,
    shell: !!opts.shell,
  });
  return {
    text: `${r.stdout || ""}${r.stderr || ""}`,
    status: r.status,
    error: r.error ? String(r.error.message || r.error) : "",
  };
}

// `ssh -G` prints `keyword value`, one line per occurrence. A multi-valued
// keyword therefore prints several lines with the same key -- which is exactly
// how we tell "IdentityFile accumulated across two Host blocks" apart from
// "IdentityFile was set twice and the first should have won". Grouped here,
// joined with `|`, in printed order.
function parseSshG(text) {
  const map = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const sp = line.indexOf(" ");
    if (sp <= 0) continue;
    const k = line.slice(0, sp).toLowerCase();
    const v = line.slice(sp + 1).trim();
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(v);
  }
  return map;
}

// Changed relative to an empty config. Both runs use the same host, so anything
// that is identical in the two is a default this fixture did not touch.
function changedKeys(withFixture, withEmpty) {
  const out = new Set();
  for (const [k, v] of withFixture) {
    const e = withEmpty.get(k);
    if (!e || e.join("|") !== v.join("|")) out.add(k);
  }
  return out;
}

function parseCases(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const t = raw.trim();
    if (!t || t.startsWith("#")) continue;
    const parts = t.split(/\s+/);
    if (parts.length >= 2) out.push({ fixture: parts[0], host: parts[1] });
  }
  return out;
}

function main() {
  console.log("side 1: MoonBit src/sshconfig via cmd/sshconfig_kat");
  const b = run(["cmd", "/c", "moon", "build", "cmd\\sshconfig_kat", "--target", "native"], { shell: true });
  if (b.status !== 0 || !existsSync(KAT_EXE)) {
    bad("build cmd/sshconfig_kat", b.text.trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/sshconfig_kat (native)");

  const mb = run([KAT_EXE, CONF]);
  if (mb.status !== 0) {
    bad("moonbit emitter", `did not run: ${mb.error || `exit ${mb.status}`} ${mb.text.slice(0, 300)}`);
    return finish();
  }
  if (!/ALL PASS/.test(mb.text)) {
    bad("moonbit emitter", "did not report ALL PASS: " + mb.text.trim().split("\n").slice(-3).join(" | "));
  } else {
    ok("moonbit emitter", "ran");
  }

  // The emitter's output, grouped by case.
  const M = new Map();
  let cur = null;
  for (const raw of mb.text.split(/\r?\n/)) {
    const line = raw.trim();
    const head = /^CASE\s+(\S+)\s+(\S+)$/.exec(line);
    if (head) {
      cur = new Map();
      M.set(`${head[1]} ${head[2]}`, cur);
      continue;
    }
    if (line === "ALL PASS") break;
    const kv = /^([a-z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (kv && cur) {
      if (cur.has(kv[1])) throw new Error(`moonbit printed ${kv[1]} twice in one CASE`);
      cur.set(kv[1], kv[2]);
    }
  }
  if (M.size === 0) {
    bad("moonbit emitter", "printed no CASE blocks");
    return finish();
  }
  ok("moonbit emitter", `${M.size} cases`);

  console.log("");
  console.log("side 2: OpenSSH `ssh -G` (OpenSSH_for_Windows_9.5p2)");
  const cases = parseCases(readFileSync(CASES, "utf-8"));
  if (cases.length === 0) {
    bad("cases.txt", "no cases");
    return finish();
  }
  // Cases come from the shared file so the emitter and the gate cannot curate
  // their own. If the emitter skipped one, M.size < cases.length and the
  // per-case lookup below says so by name.
  if (M.size !== cases.length) {
    bad("every case in cases.txt is decided", `emitter produced ${M.size}, cases.txt lists ${cases.length}`);
  } else {
    ok("every case in cases.txt is decided", `${cases.length} of ${cases.length}`);
  }

  const sshG = (conf, host) => {
    const r = run(["ssh", "-G", "-F", conf, host], { timeout: 120000 });
    // ssh exits non-zero for some hosts even on a clean -G; the map is what
    // matters, so only a truly empty result is an error.
    const map = parseSshG(r.text);
    if (map.size === 0) throw new Error(`ssh -G -F ${conf} ${host} produced nothing\n${r.text.slice(0, 400)}`);
    return map;
  };

  for (const c of cases) {
    const id = `${c.fixture} ${c.host}`;
    let withFix, withEmpty, changed;
    try {
      withFix = sshG(join(CONF, c.fixture), c.host);
      withEmpty = sshG(EMPTY, c.host);
      changed = changedKeys(withFix, withEmpty);
    } catch (e) {
      bad(`case ${id}`, String(e.message));
      continue;
    }
    const mine = M.get(id);
    if (!mine) {
      bad(`case ${id}`, "the emitter printed nothing for this case");
      continue;
    }

    // Rule 1: VALUE -- everything we resolved must match OpenSSH.
    const valueProblems = [];
    for (const [k, v] of mine) {
      const theirs = withFix.get(k);
      if (!theirs) {
        valueProblems.push(`${k}: OpenSSH reports no such option at all`);
      } else if (theirs.join("|") !== v) {
        valueProblems.push(`${k}: moonbit=${v}  openssh=${theirs.join("|")}`);
      }
    }
    if (valueProblems.length) bad(`case ${id} values match ssh -G`, valueProblems.join("\n      "));
    else ok(`case ${id} values match ssh -G`, `${mine.size} keyword(s)`);

    // Rule 2: COMPLETENESS -- nothing the fixture changed may go unanswered.
    const missed = [...changed].filter((k) => !mine.has(k)).sort();
    if (missed.length) {
      bad(`case ${id} answers every keyword the fixture changes`, `not resolved: ${missed.join(", ")}`);
    } else {
      ok(`case ${id} answers every keyword the fixture changes`, `${changed.size} changed by this fixture`);
    }
  }

  console.log("");
  console.log("regression: the Loop #24 command still runs");
  const t = run(["cmd", "/c", "moon", "run", "cmd\\sshconfig_test"], { shell: true });
  if (t.status !== 0) {
    bad("cmd/sshconfig_test", t.text.trim().split("\n").slice(-8).join("\n      "));
  } else {
    ok("cmd/sshconfig_test", "ran clean");
  }

  return finish();
}

function finish() {
  console.log("");
  console.log(`loop57: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

main();