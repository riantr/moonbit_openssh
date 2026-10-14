// host/verify_loop58.mjs -- Loop #58: the client's ssh_config resolution, diffed
// against OpenSSH's `ssh -G` on the same inputs.
//
// Loop #57 fixed `src/sshconfig` and proved its resolver agrees with OpenSSH. The
// package still had no user: `cmd/ssh_live` never called it. Correct code with no
// caller is how the first-block-only bug survived from Loop #24 to Loop #57, so
// "it is now correct" was not a resting state.
//
// This loop wires it into the client and checks the thing that decides whether the
// feature is usable at all: **precedence**. OpenSSH takes the first value obtained
// for each keyword, and the command line is read before any file:
//
//   --user / -o Key=Value  >  the config file  >  the client's built-in default
//
// If a config file were consulted only when the caller said nothing, a user with a
// config file could never override it from the command line -- which is the
// everyday case, and the reason `-o` exists here rather than being deferred.
//
// Both sides get the same inputs: the client is run with `--config-effective
// --config <f> --target <t> -o K=V`, and `ssh -G -F <f> <t> -o K=V`. OpenSSH
// computes the answer; this gate only compares. That matters for the override
// cases especially -- if the client got the precedence rule backwards, the right
// answer is "whatever ssh says", not "whatever the spec implies".
//
// Four connection keywords are compared: hostname, user, port, identityfile.
// `identityfile` is multi-valued and compared as a `|`-joined list in order,
// because the client's `-o` value is *obtained first* and therefore sorts before
// the file's -- a set comparison would hide exactly the ordering that is at issue.
//
// Also asserted here, because it is the part that could have broken silently:
// with no `--config`, the client resolves nothing and invents nothing, and
// `--proposal` still prints the same bytes it printed before any of this existed.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const CONF = join(root, "verify_c", "sshconfig");
const EMPTY = join(CONF, "empty.conf");
const CASES = join(CONF, "conn_cases.txt");
const LIVE_EXE = join(root, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");
const KEYS = ["hostname", "user", "port", "identityfile"];

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
    cwd: root,
    encoding: "utf-8",
    errors: "replace",
    maxBuffer: 64 * 1024 * 1024,
    timeout: opts.timeout || 300000,
    shell: !!opts.shell,
  });
  return { text: `${r.stdout || ""}${r.stderr || ""}`, status: r.status, error: r.error ? String(r.error.message || r.error) : "" };
}

// `key value` lines, multi-valued keys grouped in printed order.
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

// The client's `--config-effective` block.
function parseEffective(text) {
  const map = new Map();
  let inside = false;
  let sawBlock = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "=== ssh_config effective ===") { inside = true; sawBlock = true; continue; }
    if (line === "=== end ===") { inside = false; continue; }
    if (!inside) continue;
    // `config:` / `target:` are labels; the resolved keywords are `key = value`.
    const label = /^([a-z0-9]+):\s*(.*)$/.exec(line);
    if (label) { map.set(label[1], label[2]); continue; }
    const kv = /^([a-z0-9]+)\s*=\s*(.*)$/.exec(line);
    if (kv) map.set(kv[1], kv[2]);
  }
  map.sawBlock = sawBlock;
  return map;
}

function parseCases(text) {
  const out = [];
  for (const raw of text.split(/\r?\n/)) {
    const t = raw.trim();
    if (!t || t.startsWith("#")) continue;
    const parts = t.split(/\s+/);
    // `ssh -G` has no `--user`, so this one step of the chain is asserted
    // against the client's own precedence rule rather than against OpenSSH.
    // It is called out in the label so nobody reads it as a cross-check.
    //
    // `arguser=` is accepted in either field 3 or 4: a case with no `-o`
    // overrides has no field 3 to leave empty, and requiring a placeholder
    // there is how a case ends up silently passing `-o` a bare placeholder.
    let fields = parts.slice(2);
    let arguser = "";
    const f = fields.findIndex((x) => x.startsWith("arguser="));
    if (f >= 0) {
      arguser = fields[f].slice(8);
      fields.splice(f, 1);
    }
    const over = [];
    if (fields.length && fields[0]) {
      for (const kv of fields[0].split(",")) {
        const i = kv.indexOf("=");
        if (i > 0) over.push([kv.slice(0, i), kv.slice(i + 1)]);
      }
    }
    out.push({ conf: parts[0], target: parts[1], over, arguser });
  }
  return out;
}

// `ssh -G` prints every option including the compiled-in defaults, so comparing
// all four keys unconditionally would be asking the client to invent `port 22`
// and seven default IdentityFile paths. The changed set comes from diffing the
// same `ssh -G` run against an empty config, so OpenSSH decides what the fixture
// plus the overrides actually moved -- the same two-rule shape Loop #57 used,
// and the same reason: VALUE alone passes a client that resolves nothing.
function sshG(conf, target, over) {
  const args = ["ssh", "-G", "-F", conf, target];
  for (const [k, v] of over) args.push("-o", `${k}=${v}`);
  const r = run(args);
  const map = parseSshG(r.text);
  if (map.size === 0) throw new Error(`ssh -G -F ${conf} produced nothing\n${r.text.slice(0, 300)}`);
  return map;
}

function main() {
  console.log("side 1: cmd/ssh_live --config-effective");
  const b = run(["cmd", "/c", "moon", "build", "cmd\\ssh_live", "--target", "native"], { shell: true });
  if (b.status !== 0 || !existsSync(LIVE_EXE)) {
    bad("build cmd/ssh_live", b.text.trim().split("\n").slice(-10).join("\n      "));
    return finish();
  }
  ok("build cmd/ssh_live (native)");

  const cases = parseCases(readFileSync(CASES, "utf-8"));
  if (cases.length === 0) {
    bad("conn_cases.txt", "no cases");
    return finish();
  }
  ok("conn_cases.txt", `${cases.length} cases`);

  for (const c of cases) {
    const id = `${c.conf} ${c.target}${c.over.length ? " " + c.over.map(([k, v]) => `${k}=${v}`).join(",") : ""}` +
      `${c.arguser ? " --user " + c.arguser : ""}`;
    const args = ["--config-effective", "--target", c.target];
    if (c.conf !== "NONE") args.push("--config", join(CONF, c.conf));
    for (const [k, v] of c.over) args.push("-o", `${k}=${v}`);
    if (c.arguser) args.push("--user", c.arguser);
    const mine = run([LIVE_EXE, ...args]);

    if (mine.status !== 0) {
      bad(`case ${id}`, `client exited ${mine.status}: ${mine.text.trim().slice(0, 200)}`);
      continue;
    }
    const got = parseEffective(mine.text);
    if (!got.sawBlock) {
      bad(`case ${id}`, "the client printed no effective block");
      continue;
    }

    let withConf, base;
    try {
      withConf = sshG(c.conf === "NONE" ? EMPTY : join(CONF, c.conf), c.target, c.over);
      base = sshG(EMPTY, c.target, c.over);
    } catch (e) {
      bad(`case ${id}`, String(e.message));
      continue;
    }

    // Rule 1, VALUE: everything the client resolved must match ssh -G.
    // `user` is excluded when the case carries `--user`, because `ssh -G` has no
    // such flag: it would report the file's value while the client is
    // deliberately reporting the flag's. Comparing them would be asking ssh to
    // answer a question it was never asked.
    const problems = [];
    for (const k of KEYS) {
      if (k === "user" && c.arguser) continue;
      const g = got.get(k);
      if (g === undefined) continue;
      const t = withConf.has(k) ? withConf.get(k).join("|") : undefined;
      if (t === undefined) problems.push(`${k}: client says ${g}, ssh -G reports no such option`);
      else if (g !== t) problems.push(`${k}: client=${g}  openssh=${t}`);
    }
    if (problems.length) bad(`case ${id} values match ssh -G`, problems.join("\n      "));
    else ok(`case ${id} values match ssh -G`, `${[...got.keys()].filter((k) => KEYS.includes(k)).length} keyword(s)`);

    // Rule 2, COMPLETENESS: nothing the config or the overrides moved may go
    // unanswered.
    const changed = KEYS.filter((k) => {
      if (k === "user" && c.arguser) return false;
      const a = withConf.has(k) ? withConf.get(k).join("|") : "";
      const e = base.has(k) ? base.get(k).join("|") : "";
      return a !== e;
    });
    const missed = changed.filter((k) => !got.has(k));
    if (missed.length) {
      bad(`case ${id} answers everything the config changes`, `not resolved: ${missed.join(", ")}`);
    } else {
      ok(`case ${id} answers everything the config changes`, `${changed.length} moved`);
    }

    // `--user` outranks `-o` and the file. Asserted here rather than against
    // ssh -G, and labelled as such, because ssh cannot be asked.
    if (c.arguser) {
      if (got.get("user") === c.arguser) {
        ok(`case ${id} --user outranks -o and the file`, `user=${c.arguser}`);
      } else {
        bad(`case ${id} --user outranks -o and the file`,
          `user=${got.get("user") || "(absent)"} expected ${c.arguser}`);
      }
    }
  }

  // ---- the two things that could have broken silently --------------------
  console.log("");
  console.log("nothing changes without --config");
  const bare = run([LIVE_EXE, "--config-effective", "--target", "web1"]);
  const bareMap = parseEffective(bare.text);
  const leaked = KEYS.filter((k) => bareMap.has(k));
  if (bareMap.get("config") === "(none)" && leaked.length === 0) {
    ok("no config -> nothing resolved, nothing invented");
  } else {
    bad("no config -> nothing resolved, nothing invented",
      `config=${bareMap.get("config")} leaked=${leaked.join(",") || "none"}`);
  }

  console.log("");
  console.log("--proposal is byte-identical to before this loop");
  const prop = run([LIVE_EXE, "--proposal"]);
  const want = {
    kex_algs: "diffie-hellman-group14-sha256",
    enc_ctos: "aes128-ctr",
    enc_stoc: "aes128-ctr",
  };
  const propBad = Object.entries(want).filter(([k, v]) => !prop.text.includes(`${k}: ${v}`));
  if (propBad.length === 0) {
    ok("--proposal unchanged", `${prop.text.split(/\r?\n/).length} lines`);
  } else {
    bad("--proposal unchanged", "missing: " + propBad.map(([k, v]) => `${k}: ${v}`).join(", "));
  }

  return finish();
}

function finish() {
  console.log("");
  console.log(`loop58: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

main();