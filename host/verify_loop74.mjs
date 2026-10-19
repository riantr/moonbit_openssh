#!/usr/bin/env node
// Loop #74 gate: the host keys have to appear on a machine that has never
// run this before.
//
// ## The defect
//
// `host/sshd_setup.mjs` built the ssh-keygen command line by splicing `-b
// <bits>` into a literal index:
//
//     const args = ['-t', type, '-f', priv, '-q', '-C', 'loop31 test host key'];
//     if (bits !== null) args.splice(3, 0, '-b', String(bits));
//
// Element 3 is `priv`, so the two elements went in FRONT of the filename:
//
//     ssh-keygen -t ecdsa -f -b 256 D:\...\hostkey_ecdsa_256 -q -C ...
//                  Too many arguments.
//
// `-f` took `-b` as its output path and the rest became positional arguments.
// The ed25519 entry, whose `bits` is null, was unaffected -- which is why the
// failure looked selective.
//
// ## Why it lived so long
//
// The whole branch is `if (!existsSync(priv))`. On a developer machine those
// four keys were generated on 2026-09-30 and have been reused ever since, so
// the line had not executed since it was written. On CI, where `.loop31/` is
// always fresh, it failed on every single run:
//
//     loop65: FAIL  the probe ran  [sshd never came up; the probe did not test
//              anything]
//     loop65: FAIL  LEAK CONFIRMED: the port outlives its owner  [status 3]
//
// A gate that could not test anything reported the thing it exists to detect.
// That is the failure worth being frightened by, and it was only made visible
// by Loop #72 forwarding the starter's stderr instead of discarding it.
//
// ## What this gate does about it
//
// It asks the question CI asks, on every run, everywhere: run the REAL
// generation code against an EMPTY directory and require the keys to appear.
//
// `host/sshd_setup.mjs` grew `--dir <path>` and `--keys-only` for this. That
// matters: a gate that re-implemented the argument construction would be
// testing its own copy, which is the mistake Loop #71 already had to unpick in
// its exclusion tests. This one spawns the file the CI job spawns.
//
// Nothing here is Windows-specific beyond the ssh-keygen that
// sshd_setup.mjs already requires -- `--dir` and `--keys-only` are how the
// clean-room question is asked, and the same two flags would work on a POSIX
// ssh-keygen.

import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let failures = 0;
let checks = 0;
const section = (t) => console.log(`\n${t}`);
const ok = (name, cond, detail = "") => {
  checks++;
  if (!cond) failures++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};

// Every algorithm the client actually offers. Loop #38 stopped pinning
// HostKeyAlgorithms, so this list is what decides the negotiation -- a server
// that only had ECDSA keys made the ECDSA-only proposal look sufficient for
// thirty-seven loops. A key that stops being generated here is a host key type
// that stops being negotiable, and the failure would otherwise surface as "No
// matching host key type found" in an unrelated gate.
const KEYS = [
  ["ecdsa", 256, "hostkey_ecdsa_256"],
  ["ecdsa", 384, "hostkey_ecdsa_384"],
  ["ed25519", null, "hostkey_ed25519"],
  ["rsa", 2048, "hostkey_rsa_2048"],
];

// One place that knows where ssh-keygen is, and it is the same lookup
// sshd_setup.mjs performs: next to the sshd binary it found, falling back to
// PATH. A second, different probe list here would be a second thing to keep
// true, and the Loop #71 lesson is that duplicated discovery is how a
// machine-specific path survives.
function findKeygen() {
  const dirs = [
    "C:\\Program Files\\OpenSSH",
    "C:\\Program Files\\OpenSSH-Win64",
    joinWindows("SystemRoot", "System32", "OpenSSH"),
  ];
  for (const d of dirs) {
    const p = path.join(d, "ssh-keygen.exe");
    if (existsSync(p)) return p;
  }
  return "ssh-keygen";
}
function joinWindows(...parts) {
  return path.join(process.env.SystemRoot || "C:\\Windows", ...parts.slice(1));
}

section("A. host keys are generated on a machine that has never run this");
const dir = mkdtempSync(path.join(tmpdir(), "loop74-keys-"));
let gen;
try {
  gen = execFileSync("node", [
    path.join(ROOT, "host", "sshd_setup.mjs"), "--dir", dir, "--keys-only",
  ], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  ok("sshd_setup.mjs --keys-only exits 0", true, dir);
} catch (e) {
  gen = `${e.stdout || ""}${e.stderr || ""}`;
  // The whole point. `Too many arguments` from ssh-keygen arrives here as a
  // non-zero exit with the toolchain's own complaint attached, instead of
  // becoming a "port never opened" three gates downstream.
  ok("sshd_setup.mjs --keys-only exits 0", false,
     `exit ${e.status}: ${String(e.stderr || e.message).trim().split("\n")[0]}`);
}

section("B. every algorithm the client offers has both halves on disk");
for (const [, bits, name] of KEYS) {
  const priv = path.join(dir, name);
  const pub = `${priv}.pub`;
  const haveBoth = existsSync(priv) && existsSync(pub);
  ok(`${name}${bits === null ? "" : ` (${bits})`} generated`, haveBoth,
     haveBoth ? `${statSync(priv).size} B` : "missing");
}

section("C. the generated keys are keys, not empty or truncated files");
{
  const keygen = findKeygen();
  for (const [, , name] of KEYS) {
    const pub = path.join(dir, `${name}.pub`);
    if (!existsSync(pub)) {
      ok(`${name}.pub fingerprints`, false, "file absent");
      continue;
    }
    let fp = "";
    try {
      fp = execFileSync(keygen, ["-l", "-f", pub], { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] }).trim();
    } catch (e) {
      fp = `ssh-keygen -l failed: ${String(e.stderr || e.message).trim().split("\n")[0]}`;
    }
    // A .pub that exists but does not fingerprint is what a truncated write
    // looks like, and sshd would reject it at `sshd -t` -- a different gate, a
    // different day, and a much more expensive diagnosis.
    const bits = /^\d+\s+SHA256:/.test(fp) || /^\d+\s+MD5:/.test(fp);
    ok(`${name}.pub fingerprints`, bits, fp.slice(0, 70));
  }
}

section("D. the comment reaches ssh-keygen as ONE argument");
{
  // `-C 'loop31 test host key'` is a comment with spaces. If the argument array
  // is ever rebuilt as a single string, this is what breaks: ssh-keygen answers
  // `Too many arguments` and, before Loop #72, nobody downstream could see why.
  // The public key carries the comment verbatim, so it is readable evidence
  // rather than a second execution.
  const pub = path.join(dir, "hostkey_ed25519.pub");
  const text = existsSync(pub) ? readFileSync(pub, "utf8").trim() : "";
  const comment = text.split(/\s+/).slice(2).join(" ");
  ok("the -C comment survives as a single argument",
     comment === "loop31 test host key", comment ? `"${comment}"` : "no .pub to read");
}

try { rmSync(dir, { recursive: true, force: true }); } catch { /* temp dir; not worth failing over */ }

console.log("");
console.log(`loop74: ${checks - failures}/${checks} checks passed`);
if (failures) {
  console.log("");
  for (let i = 0; i < failures; i++) { /* names already printed above, in order */ }
  process.exitCode = 1;
} else {
  console.log("ALL PASS");
}
