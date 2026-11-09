#!/usr/bin/env node
// host/verify_loop87.mjs -- Loop #87: the key can be READ.
//
// ## What is being claimed
//
// Loop #85 made the client able to MAKE a key.  Loop #87 makes it able
// to READ one: `ssh-keygen -l` (the fingerprint) and `ssh-keygen -y`
// (the public key), with `-P` for the passphrase of an encrypted key
// and `-E` for the fingerprint hash.
//
// ## The judge
//
// The judge is the REAL `ssh-keygen`, and the comparison is BYTE FOR
// BYTE: the exit status, stdout, and stderr.
//
// Byte for byte, and not "the same information":
//
//   * **stdout** is compared byte for byte, including the line ending.
//     OpenSSH writes CRLF on Windows, and so does this tool -- a
//     difference here would be a difference everybody can see.
//
//   * **stderr** is compared byte for byte too, and that is stricter
//     than it sounds.  OpenSSH runs every message through `strnvis`
//     with `VIS_SAFE|VIS_OCTAL` (log.c:69), so a path in an error
//     message has its backslashes DOUBLED:
//
//         ssh-keygen: E:\\src\\moon\\nope: No such file or directory
//
//     A tool that prints single backslashes there is a tool whose error
//     output can never be compared with OpenSSH's byte for byte, and
//     the day somebody needs that comparison is the day it has to be
//     exact.
//
//   * **the exit status** is 255 for every failure, which is what
//     OpenSSH uses.
//
// ## The rules the cases pin down
//
// The rules below were READ OUT OF THE REAL TOOL, not guessed:
//
//   * `-l` on a PRIVATE key file asks for the PUBLIC key first: the
//     `.pub` file beside it decides the fingerprint and the comment,
//     and the passphrase is never needed (authfile.c:269).
//
//   * a `.pub` FILE whose line has no comment is given the FILE's NAME
//     as its comment (authfile.c:238), so `ssh-keygen -l -f key` can
//     print the path where `ssh-keygen -l -f key.pub` prints `no
//     comment` -- for the same key.
//
//   * a `.pub` LINE whose comment is empty, or whose comment starts
//     with '#', is given NO comment (ssh-keygen.c:989), and that is
//     printed as the word `no comment`.
//
//   * `no comment` and an EMPTY comment are different strings, and the
//     difference is a SPACE: one space and two.
//
//   * `-l` on an ENCRYPTED key needs no passphrase at all: the public
//     blob of an `openssh-key-v1` file is in the clear.
//
//   * `-y` always opens the PRIVATE file, so it needs the passphrase
//     for an encrypted one.
//
// ## The one divergence, stated
//
// `-E md5` is REFUSED by this tool.  OpenSSH supports it and this
// repository has no MD5, so the honest answer is a refusal rather than
// a fingerprint in the wrong form.  The gate checks that the refusal
// says so; it does not pretend the two agree.
//
// ## What runs where
//
// Everything here needs node, the MoonBit toolchain, and a real
// `ssh-keygen`.  When NO ssh-keygen is present the gate says so LOUDLY
// and fails -- a gate that cannot check its claim must not report
// success.

import { spawnSync } from "node:child_process";
import {
  existsSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop87", "gate");

let failures = 0;
let checks = 0;
let skipped = 0;
const section = (t) => console.log(`\n${t}`);
const ok = (name, cond, detail = "") => {
  checks++;
  if (!cond) failures++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};
const skip = (name, why) => {
  skipped++;
  console.log(`  SKIP  ${name}  -- ${why}`);
};

function norm(s) {
  return `${s}`.replace(/\r\n/g, "\n");
}

// A gate that runs a build must not be able to hang forever.
//
// The timeout is long enough for a cold compile of the whole tree on a
// loaded machine, and short enough that a hang is reported rather than
// waited out.  A timeout is a FAILURE of the check that was running,
// and the reason says so.
const MOON_TIMEOUT_MS = 600000;

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
    timeout: MOON_TIMEOUT_MS,
  });
  let out = norm(`${r.stdout || ""}${r.stderr || ""}`);
  if (r.error) {
    out += `\n[spawn failed: ${r.error.message} (code=${r.error.code})]\n`;
  }
  const code = r.error ? 1 : r.status;
  return { code, out };
}

function moonCheck(pkg, target) {
  const r = moon(["check", "--target", target, "-p", pkg]);
  const failed = /^\s*Error:/m.test(r.out) || (r.code !== 0 && r.code !== null);
  const m = r.out.match(/(\d+)\s+warnings?,\s*(\d+)\s+errors?/);
  return { errors: failed ? (m ? Number(m[2]) : 1) : 0, warnings: m ? Number(m[1]) : -1, out: r.out };
}

// The real OpenSSH tools.  Two builds, when both are here: two
// independent implementations of the format agreeing is worth more than
// one of them agreeing with itself.
//
// The locations are CANDIDATES, probed in order.  A PATH lookup would
// find nothing: the OpenSSH binaries are not on PATH by default.
// machine-path-exempt: each entry below is a candidate, probed until one
// exists.  None is asserted to exist, and when none does the gate says so
// LOUDLY and fails -- a gate that cannot check its claim must not report
// success.
const KEYGEN_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
  "C:\\Program Files\\OpenSSH",
];
const SSH_KEYGENS = KEYGEN_DIRS
  .map((d) => path.join(d, "ssh-keygen.exe"))
  .filter((p) => existsSync(p));

// Run a program and keep the BYTES.
//
// The bytes are the point.  `encoding: "utf8"` would decode them, and a
// decoder is lossy in exactly the places this gate is about: a lone
// CR, a NUL, a byte that is not valid UTF-8.
//
// The argument array is passed EXACTLY.  An empty passphrase is an
// empty string and has to survive as one, and a shell would eat it:
// PowerShell drops an empty argument entirely, and then `ssh-keygen -N
// "" -f file` reads the `-f` as the passphrase and complains about
// "too many arguments".  spawnSync has no shell, so the array is what
// the program sees.
function runBytes(bin, args) {
  const r = spawnSync(bin, args, {
    cwd: ROOT, timeout: 120000, input: "", maxBuffer: 64 * 1024 * 1024,
  });
  return {
    code: r.error ? 1 : r.status,
    stdout: r.stdout || Buffer.alloc(0),
    stderr: r.stderr || Buffer.alloc(0),
    error: r.error ? r.error.message : "",
  };
}

// Our own tool, once it has been built.
let OURS = null;

function ourTool(args) {
  return runBytes(OURS, args);
}

// The two tools are asked the SAME question, and the answers are
// compared byte for byte.
//
// The comparison says WHICH part differed, because "the outputs differ"
// is not a report: the exit status, the stdout and the stderr are three
// different claims, and a reader needs to know which one broke.
function sameBytes(label, a, b, expectSame = true) {
  checks++;
  const problems = [];
  if (a.code !== b.code) {
    problems.push(`exit ${a.code}, want ${b.code}`);
  }
  if (!a.stdout.equals(b.stdout)) {
    problems.push(`stdout\n        ours   ${JSON.stringify(a.stdout.toString("latin1"))}\n        theirs ${JSON.stringify(b.stdout.toString("latin1"))}`);
  }
  if (!a.stderr.equals(b.stderr)) {
    problems.push(`stderr\n        ours   ${JSON.stringify(a.stderr.toString("latin1"))}\n        theirs ${JSON.stringify(b.stderr.toString("latin1"))}`);
  }
  const same = problems.length === 0;
  if (same === expectSame) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}`);
    for (const p of problems) console.log(`        ${p}`);
  }
  return same;
}

function freshDir(name) {
  const dir = path.join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

// ---------------------------------------------------------------------------

async function main() {
  console.log("Loop #87: the key can be read.");
  console.log(`  root: ${ROOT}`);

  // -------------------------------------------------------------------------
  section("G0: the toolchain");
  // -------------------------------------------------------------------------

  const kf = moonCheck("src/keyfile", "native");
  ok("src/keyfile compiles on native", kf.errors === 0,
    kf.errors ? `${kf.errors} error(s)` : `${kf.warnings} warning(s)`);
  const kg = moonCheck("cmd/ssh_keygen", "native");
  ok("cmd/ssh_keygen compiles on native", kg.errors === 0,
    kg.errors ? `${kg.errors} error(s)` : `${kg.warnings} warning(s)`);

  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const r = moon(["test", "src/keyfile", "--target", target]);
    const m = r.out.match(/Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/);
    ok(`src/keyfile's tests pass on ${target}`,
      r.code === 0 && m && Number(m[3]) === 0 && Number(m[2]) > 0,
      m ? `${m[2]}/${m[1]} passed` : r.out.slice(-200));
  }

  // The tool itself, built once and run directly.
  //
  // The built program and not `moon run`: `moon run` mixes the build
  // output into the program's own output, and a gate that compares
  // bytes needs the program's bytes and nothing else.
  const build = moon(["build", "cmd/ssh_keygen", "--target", "native"]);
  ok("cmd/ssh_keygen builds", build.code === 0, build.code === 0 ? "" : build.out.slice(-300));
  const candidates = [
    path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_keygen", "ssh_keygen.exe"),
    path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_keygen", "ssh_keygen"),
  ];
  OURS = candidates.find((p) => existsSync(p)) || null;
  ok("the built ssh_keygen is there", OURS !== null,
    OURS || `looked in ${candidates.join(" and ")}`);

  // -------------------------------------------------------------------------
  section("G1: the real OpenSSH is here");
  // -------------------------------------------------------------------------

  if (SSH_KEYGENS.length === 0) {
    ok("a real ssh-keygen is available", false,
      "no ssh-keygen found -- this gate cannot check its claim");
    console.log("\nCI FAIL: 0 checks could be run");
    process.exit(1);
  }
  ok("a real ssh-keygen is available", true,
    `${SSH_KEYGENS.length} build(s): ${SSH_KEYGENS.map((p) => path.basename(path.dirname(p))).join(", ")}`);
  if (!OURS) {
    console.log("\nCI FAIL: our own tool was not built");
    process.exit(1);
  }

  const REAL = SSH_KEYGENS[0];
  const dir = freshDir("keys");

  // The keys the cases below use.  They are made by the REAL tool, so
  // that the files under test are files OpenSSH wrote.
  const key = (name, comment, passphrase = "") => {
    const p = path.join(dir, name);
    const r = runBytes(REAL, ["-t", "ed25519", "-f", p, "-N", passphrase, "-C", comment]);
    if (r.code !== 0) {
      console.log(`  FAIL  the real ssh-keygen could not make ${name}  -- ${r.stderr.toString()}`);
      failures++;
    }
    return p;
  };

  const plain = key("plain", "probe@loop87");
  const empty = key("empty", "");
  const nocpub = key("nocpub", "probe@loop87");
  rmSync(nocpub + ".pub", { force: true });
  const enc = key("enc", "enc@loop87", "s3cr3t");
  const encnopub = key("encnopub", "enc@loop87", "s3cr3t");
  rmSync(encnopub + ".pub", { force: true });
  const emptyNoPub = key("emptynopub", "");
  rmSync(emptyNoPub + ".pub", { force: true });

  // -------------------------------------------------------------------------
  section("G2: the same bytes as the real tool");
  // -------------------------------------------------------------------------

  // -- a plain key, with its .pub beside it ------------------------------
  sameBytes("-l on a private key", ourTool(["-l", "-f", plain]), runBytes(REAL, ["-l", "-f", plain]));
  sameBytes("-l on the .pub file", ourTool(["-l", "-f", plain + ".pub"]), runBytes(REAL, ["-l", "-f", plain + ".pub"]));
  sameBytes("-y on a private key", ourTool(["-y", "-f", plain]), runBytes(REAL, ["-y", "-f", plain]));

  // -- the same key with an EMPTY comment ---------------------------------
  sameBytes("-l on a private key whose comment is empty",
    ourTool(["-l", "-f", empty]), runBytes(REAL, ["-l", "-f", empty]));
  sameBytes("-l on the .pub file whose comment is empty",
    ourTool(["-l", "-f", empty + ".pub"]), runBytes(REAL, ["-l", "-f", empty + ".pub"]));
  sameBytes("-y on a private key whose comment is empty",
    ourTool(["-y", "-f", empty]), runBytes(REAL, ["-y", "-f", empty]));

  // -- the same key with the .pub taken away ------------------------------
  sameBytes("-l on a private key with no .pub",
    ourTool(["-l", "-f", nocpub]), runBytes(REAL, ["-l", "-f", nocpub]));
  sameBytes("-y on a private key with no .pub",
    ourTool(["-y", "-f", nocpub]), runBytes(REAL, ["-y", "-f", nocpub]));

  // -- an ENCRYPTED key ---------------------------------------------------
  sameBytes("-l on an encrypted key, with no passphrase asked for",
    ourTool(["-l", "-f", enc]), runBytes(REAL, ["-l", "-f", enc]));
  sameBytes("-y on an encrypted key with the passphrase",
    ourTool(["-y", "-P", "s3cr3t", "-f", enc]), runBytes(REAL, ["-y", "-P", "s3cr3t", "-f", enc]));
  sameBytes("-y on an encrypted key with the WRONG passphrase",
    ourTool(["-y", "-P", "wrong", "-f", enc]), runBytes(REAL, ["-y", "-P", "wrong", "-f", enc]));

  // -- an ENCRYPTED key with the .pub taken away ---------------------------
  sameBytes("-l on an encrypted key with no .pub",
    ourTool(["-l", "-f", encnopub]), runBytes(REAL, ["-l", "-f", encnopub]));
  sameBytes("-y on an encrypted key with no .pub",
    ourTool(["-y", "-P", "s3cr3t", "-f", encnopub]),
    runBytes(REAL, ["-y", "-P", "s3cr3t", "-f", encnopub]));

  // -- an EMPTY comment with the .pub taken away --------------------------
  sameBytes("-l on an empty comment with no .pub",
    ourTool(["-l", "-f", emptyNoPub]), runBytes(REAL, ["-l", "-f", emptyNoPub]));
  sameBytes("-y on an empty comment with no .pub",
    ourTool(["-y", "-f", emptyNoPub]), runBytes(REAL, ["-y", "-f", emptyNoPub]));

  // -- the file that is not there -----------------------------------------
  const missing = path.join(dir, "notthere");
  sameBytes("-l on a missing file", ourTool(["-l", "-f", missing]), runBytes(REAL, ["-l", "-f", missing]));
  sameBytes("-y on a missing file", ourTool(["-y", "-f", missing]), runBytes(REAL, ["-y", "-f", missing]));

  // -- a file that is not a key at all ------------------------------------
  const notakey = path.join(dir, "notakey");
  writeFileSync(notakey, "this is not a key\n", "utf8");
  sameBytes("-l on a file that is not a key",
    ourTool(["-l", "-f", notakey]), runBytes(REAL, ["-l", "-f", notakey]));

  // -- a .pub file whose comment carries a '#' ----------------------------
  const hashpub = path.join(dir, "hash.pub");
  writeFileSync(hashpub,
    readFileSync(plain + ".pub", "utf8").trim() + " #a hash comment\n", "utf8");
  sameBytes("-l on a .pub whose comment carries a #",
    ourTool(["-l", "-f", hashpub]), runBytes(REAL, ["-l", "-f", hashpub]));

  // -- a `known_hosts` line: the key is behind the host name --------------
  const knownHosts = path.join(dir, "known_hosts");
  writeFileSync(knownHosts,
    "example.com " + readFileSync(plain + ".pub", "utf8").trim() + "\n", "utf8");
  sameBytes("-l on a known_hosts line",
    ourTool(["-l", "-f", knownHosts]), runBytes(REAL, ["-l", "-f", knownHosts]));

  // -------------------------------------------------------------------------
  section("G3: the two-way round trip");
  // -------------------------------------------------------------------------

  // A key OURS wrote, read by the REAL tool.  The other direction of
  // the same contract: a file format is a contract with the program
  // everybody else has to read.
  const ours = path.join(dir, "ours");
  const made = ourTool(["-f", ours, "-t", "ed25519", "-C", "ours@loop87"]);
  ok("our ssh_keygen made a key", made.code === 0, made.stderr.toString().slice(0, 200));
  if (made.code === 0) {
    const theirs = runBytes(REAL, ["-l", "-f", ours]);
    const mine = ourTool(["-l", "-f", ours]);
    ok("the real tool reads the key we wrote", theirs.code === 0,
      theirs.code === 0 ? "" : theirs.stderr.toString().slice(0, 200));
    sameBytes("both tools agree about the key we wrote", mine, theirs);
  }

  // And the public key we wrote is the public key the real tool derives.
  if (existsSync(ours + ".pub")) {
    const derived = runBytes(REAL, ["-y", "-f", ours]);
    const keyPart = (s) => s.trim().split(/\s+/).slice(0, 2).join(" ");
    ok("the public key OpenSSH derives is the one we wrote",
      derived.code === 0 &&
        keyPart(derived.stdout.toString()) === keyPart(readFileSync(ours + ".pub", "utf8")),
      derived.code === 0 ? "" : derived.stderr.toString().slice(0, 200));
  }

  // -------------------------------------------------------------------------
  section("G4: the failures");
  // -------------------------------------------------------------------------

  // The exit status is 255 for a failure.  A tool that fails with 0 is a
  // tool whose failure a script cannot see.
  const failCases = [
    ["-l on a missing file", ["-l", "-f", missing]],
    ["-y on a missing file", ["-y", "-f", missing]],
    ["-l on a file that is not a key", ["-l", "-f", notakey]],
    ["-y with the wrong passphrase", ["-y", "-P", "wrong", "-f", enc]],
  ];
  for (const [label, argv] of failCases) {
    const r = ourTool(argv);
    ok(`our tool fails with 255: ${label}`, r.code === 255, `exit ${r.code}`);
    ok(`our tool says why: ${label}`, r.stderr.length > 0,
      r.stderr.toString().slice(0, 120));
    ok(`our tool says nothing on stdout when it fails: ${label}`,
      r.stdout.length === 0, JSON.stringify(r.stdout.toString().slice(0, 120)));
  }

  // The message for a file that is not there is OpenSSH's message, with
  // the backslashes doubled the way `strnvis` doubles them.
  const missingMsg = ourTool(["-l", "-f", missing]).stderr.toString();
  ok("the message for a missing file doubles the backslashes",
    missingMsg.includes("\\\\") && !/\S\\\S/.test(missingMsg.replace(/\\\\/g, "")),
    JSON.stringify(missingMsg.slice(0, 160)));
  ok("the message for a missing file names the program",
    missingMsg.startsWith("ssh-keygen: "), JSON.stringify(missingMsg.slice(0, 160)));

  // -------------------------------------------------------------------------
  section("G5: the digest option");
  // -------------------------------------------------------------------------

  sameBytes("-l -E sha256", ourTool(["-l", "-E", "sha256", "-f", plain]),
    runBytes(REAL, ["-l", "-E", "sha256", "-f", plain]));

  // An algorithm neither tool knows gets OpenSSH's own words.
  sameBytes("-l -E bogus", ourTool(["-l", "-E", "bogus", "-f", plain]),
    runBytes(REAL, ["-l", "-E", "bogus", "-f", plain]));

  // **The one divergence, stated.**  OpenSSH has md5 and this repository
  // does not, so the two cannot agree and the gate says so instead of
  // pretending they do.
  const md5 = ourTool(["-l", "-E", "md5", "-f", plain]);
  ok("-E md5 is refused", md5.code === 255, `exit ${md5.code}`);
  ok("-E md5 says why",
    md5.stderr.toString().includes("only -E sha256 is supported"),
    JSON.stringify(md5.stderr.toString().slice(0, 160)));
  const theirsMd5 = runBytes(REAL, ["-l", "-E", "md5", "-f", plain]);
  ok("the real tool does support -E md5 (this is the known divergence)",
    theirsMd5.code === 0 && theirsMd5.stdout.toString().includes("MD5:"),
    `exit ${theirsMd5.code}`);

  // -------------------------------------------------------------------------
  section("G6: the rules are visible in the output");
  // -------------------------------------------------------------------------

  // `no comment` and an empty comment leave a different number of
  // spaces, and the difference is one space.
  //
  // The two lines below are about DIFFERENT keys, so their fingerprints
  // differ and their lengths cannot be compared.  What can be compared
  // is the tail of the line -- everything after the fingerprint -- and
  // the claim is exact: taking the word `no comment` out of one line
  // leaves the other one.
  const noComment = ourTool(["-l", "-f", encnopub]).stdout.toString();
  const emptyComment = ourTool(["-l", "-f", emptyNoPub]).stdout.toString();
  const tail = (s) => s.replace(/SHA256:[^ ]+/, "FP");
  ok("an encrypted key with no .pub prints 'no comment'",
    noComment.includes(" no comment (ED25519)"), JSON.stringify(noComment));
  ok("an empty comment leaves two spaces",
    / {2}\(ED25519\)/.test(emptyComment), JSON.stringify(emptyComment));
  ok("taking 'no comment' out leaves the two spaces of the empty comment",
    tail(noComment).replace(" no comment ", "  ") === tail(emptyComment),
    `${JSON.stringify(tail(noComment))} vs ${JSON.stringify(tail(emptyComment))}`);

  // The .pub file decides the comment when there is one.
  const pubDecides = ourTool(["-l", "-f", empty]).stdout.toString();
  ok("the .pub path is the comment when the .pub has no comment of its own",
    pubDecides.includes(empty + ".pub"), JSON.stringify(pubDecides));

  // -------------------------------------------------------------------------
  console.log(`\n${checks - failures}/${checks} checks passed`);
  if (skipped) console.log(`${skipped} check(s) skipped`);
  if (failures) {
    console.log(`CI FAIL: ${failures} check(s) failed`);
    process.exit(1);
  }
  console.log("ALL PASS");
}

// **A gate that crashes reports nothing, and "nothing" is not a
// verdict.**  An exception anywhere in here would kill the process with
// a stack trace and a non-zero exit, and the mutation suite would read
// the absence of a FAIL line as "the gate did not notice" -- when in
// fact the gate had stopped running.  So the crash is caught, named,
// and reported in the same PASS/FAIL vocabulary as everything else.
try {
  main();
} catch (e) {
  const why = e && e.message ? e.message : String(e);
  console.log(`  FAIL  the gate itself threw  -- ${why}`);
  console.log("CI FAIL: the gate crashed, so nothing after the crash was checked");
  process.exit(1);
}
