#!/usr/bin/env node
// host/verify_loop88.mjs -- Loop #88: the key file can be REWRITTEN.
//
// ## What is being claimed
//
// Loop #85 made the client able to MAKE a key, Loop #86 gave the file
// a passphrase, and Loop #87 made it able to READ one.  Loop #88 does
// the middle of the story: `ssh-keygen -p` (a new passphrase) and
// `ssh-keygen -c` (a new comment) write the private key file again.
//
// ## The judge
//
// The judge is the REAL `ssh-keygen`, and the comparison is BYTE FOR
// BYTE: the exit status, stdout, and stderr.
//
// **Both tools are pointed at the SAME FILE, one after the other, and
// the file is restored between the two runs.**  That matters for a
// rewrite in a way it did not for a read: a rewrite CHANGES the file,
// so the two tools cannot be pointed at two different copies without
// changing what is being compared -- the path is IN the message, and
// two files with two names have two messages.
//
// ## The rules the cases pin down
//
// The rules below were READ OUT OF THE REAL TOOL, not guessed.  The
// scripts that read them out are `.loop88/probe_truth.py`,
// `.loop88/probe_more.py` and `.loop88/probe_three.py`.
//
//   * `-p` prints `Key has comment '<comment>'` BEFORE it writes
//     anything, and `Your identification has been saved with the new
//     passphrase.` after.
//
//   * `-c` prints `Old comment: <comment>`, and then one of
//     `Comment '<new>' applied`, `Comment removed` (the new comment is
//     empty) or `No change to comment` -- and in that last case
//     NOTHING is written.
//
//   * an EMPTY comment still prints: `Key has comment ''` and
//     `Old comment: ` with a space and nothing after it.
//
//   * `-p` does NOT touch the `.pub` file.  `-c` rewrites it with the
//     new comment, and writes it even when it was not there before.
//
//   * changing the comment does NOT change the passphrase: an
//     encrypted key is still encrypted with the same passphrase
//     afterwards.
//
//   * an empty new passphrase takes the passphrase OFF the key: the
//     file comes out unencrypted.
//
//   * the EMPTY passphrase is tried FIRST, so `-p -P whatever` on a
//     key with no passphrase works and the `-P` is never looked at.
//
//   * the two failure messages are DIFFERENT messages: `-p` says
//     `Failed to load key <path>: <why>` and `-c` says `Cannot load
//     private key "<path>": <why>`.
//
// ## The divergences, stated rather than hidden
//
//   * `-p` and `-c` together: OpenSSH prints its whole usage text and
//     exits with 1.  This tool prints the sentence that carries the
//     meaning -- `Can only have one of -p and -c.` -- and exits with 1,
//     and does NOT print OpenSSH's usage: that text is OpenSSH's, it
//     changes from one release to the next, and a tool that prints
//     another tool's usage text is a tool that lies about what it can
//     do.
//
//   * nothing here asks a question.  OpenSSH asks for the old
//     passphrase, for the new one and for the new comment on the
//     TERMINAL, and with no terminal it does not fail -- it BLOCKS.
//     Measured: `ssh-keygen -p -P "" -f key` with an empty stdin did
//     not return in 120 seconds.  This tool refuses and says which
//     option is missing.
//
//   * this tool does not check the Windows ACL of a file it reads, so
//     on a file with wide permissions it says what is wrong with the
//     FILE rather than what is wrong with its permissions.
//
//   * this repository has ed25519 only, so a rewrite of an RSA key is
//     refused rather than done.
//
//   * a rewritten file is made private again.  OpenSSH writes with
//     `umask(077)`, which only affects a file that is CREATED, so a
//     file that was already there keeps the mode it had.  This
//     repository is stricter on purpose.
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
const WORK = path.join(ROOT, ".loop88", "gate");

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
// PowerShell drops an empty argument entirely.  spawnSync has no
// shell, so the array is what the program sees.
//
// **The timeout is short and the kill is hard.**  The real `ssh-keygen`
// asks for the passphrase of an encrypted key ON THE TERMINAL, and a
// gate that ran it against a file that was still encrypted -- which is
// what happens when the code under test is broken -- would wait for a
// keypress that never comes.  Every call below therefore gives the
// passphrase, so that the tool is never in a position to ask, and the
// timeout is the backstop for the case nobody thought of.
function runBytes(bin, args) {
  const r = spawnSync(bin, args, {
    cwd: ROOT, timeout: 60000, input: "", maxBuffer: 64 * 1024 * 1024,
    killSignal: "SIGKILL",
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
function sameBytes(label, a, b) {
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
  if (problems.length === 0) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}`);
    for (const p of problems) console.log(`        ${p}`);
  }
  return problems.length === 0;
}

function freshDir(name) {
  const dir = path.join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

// The key the rewrite cases use.
//
// The pristine copy is kept BESIDE the file, because the two tools
// have to be pointed at the same path -- the path is in the messages
// -- and a rewrite changes the file.  So: make the file, keep a copy,
// let the real tool rewrite it, put the copy back, and let our tool
// rewrite it.
function makeKey(dir, name, comment, passphrase = "") {
  const p = path.join(dir, name);
  const made = runBytes(SSH_KEYGENS[0],
    ["-t", "ed25519", "-f", p, "-N", passphrase, "-C", comment]);
  if (made.code !== 0) {
    console.log(`  FAIL  the real ssh-keygen could not make ${name}  -- ${made.stderr.toString()}`);
    failures++;
  }
  return p;
}

function snapshot(p) {
  const out = {};
  for (const f of [p, p + ".pub"]) {
    out[f] = existsSync(f) ? readFileSync(f) : null;
  }
  return out;
}

function restore(p, snap) {
  for (const [f, bytes] of Object.entries(snap)) {
    if (bytes === null) {
      rmSync(f, { force: true });
    } else {
      writeFileSync(f, bytes);
    }
  }
}

// The bytes of a private key file, with the markers taken off.
//
// This is the only way to see some of the things a rewrite decides.  The
// stdout of a rewrite says that a passphrase was saved; it does not say
// WHICH salt the file now carries, and it does not say how many KDF
// rounds the file asks for.  Those are in the file, and they are
// observable there.
function blobOf(fileBytes) {
  const text = fileBytes.toString("latin1");
  const begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
  const end = "-----END OPENSSH PRIVATE KEY-----";
  const b = text.indexOf(begin);
  const e = text.indexOf(end);
  if (b < 0 || e < 0) return null;
  return Buffer.from(text.slice(b + begin.length, e).replace(/\s+/g, ""), "base64");
}

// The salt of an enciphered file: sixteen bytes at offset 47.
//
// The offset is fixed because everything before it has a fixed size:
// the magic, the cipher name, the KDF name, the length of the KDF
// options, and the length of the salt.  The layout is written out in
// `src/keyfile/moon.pkg`.
const saltOf = (blob) => (blob ? blob.slice(47, 63) : null);

// The KDF round count of an enciphered file: a big-endian word at 63.
const roundsOf = (blob) => (blob ? blob.readUInt32BE(63) : null);

// The cipher name of a file: the string at 15.
function cipherOf(blob) {
  if (!blob) return "";
  const len = blob.readUInt32BE(15);
  return blob.slice(19, 19 + len).toString("latin1");
}

// The check word of an UNENCRYPTED file: the first four bytes of the
// private block, which starts at 98.  (In an enciphered file the block
// is enciphered, so the check word is not visible there.)
const checkOf = (blob) => (blob ? blob.slice(98, 102) : null);

// The heart of the gate: both tools rewrite the SAME file, and the
// bytes they print are compared.
//
// `maker` is what puts the file there.  It is a function and not a
// description, because one of the cases is about a file that is NOT
// there -- and a key made "for" that case would be a key that IS
// there.
function compareRewrite(label, dir, name, maker, args) {
  const p = path.join(dir, name);
  maker(p);
  const pristine = snapshot(p);
  const realArgs = args.map((a) => (a === "{f}" ? p : a));
  const theirs = runBytes(SSH_KEYGENS[0], realArgs);
  restore(p, pristine);
  const ours = ourTool(realArgs);
  sameBytes(label, ours, theirs);
  return p;
}

// A key made by the REAL tool, so that the files under test are files
// OpenSSH wrote.
const keyMaker = (comment, passphrase = "") => (p) => {
  const made = runBytes(SSH_KEYGENS[0],
    ["-t", "ed25519", "-f", p, "-N", passphrase, "-C", comment]);
  if (made.code !== 0) {
    console.log(`  FAIL  the real ssh-keygen could not make ${p}  -- ${made.stderr.toString()}`);
    failures++;
  }
};

// No file at all.
const noMaker = () => () => {};

// ---------------------------------------------------------------------------

async function main() {
  console.log("Loop #88: the key file can be rewritten.");
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

  // -------------------------------------------------------------------------
  section("G2: the same bytes as the real tool");
  // -------------------------------------------------------------------------

  compareRewrite("-p on an unencrypted key", dir, "a", keyMaker("probe@loop88"),
    ["-p", "-P", "", "-N", "newpass", "-f", "{f}"]);
  compareRewrite("-p with the right old passphrase", dir, "b", keyMaker("enc@loop88", "oldpass"),
    ["-p", "-P", "oldpass", "-N", "newpass", "-f", "{f}"]);
  compareRewrite("-p with the wrong old passphrase", dir, "c", keyMaker("enc@loop88", "oldpass"),
    ["-p", "-P", "nope", "-N", "newpass", "-f", "{f}"]);
  compareRewrite("-p on a key with no comment", dir, "d", keyMaker(""),
    ["-p", "-P", "", "-N", "newpass", "-f", "{f}"]);
  compareRewrite("-p on a missing file", dir, "e", noMaker(),
    ["-p", "-P", "", "-N", "newpass", "-f", "{f}"]);
  compareRewrite("-c with a new comment", dir, "f", keyMaker("old@loop88"),
    ["-c", "-C", "new@loop88", "-f", "{f}"]);
  compareRewrite("-c with the same comment", dir, "g", keyMaker("same@loop88"),
    ["-c", "-C", "same@loop88", "-f", "{f}"]);
  compareRewrite("-c with an empty comment", dir, "h", keyMaker("old@loop88"),
    ["-c", "-C", "", "-f", "{f}"]);
  compareRewrite("-c on an encrypted key with -P", dir, "i", keyMaker("enc@loop88", "oldpass"),
    ["-c", "-C", "new@loop88", "-P", "oldpass", "-f", "{f}"]);
  compareRewrite("-c on a key with no comment", dir, "j", keyMaker(""),
    ["-c", "-C", "new@loop88", "-f", "{f}"]);
  compareRewrite("-c with the wrong passphrase", dir, "k", keyMaker("enc@loop88", "oldpass"),
    ["-c", "-C", "new@loop88", "-P", "nope", "-f", "{f}"]);
  compareRewrite("-c on a missing file", dir, "l", noMaker(),
    ["-c", "-C", "new@loop88", "-f", "{f}"]);
  compareRewrite("-c with an empty comment on a key with no comment", dir, "m", keyMaker(""),
    ["-c", "-C", "", "-f", "{f}"]);
  compareRewrite("-p with an empty new passphrase", dir, "n", keyMaker("old@loop88", "oldpass"),
    ["-p", "-P", "oldpass", "-N", "", "-f", "{f}"]);
  compareRewrite("-p with a passphrase on an unencrypted key", dir, "o", keyMaker("old@loop88"),
    ["-p", "-P", "whatever", "-N", "newpass", "-f", "{f}"]);
  compareRewrite("-c with -N on an unencrypted key", dir, "p", keyMaker("old@loop88"),
    ["-c", "-C", "new@loop88", "-N", "whatever", "-f", "{f}"]);

  // A file that is not a key at all.
  //
  // The file is made by the REAL tool first -- so that it has the
  // permissions the real tool insists on -- and then its CONTENTS are
  // overwritten in place, which keeps them.  A file written by this
  // gate would be refused for its permissions, and the message would
  // be about the permissions and not about the contents.
  {
    const p = makeKey(dir, "q", "old@loop88");
    writeFileSync(p, "this is not a key\n", "utf8");
    const pristine = snapshot(p);
    const realArgs = ["-p", "-P", "", "-N", "newpass", "-f", p];
    const theirs = runBytes(REAL, realArgs);
    restore(p, pristine);
    sameBytes("-p on a file that is not a key", ourTool(realArgs), theirs);
    const realArgs2 = ["-c", "-C", "new@loop88", "-f", p];
    const theirs2 = runBytes(REAL, realArgs2);
    restore(p, pristine);
    sameBytes("-c on a file that is not a key", ourTool(realArgs2), theirs2);
  }

  // -------------------------------------------------------------------------
  section("G3: the two-way round trip");
  // -------------------------------------------------------------------------

  // A key OURS rewrote, read by the REAL tool.  The other direction of
  // the same contract: a file format is a contract with the program
  // everybody else has to read.
  {
    const p = makeKey(dir, "r", "old@loop88");
    const ours = ourTool(["-p", "-P", "", "-N", "newpass", "-f", p]);
    ok("our ssh_keygen changed the passphrase", ours.code === 0,
      ours.stderr.toString().slice(0, 200));
    const theirs = runBytes(REAL, ["-y", "-P", "newpass", "-f", p]);
    ok("the real tool opens the key we re-enciphered", theirs.code === 0,
      theirs.code === 0 ? "" : theirs.stderr.toString().slice(0, 200));
  }

  {
    const p = makeKey(dir, "s", "old@loop88", "oldpass");
    const ours = ourTool(["-p", "-P", "oldpass", "-N", "", "-f", p]);
    ok("our ssh_keygen took the passphrase off", ours.code === 0,
      ours.stderr.toString().slice(0, 200));
    // **The passphrase is given, and it is the empty one.**  The real
    // tool asks for the passphrase of an ENCRYPTED key ON THE
    // TERMINAL, and a gate that runs it against a file that is still
    // encrypted -- which is what happens when the code under test is
    // broken -- would sit there waiting for a keypress that never
    // comes.  With `-P ""` the tool is told the passphrase, so an
    // encrypted file is refused with a sentence instead of a question.
    const theirs = runBytes(REAL, ["-y", "-P", "", "-f", p]);
    ok("the real tool opens the key we de-enciphered", theirs.code === 0,
      theirs.code === 0 ? "" : theirs.stderr.toString().slice(0, 200));
  }

  {
    const p = makeKey(dir, "t", "old@loop88");
    const ours = ourTool(["-c", "-C", "new@loop88", "-f", p]);
    ok("our ssh_keygen changed the comment", ours.code === 0,
      ours.stderr.toString().slice(0, 200));
    // `-y` and not `-l`: `-l` reads the `.pub` file, and the `.pub` file
    // is written by a DIFFERENT line of the driver than the private key
    // is.  A `-c` that changed only the `.pub` file would look right
    // under `-l` and be wrong.
    const theirs = runBytes(REAL, ["-y", "-f", p]);
    ok("the real tool reads the comment we changed",
      theirs.code === 0 && theirs.stdout.toString().includes("new@loop88"),
      theirs.code === 0 ? theirs.stdout.toString().slice(0, 120) : theirs.stderr.toString().slice(0, 200));
  }

  // And the other direction: a key the REAL tool rewrote, read by ours.
  {
    const p = makeKey(dir, "u", "old@loop88");
    const theirs = runBytes(REAL, ["-c", "-C", "new@loop88", "-f", p]);
    ok("the real tool changed the comment", theirs.code === 0,
      theirs.stderr.toString().slice(0, 200));
    const ours = ourTool(["-l", "-f", p]);
    ok("we read the comment the real tool changed",
      ours.code === 0 && ours.stdout.toString().includes("new@loop88"),
      ours.code === 0 ? ours.stdout.toString().slice(0, 120) : ours.stderr.toString().slice(0, 200));
  }

  {
    const p = makeKey(dir, "v", "old@loop88", "oldpass");
    const theirs = runBytes(REAL, ["-p", "-P", "oldpass", "-N", "newpass", "-f", p]);
    ok("the real tool changed the passphrase", theirs.code === 0,
      theirs.stderr.toString().slice(0, 200));
    const ours = ourTool(["-y", "-P", "newpass", "-f", p]);
    ok("we read the key the real tool re-enciphered", ours.code === 0,
      ours.code === 0 ? "" : ours.stderr.toString().slice(0, 200));
  }

  // -------------------------------------------------------------------------
  section("G4: the failures");
  // -------------------------------------------------------------------------

  // The exit status is 255 for a failure.  A tool that fails with 0 is
  // a tool whose failure a script cannot see.
  const enc = makeKey(dir, "w", "enc@loop88", "oldpass");
  const missing = path.join(dir, "notthere");
  const failCases = [
    ["-p with the wrong old passphrase", ["-p", "-P", "nope", "-N", "newpass", "-f", enc]],
    ["-p on a missing file", ["-p", "-P", "", "-N", "newpass", "-f", missing]],
    ["-c with the wrong passphrase", ["-c", "-C", "new@loop88", "-P", "nope", "-f", enc]],
    ["-c on a missing file", ["-c", "-C", "new@loop88", "-f", missing]],
  ];
  for (const [label, argv] of failCases) {
    const r = ourTool(argv);
    ok(`our tool fails with 255: ${label}`, r.code === 255, `exit ${r.code}`);
    ok(`our tool says why: ${label}`, r.stderr.length > 0,
      r.stderr.toString().slice(0, 120));
    ok(`our tool says nothing on stdout when it fails: ${label}`,
      r.stdout.length === 0, JSON.stringify(r.stdout.toString().slice(0, 120)));
  }

  // **The two failure messages are different messages**, and the
  // difference is in OpenSSH's source: `Failed to load key %s` for `-p`
  // and `Cannot load private key "%s"` for `-c`.
  const pMsg = ourTool(["-p", "-P", "nope", "-N", "newpass", "-f", enc]).stderr.toString();
  const cMsg = ourTool(["-c", "-C", "new@loop88", "-P", "nope", "-f", enc]).stderr.toString();
  ok("the message for -p says 'Failed to load key'",
    pMsg.startsWith("Failed to load key "), JSON.stringify(pMsg.slice(0, 160)));
  ok("the message for -c says 'Cannot load private key'",
    cMsg.startsWith("Cannot load private key \""), JSON.stringify(cMsg.slice(0, 160)));
  ok("the message for -p has no quotes around the path",
    !pMsg.includes("\""), JSON.stringify(pMsg.slice(0, 160)));
  ok("the message for -c has quotes around the path",
    cMsg.includes("\": "), JSON.stringify(cMsg.slice(0, 160)));

  // The path in a message is ESCAPED, the way OpenSSH escapes it:
  // `strnvis` with VIS_SAFE|VIS_OCTAL doubles the backslashes.
  ok("the message for a missing file doubles the backslashes",
    missingMsg().includes("\\\\") && !/\S\\\S/.test(missingMsg().replace(/\\\\/g, "")),
    JSON.stringify(missingMsg().slice(0, 160)));
  ok("the message for a missing file names no program",
    !missingMsg().startsWith("ssh-keygen: "), JSON.stringify(missingMsg().slice(0, 160)));

  function missingMsg() {
    return ourTool(["-c", "-C", "x", "-f", missing]).stderr.toString();
  }

  // -------------------------------------------------------------------------
  section("G5: the rules are visible in the output");
  // -------------------------------------------------------------------------

  // An EMPTY comment still prints, and it prints differently in the two
  // modes: `Key has comment ''` and `Old comment: ` with a space and
  // nothing after it.
  {
    const p = makeKey(dir, "x", "", "");
    const r = ourTool(["-p", "-P", "", "-N", "newpass", "-f", p]);
    ok("an empty comment prints as `Key has comment ''`",
      r.stdout.toString().includes("Key has comment ''\r\n"),
      JSON.stringify(r.stdout.toString().slice(0, 120)));
  }
  {
    const p = makeKey(dir, "y", "", "");
    const r = ourTool(["-c", "-C", "new@loop88", "-f", p]);
    ok("an empty comment prints as `Old comment: ` with a trailing space",
      r.stdout.toString().includes("Old comment: \r\n"),
      JSON.stringify(r.stdout.toString().slice(0, 120)));
  }

  // "No change to comment" -- and NOTHING is written.
  {
    const p = makeKey(dir, "z", "same@loop88", "");
    const before = snapshot(p);
    const r = ourTool(["-c", "-C", "same@loop88", "-f", p]);
    ok("the same comment says 'No change to comment'",
      r.stdout.toString().includes("No change to comment"),
      JSON.stringify(r.stdout.toString().slice(0, 120)));
    const after = snapshot(p);
    ok("the same comment writes NOTHING",
      before[p] !== null && before[p].equals(after[p]) &&
      before[p + ".pub"].equals(after[p + ".pub"]),
      "the private key file and the .pub file are both unchanged");
  }

  // `-p` does NOT touch the `.pub` file.
  {
    const p = makeKey(dir, "aa", "old@loop88", "");
    const before = snapshot(p);
    const r = ourTool(["-p", "-P", "", "-N", "newpass", "-f", p]);
    ok("-p changes the private key file", r.code === 0,
      r.stderr.toString().slice(0, 200));
    const after = snapshot(p);
    ok("-p does NOT touch the .pub file",
      before[p + ".pub"].equals(after[p + ".pub"]),
      "the .pub file is unchanged");
    ok("-p does change the private key file",
      !before[p].equals(after[p]), "the private key file is different");
  }

  // `-c` DOES rewrite the `.pub` file, with the new comment.
  {
    const p = makeKey(dir, "ab", "old@loop88", "");
    const r = ourTool(["-c", "-C", "new@loop88", "-f", p]);
    ok("-c changes the comment", r.code === 0, r.stderr.toString().slice(0, 200));
    const pub = readFileSync(p + ".pub", "utf8");
    ok("the .pub file carries the new comment",
      pub.includes("new@loop88") && !pub.includes("old@loop88"),
      JSON.stringify(pub.slice(0, 160)));
  }

  // `-c` writes the `.pub` file even when it was not there.
  {
    const p = makeKey(dir, "ac", "old@loop88", "");
    rmSync(p + ".pub", { force: true });
    const r = ourTool(["-c", "-C", "new@loop88", "-f", p]);
    ok("-c writes the .pub file that was not there", r.code === 0,
      r.stderr.toString().slice(0, 200));
    ok("the .pub file is there afterwards", existsSync(p + ".pub"));
  }

  // Changing the comment does NOT change the passphrase.
  {
    const p = makeKey(dir, "ad", "enc@loop88", "oldpass");
    const r = ourTool(["-c", "-C", "new@loop88", "-P", "oldpass", "-f", p]);
    ok("-c on an encrypted key", r.code === 0, r.stderr.toString().slice(0, 200));
    const theirs = runBytes(REAL, ["-y", "-P", "oldpass", "-f", p]);
    ok("the key still opens with the SAME passphrase",
      theirs.code === 0, theirs.code === 0 ? "" : theirs.stderr.toString().slice(0, 200));
  }

  // An empty new passphrase takes the passphrase OFF.
  {
    const p = makeKey(dir, "ae", "old@loop88", "oldpass");
    const r = ourTool(["-p", "-P", "oldpass", "-N", "", "-f", p]);
    ok("-p with an empty new passphrase", r.code === 0,
      r.stderr.toString().slice(0, 200));
    // `-P ""` and not no `-P` at all: the real tool asks for the
    // passphrase of an encrypted key on the terminal, and this call
    // has to be safe when the code under test left the file
    // encrypted.
    const theirs = runBytes(REAL, ["-y", "-P", "", "-f", p]);
    ok("the key opens with NO passphrase now",
      theirs.code === 0, theirs.code === 0 ? "" : theirs.stderr.toString().slice(0, 200));
  }

  // The EMPTY passphrase is tried FIRST: `-p -P whatever` on a key
  // with no passphrase works, and the `-P` is never looked at.
  {
    const p = makeKey(dir, "af", "old@loop88", "");
    const r = ourTool(["-p", "-P", "whatever", "-N", "newpass", "-f", p]);
    ok("-p on an unencrypted key ignores the -P", r.code === 0,
      r.stderr.toString().slice(0, 200));
  }

  // -------------------------------------------------------------------------
  section("G6: what the FILE says, which the output does not");
  // -------------------------------------------------------------------------

  // **The salt of a rewrite is drawn afresh.**  The same salt and the
  // same passphrase derive the same key, so a file that reuses its salt
  // is a file whose old passphrase is still worth something.  OpenSSH
  // draws the salt afresh every time it writes a file
  // (`arc4random_buf(salt, SALT_LEN)`).
  //
  // This is not visible in the output: the stdout of a rewrite says
  // that a passphrase was saved and says nothing about the salt.  Two
  // rewrites of the same key with the same passphrase have to differ.
  {
    const p = makeKey(dir, "ak", "old@loop88", "oldpass");
    const first = ourTool(["-p", "-P", "oldpass", "-N", "newpass", "-f", p]);
    ok("the first rewrite worked", first.code === 0,
      first.stderr.toString().slice(0, 200));
    const salt1 = saltOf(blobOf(readFileSync(p)));
    const snapshot1 = snapshot(p);
    const second = ourTool(["-p", "-P", "newpass", "-N", "newpass", "-f", p]);
    ok("the second rewrite worked", second.code === 0,
      second.stderr.toString().slice(0, 200));
    const salt2 = saltOf(blobOf(readFileSync(p)));
    restore(p, snapshot1);
    ok("two rewrites of the same key have DIFFERENT salts",
      salt1 !== null && salt2 !== null && !salt1.equals(salt2),
      `both rewrites used the salt ${salt1 ? salt1.toString("hex") : "(none)"}`);
  }

  // **The check word of a rewrite is drawn afresh.**  It is the tag
  // that says "this file was deciphered with the passphrase it thinks
  // it was", and OpenSSH draws it afresh too (`check = arc4random()`).
  //
  // The check word is only VISIBLE in an unencrypted file -- in an
  // enciphered one it is inside the enciphered block -- so both of
  // these rewrites keep the file unencrypted.  (`-p -N ""` on a key
  // with no passphrase is a rewrite that changes nothing but the salt
  // and the check word, which is exactly what is wanted here.)
  {
    const p = makeKey(dir, "al", "old@loop88", "");
    const first = ourTool(["-p", "-P", "", "-N", "", "-f", p]);
    ok("the first rewrite worked", first.code === 0,
      first.stderr.toString().slice(0, 200));
    const check1 = checkOf(blobOf(readFileSync(p)));
    const snapshot1 = snapshot(p);
    const second = ourTool(["-p", "-P", "", "-N", "", "-f", p]);
    ok("the second rewrite worked", second.code === 0,
      second.stderr.toString().slice(0, 200));
    const check2 = checkOf(blobOf(readFileSync(p)));
    restore(p, snapshot1);
    ok("two rewrites of the same key have DIFFERENT check words",
      check1 !== null && check2 !== null && !check1.equals(check2),
      `both rewrites used the check word ${check1 ? check1.toString("hex") : "(none)"}`);
  }

  // **The round count of a rewrite is the DEFAULT.**  OpenSSH's
  // `ssh-keygen` has one global `rounds`, which is 0 unless `-a` was
  // given, and `sshkey_private_to_blob2` turns a 0 into
  // `DEFAULT_ROUNDS` (24).  So a rewrite does NOT keep the round count
  // the old file had.
  {
    const p = makeKey(dir, "am", "old@loop88", "oldpass");
    const ours = ourTool(["-p", "-P", "oldpass", "-N", "newpass", "-f", p]);
    ok("the rewrite worked", ours.code === 0, ours.stderr.toString().slice(0, 200));
    const oursRounds = roundsOf(blobOf(readFileSync(p)));
    ok("the round count of our rewritten file is 24", oursRounds === 24,
      `ours ${oursRounds}`);
    // And the real tool agrees.
    const q = makeKey(dir, "an", "old@loop88", "oldpass");
    runBytes(REAL, ["-p", "-P", "oldpass", "-N", "newpass", "-f", q]);
    const theirsRounds = roundsOf(blobOf(readFileSync(q)));
    ok("the round count of the real tool's file is 24 as well",
      theirsRounds === 24, `theirs ${theirsRounds}`);
  }

  // **The comment of a rewritten key is kept.**  A `-p` changes the
  // passphrase and nothing else.
  //
  // **These two checks read the comment with `-y`, and not with `-l`.**
  // That is not a stylistic choice:
  //
  //   * `ssh-keygen -l -f <private key>` loads the **`.pub` FILE**
  //     (`sshkey_try_load_public`, authfile.c:238) and prints ITS
  //     comment.  A `-p` does not touch the `.pub` file, so `-l` would
  //     print the comment of a file that the rewrite never wrote --
  //     and a rewrite that lost the comment would still look right.
  //
  //   * `ssh-keygen -y -f <private key>` opens the **PRIVATE BLOCK** and
  //     prints the comment that is inside it, which is the comment a
  //     rewrite can lose.
  //
  // Measured, not assumed: a key whose `.pub` file was rewritten by hand
  // with a different comment prints THAT comment under `-l` and its own
  // comment under `-y`.
  {
    const p = makeKey(dir, "ao", "keep@loop88", "");
    const ours = ourTool(["-p", "-P", "", "-N", "newpass", "-f", p]);
    ok("the rewrite worked", ours.code === 0, ours.stderr.toString().slice(0, 200));
    const theirs = runBytes(REAL, ["-y", "-P", "newpass", "-f", p]);
    ok("the comment survived the rewrite",
      theirs.code === 0 && theirs.stdout.toString().includes("keep@loop88"),
      theirs.code === 0 ? theirs.stdout.toString().slice(0, 120) : theirs.stderr.toString().slice(0, 200));
  }
  {
    const p = makeKey(dir, "ap", "keep@loop88", "oldpass");
    const ours = ourTool(["-p", "-P", "oldpass", "-N", "newpass", "-f", p]);
    ok("the rewrite worked", ours.code === 0, ours.stderr.toString().slice(0, 200));
    const theirs = runBytes(REAL, ["-y", "-P", "newpass", "-f", p]);
    ok("the comment survived an enciphered rewrite",
      theirs.code === 0 && theirs.stdout.toString().includes("keep@loop88"),
      theirs.code === 0 ? theirs.stdout.toString().slice(0, 120) : theirs.stderr.toString().slice(0, 200));
  }

  // **The comment of an UNENCRYPTED rewrite is kept.**  The
  // unencrypted branch of the writer is a DIFFERENT branch from the
  // enciphered one, and a comment dropped in one of them is a key with
  // no comment -- and the two branches are exercised by different
  // cases, so one check for each.
  //
  // `-p -N ""` on an ENCRYPTED key is what takes the passphrase off,
  // and the file it writes goes through the unencrypted branch.
  {
    const p = makeKey(dir, "as", "keep@loop88", "oldpass");
    const ours = ourTool(["-p", "-P", "oldpass", "-N", "", "-f", p]);
    ok("the rewrite worked", ours.code === 0, ours.stderr.toString().slice(0, 200));
    const read = ourTool(["-y", "-f", p]);
    ok("the comment of an unencrypted rewrite is kept",
      read.code === 0 && read.stdout.toString().includes("keep@loop88"),
      read.code === 0 ? read.stdout.toString().slice(0, 120) : read.stderr.toString().slice(0, 200));
  }

  // **A re-enciphered key is REALLY enciphered.**  The stdout of a `-p`
  // says that a new passphrase was saved whatever happened, and the
  // real tool opens an UNENCRYPTED key with any passphrase at all
  // (the passphrase is ignored when there is nothing to decipher), so
  // neither the output nor the round trip can see this.  The cipher
  // name in the file's header can.
  {
    const p = makeKey(dir, "ar", "old@loop88", "");
    const ours = ourTool(["-p", "-P", "", "-N", "newpass", "-f", p]);
    ok("the rewrite worked", ours.code === 0, ours.stderr.toString().slice(0, 200));
    const cipher = cipherOf(blobOf(readFileSync(p)));
    ok("the re-enciphered key is REALLY enciphered", cipher === "aes256-ctr",
      `the cipher is ${cipher}`);
  }

  // **Changing the comment does not take the passphrase off.**  The
  // file stays enciphered, and the cipher name in its header says so.
  {
    const p = makeKey(dir, "aq", "enc@loop88", "oldpass");
    const ours = ourTool(["-c", "-C", "new@loop88", "-P", "oldpass", "-f", p]);
    ok("the rewrite worked", ours.code === 0, ours.stderr.toString().slice(0, 200));
    const cipher = cipherOf(blobOf(readFileSync(p)));
    ok("the rewritten key is STILL enciphered", cipher === "aes256-ctr",
      `the cipher is ${cipher}`);
  }

  // -------------------------------------------------------------------------
  section("G7: the divergences, stated");
  // -------------------------------------------------------------------------

  // `-p` and `-c` together: OpenSSH says so and exits with 1.  The
  // usage text is NOT printed here -- see the note at the top of this
  // file -- but the sentence is, and the status is 1.
  {
    const p = makeKey(dir, "ag", "old@loop88", "");
    const ours = ourTool(["-p", "-c", "-C", "x", "-N", "n", "-f", p]);
    const theirs = runBytes(REAL, ["-p", "-c", "-C", "x", "-N", "n", "-f", p]);
    ok("-p with -c exits with 1", ours.code === 1, `exit ${ours.code}`);
    ok("the real tool exits with 1 as well", theirs.code === 1, `exit ${theirs.code}`);
    ok("the sentence is the first line of stderr",
      ours.stderr.toString().startsWith("Can only have one of -p and -c.\r\n"),
      JSON.stringify(ours.stderr.toString().slice(0, 120)));
    ok("the sentence is the same one the real tool prints",
      theirs.stderr.toString().startsWith("Can only have one of -p and -c.\r\n"),
      JSON.stringify(theirs.stderr.toString().slice(0, 120)));
    ok("our tool does NOT print OpenSSH's usage text",
      !ours.stderr.toString().includes("usage: ssh-keygen"),
      JSON.stringify(ours.stderr.toString().slice(0, 200)));
  }

  // Nothing asks a question.  OpenSSH asks on the terminal, and with
  // no terminal it BLOCKS -- measured: `ssh-keygen -p -P "" -f key`
  // with an empty stdin did not return in 120 seconds.  So this tool
  // refuses, and says which option is missing.
  {
    const p = makeKey(dir, "ah", "old@loop88", "");
    const r = ourTool(["-p", "-P", "", "-f", p]);
    ok("-p without -N refuses", r.code === 255, `exit ${r.code}`);
    ok("-p without -N says which option is missing",
      r.stderr.toString().includes("-N"), JSON.stringify(r.stderr.toString().slice(0, 160)));
    ok("-p without -N says nothing on stdout that it should not",
      !r.stdout.toString().includes("saved with the new passphrase"),
      JSON.stringify(r.stdout.toString().slice(0, 160)));
  }
  {
    const p = makeKey(dir, "ai", "old@loop88", "");
    const r = ourTool(["-c", "-f", p]);
    ok("-c without -C refuses", r.code === 255, `exit ${r.code}`);
    ok("-c without -C says which option is missing",
      r.stderr.toString().includes("-C"), JSON.stringify(r.stderr.toString().slice(0, 160)));
  }
  {
    const p = makeKey(dir, "aj", "enc@loop88", "oldpass");
    const r = ourTool(["-p", "-N", "newpass", "-f", p]);
    ok("-p on an encrypted key without -P refuses", r.code === 255, `exit ${r.code}`);
    ok("-p on an encrypted key without -P says which option is missing",
      r.stderr.toString().includes("-P"), JSON.stringify(r.stderr.toString().slice(0, 160)));
  }

  // -------------------------------------------------------------------------
  section("G8: the rules live in src/");
  // -------------------------------------------------------------------------

  // The rewrite is done by `src/keyfile`, and the driver only
  // translates the answers into sentences.  The check is on the SOURCE
  // files and not on `pkg.generated.mbti`, because that file is
  // generated and is not tracked: a gate that reads it would be a gate
  // that cannot run on a fresh checkout.
  const rewriteSrc = readFileSync(path.join(ROOT, "src", "keyfile", "rewrite.mbt"), "utf8");
  const driverSrc = readFileSync(path.join(ROOT, "cmd", "ssh_keygen", "main.mbt"), "utf8");
  ok("src/keyfile/rewrite.mbt has private_file_text_with_passphrase",
    rewriteSrc.includes("pub fn private_file_text_with_passphrase"),
    "the API is not in src/");
  ok("src/keyfile/rewrite.mbt has comment_is_unchanged",
    rewriteSrc.includes("pub fn comment_is_unchanged"),
    "the API is not in src/");
  ok("the driver asks src/keyfile for the file",
    driverSrc.includes("@keyfile.private_file_text_with_passphrase"),
    "the driver does the file work itself");
  ok("the driver asks src/keyfile about the comment",
    driverSrc.includes("@keyfile.comment_is_unchanged"),
    "the driver does the file work itself");

  console.log();
  console.log(`${checks - failures}/${checks} checks passed`);
  if (failures) {
    console.log(`CI FAIL: ${failures} check(s) failed`);
    process.exit(1);
  }
  console.log("ALL PASS");
}

main();
