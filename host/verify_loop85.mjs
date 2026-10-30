#!/usr/bin/env node
// host/verify_loop85.mjs -- Loop #85: the client can MAKE a key.
//
// ## What is being claimed
//
// Before this loop the client could USE a key and could not MAKE one:
// there was no `ssh-keygen` here, and no code in this repository that
// could write a private key file at all.  `src/rng` (Loop #84) had just
// made the missing piece possible -- a key is a secret, and a secret
// needs an entropy source.
//
// ## The oracle is OpenSSH itself
//
// This is the first gate in the repository whose judge is not another
// implementation of the same idea but the REAL OpenSSH.  A private key
// file is a file with a published format, and the only authority on
// that format is the program everybody else has to read:
//
//   * `ssh-keygen -y -f <private>` reads a private key file and prints
//     the public key it derives from it.  If our file is right, the
//     public key it prints is the public key in our own `.pub` file --
//     byte for byte.  That is a two-way check: the file has to be
//     parseable by OpenSSH, AND the key it holds has to be the key we
//     say it is.
//   * `ssh-keygen -l -f <public>` prints the fingerprint.  It has to be
//     the fingerprint our own tool printed.
//   * `ssh-keygen -y -f <our private>` has to SUCCEED, and it only
//     succeeds if the file's permissions are private enough -- OpenSSH
//     refuses a key file that other users can read.
//
// ## The sections
//
//   G0  the toolchain: `src/keyfile` and `src/keyperm` compile on every
//       target, and the unit tests pass on every target.
//
//   G1  the FILE FORMAT, against OpenSSH's own writer: a key made by
//       the real `ssh-keygen` and a key made by ours have the same
//       shape -- the same magic, the same field lengths, the same
//       length overall -- and ours parses back to the same public key.
//
//   G2  the TWO-WAY check: OpenSSH reads our private key and derives the
//       same public key we wrote in our `.pub` file.
//
//   G3  the PERMISSIONS: the private key file is restricted to its
//       owner, and OpenSSH accepts it.  This is the check that found
//       the real defect in this loop: a file written on Windows
//       inherits the directory's ACL, and OpenSSH refuses to read a
//       private key that "Authenticated Users" can read.
//
//   G4  the tool's own behaviour: a refused passphrase, a refused key
//       type, and a refusal to overwrite an existing private key.
//
//   G5  the random part: two keys are different, and the public key in
//       the file is the public key of the secret key in the file.
//
// ## What runs where
//
// Everything here needs node, the MoonBit toolchain, Python, and a real
// `ssh-keygen`.  The Windows one at C:\Windows\System32\OpenSSH and the
// Win64 one at C:\Program Files\OpenSSH-Win64 are both used when they
// are there, because two OpenSSH builds agreeing is worth more than
// one.  When NO ssh-keygen is present the gate says so LOUDLY and
// fails -- a gate that cannot check its claim must not report success.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SKIP_REGRESSION = process.argv.includes("--skip-regression");
const WORK = path.join(ROOT, ".loop85", "gate");

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

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status, out: norm(`${r.stdout || ""}${r.stderr || ""}`) };
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
// The locations are CANDIDATES, probed in order.  A PATH lookup would find
// nothing: the OpenSSH binaries are not on PATH by default.
// machine-path-exempt: each entry below is a candidate, probed until one
// exists.  None is asserted to exist, and when none does the gate says so
// LOUDLY and fails -- a gate that cannot check its claim must not report
// success.  verify_loop71.mjs flags any drive-letter path it finds in code;
// this marker is how a file declares that its paths are a probe rather than
// a claim, and it is an obligation to say why, not a mute button.
const KEYGEN_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
  "C:\\Program Files\\OpenSSH",
];
const SSH_KEYGENS = KEYGEN_DIRS
  .map((d) => path.join(d, "ssh-keygen.exe"))
  .filter((p) => existsSync(p));

function keygen(bin, args) {
  const r = spawnSync(bin, args, {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 60000,
  });
  return { code: r.status, out: norm(`${r.stdout || ""}${r.stderr || ""}`) };
}

// The public key OpenSSH derives from a private key file.
function derivedPublic(bin, privPath) {
  const r = keygen(bin, ["-y", "-f", privPath]);
  return { code: r.code, line: r.out.trim(), out: r.out };
}

// The fingerprint OpenSSH computes for a public key file.
//
// The character class includes '=' on purpose.  The base64 of a SHA-256 is
// 32 bytes, and 32 is not a multiple of 3, so it ends in one '=' that has
// to be stripped -- and a fingerprint that still carries its padding is a
// fingerprint that is not the one OpenSSH prints.  Catching that needs the
// comparison to be on the WHOLE token, not on the part before the '='.
function fingerprint(bin, pubPath) {
  const r = keygen(bin, ["-l", "-f", pubPath]);
  const m = r.out.match(/SHA256:([A-Za-z0-9+/=]+)/);
  return { code: r.code, fp: m ? m[1] : "", out: r.out };
}

// Run our own tool.
function ourKeygen(args) {
  const r = moon(["run", "--target", "native", "cmd/ssh_keygen", "--", ...args]);
  return { code: r.code, out: r.out };
}

// A fresh directory under .loop85, cleared first.
function freshDir(name) {
  const dir = path.join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

// ---------------------------------------------------------------------------

async function main() {
  console.log("Loop #85: the client can MAKE a key.");
  console.log(`  root: ${ROOT}`);

  // -------------------------------------------------------------------------
  section("G0: the toolchain");
  // -------------------------------------------------------------------------

  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const c = moonCheck("src/keyfile", target);
    ok(`src/keyfile compiles on ${target}`, c.errors === 0,
      c.errors ? `${c.errors} error(s)` : `${c.warnings} warning(s)`);
  }
  const kp = moonCheck("src/keyperm", "native");
  ok("src/keyperm compiles on native", kp.errors === 0,
    kp.errors ? `${kp.errors} error(s)` : `${kp.warnings} warning(s)`);
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

  // -------------------------------------------------------------------------
  section("G0b: the real OpenSSH is here");
  // -------------------------------------------------------------------------

  if (SSH_KEYGENS.length === 0) {
    ok("a real ssh-keygen is available", false,
      "no ssh-keygen found -- this gate cannot check its claim");
    console.log("\nCI FAIL: 0 checks could be run");
    process.exit(1);
  }
  ok(`a real ssh-keygen is available`, true,
    `${SSH_KEYGENS.length} build(s): ${SSH_KEYGENS.map((p) => path.basename(p)).join(", ")}`);

  // -------------------------------------------------------------------------
  section("G1: our file has the shape OpenSSH's writer produces");
  // -------------------------------------------------------------------------

  // The two files are made by different writers -- OpenSSH's and ours --
  // and the COMPARISON is on the structure, because the seeds differ.
  const refDir = freshDir("reference");
  const refPriv = path.join(refDir, "ref");
  // `-N` has to be a REAL empty argument.  OpenSSH's `ssh-keygen` on
  // Windows does not read the shell's quotes: it took the two quote
  // characters as the passphrase and wrote an AES-encrypted file, which
  // is a completely different format from the one under test.
  const gen = keygen(SSH_KEYGENS[0], ["-t", "ed25519", "-f", refPriv, "-N", "", "-C", "gate@loop85"]);
  ok("the real ssh-keygen made a key", gen.code === 0, gen.out.slice(-200));
  ok("the real ssh-keygen wrote a .pub file", existsSync(refPriv + ".pub"));

  if (existsSync(refPriv) && existsSync(refPriv + ".pub")) {
    const refText = readFileSync(refPriv, "utf8");
    const refLines = refText.split("\n").filter((l) => l.length > 0);
    ok("OpenSSH's file starts with the BEGIN marker",
      refLines[0] === "-----BEGIN OPENSSH PRIVATE KEY-----", refLines[0]);
    ok("OpenSSH's file ends with the END marker",
      refLines[refLines.length - 1] === "-----END OPENSSH PRIVATE KEY-----");
    // The base64 body is wrapped at 70 columns.
    const bodyLines = refLines.slice(1, -1);
    ok("OpenSSH wraps the base64 at 70 columns",
      bodyLines.length > 1 && bodyLines[0].length === 70,
      `first body line is ${bodyLines.length ? bodyLines[0].length : 0} characters`);

    // The blob itself, decoded from OpenSSH's own file.
    const refBlob = Buffer.from(bodyLines.join(""), "base64");
    ok("OpenSSH's blob is 242 bytes", refBlob.length === 242, `${refBlob.length} bytes`);
    ok("OpenSSH's blob starts with the magic",
      refBlob.subarray(0, 15).toString("latin1") === "openssh-key-v1\0",
      refBlob.subarray(0, 15).toString("hex"));
    // The magic is 15 bytes including its NUL; the two names follow.
    ok("OpenSSH's cipher name is 'none'",
      refBlob.subarray(19, 23).toString("latin1") === "none",
      refBlob.subarray(19, 23).toString("hex"));
    ok("OpenSSH's KDF name is 'none'",
      refBlob.subarray(27, 31).toString("latin1") === "none",
      refBlob.subarray(27, 31).toString("hex"));

    // Now OUR file, and the same measurements.
    const ourDir = freshDir("ours");
    const ourPriv = path.join(ourDir, "id");
    const ours = ourKeygen(["-f", ourPriv, "-C", "gate@loop85"]);
    ok("our ssh-keygen made a key", ours.code === 0, ours.out.slice(-300));
    ok("our ssh_keygen wrote a .pub file", existsSync(ourPriv + ".pub"));

    if (existsSync(ourPriv) && existsSync(ourPriv + ".pub")) {
      const ourText = readFileSync(ourPriv, "utf8");
      const ourLines = ourText.split("\n").filter((l) => l.length > 0);
      ok("our file starts with the BEGIN marker",
        ourLines[0] === "-----BEGIN OPENSSH PRIVATE KEY-----", ourLines[0]);
      ok("our file ends with the END marker",
        ourLines[ourLines.length - 1] === "-----END OPENSSH PRIVATE KEY-----");
      const ourBody = ourLines.slice(1, -1);
      ok("we wrap the base64 at 70 columns",
        ourBody.length > 1 && ourBody[0].length === 70,
        `first body line is ${ourBody.length ? ourBody[0].length : 0} characters`);
      ok("our base64 body has as many lines as OpenSSH's does",
        ourBody.length === bodyLines.length,
        `ours ${ourBody.length}, OpenSSH's ${bodyLines.length}`);

      const ourBlob = Buffer.from(ourBody.join(""), "base64");
      ok("our blob is 242 bytes", ourBlob.length === 242, `${ourBlob.length} bytes`);
      ok("our blob starts with the same magic",
        ourBlob.subarray(0, 15).equals(refBlob.subarray(0, 15)));
      // The two files hold DIFFERENT keys -- they were made by different
      // writers with different seeds -- so the comparison is on the
      // STRUCTURE: the field lengths have to agree, and the fields that
      // are not key material have to be the same bytes.
      const u32 = (b, o) => b.readUInt32BE(o);
      ok("our blob's cipher and KDF names are the same bytes",
        ourBlob.subarray(15, 34).equals(refBlob.subarray(15, 34)));
      ok("our blob holds the same number of keys",
        u32(ourBlob, 35) === u32(refBlob, 35) && u32(ourBlob, 35) === 1,
        `${u32(ourBlob, 35)} vs ${u32(refBlob, 35)}`);
      ok("our blob's public blob has the same length",
        u32(ourBlob, 39) === u32(refBlob, 39),
        `${u32(ourBlob, 39)} vs ${u32(refBlob, 39)}`);
      ok("our blob's private block has the same length",
        u32(ourBlob, 94) === u32(refBlob, 94),
        `${u32(ourBlob, 94)} vs ${u32(refBlob, 94)}`);
      ok("our blob is the same length overall",
        ourBlob.length === refBlob.length,
        `${ourBlob.length} vs ${refBlob.length}`);

      // And the strongest shape check of all: the public key blob INSIDE
      // our private file has to be the public key in our own `.pub` file.
      // If those two disagreed, the file would be saying two things at
      // once, and a reader that trusted the private file would be wrong.
      const ourPubBlob = Buffer.from(
        readFileSync(ourPriv + ".pub", "utf8").trim().split(" ")[1], "base64");
      const embedded = ourBlob.subarray(43, 43 + u32(ourBlob, 39));
      ok("our private file embeds the public key from our .pub file",
        embedded.equals(ourPubBlob),
        `${embedded.length} vs ${ourPubBlob.length} bytes`);
    }
  }

  // -------------------------------------------------------------------------
  section("G2: OpenSSH reads our private key and derives OUR public key");
  // -------------------------------------------------------------------------

  const dir2 = freshDir("twoway");
  const priv2 = path.join(dir2, "id");
  const made2 = ourKeygen(["-f", priv2, "-C", "gate@loop85"]);
  ok("our ssh_keygen made a key", made2.code === 0, made2.out.slice(-300));

  if (existsSync(priv2) && existsSync(priv2 + ".pub")) {
    const ourPub = readFileSync(priv2 + ".pub", "utf8").trim();

    for (const bin of SSH_KEYGENS) {
      const tag = path.basename(path.dirname(bin));
      const d = derivedPublic(bin, priv2);
      ok(`${tag}: OpenSSH accepts our private key file`, d.code === 0,
        d.code === 0 ? "" : d.out.slice(-300));
      if (d.code === 0) {
        // The public key OpenSSH derives must be the public key we wrote.
        // The comment is the part that may differ (OpenSSH prints the
        // comment from the FILE), so the comparison is on the key.
        const ours = ourPub.split(" ").slice(0, 2).join(" ");
        const theirs = d.line.split(" ").slice(0, 2).join(" ");
        ok(`${tag}: the public key OpenSSH derives is the one we wrote`,
          ours === theirs, ours === theirs ? "" : `ours ${ours} / theirs ${theirs}`);
      }
    }

    // And the fingerprint, both ways.
    const ourFp = fingerprint(SSH_KEYGENS[0], priv2 + ".pub");
    ok("OpenSSH computes a fingerprint for our .pub", ourFp.code === 0 && ourFp.fp !== "",
      ourFp.fp);
    const m = made2.out.match(/SHA256:([A-Za-z0-9+/=]+)/);
    ok("the fingerprint OpenSSH prints is the one our tool printed",
      m && ourFp.fp === m[1], m ? `ours ${m[1]} / OpenSSH ${ourFp.fp}` : made2.out.slice(-200));
  }

  // -------------------------------------------------------------------------
  section("G3: the private key file is private");
  // -------------------------------------------------------------------------

  if (existsSync(priv2)) {
    // OpenSSH REFUSES to read a private key file that other users can
    // read, and says so.  So the fact that G2 succeeded is already this
    // check -- but it is worth saying out loud, because a version of
    // this loop that wrote the file without restricting it would fail
    // G2 for a reason that has nothing to do with the format.
    const d = derivedPublic(SSH_KEYGENS[0], priv2);
    ok("OpenSSH did not complain about the permissions", d.code === 0,
      d.code === 0 ? "" : d.out.slice(-300));

    // And the ACL says so independently of OpenSSH.
    const acl = spawnSync("icacls", [priv2], { encoding: "utf8", errors: "replace" });
    const aclText = norm(`${acl.stdout || ""}${acl.stderr || ""}`);
    ok("the private key file is readable by its owner only",
      aclText.includes("Authenticated Users") === false &&
      aclText.includes("BUILTIN\\Users") === false,
      aclText.split("\n").filter((l) => l.trim()).join(" | ").slice(0, 200));
  }

  // -------------------------------------------------------------------------
  section("G4: the tool refuses what it cannot do");
  // -------------------------------------------------------------------------

  // A passphrase it cannot honour.  Accepting it and writing an
  // UNENCRYPTED key would be a way to lose a secret quietly.
  const dir4 = freshDir("refuse");
  const withPass = ourKeygen(["-f", path.join(dir4, "id"), "-N", "secret", "-C", "x"]);
  ok("a passphrase is refused", withPass.code !== 0 || withPass.out.includes("not supported"),
    withPass.out.trim().slice(0, 200));
  ok("no private key was written for the refused passphrase",
    !existsSync(path.join(dir4, "id")));

  // A key type it does not implement.
  const wrongType = ourKeygen(["-f", path.join(dir4, "id2"), "-t", "rsa", "-C", "x"]);
  ok("an unimplemented key type is refused",
    wrongType.code !== 0 || wrongType.out.includes("only -t ed25519"),
    wrongType.out.trim().slice(0, 200));
  ok("no private key was written for the refused key type",
    !existsSync(path.join(dir4, "id2")));

  // An existing private key is never silently replaced.
  //
  // The refusal is reported in the output rather than in the exit code:
  // MoonBit's `main` has no way to set an exit status, so a driver here
  // says what went wrong and returns.  The claim being made is that the
  // existing key was NOT replaced -- so the message and the bytes on disk
  // are what is checked, not the status.
  const exist = path.join(dir4, "existing");
  const first = ourKeygen(["-f", exist, "-C", "x"]);
  ok("the first key was written", first.code === 0, first.out.slice(-200));
  const before = existsSync(exist) ? readFileSync(exist, "utf8") : "";
  const second = ourKeygen(["-f", exist, "-C", "y"]);
  ok("writing over an existing private key is refused",
    second.out.includes("cannot write") && !second.out.includes("has been saved"),
    second.out.trim().slice(0, 200));
  const after = existsSync(exist) ? readFileSync(exist, "utf8") : "";
  ok("the existing private key was left alone", before === after && before !== "");

  // -------------------------------------------------------------------------
  section("G5: the key in the file is the key that was drawn");
  // -------------------------------------------------------------------------

  const dir5 = freshDir("fresh");
  const p5 = path.join(dir5, "id");
  const g5 = ourKeygen(["-f", p5, "-C", "x"]);
  ok("a key was made", g5.code === 0, g5.out.slice(-200));

  const dir5b = freshDir("fresh2");
  const p5b = path.join(dir5b, "id");
  const g5b = ourKeygen(["-f", p5b, "-C", "x"]);
  ok("a second key was made", g5b.code === 0, g5b.out.slice(-200));

  if (existsSync(p5) && existsSync(p5b)) {
    const t5 = readFileSync(p5, "utf8");
    const t5b = readFileSync(p5b, "utf8");
    ok("two keys are different files", t5 !== t5b);
    ok("two keys are different public keys",
      readFileSync(p5 + ".pub", "utf8") !== readFileSync(p5b + ".pub", "utf8"));

    // The public key in the file has to be the public key of the secret
    // key in the file.  OpenSSH checks that for us when it derives the
    // public key from the private file: if the two halves disagreed,
    // the derived key would not be the one in the .pub file.
    const d5 = derivedPublic(SSH_KEYGENS[0], p5);
    ok("OpenSSH derives our public key from our private key",
      d5.code === 0 &&
      d5.line.split(" ").slice(0, 2).join(" ") ===
      readFileSync(p5 + ".pub", "utf8").trim().split(" ").slice(0, 2).join(" "),
      d5.code === 0 ? "" : d5.out.slice(-200));
  }

  // -------------------------------------------------------------------------
  section("regression: the earlier loops must not move");
  // -------------------------------------------------------------------------

  if (!SKIP_REGRESSION) {
    for (const label of ["loop79", "loop80", "loop81", "loop82", "loop83", "loop84"]) {
      const r = spawnSync("node", [`host/verify_${label}.mjs`], {
        cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 1800000,
      });
      const t = norm(`${r.stdout || ""}${r.stderr || ""}`);
      const m = t.match(/(\d+)\/(\d+) checks/);
      ok(`${label} harness still green`, r.status === 0 && t.includes("PASS"),
        m ? `${m[1]}/${m[2]}` : t.slice(-200));
    }
  }

  // -------------------------------------------------------------------------
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: ${checks - failures}/${checks} checks passed` +
    (skipped ? ` (${skipped} skipped)` : ""));
  if (failures) {
    console.log("  a red run means one of the claims above did not hold");
    process.exit(1);
  }
  console.log("  a key made here was read back by the real OpenSSH, and the");
  console.log("  public key it derived is the one this repository wrote");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
