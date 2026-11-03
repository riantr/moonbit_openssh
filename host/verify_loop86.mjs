#!/usr/bin/env node
// host/verify_loop86.mjs -- Loop #86: the key can be encrypted.
//
// ## What is being claimed
//
// Loop #85 made the client able to MAKE a key, and it refused a
// passphrase: there was no `bcrypt_pbkdf` in this repository, and a
// tool that accepts `-N secret` and writes an UNENCRYPTED key would be
// a way to lose a secret quietly.  So the refusal was the honest
// answer.
//
// This loop adds the missing piece -- Blowfish, `bcrypt_pbkdf`, and the
// AES-256-CTR layer that OpenSSH puts over the private block -- and the
// refusal becomes an encryption.
//
// ## The judges
//
// There are three of them, and they are independent of each other:
//
//   1. **OpenSSH's own C code.**  `verify_c/blowfish_ref.c` and
//      `verify_c/bcrypt_pbkdf_ref.c` are OpenSSH's
//      `openbsd-compat/blowfish.c` and `openbsd-compat/bcrypt_pbkdf.c`,
//      copied here with nothing but their include lines changed (see
//      `host/blowfish_ref.py`).  The harness compiled from them prints
//      the vectors, and `host/blowfish_kat.py --check` proves that the
//      constants the MoonBit tests assert are those vectors.
//
//   2. **OpenSSH itself.**  The real `ssh-keygen` writes an encrypted
//      key, and the real `ssh-keygen` opens the key this repository
//      writes.  A file format is a contract with the program everybody
//      else has to read, and only the program can say whether the
//      contract is kept.
//
//   3. **The MoonBit tests**, on all four targets.
//
// ## The sections
//
//   G0  the toolchain: the three new packages and the driver compile on
//       every target, and the tests pass on every target.
//
//   G1  the oracle IS OpenSSH's code: the C harness builds, runs, and
//       the committed vectors still say what it says.
//
//   G2  the FILE FORMAT: our encrypted file and OpenSSH's encrypted file
//       have the same shape -- the same cipher name, the same KDF name,
//       the same KDF options layout, the same block structure.
//
//   G3  the TWO-WAY check: OpenSSH opens our encrypted key with the
//       passphrase and derives the public key we wrote in our `.pub`
//       file.
//
//   G4  the WRONG PASSPHRASE: OpenSSH refuses our file with the wrong
//       passphrase, and the reader in `src/keyfile` says "wrong
//       passphrase" rather than "malformed".
//
//   G5  the EMPTY passphrase: `-N ""` still means no passphrase, and the
//       file is still the "none" cipher that OpenSSH reads.
//
//   G6  the tool's own behaviour: a refused key type, a refused round
//       count, and a refusal to overwrite an existing private key.
//
//   G7  the random part: two keys made with the same passphrase are
//       different keys, with different salts.
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
import {
  copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop86", "gate");

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
// `spawnSync` without a timeout waits for the child for as long as the
// child wants to run.  A defect that turns into an endless computation
// -- a key file that asks for two billion KDF rounds, say -- would then
// hang the gate instead of failing it, and the mutation suite would hang
// with it, and nothing would be left to say that anything was wrong.
//
// The timeout is long enough for a cold compile of the whole tree on a
// loaded machine, and short enough that a hang is reported rather than
// waited out.
//
// **A timeout is a FAILURE of the check that was running, and the reason
// says so.**  "The test never finished" is a failure of the test, and a
// red gate with no reason is a rumour: the reader has no way to tell
// "the round trip broke" from "the toolchain did not run".
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
  // A spawn that failed has no status to speak of, and a spawn that was
  // killed has none either; both are failures of whatever check was
  // running, so both are reported as a non-zero exit.
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

// The argument array is passed EXACTLY.  An empty passphrase is an
// empty string and has to survive as one, and a shell would eat it:
// PowerShell drops an empty argument entirely, and then `ssh-keygen -N
// "" -f file` reads the `-f` as the passphrase and complains about
// "too many arguments".  spawnSync has no shell, so the array is what
// the program sees.
function keygen(bin, args) {
  const r = spawnSync(bin, args, {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 120000, input: "",
  });
  return { code: r.status, out: norm(`${r.stdout || ""}${r.stderr || ""}`) };
}

// Run our own tool.
function ourKeygen(args) {
  const r = moon(["run", "--target", "native", "cmd/ssh_keygen", "--", ...args]);
  return { code: r.code, out: r.out };
}

// A fresh directory under .loop86, cleared first.
function freshDir(name) {
  const dir = path.join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

// The base64 body of a private key file, and the bytes it decodes to.
function keyBlob(text) {
  const lines = text.split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
  const body = lines.slice(1, -1).join("");
  return Buffer.from(body, "base64");
}

// The openssh-key-v1 structure, read the way the format says it is read.
//
//   "openssh-key-v1\0"  magic
//   string ciphername
//   string kdfname
//   string kdfoptions
//   uint32 nkeys
//   string publickey blob
//   string encrypted
function parseBlob(buf) {
  let at = 15;
  const take = () => {
    const n = buf.readUInt32BE(at);
    at += 4;
    const s = buf.subarray(at, at + n);
    at += n;
    return s;
  };
  const cipher = take();
  const kdf = take();
  const opts = take();
  const nkeys = buf.readUInt32BE(at);
  at += 4;
  const pubblob = take();
  const encLen = buf.readUInt32BE(at);
  at += 4;
  const enc = buf.subarray(at, at + encLen);
  return {
    magic: buf.subarray(0, 15).toString("latin1"),
    cipher: cipher.toString("latin1"),
    kdf: kdf.toString("latin1"),
    opts,
    nkeys,
    pubblob,
    encLen,
    enc,
    total: buf.length,
  };
}

// The KDF options: a length-prefixed salt, then a four-byte word.
//
// **The options are binary and they come out of a file that a defect
// may have given the wrong shape.**  A file with no encryption has
// EMPTY options, and reading a four-byte length out of an empty buffer
// throws -- and a gate that throws reports nothing at all, which the
// mutation suite reads as "the gate did not notice" when in fact the
// gate had stopped running.
//
// So this returns null for options it cannot read, and the caller says
// FAIL with a reason.
function parseKdfOptions(opts) {
  if (opts.length < 8) return null;
  const slen = opts.readUInt32BE(0);
  if (4 + slen + 4 > opts.length) return null;
  const salt = opts.subarray(4, 4 + slen);
  const rounds = opts.readUInt32BE(4 + slen);
  return { salt, rounds, optsLen: opts.length };
}

// A copy of a private key file that only its owner can read.
//
// OpenSSH REFUSES a private key file that other users can read, and it
// says so.  A plain file copy on Windows inherits the DIRECTORY's ACL,
// so the copy has to be given the same treatment the original got.
function copyWithOwnerOnlyAcl(src, dst) {
  rmSync(dst, { force: true });
  copyFileSync(src, dst);
  const user = process.env.USERNAME || process.env.USER;
  if (!user) return false;
  const r = spawnSync("icacls", [dst, "/inheritance:r", "/grant:r", `${user}:(F)`], {
    encoding: "utf8", errors: "replace", timeout: 60000,
  });
  return r.status === 0;
}

// OpenSSH opens our encrypted key with the passphrase and prints the
// public key it derives.
//
// `ssh-keygen -y` would ask for the passphrase on the terminal, and a
// gate has no terminal.  `ssh-keygen -p -P <pass> -N ""` does the same
// job without one: it opens the file with the passphrase given on the
// command line and writes it back with an empty passphrase, and if the
// passphrase was wrong it says so and leaves the file alone.  The file
// is then read with `ssh-keygen -y`, which needs no passphrase.
function opensshOpensOurKey(bin, ourPriv, pass) {
  const probe = ourPriv + ".probe";
  if (!copyWithOwnerOnlyAcl(ourPriv, probe)) {
    return { code: -1, out: "the probe copy could not be made private" };
  }
  const reopened = keygen(bin, ["-p", "-P", pass, "-N", "", "-f", probe]);
  if (reopened.code !== 0) {
    return { code: reopened.code, out: reopened.out };
  }
  const derived = keygen(bin, ["-y", "-f", probe]);
  return { code: derived.code, out: derived.out, reopened: reopened.out };
}

// ---------------------------------------------------------------------------

async function main() {
  console.log("Loop #86: the key can be encrypted.");
  console.log(`  root: ${ROOT}`);

  // -------------------------------------------------------------------------
  section("G0: the toolchain");
  // -------------------------------------------------------------------------

  for (const pkg of ["src/blowfish", "src/bcrypt_pbkdf", "src/keyfile"]) {
    for (const target of ["native", "js", "wasm", "wasm-gc"]) {
      const c = moonCheck(pkg, target);
      ok(`${pkg} compiles on ${target}`, c.errors === 0,
        c.errors ? `${c.errors} error(s)` : `${c.warnings} warning(s)`);
    }
  }
  const kg = moonCheck("cmd/ssh_keygen", "native");
  ok("cmd/ssh_keygen compiles on native", kg.errors === 0,
    kg.errors ? `${kg.errors} error(s)` : `${kg.warnings} warning(s)`);

  for (const pkg of ["src/blowfish", "src/bcrypt_pbkdf", "src/keyfile"]) {
    for (const target of ["native", "js", "wasm", "wasm-gc"]) {
      const r = moon(["test", pkg, "--target", target]);
      const m = r.out.match(/Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/);
      ok(`${pkg}'s tests pass on ${target}`,
        r.code === 0 && m && Number(m[3]) === 0 && Number(m[2]) > 0,
        m ? `${m[2]}/${m[1]} passed` : r.out.slice(-200));
    }
  }

  // -------------------------------------------------------------------------
  section("G1: the oracle is OpenSSH's own code");
  // -------------------------------------------------------------------------

  // The copies of OpenSSH's two files are in the repository, and their
  // ONLY difference from the originals is three include lines and one
  // #define.  `host/blowfish_ref.py --check` proves that -- but only
  // where the OpenSSH source tree is, which is not everywhere.
  const refCheck = spawnSync("python", [path.join(ROOT, "host", "blowfish_ref.py"), "--check"], {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 120000,
  });
  const refOut = norm(`${refCheck.stdout || ""}${refCheck.stderr || ""}`);
  if (refCheck.status === 3) {
    // host/openssh_src.py exits 3 when the tree is not on this machine.
    // That is a SKIP, not a failure: the check cannot be made here.  It is
    // asked as a question of the exit code rather than by matching the
    // error text, because text that says "not here" is also what a real
    // mismatch says when it goes wrong.
    skip("the committed copies still match OpenSSH's source",
      "the OpenSSH source tree is not on this machine");
  } else if (refOut.includes("does not match") || refOut.includes("MISSING")) {
    ok("the committed copies still match OpenSSH's source", false, refOut.slice(0, 300));
  } else {
    ok("the committed copies still match OpenSSH's source",
      refCheck.status === 0, refOut.trim().split("\n")[0]);
  }

  // Build the C harness and check the committed vectors against it.
  const build = spawnSync("cmd", ["/c", path.join(ROOT, "verify_c", "build_blowfish.bat")], {
    cwd: path.join(ROOT, "verify_c"), encoding: "utf8", errors: "replace", timeout: 300000,
  });
  const buildOut = norm(`${build.stdout || ""}${build.stderr || ""}`);
  if (/no C compiler on PATH/i.test(buildOut)) {
    skip("the C harness builds", "no C compiler on this machine");
    skip("the committed vectors match the C oracle", "no C compiler on this machine");
  } else {
    ok("the C harness builds", build.status === 0,
      build.status === 0 ? "" : buildOut.slice(-300));
    const kat = spawnSync("python", [path.join(ROOT, "host", "blowfish_kat.py"), "--check"], {
      cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 120000,
    });
    const katOut = norm(`${kat.stdout || ""}${kat.stderr || ""}`);
    ok("the committed vectors match the C oracle",
      kat.status === 0 && katOut.includes("OK"), katOut.trim().slice(0, 300));
  }

  // -------------------------------------------------------------------------
  section("G1b: the real OpenSSH is here");
  // -------------------------------------------------------------------------

  if (SSH_KEYGENS.length === 0) {
    ok("a real ssh-keygen is available", false,
      "no ssh-keygen found -- this gate cannot check its claim");
    console.log("\nCI FAIL: 0 checks could be run");
    process.exit(1);
  }
  ok("a real ssh-keygen is available", true,
    `${SSH_KEYGENS.length} build(s): ${SSH_KEYGENS.map((p) => path.basename(path.dirname(p))).join(", ")}`);

  // -------------------------------------------------------------------------
  section("G2: our encrypted file has OpenSSH's shape");
  // -------------------------------------------------------------------------

  const refDir = freshDir("reference");
  const refPriv = path.join(refDir, "ref");
  const refGen = keygen(SSH_KEYGENS[0], ["-t", "ed25519", "-f", refPriv, "-N", "s3cr3t-pass", "-C", "gate@loop86"]);
  ok("the real ssh-keygen made an encrypted key", refGen.code === 0, refGen.out.slice(-200));
  ok("the real ssh-keygen wrote a .pub file", existsSync(refPriv + ".pub"));

  const ourDir = freshDir("ours");
  const ourPriv = path.join(ourDir, "id");
  const ourMade = ourKeygen(["-f", ourPriv, "-N", "s3cr3t-pass", "-C", "gate@loop86"]);
  ok("our ssh_keygen made an encrypted key", ourMade.code === 0, ourMade.out.slice(-300));
  ok("our ssh_keygen wrote a .pub file", existsSync(ourPriv + ".pub"));

  if (existsSync(refPriv) && existsSync(ourPriv)) {
    const ref = parseBlob(keyBlob(readFileSync(refPriv, "utf8")));
    const ours = parseBlob(keyBlob(readFileSync(ourPriv, "utf8")));
    const refOpts = parseKdfOptions(ref.opts);
    const ourOpts = parseKdfOptions(ours.opts);

    ok("both files start with the magic",
      ref.magic === "openssh-key-v1\0" && ours.magic === "openssh-key-v1\0", ours.magic);
    ok("both files name the same cipher",
      ours.cipher === ref.cipher && ours.cipher === "aes256-ctr",
      `ours ${ours.cipher}, OpenSSH ${ref.cipher}`);
    ok("both files name the same KDF",
      ours.kdf === ref.kdf && ours.kdf === "bcrypt",
      `ours ${ours.kdf}, OpenSSH ${ref.kdf}`);
    ok("both files have readable KDF options",
      !!ourOpts && !!refOpts,
      `ours ${ourOpts ? "readable" : "not readable"}, OpenSSH ${refOpts ? "readable" : "not readable"}`);
    ok("both files have the same KDF options length",
      !!ourOpts && !!refOpts && ourOpts.optsLen === refOpts.optsLen,
      `ours ${ourOpts ? ourOpts.optsLen : "none"}, OpenSSH ${refOpts ? refOpts.optsLen : "none"}`);
    ok("both files have a 16-byte salt",
      !!ourOpts && !!refOpts && ourOpts.salt.length === 16 && refOpts.salt.length === 16,
      `ours ${ourOpts ? ourOpts.salt.length : "none"}, OpenSSH ${refOpts ? refOpts.salt.length : "none"}`);
    ok("both files have the same number of rounds",
      !!ourOpts && !!refOpts && ourOpts.rounds === refOpts.rounds,
      `ours ${ourOpts ? ourOpts.rounds : "none"}, OpenSSH ${refOpts ? refOpts.rounds : "none"}`);
    ok("the rounds are OpenSSH's default of 24",
      !!ourOpts && ourOpts.rounds === 24, String(ourOpts ? ourOpts.rounds : "none"));
    ok("both files hold one key", ours.nkeys === 1 && ref.nkeys === 1);
    ok("both files have the same public blob length",
      ours.pubblob.length === ref.pubblob.length,
      `ours ${ours.pubblob.length}, OpenSSH ${ref.pubblob.length}`);
    ok("our encrypted section is a whole number of AES blocks",
      ours.encLen > 0 && ours.encLen % 16 === 0, `${ours.encLen} bytes`);
    ok("OpenSSH's encrypted section is a whole number of AES blocks",
      ref.encLen > 0 && ref.encLen % 16 === 0, `${ref.encLen} bytes`);
    ok("the two encrypted sections have the same length",
      ours.encLen === ref.encLen, `ours ${ours.encLen}, OpenSSH ${ref.encLen}`);
    ok("the two files are different files",
      readFileSync(refPriv, "utf8") !== readFileSync(ourPriv, "utf8"));
  }

  // -------------------------------------------------------------------------
  section("G3: OpenSSH opens our encrypted key and derives OUR public key");
  // -------------------------------------------------------------------------

  if (existsSync(ourPriv) && existsSync(ourPriv + ".pub")) {
    const ourPub = readFileSync(ourPriv + ".pub", "utf8").trim();
    for (const bin of SSH_KEYGENS) {
      const tag = path.basename(path.dirname(bin));
      const r = opensshOpensOurKey(bin, ourPriv, "s3cr3t-pass");
      ok(`${tag}: OpenSSH opens our encrypted key with the passphrase`,
        r.code === 0, r.code === 0 ? "" : r.out.slice(-300));
      if (r.code === 0) {
        // The COMMENT is the part that may differ: OpenSSH 9.x prints
        // the comment from the file and the 8.0 build does not, so the
        // comparison is on the key.
        const theirs = r.out.trim().split("\n")[0].split(" ").slice(0, 2).join(" ");
        const ours = ourPub.split(" ").slice(0, 2).join(" ");
        ok(`${tag}: the public key OpenSSH derives is the one we wrote`,
          ours === theirs, ours === theirs ? "" : `ours ${ours} / theirs ${theirs}`);
      }
    }
  }

  // -------------------------------------------------------------------------
  section("G4: the wrong passphrase");
  // -------------------------------------------------------------------------

  if (existsSync(ourPriv)) {
    for (const bin of SSH_KEYGENS) {
      const tag = path.basename(path.dirname(bin));
      const probe = ourPriv + ".wrong";
      if (!copyWithOwnerOnlyAcl(ourPriv, probe)) {
        ok(`${tag}: OpenSSH refuses our file with the wrong passphrase`, false,
          "the probe copy could not be made private");
        continue;
      }
      const r = keygen(bin, ["-p", "-P", "not the passphrase", "-N", "", "-f", probe]);
      ok(`${tag}: OpenSSH refuses our file with the wrong passphrase`,
        r.code !== 0 && /passphrase/i.test(r.out),
        `exit ${r.code}: ${r.out.trim().slice(0, 200)}`);
    }
  }

  // -------------------------------------------------------------------------
  section("G5: the empty passphrase is still no passphrase");
  // -------------------------------------------------------------------------

  const emptyDir = freshDir("empty");
  const emptyPriv = path.join(emptyDir, "id");
  const emptyMade = ourKeygen(["-f", emptyPriv, "-N", "", "-C", "gate@loop86"]);
  ok("our ssh_keygen made a key with an empty passphrase", emptyMade.code === 0,
    emptyMade.out.slice(-300));

  if (existsSync(emptyPriv)) {
    const blob = parseBlob(keyBlob(readFileSync(emptyPriv, "utf8")));
    ok("the file names the 'none' cipher", blob.cipher === "none", blob.cipher);
    ok("the file names the 'none' KDF", blob.kdf === "none", blob.kdf);
    const r = keygen(SSH_KEYGENS[0], ["-y", "-f", emptyPriv]);
    ok("OpenSSH reads the file without a passphrase", r.code === 0,
      r.code === 0 ? "" : r.out.slice(-300));
    if (r.code === 0) {
      const ours = readFileSync(emptyPriv + ".pub", "utf8").trim().split(" ").slice(0, 2).join(" ");
      const theirs = r.out.trim().split("\n")[0].split(" ").slice(0, 2).join(" ");
      ok("the public key OpenSSH derives is the one we wrote", ours === theirs,
        ours === theirs ? "" : `ours ${ours} / theirs ${theirs}`);
    }
  }

  // -------------------------------------------------------------------------
  section("G6: the tool refuses what it cannot do");
  // -------------------------------------------------------------------------

  const dir6 = freshDir("refuse");
  const wrongType = ourKeygen(["-f", path.join(dir6, "id1"), "-t", "rsa", "-C", "x"]);
  ok("an unimplemented key type is refused",
    wrongType.out.includes("only -t ed25519"), wrongType.out.trim().slice(0, 200));
  ok("no private key was written for the refused key type",
    !existsSync(path.join(dir6, "id1")));

  const badRounds = ourKeygen(["-f", path.join(dir6, "id2"), "-N", "p", "-a", "0", "-C", "x"]);
  ok("a round count below one is refused",
    badRounds.out.includes("-a <rounds>"), badRounds.out.trim().slice(0, 200));
  ok("no private key was written for the refused round count",
    !existsSync(path.join(dir6, "id2")));

  const notANumber = ourKeygen(["-f", path.join(dir6, "id3"), "-N", "p", "-a", "many", "-C", "x"]);
  ok("a round count that is not a number is refused",
    notANumber.out.includes("-a <rounds>"), notANumber.out.trim().slice(0, 200));

  // A round count above the cap is refused rather than obeyed.  The
  // number is four bytes in the file, and a file that names two billion
  // rounds must not be able to make a reader work for hours.
  const hugeRounds = ourKeygen(["-f", path.join(dir6, "id4"), "-N", "p", "-a", "2000000000", "-C", "x"]);
  ok("a round count above the cap is refused",
    hugeRounds.out.includes("-a <rounds>"), hugeRounds.out.trim().slice(0, 200));
  ok("no private key was written for the round count above the cap",
    !existsSync(path.join(dir6, "id4")));

  // And a number too big to fit in an Int32 is refused too.  It is
  // 2^32 + 24: if the count were allowed to wrap around, it would land
  // on twenty-four and be written into the file as twenty-four, which is
  // a request for a lot of work quietly turned into a little.
  const wrappingRounds = ourKeygen(["-f", path.join(dir6, "id5"), "-N", "p", "-a", "4294967320", "-C", "x"]);
  ok("a round count too big to fit in an Int32 is refused",
    wrappingRounds.out.includes("-a <rounds>"), wrappingRounds.out.trim().slice(0, 200));
  ok("no private key was written for the round count too big to fit",
    !existsSync(path.join(dir6, "id5")));

  // An existing private key is never silently replaced.
  //
  // The refusal is reported in the output rather than in the exit code:
  // MoonBit's `main` has no way to set an exit status, so a driver here
  // says what went wrong and returns.  The claim being made is that the
  // existing key was NOT replaced -- so the message and the bytes on disk
  // are what is checked, not the status.
  const exist = path.join(dir6, "existing");
  const first = ourKeygen(["-f", exist, "-N", "p", "-C", "x"]);
  ok("the first key was written", first.code === 0, first.out.slice(-200));
  const before = existsSync(exist) ? readFileSync(exist, "utf8") : "";
  const second = ourKeygen(["-f", exist, "-N", "p", "-C", "y"]);
  ok("writing over an existing private key is refused",
    second.out.includes("cannot write") && !second.out.includes("has been saved"),
    second.out.trim().slice(0, 200));
  const after = existsSync(exist) ? readFileSync(exist, "utf8") : "";
  ok("the existing private key was left alone", before === after && before !== "");

  // -------------------------------------------------------------------------
  section("G7: the random part");
  // -------------------------------------------------------------------------

  const dir7 = freshDir("fresh");
  const p7 = path.join(dir7, "id");
  const g7 = ourKeygen(["-f", p7, "-N", "the same passphrase", "-C", "x"]);
  ok("a key was made", g7.code === 0, g7.out.slice(-200));

  const dir7b = freshDir("fresh2");
  const p7b = path.join(dir7b, "id");
  const g7b = ourKeygen(["-f", p7b, "-N", "the same passphrase", "-C", "x"]);
  ok("a second key was made", g7b.code === 0, g7b.out.slice(-200));

  if (existsSync(p7) && existsSync(p7b)) {
    const t7 = readFileSync(p7, "utf8");
    const t7b = readFileSync(p7b, "utf8");
    ok("two keys made with the same passphrase are different files", t7 !== t7b);
    const o7 = parseKdfOptions(parseBlob(keyBlob(t7)).opts);
    const o7b = parseKdfOptions(parseBlob(keyBlob(t7b)).opts);
    ok("the two keys have different salts",
      !!o7 && !!o7b && !o7.salt.equals(o7b.salt),
      o7 && o7b ? `${o7.salt.toString("hex")} / ${o7b.salt.toString("hex")}` : "the salts are not readable");
    const pub7 = readFileSync(p7 + ".pub", "utf8").trim();
    const pub7b = readFileSync(p7b + ".pub", "utf8").trim();
    ok("the two keys have different public keys", pub7 !== pub7b);
  }

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
// verdict.**  An exception anywhere in here used to kill the process
// with a stack trace and a non-zero exit, and the mutation suite read
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
