#!/usr/bin/env node
// host/gen_loop53_fixtures.mjs -- make the certificate fixtures verify_loop53
// needs, from nothing, with ssh-keygen.
//
// ## Why this file exists
//
// `verify_loop53.mjs` opens with a fixture check:
//
//     for (const f of ["ca", "ca.pub", "rogue.pub", "host", "host.pub",
//                      "userhost", "host-good-cert.pub", ...]) {
//       if (!existsSync(join(KEYS, f))) { bad("fixtures", `missing .loop53/${f}`); ...
//
// and on GitHub run 39231921826 that is exactly what happened:
//
//     loop53: FAIL  fixtures  missing .loop53/ca
//     loop53: 2/3 checks passed
//
// Nothing in the repository produced those eleven files. They were made once,
// on one machine, on 2026-10-13, and every run since -- local -- has found them
// already sitting there. `host/cert_gen_fixture.py` reads them and emits
// `src/hostkey/cert_fixture.mbt`; it does not create them, and it is referenced
// nowhere in the tree.
//
// This is the same shape as the Loop #74 `-b` splice: a gate whose inputs exist
// only where the gate has already run, so it is green on every developer machine
// and red on every fresh checkout. It cost three CI runs to notice, each of them
// 16 minutes.
//
// ## Why a generator and not committed keys
//
// The obvious alternative is to commit the eleven files. They are throwaway
// test keys that sign nothing but these certificates, so the security cost is
// nil -- but a repository that carries private keys has to keep carrying them,
// and a reviewer cannot tell a test CA from a real one by looking at a diff.
// Generating them means the fixture set is reproducible, reviewable as CODE, and
// absent from git. It also means the certificates differ from run to run, which
// is fine here: loop53 asserts BEHAVIOUR over these vectors (a CA that covers
// the host, a direct entry that outranks it, a rogue CA, an expired one), not
// particular bytes.
//
// **The thing this does not fix, on purpose, and it is worth naming:**
// `src/hostkey/cert_fixture.mbt` is a committed artifact generated from the
// PREVIOUS `.loop53` certificates, and no gate checks that the two still
// correspond. Generating fresh fixtures on CI therefore widens a gap that
// already exists rather than creating one: two sources of truth for the same
// certificates, with nothing comparing them. Closing that is a separate piece of
// work and deserves its own loop; until then the honest statement is that
// loop53's vectors and cert_fixture.mbt's vectors are two different sets.
//
// ## Certificate shapes, and why each one exists
//
//   host-good-cert     host cert, CA-signed, principal 127.0.0.1  -> CertAuthority
//   host-other-cert    host cert, CA-signed, principal elsewhere   -> CertAuthority
//                      but a DIFFERENT principal string, so a client that
//                      ignores principals and only compares keys passes when it
//                      should not
//   host-exp-cert      host cert, CA-signed, validity in the past -> expiry
//   host-rogue-cert    host cert signed by a DIFFERENT CA         -> untrusted
//   usercert-in-cert   USER cert (no -h) signed by the same CA     -> a user
//                      certificate presented as a host key must not satisfy a
//                      CA entry
//
// The `-h` flag is the whole difference between the first four and the last.
// `ssh-keygen -s ca -I id -h ...` produces a host certificate; without `-h` it
// produces a user certificate. Both are signed by the same CA and both are valid
// signatures, which is the point: key material alone cannot tell them apart.
//
// ## Usage
//
//   node host/gen_loop53_fixtures.mjs            # fill in what is missing
//   node host/gen_loop53_fixtures.mjs --force    # regenerate everything
//   node host/gen_loop53_fixtures.mjs --check    # report, generate nothing
//   node host/gen_loop53_fixtures.mjs --dir X    # somewhere else, for testing
//
// `--check` is what CI runs after generating, and what a human runs before
// trusting a fixture set. It exits 1 and NAMES the missing files rather than
// letting verify_loop53 be the one to discover it.
//
// `--dir` exists for the same reason Loop #74 gave sshd_setup.mjs one: to ask
// "does this work on a machine that has never run it?" without destroying the
// answer you already have. It is also how this file was tested -- generating
// into an empty temp directory and inspecting the result with `ssh-keygen -L`,
// which is the only way to see the certificate TYPE and the principals without
// reading them out of a fixture that already exists.

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, renameSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const argv = process.argv.slice(2);
const FORCE = argv.includes("--force");
const CHECK = argv.includes("--check");
const dirIdx = argv.indexOf("--dir");
const DIR = dirIdx >= 0 && argv[dirIdx + 1]
  ? path.resolve(argv[dirIdx + 1])
  : path.join(ROOT, ".loop53");

const REQUIRED = [
  "ca", "ca.pub", "rogue.pub",
  "host", "host.pub",
  "userhost", "userhost.pub",
  "host-good-cert.pub", "host-other-cert.pub", "host-exp-cert.pub",
  "host-rogue-cert.pub", "usercert-in-cert.pub",
];

// Same discovery sshd_setup.mjs uses: next to the sshd binary, else PATH. A
// second, different probe list is a second thing that can be wrong on a machine
// nobody has run this on -- which is how the Loop #74 bug survived.
function findKeygen() {
  const dirs = [
    "C:\\Program Files\\OpenSSH",
    "C:\\Program Files\\OpenSSH-Win64",
    path.join(process.env.SystemRoot || "C:\\Windows", "System32", "OpenSSH"),
  ];
  for (const d of dirs) {
    const p = path.join(d, "ssh-keygen.exe");
    if (existsSync(p)) return p;
  }
  return "ssh-keygen";
}
const KEYGEN = findKeygen();

// `-N ''` has to be a real empty argument. Driven from Node rather than a shell
// on purpose: PowerShell drops empty-string arguments when handing them to a
// native process, and ssh-keygen answers `Too many arguments` -- which reads as
// a bug in this file rather than as a shell that ate an argument.
function keygen(args) {
  return execFileSync(KEYGEN, args, {
    cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
  });
}

function makeKey(name, comment) {
  const priv = path.join(DIR, name);
  if (existsSync(priv) && existsSync(`${priv}.pub`)) return false;
  keygen(["-t", "ed25519", "-f", priv, "-q", "-N", "", "-C", comment]);
  console.log(`  generated ${name}`);
  return true;
}

function sign(caPriv, outPub, { id, host, principals, validity, serial }) {
  if (existsSync(outPub)) return false;
  const args = ["-s", path.join(DIR, caPriv), "-I", id];
  if (host) args.push("-h");
  if (principals) args.push("-n", principals);
  if (validity) args.push("-V", validity);
  if (serial !== undefined) args.push("-z", String(serial));
  args.push(path.join(DIR, "host.pub"));
  keygen(args);
  // Measured, not remembered: given `host.pub`, ssh-keygen writes `host-cert.pub`
  // -- it strips the `.pub` and appends `-cert.pub`. The first version of this
  // line looked for `host.pub-cert.pub`, found nothing, and reported
  // "ssh-keygen did not produce ..." on a run where ssh-keygen had worked
  // perfectly. A wrong filename in a verification step is indistinguishable
  // from a tool that failed, which is the exact confusion this repository keeps
  // paying for.
  const produced = path.join(DIR, "host-cert.pub");
  if (!existsSync(produced)) {
    console.error(`ssh-keygen exited 0 but ${produced} is absent; ` +
                  `is this ssh-keygen writing the certificate somewhere else?`);
    process.exit(1);
  }
  renameSync(produced, outPub);
  console.log(`  signed ${path.basename(outPub)}`);
  return true;
}

function missing() {
  return REQUIRED.filter((f) => !existsSync(path.join(DIR, f)));
}

if (CHECK) {
  const gone = missing();
  if (gone.length) {
    console.error(`missing ${gone.length} fixture(s): ${gone.join(", ")}`);
    process.exit(1);
  }
  console.log(`all ${REQUIRED.length} certificate fixtures present in ${DIR}`);
  process.exit(0);
}

mkdirSync(DIR, { recursive: true });
if (FORCE) {
  console.log("--force: the gate will regenerate anything absent; existing files are kept");
  console.log("        (delete .loop53 by hand if you truly mean to start over)");
}

console.log(`generating certificate fixtures in ${DIR}`);
// The two CAs first: every certificate below is signed by one of them.
makeKey("ca", "loop53 test CA");
makeKey("rogue", "loop53 rogue CA");
// The key the certificates are issued FOR. loop53 also compares a client-
// presented key against this one's public half (INNER_BLOB), so it is not only
// a signing subject.
makeKey("host", "loop53 inner host key");
makeKey("userhost", "loop53 user-side key");

// Validity strings are absolute for the expired one on purpose: `-V` accepts
// relative offsets, and an offset is measured from now, so "expired" computed
// relatively would drift across runs in a way nobody would notice for years.
const expiredWindow = "20200101000000:20200102000000";

try {
  sign("ca", path.join(DIR, "host-good-cert.pub"), {
    id: "loop53-good", host: true, principals: "127.0.0.1",
    validity: "-3650d:+3650d", serial: 1,
  });
  sign("ca", path.join(DIR, "host-other-cert.pub"), {
    id: "loop53-other-principal", host: true, principals: "10.0.0.9",
    validity: "-3650d:+3650d", serial: 2,
  });
  sign("ca", path.join(DIR, "host-exp-cert.pub"), {
    id: "loop53-expired", host: true, principals: "127.0.0.1",
    validity: expiredWindow, serial: 3,
  });
  sign("rogue", path.join(DIR, "host-rogue-cert.pub"), {
    id: "loop53-rogue", host: true, principals: "127.0.0.1",
    validity: "-3650d:+3650d", serial: 4,
  });
  // No -h: a USER certificate, signed by the same CA, valid signature. A client
  // that only compares key bytes accepts it; a client that reads the cert type
  // must not.
  sign("ca", path.join(DIR, "usercert-in-cert.pub"), {
    id: "loop53-user", host: false, principals: "testuser",
    validity: "-3650d:+3650d", serial: 5,
  });
} catch (e) {
  console.error(`ssh-keygen failed: ${String(e.stderr || e.message).trim()}`);
  process.exit(1);
}

const gone = missing();
if (gone.length) {
  console.error(`still missing after generating: ${gone.join(", ")}`);
  process.exit(1);
}
console.log(`all ${REQUIRED.length} certificate fixtures present`);
