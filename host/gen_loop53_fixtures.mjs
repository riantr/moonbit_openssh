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
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
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
  // Not needed by verify_loop53.mjs, but needed by `host/cert_gen_fixture.py`
  // (it is the `NON_HOST_PRINCIPAL_CERT` source) and by
  // `src/hostkey/cert_test.mbt`. Generating it here is what makes the whole
  // fixture pipeline reproducible from an empty directory instead of from one
  // machine's leftovers.
  "user-cert-cert.pub",
];

// Same discovery sshd_setup.mjs uses: next to the sshd binary, else PATH. A
// second, different probe list is a second thing that can be wrong on a machine
// nobody has run this on -- which is how the Loop #74 bug survived.
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists. None is asserted to exist, and when none does the script names
// all three and exits 3. verify_loop71.mjs flags any drive-letter path it finds
// in code; this marker is how a file declares that its paths are a probe rather
// than a claim, and it is an obligation to say why, not a mute button.
function findKeygen() {
  const dirs = [
    "C:\\Program Files\\OpenSSH-Win64",
    "C:\\Windows\\System32\\OpenSSH",
    "C:\\Program Files\\OpenSSH",
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

function sign(caPriv, subjectPub, outPub, { id, host, principals, validity, serial }) {
  // `--force` re-cuts the certificate. The CA and the host keys are NOT
  // touched: they are the trust anchors, and replacing them would change what
  // every other fixture means. Only the derived certificates are re-minted,
  // which is what you want after changing a principal or a validity window.
  //
  // The first version of this flag only printed a message and did nothing,
  // which is worse than not having it: `--force` that does not force anything
  // makes a stale fixture set look refreshed. The stale set is exactly how
  // `host-other-cert.pub` kept the OLD principal (`other.example.com`) while
  // the generator believed it had written `10.0.0.9`.
  if (existsSync(outPub) && !FORCE) return false;
  if (existsSync(outPub)) rmSync(outPub, { force: true });
  const args = ["-s", path.join(DIR, caPriv), "-I", id];
  if (host) args.push("-h");
  if (principals) args.push("-n", principals);
  if (validity) args.push("-V", validity);
  if (serial !== undefined) args.push("-z", String(serial));
  args.push(path.join(DIR, subjectPub));
  keygen(args);
  // Measured, not remembered: given `host.pub`, ssh-keygen writes `host-cert.pub`
  // -- it strips the `.pub` and appends `-cert.pub`. The first version of this
  // line looked for `host.pub-cert.pub`, found nothing, and reported
  // "ssh-keygen did not produce ..." on a run where ssh-keygen had worked
  // perfectly. A wrong filename in a verification step is indistinguishable
  // from a tool that failed, which is the exact confusion this repository keeps
  // paying for.
  //
  // The produced name follows the SUBJECT, not a fixed string: signing
  // `userhost.pub` produces `userhost-cert.pub`. See the note on `subjectPub`
  // above for why the subject is a parameter at all.
  const produced = path.join(
    DIR,
    `${subjectPub.replace(/\.pub$/, "")}-cert.pub`,
  );
  if (!existsSync(produced)) {
    console.error(`ssh-keygen exited 0 but ${produced} is absent; ` +
                  `is this ssh-keygen writing the certificate somewhere else?`);
    process.exit(1);
  }
  renameSync(produced, outPub);
  console.log(`  signed ${path.basename(outPub)}  (subject ${subjectPub})`);
  return true;
}

function missing() {
  return REQUIRED.filter((f) => !existsSync(path.join(DIR, f)));
}

// ---------------------------------------------------------------------------
// Structural self-check
// ---------------------------------------------------------------------------
//
// The generator must be able to say that what it produced is what the gate
// needs, without a 16-minute CI round trip. It parses each certificate blob
// the way OpenSSH lays it out (PROTOCOL.certkeys) and asserts the four
// properties the gate depends on:
//
//   * the cert TYPE (1 = user, 2 = host)
//   * the INNER KEY -- which public key the certificate wraps
//   * the PRINCIPALS
//   * the SIGNING CA
//
// The inner-key check is the one that caught a real bug. The first version of
// this generator signed every certificate over `host.pub`, including the USER
// certificate. The MITM signs the handshake with the `userhost` private key,
// so the client's signature check failed BEFORE the certificate-type check
// ever ran, and the gate reported `SignatureInvalid` where the contract says
// `HostkeyCertAuthority` -- a failure for entirely the wrong reason, three
// steps from the one under test.
//
// A generator that cannot tell a correct fixture set from a wrong one is a
// generator whose mistakes cost a CI run each.

function b64ToBytes(b64) {
  return Buffer.from(b64, "base64");
}

class Cursor {
  constructor(buf) { this.b = buf; this.o = 0; }
  remaining() { return this.b.length - this.o; }
  str() {
    if (this.remaining() < 4) { this.o = this.b.length; return Buffer.alloc(0); }
    const n = this.b.readUInt32BE(this.o);
    this.o += 4;
    if (this.remaining() < n) { this.o = this.b.length; return Buffer.alloc(0); }
    const v = this.b.subarray(this.o, this.o + n);
    this.o += n;
    return v;
  }
  u64() {
    if (this.remaining() < 8) { this.o = this.b.length; return 0; }
    const v = this.b.readBigUInt64BE(this.o);
    this.o += 8;
    return v;
  }
  u32() {
    if (this.remaining() < 4) { this.o = this.b.length; return 0; }
    const v = this.b.readUInt32BE(this.o);
    this.o += 4;
    return v;
  }
}

function parseCert(file) {
  const line = readFileSync(file, "utf8").trim().split(/\s+/);
  const buf = b64ToBytes(line[1]);
  const c = new Cursor(buf);
  const typeName = c.str().toString("latin1");
  c.str();                 // nonce
  const innerKey = c.str();  // bare public key material, no type name
  const serial = c.u64();
  const certType = c.u32();
  const keyId = c.str().toString("latin1");
  const principalsBlob = c.str();
  const validAfter = c.u64();
  const validBefore = c.u64();
  c.str();                 // critical options
  c.str();                 // extensions
  c.str();                 // reserved
  // The signature key is the CA's FULL public key blob, type name included --
  // that is what the client's `cert_bytes_eq(cert.sig_key, ca_blob)` compares
  // against the blob in the `@cert-authority` line. Comparing it against the
  // bare material instead would always mismatch, which is how the first
  // version of this checker reported "signed by the wrong CA" for all five
  // certificates.
  const sigKey = c.str();
  const signature = c.str();
  const principals = [];
  const pc = new Cursor(principalsBlob);
  while (pc.remaining() > 0) {
    const p = pc.str().toString("latin1");
    if (pc.remaining() === 0 && p.length === 0) break;
    principals.push(p);
  }
  return {
    typeName, innerKey, serial, certType, keyId, principals,
    validAfter, validBefore, sigKey, signature,
    trailing: c.remaining(),
  };
}

// The public key material of a `.pub` file, i.e. the blob WITHOUT the
// leading type name -- the same shape as a certificate's inner key.
function pubMaterial(file) {
  const buf = b64ToBytes(readFileSync(file, "utf8").trim().split(/\s+/)[1]);
  const c = new Cursor(buf);
  c.str();                 // type name
  return c.str();
}

// The FULL public key blob of a `.pub` file, type name included -- the shape a
// certificate's signature-key field has.
function pubBlob(file) {
  return b64ToBytes(readFileSync(file, "utf8").trim().split(/\s+/)[1]);
}

const CERT_EXPECT = [
  // file,                     type, inner subject,  principals,           CA
  ["host-good-cert.pub", 2, "host.pub", ["127.0.0.1"], "ca.pub"],
  ["host-other-cert.pub", 2, "host.pub", ["other.example.com"], "ca.pub"],
  ["host-exp-cert.pub", 2, "host.pub", ["127.0.0.1"], "ca.pub"],
  ["host-rogue-cert.pub", 2, "host.pub", ["127.0.0.1"], "rogue.pub"],
  ["usercert-in-cert.pub", 1, "userhost.pub", ["alice"], "ca.pub"],
  ["user-cert-cert.pub", 2, "userhost.pub", ["alice", "bob"], "ca.pub"],
];

function verifyFixtures() {
  let bad = 0;
  for (const [file, wantType, subject, wantPrincipals, caFile] of CERT_EXPECT) {
    const full = path.join(DIR, file);
    if (!existsSync(full)) {
      console.error(`  FAIL  ${file}: absent`);
      bad++;
      continue;
    }
    const cert = parseCert(full);
    const problems = [];
    if (cert.certType !== wantType) {
      problems.push(`type=${cert.certType} want ${wantType}`);
    }
    if (!cert.typeName.endsWith("-cert-v01@openssh.com")) {
      problems.push(`type name ${JSON.stringify(cert.typeName)}`);
    }
    const wantInner = pubMaterial(path.join(DIR, subject));
    if (!cert.innerKey.equals(wantInner)) {
      problems.push(`inner key is not ${subject}`);
    }
    if (JSON.stringify(cert.principals) !== JSON.stringify(wantPrincipals)) {
      problems.push(`principals=${JSON.stringify(cert.principals)} want ${JSON.stringify(wantPrincipals)}`);
    }
    const wantCa = pubBlob(path.join(DIR, caFile));
    if (!cert.sigKey.equals(wantCa)) {
      problems.push(`signed by the wrong CA (want ${caFile})`);
    }
    if (cert.trailing !== 0) {
      problems.push(`${cert.trailing} trailing byte(s)`);
    }
    if (problems.length) {
      console.error(`  FAIL  ${file}: ${problems.join("; ")}`);
      bad++;
    } else {
      console.log(`  ok    ${file}  type=${cert.certType} inner=${subject} ` +
                  `principals=${cert.principals.join(",")} ca=${caFile}`);
    }
  }
  if (bad) {
    console.error(`\n${bad} certificate(s) do not have the shape the gate needs.`);
    return false;
  }
  console.log(`\nall ${CERT_EXPECT.length} certificates have the type, inner key, principals and CA the gate needs`);
  return true;
}

if (CHECK) {
  const gone = missing();
  if (gone.length) {
    console.error(`missing ${gone.length} fixture(s): ${gone.join(", ")}`);
    process.exit(1);
  }
  if (!verifyFixtures()) process.exit(1);
  console.log(`all ${REQUIRED.length} certificate fixtures present in ${DIR}`);
  process.exit(0);
}

mkdirSync(DIR, { recursive: true });
if (FORCE) {
  console.log("--force: the certificates will be re-cut. The CA and host keys are kept:");
  console.log("        they are the trust anchors, and replacing them would change what");
  console.log("        every other fixture means.");
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
  sign("ca", "host.pub", path.join(DIR, "host-good-cert.pub"), {
    id: "host.example.com", host: true, principals: "127.0.0.1",
    validity: "-3650d:+3650d", serial: 1,
  });
  sign("ca", "host.pub", path.join(DIR, "host-other-cert.pub"), {
    id: "host.example.com", host: true, principals: "other.example.com",
    validity: "-3650d:+3650d", serial: 2,
  });
  sign("ca", "host.pub", path.join(DIR, "host-exp-cert.pub"), {
    id: "host.example.com", host: true, principals: "127.0.0.1",
    validity: expiredWindow, serial: 3,
  });
  sign("rogue", "host.pub", path.join(DIR, "host-rogue-cert.pub"), {
    id: "host.example.com", host: true, principals: "127.0.0.1",
    validity: "-3650d:+3650d", serial: 4,
  });
  // No -h: a USER certificate, signed by the same CA, valid signature. A client
  // that only compares key bytes accepts it; a client that reads the cert type
  // must not.
  //
  // The SUBJECT is `userhost.pub`, not `host.pub`, and that is load-bearing in
  // a way the certificate's own type is not. The MITM in `verify_loop53.mjs`
  // presents this certificate and signs the handshake with the `userhost`
  // PRIVATE key; the client verifies the handshake signature against the
  // certificate's INNER key. If the inner key were `host.pub`, the signature
  // check would fail first and the client would report `SignatureInvalid` --
  // the handshake never reaching the certificate-type check that this case
  // exists to exercise. The original 2026-10-13 fixture set has exactly this
  // shape (measured with `host/_probe_cert_inner.py`: `usercert-in-cert.pub`
  // wraps `userhost.pub`, every host certificate wraps `host.pub`).
  //
  // A gate that fails for the wrong reason is worse than a missing gate: this
  // one failed on CI run 39236194074 with `SignatureInvalid` where the
  // contract says `HostkeyCertAuthority`.
  sign("ca", "userhost.pub", path.join(DIR, "usercert-in-cert.pub"), {
    id: "loop53-user", host: false, principals: "alice",
    validity: "-3650d:+3650d", serial: 5,
  });
  // A HOST certificate over the same `userhost` key, with two principals. This
  // is the `NON_HOST_PRINCIPAL_CERT` source: it proves the principal list is
  // read as a LIST of length-prefixed strings, not one comma-joined string.
  // `ssh-keygen -n a,b` takes a comma-separated list and writes each entry as
  // its own length-prefixed string.
  sign("ca", "userhost.pub", path.join(DIR, "user-cert-cert.pub"), {
    id: "loop53-user", host: true, principals: "alice,bob",
    validity: "-3650d:+3650d", serial: 6,
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

// The generator checks its own output before it declares success. A generator
// that can only report "the files exist" is a generator that ships a wrong
// fixture set just as happily as a right one -- and the wrong one costs a CI
// run to discover.
console.log("");
if (!verifyFixtures()) process.exit(1);

