// Independent oracle for "what exactly did the CA sign?" using Node's OpenSSL
// ed25519 -- deliberately NOT our own MoonBit verifier, so the two can disagree.
//
// The cert blob layout is fixed (see host/cert_gen_fixture.py). The signature
// covers some prefix of it. This sweeps every plausible boundary and reports
// which one OpenSSL accepts.

import { readFileSync } from "node:fs";
import { createPublicKey, verify as nodeVerify } from "node:crypto";

function pubBlob(path) {
  return Buffer.from(readFileSync(path, "utf8").trim().split(/\s+/)[1], "base64");
}

function u32(buf, o) {
  return buf.readUInt32BE(o);
}
function str(buf, o) {
  const n = u32(buf, o);
  return [buf.subarray(o + 4, o + 4 + n), o + 4 + n];
}

const cert = pubBlob(process.argv[2]);
const ca = pubBlob(process.argv[3]);

// Walk to the signature key field so we know the exact boundary.
let o = 0;
[, o] = str(cert, o); // cert type name
[, o] = str(cert, o); // nonce
[, o] = str(cert, o); // inner key
o += 8; // serial
o += 4; // type
[, o] = str(cert, o); // key id
[, o] = str(cert, o); // principals
o += 16; // valid after / before
[, o] = str(cert, o); // critical options
[, o] = str(cert, o); // extensions
[, o] = str(cert, o); // reserved
const sigkeyStart = o;
[, o] = str(cert, o); // signature key
const [sig] = str(cert, o);

console.log(`cert blob       : ${cert.length} bytes`);
console.log(`reserved ends   : ${sigkeyStart}  (= start of sigkey length prefix)`);
console.log(`signature key   : ${u32(cert, sigkeyStart)} bytes at ${sigkeyStart}`);
console.log(`signature blob  : ${sig.length} bytes`);

// CA public key in OpenSSH SPKI form for Node: the raw 32 bytes go in a
// SubjectPublicKeyInfo. Ed25519 SPKI prefix is the well-known 12-byte header.
const caCur = { b: ca, o: 0 };
const [caAlg, caAfterAlg] = str(ca, 0);
const caPk = ca.subarray(caAfterAlg + 4, caAfterAlg + 4 + u32(ca, caAfterAlg));
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const spki = Buffer.concat([SPKI_ED25519_PREFIX, caPk]);
const keyObj = createPublicKey({ key: spki, format: "der", type: "spki" });
console.log(`CA alg          : ${caAlg.toString()}`);
console.log(`CA public key   : ${caPk.toString("hex")} (${caPk.length} bytes)`);

// Ed25519 signatures are 64 raw bytes; the SSH blob wraps them.
const sigInner = sig.subarray(4 + u32(sig, 0) + 4, sig.length);
console.log(`sig raw         : ${sigInner.length} bytes`);

// Diagnostic sweep: is the signature over ANY contiguous slice of the blob?
const candidates = [];
const starts = [0, 4, 36, 40];
for (const start of starts) {
  for (let end = start + 1; end <= cert.length; end++) {
    candidates.push([
      `blob[${start}:${end}] (${end - start} bytes)`,
      cert.subarray(start, end),
    ]);
  }
}

let hits = 0;
for (const [label, msg] of candidates) {
  let ok = false;
  try {
    ok = nodeVerify(null, msg, keyObj, sigInner);
  } catch (e) {
    ok = `err: ${e.message}`;
  }
  if (ok === true) {
    console.log(`  ACCEPTED  ${label}  (${msg.length} bytes)`);
    hits++;
  }
}
if (hits === 0) {
  console.log("  no candidate accepted -- the signature is not over a cert prefix");
  process.exitCode = 1;
}