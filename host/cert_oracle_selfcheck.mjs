// Self-check for cert_signed_data_oracle.mjs: generate an ed25519 key with
// Node, sign a message, verify it back through the SAME code path (SPKI ->
// createPublicKey -> verify(null, ...)). If this fails, the oracle is broken and
// any "no candidate accepted" answer is meaningless.

import { generateKeyPairSync, sign, verify, createPublicKey } from "node:crypto";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const { publicKey, privateKey } = generateKeyPairSync("ed25519");
const spkiDer = publicKey.export({ format: "der", type: "spki" });
const raw = spkiDer.subarray(spkiDer.length - 32);
const rebuilt = createPublicKey({
  key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
  format: "der",
  type: "spki",
});

const msg = Buffer.from("hello signed data", "utf8");
const sig = sign(null, msg, privateKey);
console.log(`sig length      : ${sig.length} (want 64)`);
console.log(`verify good msg : ${verify(null, msg, rebuilt, sig)}`);
console.log(
  `verify tampered : ${verify(null, Buffer.from("hello signed datA", "utf8"), rebuilt, sig)}`,
);
console.log(`raw pk == last32: ${raw.equals(spkiDer.subarray(spkiDer.length - 32))}`);

if (verify(null, msg, rebuilt, sig) !== true) {
  console.log("ORACLE SELF-CHECK FAILED");
  process.exitCode = 1;
} else {
  console.log("oracle self-check OK");
}