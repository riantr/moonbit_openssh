// host/loop92_init_rule.mjs -- the INIT extension rule, on its own.
//
// Loop #92's gate compares our SFTP server with the real
// `sftp-server.exe` reply by reply.  One of those replies -- the INIT --
// cannot be compared byte for byte, because its extension list belongs to
// the SERVER'S VERSION rather than to the protocol.  Measured on two
// machines with the real tool:
//
//   this machine  -- OpenSSH 7.9p1: 179 bytes, `statvfs` "2" plus
//                    `fstatvfs` "2"
//   the runner    -- the inbox Windows OpenSSH: 250 bytes, `statvfs` "2"
//                    plus four extensions this server does not have
//
// So the gate judges the INIT reply by RULES.  The rules live in
// `host/verify_loop92.mjs`, and this file exercises them against:
//
//   1. BOTH sets of real bytes, which are kept in
//      `host/loop92_init_replies.json` -- in the repository, so the rule
//      is checked against both machines' OpenSSH on every run;
//   2. three NEGATIVE controls, because a rule that cannot fail is not a
//      rule.
//
// It is a MODULE, and `host/verify_loop92.mjs` calls it: the rule and the
// checks that hold it up have to live and die together.  A separate gate
// file would be discovered by the CI as a step of its own (the engine
// globs `host/verify_loop*.mjs`), and then a rule and its evidence could
// be edited apart.
//
// Run: node host/loop92_init_rule.mjs   (also runs standalone)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");

let failures = 0;
let checks = 0;
const ok = (name, cond, detail = "") => {
  checks++;
  if (!cond) failures++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};

// ---------------------------------------------------------------- the rule
//
// This is a COPY of the rule in `host/verify_loop92.mjs`, and the copy is
// deliberate: a gate that tests the gate's own function by calling it
// cannot tell a rule that was weakened from a rule that was removed.  So
// the rule is stated HERE, in this file, and the gate's copy is compared
// against this one by the last check below.

const IMPLEMENTED_EXTS = ["posix-rename@openssh.com"];
const DECLARED_EXTS = [
  "statvfs@openssh.com",
  "fstatvfs@openssh.com",
  "hardlink@openssh.com",
  "fsync@openssh.com",
  "lsetstat@openssh.com",
];

// The reply body, WITHOUT the u32 length prefix:
//
//   u8 type (2 = FXP_VERSION) | u32 version | (string, string) pairs
function parseInit(body) {
  const b = Buffer.from(body, "hex");
  if (b.length < 5) return null;
  const version = b.readUInt32BE(1);
  const exts = new Map();
  let at = 5;
  while (at < b.length) {
    if (at + 4 > b.length) return null;
    const n = b.readUInt32BE(at);
    at += 4;
    if (at + n > b.length) return null;
    const name = b.toString("utf8", at, at + n);
    at += n;
    if (at + 4 > b.length) return null;
    const m = b.readUInt32BE(at);
    at += 4;
    if (at + m > b.length) return null;
    exts.set(name, b.toString("utf8", at, at + m));
    at += m;
  }
  return { version, exts };
}

function initDiffs(realHex, oursHex, implemented = IMPLEMENTED_EXTS, declared = DECLARED_EXTS) {
  const diffs = [];
  const real = parseInit(realHex);
  const ours = parseInit(oursHex);
  if (!real || !ours) return ["the INIT reply could not be parsed"];
  if (real.version !== ours.version) {
    diffs.push(`the protocol version differs: real=${real.version} ours=${ours.version}`);
  }
  for (const name of implemented) {
    if (!real.exts.has(name)) {
      diffs.push(`we implement ${name} and the real server does not declare it`);
    }
  }
  for (const name of implemented) {
    if (!ours.exts.has(name)) {
      diffs.push(`we implement ${name} but do not declare it`);
    }
  }
  for (const name of declared) {
    if (!ours.exts.has(name)) {
      diffs.push(`we declare ${name} in the contract but not in the reply`);
    }
  }
  return diffs;
}

// Remove one extension pair from a reply body.
function dropExt(hex, name) {
  const b = Buffer.from(hex, "hex");
  const nameBuf = Buffer.from(name, "utf8");
  let at = 5;
  while (at + 4 <= b.length) {
    const n = b.readUInt32BE(at);
    const start = at;
    at += 4;
    if (b.subarray(at, at + n).equals(nameBuf)) {
      at += n;
      const m = b.readUInt32BE(at);
      at += 4 + m;
      return Buffer.concat([b.subarray(0, start), b.subarray(at)]).toString("hex");
    }
    at += n;
    const m = b.readUInt32BE(at);
    at += 4 + m;
  }
  return null;
}

// ---------------------------------------------------------------- the data

// Run every check.  `ok` is the caller's own reporter, so that the rule
// and the checks that hold it up are counted in the SAME total as the
// gate's other checks -- a rule with its own count would be a rule whose
// failures could be reported separately, and separately is how they get
// missed.
export function runInitRuleChecks(ok) {
  const dataPath = path.join(HERE, "loop92_init_replies.json");
  const data = JSON.parse(fs.readFileSync(dataPath, "utf8"));
  const MACHINES = Object.keys(data.real_replies);

  for (const machine of MACHINES) {
    const real = data.real_replies[machine];
    const ours = data.our_replies[machine];
    const diffs = initDiffs(real, ours);
    ok(`the rule accepts the real reply from ${machine}`, diffs.length === 0,
      diffs.join("; "));
  }

  // The rule has to be able to fail.  Three ways it must go red:

  const base = data.real_replies["this_machine"];
  const baseOurs = data.our_replies["this_machine"];

  // 1. We stop declaring an extension we implement.
  const dropped = dropExt(baseOurs, "posix-rename@openssh.com");
  ok("the control data can actually remove an extension", dropped !== null);
  if (dropped !== null) {
    const diffs = initDiffs(base, dropped);
    ok("the rule refuses a reply that drops an implemented extension",
      diffs.length > 0, diffs.join("; "));
  }

  // 2. The protocol version differs.
  const wrongVersion = "02" + "00000004" + baseOurs.slice(10);
  {
    const diffs = initDiffs(base, wrongVersion);
    ok("the rule refuses a reply with a different protocol version",
      diffs.length > 0, diffs.join("; "));
  }

  // 3. We implement an extension the peer does not declare -- the case
  //    that would break a client, because it would send a request the
  //    peer answers with "8 Operation unsupported".
  {
    const name = "invented@openssh.com";
    const b = Buffer.from(baseOurs, "hex");
    const added = Buffer.concat([
      b,
      Buffer.alloc(4),
      Buffer.from(name, "utf8"),
      Buffer.from([0, 0, 0, 1]),
      Buffer.from("1", "utf8"),
    ]);
    added.writeUInt32BE(name.length, b.length);
    const diffs = initDiffs(base, added.toString("hex"), [...IMPLEMENTED_EXTS, name]);
    ok("the rule refuses a reply that implements an extension the peer lacks",
      diffs.length > 0, diffs.join("; "));
  }

  // And the gate's own copy of the rule has to be this one.  The gate
  // keeps its rule in `host/verify_loop92.mjs`; this check is what stops
  // the two from drifting apart -- and drift is how a rule gets quietly
  // weakened.
  {
    const gateSrc = fs.readFileSync(path.join(HERE, "verify_loop92.mjs"), "utf8");
    const names = ["posix-rename@openssh.com", "statvfs@openssh.com",
      "fstatvfs@openssh.com", "hardlink@openssh.com", "fsync@openssh.com",
      "lsetstat@openssh.com"];
    const missing = names.filter((n) => !gateSrc.includes(`"${n}"`));
    ok("the gate's copy of the rule names the same extensions",
      missing.length === 0, missing.join(", "));
    ok("the gate judges reply 0 by the rule, not byte for byte",
      /initDiffs\(real\.replies\[0\], ours\.replies\[0\]\)/.test(gateSrc));
  }
}

// Standalone: `node host/loop92_init_rule.mjs`.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log("=== Loop #92: the INIT extension rule ===");
  runInitRuleChecks(ok);
  console.log("");
  console.log(`${checks - failures}/${checks} checks passed`);
  if (failures) {
    console.log("failed:");
    process.exit(1);
  }
  console.log("ALL PASS");
}
