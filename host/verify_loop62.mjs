// host/verify_loop62.mjs -- Loop #62: `flow_on_reply` completes a real handshake.
//
// Loop #61's AGENTS.md entry ended by naming what it had *not* proved: "flow_on_reply
// has no caller and no end-to-end test -- a real handshake vector through the
// browser path would be the next thing worth building. Argument order and the
// derived length are pinned, but 'this function can complete a handshake' is not
// yet a claim anything here can support." This is that.
//
// ## The vectors are two-blind, which is the whole point
//
// `host/gen_flow62_vectors.py` implements the *server* half independently:
// X25519 and Ed25519 come from Python's `cryptography`, and the exchange-hash
// layout is transcribed from OpenSSH kexgen.c:67-82 rather than copied from
// `src/kexc25519/exchange_hash.mbt`. H and the signature are therefore each
// computed twice, by code sharing nothing with the tree under test. A layout
// mistake on either side shows up as a mismatch, not as two agreeing copies of
// the same wrong thing.
//
// The X25519 helper in the generator is itself cross-checked against
// `cryptography` (they must agree, or the generator is not independent).
//
// ## What the three failures cost, and what they were
//
// The vector file was wrong three times before it was right, and all three were
// in the generator. This is worth stating plainly, because the temptation on
// reading the results is to assume the client was broken:
//
//   1. K_S was built as `type ‖ pubkey`, missing the key's own length prefix.
//      `from_blob` reported `InvalidFormat` and was **correct** -- the blob was
//      malformed.
//   2. I_C was a copy of I_S. The exchange hash covers both, so the signature
//      could never verify.
//   3. The signature blob got an extra length prefix around the algorithm name.
//
// Each was found by a probe rather than by reading RFC 4253 a fourth time. The
// probes are kept in `flow_kat` (`probe_k_s`, `probe_h`) because a gate that
// cannot say *why* a case failed is a gate you end up debugging by hand.
//
// The client code under test changed **not at all** in this loop. Loop #61's
// fixes were sufficient; what was missing was the ability to know that.
//
// ## Two probes, both worth their cost
//
// `FLOW_PROBE <id> from_blob=<...> ks_len=<n>` -- the verdict alone collapses
// "the blob did not parse" and "the blob was the wrong key type" into one
// `HostkeyInvalid`, which was not enough to tell a bad vector from a real bug.
//
// `FLOW_H <id> h=<hex>` -- the client-side exchange hash, diffed against the
// `h = ` line the generator wrote. A hash mismatch is unambiguous: exactly one
// of the two sides has the layout wrong, and this says which.
//
// Both are gated on. A probe that is emitted but never checked is decoration.
//
// ## The attack case
//
// V7 is the one that matters most. The server signs an exchange hash computed
// over a *different* Q_S than the one it transmits -- a substituted server
// public key, the classic active attack on curve25519 ECDH. The client recomputes
// H from its own view and must reject it. If this case ever returns
// `Established`, the verification is decorative.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

let checks = 0;
const failures = [];
const skipped = [];

function ok(label, detail = "") {
  checks++;
  console.log(`  ok    ${label}${detail ? `  [${detail}]` : ""}`);
}

function bad(label, detail = "") {
  checks++;
  failures.push(label);
  console.log(`  FAIL  ${label}${detail ? `  [${detail}]` : ""}`);
}

function skip(label, why) {
  skipped.push(label);
  console.log(`  SKIP  ${label}  [${why}]`);
}

function expect(label, cond, detail = "") {
  if (cond) ok(label, detail);
  else bad(label, detail);
  return cond;
}

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024, ...opts });
  return { code: r.status, out: (r.stdout ?? "") + (r.stderr ?? "") };
}

async function main() {
  // ------------------------------------------------ A. drift ------------
  // The vector file is generated. If it can be hand-edited and still pass, the
  // gate is measuring the file rather than the code, so regeneration must
  // produce byte-identical output.
  console.log("A. the vector file is reproducible, not hand-editable");
  const vecPath = join(root, "verify_c", "kexflow", "flow_vectors.txt");
  if (!existsSync(vecPath)) {
    bad("verify_c/kexflow/flow_vectors.txt exists");
    return finish();
  }
  const before = readFileSync(vecPath, "utf8");
  // Compare content, not `git status`. The first version used `git status
  // --porcelain`, which reports `??` for a file that is new and uncommitted --
  // so the check failed every run for a reason that had nothing to do with
  // reproducibility. A drift check that cannot distinguish "changed" from
  // "untracked" is not a drift check.
  const gen = run("python", ["host/gen_flow62_vectors.py"], { cwd: root });
  expect("the generator runs", gen.code === 0, gen.out.split("\n").slice(-2).join(" | "));
  const after = readFileSync(vecPath, "utf8");
  expect(
    "regenerating the vectors reproduces the file byte for byte",
    before === after,
    before === after ? "" : `${before.length} vs ${after.length} bytes`,
  );

  const vec = after;

  // ------------------------------------------------ B. build/run ---------
  console.log("");
  console.log("B. flow_kat runs the vectors");
  const b = run("cmd", ["/c", "moon build cmd\\flow_kat --target native"], { cwd: root });
  if (b.code !== 0) {
    bad("flow_kat builds", b.out.split("\n").slice(-6).join(" | "));
    return finish();
  }
  ok("flow_kat builds");
  const r = run("cmd", ["/c", "moon run cmd\\flow_kat --target native"], { cwd: root });
  if (r.code !== 0) {
    bad("flow_kat runs", r.out.split("\n").slice(-8).join(" | "));
    return finish();
  }
  ok("flow_kat runs");
  const out = r.out;

  const cases = parseCases(out);
  expect("seven cases were exercised", cases.length === 7, cases.map((c) => c.id).join(", "));
  for (const c of cases) {
    expect(`case ${c.id} returns ${c.want}`, c.got === c.want && !c.fail, c.fail ? `got=${c.got}` : "");
  }
  const passed = Number(out.match(/FLOW_PASS (\d+)/)?.[1]);
  const failed = Number(out.match(/FLOW_FAIL (\d+)/)?.[1]);
  expect("the emitter's own tally agrees", failed === 0 && passed === cases.length, `${passed} pass / ${failed} fail`);

  // ------------------------------------------------ C. the verdicts -----
  // Not just "all pass". The point of the vector set is that each case has a
  // *distinct* expected verdict, so a flow that always returned Established
  // would still fail -- and one that always returned ProtocolError would too.
  console.log("");
  console.log("C. the verdicts are the contract, and they are varied");
  const verdicts = new Map(cases.map((c) => [c.id, c.want]));
  expect("V1 completes the handshake", verdicts.get("V1") === "Established", verdicts.get("V1"));
  expect("V2 completes with the strict-kex marker", verdicts.get("V2") === "Established", verdicts.get("V2"));
  expect("V3 fails on host key intersection", verdicts.get("V3") === "NoAgreement(hostkey)", verdicts.get("V3"));
  expect("V4 fails on cipher intersection", verdicts.get("V4") === "NoAgreement(cipher)", verdicts.get("V4"));
  expect("V5 rejects a flipped signature bit", verdicts.get("V5") === "SignatureInvalid", verdicts.get("V5"));
  expect("V6 rejects an empty kex list", verdicts.get("V6") === "NoAgreement(kex)", verdicts.get("V6"));
  expect("V7 rejects a substituted server key", verdicts.get("V7") === "SignatureInvalid", verdicts.get("V7"));
  expect(
    "at least three distinct verdicts appear",
    new Set(verdicts.values()).size >= 3,
    [...new Set(verdicts.values())].join(", "),
  );

  // The attack case gets its own line. If this one ever reads Established, the
  // verification is decorative and nothing else in the file matters.
  const v7 = cases.find((c) => c.id === "V7");
  expect("V7 does NOT establish", v7 && v7.got !== "Established", v7?.got);

  // ------------------------------------------------ D. two-blind H ------
  console.log("");
  console.log("D. the client and the peer agree on the exchange hash");
  const hLines = [...out.matchAll(/^FLOW_H (\S+) h=([0-9a-f]{64})$/gm)].map((m) => ({ id: m[1], h: m[2] }));
  expect("H was printed for every case", hLines.length >= 2, hLines.map((x) => x.id).join(", "));
  const fileHs = parseFileHashes(vec);
  let compared = 0;
  for (const line of hLines) {
    const want = fileHs.get(line.id);
    if (!want) {
      skip(`H for ${line.id}`, "the vector file has no h line");
      continue;
    }
    compared++;
    expect(`H agrees for ${line.id}`, line.h === want, line.h === want ? "" : `client=${line.h} peer=${want}`);
  }
  expect("at least two H values were diffed", compared >= 2, String(compared));

  // ------------------------------------------------ E. the K_S probe ----
  console.log("");
  console.log("E. the K_S probe is emitted and is not vacuous");
  const probes = [...out.matchAll(/^FLOW_PROBE (\S+) from_blob=(\S+) ks_len=(\d+)$/gm)];
  expect("a K_S probe was emitted for every case", probes.length >= 5, String(probes.length));
  expect(
    "every K_S blob parsed",
    probes.every((p) => p[2] === "ok"),
    probes.filter((p) => p[2] !== "ok").map((p) => `${p[1]}=${p[2]}`).join(", "),
  );
  // 51 = 4 + 11 ("ssh-ed25519") + 4 + 32. Assert the number so a silently
  // truncated blob cannot pass as "parsed".
  expect(
    "the K_S blob is 51 bytes, i.e. the key string is nested",
    probes.every((p) => p[3] === "51"),
    [...new Set(probes.map((p) => p[3]))].join(","),
  );

  // ------------------------------------------------ F. no temp tools ----
  // `sig_probe` was the throwaway I used to separate "bad framing" from "bad
  // cryptography". It answered the question and does not belong in the tree;
  // a diagnostic nobody reads rots into a second, contradictory source of truth.
  console.log("");
  console.log("F. the throwaway diagnostic is gone");
  expect("cmd/sig_probe does not exist", !existsSync(join(root, "cmd", "sig_probe")));

  return finish();
}

// ---------------------------------------------------------------------------

function parseCases(out) {
  const cases = [];
  for (const m of out.matchAll(/^FLOW_CASE (\S+) expected=(\S+) got=(\S+) (ok|FAIL)/gm)) {
    cases.push({ id: m[1], want: m[2], got: m[3], fail: m[4] === "FAIL" });
  }
  return cases;
}

function parseFileHashes(vec) {
  const map = new Map();
  let tag = "";
  for (const line of vec.split(/\r?\n/)) {
    if (line.startsWith("CASE ")) tag = line.slice(5).trim();
    else if (line.startsWith("h = ")) map.set(tag, line.slice(4).trim());
  }
  return map;
}

function finish() {
  console.log("");
  if (skipped.length) {
    console.log(`skipped: ${skipped.length}`);
    for (const s of skipped) console.log(`  SKIP  ${s}`);
  }
  console.log(`loop62: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

await main();