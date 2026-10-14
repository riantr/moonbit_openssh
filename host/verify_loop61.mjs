// host/verify_loop61.mjs -- Loop #61: the kex and host key axes, and the one
// function that had never been run.
//
// Loop #60 enforced "a client proposal may only name algorithms this client can
// actually run" over cipher and MAC, and said in its own AGENTS.md entry that
// kex and hostkey were out of scope. This closes that, and finds more.
//
// ## What was actually wrong, in order of weight
//
// 1. **`flow_on_reply` could never succeed.** It called
//    `derive_keys(shared_mpint, h, we_need)`; the signature is
//    `derive_keys(hash, shared_secret_mpint, we_need)`, and `derive_single`
//    concatenates `K || H || letter || session_id` (RFC 4253 7.2). So K1 was
//    computed as HASH(H || K || letter || H) and `session_id` came back as the
//    shared secret. The `session_id == h` assertion two lines later therefore
//    always failed. The failure was reported as `ProtocolError` -- "the peer's
//    bytes are malformed" -- for a bug that is entirely ours.
//
//    Nothing caught it because **the function has no caller**. `cmd/ssh_full_ws`
//    calls `flow_start` and stops. A function that has never run cannot have
//    been tested, and that is where its other two defects were hiding.
//
// 2. **`FLOW_WE_NEED = 64` was hardcoded.** Correct for chacha20-poly1305, and
//    silently the wrong length for anything else -- which is how defect 1 could
//    still produce a *successful* `Established` on a cipher we cannot run.
//
// 3. **"We cannot answer this algorithm" was reported as `ProtocolError`.**
//    The tree already made this split once, for `@cert-authority`
//    (`HostKeyCertUntrusted`), because reporting it as `HostKeyMismatch` walks
//    the user into `--kh-tofu`. Same rule, second application.
//
// ## What was checked and found clean, before anything was written
//
// I expected the host key list to be the real problem -- a client advertising
// RSA/ECDSA host keys it cannot verify would be a real security defect. It is
// not: `HostKey::verify` does ed25519 and ECDSA, and `verify_with_alg` adds the
// RSA path (Loop #38) precisely because RFC 8332 means the negotiated name is
// not the blob's type string. All five names are backed. Recorded here because
// "I checked and it was fine" is a result, and because the next person should
// not have to redo it.
//
// I also expected `cmd/ssh_full_ws` to carry a hand-copied proposal literal
// with the EtM name Loop #60 removed. It does not -- it calls
// `Proposal::default_client(false)`, and its own `make_server_kexinit_reply` is
// a mock *server*, which is exempt by design.
//
// ## Two false positives the checker produced, and what they taught
//
// The first honest run reported `default_client/strict=true` and
// `live_proposal_with_certs=true` as over-promising. Both wrong:
//
//   * `kex-strict-c-v00@openssh.com` is not a key exchange at all. OpenSSH
//     appends it in `kex_proposal_populate_entries` to signal strict-KEX, and
//     `ssh -Q kex` lists twelve algorithms that do not include it. Calling it
//     unimplemented means the fix under pressure is to delete the marker and
//     turn off strict KEX -- trading a security property for a green gate.
//   * `ssh-ed25519-cert-v01@openssh.com` is gated by **policy**, not by
//     implementation: Loop #53 parses and validates certificate structure but
//     refuses certificates as host keys. `ssh -Q key-plain` and
//     `ssh -Q key-cert` are two disjoint lists, which is the authority saying
//     exactly this.
//
// So a name list is not a uniform list of algorithms. The emitter now has four
// verdicts -- `ok`, `NO-PATH`, `MARKER`, `POLICY-GATED` -- and the gate asserts
// the classification rather than the binary.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
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
  console.log("building cmd/proposal_kat");
  const b = run("cmd", ["/c", "moon build cmd\\proposal_kat --target native"], { cwd: root });
  if (b.code !== 0) {
    bad("proposal_kat builds", b.out.split("\n").slice(-6).join(" | "));
    return finish();
  }
  ok("proposal_kat builds");

  const r = run("cmd", ["/c", "moon run cmd\\proposal_kat --target native"], { cwd: root });
  if (r.code !== 0) {
    bad("proposal_kat runs", r.out.split("\n").slice(-6).join(" | "));
    return finish();
  }
  ok("proposal_kat runs");
  const out = r.out;

  // ------------------------------------------------- A. the two axes -------
  console.log("");
  console.log("A. kex and hostkey runnability, checked against ssh -Q");

  const kexNames = lineValue(out, "RUNNABLE_KEX").split(",").filter(Boolean);
  const hkNames = lineValue(out, "RUNNABLE_HOSTKEY").split(",").filter(Boolean);

  expect(
    "two KEX algorithms are runnable",
    kexNames.length === 2 && kexNames.includes("curve25519-sha256") && kexNames.includes("diffie-hellman-group14-sha256"),
    kexNames.join(","),
  );
  expect(
    "five host key algorithms are verifiable",
    hkNames.length === 5,
    hkNames.join(","),
  );

  const sshQ = run("ssh", ["-Q", "kex"]);
  if (sshQ.code === 0) {
    const q = new Set(sshQ.out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
    for (const n of kexNames) expect(`ssh -Q kex knows ${n}`, q.has(n));
    // The authority for the MARKER verdict: it is absent from the algorithm list.
    expect(
      "ssh -Q kex does NOT list the strict-kex marker (so it is not an algorithm)",
      !q.has("kex-strict-c-v00@openssh.com"),
    );
  } else {
    skip("ssh -Q kex cross-check", "ssh unavailable");
  }

  const plain = run("ssh", ["-Q", "key-plain"]);
  const cert = run("ssh", ["-Q", "key-cert"]);
  const sig = run("ssh", ["-Q", "key-sig"]);
  if (plain.code === 0 && cert.code === 0 && sig.code === 0) {
    const p = new Set(plain.out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
    const c = new Set(cert.out.split(/\r?\n/).map((s) => s.trim()).filter(Boolean));
    const s = new Set(sig.out.split(/\r?\n/).map((x) => x.trim()).filter(Boolean));
    // `key-sig`, not `key-plain`. The first version of this check used
    // `key-plain` for all five names and failed on `rsa-sha2-256` /
    // `rsa-sha2-512` -- correctly, because those are *signature* algorithm
    // names (RFC 8332), not key types. `key-plain` lists `ssh-rsa`. Conflating
    // the two is the exact mistake `src/hostkey/sig_verify.mbt` documents at
    // length, and I made it in the checker that exists to prevent it.
    for (const n of hkNames) expect(`ssh -Q key-sig knows ${n}`, s.has(n), "key-sig");
    // Two disjoint lists -- the authority for POLICY-GATED.
    expect("ssh -Q key-cert is a separate list from key-plain", ![...hkNames].some((n) => c.has(n)));
    expect("the cert name in our proposal is a real OpenSSH certificate name", c.has("ssh-ed25519-cert-v01@openssh.com"));
    // And the names we deliberately do not implement, so the omission is a
    // decision rather than an oversight.
    expect("ssh-rsa is a plain host key we do not verify", p.has("ssh-rsa") && !hkNames.includes("ssh-rsa"));
    // The RSA names really are absent from key-plain, which is why the check
    // above had to move. Asserted so the distinction stays understood.
    expect("rsa-sha2-512 is a signature name, absent from key-plain", !p.has("rsa-sha2-512") && s.has("rsa-sha2-512"));
  } else {
    skip("ssh -Q key cross-check", "ssh unavailable");
  }

  // ------------------------------------- B. the proposal verdicts ----------
  console.log("");
  console.log("B. every client proposal is honorable on all four axes");

  const blocks = parseProposals(out);
  const clients = blocks.filter((b) => b.scope === "client");
  const servers = blocks.filter((b) => b.scope === "server");
  expect("five client proposals were reached", clients.length === 5, clients.map((c) => c.label).join(", "));

  for (const c of clients) {
    const badNames = c.names.filter((n) => n.tag === "NO-PATH");
    expect(
      `client proposal ${c.label} names only runnable algorithms`,
      badNames.length === 0,
      badNames.map((n) => `${n.kind}:${n.name}`).join(", "),
    );
    expect(`client proposal ${c.label} is honorable`, c.verdict === "honorable", c.verdict ?? "(none)");
    expect(`client proposal ${c.label} has no full-axis violation`, !c.verdictFull, c.verdictFull ?? "");
  }

  // The two verdicts that are neither ok nor broken. Asserted positively: a
  // classifier that answered `ok` for both would pass everything above.
  const strictBlock = clients.find((c) => c.label === "kexflow.default_client/strict=true");
  expect("the strict-kex proposal block was found", !!strictBlock);
  if (strictBlock) {
    const marker = strictBlock.names.find((n) => n.name === "kex-strict-c-v00@openssh.com");
    expect("the strict-kex marker is classified MARKER", marker?.tag === "MARKER", marker?.tag);
  }
  const certBlock = clients.find((c) => c.label === "sshclient.live_proposal_with_certs=true");
  expect("the cert proposal block was found", !!certBlock);
  if (certBlock) {
    const certName = certBlock.names.find((n) => n.name.includes("-cert-v01@openssh.com"));
    expect("the certificate name is classified POLICY-GATED", certName?.tag === "POLICY-GATED", certName?.tag);
    expect("the certificate name is NOT called NO-PATH", certName?.tag !== "NO-PATH", certName?.tag);
    // The block without certificates must not contain one.
    const plainBlock = clients.find((c) => c.label === "sshclient.live_proposal_with_certs=false");
    expect(
      "the no-certs proposal contains no certificate name",
      !plainBlock.names.some((n) => n.name.includes("-cert-v01@openssh.com")),
    );
  }

  // Recompute, without trusting the emitter's tags. Same reason as Loop #60's.
  const gateKex = new Set(kexNames);
  const gateHk = new Set(hkNames);
  for (const c of clients) {
    const disagree = c.names
      .filter((n) => n.kind === "kex" || n.kind === "hostkey")
      .filter((n) => {
        if (n.name === "kex-strict-c-v00@openssh.com") return n.tag !== "MARKER";
        if (n.name.includes("-cert-v01@openssh.com")) return n.tag !== "POLICY-GATED";
        const want = n.kind === "kex" ? gateKex.has(n.name) : gateHk.has(n.name);
        return n.tag !== (want ? "ok" : "NO-PATH");
      })
      .map((n) => `${n.name}:${n.tag}`);
    expect(`client proposal ${c.label}: gate's own table agrees on kex/hostkey`, disagree.length === 0, disagree.join(", "));
  }

  // The server fixture stays exempt, and now carries an unrunnable kex too.
  expect("one server-scope fixture was emitted", servers.length === 1, String(servers.length));
  const srv = servers[0] ?? { names: [], verdict: "" };
  expect("the peer fixture is still not judged", srv.verdict === "not-checked(scope=server)", srv.verdict);

  // ------------------------------- C. flow_on_reply's three defects --------
  console.log("");
  console.log("C. flow_on_reply: argument order, derived length, typed errors");

  const flow = stripComments(readFileSync(join(root, "src", "kexflow", "flow.mbt"), "utf8"));
  const flowBody = functionBody(flow, "pub fn flow_on_reply");
  expect("flow_on_reply was found", !!flowBody);
  if (flowBody) {
    // A labelled source check, and deliberately so: both parameters are
    // `FixedArray[Byte]`, so the MoonBit type system cannot catch a swap. This
    // is one of the few places a source assertion beats a unit test.
    const call = flowBody.match(/derive_keys\(([^,]+),\s*([^,]+),/);
    expect("flow_on_reply's derive_keys call was located", !!call);
    if (call) {
      expect("derive_keys receives H first", call[1].trim() === "h", call[1].trim());
      expect("derive_keys receives the shared secret second", call[2].trim() === "shared_mpint", call[2].trim());
    }
    expect("FLOW_WE_NEED is gone", !flow.includes("FLOW_WE_NEED"));
    // Not "the body mentions transport_params" -- a leftover mention satisfies
    // that while the length is still hardcoded, which is exactly how mutation B
    // slipped through the first time. The claim is that `we_need` *is* the
    // table's value, so assert the assignment, not the mention.
    expect(
      "the derivation length is seeded from the table's key length",
      /let\s+mut\s+we_need\s*=\s*we_key\b/.test(flowBody),
    );
    expect(
      "the derivation length accounts for the MAC key length",
      /we_need\s*=\s*we_mac\b/.test(flowBody),
    );
    expect(
      "we_need is never bound to a numeric literal",
      !/we_need\s*(?::\s*\w+\s*)?=\s*\d/.test(flowBody),
      (flowBody.match(/we_need\s*(?::\s*\w+\s*)?=\s*\d/) ?? [])[0],
    );
    // The old failure class: an unimplemented algorithm reported as malformed
    // peer bytes. Two error variants now, so the two are distinguishable.
    expect("FlowError has AlgorithmNotRunnable", flow.includes("AlgorithmNotRunnable"));
    expect("FlowError has CipherNotRunnable", flow.includes("CipherNotRunnable"));
    expect("the old kex/hostkey guard no longer returns ProtocolError",
      !/if neg\.kex_alg != "curve25519-sha256" \|\| neg\.hostkey_alg[\s\S]{0,120}return Failed\(ProtocolError\)/.test(flowBody));
  }

  // The contract the swap violated, pinned by a test rather than by reading code.
  console.log("");
  console.log("D. the argument-order contract has a test, and the suite passes");
  const t = run("cmd", ["/c", "moon test src\\kexflow"], { cwd: root });
  const total = t.out.match(/Total tests:\s*(\d+)/)?.[1];
  const failed = t.out.match(/failed:\s*(\d+)/)?.[1];
  expect("moon test src/kexflow passes", t.code === 0 && failed === "0", `${total} tests, ${failed} failed`);
  const kexflowTest = readFileSync(join(root, "src", "kexflow", "kexflow_test.mbt"), "utf8");
  expect(
    "the argument-order test exists",
    kexflowTest.includes("t12_derive_keys_argument_order"),
  );

  // ------------------------------- E. hostkey has one source of names -----
  console.log("");
  console.log("E. the host key name lists have one source, not two");
  const sigSrc = stripComments(readFileSync(join(root, "src", "hostkey", "sig_verify.mbt"), "utf8"));
  const agrees = functionBody(sigSrc, "pub fn HostKey::agrees_with_alg");
  expect("agrees_with_alg was found", !!agrees);
  if (agrees) {
    expect(
      "agrees_with_alg consults the named lists rather than inline literals",
      agrees.includes("ecdsa_p256_alg_names()") && agrees.includes("rsa_digest_of_keyname"),
    );
    // The whole point of the refactor: the union is computed, not written.
    expect(
      "no algorithm name is spelled as a bare literal inside agrees_with_alg",
      !/"(ssh-ed25519|ecdsa-sha2-[a-z0-9]+|rsa-sha2-[0-9]+)"/.test(agrees),
      (agrees.match(/"(ssh-ed25519|ecdsa-sha2-[a-z0-9]+|rsa-sha2-[0-9]+)"/) ?? [])[0],
    );
  }
  expect("verifiable_alg_names is exported", sigSrc.includes("pub fn verifiable_alg_names()"));

  return finish();
}

// ---------------------------------------------------------------------------

function lineValue(out, key) {
  const m = out.match(new RegExp(`^${key} (.*)$`, "m"));
  return m ? m[1].trim() : "";
}

function parseProposals(out) {
  const blocks = [];
  let cur = null;
  for (const raw of out.split(/\r?\n/)) {
    const line = raw.trimEnd();
    const head = line.match(/^PROPOSAL (\S+) scope=(\S+)$/);
    if (head) {
      cur = { label: head[1], scope: head[2], names: [], verdict: null, verdictStoc: null, verdictFull: null };
      blocks.push(cur);
      continue;
    }
    if (!cur) continue;
    const nm = line.match(/^\s+(\S+) name=(\S+) kind=(\S+) (\S+)$/);
    if (nm) {
      cur.names.push({ cat: nm[1], name: nm[2], kind: nm[3], tag: nm[4] });
      continue;
    }
    const v = line.match(/^\s+verdict=(.*)$/);
    if (v) cur.verdict = v[1];
    const vs = line.match(/^\s+verdict_stoc=(.*)$/);
    if (vs) cur.verdictStoc = vs[1];
    const vf = line.match(/^\s+verdict_full=(.*)$/);
    if (vf) cur.verdictFull = vf[1];
  }
  return blocks;
}

///|
/// Blank out comments before any source-text assertion.
///
/// The first version of section C matched `derive_keys(...)` inside the very
/// comment that documents the swap, and looked for `FLOW_WE_NEED` in a comment
/// that says "`FLOW_WE_NEED` was 64" -- three confident failures caused by the
/// gate reading its own documentation. A comment explaining a bug will always
/// contain the bug's text, so a textual gate that does not strip comments is
/// guaranteed to be wrong about any fix it documents.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .split("\n")
    .map((line) => {
      const t = line.trim();
      if (t.startsWith("//")) return "";
      // Trailing comments only, and only when the slashes are not inside a
      // string literal -- good enough here because the anchors are all code.
      const at = line.indexOf("//");
      return at < 0 ? line : line.slice(0, at);
    })
    .join("\n");
}

function functionBody(src, signature) {
  const start = src.indexOf(signature);
  if (start < 0) return "";
  let depth = 0;
  let seen = false;
  for (let i = start + signature.length; i < src.length; i++) {
    const ch = src[i];
    if (ch === "{") {
      depth++;
      seen = true;
    } else if (ch === "}") {
      depth--;
      if (seen && depth === 0) return src.slice(start, i + 1);
    }
  }
  return "";
}

function finish() {
  console.log("");
  if (skipped.length) {
    console.log(`skipped: ${skipped.length}`);
    for (const s of skipped) console.log(`  SKIP  ${s}`);
  }
  console.log(`loop61: ${checks - failures.length}/${checks} checks passed`);
  if (failures.length) {
    console.log("");
    for (const f of failures) console.log(`  FAIL  ${f}`);
    process.exitCode = 1;
  } else {
    console.log("ALL PASS");
  }
}

await main();