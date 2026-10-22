#!/usr/bin/env node
// host/verify_loop80.mjs -- Loop #80: the SSH agent, and publickey
// authentication with a key the client never sees.
//
// ## What is being claimed
//
// `ssh-agent` holds private keys so the client does not have to. The client
// asks it two things -- "which keys do you have?" and "sign this" -- over a
// local transport, and then uses the returned signature to authenticate.
//
// The claim this gate has to earn is not "we spoke to an agent". It is:
//
//   1. the **wire format** of the agent protocol is right, byte for byte,
//      checked against an implementation written from OpenSSH's `authfd.c`
//      rather than from ours;
//   2. a real OpenSSH server accepts a publickey authentication whose
//      signature was produced by the agent, and the bytes we signed are the
//      bytes RFC 4252 section 7 says to sign;
//   3. the **probe** (RFC 4252 section 7, boolean FALSE) really comes first,
//      so a key the server will not accept never reaches the agent.
//
// The third one is the reason this gate runs a second agent. "The agent was
// never asked to sign" is not something the transcript of a successful run
// can show -- a successful run signs exactly once whether or not the probe
// happened. So the negative case gets its own agent, holding a key the
// server does not accept, and the assertion is that its sign counter is
// still zero. A client that signed first would show one.
//
// ## What is deliberately not claimed
//
// The real agent on Windows is reached over a **named pipe**
// (\\.\pipe\openssh-ssh-agent), and on unix over a unix domain socket. This
// gate uses a TCP mock instead, because the agent protocol does not care
// which local transport carries it -- and because that is the same property
// the browser path will need. The named-pipe transport is not implemented
// yet, and this gate does not pretend otherwise.
//
// 用法: node host/verify_loop80.mjs [--skip-regression]

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sshUserInfo } from "./ssh_user.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop80");
const SKIP_REGRESSION = process.argv.includes("--skip-regression");

const SSHD_PORT = 22291;
const AGENT_PORT = 18801;
const AGENT_PORT_ALT = 18802;

// The account this gate authenticates as. Derived, never written down: see
// host/ssh_user.mjs for why.
const USER_INFO = sshUserInfo();
const USER = USER_INFO.name;

// The pin is explicit: the key is accepted, nothing is stored, and the
// developer's own known_hosts is never touched.
const PIN_ARGS = ["--kh-tofu", "--kh-host", "127.0.0.1", "--known-hosts-text", ""];

let failures = 0;
let checks = 0;
const section = (t) => console.log(`\n${t}`);
const ok = (name, cond, detail = "") => {
  checks++;
  if (!cond) failures++;
  console.log(`  ${cond ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
};

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

function norm(s) {
  return `${s}`.replace(/\r\n/g, "\n");
}

function hashOut(out) {
  return createHash("sha256").update(norm(out)).digest("hex").slice(0, 16);
}

function lineOf(text, key) {
  const m = norm(text).match(new RegExp(`^${key}: (.*)$`, "m"));
  return m ? m[1] : undefined;
}

function tap(child) {
  child.tapBuf = "";
  for (const stream of [child.stdout, child.stderr]) {
    if (stream) stream.on("data", (d) => { child.tapBuf += d.toString(); });
  }
  return child;
}

async function waitForText(child, needle, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((child.tapBuf || "").includes(needle)) return true;
    await new Promise((r) => setTimeout(r, 120));
  }
  console.log(`      (never saw "${needle}"; saw: ${(child.tapBuf || "").trim().slice(0, 300)})`);
  return false;
}

// ---------------------------------------------------------------------------
// An independent reader for the SSH blobs, written from RFC 4252 section 7
// and RFC 5656 section 3.1 -- not from this repository's MoonBit code.
// ---------------------------------------------------------------------------
function reader(buf) {
  let off = 0;
  return {
    get remaining() { return buf.length - off; },
    str(label) {
      if (off + 4 > buf.length) throw new Error(`${label}: truncated length`);
      const n = buf.readUInt32BE(off);
      off += 4;
      if (off + n > buf.length) throw new Error(`${label}: truncated body`);
      const s = buf.subarray(off, off + n);
      off += n;
      return s;
    },
    u8(label) {
      if (off + 1 > buf.length) throw new Error(`${label}: truncated byte`);
      const v = buf[off];
      off += 1;
      return v;
    },
    done(label) {
      if (off !== buf.length) throw new Error(`${label}: ${off} consumed of ${buf.length}`);
    },
  };
}

const sshString = bytes => {
  const out = Buffer.alloc(4 + bytes.length);
  out.writeUInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(out, 4);
  return out;
};

/** The bytes RFC 4252 section 7 says to sign. */
function parseSignedBlob(hex) {
  const b = Buffer.from(hex, "hex");
  const r = reader(b);
  const f = {
    session_id: r.str("session_id"),
    msg_type: r.u8("msg_type"),
    user: r.str("user"),
    service: r.str("service"),
    method: r.str("method"),
    have_sig: r.u8("have_sig"),
    pkalg: r.str("pkalg"),
    pkblob: r.str("pkblob"),
  };
  r.done("signed_blob");
  return f;
}

/** What OpenSSH rebuilds from its own copy of the request. */
function rebuildSignedBlob(f) {
  return Buffer.concat([
    sshString(f.session_id),
    Buffer.from([f.msg_type]),
    sshString(f.user),
    sshString(f.service),
    sshString(f.method),
    Buffer.from([f.have_sig]),
    sshString(f.pkalg),
    sshString(f.pkblob),
  ]);
}

/** SSH_MSG_USERAUTH_REQUEST payload, with the signature appended. */
function parseRequest(hex) {
  const b = Buffer.from(hex, "hex");
  const r = reader(b);
  const f = {
    user: r.str("user"),
    service: r.str("service"),
    method: r.str("method"),
    have_sig: r.u8("have_sig"),
    pkalg: r.str("pkalg"),
    pkblob: r.str("pkblob"),
    sig: r.str("sig"),
  };
  r.done("request");
  return f;
}

/** The RFC 4252 section 7 probe: boolean FALSE, and no signature field. */
function parseProbe(hex) {
  const b = Buffer.from(hex, "hex");
  const r = reader(b);
  const f = {
    user: r.str("user"),
    service: r.str("service"),
    method: r.str("method"),
    have_sig: r.u8("have_sig"),
    pkalg: r.str("pkalg"),
    pkblob: r.str("pkblob"),
  };
  r.done("probe");
  return f;
}

/** RFC 5656 section 3.1.2: string alg, string (mpint r || mpint s). */
function parseSigBlob(hex) {
  const b = Buffer.from(hex, "hex");
  const r = reader(b);
  const alg = r.str("alg");
  const inner = r.str("signature_blob");
  r.done("sig_blob");
  const ir = reader(inner);
  const rb = ir.str("r");
  const sb = ir.str("s");
  ir.done("signature_blob(inner)");
  return { alg: alg.toString("ascii"), r: rb, s: sb };
}

/** A conformant mpint is minimal-length, with a sign pad iff it is needed. */
function mpintOk(b) {
  if (b.length === 0) return false;
  if (b[0] === 0x00) return b.length > 1 && (b[1] & 0x80) !== 0;
  return (b[0] & 0x80) === 0;
}

// ---------------------------------------------------------------------------
// The mock agent and the server.
// ---------------------------------------------------------------------------
function startAgent(port, extra = []) {
  return tap(spawn("python", ["host/agent_mock.py", "--port", String(port), ...extra], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
}

function startSshd(port, name) {
  return tap(spawn("node", ["host/sshd_setup.mjs", "--port", String(port), "--name", name], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
}

function stopSshd(name) {
  spawnSync("node", ["host/sshd_setup.mjs", "--stop", "--name", name], { cwd: ROOT, encoding: "utf8" });
}

const CLIENT_EXE = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");

// The client is run through an argv **array**, never a command string: on
// Windows an empty argument cannot survive a shell, and `--known-hosts-text ''`
// is exactly such an argument.
//
// The timeout is not politeness. A defect in the agent protocol can make the
// client and the peer wait for each other for ever: if the client writes a
// frame whose length prefix is wrong, the agent reads the wrong number of
// bytes and blocks, and the client blocks waiting for a reply that will never
// come. That is a real deadlock, not a slow run, and a gate that hangs on it
// measures nothing -- the mutation run would sit there until the harness's
// own limit killed it. So the client gets a deadline, and a client that
// misses it simply has no "result:" line, which fails the check that wanted
// one.
const CLIENT_TIMEOUT_MS = 60000;

function runClient(extra) {
  const r = spawnSync(
    CLIENT_EXE,
    ["--user", USER, ...PIN_ARGS, "--port", String(SSHD_PORT), ...extra],
    {
      cwd: ROOT, encoding: "utf8", errors: "replace",
      maxBuffer: 64 * 1024 * 1024, timeout: CLIENT_TIMEOUT_MS,
    },
  );
  const out = norm(`${r.stdout || ""}${r.stderr || ""}`);
  if (r.error) {
    return out + `\n(the client did not finish: ${r.error.message})\n`;
  }
  return out;
}

async function main() {
  console.log("verify_loop80 -- the SSH agent, and publickey auth with an agent-held key\n");
  mkdirSync(WORK, { recursive: true });

  // ------------------------------------------------------------------- G1 --
  section("G1: the agent wire format, byte for byte, against an independent oracle");
  const oracle = spawnSync("python", ["host/agent_oracle.py", "--json"], {
    cwd: ROOT, encoding: "utf8", errors: "replace",
  });
  const oracleText = norm(`${oracle.stdout || ""}${oracle.stderr || ""}`);
  ok("the oracle runs", oracle.status === 0, oracle.status === 0 ? "" : oracleText.slice(-300));
  let ref = {};
  try {
    ref = JSON.parse(oracle.stdout);
  } catch { /* reported above */ }
  ok("the oracle emits the vectors", ref && ref.frame_request_identities_hex);

  // 4 target x 2 mode, byte identical. The agent protocol is pure byte
  // assembly -- no socket anywhere -- so it has to come out the same
  // everywhere.
  const TARGETS = ["native", "js", "wasm", "wasm-gc"];
  const MODES = ["debug", "release"];
  const runs = [];
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(["run", "cmd/agent_kat", "--target", t, "-d", m]);
      const out = norm(r.out);
      runs.push({ t, m, out, hash: hashOut(out), code: r.code });
    }
  }
  const refHash = runs[0].hash;
  const allRan = runs.every((r) => r.code === 0);
  ok("cmd/agent_kat runs on 4 target x 2 mode", allRan,
    allRan ? refHash : runs.filter((r) => r.code !== 0).map((r) => `${r.t}/${r.m}`).join(" "));
  ok("4 target x 2 mode byte-identical", allRan && runs.every((r) => r.hash === refHash),
    allRan ? refHash : runs.filter((r) => r.hash !== refHash).map((r) => `${r.t}/${r.m}`).join(" "));
  const kat = runs[0].out;
  ok("the KAT reports OK", lineOf(kat, "result") === "OK", lineOf(kat, "result"));

  // Every byte the KAT prints has to equal the oracle's.
  const pairs = [
    ["frame_request_identities", "frame_request_identities_hex"],
    ["identities_payload", "identities_payload_hex"],
    ["sign_request_payload", "sign_request_payload_hex"],
    ["frame_sign_request", "frame_sign_request_hex"],
    ["sign_response_payload", "sign_response_payload_hex"],
    ["sig_blob", "sig_blob_hex"],
    ["probe_payload", "probe_payload_hex"],
    ["signed_blob", "signed_blob_hex"],
    ["pubkey_blob", "pubkey_blob_hex"],
    ["data", "data_hex"],
  ];
  for (const [mine, theirs] of pairs) {
    const got = (lineOf(kat, mine) || "").toLowerCase();
    const want = (ref[theirs] || "").toLowerCase();
    ok(`KAT ${mine} == oracle ${theirs}`, got.length > 0 && got === want,
      got === want ? `${got.length / 2} bytes` : `ours=${got.slice(0, 48)} theirs=${want.slice(0, 48)}`);
  }
  ok("KAT key_type matches the oracle", lineOf(kat, "key_type") === ref.key_type,
    `${lineOf(kat, "key_type")}`);
  ok("KAT comment matches the oracle", lineOf(kat, "comment") === ref.comment,
    `${lineOf(kat, "comment")}`);

  // The KAT also has to *parse* what it built, not only build it.
  ok("the identities payload parses back to one identity", lineOf(kat, "identities_count") === "1",
    `${lineOf(kat, "identities_count")}`);
  ok("the parsed identity keeps its comment", lineOf(kat, "identity_comment") === ref.comment,
    `${lineOf(kat, "identity_comment")}`);
  ok("the parsed identity keeps its key type", lineOf(kat, "identity_key_type") === ref.key_type,
    `${lineOf(kat, "identity_key_type")}`);
  ok("the sign response parses back to the same signature",
    (lineOf(kat, "parsed_sig_blob") || "").toLowerCase() === (lineOf(kat, "sig_blob") || "").toLowerCase());

  // The bounds. Every length in the agent protocol is given by the peer, so
  // each one has to be checked before it is used to allocate.
  ok("no KAT assertion failed", (kat.match(/: FAIL\b/g) || []).length === 0,
    (kat.match(/: FAIL\b/g) || []).join(" "));
  for (const k of ["reply_limit", "reply_zero_length", "identities_count_limit",
    "identities_truncated", "signature_truncated"]) {
    ok(`the KAT refuses a bad ${k.replace(/_/g, " ")}`, lineOf(kat, k) === "PASS",
      `${lineOf(kat, k)}`);
  }

  // The framing rule, stated as a measurement: the length prefix counts the
  // type byte and the payload, and not itself.
  {
    const f = Buffer.from(ref.frame_request_identities_hex, "hex");
    ok("the frame length counts the type byte and not itself",
      f.readUInt32BE(0) === f.length - 4 && f[4] === 0x0b, `${f.length} bytes`);
    const s = Buffer.from(ref.frame_sign_request_hex, "hex");
    ok("the sign request frame length counts the type byte and not itself",
      s.readUInt32BE(0) === s.length - 4 && s[4] === 0x0d, `${s.length} bytes`);
  }

  // ------------------------------------------------------------------- G2 --
  section("G2: a real OpenSSH server accepts a signature the agent produced");
  const build = moon(["build", "cmd/ssh_live", "--target", "native"]);
  ok("cmd/ssh_live builds for native", build.code === 0,
    build.code === 0 ? "" : build.out.slice(-300));

  // The server has to hold the public half of the key the agent holds.
  const keys = spawnSync("python", ["host/ecdsa_auth_oracle.py", "--json", "--authorized-keys",
    ".loop31/sshd/authorized_keys"], { cwd: ROOT, encoding: "utf8", errors: "replace" });
  ok("wrote authorized_keys for the test key", keys.status === 0,
    keys.status === 0 ? "" : norm(`${keys.stdout || ""}${keys.stderr || ""}`).slice(-200));

  const agent = startAgent(AGENT_PORT);
  ok("the mock agent is listening", await waitForText(agent, "listening on 127.0.0.1:"));

  const sshd = startSshd(SSHD_PORT, "loop80");
  ok("private sshd is up", await waitForText(sshd, "sshd listening"));

  // Everything from here to the end of G3 runs with two agents and a server
  // alive, so it is wrapped: a gate that throws in the middle must not leave
  // an sshd behind. The leak Loop #40 paid for is real -- `sshd_setup.mjs`
  // parks for ever, so a gate that dies early turns the next run's port into
  // "address already in use".
  const agentAltRef = { proc: null };
  try {
  const text = runClient(["--agent", `127.0.0.1::${AGENT_PORT}`]);
  for (const l of text.split("\n")) {
    if (/^(result|user|method|key_type|identity_)/.test(l)) console.log(`      ${l.trim()}`);
  }
  ok("result: USERAUTH_SUCCESS", text.includes("result: USERAUTH_SUCCESS"),
    text.includes("result: USERAUTH_SUCCESS") ? "" : text.split("\n").slice(-6).join(" | "));
  ok("the method is publickey with the ECDSA algorithm",
    text.includes("method: publickey") && text.includes("key_type: ecdsa-sha2-nistp256"));
  ok("the identity came from the agent", text.includes("identity_comment: " + ref.comment),
    lineOf(text, "identity_comment"));

  // The agent's own account of what it was asked: one identity request, one
  // signature request, in that order.
  ok("the agent was asked for its identities", await waitForText(agent, "REQUEST_IDENTITIES"));
  ok("the agent was asked to sign", await waitForText(agent, "SIGN_REQUEST"));
  ok("the agent served exactly one identity and one signature",
    /served identities=1 signs=1/.test(agent.tapBuf || ""),
    (agent.tapBuf || "").split("\n").filter((l) => l.includes("served")).join(" | "));

  // The signed bytes, the request and the signature, judged here rather than
  // by the server.
  const signedHex = lineOf(text, "signed_blob");
  const sigHex = lineOf(text, "sig_blob");
  const reqHex = lineOf(text, "request");
  const probeHex = lineOf(text, "probe");
  ok("the client printed the signed blob, the signature and the request",
    !!signedHex && !!sigHex && !!reqHex);
  if (signedHex && sigHex && reqHex) {
    let signed = null;
    let req = null;
    let sig = null;
    let err = null;
    try {
      signed = parseSignedBlob(signedHex);
      req = parseRequest(reqHex);
      sig = parseSigBlob(sigHex);
    } catch (e) {
      err = String(e.message || e);
    }
    ok("all three blobs parse under the RFC layout", !err, err || "");

    const same = (k) => signed && req && Buffer.compare(signed[k], req[k]) === 0;
    ok("the signed blob's fields are the request's fields",
      !err && same("user") && same("service") && same("method") &&
      same("pkalg") && same("pkblob") && signed.have_sig === req.have_sig && signed.have_sig === 1,
      err || "");
    ok("the server-side reconstruction is byte-identical",
      !err && rebuildSignedBlob(signed).equals(Buffer.from(signedHex, "hex")),
      err || "");
    ok("the signed blob is the request minus the signature",
      !err && Buffer.compare(req.sig, Buffer.from(sigHex, "hex")) === 0);
    ok("the signature blob wraps r||s in one outer string",
      !err && sig.alg === "ecdsa-sha2-nistp256" && mpintOk(sig.r) && mpintOk(sig.s),
      err || "");
    ok("the signature verifies over exactly the bytes we signed",
      !err && verifySignature(signedHex, sigHex, req ? req.pkblob.toString("hex") : ""),
      err || "");
  }

  // The probe: a well-formed RFC 4252 section 7 request with boolean FALSE.
  if (probeHex) {
    let probe = null;
    let err = null;
    try {
      probe = parseProbe(probeHex);
    } catch (e) {
      err = String(e.message || e);
    }
    ok("the probe parses under the RFC layout", !err, err || "");
    ok("the probe's boolean is FALSE -- this is the probe, not the signed request",
      !err && probe.have_sig === 0, err || `have_sig=${probe && probe.have_sig}`);
    ok("the probe names the publickey method",
      !err && probe.method.toString("ascii") === "publickey");
    ok("the probe carries the agent's public key",
      !err && Buffer.compare(probe.pkblob, Buffer.from(ref.pubkey_blob_hex, "hex")) === 0);
    ok("the probe asks for the ssh-connection service",
      !err && probe.service.toString("ascii") === "ssh-connection");
  } else {
    ok("the probe was printed", false, "no probe line");
  }

  // ------------------------------------------------------------------- G3 --
  section("G3: the probe comes first -- a key the server rejects never reaches the agent");
  // A second agent, holding a key the server does not accept. Its private
  // key is d=2; only the *public* half matters here, because the client must
  // never get as far as asking for a signature.
  const agentAlt = startAgent(AGENT_PORT_ALT, ["--key-d", "2"]);
  agentAltRef.proc = agentAlt;
  ok("the second mock agent is listening", await waitForText(agentAlt, "listening on 127.0.0.1:"));
  const text2 = runClient(["--agent", `127.0.0.1::${AGENT_PORT_ALT}`]);
  for (const l of text2.split("\n")) {
    if (/^(result|error|reason)/.test(l)) console.log(`      ${l.trim()}`);
  }
  ok("result: FAILED", text2.includes("result: FAILED"));
  ok("the failure is ProbeRejected -- the server did not accept the key",
    text2.includes("error: ProbeRejected"), lineOf(text2, "error"));
  ok("the agent was asked for its identities",
    await waitForText(agentAlt, "REQUEST_IDENTITIES"));
  ok("the agent was NEVER asked to sign -- the probe gated it",
    !/SIGN_REQUEST/.test(agentAlt.tapBuf || ""),
    (agentAlt.tapBuf || "").split("\n").filter((l) => l.includes("SIGN")).join(" | "));
  ok("the agent served one identity and zero signatures",
    /served identities=1 signs=0/.test(agentAlt.tapBuf || ""),
    (agentAlt.tapBuf || "").split("\n").filter((l) => l.includes("served")).join(" | "));

  } finally {
    if (agentAltRef.proc) agentAltRef.proc.kill();
    agent.kill();
    sshd.kill();
    stopSshd("loop80");
  }

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    section("regression: the earlier loops must not move");
    const BASELINE = {
      u128_test: "1bbbc364fb3d5e51",
      fastpow_test: "9707cf997769eddb",
      bigint_test: "12ff7ed89fd9d856",
      kexdh_test: "afbca72be34dfba2",
      rsa_test: "7382ee95fe7d6677",
      rsa2048_test: "dffb73d5452ae5e6",
      ecdsa_test: "d78cd820e9ea2317",
    };
    for (const [name, want] of Object.entries(BASELINE)) {
      const r = moon(["run", `cmd/${name}`, "--target", "native"]);
      const got = hashOut(r.out);
      ok(`${name} unchanged`, got === want, `${got}${got === want ? "" : ` (baseline ${want})`}`);
    }
    for (const [label, script] of [["loop78", "host/verify_loop78.mjs"], ["loop79", "host/verify_loop79.mjs"]]) {
      const r = spawnSync("node", [script], { cwd: ROOT, encoding: "utf8", errors: "replace" });
      const t = norm(`${r.stdout || ""}${r.stderr || ""}`);
      const m = t.match(/(\d+)\/(\d+) checks/);
      ok(`${label} harness still green`, r.status === 0 && t.includes("PASS"),
        m ? `${m[1]}/${m[2]}` : t.slice(-200));
    }
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: ${checks - failures}/${checks} checks passed`);
  if (failures) {
    console.log("  a red run means one of the claims above did not hold");
    process.exit(1);
  }
  console.log("  the agent protocol was pinned byte for byte against an independent");
  console.log("  implementation, a real OpenSSH server accepted a signature the agent");
  console.log("  produced, and a key the server rejects never reached the agent at all.");
  process.exit(0);
}

// Ask an implementation that shares no code with this repository whether the
// signature really is a signature over exactly the bytes we claim.
function verifySignature(signedHex, sigHex, pubkeyHex) {
  if (!pubkeyHex) return false;
  const r = spawnSync("python", ["host/agent_sig_verify.py", signedHex, sigHex, pubkeyHex], {
    cwd: ROOT, encoding: "utf8", errors: "replace",
  });
  if (r.status !== 0) {
    console.log(`      (signature verifier said: ${norm(`${r.stdout || ""}${r.stderr || ""}`).trim()})`);
  }
  return r.status === 0 && norm(r.stdout || "").trim() === "OK";
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
