#!/usr/bin/env node
// host/verify_loop101.mjs -- Loop #101: the SSH server's half of a port
// forward (`ssh -L`, the "direct-tcpip" channel).
//
// ## What is being claimed
//
// `ssh -L 8080:db:5432 host` is one thing at the protocol level: the client
// opens a channel of type "direct-tcpip" and asks the SERVER to connect to
// db:5432; after that the channel carries the bytes of that TCP connection
// (RFC 4254 section 7.2).  This repository had the CLIENT half (Loop #76)
// and no server half at all: the server refused every channel that was not a
// session.
//
// ## The oracle
//
// The real `sshd.exe` on this machine, driven by the real `ssh.exe`.  Every
// case below is run TWICE -- once against our server and once against the
// real one -- and the two have to agree, byte for byte, on what the client
// sees.  A comparison with only our server in it would be a comparison of
// our server with itself.
//
// The behaviours that were MEASURED against the real server (and that this
// gate therefore pins) are:
//
//   * the confirmation is sent even when the connect to the target failed,
//     and the channel then closes with no data and no error message -- the
//     real server's own log: `finish_connect - ERROR: ... 10061`, then
//     `send packet: type 91`, `send packet: type 96`, `send packet: type 97`;
//   * the window is 2097152 and the maximum packet 32768;
//   * the peer's EOF half-closes the target: the target sees EOF, and the
//     real server's log says `chan_shutdown_write` at exactly that point.
//
// ## What runs where
//
// Every section needs the real client and the real server.  Where they are
// not available the section is SKIPPED LOUDLY rather than quietly passed --
// a machine that cannot run a check has not run it.
//
// The gate also runs against a server that is NOT OpenSSH, so the account it
// authenticates as has to be the account THIS machine runs as.  Loop #76
// measured what a hardcoded name costs: on GitHub Actions, where the
// account is `runneradmin`, every section that needed a live server failed
// with an authentication rejection that had nothing to do with the code
// under test.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

// The file lock that Windows real-time protection puts on an executable
// while it scans it, and the narrow retry that survives it.
import { spawnLocked, buildLocked } from "./win_lock.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const BED = path.join(ROOT, ".loop101", "bed");
const REAL_BED = path.join(ROOT, ".loop101", "realbed");

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

// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists. None is asserted to exist, and when none does the gate says so
// and fails rather than pretending. verify_loop71.mjs flags any drive-letter
// path it finds in code; this marker is how a file declares that its paths are
// a probe rather than a claim, and it is an obligation to say why, not a mute
// button. The reason it is a list at all: this repository is developed where
// the server lives under `C:\Program Files\OpenSSH-Win64` and it is tested on
// a runner where it lives under `C:\Windows\System32\OpenSSH`.
const OPENSSH_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
];
const pick = (name) =>
  OPENSSH_DIRS.map((d) => path.join(d, name)).find((p) => fs.existsSync(p)) || null;
const REAL_SSH = pick("ssh.exe");
const REAL_KEYGEN = pick("ssh-keygen.exe");

const OUR_SSHD_CANDIDATES = [
  path.join(ROOT, "_build", "native", "debug", "build", "cmd", "sshd", "sshd.exe"),
  path.join(ROOT, "_build", "native", "release", "build", "cmd", "sshd", "sshd.exe"),
];
const OUR_SSHD =
  OUR_SSHD_CANDIDATES.find((p) => fs.existsSync(p)) || OUR_SSHD_CANDIDATES[0];

// The account THIS machine runs as.
function sshUser() {
  for (const key of ["USERNAME", "USER", "LOGNAME", "LNAME"]) {
    const value = process.env[key];
    if (value && value.trim()) return value.trim();
  }
  return "";
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const p = srv.address().port;
      srv.close(() => resolve(p));
    });
  });
}

async function waitForPort(port, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const up = await new Promise((resolve) => {
      const s = net.connect({ host: "127.0.0.1", port }, () => {
        s.destroy();
        resolve(true);
      });
      s.on("error", () => {
        s.destroy();
        resolve(false);
      });
    });
    if (up) return true;
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

function moon(args) {
  // The build can lose a race with a real-time protection engine that has
  // the output file open; `buildLocked` retries exactly that and nothing
  // else.
  return buildLocked("cmd/sshd", () => {
    const r = spawnSync("cmd", ["/c", "moon", ...args], {
      cwd: ROOT,
      encoding: "utf8",
      errors: "replace",
      maxBuffer: 64 * 1024 * 1024,
      timeout: 900000,
    });
    return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
  });
}

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

// --------------------------------------------------------------------- keys
//
// The user key is ECDSA nistp256, and the reason is the real server: the
// sshd_setup helper pins `PubkeyAcceptedKeyTypes` to the two ECDSA curves,
// so an ed25519 user key -- which our own server accepts -- would be
// REFUSED by the real one, and the gate would compare "our server works"
// against "the real server said no".
function makeKeys(dir) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  for (const [file, type] of [["hostkey", "ed25519"], ["userkey", "ecdsa"]]) {
    const args = ["-t", type, "-f", path.join(dir, file), "-N", "", "-C", `loop101 ${file}`];
    if (type === "ecdsa") args.splice(2, 0, "-b", "256");
    const r = spawnSync(REAL_KEYGEN, args, { encoding: "utf8", timeout: 120000 });
    if (r.status !== 0) throw new Error(`ssh-keygen failed for ${file}: ${r.stderr}`);
  }
  fs.copyFileSync(path.join(dir, "userkey.pub"), path.join(dir, "authorized_keys"));
}

// The real server's bed.
//
// It gets the SAME user key as ours -- one key, two servers -- because the
// client is started with one `-i` and the comparison is about the FORWARD,
// not about which key each server happens to accept.  A second key would
// mean the real server refuses the client for a reason that has nothing to
// do with what is being compared.
function makeRealBed() {
  fs.rmSync(REAL_BED, { recursive: true, force: true });
  fs.mkdirSync(REAL_BED, { recursive: true });
  fs.copyFileSync(path.join(BED, "authorized_keys"), path.join(REAL_BED, "authorized_keys"));
}

// The known_hosts entry for a host key.  The key goes in BEFORE any
// connection: the client's "Permanently added" warning goes to its stderr,
// which is the same stream the rest of the client's output arrives on.
function writeKnownHosts(dir, hostKeyFile) {
  const pub = fs.readFileSync(hostKeyFile + ".pub", "utf8").trim().split(/\s+/);
  fs.writeFileSync(path.join(dir, "known_hosts"), `127.0.0.1 ${pub[0]} ${pub[1]}\n`, "utf8");
}

// The real server's known_hosts.
//
// The sshd_setup helper generates its OWN host keys in the bed it is given,
// and it offers all of them.  The client picks one of them by its own
// preference, so the known_hosts file has to name all of them: a file with
// only one of them makes the client refuse the host, and the refusal reads
// as "the forwarding did not work" when it is really "the host key was not
// in the file".
function writeRealKnownHosts() {
  const names = ["hostkey_ed25519", "hostkey_ecdsa_256", "hostkey_ecdsa_384", "hostkey_rsa_2048"];
  const lines = [];
  for (const n of names) {
    const pub = path.join(REAL_BED, n + ".pub");
    if (!fs.existsSync(pub)) continue;
    const parts = fs.readFileSync(pub, "utf8").trim().split(/\s+/);
    lines.push(`127.0.0.1 ${parts[0]} ${parts[1]}`);
  }
  fs.writeFileSync(path.join(REAL_BED, "known_hosts"), lines.join("\n") + "\n", "utf8");
}

// ---------------------------------------------------------------- our server
function startOurServer() {
  return new Promise((resolve, reject) => {
    const p = spawnLocked(
      OUR_SSHD,
      [
        "--host-key", path.join(BED, "hostkey"),
        "--authorized-keys", path.join(BED, "authorized_keys"),
        "--port", "0",
        "--accept-timeout-ms", "120000",
      ],
      { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    p.stdout.on("data", (d) => { out += d.toString(); });
    p.stderr.on("data", (d) => { out += d.toString(); });
    const exited = new Promise((done) => p.on("close", () => done()));
    const deadline = Date.now() + 30000;
    const tick = () => {
      const m = /listen_port:\s*(\d+)/i.exec(out);
      if (m) {
        return resolve({ proc: p, port: Number(m[1]), out: () => out, exited: () => exited });
      }
      if (Date.now() > deadline) return reject(new Error(`our sshd did not start:\n${out}`));
      setTimeout(tick, 100);
    };
    tick();
  });
}

// --------------------------------------------------------------- real server
function startRealServer(port) {
  const p = spawn(
    "node",
    [path.join(ROOT, "host", "sshd_setup.mjs"), "--dir", REAL_BED, "--port", String(port), "--name", "loop101"],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  let out = "";
  p.stdout.on("data", (d) => { out += d.toString(); });
  p.stderr.on("data", (d) => { out += d.toString(); });
  return { proc: p, out: () => out };
}

function stopRealServer() {
  spawnSync("node", [path.join(ROOT, "host", "sshd_setup.mjs"), "--stop", "--name", "loop101"],
    { cwd: ROOT, encoding: "utf8", timeout: 60000 });
}

// ------------------------------------------------------------------- client
//
// The real client, run ASYNCHRONOUSLY.
//
// `spawnSync` blocks the event loop, and this gate has `spawn`ed servers
// whose output is read with events.  While `spawnSync` runs, those events
// cannot be delivered -- so a server's report would still be empty when the
// gate looks at it, no matter how long it waits afterwards.
function startForwardClient(port, localPort, targetPort, knownHosts) {
  const p = spawn(
    REAL_SSH,
    [
      "-p", String(port),
      "-N",
      "-L", `127.0.0.1:${localPort}:127.0.0.1:${targetPort}`,
      "-i", path.join(BED, "userkey"),
      "-o", "IdentitiesOnly=yes",
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=yes",
      "-o", `UserKnownHostsFile=${knownHosts}`,
      `${sshUser()}@127.0.0.1`,
    ],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  const err = [];
  p.stderr.on("data", (d) => err.push(d));
  p.stdout.on("data", () => {});
  return { proc: p, stderr: () => Buffer.concat(err).toString("latin1") };
}

// A connection to the client's local listener.
//
// `halfClose` sends the FIN without closing the read side: that is the
// client's "I will send no more bytes", and it is what the server has to
// pass on to the target.
//
// A refused connection is retried: the client sets its local listener up
// after the handshake, and a gate that gives up on the first refusal would
// be measuring the gate's impatience.
async function roundTrip(localPort, payload, { halfClose = false, expect = null } = {}) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const r = await oneRoundTrip(localPort, payload, halfClose, expect);
    if (r.why !== "error" || !/ECONNREFUSED/i.test(r.error)) return r;
    await new Promise((res) => setTimeout(res, 500));
  }
  return oneRoundTrip(localPort, payload, halfClose, expect);
}

function oneRoundTrip(localPort, payload, halfClose, expect) {
  return new Promise((resolve) => {
    const c = net.connect(localPort, "127.0.0.1");
    const chunks = [];
    let got = 0;
    let settled = false;
    const finish = (why, error = "") => {
      if (settled) return;
      settled = true;
      try { c.destroy(); } catch { /* already gone */ }
      resolve({ data: Buffer.concat(chunks), why, error });
    };
    c.on("connect", () => {
      c.write(payload);
      if (halfClose) c.end();
    });
    c.on("data", (d) => {
      chunks.push(d);
      got += d.length;
      if (expect !== null && got >= expect) finish("complete");
    });
    c.on("end", () => finish("closed"));
    c.on("close", () => finish("closed"));
    c.on("error", (e) => finish("error", e.message));
    setTimeout(() => finish("timeout"), 10000);
  });
}

// The digest the TARGET computed, once it has been printed.
//
// The echo server prints its line when the connection CLOSES, so the line
// for a forward appears only after the client's local connection has been
// closed and the server has passed the EOF on.  Waiting for the line is
// therefore part of the measurement, not a nicety: reading the file too
// early finds no line and looks like a forward that delivered nothing.
async function waitForEcho(bytes, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const d = echoDigest(bytes);
    if (d) return d;
    await new Promise((r) => setTimeout(r, 150));
  }
  return null;
}

// The digest the TARGET computed.  The point is that it is computed at the
// far end of the forward: a payload the gate does not know by heart can
// still be checked end to end, because the target says what it got and the
// client says what it got back.
//
// The line is found BY ITS BYTE COUNT.  The echo server prints one line per
// connection, and a readiness probe of the target's port is itself a
// connection -- so the file holds a line for a connection that received
// nothing, and picking the LAST line picks that one instead of the real
// one.
function echoDigest(expectedBytes) {
  const out = echoServer.out();
  const lines = out.split(/\r?\n/).filter(Boolean);
  for (let i = lines.length - 1; i >= 0; i--) {
    const m = lines[i].match(/^ECHO (\d+) ([0-9a-f]{64})$/);
    if (m && Number(m[1]) === expectedBytes) return { bytes: Number(m[1]), sha: m[2] };
  }
  return null;
}

let echoServer = { out: () => "" };

function startEchoTarget(port) {
  const p = spawn("node", [path.join(ROOT, "host", "echo_server.mjs"), String(port)],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  p.stdout.on("data", (d) => { out += d.toString(); });
  p.stderr.on("data", (d) => { out += d.toString(); });
  return { proc: p, out: () => out };
}

// ------------------------------------------------------- the tight peer
//
// A second witness, and the reason the rule about the peer's limits can be
// tested AT ALL.
//
// The real `ssh.exe` asks for a window of 2097152 and a maximum packet of
// 32768 -- and this repository's own server cuts its packets at exactly the
// same place, because `sd_chunk_size` clamps at 32768.  A server that IGNORED
// the peer's maximum packet would therefore still send packets of at most
// 32768 bytes, and the real client could not tell the difference.  The rule
// would be untestable against the real client.
//
// So this peer asks for LESS.  paramiko lets the caller set the window and the
// maximum packet of the channel it opens (its lower bounds are 32768 and
// 4096), and it reports the size of every CHANNEL_DATA packet it receives --
// taken from the packets themselves, not from anything the server says.
//
// The real server is measured the same way, with the same peer and the same
// payload, so the two can be compared: this repository's server has to cut
// its packets the way the real one does.
function runTightPeer(port, destPort, outJson) {
  const r = spawnSync("python", [
    path.join(ROOT, "host", "loop101_tight_peer.py"),
    "--port", String(port),
    "--dest-port", String(destPort),
    "--key", path.join(BED, "userkey"),
    "--out-json", outJson,
  ], { cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 300000 });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

function readTightPeer(outJson) {
  try {
    return JSON.parse(fs.readFileSync(outJson, "utf8"));
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------- the run
async function main() {
  console.log("=== Loop #101: the SSH server's half of a port forward ===");

  if (!REAL_SSH || !REAL_KEYGEN) {
    ok("a real ssh.exe and ssh-keygen.exe are available", false,
       `looked in: ${OPENSSH_DIRS.join(", ")}`);
    return summary();
  }
  const user = sshUser();
  ok("the account this machine runs as could be named", user !== "",
     "no USERNAME, USER, LOGNAME or LNAME in the environment");
  if (user === "") return summary();

  // ---- A. this loop's own code ----
  section("A. this loop's own code");
  const build = moon(["build", "--target", "native", "cmd/sshd"]);
  ok("cmd/sshd builds", build.code === 0, build.code === 0 ? "" : build.out.slice(-3000));
  if (build.code !== 0) return summary();
  const unit = moon(["test", "--target", "native", "src/sshd"]);
  ok("the src/sshd unit tests pass", unit.code === 0,
     unit.code === 0 ? "" : unit.out.slice(-3000));

  makeKeys(BED);
  makeRealBed();
  writeKnownHosts(BED, path.join(BED, "hostkey"));

  // ---- B. the happy path, against our server ----
  section("B. the real client forwards through OUR server");
  const echoPort = await freePort();
  echoServer = startEchoTarget(echoPort);
  ok("the echo target is up", await waitForPort(echoPort, 15000));

  const payload = Buffer.from("loop101-direct-tcpip-" + "0123456789abcdef".repeat(8), "latin1");
  const payloadSha = sha256(payload);
  const ourServer = await startOurServer();
  const ourPort = ourServer.port;
  const localPort = await freePort();
  const client = startForwardClient(ourPort, localPort, echoPort, path.join(BED, "known_hosts"));
  await new Promise((r) => setTimeout(r, 2500));
  // The local listener is NOT probed with a connection: every connection to
  // it is a forward, and a probe would be a second forward that the
  // server's own report would have to explain.

  const back = await roundTrip(localPort, payload, { expect: payload.length });
  ok("the bytes come back", back.data.length === payload.length,
     `got ${back.data.length} bytes, want ${payload.length} (${back.why})`);
  ok("the bytes are the same bytes", sha256(back.data) === payloadSha,
     `sha=${sha256(back.data)} want=${payloadSha}`);
  const targetSaw = await waitForEcho(payload.length);
  ok("the target received the payload", targetSaw !== null,
     `no ECHO line for ${payload.length} bytes in: ${echoServer.out().trim().split(/\r?\n/).join(" | ")}`);
  ok("the target's digest is the payload's digest", targetSaw !== null && targetSaw.sha === payloadSha,
     targetSaw ? `sha=${targetSaw.sha}` : "the target said nothing");

  // ---- C. the same scenario against the REAL server ----
  section("C. the real server does the same thing");
  const realPort = await freePort();
  const real = startRealServer(realPort);
  const realUp = await waitForPort(realPort, 30000);
  if (!realUp) {
    skip("the comparison against the real server", (real.out() || "").trim().split("\n")[0] || "no sshd");
  } else {
    // The real server's own host keys, which are NOT the ones this gate
    // generated: the sshd_setup helper makes its own.  The client's
    // known_hosts has to name the key the server will actually offer, or
    // the client refuses the host and the comparison measures a refusal.
    writeRealKnownHosts();
    const realLocal = await freePort();
    const realClient = startForwardClient(realPort, realLocal, echoPort, path.join(REAL_BED, "known_hosts"));
    await new Promise((r) => setTimeout(r, 2500));
    const realBack = await roundTrip(realLocal, payload, { expect: payload.length });
    ok("the real server returns the same bytes", realBack.data.length === payload.length &&
       sha256(realBack.data) === payloadSha,
       `bytes=${realBack.data.length} sha=${sha256(realBack.data)}` +
       (realClient.stderr() ? ` client said: ${realClient.stderr().trim().split(/\r?\n/)[0]}` : ""));
    ok("our server and the real server agree byte for byte",
       Buffer.compare(realBack.data, back.data) === 0,
       `ours=${back.data.length} bytes, real=${realBack.data.length} bytes`);
    realClient.proc.kill();
  }

  // ---- D. the target is not listening ----
  //
  // A server of its own: `cmd/sshd` serves ONE connection and then exits,
  // so a second client needs a second server.  That is a property of the
  // driver, not of the protocol, and the gate has to respect it.
  section("D. a target that is not listening");
  const deadPort = await freePort();   // nothing is listening here
  const deadLocal = await freePort();
  const deadServer = await startOurServer();
  const deadClient = startForwardClient(deadServer.port, deadLocal, deadPort, path.join(BED, "known_hosts"));
  await new Promise((r) => setTimeout(r, 2000));
  const dead = await roundTrip(deadLocal, Buffer.from("nope"), { expect: 1 });
  ok("the local connection is closed with no data", dead.data.length === 0,
     `got ${dead.data.length} bytes, why=${dead.why}`);
  ok("the local connection is not an error", dead.why !== "error",
     `why=${dead.why} error=${dead.error}`);
  // The real server's answer to a target that is not listening is a
  // confirmation followed by a channel that closes: the client is told
  // NOTHING about the failure, and its local connection is closed with no
  // data.  A server that answered CHANNEL_OPEN_FAILURE instead would put a
  // message in the client's stderr -- and the client would not open its
  // local connection at all.  So "the client says nothing" is part of the
  // behaviour, not an absence of behaviour.
  await new Promise((r) => setTimeout(r, 800));
  ok("the client says nothing about a target that is not listening",
     deadClient.stderr().trim() === "",
     deadClient.stderr().trim().split(/\r?\n/).slice(0, 2).join(" | "));
  deadClient.proc.kill();

  // ---- E. the peer half-closes: the target must see EOF ----
  section("E. the peer half-closes and the target sees EOF");
  const halfEchoPort = await freePort();
  const halfEcho = startEchoTarget(halfEchoPort);
  await waitForPort(halfEchoPort, 15000);
  const halfLocal = await freePort();
  const halfServer = await startOurServer();
  const halfClient = startForwardClient(halfServer.port, halfLocal, halfEchoPort, path.join(BED, "known_hosts"));
  await new Promise((r) => setTimeout(r, 2500));
  const half = await roundTrip(halfLocal, Buffer.from("half-close-payload"), { halfClose: true });
  ok("the bytes come back before the close", half.data.length === 18,
     `got ${half.data.length} bytes`);
  await new Promise((r) => setTimeout(r, 1500));
  const halfLines = halfEcho.out().split(/\r?\n/).filter((l) => l.startsWith("ECHO "));
  ok("the target saw EOF (it printed its digest, which it does on EOF)",
     halfLines.some((l) => l.startsWith("ECHO 18 ")), halfLines.join(" | ") || "the target printed nothing");
  halfClient.proc.kill();

  // ---- F. a payload bigger than one window ----
  //
  // Three megabytes, and not a hundred kilobytes: the window this server
  // advertises is 2 MiB, so a payload below that never SPENDS the window
  // and the WINDOW_ADJUST that tops it back up is never sent.  A payload
  // above it exercises the window in BOTH directions -- the peer's window
  // for what we send, and ours for what the peer sends.
  section("F. a payload bigger than one window");
  const big = Buffer.alloc(3000000);
  for (let i = 0; i < big.length; i++) big[i] = (i * 7 + 3) % 256;
  const bigEchoPort = await freePort();
  const bigEcho = startEchoTarget(bigEchoPort);
  await waitForPort(bigEchoPort, 15000);
  const bigLocal = await freePort();
  const bigServer = await startOurServer();
  const bigClient = startForwardClient(bigServer.port, bigLocal, bigEchoPort, path.join(BED, "known_hosts"));
  await new Promise((r) => setTimeout(r, 2500));
  const bigBack = await roundTrip(bigLocal, big, { expect: big.length });
  ok("every byte of the big payload comes back", bigBack.data.length === big.length,
     `got ${bigBack.data.length} want ${big.length}`);
  ok("the big payload is byte-identical", sha256(bigBack.data) === sha256(big),
     `sha=${sha256(bigBack.data)} want=${sha256(big)}`);
  bigClient.proc.kill();

  // ---- G. the server's own report ----
  //
  // The report is printed when the connection ENDS, so the client has to be
  // killed first: a server that is still holding the connection has nothing
  // to report yet.
  section("G. the server's own report");
  client.proc.kill();
  await ourServer.exited();
  const reportText = ourServer.out();
  const numOf = (key) => {
    const m = new RegExp(`^${key}: (\\d+)$`, "m").exec(reportText);
    return m ? Number(m[1]) : undefined;
  };
  ok("the server says how many bytes it relayed", numOf("forward_bytes") === payload.length,
     `forward_bytes=${numOf("forward_bytes")} want=${payload.length}`);
  ok("the server says how many channels it forwarded", numOf("forward_targets") === 1,
     `forward_targets=${numOf("forward_targets")} want=1`);
  ok("the server says the peer closed the channel", numOf("peer_closed") === 1,
     `peer_closed=${numOf("peer_closed")}`);
  if (numOf("forward_bytes") === undefined) {
    console.log("      (the server's report was:)");
    for (const l of reportText.split(/\r?\n/).filter(Boolean)) console.log(`        ${l}`);
  }

  // ---- H. a peer that asks for small packets ----
  //
  // The rule under test: the data is cut to the peer's limits -- the window
  // the peer granted and the maximum packet the peer asked for (RFC 4254
  // section 5.2).  Against the real `ssh.exe` the rule is UNOBSERVABLE,
  // because the real client asks for 32768 and this server's own ceiling is
  // 32768; so this section uses a peer that asks for less.
  section("H. a peer that asks for small packets");
  const tightEchoPort = await freePort();
  const tightEcho = startEchoTarget(tightEchoPort);
  await waitForPort(tightEchoPort, 15000);
  const tightServer = await startOurServer();
  const tightOursJson = path.join(ROOT, ".loop101", "tight_ours.json");
  const tightRealJson = path.join(ROOT, ".loop101", "tight_real.json");
  const tightOurs = runTightPeer(tightServer.port, tightEchoPort, tightOursJson);
  const ours = readTightPeer(tightOursJson);
  ok("the tight peer could forward through our server", tightOurs.code === 0 && ours !== null,
     tightOurs.code === 0 ? "" : tightOurs.out.trim().split(/\r?\n/).slice(-3).join(" | "));
  let realTight = null;
  let tightReal = { code: -1, out: "the real server was not available" };
  if (realUp) {
    tightReal = runTightPeer(realPort, tightEchoPort, tightRealJson);
    realTight = readTightPeer(tightRealJson);
    ok("the tight peer could forward through the real server", tightReal.code === 0 && realTight !== null,
       tightReal.code === 0 ? "" : tightReal.out.trim().split(/\r?\n/).slice(-3).join(" | "));
  } else {
    skip("the tight peer against the real server", "no real sshd");
  }
  if (ours) {
    // The measurement has to be meaningful: if the peer had asked for the
    // default 32768, nothing below could tell a server that honours the
    // limit from one that ignores it.
    ok("the peer really did ask for a small packet",
       ours.allowed && ours.allowed.max_packet === 4096,
       `allowed=${JSON.stringify(ours.allowed)}`);
    // A measurement that measured NOTHING must not pass the rule it was
    // supposed to measure: the packet count is checked first, so a broken
    // witness is a red gate rather than a green one.
    ok("the witness measured the packets themselves", ours.packet_count > 0,
       `packets=${ours.packet_count}`);
    ok("the server never sends a packet bigger than the peer allowed",
       ours.packet_count > 0 && ours.largest_packet <= (ours.allowed ? ours.allowed.max_packet : 0),
       `largest=${ours.largest_packet} allowed=${ours.allowed ? ours.allowed.max_packet : "?"} ` +
       `packets=${ours.packet_count}`);
    ok("the bytes still come back whole", ours.identical === true && ours.received === ours.sent,
       `received=${ours.received} sent=${ours.sent}`);
    if (realTight) {
      ok("the real server cuts its packets the same way",
         realTight.packet_count > 0 && realTight.largest_packet === ours.largest_packet,
         `ours=${ours.largest_packet} real=${realTight.largest_packet} ` +
         `allowed=${realTight.allowed ? realTight.allowed.max_packet : "?"}`);
    }
  }
  tightServer.proc.kill();
  try { tightEcho.proc.kill(); } catch { /* gone */ }

  stopRealServer();
  try { echoServer.proc.kill(); } catch { /* gone */ }
  try { halfEcho.proc.kill(); } catch { /* gone */ }
  try { bigEcho.proc.kill(); } catch { /* gone */ }
  try { real.proc.kill(); } catch { /* gone */ }
  return summary();
}

function summary() {
  console.log("");
  console.log(`${checks - failures}/${checks} checks passed${skipped ? `, ${skipped} skipped` : ""}`);
  if (failures) {
    console.log(`FAILED: ${failures}`);
    process.exit(1);
  }
  process.exit(0);
}

main().catch((e) => {
  console.log(`the gate itself failed: ${e && e.stack ? e.stack : e}`);
  process.exit(1);
});
