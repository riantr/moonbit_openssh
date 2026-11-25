#!/usr/bin/env node
// host/verify_loop102.mjs -- Loop #102: the SSH server's half of a REMOTE
// port forward (`ssh -R`).
//
// ## What is being claimed
//
// `ssh -R 8080:db:5432 host` is the other direction of Loop #101.  The CLIENT
// asks the SERVER to LISTEN on a port, and every connection that arrives
// there is carried to the client over a channel the SERVER opens
// (RFC 4254 section 7.1).  This repository had no server half of it at all:
// the server ignored every global request.
//
// ## The oracle
//
// The real `sshd.exe` on this machine, driven by two independent clients:
//
//   * **paramiko**, through `host/loop102_peer.py` -- an implementation that
//     shares no code with this repository.  It reads the reply payloads, the
//     channel the server opens, and the bytes that go through it.  The client
//     log cannot show the reply payload (OpenSSH prints "Allocated port N"
//     only when the client asked for port 0), so the payload has to be read
//     off the wire by something else.
//   * **the real `ssh.exe`**, whose own DEBUG log names the channel the
//     server opened -- its type, its window, its maximum packet and the four
//     fields it carries.
//
// Every case below is run TWICE -- once against our server and once against
// the real one -- and the two have to agree.  A comparison with only our
// server in it would be a comparison of our server with itself.
//
// ## The behaviours that were MEASURED against the real server
//
// (and that this gate therefore pins):
//
//   * the reply to `tcpip-forward` with a FIXED port has an EMPTY payload,
//     and the reply to port 0 carries the chosen port as a u32;
//   * the channel the server opens is `forwarded-tcpip`, and its four fields
//     are in this order: the LISTEN address and port first, then the
//     ORIGINATOR address and port;
//   * the window is 2097152 and the maximum packet 32768;
//   * the `tcpip-forward` request arrives BEFORE any session channel, and
//     `ssh -N` never opens one at all.
//
// ## What is NOT compared, and why
//
//   * **The address the server binds.**  The real server ignores the address
//     the client asked for when `GatewayPorts` is off -- the default -- and
//     binds the loopback instead.  Its own log says so:
//     `server_input_global_request: tcpip-forward listen 192.0.2.1 port 55161`
//     followed by `Local forwarding listening on ::1 port 55161`.  So a
//     request for an address that cannot be bound is NOT a bind failure for
//     the real server, and using one to measure a bind failure would measure
//     that policy instead.  The gate uses a port that is ALREADY IN USE,
//     which both servers see the same way.
//   * **A second forward on the same connection.**  The real server allows
//     several; this one allows one and REFUSES the second, which is checked
//     on our side only.
//
// ## What runs where
//
// Every section needs the real client and the real server.  Where they are
// not available the section is SKIPPED LOUDLY rather than quietly passed --
// a machine that cannot run a check has not run it.

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
const BED = path.join(ROOT, ".loop102", "bed");
const REAL_BED = path.join(ROOT, ".loop102", "realbed");

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

// A field that may be MISSING because the step died half way through.
//
//   A step that fails early leaves fields out of its JSON, and a gate that
//   reads one of them without asking whether it is there does not report a
//   FAIL -- it CRASHES, and then every check after the crash never runs and
//   the evidence is gone.  A crash is not a report.
//
//   This was found by the mutation suite, not by reading the code: the
//   mutation "the reply for port 0 carries the port the peer named" made the
//   peer connect to port 0, the step stopped before it had a cancel to
//   report, and the gate died on `ours.channel.cancel.ok`.
const field = (obj, name) => (obj && obj[name] !== undefined ? obj[name] : null);

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

// A port that is ALREADY IN USE: the listener is held open for the whole
// gate, so a server asked to bind it meets a port that is taken.
function holdPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => resolve({ srv, port: srv.address().port }));
  });
}

async function waitForPort(port, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const up = await new Promise((resolve) => {
      const s = net.connect({ host: "127.0.0.1", port }, () => { s.destroy(); resolve(true); });
      s.on("error", () => { s.destroy(); resolve(false); });
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
    const args = ["-t", type, "-f", path.join(dir, file), "-N", "", "-C", `loop102 ${file}`];
    if (type === "ecdsa") args.splice(2, 0, "-b", "256");
    const r = spawnSync(REAL_KEYGEN, args, { encoding: "utf8", timeout: 120000 });
    if (r.status !== 0) throw new Error(`ssh-keygen failed for ${file}: ${r.stderr}`);
  }
  fs.copyFileSync(path.join(dir, "userkey.pub"), path.join(dir, "authorized_keys"));
}

// The real server's bed.
//
// It gets the SAME user key as ours -- one key, two servers -- because the
// peer is started with one key and the comparison is about the FORWARD, not
// about which key each server happens to accept.
function makeRealBed() {
  fs.rmSync(REAL_BED, { recursive: true, force: true });
  fs.mkdirSync(REAL_BED, { recursive: true });
  fs.copyFileSync(path.join(BED, "authorized_keys"), path.join(REAL_BED, "authorized_keys"));
}

// The known_hosts entry for a host key.
function writeKnownHosts(dir, hostKeyFile) {
  const pub = fs.readFileSync(hostKeyFile + ".pub", "utf8").trim().split(/\s+/);
  fs.writeFileSync(path.join(dir, "known_hosts"), `127.0.0.1 ${pub[0]} ${pub[1]}\n`, "utf8");
}

// The real server's known_hosts.
//
// The sshd_setup helper generates its OWN host keys in the bed it is given,
// and it offers all of them.  The client picks one of them by its own
// preference, so the known_hosts file has to name all of them.
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
    [path.join(ROOT, "host", "sshd_setup.mjs"), "--dir", REAL_BED, "--port", String(port), "--name", "loop102"],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  let out = "";
  p.stdout.on("data", (d) => { out += d.toString(); });
  p.stderr.on("data", (d) => { out += d.toString(); });
  return { proc: p, out: () => out };
}

function stopRealServer() {
  spawnSync("node", [path.join(ROOT, "host", "sshd_setup.mjs"), "--stop", "--name", "loop102"],
    { cwd: ROOT, encoding: "utf8", timeout: 60000 });
}

// ---------------------------------------------------------------- the peer
//
// The paramiko peer.  It is a separate program because it is a separate
// implementation, and a witness that shares this repository's code would be
// this repository agreeing with itself.
function runPeer(port, step, fixedPort, busyPort, keyPath) {
  const r = spawnSync("python", [
    path.join(ROOT, "host", "loop102_peer.py"),
    "127.0.0.1", String(port), keyPath, sshUser(), step,
    String(fixedPort), String(busyPort),
  ], { cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 300000 });
  const out = `${r.stdout || ""}${r.stderr || ""}`;
  let parsed = null;
  try {
    parsed = JSON.parse((r.stdout || "").trim().split(/\r?\n/).filter(Boolean).pop() || "null");
  } catch {
    parsed = null;
  }
  return { code: r.status, out, parsed };
}

// The five steps, in the order they are run.
//
// The `session` step is the one that opens a SESSION channel before it asks
// for the forward.  Every other step asks for the forward and never opens a
// session channel, so every other step exercises only the phase of the
// server that answers global requests BEFORE a session channel exists.  The
// server answers them in two places -- `ssh -N -R` sends the request with no
// session channel at all, and `ssh -R 55123:target:5432 host cmd` sends it
// with one -- and a gate that only ever asked the first way would leave the
// second way unmeasured.
const STEPS = ["payloads", "fixed", "busy", "channel", "session"];

// ------------------------------------------------------------------ the echo
//
// The target the CLIENT connects to when the server opens a forwarded-tcpip
// channel.  It ECHOES -- the bytes have to come back, not just arrive -- and
// it prints the digest of everything it received, when the connection closes,
// so the gate has to wait for the line and not just for the bytes.
function startEchoTarget(port) {
  const lines = [];
  const srv = net.createServer((c) => {
    const chunks = [];
    c.on("data", (d) => {
      chunks.push(d);
      c.write(d);
    });
    c.on("close", () => {
      const buf = Buffer.concat(chunks);
      lines.push(`ECHO ${buf.length} ${sha256(buf)}`);
    });
  });
  srv.listen(port, "127.0.0.1");
  return { srv, lines: () => lines };
}

async function waitForEcho(lines, bytes, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const hit = lines().find((l) => l.startsWith(`ECHO ${bytes} `));
    if (hit) return hit.split(" ")[2];
    await new Promise((r) => setTimeout(r, 150));
  }
  return null;
}

// ------------------------------------------------------------------- client
//
// The real client, run ASYNCHRONOUSLY.
//
// `spawnSync` blocks the event loop, and this gate has `spawn`ed servers
// whose output is read with events.  While `spawnSync` runs, those events
// cannot be delivered -- so a server's report would still be empty when the
// gate looks at it, no matter how long it waits afterwards.
function startRemoteForwardClient(port, listenPort, targetPort, knownHosts) {
  const p = spawn(
    REAL_SSH,
    [
      "-p", String(port),
      "-N",
      "-R", `${listenPort}:127.0.0.1:${targetPort}`,
      "-i", path.join(BED, "userkey"),
      "-o", "IdentitiesOnly=yes",
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=yes",
      "-o", `UserKnownHostsFile=${knownHosts}`,
      "-v", "-v", "-v",
      `${sshUser()}@127.0.0.1`,
    ],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  const err = [];
  p.stderr.on("data", (d) => err.push(d));
  p.stdout.on("data", () => {});
  return { proc: p, stderr: () => Buffer.concat(err).toString("latin1") };
}

function oneRoundTrip(port, payload, expect) {
  return new Promise((resolve) => {
    const c = net.connect(port, "127.0.0.1");
    const chunks = [];
    let got = 0;
    let settled = false;
    const finish = (why, error = "") => {
      if (settled) return;
      settled = true;
      try { c.destroy(); } catch { /* already gone */ }
      resolve({ data: Buffer.concat(chunks), why, error });
    };
    c.on("connect", () => c.write(payload));
    c.on("data", (d) => {
      chunks.push(d);
      got += d.length;
      if (expect !== null && got >= expect) finish("complete");
    });
    c.on("end", () => finish("closed"));
    c.on("close", () => finish("closed"));
    c.on("error", (e) => finish("error", e.message));
    setTimeout(() => finish("timeout"), 15000);
  });
}

// What the two servers have to agree on.
//
// The numbers that cannot be the same -- the ports, the channel number --
// are left out on purpose and checked against what was asked for instead.
function comparable(r) {
  const c = r.channel ? r.channel.channel || {} : {};
  const s = r.session ? r.session.channel || {} : {};
  const fixed = r.fixed ? field(r.fixed, "reply_fixed") : null;
  const p0 = r.payloads ? field(r.payloads, "reply_port0") : null;
  const cancel = r.channel ? field(r.channel, "cancel") : null;
  const scancel = r.session ? field(r.session, "cancel") : null;
  return {
    reply_fixed_ok: fixed ? fixed.ok : null,
    reply_fixed_len: fixed ? fixed.len : null,
    reply_port0_ok: p0 ? p0.ok : null,
    reply_port0_len: p0 ? p0.len : null,
    channel_window: c.window ?? null,
    channel_max_packet: c.max_packet ?? null,
    channel_listen_addr: c.listen_addr ?? null,
    channel_origin_addr: c.origin_addr ?? null,
    bytes_through_channel: r.channel ? r.channel.bytes_through_channel : null,
    echo_len: r.channel ? r.channel.echo_len : null,
    echo_sha256: r.channel ? r.channel.echo_sha256 : null,
    cancel_ok: cancel ? cancel.ok : null,
    session_window: s.window ?? null,
    session_max_packet: s.max_packet ?? null,
    session_listen_addr: s.listen_addr ?? null,
    session_origin_addr: s.origin_addr ?? null,
    session_bytes_through_channel: r.session ? r.session.bytes_through_channel : null,
    session_echo_len: r.session ? r.session.echo_len : null,
    session_echo_sha256: r.session ? r.session.echo_sha256 : null,
    session_cancel_ok: scancel ? scancel.ok : null,
  };
}

// ------------------------------------------------------------------- the run
async function main() {
  console.log("=== Loop #102: the SSH server's half of a REMOTE port forward ===");

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
  // The protection engine on this machine sometimes TAKES the test binary
  // away: the file cannot even be stat'ed, and `moon test` answers
  //
  //     stat "...\sshd.blackbox_test.exe": 拒绝访问。 (os error 5)
  //
  // That is not a failing test, and it is not a passing one either -- the
  // tests did not run at all.  A gate that reports it as a FAIL teaches the
  // reader to ignore red, and a gate that reports it as a PASS is a lie.
  // So it is SKIPPED, loudly, with the reason; the CI, where there is no
  // such engine, is what actually runs them.
  //
  // The signature is narrow on purpose: the message has to be about a
  // `stat` of an `.exe`, and about access being denied.  A test that FAILED
  // prints its own assertion, and that is not this shape.
  const avTookTheBinary =
    /拒绝访问|Access is denied/i.test(unit.out) && /stat .*\.exe/i.test(unit.out);
  if (avTookTheBinary) {
    skip("the src/sshd unit tests",
         "the real-time protection engine took the test binary away; " +
         "they did not run on this machine (the CI runs them)");
  } else {
    ok("the src/sshd unit tests pass", unit.code === 0,
       unit.code === 0 ? "" : unit.out.slice(-3000));
  }

  makeKeys(BED);
  makeRealBed();
  writeKnownHosts(BED, path.join(BED, "hostkey"));

  // The port the FIXED-port case asks for, and a port that is ALREADY IN
  // USE.  Both are found once and used for both servers, so the two are
  // asked the same question.
  const fixedPort = await freePort();
  const busy = await holdPort();

  // ---- B. the peer against OUR server ----
  section("B. the peer asks OUR server for a remote forward");
  const ours = {};
  for (const step of STEPS) {
    const s = await startOurServer();
    const r = runPeer(s.port, step, fixedPort, busy.port, path.join(BED, "userkey"));
    ours[step] = r.parsed;
    ok(`the peer got an answer for the ${step} step`, r.parsed !== null,
       r.parsed ? "" : r.out.slice(-2000));
    s.proc.kill();
    await s.exited();
  }

  // The SAME bytes the peer sends.  The peer is a separate program, so the
  // two have to agree on the payload by construction -- and they do, by
  // both spelling it out here and in `host/loop102_peer.py`.
  const payload = Buffer.from("loop102 remote forward probe\n".repeat(7), "latin1");
  const payloadSha = sha256(payload);

  if (ours.payloads) {
    const p0 = field(ours.payloads, "reply_port0");
    const p1 = field(ours.payloads, "reply_second");
    ok("a request for port 0 is granted",
       p0 !== null && p0.ok === true,
       `reply=${JSON.stringify(p0)}`);
    ok("the reply for port 0 carries the port as a u32",
       p0 !== null && p0.len === 4 && p0.port > 0,
       `len=${p0 && p0.len} port=${p0 && p0.port}`);
    ok("a second forward on the same connection is refused, not ignored",
       p1 !== null && p1.ok === false && !p1.error,
       `reply=${JSON.stringify(p1)}`);
  }
  if (ours.fixed) {
    const f = field(ours.fixed, "reply_fixed");
    ok("the reply for a fixed port carries nothing",
       f !== null && f.ok === true && f.len === 0,
       `reply=${JSON.stringify(f)}`);
  }
  if (ours.busy) {
    // A port that is already in use.  This one is checked on OUR side only,
    // and the reason is a platform difference that was measured: on this
    // machine the REAL server binds the port anyway (its own log says
    // `Local forwarding listening on 127.0.0.1 port 61901` for a port the
    // gate was holding), while ours refuses it.  On Linux both refuse it.
    // What is checked here is the RULE -- a forward that could not be bound
    // is REFUSED, not silently accepted.
    const b = field(ours.busy, "reply_busy");
    ok("a port that is already in use is refused",
       b !== null && b.ok === false && !b.error,
       `reply=${JSON.stringify(b)}`);
    ok("the refusal carries nothing",
       b !== null && b.len === 0,
       `reply=${JSON.stringify(b)}`);
  }
  if (ours.channel) {
    const c = ours.channel.channel || {};
    const cancel = field(ours.channel, "cancel");
    ok("the server opened a channel for the connection",
       ours.channel.bytes_through_channel === payload.length,
       `bytes=${ours.channel.bytes_through_channel} want=${payload.length}` +
       (ours.channel.error ? ` error=${ours.channel.error}` : ""));
    ok("the window is 2097152", c.window === 2097152, `window=${c.window}`);
    ok("the maximum packet is 32768", c.max_packet === 32768, `max_packet=${c.max_packet}`);
    ok("the channel names the address that was connected",
       c.listen_addr === "localhost", `listen_addr=${c.listen_addr}`);
    ok("the channel names the port that was connected",
       c.listen_port !== undefined && c.listen_port === ours.channel.allocated_port,
       `listen_port=${c.listen_port} allocated=${ours.channel.allocated_port}`);
    ok("the channel names the originator", c.origin_addr === "127.0.0.1",
       `origin_addr=${c.origin_addr}`);
    ok("the bytes came back the other way", ours.channel.echo_len === payload.length,
       `echo=${ours.channel.echo_len} want=${payload.length}`);
    ok("the cancel is answered with a success",
       cancel !== null && cancel.ok === true,
       `cancel=${JSON.stringify(cancel)}`);
  }
  if (ours.session) {
    // The same forward, asked for AFTER a session channel was opened.  This
    // is the path `ssh -R 55123:target:5432 host cmd` takes, and it is
    // answered by a DIFFERENT part of the server than the one above.
    const c = ours.session.channel || {};
    ok("the forward works after a session channel was opened",
       ours.session.bytes_through_channel === payload.length,
       `bytes=${ours.session.bytes_through_channel} want=${payload.length}` +
       (ours.session.error ? ` error=${ours.session.error}` : ""));
    ok("the channel opened after a session channel names the address that was connected",
       c.listen_addr === "localhost", `listen_addr=${c.listen_addr}`);
    ok("the channel opened after a session channel names the originator",
       c.origin_addr === "127.0.0.1", `origin_addr=${c.origin_addr}`);
    ok("the bytes came back after a session channel was opened",
       ours.session.echo_len === payload.length,
       `echo=${ours.session.echo_len} want=${payload.length}`);
    ok("the cancel after a session channel is answered with a success",
       field(ours.session, "cancel") !== null &&
       field(ours.session, "cancel").ok === true,
       `cancel=${JSON.stringify(field(ours.session, "cancel"))}`);
  }

  // ---- C. the same peer against the REAL server ----
  section("C. the real server does the same thing");
  const realPort = await freePort();
  const real = startRealServer(realPort);
  const realUp = await waitForPort(realPort, 30000);
  if (!realUp) {
    skip("the comparison against the real server",
         (real.out() || "").trim().split("\n")[0] || "no sshd");
  } else {
    writeRealKnownHosts();
    const theirs = {};
    for (const step of STEPS) {
      const r = runPeer(realPort, step, fixedPort, busy.port, path.join(BED, "userkey"));
      theirs[step] = r.parsed;
      ok(`the real server answered the ${step} step`, r.parsed !== null,
         r.parsed ? "" : r.out.slice(-1500));
    }
    if (theirs.payloads) {
      const p0 = field(theirs.payloads, "reply_port0");
      ok("the real server answered a request for port 0",
         p0 !== null && p0.ok === true && p0.len === 4,
         JSON.stringify(p0));
    }
    if (theirs.fixed) {
      const f = field(theirs.fixed, "reply_fixed");
      ok("the real server's reply for a fixed port carries nothing",
         f !== null && f.ok === true && f.len === 0,
         JSON.stringify(f));
    }
    if (theirs.busy) {
      // Information, not a check: on this machine the real server binds the
      // port anyway (Windows lets a second socket take a port that is being
      // listened on), and on Linux it refuses it.  Either way the real
      // server's answer is printed, because a gate that hides the oracle's
      // answer is a gate that hides a difference.
      console.log(`  NOTE  the real server's answer for the port that was already in use: ` +
                  `${JSON.stringify(field(theirs.busy, "reply_busy"))}`);
    }
    if (theirs.channel) {
      const c = theirs.channel.channel || {};
      ok("the real server opened a channel for the connection",
         theirs.channel.bytes_through_channel === payload.length,
         `bytes=${theirs.channel.bytes_through_channel}`);
      ok("the real server's channel names the address that was connected",
         c.listen_addr === "localhost", `listen_addr=${c.listen_addr}`);
      ok("the real server's channel names the originator",
         c.origin_addr === "127.0.0.1", `origin_addr=${c.origin_addr}`);
    }
    if (theirs.session) {
      ok("the real server carried a forward asked for after a session channel",
         theirs.session.bytes_through_channel === payload.length,
         `bytes=${theirs.session.bytes_through_channel}` +
         (theirs.session.error ? ` error=${theirs.session.error}` : ""));
      ok("the real server's channel after a session channel names the address that was connected",
         (theirs.session.channel || {}).listen_addr === "localhost",
         `listen_addr=${(theirs.session.channel || {}).listen_addr}`);
    }

    // The comparison.  Everything that CAN be the same IS compared.
    const a = comparable(ours);
    const b = comparable(theirs);
    const diffs = [];
    for (const k of Object.keys(a)) {
      if (a[k] === null || b[k] === null) continue;
      if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) {
        diffs.push(`${k}: ours=${JSON.stringify(a[k])} real=${JSON.stringify(b[k])}`);
      }
    }
    ok("our server and the real server agree on every measurable field",
       diffs.length === 0, diffs.join("; "));
    stopRealServer();
  }
  busy.srv.close();

  // ---- D. the real client asks OUR server for a remote forward ----
  section("D. the real client asks OUR server for a remote forward");
  const echoPort = await freePort();
  const echo = startEchoTarget(echoPort);
  ok("the echo target is up", await waitForPort(echoPort, 15000));

  const ourServer = await startOurServer();
  const listenPort = await freePort();
  const client = startRemoteForwardClient(
    ourServer.port, listenPort, echoPort, path.join(BED, "known_hosts"));

  // The client's own verdict.  It prints this when the server's reply says
  // the forward was set up.
  let said = "";
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    said = client.stderr();
    if (/remote forward success/i.test(said)) break;
    if (/Warning: remote port forwarding failed/i.test(said)) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  ok("the client says the remote forward succeeded",
     /remote forward success/i.test(said),
     said.trim().split(/\r?\n/).filter((l) => /forward/i.test(l)).join(" | ") ||
     said.trim().split(/\r?\n/).slice(-1)[0] || "the client said nothing");

  // Something connects to the port the server is listening on.  That is the
  // moment the server opens its channel.
  const back = await oneRoundTrip(listenPort, payload, payload.length);
  ok("the bytes come back through the client's forward",
     back.data.length === payload.length && sha256(back.data) === payloadSha,
     `got ${back.data.length} bytes, want ${payload.length} (${back.why}${back.error ? ": " + back.error : ""})`);

  // The client's own account of the channel the server opened.  It is read
  // AFTER the round trip on purpose: the channel does not exist until
  // something connects to the listening port, so a gate that read the log
  // before that would be looking for a line that has not been written yet.
  const saidAfter = client.stderr();
  ok("the client names the channel the server opened",
     /client_input_channel_open: ctype forwarded-tcpip/.test(saidAfter),
     (saidAfter.match(/client_input_channel_open: ctype forwarded-tcpip.*/) || ["the client did not say"])[0]);
  ok("the window and the maximum packet are the real ones",
     /client_input_channel_open: ctype forwarded-tcpip rchan \d+ win 2097152 max 32768/.test(saidAfter),
     (saidAfter.match(/client_input_channel_open: ctype forwarded-tcpip.*/) || ["the client did not say"])[0]);
  ok("the client reads the channel's fields the way the real server's does",
     /client_request_forwarded_tcpip: listen localhost port \d+, originator 127\.0\.0\.1 port \d+/.test(saidAfter),
     (saidAfter.match(/client_request_forwarded_tcpip:.*/) || ["the client did not say"])[0]);
  const targetSaw = await waitForEcho(echo.lines, payload.length);
  ok("the client's target received the payload", targetSaw !== null,
     `no ECHO line for ${payload.length} bytes in: ${echo.lines().join(" | ")}`);
  ok("the target's digest is the payload's digest",
     targetSaw !== null && targetSaw === payloadSha,
     targetSaw ? `sha=${targetSaw}` : "the target said nothing");

  // ---- E. the server's own report ----
  section("E. the server's own report");
  client.proc.kill();
  await client.proc;
  await ourServer.exited();
  const report = ourServer.out();
  const grab = (name) => {
    const m = new RegExp(`^${name}:\\s*(\\d+)\\s*$`, "m").exec(report);
    return m ? Number(m[1]) : null;
  };
  const port = grab("remote_forward_port");
  const conns = grab("remote_forward_connections");
  const bytes = grab("remote_forward_bytes");
  ok("the server says which port it is listening on",
     port === listenPort, `remote_forward_port=${port} want=${listenPort}`);
  ok("the server says how many connections it carried",
     conns === 1, `remote_forward_connections=${conns} want=1`);
  ok("the server says how many bytes it relayed",
     bytes === payload.length, `remote_forward_bytes=${bytes} want=${payload.length}`);

  echo.srv.close();
  return summary();
}

function summary() {
  console.log(`\n${checks - failures}/${checks} checks passed` + (skipped ? `, ${skipped} skipped` : ""));
  return failures === 0 ? 0 : 1;
}

main().then((code) => process.exit(code)).catch((e) => {
  console.error(e);
  process.exit(1);
});
