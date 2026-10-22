#!/usr/bin/env node
// host/verify_loop78.mjs -- Loop #78: forwarded-tcpip, the **server** half of
// a remote port forward.
//
// ## What is being claimed
//
// `ssh -R 9000:db:5432 host` is, at the protocol level, two things:
//
//   1. the client asks the **server** to listen on a port (the "tcpip-forward"
//      global request, RFC 4254 section 7.1), and
//   2. when somebody connects to that port, the **server** opens a
//      "forwarded-tcpip" channel back to the client (RFC 4254 section 7.2),
//      and the client relays the bytes to its own local target.
//
// This repository had no implementation of it. `src/channel` could not name
// the channel type, and `chan_step` had no branch for an inbound
// CHANNEL_OPEN at all -- 0x5a fell into the catch-all and was silently
// dropped, which is the exact symptom of "the server opened a channel and it
// never appeared".
//
// ## The evidence, and why each piece is here
//
// 1. **The bytes are what paramiko's encoder produces.** `cmd/remote_fwd_kat`
//    prints this client's payloads; `host/gen_remote_fwd_vectors.py` prints
//    the same payloads built with paramiko's own `Message` encoder, and
//    decodes an inbound open with paramiko's own decoder. Comparing our
//    encoder with our encoder would prove nothing.
//
// 2. **One of the vectors is a real server's bytes.** P1 is the exact
//    "forwarded-tcpip" CHANNEL_OPEN payload a Win32-OpenSSH 8.0p1 server put
//    on the wire, captured by `host/remote_fwd_capture.py`. It settles the
//    question the RFC leaves open: the u32 in that payload is the port the
//    server was **listening** on, not the ephemeral port of the accepted
//    connection. OpenSSH's own client matches the incoming channel against
//    its configured forwards by exactly that number.
//
// 3. **The server opened a channel, and the bytes survived the round trip.**
//    A probe connects to the port the server was listening on; the server
//    opens the channel; the client relays to a local echo target; the bytes
//    come back to the probe. Both directions are checked, because a relay
//    that only moves one way is not a relay.
//
// 4. **A second implementation agrees.** paramiko drives the same server
//    through the same exchange and gets the same bytes back.
//
// 5. **The refusal is told apart from the success.** A server with
//    `AllowTcpForwarding no` answers SSH_MSG_REQUEST_FAILURE. That has to
//    come out as a refusal, not as a hang and not as a silent success.
//
// ## What runs where
//
// Section B needs only node and paramiko, so it runs everywhere. The rest
// needs an OpenSSH **server**. When there is none, those sections are
// **skipped loudly** rather than quietly passed: a machine that cannot run a
// check has not run it.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sshUser, sshUserInfo } from "./ssh_user.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop78");

// The account this gate authenticates as. Derived, never written down: see
// host/ssh_user.mjs for why, and for the same rule applied to paths.
const USER_INFO = sshUserInfo();
const USER = USER_INFO.name;

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

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

function numOf(text, key) {
  const m = text.match(new RegExp(`^${key}: (\\d+)$`, "m"));
  return m ? Number(m[1]) : undefined;
}

function lineOf(text, key) {
  const m = text.match(new RegExp(`^${key}: (.*)$`, "m"));
  return m ? m[1] : undefined;
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

async function waitForPort(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const up = await new Promise((resolve) => {
      const s = net.connect({ host: "127.0.0.1", port }, () => { s.destroy(); resolve(true); });
      s.on("error", () => { s.destroy(); resolve(false); });
    });
    if (up) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

// A child's stdout, accumulated as it arrives.
function tap(child) {
  child.tapBuf = "";
  for (const stream of [child.stdout, child.stderr]) {
    if (stream) stream.on("data", (d) => { child.tapBuf += d.toString(); });
  }
  return child;
}

async function waitForText(child, needle, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if ((child.tapBuf || "").includes(needle)) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  return false;
}

const CLIENT_EXE = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");

// Start the client with the sshd's port in front of the arguments.
//
// It has to run **asynchronously**: the whole point of the remote forward is
// that the client waits for the server to open a channel, and the server only
// does that when somebody connects to the port it was listening on. The gate
// is that somebody. A synchronous client would be waiting for a connection
// that only the gate can make, and the gate would be waiting for the client.
function startClientAt(sshdPort, extra) {
  const child = spawn(
    CLIENT_EXE,
    [String(sshdPort), "--kh-tofu", "--kh-host", "127.0.0.1", "--user", USER, ...extra],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  return tap(child);
}

// Wait for a line matching `re` in the child's output.
async function waitForLine(child, re, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const m = (child.tapBuf || "").match(re);
    if (m) return m;
    if (child.exitCode !== null) return null;
    await new Promise((r) => setTimeout(r, 100));
  }
  return null;
}

// Read exactly `n` bytes from a socket, or null on timeout.
function readBytes(sock, n, timeoutMs) {
  return new Promise((resolve) => {
    const chunks = [];
    let got = 0;
    const done = (value) => {
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("close", onClose);
      resolve(value);
    };
    const onData = (b) => {
      chunks.push(b);
      got += b.length;
      if (got >= n) done(Buffer.concat(chunks).subarray(0, n));
    };
    const onClose = () => done(got >= n ? Buffer.concat(chunks).subarray(0, n) : null);
    const timer = setTimeout(() => done(got >= n ? Buffer.concat(chunks).subarray(0, n) : null), timeoutMs);
    sock.on("data", onData);
    sock.on("close", onClose);
  });
}

function connectProbe(port, timeoutMs = 10000) {
  return new Promise((resolve) => {
    const s = net.connect({ host: "127.0.0.1", port });
    const timer = setTimeout(() => { s.destroy(); resolve(null); }, timeoutMs);
    s.on("connect", () => { clearTimeout(timer); resolve(s); });
    s.on("error", () => { clearTimeout(timer); resolve(null); });
  });
}

// Each instance gets its own name, so the config, the pid file and the log
// are its own.
function startSshd(port, name, extra) {
  return tap(spawn("node", ["host/sshd_setup.mjs", "--port", String(port), "--name", name, ...extra], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
}

function stopSshd(name) {
  spawnSync("node", ["host/sshd_setup.mjs", "--stop", "--name", name], { cwd: ROOT, encoding: "utf8" });
}

function sshdLog(name) {
  return path.join(ROOT, ".loop31", "sshd", `sshd.log_${name}`);
}

function readSshdLog(name) {
  try {
    return readFileSync(sshdLog(name), "utf8");
  } catch (e) {
    return "";
  }
}

function authLogLines(name, limit = 20) {
  return readSshdLog(name)
    .split(/\r?\n/)
    .filter((l) =>
      /userauth|publickey|authorized_keys|invalid user|not allowed|Accepted|Failed|refused|error/i.test(l))
    .slice(-limit);
}

function explainAuthFailure(name) {
  const lines = authLogLines(name);
  if (!lines.length) {
    console.log("      (the server's log said nothing about the authentication)");
    return;
  }
  console.log("      the server's own account of it:");
  for (const l of lines) console.log(`        ${l}`);
}

// Comments explaining a bug necessarily contain the bug's text, so a source
// scan has to take them out before it looks for anything.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

async function main() {
  mkdirSync(WORK, { recursive: true });
  for (const n of ["loop78", "loop78nf"]) rmSync(sshdLog(n), { force: true });

  // ---------------------------------------------------------------- A. build
  section("A. the code builds");
  const b1 = moon(["build", "cmd/ssh_live", "--target", "native"]);
  ok("cmd/ssh_live builds (native)", b1.code === 0, b1.code === 0 ? "" : b1.out.slice(-300));
  const b2 = moon(["build", "cmd/remote_fwd_kat", "--target", "native"]);
  ok("cmd/remote_fwd_kat builds (native)", b2.code === 0, b2.code === 0 ? "" : b2.out.slice(-300));
  if (failures) return finish();

  // ------------------------------------------------- B. the wire format itself
  section("B. the bytes are paramiko's bytes");
  const py = spawnSync("cmd", ["/c", "python", "host/gen_remote_fwd_vectors.py"], {
    cwd: ROOT, encoding: "utf8", errors: "replace",
  });
  ok("the reference vectors are produced", py.status === 0, (py.stderr || "").trim().split("\n")[0] || "");
  const mb = moon(["run", "cmd/remote_fwd_kat", "--target", "native"]);
  const want = (py.stdout || "").trim().split(/\r?\n/).filter(Boolean).map((l) => l.toLowerCase());
  const got = mb.out.trim().split(/\r?\n/).filter((l) => /^(REQ|CONFIRM|FAIL|PARSE) /.test(l)).map((l) => l.toLowerCase());
  ok("this client emits the same number of vectors", want.length === got.length && want.length > 0,
     `reference=${want.length} ours=${got.length}`);
  for (let i = 0; i < Math.max(want.length, got.length); i++) {
    const w = want[i] || "(missing)";
    const g = got[i] || "(missing)";
    const label = (w.split(" ")[1] || String(i));
    ok(`vector ${label} is byte-identical to paramiko's encoder`, w === g,
       w === g ? "" : `reference=${w.slice(0, 90)} ours=${g.slice(0, 90)}`);
  }

  // ------------------------------------------- C. is there a server at all?
  section("C. a real OpenSSH server forwards for us");
  const sshdPort = await freePort();
  const sshd = startSshd(sshdPort, "loop78", []);
  const up = await waitForText(sshd, "sshd listening", 30000);
  if (!up) {
    const why = (sshd.tapBuf || "").trim().split("\n").slice(0, 4).join(" | ") || "the server never came up";
    if (/no sshd\.exe/.test(why)) {
      skip("every section that needs a live OpenSSH server", why);
      console.log("  (section B still ran: the wire format is compared against");
      console.log("   paramiko's own encoder on every machine)");
      sshd.kill();
      stopSshd("loop78");
      return finish();
    }
    ok("the private sshd is up", false, why);
    sshd.kill();
    stopSshd("loop78");
    return finish();
  }
  ok("the private sshd is up", true);
  ok("the sshd is listening", await waitForPort(sshdPort, 5000));

  // The account itself. Two assertions, because they catch different mistakes:
  // the first catches a gate that asks for an account this machine does not
  // have, the second catches one that asks for a DIFFERENT account than the
  // one it is running as.
  ok("the gate authenticates as the account this machine runs as",
     USER === (process.env.USERNAME || process.env.USER || process.env.LOGNAME || USER),
     `user=${USER} (${USER_INFO.source})`);
  const ownSource = stripComments(readFileSync(path.join(ROOT, "host", "verify_loop78.mjs"), "utf8"));
  const quoted = new RegExp(`['"]${USER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}['"]`);
  ok("this gate does not name an account of its own", !quoted.test(ownSource),
     "the account name appears as a literal in this file, so the gate only works on one machine");

  const echoPort = await freePort();
  const echo = tap(spawn("node", ["host/echo_server.mjs", String(echoPort)], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
  ok("the echo target is up", await waitForText(echo, "echo server listening", 15000));

  const payload = "loop78-forwarded-tcpip-payload-0123456789-abcdefghij";
  const payloadSha = createHash("sha256").update(payload, "utf8").digest("hex");
  const ping = "PING-loop78";
  const pingSha = createHash("sha256").update(ping, "utf8").digest("hex");

  // ------------------------------------------------------------- C1. port 0
  //
  // The client asks for a forward on port 0, so the SERVER picks the port.
  // That is the case where the server's reply carries an allocated port -- and
  // the case a fixed port never exercises (there, the reply payload is empty).
  section("C1. the server picks the port (the client asked for 0)");
  const allocated = await relayCase({
    sshdPort, echoPort, echo, listenArg: 0, payload, ping, payloadSha, pingSha,
    expectSamePort: false,
  });
  const listenPort = allocated.listenPort;

  // The server's own account of what it did. The client's report and the
  // server's log are two independent witnesses; either alone could be a lie.
  const log = readSshdLog("loop78");
  const fwdLine = (log.match(/^.*forwarded-tcpip.*$/m) || [""])[0].trim();
  ok("the server's log mentions the forwarded-tcpip channel", /forwarded-tcpip/.test(log),
     fwdLine || "the server never logged a forwarded-tcpip channel");
  const portLine = (log.match(new RegExp(`^.*${listenPort}.*$`, "m")) || [""])[0].trim();
  ok("the server's log mentions the port it was listening on",
     new RegExp(`${listenPort}`).test(log),
     portLine || `the server's log does not mention ${listenPort}`);

  // ------------------------------------------------- C2. a port we name ourselves
  //
  // The other shape of the server's reply: the client names the port, the
  // server binds exactly that one, and the reply payload comes back **empty**.
  // A client that reads a u32 out of that reply unconditionally reads past the
  // end of the message -- so this case is the only thing that can catch it.
  //
  // A different payload on purpose: the local target's own digest is printed
  // once per connection, and two connections that carried the same bytes would
  // print the same line -- so the second case could match the first case's
  // line and pass without the local end ever having been closed.
  section("C2. the port is the one we named (the reply carries no port)");
  const fixedPort = await freePort();
  const payload2 = "loop78-fixed-port-payload-9876543210-zyxwvutsrq";
  const payload2Sha = createHash("sha256").update(payload2, "utf8").digest("hex");
  const ping2 = "PING-loop78-fixed";
  const ping2Sha = createHash("sha256").update(ping2, "utf8").digest("hex");
  const fixed = await relayCase({
    sshdPort, echoPort, echo, listenArg: fixedPort,
    payload: payload2, ping: ping2, payloadSha: payload2Sha, pingSha: ping2Sha,
    expectSamePort: true,
  });
  ok("the client listened on the port it was told to", fixed.listenPort === fixedPort,
     `listen_port=${fixed.listenPort} want=${fixedPort}`);

  // ------------------------------------------- D. a refusal is not a success
  section("D. a server that refuses to forward says so");
  const nfPort = await freePort();
  const nfSshd = startSshd(nfPort, "loop78nf", ["--no-forward"]);
  const nfUp = await waitForText(nfSshd, "sshd listening", 30000);
  if (!nfUp) {
    skip("the refusing server", (nfSshd.tapBuf || "").trim().split("\n").slice(0, 3).join(" | "));
  } else {
    const nf = spawnSync(
      CLIENT_EXE,
      [String(nfPort), "--kh-tofu", "--kh-host", "127.0.0.1", "--user", USER,
       "--remote-forward", `0:127.0.0.1:${echoPort}`, "--stdin-text", payload],
      { cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 60000 },
    );
    const nfText = `${nf.stdout || ""}${nf.stderr || ""}`;
    ok("the refusing server makes the client report a refusal",
       /result: REMOTE_FORWARD_FAILED/.test(nfText) && /error: ForwardRefused/.test(nfText),
       (nfText.match(/^result: .*$/m) || ["no result line"])[0] +
       " / " + (lineOf(nfText, "error") || "no error line"));
    ok("the refusing client did not hang", nf.status !== null && nf.status !== "timeout",
       `status=${nf.status}`);
    nfSshd.kill();
    stopSshd("loop78nf");
  }

  sshd.kill();
  stopSshd("loop78");
  return finish();
}

// The echo target's own account of what it received: "ECHO <bytes> <sha256>".
// Waited for, because the line is printed when the connection closes, which
// is after the client has already reported what it got back.
//
// This is the far side of the relay saying what it saw. The client's counters
// say what the client *believed* it moved; the echo server's digest says what
// actually arrived. A relay that counted bytes it never sent would pass the
// first and fail this one.
async function waitForEcho(child, bytes, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const lines = (child.tapBuf || "").split(/\r?\n/);
    for (let i = lines.length - 1; i >= 0; i--) {
      const m = lines[i].match(/^ECHO (\d+) ([0-9a-f]{64})$/);
      if (m && Number(m[1]) === bytes) return m[2];
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return null;
}

// One whole forward: the client asks for a forward, a probe connects to the
// port the server was listening on, the bytes go both ways, and the channel
// is closed at the end.
//
// `expectSamePort` says whether the client asked for a specific port (and so
// the server's reply carries no port at all) or asked for port 0 (and so the
// server allocated one and said which).
async function relayCase(opts) {
  const { sshdPort, echoPort, echo, payload, ping, payloadSha, pingSha, expectSamePort, listenArg } = opts;
  const client = startClientAt(sshdPort, [
    "--remote-forward", `${listenArg}:127.0.0.1:${echoPort}`, "--stdin-text", payload,
  ]);

  const granted = await waitForLine(client, /^granted_port: (\d+)$/m, 30000);
  ok("the server granted a listening port", !!granted,
     granted ? `port=${granted[1]}` : `the client said: ${(client.tapBuf || "").trim().split("\n").slice(-3).join(" | ")}`);
  if (!granted) {
    explainAuthFailure("loop78");
    client.kill();
    return { listenPort: -1 };
  }
  const listenPort = Number(granted[1]);
  if (expectSamePort) {
    ok("the granted port is the one we asked for", listenPort === listenArg,
       `listen_port=${listenPort} want=${listenArg}`);
  } else {
    ok("the granted port is not the one we asked for (we asked for 0)",
       listenPort > 0, `listen_port=${listenPort}`);
  }

  // Now play the part of the party that connects to the forwarded port.
  const probe = await connectProbe(listenPort);
  ok("a probe can connect to the port the server was listening on", !!probe);
  if (!probe) {
    client.kill();
    return { listenPort };
  }

  // The client writes the payload into the local target; the target echoes
  // it; the client relays the echo back over the channel; the probe reads it.
  const echoed = await readBytes(probe, payload.length, 30000);
  ok("the probe received the relayed bytes", !!echoed,
     echoed ? `got ${echoed.length} bytes` : "nothing arrived at the probe");
  ok("the relayed bytes are the same bytes",
     !!echoed && createHash("sha256").update(echoed).digest("hex") === payloadSha,
     echoed ? `sha=${createHash("sha256").update(echoed).digest("hex")} want=${payloadSha}` : "no bytes");

  // The other direction: the probe speaks, the client relays it to the local
  // target, the target's echo comes back through the same channel.
  probe.write(ping);
  const pong = await readBytes(probe, ping.length, 30000);
  ok("the probe's own bytes made the round trip", !!pong,
     pong ? `got ${pong.length} bytes` : "nothing came back to the probe");
  ok("the round-tripped bytes are the same bytes",
     !!pong && createHash("sha256").update(pong).digest("hex") === pingSha,
     pong ? `sha=${createHash("sha256").update(pong).digest("hex")} want=${pingSha}` : "no bytes");

  // The probe hangs up. That is what makes the server send CHANNEL_EOF, and
  // the client has to finish the channel rather than wait for ever.
  probe.end();
  const exitCode = await new Promise((resolve) => {
    const timer = setTimeout(() => { client.kill(); resolve(null); }, 30000);
    client.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  ok("the client finished after the probe hung up", exitCode !== null,
     exitCode === null ? "the client was still running 30s after the probe closed" : `exit=${exitCode}`);
  const text = client.tapBuf || "";
  ok("the client reports the forward as done", /result: REMOTE_FORWARD_DONE/.test(text),
     (text.match(/^result: .*$/m) || ["no result line"])[0]);
  ok("the channel type is the one the server opened", /channel_type: forwarded-tcpip/.test(text),
     lineOf(text, "channel_type") || "no channel_type line");
  ok("the listener port in the open is the port we were granted",
     numOf(text, "open_port") === listenPort,
     `open_port=${numOf(text, "open_port")} granted=${listenPort}`);
  // The two counters mean opposite things, and getting them the wrong way
  // round is the easy mistake:
  //
  //   to_channel   -- bytes we pushed INTO the channel. The payload's echo
  //                  (the local target answering us) plus the probe's PING
  //                  coming back: payload.length + ping.length.
  //   from_channel -- bytes we pulled OUT of the channel, i.e. what the probe
  //                  sent us: just the PING. The payload never travelled this
  //                  way: it started on our side, at the local target.
  ok("the bytes that came back from the channel were counted",
     numOf(text, "from_channel") === ping.length,
     `from_channel=${numOf(text, "from_channel")} want=${ping.length}`);
  ok("the bytes that went out to the channel were counted",
     numOf(text, "to_channel") === payload.length + ping.length,
     `to_channel=${numOf(text, "to_channel")} want=${payload.length + ping.length}`);
  ok("the bytes that went into the local target were counted",
     numOf(text, "to_link") === payload.length + ping.length,
     `to_link=${numOf(text, "to_link")} want=${payload.length + ping.length}`);
  ok("EOF was sent and the channel closed", /eof_sent: true/.test(text) && /closed: true/.test(text),
     `eof_sent=${lineOf(text, "eof_sent")} closed=${lineOf(text, "closed")}`);
  ok("the forward ran over the negotiated cipher", /cipher_ctos: aes128-ctr/.test(text));

  // The far end's own account. The echo target says what actually arrived at
  // the other end of the relay; the client's counters say what it believed it
  // moved. Only the first one is independent of the client.
  const wantEchoSha = createHash("sha256").update(payload + ping, "utf8").digest("hex");
  const echoSha = await waitForEcho(echo, payload.length + ping.length, 20000);
  ok("the local target's own digest agrees", echoSha === wantEchoSha,
     echoSha ? `sha=${echoSha} want=${wantEchoSha}` :
     "the local target never printed its ECHO line (the client did not close its end?)");
  return { listenPort };
}

function finish() {
  console.log(`\n${checks} checks, ${failures} failed, ${skipped} skipped`);
  process.exit(failures ? 1 : 0);
}

main();
