#!/usr/bin/env node
// host/verify_loop79.mjs -- Loop #79: the local listener, the other half of
// `ssh -L`.
//
// ## What is being claimed
//
// `ssh -L 9000:db:5432 host` is, at the protocol level, two things:
//
//   1. the client **listens** on a local port, and
//   2. every connection that arrives on that port becomes one
//      "direct-tcpip" channel to the server (RFC 4254 section 7), and the
//      bytes are relayed to and from the server's target.
//
// Loop #76 built the channel half. Nothing listened: there was no
// `listen()` anywhere in the repository, so a client could open a
// direct-tcpip channel but there was no way for a local program to reach one.
// This loop adds the listener, and the relay that drives it.
//
// ## The evidence, and why each piece is here
//
// 1. **The listener works on its own.** `cmd/listen_kat` binds, reports the
//    port it actually got, accepts one connection, and echoes the bytes
//    back. It needs no SSH server, so it runs everywhere -- including on a
//    machine that has no OpenSSH at all.
//
// 2. **A real server forwards for us.** A probe connects to the port the
//    client is listening on; the client opens a direct-tcpip channel; the
//    server connects to the target; the bytes come back to the probe. Both
//    directions are checked, because a relay that only moves one way is not
//    a relay.
//
// 3. **The far end says what it saw.** The echo target prints a digest of
//    everything it received; the client prints a digest of everything it
//    relayed. The client's counters say what it *believed* it moved; the
//    target's digest says what actually arrived. Only the second one is
//    independent of the client.
//
// 4. **The originator is the real one.** Loop #76 could only fill in
//    "127.0.0.1", 0, because nobody was listening and there was no peer
//    address to report. The server's own log now says which port the probe
//    connected from, and the gate compares that with the port the probe
//    actually used. Two independent witnesses of the same number.
//
// 5. **More bytes than the window holds.** The SSH channel window is 2 MiB.
//    Moving 4 MiB means the window has to close and reopen, and that is the
//    path where the relay used to lose data: `stdin_take` clips to the
//    window and returns the rest, and the rest used to be dropped. The far
//    end stops reading until the gate lets it, so the window really does
//    close -- a target that reads as fast as it can would never exercise
//    the path at all.
//
// 6. **The refusal is told apart from the success.** A server with
//    `AllowTcpForwarding no` refuses the channel. That has to come out as a
//    refusal, not as a hang and not as a silent success.
//
// 7. **Nobody connecting is told apart from a broken listener.** A forward
//    nobody uses is not an error; a listener that cannot accept is.
//
// ## What runs where
//
// Sections A and B need only node and a compiler, so they run everywhere.
// The rest needs an OpenSSH **server**. When there is none, those sections
// are **skipped loudly** rather than quietly passed: a machine that cannot
// run a check has not run it.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { sshUserInfo } from "./ssh_user.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop79");

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

const CLIENT_EXE = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe");

// Start the client with the sshd's port in front of the arguments.
//
// It has to run **asynchronously**: the whole point of a local forward is
// that the client waits for somebody to connect to the port it is listening
// on, and the gate is that somebody. A synchronous client would be waiting
// for a connection that only the gate can make, and the gate would be
// waiting for the client.
function startClientAt(sshdPort, extra) {
  const child = spawn(
    CLIENT_EXE,
    [String(sshdPort), "--kh-tofu", "--kh-host", "127.0.0.1", "--user", USER, ...extra],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  return tap(child);
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

// Comments explaining a bug necessarily contain the bug's text, so a source
// scan has to take them out before it looks for anything.
function stripComments(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

// The far end's own account of what it received: "ECHO <bytes> <sha256>".
// Waited for, because the line is printed when the connection closes, which
// is after the client has already reported what it got back.
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

async function waitForSink(child, bytes, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const lines = (child.tapBuf || "").split(/\r?\n/);
    for (let i = lines.length - 1; i >= 0; i--) {
      const m = lines[i].match(/^SINK (\d+) ([0-9a-f]{64})$/);
      if (m && Number(m[1]) === bytes) return m[2];
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  return null;
}

async function main() {
  mkdirSync(WORK, { recursive: true });
  for (const n of ["loop79", "loop79nf"]) rmSync(sshdLog(n), { force: true });

  // ---------------------------------------------------------------- A. build
  section("A. the code builds");
  const b1 = moon(["build", "cmd/ssh_live", "--target", "native"]);
  ok("cmd/ssh_live builds (native)", b1.code === 0, b1.code === 0 ? "" : b1.out.slice(-300));
  const b2 = moon(["build", "cmd/listen_kat", "--target", "native"]);
  ok("cmd/listen_kat builds (native)", b2.code === 0, b2.code === 0 ? "" : b2.out.slice(-300));
  if (failures) return finish();

  // ----------------------------------------- B. the listener, on its own
  //
  // No SSH server anywhere near this one. It proves the Winsock listener
  // binds, reports the port it actually got, accepts, and sees the peer's
  // real address -- the three things the rest of the loop stands on.
  section("B. the listener works without any SSH server");
  const katPayload = "loop79-listener-kat-payload-0123456789";
  const katHex = Buffer.from(katPayload, "utf8").toString("hex");
  const kat = tap(spawn("moon", ["run", "cmd/listen_kat", "--target", "native"], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
  const katPortLine = await waitForLine(kat, /^listen_port: (\d+)$/m, 30000);
  ok("the listener reports the port it is on", !!katPortLine,
     katPortLine ? `port=${katPortLine[1]}` :
     `the program said: ${(kat.tapBuf || "").trim().split("\n").slice(-3).join(" | ")}`);
  if (katPortLine) {
    const katPort = Number(katPortLine[1]);
    ok("the port it reports is a real port", katPort > 0 && katPort <= 65535, `port=${katPort}`);
    const katProbe = await connectProbe(katPort);
    ok("a program can connect to it", !!katProbe);
    if (katProbe) {
      const katLocalPort = katProbe.localPort;
      katProbe.write(katPayload);
      const katBack = await readBytes(katProbe, katPayload.length, 15000);
      ok("the bytes come back unchanged", !!katBack && katBack.toString("utf8") === katPayload,
         katBack ? `got ${katBack.length} bytes` : "nothing came back");
      katProbe.end();
      const katExit = await new Promise((resolve) => {
        const timer = setTimeout(() => { kat.kill(); resolve(null); }, 20000);
        kat.on("exit", (c) => { clearTimeout(timer); resolve(c); });
      });
      ok("the listener program finished", katExit !== null, katExit === null ? "it was still running" : `exit=${katExit}`);
      const katText = kat.tapBuf || "";
      ok("it saw the peer's real address", lineOf(katText, "peer_ip") === "127.0.0.1",
         `peer_ip=${lineOf(katText, "peer_ip")}`);
      ok("it saw the peer's real port", numOf(katText, "peer_port") === katLocalPort,
         `peer_port=${numOf(katText, "peer_port")} want=${katLocalPort}`);
      ok("it read exactly what was sent", (lineOf(katText, "recv") || "").toLowerCase() === katHex,
         `recv=${lineOf(katText, "recv")}`);
      ok("it echoed exactly what it read", (lineOf(katText, "echoed") || "").toLowerCase() === katHex,
         `echoed=${lineOf(katText, "echoed")}`);
    }
  }

  // ------------------------------------------- C. is there a server at all?
  section("C. a real OpenSSH server forwards for us");
  const sshdPort = await freePort();
  const sshd = startSshd(sshdPort, "loop79", []);
  const up = await waitForText(sshd, "sshd listening", 30000);
  if (!up) {
    const why = (sshd.tapBuf || "").trim().split("\n").slice(0, 4).join(" | ") || "the server never came up";
    if (/no sshd\.exe/.test(why)) {
      skip("every section that needs a live OpenSSH server", why);
      console.log("  (sections A and B still ran: the listener is checked on every machine)");
      sshd.kill();
      stopSshd("loop79");
      return finish();
    }
    ok("the private sshd is up", false, why);
    sshd.kill();
    stopSshd("loop79");
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
  const ownSource = stripComments(readFileSync(path.join(ROOT, "host", "verify_loop79.mjs"), "utf8"));
  const quoted = new RegExp(`['"]${USER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}['"]`);
  ok("this gate does not name an account of its own", !quoted.test(ownSource),
     "the account name appears as a literal in this file, so the gate only works on one machine");

  const echoPort = await freePort();
  const echo = tap(spawn("node", ["host/echo_server.mjs", String(echoPort)], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
  ok("the echo target is up", await waitForText(echo, "echo server listening", 15000));

  // ------------------------------------------------------------- C1. one turn
  section("C1. a local connection becomes a channel, and the bytes go both ways");
  const payload = "loop79-local-forward-payload-0123456789-abcdefghij";
  const payloadSha = createHash("sha256").update(payload, "utf8").digest("hex");
  const ping = "PING-loop79-local";
  const pingSha = createHash("sha256").update(ping, "utf8").digest("hex");
  const one = await relayCase({ sshdPort, echoPort, echo, payload, ping, payloadSha, pingSha });
  const listenPort = one.listenPort;

  // The server's own account of what it did. The client's report and the
  // server's log are two independent witnesses; either alone could be a lie.
  const log = readSshdLog("loop79");
  ok("the server's log mentions the direct-tcpip channel", /direct-tcpip/.test(log),
     (log.match(/^.*direct-tcpip.*$/m) || [""])[0].trim() || "the server never logged a direct-tcpip channel");
  const origLine = (log.match(/^.*server_request_direct_tcpip.*$/m) || [""])[0].trim();
  ok("the server's log mentions the originator's address and port", /originator 127\.0\.0\.1 port \d+/.test(log),
     origLine || "the server never logged an originator");
  // The number in the log and the number in the client's report are the same
  // number, produced on two different machines (well, two different pieces of
  // code): the probe's real ephemeral port. Loop #76 could only put "0" here.
  ok("the originator the server saw is the probe's real port",
     origLine.includes(`port ${one.probePort}`),
     `the server said "${origLine}", the probe used port ${one.probePort}`);

  // ------------------------------------------ C2. two connections, one session
  //
  // `ssh -L` is one SSH connection and many channels. A client that
  // re-authenticates per connection would be a different (and much worse)
  // program, and the symptom -- the server's log showing two *sessions*
  // instead of two channels -- is what this checks.
  section("C2. two local connections over ONE ssh session");
  // The server's log is shared by every case so far, so only the part that
  // this case adds is looked at. Otherwise the first case's channel would be
  // counted as one of this case's two.
  const logBeforeC2 = readSshdLog("loop79").length;
  const two = await twoConnectionCase({ sshdPort, echoPort, echo });
  ok("the client reports two connections", numOf(two.text, "connections") === 2,
     `connections=${numOf(two.text, "connections")}`);
  const logSlice = readSshdLog("loop79").slice(logBeforeC2);
  // "rchan" is the channel number the **client** chose. Two connections on
  // one session have to use two different numbers, or the server cannot tell
  // them apart.
  const rchans = [...new Set(
    [...logSlice.matchAll(/server_input_channel_open: ctype direct-tcpip rchan (\d+)/g)].map((m) => m[1]),
  )];
  ok("the server saw two channels with different numbers", rchans.length === 2,
     `rchan values: ${rchans.join(", ") || "(none)"}`);
  ok("the two connections were on one ssh session",
     (logSlice.match(/^.*Accepted publickey for .*$/gm) || []).length === 1,
     `${(logSlice.match(/^.*Accepted publickey for .*$/gm) || []).length} authentication(s) in the log`);

  // ------------------------------------------------- D. more than the window
  //
  // The SSH channel window is 2 MiB. Moving 4 MiB means it has to close and
  // reopen, and that is where the relay used to drop bytes.
  section("D. more bytes than the channel window holds");
  const big = await windowCase({ sshdPort });
  if (big.skipped) {
    skip("the window case", big.why);
  } else {
    ok("the far end received every byte", big.sinkBytes === big.total,
       `the sink got ${big.sinkBytes} bytes, the probe sent ${big.total}`);
    ok("the far end's digest agrees with the bytes sent", big.sinkSha === big.wantSha,
       `sha=${big.sinkSha} want=${big.wantSha}`);
    ok("the client counted every byte it moved", big.clientBytes === big.total,
       `local_to_channel=${big.clientBytes} want=${big.total}`);
    ok("the window really was smaller than the transfer", big.window < big.total,
       `the server's window was ${big.window} bytes and the transfer was ${big.total}`);
  }

  // ------------------------------------------- E. a refusal is not a success
  section("E. a server that refuses to forward says so");
  const nfPort = await freePort();
  const nfSshd = startSshd(nfPort, "loop79nf", ["--no-forward"]);
  const nfUp = await waitForText(nfSshd, "sshd listening", 30000);
  if (!nfUp) {
    skip("the refusing server", (nfSshd.tapBuf || "").trim().split("\n").slice(0, 3).join(" | "));
  } else {
    const nf = startClientAt(nfPort, ["--local-forward", `0:127.0.0.1:${echoPort}`]);
    const nfPortLine = await waitForLine(nf, /^listen_port: (\d+)$/m, 30000);
    ok("the refusing client still listens", !!nfPortLine,
       nfPortLine ? `port=${nfPortLine[1]}` : "the client never reported a port");
    if (nfPortLine) {
      const p = await connectProbe(Number(nfPortLine[1]));
      ok("a probe can still connect to it", !!p);
      if (p) p.end();
    }
    const nfExit = await new Promise((resolve) => {
      const timer = setTimeout(() => { nf.kill(); resolve(null); }, 30000);
      nf.on("exit", (c) => { clearTimeout(timer); resolve(c); });
    });
    const nfText = nf.tapBuf || "";
    ok("the refusing server makes the client report a refusal",
       /result: LOCAL_FORWARD_FAILED/.test(nfText) && /error: OpenFailed/.test(nfText),
       (nfText.match(/^result: .*$/m) || ["no result line"])[0] +
       " / " + (lineOf(nfText, "error") || "no error line"));
    ok("the refusing client did not hang", nfExit !== null,
       nfExit === null ? "the client was still running 30s after the refusal" : `exit=${nfExit}`);
    nfSshd.kill();
    stopSshd("loop79nf");
  }

  // --------------------------------------- F. nobody connects is not an error
  //
  // A forward nobody uses is not a failure, and a listener that cannot
  // accept is. The client is told how many idle rounds to tolerate; after
  // that it says "nobody came" rather than waiting for ever.
  section("F. nobody connects is told apart from a broken listener");
  const idle = spawnSync(
    CLIENT_EXE,
    [String(sshdPort), "--kh-tofu", "--kh-host", "127.0.0.1", "--user", USER,
     "--local-forward", `0:127.0.0.1:${echoPort}`, "--max-idle-rounds", "2"],
    { cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 60000 },
  );
  const idleText = `${idle.stdout || ""}${idle.stderr || ""}`;
  ok("the client says nobody connected",
     /result: LOCAL_FORWARD_FAILED/.test(idleText) && /error: NoConnection/.test(idleText),
     (idleText.match(/^result: .*$/m) || ["no result line"])[0] +
     " / " + (lineOf(idleText, "error") || "no error line"));
  ok("the idle client did not hang", idle.status !== null && idle.status !== "timeout",
     `status=${idle.status}`);

  sshd.kill();
  stopSshd("loop79");
  return finish();
}

// One whole forward: the client listens, a probe connects to the port it is
// listening on, the bytes go both ways, and the channel is closed at the end.
async function relayCase(opts) {
  const { sshdPort, echoPort, echo, payload, ping, payloadSha, pingSha } = opts;
  const client = startClientAt(sshdPort, [
    "--local-forward", `0:127.0.0.1:${echoPort}`, "--max-conns", "1",
  ]);

  const lp = await waitForLine(client, /^listen_port: (\d+)$/m, 30000);
  ok("the client reports the port it is listening on", !!lp,
     lp ? `port=${lp[1]}` :
     `the client said: ${(client.tapBuf || "").trim().split("\n").slice(-3).join(" | ")}`);
  if (!lp) {
    client.kill();
    return { listenPort: -1, probePort: -1 };
  }
  const listenPort = Number(lp[1]);
  ok("the port it reports is a real port", listenPort > 0 && listenPort <= 65535,
     `listen_port=${listenPort}`);

  // Now play the part of the party that connects to the forwarded port.
  const probe = await connectProbe(listenPort);
  ok("a probe can connect to the port the client is listening on", !!probe);
  if (!probe) {
    client.kill();
    return { listenPort, probePort: -1 };
  }
  const probePort = probe.localPort;

  // The probe speaks; the client relays it to the server's target; the
  // target echoes it; the client relays the echo back.
  probe.write(payload);
  const echoed = await readBytes(probe, payload.length, 30000);
  ok("the probe received the relayed bytes", !!echoed,
     echoed ? `got ${echoed.length} bytes` : "nothing arrived at the probe");
  ok("the relayed bytes are the same bytes",
     !!echoed && createHash("sha256").update(echoed).digest("hex") === payloadSha,
     echoed ? `sha=${createHash("sha256").update(echoed).digest("hex")} want=${payloadSha}` : "no bytes");

  // The other direction: the probe sends more, and gets it back.
  probe.write(ping);
  const pong = await readBytes(probe, ping.length, 30000);
  ok("the probe's second write made the round trip", !!pong,
     pong ? `got ${pong.length} bytes` : "nothing came back to the probe");
  ok("the round-tripped bytes are the same bytes",
     !!pong && createHash("sha256").update(pong).digest("hex") === pingSha,
     pong ? `sha=${createHash("sha256").update(pong).digest("hex")} want=${pingSha}` : "no bytes");

  // The probe hangs up. That is what makes the client finish the channel
  // rather than wait for ever.
  probe.end();
  const exitCode = await new Promise((resolve) => {
    const timer = setTimeout(() => { client.kill(); resolve(null); }, 30000);
    client.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  ok("the client finished after the probe hung up", exitCode !== null,
     exitCode === null ? "the client was still running 30s after the probe closed" : `exit=${exitCode}`);
  const text = client.tapBuf || "";
  ok("the client reports the forward as done", /result: LOCAL_FORWARD_DONE/.test(text),
     (text.match(/^result: .*$/m) || ["no result line"])[0]);
  ok("the bytes that went into the channel were counted",
     numOf(text, "local_to_channel") === payload.length + ping.length,
     `local_to_channel=${numOf(text, "local_to_channel")} want=${payload.length + ping.length}`);
  ok("the bytes that came out of the channel were counted",
     numOf(text, "channel_to_local") === payload.length + ping.length,
     `channel_to_local=${numOf(text, "channel_to_local")} want=${payload.length + ping.length}`);
  ok("the client reported the probe's real address",
     numOf(text, "originator_port") === probePort,
     `originator_port=${numOf(text, "originator_port")} want=${probePort}`);
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
  return { listenPort, probePort };
}

// Two connections, one SSH session.
async function twoConnectionCase(opts) {
  const { sshdPort, echoPort } = opts;
  const client = startClientAt(sshdPort, [
    "--local-forward", `0:127.0.0.1:${echoPort}`, "--max-conns", "2",
  ]);
  const lp = await waitForLine(client, /^listen_port: (\d+)$/m, 30000);
  ok("the client reports the port it is listening on", !!lp,
     lp ? `port=${lp[1]}` : "the client never reported a port");
  if (!lp) {
    client.kill();
    return { text: "" };
  }
  const listenPort = Number(lp[1]);
  for (const tag of ["one", "two"]) {
    const probe = await connectProbe(listenPort);
    ok(`the ${tag} probe can connect`, !!probe);
    if (!probe) break;
    const msg = `loop79-second-connection-${tag}`;
    probe.write(msg);
    const back = await readBytes(probe, msg.length, 30000);
    ok(`the ${tag} connection carried its bytes`, !!back && back.toString("utf8") === msg,
       back ? `got ${back.length} bytes` : "nothing came back");
    probe.end();
    await new Promise((r) => setTimeout(r, 500));
  }
  const exitCode = await new Promise((resolve) => {
    // The client may already have exited before this listener was attached --
    // the 'exit' event fires once, and attaching afterwards hears nothing.
    // A gate that waits 30 seconds for an event that already happened is a
    // gate that reports a hang that did not happen.
    if (client.exitCode !== null) return resolve(client.exitCode);
    const timer = setTimeout(() => { client.kill(); resolve(null); }, 30000);
    client.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  ok("the client finished after two connections", exitCode !== null,
     exitCode === null ? "the client was still running 30s after the second connection" : `exit=${exitCode}`);
  return { text: client.tapBuf || "" };
}

// The window case: more bytes than the channel window holds.
//
// The far end is a sink that does not read until the gate says so, so the
// window really does close. Then the gate lets it read and checks that
// every byte arrived.
async function windowCase(opts) {
  const { sshdPort } = opts;
  const sinkPort = await freePort();
  const goFile = path.join(WORK, "sink_go");
  rmSync(goFile, { force: true });
  const sink = tap(spawn("node", ["host/sink_server.mjs", String(sinkPort), goFile], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
  if (!await waitForText(sink, "sink server listening", 15000)) {
    sink.kill();
    return { skipped: true, why: "the sink target did not come up" };
  }
  const client = startClientAt(sshdPort, [
    "--local-forward", `0:127.0.0.1:${sinkPort}`, "--max-conns", "1",
  ]);
  const lp = await waitForLine(client, /^listen_port: (\d+)$/m, 30000);
  if (!lp) {
    client.kill();
    sink.kill();
    return { skipped: true, why: "the client never reported a port" };
  }
  const listenPort = Number(lp[1]);
  const probe = await connectProbe(listenPort);
  if (!probe) {
    client.kill();
    sink.kill();
    return { skipped: true, why: "the probe could not connect" };
  }

  // Four megabytes of a deterministic pattern. Bigger than the 2 MiB
  // channel window, so the window has to close and reopen at least once.
  const total = 4 * 1024 * 1024;
  const chunk = Buffer.alloc(64 * 1024);
  for (let i = 0; i < chunk.length; i++) chunk[i] = (i * 7 + 13) & 0xff;
  const big = Buffer.concat(Array.from({ length: total / chunk.length }, () => chunk));
  const wantSha = createHash("sha256").update(big).digest("hex");

  let written = false;
  probe.write(big, () => { written = true; });
  // Give the relay time to fill the window and stall on it. The far end is
  // not reading, so the window cannot reopen until the gate lets it.
  await new Promise((r) => setTimeout(r, 4000));
  writeFileSync(goFile, "go\n");

  const deadline = Date.now() + 120000;
  while (Date.now() < deadline && !written) {
    await new Promise((r) => setTimeout(r, 200));
  }
  ok("the probe managed to send every byte", written,
     written ? "" : "the probe's write never completed");
  probe.end();

  const exitCode = await new Promise((resolve) => {
    const timer = setTimeout(() => { client.kill(); resolve(null); }, 60000);
    client.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  ok("the client finished after the big transfer", exitCode !== null,
     exitCode === null ? "the client was still running 60s after the transfer" : `exit=${exitCode}`);
  const text = client.tapBuf || "";

  let sinkBytes = -1;
  let sinkSha = null;
  const sd = Date.now() + 60000;
  while (Date.now() < sd && sinkSha === null) {
    const m = (sink.tapBuf || "").match(/^SINK (\d+) ([0-9a-f]{64})$/m);
    if (m) {
      sinkBytes = Number(m[1]);
      sinkSha = m[2];
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  sink.kill();

  // The window the server advertised, from the server's own log. It has to
  // be smaller than the transfer, or the case proved nothing.
  const log = readSshdLog("loop79");
  const winMatch = log.match(/server_input_channel_open: ctype direct-tcpip rchan \d+ win (\d+)/);
  const window = winMatch ? Number(winMatch[1]) : 0;
  return {
    skipped: false,
    total,
    sinkBytes,
    sinkSha,
    wantSha,
    window,
    clientBytes: numOf(text, "local_to_channel"),
  };
}

function finish() {
  console.log(`\n${checks} checks, ${failures} failed, ${skipped} skipped`);
  process.exit(failures ? 1 : 0);
}

main();
