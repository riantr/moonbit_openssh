#!/usr/bin/env node
// host/verify_loop76.mjs -- Loop #76: direct-tcpip, the client half of a
// local port forward.
//
// ## What is being claimed
//
// `ssh -L 8080:db:5432` is, at the protocol level, one thing: the client
// opens a channel of type "direct-tcpip" and asks the **server** to connect
// to db:5432; after that the channel carries the TCP connection's bytes
// (RFC 4254 section 7.2). This repository had no implementation of it at
// all -- `src/kexflow` and `src/sshclient` could not even name the channel
// type.
//
// ## The evidence, and why each piece is here
//
// 1. **The bytes are what paramiko's encoder produces.** `cmd/forward_kat`
//    prints this client's CHANNEL_OPEN payload; `host/gen_forward_vectors.py`
//    prints the same payload built with paramiko's own `Message` encoder. They
//    have to be equal, byte for byte. Comparing our encoder with our encoder
//    would prove nothing, and the server is *tolerant* about the fields it
//    does not use -- an originator it cannot parse, for instance -- so a
//    layout that is right where it matters and wrong where it does not would
//    pass every end-to-end test and still be a wrong wire format.
//
// 2. **The server read our packet the way we meant it.** The sshd's own log
//    prints the channel type and the destination it decoded out of our
//    payload. That is a third party parsing our bytes and telling us what it
//    saw.
//
// 3. **The bytes survive the round trip.** The client's payload comes back
//    unchanged, over a real OpenSSH server, through a real TCP target.
//
// 4. **A second implementation agrees.** paramiko does the same transfer
//    through the same server to the same target and gets the same bytes back.
//    Two different implementations making the same request and getting the
//    same answer is the only comparison that cannot be satisfied by both of
//    them being wrong in the same way.
//
// 5. **The two failure modes are told apart.** They are not the same failure
//    and they arrive by different routes:
//      * the server refuses to forward at all -> CHANNEL_OPEN_FAILURE,
//        reason 1 (administratively prohibited) -- synchronous, and reported;
//      * the server accepts the channel and then cannot reach the target ->
//        the connect is **asynchronous** (measured: the server confirms the
//        open first and only then fails the connect), so the protocol carries
//        no failure message at all and the channel just closes.
//
//    OpenSSH's own client treats the second one as success: `ssh -W` against a
//    dead port exits 0 with empty stdout and empty stderr. This gate requires
//    the opposite -- silence must not be reported as a successful forward.
//
// ## What runs where
//
// Section B needs only node and paramiko, so it runs everywhere. The rest
// needs an OpenSSH **server**. No gate in the default CI tier has ever
// needed one -- every gate that does is in the peer-gates tier, which CI does
// not run -- so whether the runner has an sshd at all is unproven. When there
// is none, those sections are **skipped loudly** rather than quietly passed:
// a machine that cannot run a check has not run it, and saying otherwise is
// the failure this repository keeps having to undo.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop76");

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

// A child's stdout, accumulated as it arrives. The sshd_setup helper prints
// "sshd listening" once the server is up, and prints the three directories it
// looked in when there is none -- so the same buffer answers both questions.
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

// The echo target's own account of what it received: "ECHO <bytes> <sha256>".
// Waited for, because the line is printed when the connection closes, which is
// after the client has already reported what it got back.
async function waitForEcho(child, bytes, timeoutMs = 15000) {
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

// The client, run to completion. The output is parsed as `key: value` lines,
// which is the shape every other gate in this repository reads.
function runClient(port, extra) {
  const r = spawnSync(
    path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_live", "ssh_live.exe"),
    [String(port), "--kh-tofu", "--kh-host", "127.0.0.1", "--user", "hp", ...extra],
    { cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024, timeout: 90000 },
  );
  return { code: r.status, text: `${r.stdout || ""}${r.stderr || ""}` };
}

// Each instance gets its own name, so the config, the pid file and the log
// are its own. Two instances sharing a name would overwrite each other's
// config while the first was still running, and the stop would only reach one
// of them.
function startSshd(port, name, extra) {
  return tap(spawn("node", ["host/sshd_setup.mjs", "--port", String(port), "--name", name, ...extra], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
}

function stopSshd(name) {
  spawnSync("node", ["host/sshd_setup.mjs", "--stop", "--name", name], { cwd: ROOT, encoding: "utf8" });
}

// The sshd_setup `--name` lever namespaces by *suffix*, so the log for instance
// "loop76" is "sshd.log_loop76" -- the suffix goes after the extension, not
// before the stem. (A wrong guess here reads as "the server logged nothing",
// which is a different claim entirely.)
function sshdLog(name) {
  return path.join(ROOT, ".loop31", "sshd", `sshd.log_${name}`);
}

// The server's own reading of our packet. Read while the server is still up:
// its log is the child's stdout, so the tail of it is only guaranteed to be
// on disk while it is being written.
function readSshdLog(name) {
  try {
    return readFileSync(sshdLog(name), "utf8");
  } catch (e) {
    return "";
  }
}

async function main() {
  mkdirSync(WORK, { recursive: true });
  rmSync(sshdLog("loop76"), { force: true });
  rmSync(sshdLog("loop76nf"), { force: true });

  // ---------------------------------------------------------------- A. build
  section("A. the code builds");
  const b1 = moon(["build", "cmd/ssh_live", "--target", "native"]);
  ok("cmd/ssh_live builds (native)", b1.code === 0, b1.code === 0 ? "" : b1.out.slice(-300));
  const b2 = moon(["build", "cmd/forward_kat", "--target", "native"]);
  ok("cmd/forward_kat builds (native)", b2.code === 0, b2.code === 0 ? "" : b2.out.slice(-300));
  if (failures) return finish();

  // ------------------------------------------------- B. the wire format itself
  section("B. the CHANNEL_OPEN bytes are paramiko's bytes");
  const py = spawnSync("cmd", ["/c", "python", "host/gen_forward_vectors.py"], {
    cwd: ROOT, encoding: "utf8", errors: "replace",
  });
  ok("the reference vectors are produced", py.status === 0, (py.stderr || "").trim().split("\n")[0] || "");
  const mb = moon(["run", "cmd/forward_kat", "--target", "native"]);
  const want = (py.stdout || "").trim().split(/\r?\n/).filter(Boolean).map((l) => l.toLowerCase());
  const got = mb.out.trim().split(/\r?\n/).filter((l) => l.startsWith("OPEN ")).map((l) => l.toLowerCase());
  ok("this client emits the same number of vectors", want.length === got.length && want.length > 0,
     `reference=${want.length} ours=${got.length}`);
  for (let i = 0; i < Math.max(want.length, got.length); i++) {
    const w = want[i] || "(missing)";
    const g = got[i] || "(missing)";
    const label = (w.split(" ")[1] || String(i));
    ok(`vector ${label} is byte-identical to paramiko's encoder`, w === g,
       w === g ? "" : `reference=${w.slice(0, 80)} ours=${g.slice(0, 80)}`);
  }

  // ------------------------------------------- C. is there a server at all?
  section("C. a real OpenSSH server forwards for us");
  const sshdPort = await freePort();
  const sshd = startSshd(sshdPort, "loop76", []);
  const up = await waitForText(sshd, "sshd listening", 30000);
  if (!up) {
    const why = (sshd.tapBuf || "").trim().split("\n").slice(0, 4).join(" | ") || "the server never came up";
    if (/no sshd\.exe/.test(why)) {
      skip("every section that needs a live OpenSSH server", why);
      console.log("  (section B still ran: the wire format is compared against");
      console.log("   paramiko's own encoder on every machine)");
      sshd.kill();
      stopSshd("loop76");
      return finish();
    }
    ok("the private sshd is up", false, why);
    sshd.kill();
    stopSshd("loop76");
    return finish();
  }
  ok("the private sshd is up", true);
  ok("the sshd is listening", await waitForPort(sshdPort, 5000));

  const keys = spawnSync("cmd", ["/c", "python", "host/ecdsa_auth_oracle.py", "--json",
    "--authorized-keys", ".loop31/sshd/authorized_keys"], { cwd: ROOT, encoding: "utf8" });
  ok("the test key is in authorized_keys", keys.status === 0,
     (keys.stdout || keys.stderr || "").trim().split("\n")[0]);

  const echoPort = await freePort();
  const echo = tap(spawn("node", ["host/echo_server.mjs", String(echoPort)], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  }));
  ok("the echo target is up", await waitForText(echo, "echo server listening", 15000));

  const payload = "loop76-direct-tcpip-payload-0123456789-abcdefghijklmnop";
  const payloadSha = createHash("sha256").update(payload, "utf8").digest("hex");

  const fwd = runClient(sshdPort, ["--forward", `127.0.0.1:${echoPort}`, "--stdin-text", payload]);
  ok("the forward runs", fwd.text.includes("result: FORWARD_DONE"),
     (fwd.text.match(/^result: .*$/m) || ["no result line"])[0]);
  ok("every byte came back", numOf(fwd.text, "stdout_len") === payload.length,
     `stdout_len=${numOf(fwd.text, "stdout_len")} want=${payload.length}`);
  ok("the bytes are the same bytes", lineOf(fwd.text, "stdout_sha256") === payloadSha.toUpperCase(),
     `sha=${lineOf(fwd.text, "stdout_sha256")} want=${payloadSha.toUpperCase()}`);
  ok("the payload went out in one piece", numOf(fwd.text, "stdin_sent") === payload.length &&
     numOf(fwd.text, "stdin_packets") === 1,
     `sent=${numOf(fwd.text, "stdin_sent")} packets=${numOf(fwd.text, "stdin_packets")}`);
  ok("EOF followed the data, and the channel closed", /eof_sent: true/.test(fwd.text) &&
     /closed: true/.test(fwd.text));
  ok("the forward ran over the negotiated cipher", /cipher_ctos: aes128-ctr/.test(fwd.text));

  // --------------------------------- C2. a payload that needs several packets
  section("C2. a payload larger than one packet is split and reassembled");
  // The window clamp is the part of the forwarding that a small payload never
  // exercises: at 55 bytes there is exactly one CHANNEL_DATA and the maximum
  // packet size is never consulted. This case is the one that does.
  const BIG = 100000;
  const big = runClient(sshdPort, ["--forward", `127.0.0.1:${echoPort}`, "--stdin-bytes", String(BIG)]);
  ok("the big forward runs", /result: FORWARD_DONE/.test(big.text),
     (big.text.match(/^result: .*$/m) || ["no result line"])[0]);
  const maxPacket = numOf(big.text, "remote_max_packet") || 32768;
  const wantPackets = Math.ceil(BIG / maxPacket);
  ok("the payload was split into packets the peer can accept",
     numOf(big.text, "stdin_packets") === wantPackets && wantPackets > 1,
     `packets=${numOf(big.text, "stdin_packets")} want=${wantPackets} max_packet=${maxPacket}`);
  ok("every byte came back", numOf(big.text, "stdout_len") === BIG,
     `stdout_len=${numOf(big.text, "stdout_len")} want=${BIG}`);
  // The digest is computed by the **target**: what the far end of the forward
  // received. Comparing it with the client's own digest checks the content
  // end to end without either side having to know what the payload was.
  const echoDigest = await waitForEcho(echo, BIG);
  ok("the target received exactly the bytes that came back",
     echoDigest !== null && lineOf(big.text, "stdout_sha256") === echoDigest.toUpperCase(),
     echoDigest ? `target=${echoDigest} client=${lineOf(big.text, "stdout_sha256")}` : "the target reported nothing");

  section("D. the server's own reading of our packet");
  // Asserted on the *facts*, not on OpenSSH's wording. A log line that says
  // the same thing in another way is still the server telling us what it
  // read; a log that does not contain the fact at all is a real problem.
  const log = readSshdLog("loop76");
  const logLines = log.split(/\r?\n/);
  ok("the server logged the channel open", /direct-tcpip/.test(log),
     log ? "" : `the sshd log could not be read (${sshdLog("loop76")})`);
  ok("the server decoded the destination we asked for",
     logLines.some((l) => l.includes("127.0.0.1") && new RegExp(`\\b${echoPort}\\b`).test(l)),
     `looking for 127.0.0.1 and ${echoPort} in the server's log`);
  // The window and the maximum packet size are the two numbers the server
  // reads out of our packet and then acts on: it will not send us more than
  // the window, and it will not accept a packet larger than the maximum. If
  // either were misread, the transfer would stall or be dropped -- but the
  // fact that the server *read* them is what the log shows, and the numbers
  // are checked without depending on OpenSSH's wording for them.
  ok("the server read our window and maximum packet size",
     logLines.some((l) => l.includes("direct-tcpip") && l.includes("2097152") && l.includes("32768")),
     "looking for 2097152 and 32768 on the direct-tcpip line");

  // ---------------------------------------- E. a second implementation agrees
  section("E. paramiko does the same transfer and gets the same bytes");
  writeFileSync(path.join(WORK, "payload.bin"), payload, "utf8");
  const oracleOut = path.join(WORK, "oracle.json");
  const or = spawnSync("cmd", ["/c", "python", "host/forward_oracle.py",
    "--port", String(sshdPort), "--dest-host", "127.0.0.1", "--dest-port", String(echoPort),
    "--payload-file", ".loop76/payload.bin", "--out-json", ".loop76/oracle.json"], {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 90000,
  });
  ok("the paramiko oracle runs", or.status === 0, (or.stderr || "").trim().split("\n").slice(-2).join(" | "));
  let oracle = null;
  try { oracle = JSON.parse(readFileSync(oracleOut, "utf8")); } catch (e) { oracle = null; }
  ok("the oracle transferred the same number of bytes", oracle && oracle.received === payload.length,
     oracle ? `received=${oracle.received} want=${payload.length}` : "no oracle json");
  ok("the oracle's bytes have the same digest as ours",
     oracle && oracle.sha256 === payloadSha, oracle ? oracle.sha256 : "");

  // --------------------------------------- F. the target is not there at all
  section("F. a target that is not there is not reported as a success");
  // The intent, not one server's timing.
  //
  // OpenSSH 8.0p1 connects to the target asynchronously: it confirms the
  // channel open first and fails the connect afterwards, so the protocol
  // carries no failure message and the client sees a channel that opens and
  // closes having moved nothing. This client calls that FORWARD_NO_DATA.
  //
  // A server that fails the connect *synchronously* -- which is allowed, and
  // which a different version may do -- answers CHANNEL_OPEN_FAILURE
  // instead, and this client calls that FORWARD_FAILED. Which of the two
  // happens is the server's business, not ours.
  //
  // What is NOT the server's business is whether the client says "success".
  // So the assertion is on that: not a success, and one of the two
  // failure-shaped results, with the note attached when the result is the
  // one that carries it. A gate that pinned the exact classification would
  // be a gate about OpenSSH's scheduling, not about this client.
  const deadPort = await freePort();   // nothing is listening here
  const dead = runClient(sshdPort, ["--forward", `127.0.0.1:${deadPort}`, "--stdin-text", payload]);
  ok("the dead target is not reported as a successful forward", !/result: FORWARD_DONE/.test(dead.text),
     (dead.text.match(/^result: .*$/m) || ["no result line"])[0]);
  const deadResult = (dead.text.match(/^result: (\S+)$/m) || [])[1];
  ok("the outcome is one of the two failure-shaped results",
     deadResult === "FORWARD_NO_DATA" || deadResult === "FORWARD_FAILED", String(deadResult));
  ok("no byte is claimed", numOf(dead.text, "stdout_len") === 0 || numOf(dead.text, "stdout_len") === undefined,
     `stdout_len=${numOf(dead.text, "stdout_len")}`);
  if (deadResult === "FORWARD_NO_DATA") {
    ok("the reason is stated, and it does not pretend to know the cause",
       /note: the usual cause is that the server could not reach the/.test(dead.text));
  } else {
    console.log("  (this server refused the connect synchronously; the reason code it gave is below)");
    console.log(`      ${(dead.text.match(/^error: .*$/m) || ["no error line"])[0]}`);
  }

  // ------------------------------------- G. the server refuses to forward at all
  section("G. a server that refuses to forward says so");
  const noFwdPort = await freePort();
  const noFwd = startSshd(noFwdPort, "loop76nf", ["--no-forward"]);
  const noFwdUp = await waitForText(noFwd, "sshd listening", 30000);
  ok("the refusing sshd is up", noFwdUp, noFwdUp ? "" : (noFwd.tapBuf || "").slice(-200));
  if (noFwdUp) {
    const refused = runClient(noFwdPort, ["--forward", `127.0.0.1:${echoPort}`, "--stdin-text", payload]);
    ok("the refusal is reported as a failure", /result: FORWARD_FAILED/.test(refused.text),
       (refused.text.match(/^result: .*$/m) || ["no result line"])[0]);
    ok("the failure names the protocol's own reason code",
       /error: OpenFailed\(1,/.test(refused.text),
       (refused.text.match(/^error: .*$/m) || ["no error line"])[0]);
  }
  noFwd.kill();
  stopSshd("loop76nf");

  sshd.kill();
  stopSshd("loop76");
  echo.kill();
  return finish();
}

function finish() {
  const verdict = failures === 0 ? "PASS" : "FAIL";
  console.log(`\n${verdict}: ${checks - failures}/${checks} checks` +
    (skipped ? `, ${skipped} skipped` : ""));
  stopSshd("loop76");
  stopSshd("loop76nf");
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("harness error:", e);
  stopSshd("loop76");
  stopSshd("loop76nf");
  process.exit(2);
});
