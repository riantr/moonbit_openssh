#!/usr/bin/env node
// host/verify_loop94.mjs -- our SSH server's CHANNEL layer, judged by the
// real OpenSSH client AND measured against the real OpenSSH server.
//
// Loop #93 measured the handshake.  What was left between a logged-in
// client and a command is RFC 4254, and this gate is about that.
//
// ## Two oracles, because the answer has two halves
//
//   * The real `ssh.exe` is the CLIENT half: it authenticates, it sends the
//     `exec`, it prints the command's output and it exits with the command's
//     status.  Everything it says is about us.
//   * The real `sshd` is the SERVER half: what bytes come back for a given
//     command, and in what order.  We cannot invent that, so it is measured
//     and the measurement is committed (`host/loop94_oracle.json`).
//
// The recording is committed so the gate is deterministic on a machine with
// no sshd; it is RE-MEASURED whenever a real sshd can be started, and a
// disagreement is a failure rather than a surprise.  A stale recording
// cannot survive.
//
// ## Why the comparison is byte for byte
//
// Because the thing being compared has a trailing quote in it.  The real
// server runs `cmd.exe /c "<command>"`, and cmd.exe's `/c` rule leaves the
// LAST quote of the command line in the output: `echo hello` comes back as
// `hello"`.  A "contains hello" check would pass for an implementation that
// dropped the quote, and dropping it means the command line was built
// differently from the real server's.
//
// ## What went wrong the first time, and what caught it
//
// Two defects, both found by running the real client rather than by reading:
//
//   1. The reported output was the right LENGTH and every byte zero,
//      because `Bytes::from_array` COPIES and the read filled the copy.
//   2. The connection was closed immediately after our CHANNEL_CLOSE, so the
//      client's answering CLOSE was still in flight, the close became a TCP
//      RESET, and the reset threw away the exit status we had just sent --
//      the client said `Connection reset` and exited 255 even though the
//      command had run and its output had been sent.
//
// Run: node host/verify_loop94.mjs

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(
  new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
);

// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists. None is asserted to exist, and when none does the gate says so
// and fails rather than pretending. verify_loop71.mjs flags any drive-letter
// path it finds in code; this marker is how a file declares that its paths are
// a probe rather than a claim, and it is an obligation to say why, not a mute
// button. The reason it is a list at all: this repository is developed where
// the server lives under `C:\Program Files\OpenSSH-Win64` and it is tested on
// a runner where it lives under `C:\Windows\System32\OpenSSH`, and hardcoding
// either one made every gate that needs a server fail on the other machine.
const OPENSSH_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
];
const REAL_CLIENT =
  OPENSSH_DIRS.map((d) => path.join(d, "ssh.exe")).find((p) => fs.existsSync(p)) || null;
const REAL_KEYGEN =
  OPENSSH_DIRS.map((d) => path.join(d, "ssh-keygen.exe")).find((p) => fs.existsSync(p)) || null;

// `moon build` puts the executable under _build/<target>/<mode>/build/<pkg>/.
const OUR_SSHD_CANDIDATES = [
  path.join(ROOT, "_build", "native", "debug", "build", "cmd", "sshd", "sshd.exe"),
  path.join(ROOT, "_build", "native", "release", "build", "cmd", "sshd", "sshd.exe"),
];
const OUR_SSHD = OUR_SSHD_CANDIDATES.find((p) => fs.existsSync(p)) || OUR_SSHD_CANDIDATES[0];

const BED = path.join(ROOT, ".loop94", "gate94");
const ORACLE = path.join(ROOT, "host", "loop94_oracle.json");

let passed = 0;
let failed = 0;
const failures = [];

function ok(name, cond, detail = "") {
  if (cond) {
    passed++;
    console.log(`  ok    ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  FAIL  ${name}${detail ? `  -- ${detail}` : ""}`);
  }
}

// The `binary` case runs a PowerShell script that writes bytes which are not
// text.  The bytes are the point: a text round trip would turn 0xFF into
// U+FFFD, and the comparison would then be about a decoder.
//
// This is the SAME script `host/loop94_oracle.py` used when it recorded the
// real server's answer, and the two must stay identical or the comparison is
// between two different commands.
const EMIT_PS1 = [
  "$ErrorActionPreference = 'Stop'",
  "$bytes = [byte[]](0, 1, 2, 255, 254, 10, 13, 0)",
  "[Console]::OpenStandardOutput().Write($bytes, 0, $bytes.Length)",
  "[Console]::Out.Flush()",
  "exit 7",
  "",
].join("\r\n");

// ------------------------------------------------------------------- the bed

function freshBed() {
  fs.rmSync(BED, { recursive: true, force: true });
  fs.mkdirSync(BED, { recursive: true });
  for (const [name, file] of [["host", "hostkey"], ["user", "userkey"]]) {
    const r = spawnSync(
      REAL_KEYGEN,
      ["-t", "ed25519", "-f", path.join(BED, file), "-N", "", "-C", `loop94 ${name} key`],
      { encoding: "utf8", timeout: 60000 },
    );
    if (r.status !== 0) throw new Error(`ssh-keygen failed for ${file}: ${r.stderr}`);
  }
  fs.copyFileSync(path.join(BED, "userkey.pub"), path.join(BED, "authorized_keys"));
  fs.writeFileSync(path.join(BED, "emit.ps1"), EMIT_PS1, "utf8");
  // The host key goes into known_hosts BEFORE any connection: the client's
  // "Permanently added" warning is written to ITS stderr, which is the same
  // stream the command's stderr arrives on, and comparing that stream means
  // comparing what the COMMAND wrote.
  const pub = fs.readFileSync(path.join(BED, "hostkey.pub"), "utf8").trim().split(/\s+/);
  fs.writeFileSync(`${BED}/known_hosts`, `127.0.0.1 ${pub[0]} ${pub[1]}\n`, "utf8");
}

// ----------------------------------------------------------------- the server

function startServer() {
  return new Promise((resolve, reject) => {
    const p = spawn(
      OUR_SSHD,
      [
        "--host-key", path.join(BED, "hostkey"),
        "--authorized-keys", path.join(BED, "authorized_keys"),
        "--port", "0",
        "--accept-timeout-ms", "60000",
      ],
      { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
    );
    let out = "";
    p.stdout.on("data", (d) => { out += d.toString(); });
    p.stderr.on("data", (d) => { out += d.toString(); });
    // The report goes to STDOUT, and stdout is BLOCK-buffered when it is a
    // pipe -- the same trap `cmd/sshd`'s own header warns about for the port
    // line, which is why the port goes to stderr.
    //
    // `close` and not `exit`: `exit` fires when the PROCESS is gone, which
    // can be before the last of its stdout has been read out of the pipe.
    // Waiting for `close` waits for the stdio streams to end as well, and
    // then `out` is complete.  Getting this wrong is invisible -- the report
    // is simply truncated, and a check that reads it says "the server never
    // said that" about a server that did.
    const exited = new Promise((done) => p.on("close", () => done()));
    // A server that never gets a connection would hold the gate forever.
    const killTimer = setTimeout(() => {
      try { p.kill(); } catch { /* already gone */ }
    }, 45000);
    exited.then(() => clearTimeout(killTimer));
    const deadline = Date.now() + 30000;
    const tick = () => {
      const m = /listen_port:\s*(\d+)/i.exec(out);
      if (m) {
        return resolve({
          proc: p,
          port: Number(m[1]),
          out: () => out,
          exited: () => exited,
        });
      }
      if (Date.now() > deadline) return reject(new Error(`our sshd did not start:\n${out}`));
      setTimeout(tick, 100);
    };
    tick();
  });
}

// The client, run ASYNCHRONOUSLY.
//
// `spawnSync` blocks the event loop, and this gate has a `spawn`ed server
// whose stdout is read with events.  While `spawnSync` runs, those events
// cannot be delivered -- so the server's report is still empty when the gate
// looks at it, no matter how long it waits afterwards.  The symptom is a
// gate that says "the server never reported the command" about a server
// whose report was correct all along.
function runClient(port, command) {
  return new Promise((resolve, reject) => {
    const p = spawn(
      REAL_CLIENT,
      [
        "-p", String(port),
        "-i", path.join(BED, "userkey"),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", `UserKnownHostsFile=${path.join(BED, "known_hosts")}`,
        "hp@127.0.0.1",
        command,
      ],
      { timeout: 60000 },
    );
    const outChunks = [];
    const errChunks = [];
    p.stdout.on("data", (d) => outChunks.push(d));
    p.stderr.on("data", (d) => errChunks.push(d));
    const timer = setTimeout(() => {
      try { p.kill(); } catch { /* already gone */ }
    }, 60000);
    p.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    p.on("close", (code) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(outChunks);
      const stderr = Buffer.concat(errChunks);
      resolve({
        code,
        stdout: stdout.toString("latin1"),
        stderr: stderr.toString("latin1"),
        stdoutHex: stdout.toString("hex"),
        stderrHex: stderr.toString("hex"),
      });
    });
  });
}

function spawnSyncMoon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", timeout: 900000,
  });
  return { code: r.status, out: `${r.stdout || ""}${r.stderr || ""}` };
}

// ------------------------------------------------------------------- the gate

function checkMessageNumbers() {
  console.log("");
  console.log("A. the connection protocol's message numbers");
  // The table in `src/sshwire` was wrong until this loop: EOF and CLOSE were
  // one byte low, and CHANNEL_EXTENDED_DATA did not exist at all.  Nothing
  // caught it, because every test that used those constants also BUILT
  // packets with them -- a mock and the code that checks the mock agree by
  // construction.  So the numbers are pinned here, as literal bytes, against
  // what RFC 4254 §5.1 and the real server both say.
  const src = fs.readFileSync(path.join(ROOT, "src", "sshwire", "msg.mbt"), "utf8");
  const value = (name) => {
    const m = new RegExp(
      `pub const ${name}\\s*:\\s*Byte\\s*=\\s*b'\\\\x([0-9a-fA-F]{2})'`,
    ).exec(src);
    return m ? parseInt(m[1], 16) : null;
  };
  const expected = {
    SSH_MSG_GLOBAL_REQUEST: 80,
    SSH_MSG_REQUEST_SUCCESS: 81,
    SSH_MSG_REQUEST_FAILURE: 82,
    SSH_MSG_CHANNEL_OPEN: 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION: 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE: 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST: 93,
    SSH_MSG_CHANNEL_DATA: 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA: 95,
    SSH_MSG_CHANNEL_EOF: 96,
    SSH_MSG_CHANNEL_CLOSE: 97,
    SSH_MSG_CHANNEL_REQUEST: 98,
    SSH_MSG_CHANNEL_SUCCESS: 99,
    SSH_MSG_CHANNEL_FAILURE: 100,
  };
  for (const [name, want] of Object.entries(expected)) {
    ok(`${name} is ${want}`, value(name) === want, `got ${value(name)}`);
  }
}

function checkOrderAgainstTheServerLog(recording) {
  console.log("");
  console.log("B. the message order the real server logged");
  // The real server's own DEBUG3 log, reduced to the distinct types it SENT
  // in first-seen order.  The tail is the channel sequence, and it is the
  // order this server has to reproduce:
  //
  //   91 CHANNEL_OPEN_CONFIRMATION
  //   99 CHANNEL_SUCCESS            (the answer to "exec")
  //   96 CHANNEL_EOF
  //   98 CHANNEL_REQUEST exit-status
  //   97 CHANNEL_CLOSE
  //
  // The EOF BEFORE the exit status is the part that is easy to get wrong, so
  // it is asserted as a subsequence rather than as a set.
  const types = recording.sshd_log_sent_types || [];
  const want = [91, 99, 96, 98, 97];
  let at = 0;
  for (const t of types) {
    if (at < want.length && t === want[at]) at++;
  }
  ok(
    "the real server's log shows 91, 99, 96, 98, 97 in that order",
    at === want.length,
    `its sent types were ${types.join(", ")}`,
  );
  // And the numbers themselves are the ones in the table above, which is why
  // this recording is also evidence ABOUT the table.
  ok(
    "the real server sent 96 for EOF (not 95)",
    types.includes(96) && !types.includes(95),
    types.join(", "),
  );
  ok(
    "the real server sent 97 for CLOSE (not 96)",
    types.includes(97),
    types.join(", "),
  );
}

async function main() {
  console.log("=== Loop #94: the SSH server's channel layer ===");

  checkMessageNumbers();

  if (!fs.existsSync(ORACLE)) {
    ok("the committed oracle exists", false, ORACLE);
    return summary();
  }
  const recording = JSON.parse(fs.readFileSync(ORACLE, "utf8"));
  ok(
    "the committed oracle has the fixed command list",
    Array.isArray(recording.commands) && recording.commands.length === 6,
    `${(recording.commands || []).length} commands`,
  );
  checkOrderAgainstTheServerLog(recording);

  // ---- C. re-measure, when a real sshd is here ----
  console.log("");
  console.log("C. the committed recording, re-measured");
  const remeasure = spawnSync("python", [path.join(ROOT, "host", "loop94_oracle.py"), "--check"], {
    cwd: ROOT, encoding: "utf8", timeout: 600000,
  });
  if (remeasure.status === 3) {
    console.log(`  skip  ${(remeasure.stdout || "").trim()}`);
  } else {
    ok(
      "the committed recording matches the live measurement",
      remeasure.status === 0,
      (remeasure.stdout || "") + (remeasure.stderr || ""),
    );
  }

  if (!REAL_CLIENT || !REAL_KEYGEN) {
    ok("a real ssh.exe and ssh-keygen.exe are available", false,
       `looked in: ${OPENSSH_DIRS.join(", ")}`);
    return summary();
  }
  console.log(`real client: ${REAL_CLIENT}`);
  console.log(`our server:  ${OUR_SSHD}`);

  // ---- D. it builds, and the unit tests pass ----
  console.log("");
  console.log("D. this loop's own code");
  const build = spawnSyncMoon(["build", "--target", "native", "cmd/sshd"]);
  if (build.code !== 0) {
    ok("cmd/sshd builds", false, build.out.slice(-3000));
    return summary();
  }
  ok("cmd/sshd builds", fs.existsSync(OUR_SSHD));
  const unit = spawnSyncMoon(["test", "--target", "native", "src/sshd"]);
  ok("the src/sshd unit tests pass", unit.code === 0,
     unit.code === 0 ? "" : unit.out.slice(-3000));

  // ---- E. the same commands, byte for byte ----
  console.log("");
  console.log("E. our server against the recorded bytes");
  freshBed();
  for (const c of recording.commands) {
    const server = await startServer();
    let got;
    try {
      // The recording names `EMIT_PS1` as a placeholder so the recorded JSON
      // does not carry a path from the machine that made it.  Here it is
      // resolved to THIS bed's script, which is the same script.
      got = await runClient(server.port, c.command.replace("EMIT_PS1", path.join(BED, "emit.ps1")));
    } finally {
      await server.exited();
    }
    ok(`[${c.id}] the exit status is ${c.code}`, got.code === c.code, `got ${got.code}`);
    ok(
      `[${c.id}] stdout is the real server's bytes`,
      got.stdoutHex === c.stdoutHex,
      `ours ${got.stdoutHex} / real ${c.stdoutHex}`,
    );
    ok(
      `[${c.id}] stderr is the real server's bytes`,
      got.stderrHex === c.stderrHex,
      `ours ${got.stderrHex} / real ${c.stderrHex}`,
    );
  }

  // ---- F. the two defects, named ----
  console.log("");
  console.log("F. the two defects this loop found, as checks");
  //
  // (1) The output that was the right length and all zeros.
  //
  // `Bytes::from_array` copies, so a read that fills `Bytes::from_array(buf)`
  // fills the copy and leaves the caller's array untouched.  The symptom is
  // not a short read -- the length is right -- so this asserts that a
  // command that is KNOWN to say something says THAT something.
  {
    const server = await startServer();
    let got;
    try {
      got = await runClient(server.port, "cmd /c echo loop94-stdout");
    } finally {
      await server.exited();
    }
    ok(
      "a command's stdout is not a run of zero bytes",
      got.stdout.length > 0 && got.stdoutHex !== "0".repeat(got.stdoutHex.length),
      got.stdoutHex,
    );
    ok(
      "the trailing quote cmd.exe leaves behind is IN the output",
      got.stdoutHex === Buffer.from('loop94-stdout"\r\n', "latin1").toString("hex"),
      got.stdoutHex,
    );
  }
  //
  // (2) The reset that threw away the exit status.
  //
  // Closing the socket right after our CHANNEL_CLOSE makes the close a RESET
  // while the client's answering CLOSE is in flight, and the reset discards
  // what the peer has not read yet.  The client's words for that are
  // `Connection reset` and exit 255, and the check is that neither happens.
  {
    const server = await startServer();
    let client;
    try {
      client = await runClient(server.port, "cmd /c echo loop94-after-close");
    } finally {
      // The report is read AFTER the server has exited, not before: stdout
      // is block-buffered when it is a pipe, so a read taken while the
      // server is still alive sees the stderr lines and nothing else.  This
      // gate made exactly that mistake one screen above its own comment
      // about it, and the check went red intermittently -- which is the
      // worst way for a gate to be wrong.
      await server.exited();
    }
    const serverOut = server.out();
    ok(
      "the client does not report a connection reset",
      !client.stderr.includes("Connection reset"),
      client.stderr.slice(-1200),
    );
    ok(
      "the client exits with the command's status, not the transport's",
      client.code === 0,
      `exit ${client.code}`,
    );
    // `peer_closed: 1` is the observable side of the drain: only a server
    // that READ the peer's CHANNEL_CLOSE before closing its socket reports
    // 1.  Without the drain the server closes first, the peer's answer is
    // still in flight, and the close becomes a TCP RESET that discards
    // whatever the peer had not read -- so this line is the one that turns
    // to 0 when the drain is removed, whether or not the RESET is visible
    // in the client's own output on a fast loopback connection.
    ok(
      "our server read the peer's CLOSE before it closed the connection",
      serverOut.includes("peer_closed: 1"),
      serverOut.slice(-1200),
    );
  }

  // ---- G. the client's own words about the channel ----
  console.log("");
  console.log("G. what the real client says about the channel");
  {
    const server = await startServer();
    let client;
    try {
      client = await runClient(server.port, "cmd /c exit 7");
    } finally {
      // Read after the exit, for the same reason as the block above.
      await server.exited();
    }
    const serverOut = server.out();
    ok(
      "the client authenticated",
      !client.stderr.includes("Permission denied"),
      client.stderr.slice(-1200),
    );
    ok(
      "the client was not refused a channel",
      !client.stderr.includes("open failed"),
      client.stderr.slice(-1200),
    );
    ok(
      "the client did not complain about the channel number",
      !client.stderr.includes("nonexistent channel"),
      client.stderr.slice(-1200),
    );
    ok(
      "our server reports the command it ran",
      serverOut.includes("command: cmd /c exit 7"),
      serverOut.slice(-1200),
    );
    ok(
      "our server reports the exit status the client received",
      serverOut.includes("exit_status: 7") && client.code === 7,
      `server ${serverOut.includes("exit_status: 7")}, client exit ${client.code}`,
    );
  }

  return summary();
}

function summary() {
  console.log("");
  console.log(`loop94: ${passed}/${passed + failed} checks passed`);
  if (failed) {
    console.log("  failed:");
    for (const f of failures) console.log(`    ${f}`);
  }
  return failed ? 1 : 0;
}

main().then((code) => process.exit(code || 0)).catch((e) => {
  console.error(e);
  process.exit(1);
});
