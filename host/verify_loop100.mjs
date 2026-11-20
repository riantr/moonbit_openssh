#!/usr/bin/env node
// host/verify_loop100.mjs -- our SSH server's SFTP SUBSYSTEM, judged by the
// real OpenSSH client AND measured against the real OpenSSH server.
//
// Loop #94 measured the channel layer's `exec`.  What is left of the real
// server's session surface is the `sftp` subsystem: the peer asks for a
// named subsystem, and the server answers a stream of SFTP packets inside
// the channel.
//
// ## Two oracles, because the answer has two halves
//
//   * The real `sftp.exe` is the CLIENT half: it asks for the subsystem, it
//     sends the requests, it prints the answers and it exits with a status.
//     Everything it says is about us.
//   * The real `sshd` is the SERVER half: what bytes come back for a given
//     batch, and in what order.  We cannot invent that, so it is measured
//     and the measurement is committed (`host/loop100_oracle.json`).
//
// The recording is committed so the gate is deterministic on a machine with
// no sshd; it is RE-MEASURED whenever a real sshd can be started, and a
// disagreement is a failure rather than a surprise.  A stale recording
// cannot survive.
//
// ## What is compared, byte for byte
//
// The exit status, the client's stdout and the client's stderr, for each of
// the recorded batches.  Two things are taken out of the comparison, and
// both of them are facts about the MACHINE rather than about the server:
//
//   * the bed's absolute path, which appears in the client's own echo of
//     every command -- replaced with the token `BED` at RECORD time;
//   * the timestamp in the `ls -l` line, which is the time of the run --
//     normalised on both sides at COMPARISON time.
//
// Everything else -- the file names, the sizes, the permission words, the
// error sentences, the exit status -- is compared as bytes.
//
// ## What went wrong the first time, and what caught it
//
// One defect, and the real client caught it:
//
//   1. The server answered REALPATH with `/E:/src/...` -- a slash in front
//      of the drive letter, which is what the REAL server answers -- and
//      then could not open the path it had just produced.  The client's
//      `ls` asks for the directory by exactly the name the server handed
//      out, so every listing came back "No such file or directory".
//
// Run: node host/verify_loop100.mjs

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ROOT = path.resolve(
  new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
);

// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists. None is asserted to exist, and when none does the gate says so
// and fails rather than pretending.  verify_loop71.mjs flags any drive-letter
// path it finds in code; this marker is how a file declares that its paths
// are a probe rather than a claim.
const OPENSSH_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
];
const REAL_SFTP =
  OPENSSH_DIRS.map((d) => path.join(d, "sftp.exe")).find((p) => fs.existsSync(p)) || null;
const REAL_KEYGEN =
  OPENSSH_DIRS.map((d) => path.join(d, "ssh-keygen.exe")).find((p) => fs.existsSync(p)) || null;

const OUR_SSHD_CANDIDATES = [
  path.join(ROOT, "_build", "native", "debug", "build", "cmd", "sshd", "sshd.exe"),
  path.join(ROOT, "_build", "native", "release", "build", "cmd", "sshd", "sshd.exe"),
];
const OUR_SSHD = OUR_SSHD_CANDIDATES.find((p) => fs.existsSync(p)) || OUR_SSHD_CANDIDATES[0];

const BED = path.join(ROOT, ".loop100", "bed");
const WORK = path.join(BED, "work");
const LOCAL = path.join(BED, "local");
const ORACLE = path.join(ROOT, "host", "loop100_oracle.json");
const BED_TOKEN = "BED";

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

// The `ls -l` line carries the file's mtime, in the spelling the client's
// own formatter produces.  It is NOT the C library's strftime: every field
// is padded to WIDTH TWO WITH A SPACE, so the minute of 11:07 is " 7" and
// not "07", and the hour of 09:30 is " 9" and not "09".  Measured, in
// bytes: "Nov 20 11: 7 hello.txt".
//
// The clock is not a property of the server, and a gate that only matches
// two-digit minutes is a gate that goes red for a quarter of every hour.
const TIME_RE = /[A-Z][a-z]{2} [ 0-9]\d (?:[ 0-9]\d:[ 0-9]\d|  [0-9]{4})/g;

function normalizeTime(text) {
  return text.replace(TIME_RE, "<TIME>");
}

function tokenize(text) {
  return text.split(BED.replace(/\\/g, "/")).join(BED_TOKEN);
}

// ------------------------------------------------------------------- the bed

function resetBed() {
  fs.rmSync(WORK, { recursive: true, force: true });
  fs.rmSync(LOCAL, { recursive: true, force: true });
  fs.mkdirSync(WORK, { recursive: true });
  fs.mkdirSync(LOCAL, { recursive: true });
  fs.writeFileSync(path.join(WORK, "hello.txt"), "hello loop100\n", "utf8");
  const blob = Buffer.from([0, 1, 2, 255, 254, 10, 13, 0]);
  fs.writeFileSync(path.join(WORK, "bytes.bin"), blob);
  fs.writeFileSync(path.join(LOCAL, "bytes.bin"), blob);
  // A file bigger than one SSH packet: the client's READ request asks for
  // 64 KiB, so the server's answer is bigger than the 32768-byte maximum
  // packet and has to be cut, and the client's WRITE request is bigger
  // than one packet too, so the server has to REASSEMBLE.
  const big = Buffer.alloc(100000);
  for (let i = 0; i < big.length; i++) big[i] = (i * 7 + 3) % 256;
  fs.writeFileSync(path.join(WORK, "big.bin"), big);
  fs.writeFileSync(path.join(LOCAL, "big.bin"), big);
}

function makeBed() {
  fs.rmSync(BED, { recursive: true, force: true });
  fs.mkdirSync(BED, { recursive: true });
  for (const [name, file] of [["host", "hostkey"], ["user", "userkey"]]) {
    const r = spawnSync(
      REAL_KEYGEN,
      ["-t", "ed25519", "-f", path.join(BED, file), "-N", "", "-C", `loop100 ${name} key`],
      { encoding: "utf8", timeout: 60000 },
    );
    if (r.status !== 0) throw new Error(`ssh-keygen failed for ${file}: ${r.stderr}`);
  }
  fs.copyFileSync(path.join(BED, "userkey.pub"), path.join(BED, "authorized_keys"));
  // The host key goes into known_hosts BEFORE any connection: the client's
  // "Permanently added" warning goes to ITS stderr, which is the same
  // stream the session's stderr arrives on.
  const pub = fs.readFileSync(path.join(BED, "hostkey.pub"), "utf8").trim().split(/\s+/);
  fs.writeFileSync(
    path.join(BED, "known_hosts"),
    `127.0.0.1 ${pub[0]} ${pub[1]}\n`,
    "utf8",
  );
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
    // `close` and not `exit`: `exit` fires when the PROCESS is gone, which
    // can be before the last of its stdout has been read out of the pipe.
    const exited = new Promise((done) => p.on("close", () => done()));
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

// The account THIS machine runs as.
//
// The same rule as `host/ssh_user.py`: a tool that connects to a real
// OpenSSH server has to name an account that EXISTS on the machine running
// that server.  Loop #76 measured what a hardcoded name costs -- the gate
// authenticated as `hp`, one developer's account, and on GitHub Actions,
// where the account is `runneradmin`, every section that needed a live
// server failed with `AuthRejected`.  The failure was about the account
// name, and nothing in the output said so.
function sshUser() {
  for (const key of ["USERNAME", "USER", "LOGNAME", "LNAME"]) {
    const value = process.env[key];
    if (value && value.trim()) return value.trim();
  }
  return "";
}

// The client, run ASYNCHRONOUSLY.
//
// `spawnSync` blocks the event loop, and this gate has a `spawn`ed server
// whose stdout is read with events.  While `spawnSync` runs, those events
// cannot be delivered -- so the server's report is still empty when the gate
// looks at it, no matter how long it waits afterwards.
function runSftp(port, batchFile, extra = []) {
  return new Promise((resolve, reject) => {
    const p = spawn(
      REAL_SFTP,
      [
        ...extra,
        "-b", batchFile,
        "-P", String(port),
        "-i", path.join(BED, "userkey"),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", `UserKnownHostsFile=${path.join(BED, "known_hosts")}`,
        `${sshUser()}@127.0.0.1`,
      ],
      { timeout: 90000 },
    );
    const outChunks = [];
    const errChunks = [];
    p.stdout.on("data", (d) => outChunks.push(d));
    p.stderr.on("data", (d) => errChunks.push(d));
    const timer = setTimeout(() => {
      try { p.kill(); } catch { /* already gone */ }
    }, 90000);
    p.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    p.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(outChunks).toString("latin1"),
        stderr: Buffer.concat(errChunks).toString("latin1"),
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

function checkTheOracleShape(recording) {
  console.log("");
  console.log("A. the committed recording");
  ok(
    "the committed oracle exists",
    fs.existsSync(ORACLE),
    ORACLE,
  );
  ok(
    "the committed oracle has the fixed case list",
    Array.isArray(recording.cases) && recording.cases.length === 6,
    `${(recording.cases || []).length} cases`,
  );
  ok(
    "every case names a batch",
    (recording.cases || []).every((c) => Array.isArray(c.batch) && c.batch.length > 0),
  );
  ok(
    "the bed's path is the token, not a machine's path",
    (recording.cases || []).every((c) =>
      c.batch.join("\n").includes(BED_TOKEN) &&
      !/[A-Za-z]:\\/.test(c.batch.join("\n")),
    ),
  );
}

async function main() {
  console.log("=== Loop #100: the SSH server's SFTP subsystem ===");

  if (!fs.existsSync(ORACLE)) {
    ok("the committed oracle exists", false, ORACLE);
    return summary();
  }
  const recording = JSON.parse(fs.readFileSync(ORACLE, "utf8"));
  checkTheOracleShape(recording);

  // ---- B. the committed recording, re-measured ----
  console.log("");
  console.log("B. the committed recording, re-measured");
  const remeasure = spawnSync("python", [path.join(ROOT, "host", "loop100_oracle.py"), "--check"], {
    cwd: ROOT, encoding: "utf8", timeout: 900000,
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

  if (!REAL_SFTP || !REAL_KEYGEN) {
    ok("a real sftp.exe and ssh-keygen.exe are available", false,
       `looked in: ${OPENSSH_DIRS.join(", ")}`);
    return summary();
  }
  // The account has to be NAMED, and it has to exist on the machine that
  // runs the server.  Loop #76 measured what a hardcoded name costs.
  const user = sshUser();
  ok(
    "the account this machine runs as could be named",
    user !== "",
    "no USERNAME, USER, LOGNAME or LNAME in the environment",
  );
  if (user === "") {
    return summary();
  }
  console.log(`real client: ${REAL_SFTP}`);
  console.log(`our server:  ${OUR_SSHD}`);
  console.log(`account:     ${user}`);

  // ---- C. it builds, and the unit tests pass ----
  console.log("");
  console.log("C. this loop's own code");
  const build = spawnSyncMoon(["build", "--target", "native", "cmd/sshd"]);
  if (build.code !== 0) {
    ok("cmd/sshd builds", false, build.out.slice(-3000));
    return summary();
  }
  ok("cmd/sshd builds", fs.existsSync(OUR_SSHD));
  const unit = spawnSyncMoon(["test", "--target", "native", "src/sshd"]);
  ok("the src/sshd unit tests pass", unit.code === 0,
     unit.code === 0 ? "" : unit.out.slice(-3000));

  // ---- D. the same batches, byte for byte ----
  console.log("");
  console.log("D. our server against the recorded bytes");
  makeBed();
  for (const c of recording.cases) {
    resetBed();
    const batchText = c.batch.join("\n").split(BED_TOKEN).join(BED.replace(/\\/g, "/")) + "\n";
    const batchFile = path.join(BED, `batch_${c.id}.txt`);
    fs.writeFileSync(batchFile, batchText, "utf8");
    const server = await startServer();
    let got;
    try {
      got = await runSftp(server.port, batchFile);
    } finally {
      await server.exited();
    }
    const wantOut = normalizeTime(Buffer.from(c.stdoutHex, "hex").toString("latin1"));
    const wantErr = normalizeTime(Buffer.from(c.stderrHex, "hex").toString("latin1"));
    const ourOut = normalizeTime(tokenize(got.stdout));
    const ourErr = normalizeTime(tokenize(got.stderr));
    ok(`[${c.id}] the exit status is ${c.code}`, got.code === c.code, `got ${got.code}`);
    ok(
      `[${c.id}] stdout is the real server's bytes`,
      ourOut === wantOut,
      `ours ${JSON.stringify(ourOut)} / real ${JSON.stringify(wantOut)}`,
    );
    ok(
      `[${c.id}] stderr is the real server's bytes`,
      ourErr === wantErr,
      `ours ${JSON.stringify(ourErr)} / real ${JSON.stringify(wantErr)}`,
    );
  }

  // ---- E. the defects this loop found, as checks ----
  console.log("");
  console.log("E. the defect this loop found, as a check");
  //
  // The server answers REALPATH with `/E:/src/...` -- a slash in front of
  // the drive letter, which is what the REAL server answers -- and the
  // client then asks for that very path.  A server that cannot open the
  // path it just handed out says "No such file or directory" for every
  // listing, and the symptom is a client that works for `pwd` and fails
  // for `ls`.
  {
    resetBed();
    const batchFile = path.join(BED, "batch_e.txt");
    fs.writeFileSync(
      batchFile,
      `lcd ${LOCAL.replace(/\\/g, "/")}\ncd ${WORK.replace(/\\/g, "/")}\npwd\nls\n`,
      "utf8",
    );
    const server = await startServer();
    let got;
    try {
      got = await runSftp(server.port, batchFile);
    } finally {
      await server.exited();
    }
    ok(
      "the path the server hands out is one it can take back",
      got.stderr === "" && got.stdout.includes("bytes.bin"),
      `stderr ${JSON.stringify(got.stderr)} stdout ${JSON.stringify(got.stdout)}`,
    );
  }

  // ---- F. a subsystem this server does not have ----
  console.log("");
  console.log("F. a subsystem this server does not have");
  //
  // `sftp -s <name>` asks for a NAMED subsystem.  The real server refuses
  // a name it does not have, and so must ours: a server that answers
  // SUCCESS to a subsystem it cannot run leaves the peer waiting for
  // bytes that never come.
  {
    resetBed();
    const batchFile = path.join(BED, "batch_f.txt");
    fs.writeFileSync(batchFile, "ls\n", "utf8");
    const server = await startServer();
    let got;
    try {
      got = await runSftp(server.port, batchFile, ["-s", "loop100-no-such-subsystem"]);
    } finally {
      await server.exited();
    }
    ok(
      "an unknown subsystem is refused, and the client says so",
      got.code !== 0 && /subsystem/i.test(got.stderr),
      `exit ${got.code} stderr ${JSON.stringify(got.stderr)}`,
    );
  }

  // ---- G. the server's own report ----
  console.log("");
  console.log("G. what our server says about the session");
  {
    resetBed();
    const batchFile = path.join(BED, "batch_g.txt");
    fs.writeFileSync(
      batchFile,
      `lcd ${LOCAL.replace(/\\/g, "/")}\ncd ${WORK.replace(/\\/g, "/")}\nls\n`,
      "utf8",
    );
    const server = await startServer();
    try {
      await runSftp(server.port, batchFile);
    } finally {
      await server.exited();
    }
    const serverOut = server.out();
    ok("our server reports the subsystem it ran", serverOut.includes("command: subsystem sftp"),
       serverOut.slice(-1200));
    ok("our server reports the requests it answered", /sftp_requests: [1-9]/.test(serverOut),
       serverOut.slice(-1200));
    ok("our server reports the bytes it sent", /sftp_bytes: [1-9]/.test(serverOut),
       serverOut.slice(-1200));
    ok("our server read the peer's CLOSE before it closed the connection",
       serverOut.includes("peer_closed: 1"), serverOut.slice(-1200));
  }

  return summary();
}

function summary() {
  console.log("");
  console.log(`${passed}/${passed + failed} checks passed`);
  if (failed) {
    console.log("FAILED:");
    for (const f of failures) console.log(`  - ${f}`);
    process.exitCode = 1;
  }
  return failed;
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
