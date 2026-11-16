// host/loop94_probe.mjs -- measure a real SSH server's CHANNEL layer.
//
// Loop #93 measured the handshake and the authentication.  What is left of
// RFC 4254 is the connection layer: the session channel, the `exec` request,
// stdout/stderr as data, and the exit status.
//
// The rule of this repository is that the protocol is measured, not recalled.
// So this file does not implement anything: it RUNS a server, RUNS a fixed
// list of commands through the real `ssh.exe`, and writes down exactly what
// came back -- stdout bytes, stderr bytes, exit code -- so that the same list
// can be run against our own server and compared byte for byte.
//
//   node host/loop94_probe.mjs --server real   # the system OpenSSH sshd
//   node host/loop94_probe.mjs --server ours   # our cmd/sshd
//
// The result is written to .loop94/probe-<server>.json.
//
// ## Why the command list is fixed
//
// A probe that invents its own commands is a probe whose result cannot be
// compared with anything.  The list below is the same in both directions, and
// each entry covers one thing the channel layer has to get right:
//
//   * `stdout`   -- stdout, exit 0
//   * `stderr`   -- the OTHER channel: stderr must not land on stdout
//   * `both`     -- both at once, so the two streams cannot be swapped
//   * `exit3`    -- the exit status, which is a channel REQUEST and not a byte
//                   of stdout
//   * `binary`   -- bytes that are not text, so an accidental text round trip
//                   cannot pass
//   * `silent`   -- a command that says nothing, so the EOF/close sequence can
//                   be observed on its own
//
// ## Why the two beds do not share a key
//
// The shared helper pins the real server's accepted user-key algorithms to
// ECDSA (`PubkeyAcceptedKeyTypes ecdsa-sha2-nistp256,ecdsa-sha2-nistp384`),
// so the real server's bed holds an nistp256 key.  Our server speaks
// `ssh-ed25519` for the USER key as well, and Loop #93 proved it, so our bed
// holds an ed25519 key.  The comparison is about the bytes a command
// produces, never about the key.
//
// ## Why the output is hex, not text
//
// The bytes are compared, and `JSON.stringify` of a string mangles the ones
// that are not printable.  So each stream is stored as hex and only shown as
// text where a human has to read it.

import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import net from "node:net";

const ROOT = path.resolve(
  new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
);

function flag(name, fallback = "") {
  const i = process.argv.indexOf(name);
  if (i >= 0 && i + 1 < process.argv.length) return process.argv[i + 1];
  return fallback;
}

const SERVER = flag("--server", "real");
const OUT_DIR = path.join(ROOT, ".loop94");
const BED = path.join(OUT_DIR, `bed-${SERVER}`);
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists. None is asserted to exist, and when none does this probe says so
// and exits rather than pretending. verify_loop71.mjs flags any drive-letter
// path it finds in code; this marker is how a file declares that its paths are
// a probe rather than a claim, and it is an obligation to say why, not a mute
// button. It is a list because the development machine and the CI runner keep
// their OpenSSH builds in different places, and naming either one would make
// this probe a fact about one machine.
const OPENSSH_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
];
const REAL_CLIENT = OPENSSH_DIRS.map((d) => path.join(d, "ssh.exe")).find((p) => fs.existsSync(p));
const REAL_KEYGEN = OPENSSH_DIRS.map((d) => path.join(d, "ssh-keygen.exe")).find((p) => fs.existsSync(p));
// The build output path, and it moved: `moon build` puts the executable
// under `_build/<target>/<mode>/build/<package>/`, and `moon build
// --release` uses `release` instead of `debug`.  Both are probed, so the
// probe works whether or not somebody built in release mode.
const OUR_SSHD_CANDIDATES = [
  path.join(ROOT, "_build", "native", "debug", "build", "cmd", "sshd", "sshd.exe"),
  path.join(ROOT, "_build", "native", "release", "build", "cmd", "sshd", "sshd.exe"),
  path.join(ROOT, "_build", "native", "cmd", "sshd", "sshd.exe"),
];
const OUR_SSHD = OUR_SSHD_CANDIDATES.find((p) => fs.existsSync(p)) || OUR_SSHD_CANDIDATES[0];

// The commands.  `cmd /c` is explicit so that the SAME string means the same
// thing on both servers: the real sshd runs the command through the login
// shell, and our server has to run it through the same shell or the outputs
// differ for a reason that has nothing to do with the channel layer.
//
// `ssh.exe` joins everything after the host into ONE command string, which is
// what the server receives.
const COMMANDS = [
  { id: "stdout", argv: ["cmd", "/c", "echo loop94-stdout"] },
  { id: "stderr", argv: ["cmd", "/c", "echo loop94-stderr 1>&2"] },
  { id: "both", argv: ["cmd", "/c", "echo out-part & echo err-part 1>&2"] },
  { id: "exit3", argv: ["cmd", "/c", "exit 3"] },
  { id: "binary", argv: ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "EMIT_PS1"] },
  { id: "silent", argv: ["cmd", "/c", "rem nothing to say"] },
];

const EMIT_PS1 = [
  "$ErrorActionPreference = 'Stop'",
  "$bytes = [byte[]](0, 1, 2, 255, 254, 10, 13, 0)",
  "[Console]::OpenStandardOutput().Write($bytes, 0, $bytes.Length)",
  "[Console]::Out.Flush()",
  "exit 7",
].join("\r\n");

function hex(buf) {
  return Buffer.from(buf).toString("hex");
}

// The client's "Warning: Permanently added ..." is written to ITS stderr, and
// it lands in the same stream as the remote's stderr.  Comparing the two
// servers means comparing the remote's stderr, so the warning has to be gone
// -- and the honest way to make it go is to write the host key down BEFORE
// the first connection, not to filter the warning out afterwards.
function writeKnownHosts(pubPath) {
  const line = fs.readFileSync(pubPath, "utf8").trim().split(/\s+/);
  const type = line[0];
  const blob = line[1];
  const known = path.join(BED, "known_hosts");
  fs.writeFileSync(known, `127.0.0.1 ${type} ${blob}\n`, "utf8");
  return known;
}

function freshBed() {
  fs.rmSync(BED, { recursive: true, force: true });
  fs.mkdirSync(BED, { recursive: true });
  // The user key.  The real server only accepts ECDSA (see the header); ours
  // speaks ed25519.
  const userKey = path.join(BED, "userkey");
  const type = SERVER === "real" ? ["-t", "ecdsa", "-b", "256"] : ["-t", "ed25519"];
  const r = spawnSync(REAL_KEYGEN, [...type, "-f", userKey, "-N", "", "-C", `loop94 ${SERVER} user key`],
    { encoding: "utf8", timeout: 60000 });
  if (r.status !== 0) throw new Error(`ssh-keygen failed: ${r.stderr}`);
  fs.copyFileSync(`${userKey}.pub`, path.join(BED, "authorized_keys"));

  if (SERVER === "ours") {
    // Our server's host key must be an OpenSSH private key file it can read.
    const h = spawnSync(REAL_KEYGEN, ["-t", "ed25519", "-f", path.join(BED, "hostkey"), "-N", "", "-C", "loop94 host key"],
      { encoding: "utf8", timeout: 60000 });
    if (h.status !== 0) throw new Error(`ssh-keygen failed: ${h.stderr}`);
  }

  fs.writeFileSync(path.join(BED, "emit.ps1"), EMIT_PS1, "utf8");
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

function waitForPort(port, timeoutMs = 20000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const sock = net.connect({ host: "127.0.0.1", port }, () => {
        sock.destroy();
        resolve();
      });
      sock.on("error", () => {
        sock.destroy();
        if (Date.now() > deadline) reject(new Error(`port ${port} never answered`));
        else setTimeout(tryOnce, 150);
      });
    };
    tryOnce();
  });
}

// The real sshd, through the shared helper: it knows where the Windows
// OpenSSH builds live, how to spell the config options, and how to generate
// the host keys.
async function startReal() {
  const port = await freePort();
  const proc = spawn(
    "node",
    [path.join(ROOT, "host", "sshd_setup.mjs"), "--dir", BED, "--port", String(port), "--name", "loop94"],
    { cwd: ROOT, stdio: ["ignore", "pipe", "pipe"] },
  );
  let out = "";
  proc.stdout.on("data", (d) => { out += d.toString(); });
  proc.stderr.on("data", (d) => { out += d.toString(); });
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (/sshd listening on/i.test(out)) break;
    if (/exited early|INVALID|Error/i.test(out)) throw new Error(`real sshd failed:\n${out}`);
    await new Promise((r) => setTimeout(r, 200));
  }
  await waitForPort(port);
  return {
    port,
    stop: () => { try { proc.kill(); } catch { /* already gone */ } },
  };
}

// Our server prints `listen_port: N` on STDERR -- stdout is block-buffered
// when it is a pipe, and the caller has to know the port before it can
// connect, so a buffered line would deadlock the probe.
async function startOurs() {
  const proc = spawn(
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
  proc.stdout.on("data", (d) => { out += d.toString(); });
  proc.stderr.on("data", (d) => { out += d.toString(); });
  const port = await new Promise((resolve, reject) => {
    const deadline = Date.now() + 30000;
    const tick = () => {
      const m = /listen_port:\s*(\d+)/i.exec(out);
      if (m) return resolve(Number(m[1]));
      if (Date.now() > deadline) return reject(new Error(`our sshd did not start:\n${out}`));
      setTimeout(tick, 100);
    };
    tick();
  });
  return {
    port,
    stop: () => { try { proc.kill(); } catch { /* already gone */ } },
  };
}

function runClient(port, argv) {
  const cmd = argv.map((a) => (a === "EMIT_PS1" ? path.join(BED, "emit.ps1") : a)).join(" ");
  const args = [
    "-p", String(port),
    "-i", path.join(BED, "userkey"),
    "-o", "IdentitiesOnly=yes",
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes",
    "-o", `UserKnownHostsFile=${path.join(BED, "known_hosts")}`,
    "hp@127.0.0.1",
    cmd,
  ];
  // No `encoding`: the bytes are the measurement.  Decoding them as UTF-8
  // first turns 0xFF into U+FFFD, and then the "binary" case measures the
  // decoder instead of the channel.
  const r = spawnSync(REAL_CLIENT, args, { timeout: 60000 });
  const stdout = r.stdout || Buffer.alloc(0);
  const stderr = r.stderr || Buffer.alloc(0);
  return {
    code: r.status,
    stdout: stdout.toString("latin1"),
    stderr: stderr.toString("latin1"),
    stdoutHex: hex(stdout),
    stderrHex: hex(stderr),
  };
}

async function main() {
  console.log(`=== Loop #94 probe: the ${SERVER} server's channel layer ===`);
  if (!REAL_CLIENT || !REAL_KEYGEN) {
    console.error("no real ssh.exe / ssh-keygen.exe on this machine");
    process.exit(3);
  }
  fs.mkdirSync(OUT_DIR, { recursive: true });
  freshBed();

  const results = {};
  if (SERVER === "ours") {
    writeKnownHosts(path.join(BED, "hostkey.pub"));
    // Our cmd/sshd serves ONE connection and then exits, so each command gets
    // its own server.  (A server that serves many is a later change; the
    // measurement does not depend on it.)
    for (const cmd of COMMANDS) {
      const server = await startOurs();
      let r;
      try {
        r = runClient(server.port, cmd.argv);
      } finally {
        server.stop();
      }
      results[cmd.id] = { argv: cmd.argv, ...r };
      console.log(`  ${cmd.id.padEnd(7)} code=${String(r.code).padEnd(4)} out=${JSON.stringify(r.stdout)} err=${JSON.stringify(r.stderr)}`);
    }
  } else {
    const server = await startReal();
    console.log(`real sshd on 127.0.0.1:${server.port}`);
    // The shared helper generates the host keys when it starts, so the known
    // hosts file can only be written now -- before the first connection.
    writeKnownHosts(path.join(BED, "hostkey_ed25519.pub"));
    try {
      for (const cmd of COMMANDS) {
        const r = runClient(server.port, cmd.argv);
        results[cmd.id] = { argv: cmd.argv, ...r };
        console.log(`  ${cmd.id.padEnd(7)} code=${String(r.code).padEnd(4)} out=${JSON.stringify(r.stdout)} err=${JSON.stringify(r.stderr)}`);
      }
    } finally {
      server.stop();
    }
  }

  const outFile = path.join(OUT_DIR, `probe-${SERVER}.json`);
  fs.writeFileSync(outFile, JSON.stringify({ server: SERVER, results }, null, 2));
  console.log(`written: ${path.relative(ROOT, outFile)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
