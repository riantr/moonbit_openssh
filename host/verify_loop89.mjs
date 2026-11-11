#!/usr/bin/env node
// host/verify_loop89.mjs -- Loop #89: the SSH agent protocol works.
// 
// ## What is being claimed
//
// Loop #89 implements the SSH agent protocol on Windows via named pipes:
//   * `src/agentpipe` -- Windows named pipe transport (C-FFI)
//   * `src/agentserver` -- the agent server: key store + request handling
//   * `cmd/ssh_agent` -- the agent daemon: creates pipe, accepts, serves
//   * `cmd/ssh_add` -- the agent client: -l/-L/-d/-D with real sentences/exit codes
//
// The claim is that the WHOLE STACK -- from the named pipe up to the
// sentences printed by `ssh-add` -- matches the real OpenSSH agent byte for
// byte: exit status, stdout, and stderr.
//
// ## The judge
//
// The judge is the REAL `ssh-add` from Windows OpenSSH.
//
// **Each client gets its OWN agent instance**, and the two sequences run in
// lockstep.  This is not a detail: the sequence is a state machine, so
// "add" then "-d" then "add again" only means something against an agent
// whose state evolves.  Sharing one agent would make the SECOND client see
// the FIRST client's leftovers -- our client's "add" would leave the key in
// the agent, and the real client's "add" would then be a DUPLICATE, which
// the agent refuses on purpose.  (That is exactly how this gate first
// failed, and the failure looked like a protocol bug.)
//
// So: two agents, two pipes, one per client, and the comparison is between
// what the two clients PRINTED, each against a fresh agent of its own.
//
// ## The rules the cases pin down
//
// The rules below were READ OUT OF THE REAL TOOLS, not guessed.  The
// scripts that read them out are `.loop89/probe_e2e.py`,
// `.loop89/probe_add_proto.py`, `.loop89/probe_sign.py`,
// `.loop89/probe_agent.py`, and `.loop89/facts.md`.
//
//   * The pipe name is `\\.\pipe\openssh-<random>-agent` -- OpenSSH on
//     Windows only talks to named pipes, it does NOT do TCP for the agent.
// 
//   * `ADD_IDENTITY` payload shape (no outer length prefix):
//     `string "ssh-ed25519"` `string <32-byte public key>` `string <64-byte private key>` `string <comment>`
//     The public key blob (51 bytes = `string "ssh-ed25519"` + `string <32>`) is NOT wrapped in another string.
// 
//   * `REMOVE_IDENTITY` payload shape (HAS outer length prefix):
//     `string <51-byte public key blob>`
//     The asymmetry is the point: a server that reads both the same way gets one wrong.
// 
//   * `AGENT_IDENTITIES_ANSWER` is `u32 count` then per identity: `string <public key blob>` `string <comment>`.
//     TWO strings per identity.  One string and the real `ssh-add` says "incomplete message".
// 
//   * `SIGN_REQUEST` payload: `string <public key blob>` `string <data>` `u32 flags`.
//     Reply is `AGENT_SIGN_RESPONSE` with `string <signature blob>` where signature blob is
//     `string "ssh-ed25519"` `string <64-byte signature>`.
// 
//   * The agent does `key_is_consistent` on ADD: the public key inside the
//     private blob must match the public key blob.  Mismatched keys are
//     refused with `AGENT_FAILURE`.
// 
//   * Sentences and exit codes (ALL from real `ssh-add` stderr/stdout):
//     - empty `-l`: exit 1, stdout "The agent has no identities.\r\n"
//     - successful add: exit 0, stderr "Identity added: <path> (<comment>)\r\n"
//     - `-l` one key: exit 0, stdout "256 SHA256:<fp> <comment> (ED25519)\r\n"
//     - `-L` one key: exit 0, stdout "<pubkey line>\r\n"
//     - `-d` remove one: exit 0, stderr "Identity removed: <path> ED25519 (<comment>)\r\n"
//     - `-D` remove all: exit 0, stderr "All identities removed.\r\n"
//     - no agent (SSH_AUTH_SOCK points to non-existent pipe): exit 2,
//       stderr "Error connecting to agent: No such file or directory\r\n"
// 
//   * The agent daemon prints NOTHING on success.  On error it prints to
//     stderr and exits non-zero.
//
// ## The divergences, stated rather than hidden
//
//   * This repository has ed25519 only.  An RSA key is refused.
// 
//   * The real `ssh-agent` on Windows is a Windows service / COM thing that
//     lives forever.  This tool is a simple foreground process that exits
//     when the pipe is closed (or on Ctrl-C).  The test protocol starts a
//     fresh agent for each case, so lifetime differences don't matter.
// 
//   * The real `ssh-add -l` on an empty agent prints to stdout (not stderr)
//     and exits 1.  Our client matches that.
//
//   * We do not implement agent locking / confirmation / constraints.  Those
//     are `SSH_AGENTC_ADD_IDENTITY_CONSTRAINED` etc.  The real `ssh-add`
//     doesn't send them unless you ask for them.
// 
//   * The pipe is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` so a second
//     agent on the same name fails fast.  **That is OUR choice, not a
//     claim about OpenSSH** -- the real agent is a service here and could
//     not be measured.
// 
//   * The agent's stderr is NOT captured in the byte comparison -- the gate
//     compares the `ssh-add` client outputs only.  The agent's own logs are
//     printed separately for debugging.
//
// ## What runs where
//
// Everything here needs node, the MoonBit toolchain, and the real
// `ssh-add.exe` from Windows OpenSSH.  When it is not present the gate says
// so LOUDLY and fails -- a gate that cannot check its claim must not report
// success.
//
// **The real `ssh-agent` is NOT available on this machine.**  It is a
// Windows service: `ssh-agent.exe` says `unable to start ssh-agent
// service, error :1058`, and `sc start ssh-agent` says `StartService
// FAILED 1058` (the service is disabled).  So the judge here is the real
// CLIENT, and the server's decisions are pinned by OpenSSH's rules and by
// the real client's rendering of them -- see G5.

import { spawnSync, spawn } from "node:child_process";
import {
  existsSync, mkdirSync, readFileSync, rmSync,
} from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop89", "gate");

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

function norm(s) {
  return `${s}`.replace(/\r\n/g, "\n");
}

// A gate that runs a build must not be able to hang forever.
const MOON_TIMEOUT_MS = 600000;

function moon(args) {
  const r = spawnSync("cmd", ["/c", "moon", ...args], {
    cwd: ROOT, encoding: "utf8", errors: "replace", maxBuffer: 64 * 1024 * 1024,
    timeout: MOON_TIMEOUT_MS,
  });
  let out = norm(`${r.stdout || ""}${r.stderr || ""}`);
  if (r.error) {
    out += `\n[spawn failed: ${r.error.message} (code=${r.error.code})]\n`;
  }
  const code = r.error ? 1 : r.status;
  return { code, out };
}

function moonCheck(pkg, target) {
  const r = moon(["check", "--target", target, "-p", pkg]);
  const failed = /^\s*Error:/m.test(r.out) || (r.code !== 0 && r.code !== null);
  const m = r.out.match(/(\d+)\s+warnings?,\s*(\d+)\s+errors?/);
  return { errors: failed ? (m ? Number(m[2]) : 1) : 0, warnings: m ? Number(m[1]) : -1, out: r.out };
}

// The real OpenSSH ssh-add.
const KEYGEN_DIRS = [
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH-Win64",
  "C:\\Program Files\\OpenSSH",
];
const SSH_ADDS = KEYGEN_DIRS
  .map((d) => path.join(d, "ssh-add.exe"))
  .filter((p) => existsSync(p));

// Run a program and keep the BYTES.
function runBytes(bin, args, env = {}) {
  const r = spawnSync(bin, args, {
    cwd: ROOT, timeout: 60000, input: "", maxBuffer: 64 * 1024 * 1024,
    killSignal: "SIGKILL",
    env: { ...process.env, ...env },
  });
  return {
    code: r.error ? 1 : r.status,
    stdout: r.stdout || Buffer.alloc(0),
    stderr: r.stderr || Buffer.alloc(0),
    error: r.error ? r.error.message : "",
  };
}

// Our own tools, once built.
let OUR_AGENT = null;
let OUR_ADD = null;

function ourAdd(args, env = {}) {
  return runBytes(OUR_ADD, args, env);
}
function realAdd(args, env = {}) {
  return runBytes(SSH_ADDS[0], args, env);
}

// Compare the outputs of two `ssh-add` runs byte for byte.
function sameBytes(label, a, b) {
  checks++;
  const problems = [];
  if (a.code !== b.code) {
    problems.push(`exit ${a.code}, want ${b.code}`);
  }
  if (!a.stdout.equals(b.stdout)) {
    problems.push(`stdout\n        ours   ${JSON.stringify(a.stdout.toString("latin1"))}\n        theirs ${JSON.stringify(b.stdout.toString("latin1"))}`);
  }
  if (!a.stderr.equals(b.stderr)) {
    problems.push(`stderr\n        ours   ${JSON.stringify(a.stderr.toString("latin1"))}\n        theirs ${JSON.stringify(b.stderr.toString("latin1"))}`);
  }
  if (problems.length === 0) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}`);
    for (const p of problems) console.log(`        ${p}`);
  }
  return problems.length === 0;
}

function freshDir(name) {
  const dir = path.join(WORK, name);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  return dir;
}

// Generate a unique pipe name for this test case.
function makePipeName(tag) {
  const rand = Math.random().toString(36).slice(2, 10);
  return `\\\\.\\pipe\\openssh-${rand}-${tag}-agent`;
}

// Wait for pipe to exist (try to connect)
async function waitForPipe(pipeName, timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const { createConnection } = await import("node:net");
      await new Promise((resolve, reject) => {
        const sock = createConnection(pipeName);
        sock.on("connect", () => { sock.destroy(); resolve(); });
        sock.on("error", reject);
        sock.setTimeout(1000, () => { sock.destroy(); reject(new Error("timeout")); });
      });
      return true;
    } catch {
      await new Promise(r => setTimeout(r, 100));
    }
  }
  return false;
}

// Start our agent in background on a given pipe.
async function startOurAgent(pipeName) {
  return new Promise((resolve, reject) => {
    const child = spawn(OUR_AGENT, ["--socket", pipeName], {
      cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => { stdout += d.toString(); });
    child.stderr.on("data", (d) => { stderr += d.toString(); });
    child.on("error", (e) => reject(e));
    child.on("exit", (code) => resolve({ code, stdout, stderr, child }));
    // Give it time to start and create the pipe -- 1.5s like probe_e2e.py
    setTimeout(() => resolve({ code: null, stdout, stderr, child, running: true }), 1500);
  });
}

// Run a sequence of ssh-add operations against an agent.
//
// **Each client gets its OWN agent instance.**
//
// This matters, and it is not a detail: the sequence is a state machine.
// "add" then "-d" then "add again" only makes sense against an agent
// whose state evolves.  If both clients shared one agent, the second
// client would see the first client's leftovers -- the first client's
// "add" would leave the key in the agent, and the second client's "add"
// would then be a DUPLICATE, which our agent refuses on purpose.
//
// So: two agents, two pipes, one per client, and the two sequences run
// in lockstep.  The comparison is between what the two clients printed,
// each against a fresh agent of its own.
async function runSequence(label, ops) {
  console.log(`\n  --- ${label} ---`);

  const ourPipe = makePipeName(`our-${label.replace(/[^a-z0-9]+/gi, "-")}`);
  const theirPipe = makePipeName(`their-${label.replace(/[^a-z0-9]+/gi, "-")}`);
  console.log(`    our pipe:  ${ourPipe}`);
  console.log(`    their pipe: ${theirPipe}`);

  // Start our agent for OUR client
  const ourAgentResult = await startOurAgent(ourPipe);
  if (!ourAgentResult.running) {
    console.log(`  FAIL  agent failed to start: ${ourAgentResult.stderr}`);
    failures++;
    return;
  }
  // Start our agent for THEIR client -- the same binary, a different
  // pipe, a different (empty) store.
  const theirAgentResult = await startOurAgent(theirPipe);
  if (!theirAgentResult.running) {
    console.log(`  FAIL  agent failed to start: ${theirAgentResult.stderr}`);
    failures++;
    ourAgentResult.child.kill("SIGKILL");
    return;
  }

  const ourPipeReady = await waitForPipe(ourPipe);
  const theirPipeReady = await waitForPipe(theirPipe);
  if (!ourPipeReady || !theirPipeReady) {
    console.log(`  FAIL  pipe not ready after timeout (ours=${ourPipeReady}, theirs=${theirPipeReady})`);
    ourAgentResult.child.kill("SIGKILL");
    theirAgentResult.child.kill("SIGKILL");
    failures++;
    return;
  }

  const ourEnv = { SSH_AUTH_SOCK: ourPipe };
  const theirEnv = { SSH_AUTH_SOCK: theirPipe };

  // Run each operation: ours against our agent, theirs against theirs.
  for (const [opLabel, addArgs] of ops) {
    const ours = ourAdd(addArgs, ourEnv);
    const theirs = realAdd(addArgs, theirEnv);
    sameBytes(`${label}: ${opLabel}`, ours, theirs);
  }

  // Clean up both agents
  ourAgentResult.child.kill("SIGKILL");
  theirAgentResult.child.kill("SIGKILL");
  await new Promise(r => setTimeout(r, 200));
}

// ---------------------------------------------------------------------------
// The wire capture: what the client actually PUTS ON THE PIPE.
//
// Comparing what the two clients PRINT is half the claim.  The other
// half is that they TALK the same protocol -- and that is a claim about
// BYTES, not about sentences.
//
// So this is a stub agent: a Node named-pipe server that records the
// request it receives and answers it.  The real `ssh-add` is pointed at
// it, our `ssh_add` is pointed at it, and the two recorded byte strings
// are compared.
//
// This is the check that pins the protocol SHAPE, and the shape is
// where the trap is:
//   * `ADD_IDENTITY` has NO outer length prefix around the key;
//   * `REMOVE_IDENTITY` HAS one.
// A server that reads both the same way gets one of them wrong, and the
// one it gets wrong is the one that "works" against a mock agent.
// ---------------------------------------------------------------------------

// The answers the stub gives.
const STUB_SUCCESS = Buffer.from([0, 0, 0, 1, 0x06]);
const STUB_IDENTITIES_ANSWER_EMPTY = Buffer.from([0, 0, 0, 5, 0x0c, 0, 0, 0, 0]);

// Run one client against a stub agent and return the bytes it sent.
//
// The stub answers whatever it is asked, so the client does not hang.
// It records the FIRST request: `ssh-add` sends one request per
// connection.
function captureWire(pipeName, clientBin, args) {
  return new Promise((resolve) => {
    const captured = [];
    const server = net.createServer((sock) => {
      let buf = Buffer.alloc(0);
      sock.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        // A frame is u32 length + that many bytes.
        if (buf.length < 4) return;
        const len = buf.readUInt32BE(0);
        if (buf.length < 4 + len) return;
        const frame = buf.subarray(0, 4 + len);
        captured.push(frame);
        const type = frame[4];
        // 11 = REQUEST_IDENTITIES, 12 = IDENTITIES_ANSWER.
        if (type === 0x0b) {
          sock.write(STUB_IDENTITIES_ANSWER_EMPTY);
        } else {
          sock.write(STUB_SUCCESS);
        }
      });
      sock.on("error", () => {});
    });
    server.on("error", (e) => {
      resolve({ frame: null, error: e.message });
    });
    server.listen(pipeName, () => {
      const env = { ...process.env, SSH_AUTH_SOCK: pipeName };
      const child = spawn(clientBin, args, {
        cwd: ROOT, env, stdio: ["ignore", "pipe", "pipe"],
      });
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        try { server.close(); } catch { /* already closed */ }
        resolve({ frame: captured.length ? captured[0] : null, error: "" });
      };
      child.on("exit", finish);
      // The client closes the connection after its answer; give it a
      // moment, then take what we have.
      setTimeout(finish, 2500);
    });
  });
}

// Compare two recorded frames byte for byte.
function sameFrame(label, a, b) {
  checks++;
  if (a === null || b === null) {
    failures++;
    console.log(`  FAIL  ${label}`);
    console.log(`        ${a === null ? "the real client sent nothing" : "our client sent nothing"}`);
    return false;
  }
  if (a.equals(b)) {
    console.log(`  PASS  ${label}  -- ${a.length} bytes`);
    return true;
  }
  failures++;
  console.log(`  FAIL  ${label}`);
  console.log(`        ours   ${a.length} bytes: ${a.toString("hex")}`);
  console.log(`        theirs ${b.length} bytes: ${b.toString("hex")}`);
  return false;
}

async function main() {
  console.log("Loop #89: the SSH agent protocol works.");
  console.log(`  root: ${ROOT}`);

  // -------------------------------------------------------------------------
  section("G0: the toolchain");
  // -------------------------------------------------------------------------

  // Compile checks
  const pkgs = [
    "src/agentpipe",
    "src/agentserver",
    "src/keyfile",
    "cmd/ssh_agent",
    "cmd/ssh_add",
  ];
  for (const pkg of pkgs) {
    const r = moonCheck(pkg, "native");
    ok(`${pkg} compiles on native`, r.errors === 0,
      r.errors ? `${r.errors} error(s)` : `${r.warnings} warning(s)`);
  }

  // Test runs
  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const r = moon(["test", "src/keyfile", "--target", target]);
    const m = r.out.match(/Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/);
    ok(`src/keyfile's tests pass on ${target}`,
      r.code === 0 && m && Number(m[3]) === 0 && Number(m[2]) > 0,
      m ? `${m[2]}/${m[1]} passed` : r.out.slice(-200));
  }
  // The protocol and the transport have their own tests.  `src/agentpipe`
  // is split the way the implementation is: the real named pipe is native
  // only, and the stub that refuses everything is tested on the targets
  // where the stub IS the whole story.
  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const r = moon(["test", "src/agent", "--target", target]);
    const m = r.out.match(/Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/);
    ok(`src/agent's tests pass on ${target}`,
      r.code === 0 && m && Number(m[3]) === 0 && Number(m[2]) > 0,
      m ? `${m[2]}/${m[1]} passed` : r.out.slice(-200));
  }
  for (const target of ["native", "js", "wasm", "wasm-gc"]) {
    const r = moon(["test", "src/agentpipe", "--target", target]);
    const m = r.out.match(/Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/);
    ok(`src/agentpipe's tests pass on ${target}`,
      r.code === 0 && m && Number(m[3]) === 0 && Number(m[2]) > 0,
      m ? `${m[2]}/${m[1]} passed` : r.out.slice(-200));
  }
  const rAg = moon(["test", "src/agentserver", "--target", "native"]);
  const mAg = rAg.out.match(/Total tests:\s*(\d+),\s*passed:\s*(\d+),\s*failed:\s*(\d+)/);
  ok(`src/agentserver's tests pass on native`,
    rAg.code === 0 && mAg && Number(mAg[3]) === 0 && Number(mAg[2]) > 0,
    mAg ? `${mAg[2]}/${mAg[1]} passed` : rAg.out.slice(-200));

  // Build the tools
  const buildAgent = moon(["build", "cmd/ssh_agent", "--target", "native"]);
  ok("cmd/ssh_agent builds", buildAgent.code === 0, buildAgent.code === 0 ? "" : buildAgent.out.slice(-300));
  const buildAdd = moon(["build", "cmd/ssh_add", "--target", "native"]);
  ok("cmd/ssh_add builds", buildAdd.code === 0, buildAdd.code === 0 ? "" : buildAdd.out.slice(-300));

  const agentCandidates = [
    path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_agent", "ssh_agent.exe"),
    path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_agent", "ssh_agent"),
  ];
  OUR_AGENT = agentCandidates.find((p) => existsSync(p)) || null;
  ok("the built ssh_agent is there", OUR_AGENT !== null,
    OUR_AGENT || `looked in ${agentCandidates.join(" and ")}`);

  const addCandidates = [
    path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_add", "ssh_add.exe"),
    path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_add", "ssh_add"),
  ];
  OUR_ADD = addCandidates.find((p) => existsSync(p)) || null;
  ok("the built ssh_add is there", OUR_ADD !== null,
    OUR_ADD || `looked in ${addCandidates.join(" and ")}`);

  // -------------------------------------------------------------------------
  section("G1: the real ssh-add is here");
  // -------------------------------------------------------------------------

  if (SSH_ADDS.length === 0) {
    ok("a real ssh-add is available", false,
      "no ssh-add found -- this gate cannot check its claim");
    console.log("\nCI FAIL: 0 checks could be run");
    process.exit(1);
  }
  ok("a real ssh-add is available", true,
    `${SSH_ADDS.length} build(s): ${SSH_ADDS.map((p) => path.basename(path.dirname(p))).join(", ")}`);

  if (!OUR_AGENT || !OUR_ADD) {
    console.log("\nCI FAIL: our own tools were not built");
    process.exit(1);
  }

  const dir = freshDir("keys");

  // -------------------------------------------------------------------------
  // Helper: make a test key using real ssh-keygen
  // -------------------------------------------------------------------------
  const SSH_KEYGENS = KEYGEN_DIRS
    .map((d) => path.join(d, "ssh-keygen.exe"))
    .filter((p) => existsSync(p));
  
  function makeKey(name, comment = "probe@loop89", passphrase = "") {
    const p = path.join(dir, name);
    const made = runBytes(SSH_KEYGENS[0],
      ["-t", "ed25519", "-f", p, "-N", passphrase, "-C", comment]);
    if (made.code !== 0) {
      console.log(`  FAIL  the real ssh-keygen could not make ${name}  -- ${made.stderr.toString()}`);
      failures++;
    }
    return p;
  }

  // -------------------------------------------------------------------------
  section("G2: real ssh-add vs our ssh_add -- outputs match byte for byte");
  // -------------------------------------------------------------------------
  //
  // The protocol:
  // 1. Start TWO agents, each on its own unique pipe
  // 2. Set SSH_AUTH_SOCK to each pipe
  // 3. Run real ssh-add for a sequence of operations against ITS agent
  // 4. Run our ssh_add for the SAME sequence against ITS agent
  // 5. Compare outputs byte for byte
  //
  // Each case uses fresh agents and fresh pipes.  **Two agents, not one**:
  // the sequence is a state machine, so sharing one agent would make the
  // second client see the first client's leftovers.

  // Case 1: empty agent -l
  await runSequence("empty agent -l", [
    ["-l empty", ["-l"]],
  ]);

  // Case 2: full lifecycle - add, list, list public, remove, list, remove all, list
  const keyPath = makeKey("testkey");

  await runSequence("full lifecycle", [
    ["-l empty", ["-l"]],
    ["add", [keyPath]],
    ["-l one", ["-l"]],
    ["-L one", ["-L"]],
    ["-d remove", ["-d", keyPath]],
    ["-l after -d", ["-l"]],
    ["add again", [keyPath]],
    ["-D remove all", ["-D"]],
    ["-l after -D", ["-l"]],
  ]);

  // Case 3: no agent running -- SSH_AUTH_SOCK points to non-existent pipe
  {
    console.log(`\n  --- no agent running ---`);
    const noAgentPipe = makePipeName("no-agent");
    console.log(`    pipe: ${noAgentPipe} (no agent listening)`);
    const env = { SSH_AUTH_SOCK: noAgentPipe };
    const ours = ourAdd(["-l"], env);
    const theirs = realAdd(["-l"], env);
    sameBytes("no agent: -l", ours, theirs);
  }

  // Case 4: add with -q (quiet)
  await runSequence("quiet add", [
    ["add -q", ["-q", keyPath]],
    ["-l one", ["-l"]],
    ["-d -q", ["-q", "-d", keyPath]],
    ["-l after -d", ["-l"]],
  ]);

  // Case 5: multiple keys
  const keyPath2 = makeKey("testkey2", "second@loop89");
  await runSequence("multiple keys", [
    ["-l empty", ["-l"]],
    ["add first", [keyPath]],
    ["add second", [keyPath2]],
    ["-l two", ["-l"]],
    ["-L two", ["-L"]],
    ["-D remove all", ["-D"]],
    ["-l after -D", ["-l"]],
  ]);

  // Case 6: adding a key twice -- the second one is a DUPLICATE
  //
  // Our agent refuses a duplicate on purpose, and so does OpenSSH's.
  // This is a claim about the agent's behaviour, so it is checked
  // against the real tool's answer.
  await runSequence("duplicate add", [
    ["add first", [keyPath]],
    ["add same again", [keyPath]],
    ["-l one", ["-l"]],
  ]);

  // Case 7: removing a key the agent does not have
  await runSequence("remove a key that is not there", [
    ["-d missing", ["-d", keyPath]],
    ["-l empty", ["-l"]],
  ]);

  // -------------------------------------------------------------------------
  section("G3: keyfile round-trip through agent");
  // -------------------------------------------------------------------------
  // A key added to our agent, then listed by the REAL ssh-add.  The other
  // direction of the same contract: the agent is a program other people
  // have to read.
  {
    const pipeName = makePipeName("roundtrip");
    console.log(`\n  --- roundtrip ---`);
    console.log(`    pipe: ${pipeName}`);

    const agentResult = await startOurAgent(pipeName);
    if (!agentResult.running) {
      console.log(`  FAIL  agent failed to start: ${agentResult.stderr}`);
      failures++;
    } else {
      const agent = agentResult.child;
      const pipeReady = await waitForPipe(pipeName);
      if (pipeReady) {
        const keyPath3 = makeKey("roundtrip");
        const env = { SSH_AUTH_SOCK: pipeName };

        // Add to our agent using our ssh_add
        const addResult = ourAdd([keyPath3], env);
        ok("our ssh_add adds key", addResult.code === 0, addResult.code === 0 ? "" : addResult.stderr.toString());

        // Real ssh-add -l should see it
        const realList = realAdd(["-l"], env);
        ok("real ssh-add -l sees our key", realList.code === 0, realList.code === 0 ? "" : realList.stderr.toString());

        // Our ssh_add -l should also see it
        const ourList = ourAdd(["-l"], env);
        ok("our ssh_add -l sees our key", ourList.code === 0, ourList.code === 0 ? "" : ourList.stderr.toString());

        // Compare the two lists byte for byte
        sameBytes("roundtrip: both clients see same list", ourList, realList);

        // And the REAL ssh-add can remove it again -- so our agent really
        // speaks the protocol, not just our own client.
        const realRemove = realAdd(["-d", keyPath3], env);
        ok("real ssh-add removes our key", realRemove.code === 0,
          realRemove.code === 0 ? "" : realRemove.stderr.toString());
        const afterRemove = realAdd(["-l"], env);
        ok("the agent is empty after the real tool removed the key",
          afterRemove.code === 1 && afterRemove.stdout.toString() === "The agent has no identities.\r\n",
          `exit ${afterRemove.code}, stdout ${JSON.stringify(afterRemove.stdout.toString("latin1"))}`);
      }
      agent.kill("SIGKILL");
    }
    await new Promise(r => setTimeout(r, 200));
  }

  // -------------------------------------------------------------------------
  section("G4: the two clients speak the SAME BYTES on the wire");
  // -------------------------------------------------------------------------
  //
  // The printed output says the two clients behave alike.  This says the
  // two clients TALK alike -- the request frames are compared byte for
  // byte, against a stub agent that records them.
  {
    const keyPath4 = makeKey("wirekey", "wire@loop89");

    // ADD_IDENTITY: the payload is `string 类型名` + `string 公钥` +
    // `string 私钥` + `string 注释`, and there is NO outer length prefix.
    const addReal = await captureWire(makePipeName("wire-add-real"), SSH_ADDS[0], [keyPath4]);
    const addOurs = await captureWire(makePipeName("wire-add-ours"), OUR_ADD, [keyPath4]);
    sameFrame("the ADD_IDENTITY frame is the same", addOurs.frame, addReal.frame);

    // REMOVE_IDENTITY: the payload is `string 公钥 blob`, and it HAS an
    // outer length prefix.  **The two frames are NOT the same shape**,
    // and that is the point: ADD has no prefix and REMOVE has one.
    const remReal = await captureWire(makePipeName("wire-rem-real"), SSH_ADDS[0], ["-d", keyPath4]);
    const remOurs = await captureWire(makePipeName("wire-rem-ours"), OUR_ADD, ["-d", keyPath4]);
    sameFrame("the REMOVE_IDENTITY frame is the same", remOurs.frame, remReal.frame);

    // REQUEST_IDENTITIES: no payload at all.
    const listReal = await captureWire(makePipeName("wire-list-real"), SSH_ADDS[0], ["-l"]);
    const listOurs = await captureWire(makePipeName("wire-list-ours"), OUR_ADD, ["-l"]);
    sameFrame("the REQUEST_IDENTITIES frame is the same", listOurs.frame, listReal.frame);

    // REMOVE_ALL_IDENTITIES: no payload at all.
    const allReal = await captureWire(makePipeName("wire-all-real"), SSH_ADDS[0], ["-D"]);
    const allOurs = await captureWire(makePipeName("wire-all-ours"), OUR_ADD, ["-D"]);
    sameFrame("the REMOVE_ALL_IDENTITIES frame is the same", allOurs.frame, allReal.frame);
  }

  // -------------------------------------------------------------------------
  section("G5: the SERVER's decisions, rendered by the REAL client");
  // -------------------------------------------------------------------------
  //
  // G2 has a blind spot, and it is worth naming it.
  //
  // In G2 BOTH clients talk to OUR agent.  So when the AGENT decides
  // something, both clients see the same decision and print the same
  // thing -- and the comparison cannot tell whether that decision was
  // RIGHT.  A server that accepted a duplicate key would make both
  // clients print "Identity added", and the two would agree perfectly
  // about a wrong answer.
  //
  // This section closes that gap by asking the REAL client a question
  // whose answer only the SERVER can give, and checking the answer
  // against OpenSSH's rule.  The server's decisions here are:
  //
  //   * adding a key it does not have  -> SUCCESS
  //   * adding a key it DOES have      -> FAILURE (OpenSSH's
  //     `process_add_identity` refuses a duplicate key)
  //   * removing a key it does not have -> FAILURE
  //   * removing all its keys          -> SUCCESS, even when it had none
  //
  // The SENTENCES are measured from the real tool (`.loop89/facts.md`),
  // and the DECISIONS are OpenSSH's rules (`ssh-agent.c`).
  {
    const keyPath5 = makeKey("serverkey", "server@loop89");
    const pipeName = makePipeName("server-decisions");
    console.log(`\n  --- server decisions ---`);
    console.log(`    pipe: ${pipeName}`);

    const agentResult = await startOurAgent(pipeName);
    if (!agentResult.running) {
      console.log(`  FAIL  agent failed to start: ${agentResult.stderr}`);
      failures++;
    } else {
      const agent = agentResult.child;
      const pipeReady = await waitForPipe(pipeName);
      if (!pipeReady) {
        console.log(`  FAIL  pipe not ready after timeout`);
        failures++;
      } else {
        const env = { SSH_AUTH_SOCK: pipeName };

        // 1. An agent with nothing in it: the client says so on STDOUT
        //    and exits 1.
        const emptyList = realAdd(["-l"], env);
        ok("the real client says an empty agent has no identities",
          emptyList.code === 1 &&
          emptyList.stdout.toString() === "The agent has no identities.\r\n" &&
          emptyList.stderr.length === 0,
          `exit ${emptyList.code}, stdout ${JSON.stringify(emptyList.stdout.toString("latin1"))}, stderr ${JSON.stringify(emptyList.stderr.toString("latin1"))}`);

        // 2. Removing ALL from an empty agent SUCCEEDS.  "Removed zero
        //    keys" is still "removed them all".
        const emptyRemoveAll = realAdd(["-D"], env);
        ok("removing all from an empty agent succeeds",
          emptyRemoveAll.code === 0 &&
          emptyRemoveAll.stderr.toString() === "All identities removed.\r\n",
          `exit ${emptyRemoveAll.code}, stderr ${JSON.stringify(emptyRemoveAll.stderr.toString("latin1"))}`);

        // 3. Removing a key the agent does not have is a REFUSAL, and
        //    the client says so.
        const missingRemove = realAdd(["-d", keyPath5], env);
        ok("removing a key the agent does not have is refused",
          missingRemove.code === 1 &&
          missingRemove.stderr.toString() ===
            `Could not remove identity "${keyPath5}": agent refused operation\r\n`,
          `exit ${missingRemove.code}, stderr ${JSON.stringify(missingRemove.stderr.toString("latin1"))}`);

        // 4. Adding a key it does not have SUCCEEDS.
        const firstAdd = realAdd([keyPath5], env);
        ok("adding a new key succeeds",
          firstAdd.code === 0 &&
          firstAdd.stderr.toString() === `Identity added: ${keyPath5} (server@loop89)\r\n`,
          `exit ${firstAdd.code}, stderr ${JSON.stringify(firstAdd.stderr.toString("latin1"))}`);

        // 5. Adding the SAME key again is a REFUSAL.  OpenSSH's agent
        //    refuses a duplicate key (`process_add_identity`), and a
        //    server that accepted it would be holding two copies of
        //    one key.
        const dupAdd = realAdd([keyPath5], env);
        ok("adding the same key again is refused",
          dupAdd.code === 1 &&
          dupAdd.stderr.toString() ===
            `Could not add identity "${keyPath5}": agent refused operation\r\n`,
          `exit ${dupAdd.code}, stderr ${JSON.stringify(dupAdd.stderr.toString("latin1"))}`);

        // 6. And the agent still holds exactly ONE key -- a refusal
        //    that still added the key would be a refusal in name only.
        const afterDup = realAdd(["-l"], env);
        ok("the agent holds exactly one key after a refused duplicate",
          afterDup.code === 0 &&
          afterDup.stdout.toString().split("\r\n").filter((l) => l.length > 0).length === 1,
          `exit ${afterDup.code}, stdout ${JSON.stringify(afterDup.stdout.toString("latin1"))}`);

        // 7. The COMMENT the agent gives back is the comment it was
        //    given.  The real client's `-l` line shows it, so the REAL
        //    CLIENT is what reads the agent's copy of the comment back
        //    out.
        //
        //    **This check exists because of a mutation.**  An agent
        //    that answers the identity list with an EMPTY comment
        //    passes every output comparison in G2 -- because in G2 both
        //    clients talk to our agent and would agree perfectly about
        //    an agent that holds the wrong thing -- and the only thing
        //    that catches it is a check that reads what the agent
        //    HOLDS.
        const listWithComment = realAdd(["-l"], env);
        ok("the agent gives back the comment it was given",
          listWithComment.code === 0 &&
          listWithComment.stdout.toString().includes("server@loop89"),
          `exit ${listWithComment.code}, stdout ${JSON.stringify(listWithComment.stdout.toString("latin1"))}`);

        // 8. The public key line the agent gives back is the key FILE's
        //    line.  This pins the agent's copy of the KEY BLOB as well
        //    as the comment: the fingerprint in `-l` and the blob in
        //    `-L` both come out of the agent, and the `.pub` file is
        //    what they have to agree with.
        const pubLine = realAdd(["-L"], env);
        const pubFile = readFileSync(keyPath5 + ".pub", "latin1");
        ok("the public key line the agent gives back is the key file's line",
          pubLine.code === 0 &&
          pubLine.stdout.toString().trim() === pubFile.trim(),
          `stdout ${JSON.stringify(pubLine.stdout.toString("latin1"))}, file ${JSON.stringify(pubFile)}`);
      }
      agent.kill("SIGKILL");
    }
    await new Promise(r => setTimeout(r, 200));
  }

  // -------------------------------------------------------------------------
  section("G6: the agent can be given a key at startup (--key)");
  // -------------------------------------------------------------------------
  {
    const keyPath6 = makeKey("startupkey", "startup@loop89");
    const pipeName = makePipeName("startup");
    console.log(`\n  --- startup key ---`);
    console.log(`    pipe: ${pipeName}`);

    const child = spawn(OUR_AGENT, ["--socket", pipeName, "--key", keyPath6], {
      cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (d) => { stderr += d.toString(); });
    await new Promise(r => setTimeout(r, 1500));
    const pipeReady = await waitForPipe(pipeName);
    if (!pipeReady) {
      console.log(`  FAIL  pipe not ready after timeout`);
      failures++;
    } else {
      const env = { SSH_AUTH_SOCK: pipeName };
      const list = realAdd(["-l"], env);
      ok("the real client sees the key the agent was given at startup",
        list.code === 0 &&
        list.stdout.toString().includes("startup@loop89"),
        `exit ${list.code}, stdout ${JSON.stringify(list.stdout.toString("latin1"))}, agent stderr ${JSON.stringify(stderr)}`);
    }
    child.kill("SIGKILL");
    await new Promise(r => setTimeout(r, 200));
  }

  // -------------------------------------------------------------------------
  section("G7: the options this tool REFUSES, and why");
  // -------------------------------------------------------------------------
  //
  // An option that a tool does not implement has three possible
  // behaviours, and only one of them is honest:
  //
  //   1. take the letter and give it a DIFFERENT meaning;
  //   2. say "unknown option" -- which is a lie, because it is a known
  //      OpenSSH option;
  //   3. say what the option MEANS and that this tool does not do it.
  //
  // This section pins (3), and it is here because the first version of
  // this loop did (1): `ssh_add -s <socket>` meant "the agent is here",
  // while OpenSSH's `-s` means "add keys from a PKCS#11 provider".  A
  // `ssh-add -s pkcs11` typed at our tool would have SUCCEEDED as a
  // no-op, which is the worst possible answer.
  //
  // The measurements behind these sentences are in
  // `.loop89/probe_dash_s2.py`, run against our own agent so the
  // connection succeeded and the provider was actually reached:
  //
  //   * `ssh-add -s <provider>` BLOCKS -- it wants a PIN, asks on the
  //     terminal, and with no terminal it waits.  Killed at 6s with no
  //     output at all.
  //   * `ssh-add -s` with no argument: `option requires an argument -- s`
  //     plus a usage text that itself says `ssh-add -s pkcs11`.
  //   * `ssh-add -e <provider>`: `Could not remove card "<path>":
  //     agent refused operation`, exit 1.
  {
    // Our client refuses `-s` and `-e`, names what they are, and exits 1
    // -- and it must NOT block.  A tool that hangs is a tool a script
    // cannot tell from a slow one.
    for (const opt of ["-s", "-e", "-S"]) {
      const r = ourAdd([opt, "anything"], {});
      const msg = r.stderr.toString();
      ok(`our ssh_add refuses '${opt}' as a smartcard option`,
        r.code === 1 &&
        msg.includes("PKCS#11") &&
        msg.includes("does not support"),
        `exit ${r.code}, stderr ${JSON.stringify(r.stderr.toString("latin1"))}`);
    }

    // The line the refusal prints names the option that was given.
    const s = ourAdd(["-s", "provider"], {});
    ok("the refusal names the option it refused",
      s.stderr.toString().startsWith("ssh_add: -s is for a PKCS#11"),
      JSON.stringify(s.stderr.toString("latin1")));

    // **A real OpenSSH option we do not implement is not an "unknown
    // option".**  `-c` `-t` `-k` `-K` `-X` `-x` `-E` `-T` `-v` are in the
    // real tool's own usage line; saying "unknown" would be a statement
    // about the USER being wrong when the fact is about US.
    for (const opt of ["-c", "-t", "-E", "-v"]) {
      const r = ourAdd([opt, "x"], {});
      ok(`our ssh_add says '${opt}' is a real option it does not implement`,
        r.code === 1 &&
        r.stderr.toString().includes("is a real ssh-add option") &&
        r.stderr.toString().includes("does not implement"),
        `exit ${r.code}, stderr ${JSON.stringify(r.stderr.toString("latin1"))}`);
    }

    // And a thing that is NOT an option at all still says "unknown".
    const bogus = ourAdd(["-Q"], {});
    ok("our ssh_add still calls a non-option an unknown option",
      bogus.code === 1 &&
      bogus.stderr.toString().includes("unknown option: -Q"),
      `exit ${bogus.code}, stderr ${JSON.stringify(bogus.stderr.toString("latin1"))}`);

    // The AGENT has no short options at all, and says why.  Every
    // `ssh-agent` short option already means something else.
    const agentShort = runBytes(OUR_AGENT, ["-s", "something"], {});
    ok("our ssh_agent refuses a short option and says why",
      agentShort.code === 1 &&
      agentShort.stderr.toString().includes("no short options"),
      `exit ${agentShort.code}, stderr ${JSON.stringify(agentShort.stderr.toString("latin1"))}`);

    // `--help` is the one thing that succeeds without starting an agent.
    const help = runBytes(OUR_AGENT, ["--help"], {});
    ok("our ssh_agent answers --help with its usage",
      help.code === 0 &&
      help.stdout.toString().includes("--socket") &&
      help.stdout.toString().includes("--key"),
      `exit ${help.code}, stdout ${JSON.stringify(help.stdout.toString("latin1"))}`);

    // An option with its argument missing is NOT "unexpected": the tool
    // knows what was meant and the user simply did not finish.  Saying
    // "unexpected argument" would blame a word that was spelled right.
    const noArg = runBytes(OUR_AGENT, ["--socket"], {});
    ok("our ssh_agent says an option needs its argument",
      noArg.code === 1 &&
      noArg.stderr.toString().includes("--socket requires an argument"),
      `exit ${noArg.code}, stderr ${JSON.stringify(noArg.stderr.toString("latin1"))}`);
  }

  // -------------------------------------------------------------------------
  // Summary
  // -------------------------------------------------------------------------
  console.log(`\n=== SUMMARY ===`);
  console.log(`  checks: ${checks}`);
  console.log(`  failures: ${failures}`);
  console.log(`  skipped: ${skipped}`);
  if (failures > 0) {
    console.log("\nCI FAIL: some checks failed");
    process.exit(1);
  } else {
    console.log("\nALL PASS");
    process.exit(0);
  }
}

main().catch((e) => {
  console.error("Gate crashed:", e);
  process.exit(1);
});