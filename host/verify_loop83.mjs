#!/usr/bin/env node
// host/verify_loop83.mjs -- Loop #83: src/tcp resolves host names.
//
// ## What is being claimed
//
// `ssh user@example.com` and `ssh-keyscan example.com` are the way anybody
// actually uses an SSH client, and this repository could do neither: the
// transport only understood an IPv4 literal (`inet_pton(AF_INET)`), so a
// name was never turned into an address and the connection never left the
// machine.
//
// The claim is not just "a name now resolves". It is the whole set of
// behaviours a name brings with it, each of which is asserted here:
//
// 1. **A name reaches the server.**  The same scan by name and by number
//    must produce the same three keys -- only the hosts field differs --
//    and the server's own log must show the extra connections arriving.
//
// 2. **Every address is tried, in order.**  A name usually maps to more than
//    one address, and the first one may not answer.  OpenSSH's
//    `ssh_connect_direct` says it outright: "try each one in sequence until
//    the connection succeeds".  So the tool has to say which address it
//    reached and what happened to the ones before it.
//
// 3. **The same addresses as OpenSSH's own client.**  Not "an address that
//    works" -- the *same* address, in the same order.  The oracle is
//    OpenSSH's own `ssh -vv`, whose debug output names every address it
//    tries.  This is the check that would catch a resolver that reordered
//    the list or picked a different one.
//
// 4. **The failures are told apart.**  A name that does not resolve, a
//    connection that is refused, and a connection that ran out of time are
//    three different problems, and the tool has to say which one happened.
//    The same refused port produces two different labels depending on
//    whether the deadline was long enough to see the refusal -- which is
//    what makes the deadline itself testable.
//
// 5. **The numeric path did not move.**  Everything that used to work by
//    number still works by number.
//
// ## A note on the refusal, and why the deadline has to be measured
//
// On this machine a refused TCP connection is not visible straight away.
// Measured (see .loop83/measure_socket.py and AGENTS.md): the non-blocking
// connect reports "in progress" at once, and for the next ~2.2 seconds
// `select()` reports the socket in neither the write nor the except set,
// with SO_ERROR still zero.  Then the socket shows up in the *except* set
// with SO_ERROR = 10061 (connection refused).  A blocking connect to the
// same port takes about 2.0 seconds and returns the same code.
//
// Two consequences, and both of them are in the implementation rather than
// in this file:
//
//   * Windows puts a refused connect in the **except** set, not in the write
//     set.  Waiting only for writability would wait out the whole deadline
//     on every refused connection and never learn that it had already
//     failed.
//
//   * A deadline shorter than that refusal latency cannot see the refusal,
//     so it has to report a timeout instead.  Which is why this gate
//     *measures* the refusal latency before it asks for a timeout: on a
//     machine where the refusal shows up in ten milliseconds, the two
//     outcomes are the same thing and the check is skipped loudly rather
//     than failed on a distinction that does not exist there.
//
// ## A note on what is this machine's and what is the code's
//
// "localhost" is not a fixed fact.  On this machine it resolves to ::1 first
// and 127.0.0.1 second, but that comes from the Windows DNS client -- the
// hosts file here has its localhost lines commented out ("localhost name
// resolution is handled within DNS itself").  A machine whose resolver
// handed back only 127.0.0.1 would be just as correct.
//
// So OpenSSH's own client runs first, and its answer decides which of the
// claims below are about this machine and which are about the code.  The
// portable claim -- the same addresses, in the same order -- is asserted
// unconditionally; the claims about the particular pair are asserted only
// when the oracle shows that pair, and are skipped loudly otherwise.
//
// ## What runs where
//
// G0 needs only node and the MoonBit toolchain.  The rest needs an OpenSSH
// **server** and an OpenSSH **client**.  When either is missing those
// sections are **skipped loudly** rather than quietly passed: a machine
// that cannot run a check has not run it.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const WORK = path.join(ROOT, ".loop83");

const SKIP_REGRESSION = process.argv.includes("--skip-regression");

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

function norm(s) {
  return `${s}`.replace(/\r\n/g, "\n");
}

// ---------------------------------------------------------------------------
// Where the real OpenSSH binaries might be.
// ---------------------------------------------------------------------------
//
// The same list host/sshd_setup.mjs probes, because the two OpenSSH
// installations on a Windows machine are the same installation: one portable
// build under Program Files, one inbox feature under System32.  Neither is
// on PATH by default.
//
// None of these is asserted to exist; each is probed in order until one
// does.  verify_loop71.mjs flags any drive-letter path it finds in code;
// the marker below is how a file declares that its paths are a probe rather
// than a claim, and it is an obligation to say why, not a mute button.
//
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
const OPENSSH_DIRS = [
  "C:\\Program Files\\OpenSSH-Win64",
  "C:\\Windows\\System32\\OpenSSH",
  "C:\\Program Files\\OpenSSH",
];

function openSshBinary(name) {
  for (const d of OPENSSH_DIRS) {
    const p = path.join(d, name + ".exe");
    if (existsSync(p)) return p;
  }
  return null;
}

// The keyscan's, when there is one.  The list is the same one
// host/sshd_setup.mjs probes, and the same one Loop #82's gate used.
function keyscanBinaries() {
  const out = [];
  for (const d of OPENSSH_DIRS) {
    const p = path.join(d, "ssh-keyscan.exe");
    if (existsSync(p)) out.push(p);
  }
  return out;
}

// The same set of known_hosts lines, byte for byte, order apart.
function sameLines(a, b) {
  const la = keyLines(a).slice().sort();
  const lb = keyLines(b).slice().sort();
  return la.length === lb.length && la.every((l, i) => l === lb[i]);
}

function startSshd(port, name) {
  const child = spawn("node", ["host/sshd_setup.mjs", "--port", String(port), "--name", name], {
    cwd: ROOT, stdio: ["ignore", "pipe", "pipe"],
  });
  child.tapBuf = "";
  for (const stream of [child.stdout, child.stderr]) {
    if (stream) stream.on("data", (d) => { child.tapBuf += d.toString(); });
  }
  return child;
}

function stopSshd(name) {
  spawnSync("node", ["host/sshd_setup.mjs", "--stop", "--name", name], { cwd: ROOT, encoding: "utf8" });
}

function sshdLog(name) {
  return path.join(ROOT, ".loop31", "sshd", `sshd.log_${name}`);
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

const KEYSCAN_EXE = path.join(ROOT, "_build", "native", "debug", "build", "cmd", "ssh_keyscan", "ssh_keyscan.exe");

// A timeout is not politeness.  A scan that hangs on a server that never
// answers would hang the gate, and a gate that hangs measures nothing.
const SCAN_TIMEOUT_MS = 120000;

function runKeyscan(args) {
  const t0 = Date.now();
  const r = spawnSync(KEYSCAN_EXE, args, {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: SCAN_TIMEOUT_MS,
  });
  const ms = Date.now() - t0;
  if (r.error) return { out: "", err: String(r.error.message), code: null, ms };
  return { out: norm(r.stdout || ""), err: norm(r.stderr || ""), code: r.status, ms };
}

function runRealSsh(bin, args) {
  const t0 = Date.now();
  const r = spawnSync(bin, args, {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: SCAN_TIMEOUT_MS,
  });
  const ms = Date.now() - t0;
  const text = norm(`${r.stdout || ""}${r.stderr || ""}`);
  return { text, out: norm(r.stdout || ""), err: norm(r.stderr || ""), code: r.status, ms, error: r.error && r.error.message };
}

function runRealKeyscan(bin, args) {
  const t0 = Date.now();
  const r = spawnSync(bin, args, {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: SCAN_TIMEOUT_MS,
  });
  const ms = Date.now() - t0;
  if (r.error) return { out: "", err: String(r.error.message), code: null, ms };
  return { out: norm(r.stdout || ""), err: norm(r.stderr || ""), code: r.status, ms };
}

// ---------------------------------------------------------------------------
// Reading our own tool's -v output.
// ---------------------------------------------------------------------------
//
// `-v` prints one block per connection attempt:
//     resolve: <host> -> <addr> <addr> ...
//     tried: <addr> <state>
//
// The states are the ones src/tcp defines: connected, failed, timed_out,
// not_tried.

// The -v output has one block per connection attempt, and a scan makes one
// connection per key type -- so the whole output holds three blocks.  Only
// the first one is about "this connection"; the other two say the same
// thing again.
function firstBlock(text) {
  const lines = norm(text).split("\n");
  const out = [];
  let seen = false;
  for (const line of lines) {
    if (line.startsWith("resolve: ")) {
      if (seen) break;
      seen = true;
    }
    if (seen) out.push(line);
  }
  return out.join("\n");
}

function parseResolve(text) {
  const m = norm(text).match(/^resolve: (.*) -> (.*)$/m);
  if (!m) return null;
  const addrs = m[2].trim();
  if (addrs === "(unresolved)") return [];
  return addrs.split(/\s+/).filter(Boolean);
}

function parseTried(text) {
  const out = [];
  for (const line of norm(text).split("\n")) {
    const m = line.match(/^tried: (\S+) (\S+)$/);
    if (m) out.push({ addr: m[1], state: m[2] });
  }
  return out;
}

function keyLines(text) {
  return norm(text).split("\n").filter((l) => l.trim() && !l.startsWith("#"));
}

// The key material of a known_hosts line: the third field.
function keyBlobs(text) {
  return keyLines(text).map((l) => (l.split(" ")[2] || ""));
}

// ---------------------------------------------------------------------------
// How long does a refusal take to become visible?
// ---------------------------------------------------------------------------
//
// This is the measurement the timeout check calibrates itself against, and
// it has to be taken with the **same kind of socket** the implementation
// uses.  On this machine the two are two thousand times apart:
//
//     a plain Winsock socket       the refusal shows up after ~2.0 s
//     node's socket (libuv)        the refusal shows up after ~0.001 s
//
// Both are real, and they are not measuring the same thing: node creates
// its sockets with WSA_FLAG_OVERLAPPED, and an overlapped socket is told
// about the failed connect through its completion path, which is prompt.
// `src/tcp/winsock.c` uses a plain socket, and a plain socket does not see
// the error until the connect attempt has expired.
//
// So the calibration runs host/refusal_latency.py, which measures it the
// way the implementation measures it.  Calibrating with node would report
// "a refusal shows up in a millisecond", and the check that tells a
// timeout apart from a refusal would be skipped on a machine where the
// distinction plainly exists.
//
// Returns the milliseconds, or -1 if the connection succeeded (there was no
// refusal to measure) and -2 if the error never arrived.
function refusalLatencyMs(port) {
  const r = spawnSync("python", ["host/refusal_latency.py", String(port)], {
    cwd: ROOT, encoding: "utf8", errors: "replace", timeout: 60000,
  });
  if (r.status !== 0) return -2;
  const v = parseInt(norm(r.stdout || "").trim(), 10);
  return Number.isFinite(v) ? v : -2;
}

async function main() {
  console.log("verify_loop83 -- src/tcp: host names resolve\n");

  // ------------------------------------------------------------------- G0 --
  section("G0: the code builds");
  const b = moon(["build", "cmd/ssh_keyscan", "--target", "native"]);
  ok("cmd/ssh_keyscan builds for native", b.code === 0, b.code === 0 ? "" : b.out.slice(-400));
  // The js and wasm backends answer for the browser targets, so the whole
  // tree has to type-check there too -- the resolution code is shared.
  const c = moon(["check"]);
  ok("the whole tree type-checks", c.code === 0, c.code === 0 ? "" : c.out.slice(-400));

  // ------------------------------------------------------------------- G1 --
  section("G1: a name reaches the server, and the keys are the same");
  const sshExe = openSshBinary("ssh");
  if (!sshExe) {
    skip("everything that needs a server", "no ssh.exe in " + OPENSSH_DIRS.join(", "));
    skip("the same addresses as OpenSSH's own client", "no ssh.exe");
    console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: ${checks - failures}/${checks} checks passed` +
      (skipped ? ` (${skipped} skipped)` : ""));
    if (failures) process.exit(1);
    process.exit(0);
  }

  const sshdPort = await freePort();
  const name = "loop83";
  rmSync(sshdLog(name), { force: true });
  const sshd = startSshd(sshdPort, name);
  try {
    if (!await waitForText(sshd, "sshd listening", 30000)) {
      const why = (sshd.tapBuf || "").trim().split("\n").slice(0, 4).join(" | ") || "the server never came up";
      ok("the private sshd is up", false, why);
    } else {
      ok("the private sshd is up", true);

      // OpenSSH's own client runs FIRST, because it is the oracle for the
      // one thing the rest of this section cannot know on its own: what this
      // machine's resolver makes of the name.
      //
      // "localhost" is not a fixed fact. On this machine it resolves to
      // ::1 first and 127.0.0.1 second -- but that comes from the Windows
      // DNS client, not from the hosts file (the hosts file here has its
      // localhost lines commented out: "localhost name resolution is handled
      // within DNS itself"). A machine whose resolver hands back only
      // 127.0.0.1 would be just as correct, and a gate that insisted on
      // ::1 would be red on it for saying something true.
      //
      // So the client's own answer decides which of the specific claims
      // below are about this machine and which are about the code.
      const real = runRealSsh(sshExe, [
        "-vv", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=NUL", "-p", String(sshdPort), "localhost", "exit",
      ]);
      const realAddrs = [...real.text.matchAll(/Connecting to \S+ \[([^\]]+)\]/g)].map((m) => m[1]);
      const twoAddresses = realAddrs.length >= 2 &&
        realAddrs.includes("::1") && realAddrs.includes("127.0.0.1");

      // The scan by number first, so that the server's log has a baseline
      // to subtract.  The log also contains the probe connection that
      // sshd_setup.mjs makes while it waits for the port to come up, so
      // counting the difference is the only honest way to count ours.
      const numeric = runKeyscan(["-p", String(sshdPort), "127.0.0.1"]);
      const logA = existsSync(sshdLog(name)) ? readFileSync(sshdLog(name), "utf8") : "";

      const byName = runKeyscan(["-p", String(sshdPort), "-v", "localhost"]);
      const logB = existsSync(sshdLog(name)) ? readFileSync(sshdLog(name), "utf8") : "";

      ok("the scan by number printed three keys", keyLines(numeric.out).length === 3,
        `${keyLines(numeric.out).length} keys`);
      ok("the scan by name printed three keys", keyLines(byName.out).length === 3,
        `${keyLines(byName.out).length} keys`);

      // The keys themselves must be the same keys: a name is a way of
      // naming an address, not a way of reaching a different server.
      const numBlobs = keyBlobs(numeric.out);
      const nameBlobs = keyBlobs(byName.out);
      ok("the same three keys by name and by number",
        numBlobs.length === 3 && nameBlobs.length === 3 &&
        numBlobs.slice().sort().join("\n") === nameBlobs.slice().sort().join("\n"),
        `${numBlobs.length} vs ${nameBlobs.length}`);

      // The hosts field is the only thing that may differ.
      ok("the hosts field carries the name and the port",
        keyLines(byName.out).every((l) => l.startsWith(`[localhost]:${sshdPort} `)),
        keyLines(byName.out)[0] ? keyLines(byName.out)[0].slice(0, 40) : "no line");

      // Loop #82 could not observe the lower-casing end to end, because the
      // only host this client could reach was a numeric literal -- and a
      // numeric literal has no letters to fold.  A name has letters.
      const upper = runKeyscan(["-p", String(sshdPort), "-t", "ed25519", "LOCALHOST"]);
      ok("a name in upper case is lower-cased in the hosts field",
        keyLines(upper.out).length === 1 &&
        keyLines(upper.out)[0].startsWith(`[localhost]:${sshdPort} `),
        keyLines(upper.out)[0] ? keyLines(upper.out)[0].slice(0, 40) : "no line");
      ok("the name in the note keeps the case it was typed in",
        /^# LOCALHOST:/m.test(norm(upper.err)),
        (norm(upper.err).match(/^# .*$/m) || ["no note"])[0]);

      // The server's own log: three more connections, all of them from
      // 127.0.0.1 -- which is the address we actually reached.
      const conns = (t) => (t.match(/Connection from/g) || []).length;
      const connsLocal = (t) => (t.match(/Connection from 127\.0\.0\.1/g) || []).length;
      ok("the server logged three more connections for the scan by name",
        conns(logB) - conns(logA) === 3, `${conns(logA)} -> ${conns(logB)}`);
      ok("every one of them came from 127.0.0.1",
        connsLocal(logB) - connsLocal(logA) === 3,
        `${connsLocal(logA)} -> ${connsLocal(logB)}`);

      // ------------------------------------------------------- G1: the order --
      section("G1b: every address is tried, in order");
      const resolved = parseResolve(firstBlock(byName.err));
      const tried = parseTried(firstBlock(byName.err));
      ok("the name resolved to at least one address", resolved && resolved.length >= 1,
        resolved ? resolved.join(",") : "no resolve line");
      ok("every resolved address was tried",
        resolved && tried.length === resolved.length,
        `${tried.length} tried, ${resolved ? resolved.length : 0} resolved`);
      ok("exactly one of them was reached",
        tried.filter((t) => t.state === "connected").length === 1,
        JSON.stringify(tried));
      ok("the address that was reached is the one the tool reports",
        tried.some((t) => t.state === "connected" && t.addr === /^connected: (\S+)$/m.exec(norm(byName.err))?.[1]),
        (norm(byName.err).match(/^connected: .*$/m) || ["nothing"])[0]);

      // The two specific addresses are this machine's, not the code's.  When
      // the resolver here hands back one address only -- or a different
      // pair -- these claims are about something this gate cannot assert, so
      // they are skipped loudly rather than failed.
      if (twoAddresses) {
        ok("the name resolved to two addresses", resolved && resolved.length === 2,
          resolved ? resolved.join(",") : "?");
        ok("the first address is the IPv6 one", resolved && resolved[0] === "::1",
          resolved ? resolved[0] : "?");
        ok("the second address is the IPv4 one", resolved && resolved[1] === "127.0.0.1",
          resolved ? resolved[1] : "?");
        ok("the first address was tried and refused",
          tried.length >= 2 && tried[0].addr === "::1" && tried[0].state === "failed",
          tried[0] ? `${tried[0].addr} ${tried[0].state}` : "nothing was tried");
        ok("the second address was tried and connected",
          tried.length >= 2 && tried[1].addr === "127.0.0.1" && tried[1].state === "connected",
          tried[1] ? `${tried[1].addr} ${tried[1].state}` : "nothing was tried");
        ok("the tool says which address it reached",
          /^connected: 127\.0\.0\.1$/m.test(norm(byName.err)),
          (norm(byName.err).match(/^connected: .*$/m) || ["nothing"])[0]);
      } else {
        for (const what of [
          "the name resolved to two addresses",
          "the first address is the IPv6 one",
          "the second address is the IPv4 one",
          "the first address was tried and refused",
          "the second address was tried and connected",
          "the tool says which address it reached",
        ]) {
          skip(what, "this machine resolves the name to " + (realAddrs.join(",") || "nothing"));
        }
      }

      // ------------------------------------------------------------- G2 --
      section("G2: the failures are told apart");
      const closedPort = await freePort();
      const unresolvable = runKeyscan(["-p", String(sshdPort), "-t", "ed25519", "no-such-host.invalid"]);
      ok("a name that does not resolve says RESOLVE_FAILED",
        /result: RESOLVE_FAILED/.test(unresolvable.err), unresolvable.err.trim().split("\n").slice(-2).join(" | "));
      ok("a name that does not resolve is not reported as a connect failure",
        !/CONNECT_FAILED/.test(unresolvable.err));
      ok("a name that does not resolve fails fast", unresolvable.ms < 3000,
        `${unresolvable.ms} ms`);

      const refused = runKeyscan(["-p", String(closedPort), "-t", "ed25519", "-v", "localhost"]);
      ok("a refused connection says CONNECT_FAILED",
        /result: CONNECT_FAILED/.test(refused.err), refused.err.trim().split("\n").slice(-3).join(" | "));
      ok("a refused connection is not reported as a resolve failure",
        !/RESOLVE_FAILED/.test(refused.err));
      ok("the refusal carries the system's own code (10061 = connection refused)",
        /error: 10061/.test(refused.err), (refused.err.match(/error: \d+/) || ["no code"])[0]);
      ok("every address was tried and none of them was reached",
        parseTried(refused.err).length >= 1 &&
        parseTried(refused.err).every((t) => t.state === "failed"),
        JSON.stringify(parseTried(refused.err)));

      // The deadline.
      //
      // A refusal on this machine only becomes visible after about two
      // seconds, so a deadline shorter than that cannot see it and has to
      // report a timeout.  That is only a meaningful distinction if the
      // refusal really is that slow here, so it is measured first -- and if
      // the machine is too fast for the distinction to exist, the check says
      // so instead of failing.
      const latency = await refusalLatencyMs(closedPort);
      ok("the refusal latency could be measured", latency > 0, `${latency} ms`);
      if (latency > 1200) {
        // The budget is per ADDRESS, not per name.  OpenSSH resets the
        // timeout before every address it tries (ssh_connect_direct), and
        // so does this implementation, so a name that resolves to three
        // addresses gets three one-second budgets and not one.  A bound
        // written for a single address would therefore fail on a name that
        // resolves to more -- and the number of addresses is not the same
        // on every machine, so it is read out of the run rather than
        // assumed.
        //
        // The multiplier is two because the deadline is checked between
        // waits, and a wait can come back late on a loaded machine; the
        // extra second is for starting the process and resolving the name.
        // This bound is deliberately loose: the two checks around it are
        // the ones with teeth.  The label says the deadline was honoured,
        // and the comparison says it was honoured EARLIER than waiting out
        // the refusal would have been -- and that comparison is what
        // catches a deadline that is only accounted for rather than
        // measured against the clock.
        const nTried = Math.max(1, parseTried(refused.err).length);
        const deadlineBudgetMs = 1000 * nTried * 2 + 1000;
        const timedOut = runKeyscan(["-p", String(closedPort), "-t", "ed25519", "-T", "1", "-v", "localhost"]);
        ok("a deadline shorter than the refusal says CONNECT_TIMEOUT",
          /result: CONNECT_TIMEOUT/.test(timedOut.err),
          timedOut.err.trim().split("\n").slice(-3).join(" | "));
        ok("the deadline was honoured -- it finished before the refusal arrived",
          timedOut.ms < refused.ms, `${timedOut.ms} ms vs ${refused.ms} ms`);
        ok("the deadline was honoured -- it did not wait for either refusal",
          timedOut.ms <= deadlineBudgetMs, `${timedOut.ms} ms, budget ${deadlineBudgetMs} ms`);
      } else {
        skip("a deadline shorter than the refusal says CONNECT_TIMEOUT",
          `the refusal shows up in ${latency} ms here, so a timeout and a refusal are the same thing`);
        skip("the deadline was honoured -- it finished before the refusal arrived",
          `the refusal shows up in ${latency} ms here`);
        skip("the deadline was honoured -- it did not wait for either refusal",
          `the refusal shows up in ${latency} ms here`);
      }

      const badTimeout = runKeyscan(["-p", String(sshdPort), "-T", "0", "localhost"]);
      ok("a timeout of zero is a usage error, as it is in OpenSSH",
        /result: BAD_USAGE/.test(badTimeout.err), badTimeout.err.trim().split("\n")[0]);

      // ------------------------------------------------------------- G3 --
      section("G3: the same addresses as OpenSSH's own client");
      ok("OpenSSH's own client named the addresses it tried", realAddrs.length > 0,
        realAddrs.join(",") || (real.text.trim().split("\n").slice(-3).join(" | ")));
      ok("OpenSSH's own client reached the server",
        /Connection established/.test(real.text),
        "the client never got a connection");
      ok("we resolve to the same addresses, in the same order",
        resolved && realAddrs.length > 0 &&
        resolved.join(",") === realAddrs.join(","),
        `ours=${resolved ? resolved.join(",") : "?"} theirs=${realAddrs.join(",")}`);
      if (twoAddresses) {
        ok("OpenSSH's own client tried the IPv6 address first",
          realAddrs[0] === "::1", realAddrs.join(","));
        ok("OpenSSH's own client fell back to the IPv4 address",
          realAddrs.includes("127.0.0.1"), realAddrs.join(","));
      } else {
        skip("OpenSSH's own client tried the IPv6 address first",
          "this machine resolves the name to " + (realAddrs.join(",") || "nothing"));
        skip("OpenSSH's own client fell back to the IPv4 address",
          "this machine resolves the name to " + (realAddrs.join(",") || "nothing"));
      }

      // ------------------------------------------------------------- G3b --
      //
      // OpenSSH's own ssh-keyscan, on the same name.
      //
      // It has a different connect path from OpenSSH's own client:
      // `ssh-keyscan.c:tcpconnect` breaks out of the address loop as soon as
      // a connect() returns EINPROGRESS, so a refusal that arrives after the
      // socket was handed to its select() loop is never retried on the next
      // address.  On a name whose first address refuses, the real tool
      // therefore never reaches the server at all.
      //
      // So the claim is not "the two tools agree" -- it is "when the real
      // tool does produce keys, they are our keys".  And when it does not,
      // its own message has to say why, because a tool that fails silently
      // is a tool whose failure nobody can act on.
      section("G3b: the real ssh-keyscan, on the same name");
      const scanners = keyscanBinaries();
      if (!scanners.length) {
        skip("the comparison against OpenSSH's own ssh-keyscan",
          "no ssh-keyscan.exe in " + OPENSSH_DIRS.join(", "));
      }
      for (const bin of scanners) {
        const who = path.basename(path.dirname(bin));
        const ref = runRealKeyscan(bin, ["-p", String(sshdPort), "localhost"]);
        const refLines = keyLines(ref.out);
        if (refLines.length === 0) {
          ok(`${who}'s ssh-keyscan could not reach the name either, and says why`,
            /(refused|timed out)/i.test(ref.err),
            (norm(ref.err).trim().split("\n").filter(Boolean).pop()) || "no message");
        } else {
          ok(`${who}'s ssh-keyscan got the same keys by name`,
            sameLines(ref.out, byName.out) && refLines.length === 3,
            `${refLines.length} line(s) against our ${keyLines(byName.out).length}`);
        }
      }

      // ------------------------------------------------------------- G4 --
      section("G4: the numeric path did not move");
      ok("the numeric scan still prints the hosts field with the port",
        keyLines(numeric.out).every((l) => l.startsWith(`[127.0.0.1]:${sshdPort} `)),
        keyLines(numeric.out)[0] ? keyLines(numeric.out)[0].slice(0, 40) : "no line");
      const numericV = runKeyscan(["-p", String(sshdPort), "-t", "ed25519", "-v", "127.0.0.1"]);
      const numericResolved = parseResolve(numericV.err);
      ok("a number resolves to itself", numericResolved && numericResolved.length === 1 &&
        numericResolved[0] === "127.0.0.1", numericResolved ? numericResolved.join(",") : "?");
      ok("a number is reached on the first try",
        parseTried(numericV.err).length === 1 &&
        parseTried(numericV.err)[0].state === "connected",
        JSON.stringify(parseTried(numericV.err)));
      ok("a number is reported as the address it reached",
        /^connected: 127\.0\.0\.1$/m.test(norm(numericV.err)),
        (norm(numericV.err).match(/^connected: .*$/m) || ["nothing"])[0]);
      ok("a number is not slowed down by the deadline machinery",
        numericV.ms < 3000, `${numericV.ms} ms`);
    }
  } finally {
    sshd.kill();
    stopSshd(name);
  }

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    section("regression: the earlier loops must not move");
    for (const label of ["loop78", "loop79", "loop80", "loop81", "loop82"]) {
      const r = spawnSync("node", [`host/verify_${label}.mjs`], { cwd: ROOT, encoding: "utf8", errors: "replace" });
      const t = norm(`${r.stdout || ""}${r.stderr || ""}`);
      const m = t.match(/(\d+)\/(\d+) checks/);
      ok(`${label} harness still green`, r.status === 0 && t.includes("PASS"),
        m ? `${m[1]}/${m[2]}` : t.slice(-200));
    }
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: ${checks - failures}/${checks} checks passed` +
    (skipped ? ` (${skipped} skipped)` : ""));
  if (failures) {
    console.log("  a red run means one of the claims above did not hold");
    process.exit(1);
  }
  console.log("  a name reaches the server, every address is tried in order, the");
  console.log("  addresses are the ones OpenSSH's own client picks, and the three");
  console.log("  ways a connect can fail are three different names.");
  process.exit(0);
}

main().catch((e) => {
  console.error("harness error:", e);
  process.exit(2);
});
