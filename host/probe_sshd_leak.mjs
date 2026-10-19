#!/usr/bin/env node
// host/probe_sshd_leak.mjs -- Loop #65: does verify_loop40 leave an sshd behind?
//
// ## What is being claimed
//
// `verify_loop40.mjs` starts an OpenSSH server through `host/sshd_setup.mjs`,
// which runs `sshd -D` in the foreground and then parks on
// `await new Promise(() => {})` (sshd_setup.mjs:210) -- it never returns on its
// own and installs no SIGTERM/SIGINT handler. `startSshd()` in verify_loop40
// (line 147) does three things that make the server unownable:
//
//     const child = spawn(..., { stdio: 'ignore', detached: false });
//     child.unref();
//     ... return true                       // the handle is dropped
//
// `unref()` takes the child off the parent's event loop so Node can exit while
// it keeps running, `stdio: 'ignore'` leaves no handle to write to, and the
// function returns a boolean -- the handle is discarded and never stored. The
// only `kill()` anywhere in verify_loop40 is `relay.kill()` (line 556), which
// is a different process.
//
// So there is no code path, on success or on failure, that stops that sshd.
// The port is SSHD_PORT = 18783 (line 52).
//
// ## Why this needs measuring rather than reading
//
// A leak that happened on every run would be obvious long ago, so something in
// the environment sometimes reaps the orphan. That is exactly the shape of bug
// that produces intermittent, order-dependent failures in a gate suite -- and
// `verify_loop49` is already observed to pass standalone and fail inside the
// suite. Reading the code establishes that there is no owner; it does not
// establish that the process survives in practice.
//
// ## Method
//
// Two processes. The inner one performs loop40's spawn+unref+discard verbatim
// and exits normally, exactly as a gate that finished (or was killed) would.
// The outer one then polls the port. If it still answers, the server outlived
// its only owner -- which is the leak, observed rather than argued.
//
// The outer probe cleans up after itself, so running it does not become the
// next leak. That cleanup is precisely what verify_loop40 lacks, which is why
// the two are separate files.
//
// Usage: node host/probe_sshd_leak.mjs
// Exit:  0 = no leak (port free after the owner exited)
//        1 = LEAK CONFIRMED (port still bound after the owner exited)

import { spawn, execSync } from 'node:child_process';
import net from 'node:net';
import { unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { keep } from './keep_output.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 18783;
const pidFile = join(tmpdir(), 'openssh_sshd_leak_probe.pid');

function portOpen(p) {
  return new Promise((r) => {
    const s = net.connect({ host: '127.0.0.1', port: p });
    s.once('connect', () => { s.destroy(); r(true); });
    s.once('error', () => r(false));
    s.setTimeout(500, () => { s.destroy(); r(false); });
  });
}

async function waitForPort(p, ms) {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (await portOpen(p)) return true;
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

function reap() {
  // This is the cleanup verify_loop40 does not have. Scoped to this probe's
  // own port so it can never take down a developer's real sshd.
  try {
    const out = execSync(
      `powershell -NoProfile -Command ` +
      `"Get-NetTCPConnection -LocalPort ${PORT} -ErrorAction SilentlyContinue | ` +
      `Select-Object -ExpandProperty OwningProcess -Unique"`,
      { encoding: 'utf8' },
    );
    for (const pid of out.split(/\s+/).filter(Boolean)) {
      try { execSync(`taskkill /PID ${pid} /T /F`, { stdio: 'ignore' }); } catch { /* gone */ }
    }
  } catch { /* nothing listening */ }
  try { unlinkSync(pidFile); } catch { /* never created */ }
}

console.log(`Loop #65 probe: does verify_loop40 leak its sshd on port ${PORT}?`);
reap();

const before = await portOpen(PORT);
console.log(`  before: port ${before ? 'IN USE (aborting)' : 'free'}`);
if (before) process.exit(2);

console.log('  running the inner starter (loop40 spawn + unref + drop, then exit)...');
const inner = spawn('cmd', ['/c', 'node', 'host/probe_sshd_starter.mjs',
                            '--port', String(PORT), '--pid-file', pidFile],
                   { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
let innerOut = '';
let innerErr = '';
inner.stdout.on('data', d => { innerOut += d.toString(); });
// This used to be `inner.stderr.on('data', () => {})` -- the stream was
// consumed and thrown away. On GitHub run 39200128854 the probe exited 3 with
// `the sshd never came up, so there is nothing to leak. Not a pass.` and no
// way to tell a missing binary from a rejected sshd_config from a taken port.
// The gate was careful to refuse to call "no sshd" a pass, and then withheld
// the one fact that would say why there was no sshd.
inner.stderr.on('data', d => { innerErr += d.toString(); });
const innerCode = await new Promise((r) => inner.on('exit', r));

console.log(`  inner exited ${innerCode}: ${innerOut.trim() || '(no output)'}`);
if (innerErr.trim()) {
  console.log(`  inner stderr: ${innerErr.trim().split(/\r?\n/).slice(-8).join(' | ')}`);
}
if (innerCode !== 0) {
  // Kept BEFORE the exit: this process is about to end, and an exit(3) with
  // the reason on disk and none on screen teaches the next reader nothing.
  keep('probe-sshd-leak-inner',
       `exit ${innerCode}\n--- stdout ---\n${innerOut}\n--- stderr ---\n${innerErr}`,
       200);
  console.log('  the sshd never came up, so there is nothing to leak. Not a pass.');
  console.log("  (the starter's own output is in .loop70/probe-sshd-leak-inner.log)");
  reap();
  process.exit(3);
}

// The owner is gone. Anything still listening now is an orphan.
//
// The wait used to be a flat `setTimeout(1500)` -- a guess at how long the OS
// needs to let a child go. Loop #68 measured that guess being wrong: a full CI
// run put verify_loop65 red with "self-cleanup by this probe: FAILED, port still
// bound", while the same gate passed standalone minutes later with no sshd
// process left behind. A fixed sleep is a race that only reports itself when
// the machine happens to be loaded, and a check that fails under load and
// passes when idle is indistinguishable from a flaky check.
//
// So the question becomes the one that actually matters: has the port been
// free CONTINUOUSLY for a settling window, rather than "was it free at one
// instant after N milliseconds"? `waitForPort` returns on the first successful
// bind; `settle` below requires every attempt to succeed.
const SETTLE_MS = 3000;
const POLL_MS = 150;
const deadline = Date.now() + SETTLE_MS;
let stable = 0;
let leaked = false;
while (Date.now() < deadline) {
  if (await waitForPort(PORT, 500)) {
    stable = 0;
    leaked = true;
  } else {
    stable += POLL_MS;
    if (stable >= SETTLE_MS) break;
  }
  await new Promise((r) => setTimeout(r, POLL_MS));
}
const after = leaked;

console.log('');
if (after) {
  console.log('  LEAK CONFIRMED: the port still answers after the owner exited.');
  console.log('  verify_loop40 has no code path that stops this sshd:');
  console.log('    - startSshd() unrefs the child and drops the handle');
  console.log('    - sshd_setup.mjs:210 parks on `new Promise(() => {})`');
  console.log('    - the only kill() in verify_loop40 is relay.kill() (line 556)');
  const wasUp = await waitForPort(PORT, 1000);
  if (wasUp) reap();
  const released = (await waitForPort(PORT, 5000)) === false;
  console.log(`  self-cleanup by this probe: ${released ? 'ok, port released' : 'FAILED, port still bound'}`);
  process.exit(1);
}

console.log('  no leak observed: the port was released when the owner exited.');
console.log('  This does NOT clear verify_loop40 -- there is still no code that');
console.log('  stops the server, so anything that kills the gate mid-run leaks it.');
reap();
process.exit(0);
