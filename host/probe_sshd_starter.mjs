// host/probe_sshd_starter.mjs -- the inner half of the sshd-leak experiment.
//
// This deliberately reproduces verify_loop40's startSshd() exactly:
//
//     const child = spawn('cmd', ['/c','node','host/sshd_setup.mjs','--port',p],
//                         { cwd: ROOT, stdio: 'ignore', detached: false });
//     child.unref();
//     ... poll until the port answers, then `return true`
//
// The handle is dropped and never kept, because that is what loop40 does. This
// process then exits normally. If the sshd is still listening afterwards, it
// has no owner left: nothing in the gate can ever stop it.
//
// The probe records the sshd's PID to a file purely so the OUTER probe can
// clean up after itself. The gate under test has no such file; giving it one
// here would change the thing being measured.

import { spawn } from 'node:child_process';
import net from 'node:net';
import { writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.argv[process.argv.indexOf('--port') + 1]);
const pidFile = process.argv[process.argv.indexOf('--pid-file') + 1];

function portOpen(p) {
  return new Promise((r) => {
    const s = net.connect({ host: '127.0.0.1', port: p });
    s.once('connect', () => { s.destroy(); r(true); });
    s.once('error', () => r(false));
    s.setTimeout(500, () => { s.destroy(); r(false); });
  });
}

// Loop #72: `stdio: 'ignore'` was copied from verify_loop40 to be faithful to
// what is being reproduced, and it faithfully reproduced one more thing nobody
// wanted: sshd_setup.mjs's own output went nowhere.
//
// Measured on GitHub run 39218394411, the outer probe's kept transcript was
// 65 bytes in total:
//
//     exit 1
//     --- stdout ---
//     STARTER: port never opened
//     --- stderr ---
//
// Empty. The gate under test had spent three runs refusing to call "sshd never
// came up" a pass, and the one sentence that would have said WHY -- Loop #69's
// "no sshd.exe in any of: <three paths>" -- was being thrown away one layer
// further down.
//
// Capturing the child's streams does not change what is measured. The leak
// depends on `detached: false` and `child.unref()` -- the owner exits and the
// sshd does not -- and on neither of those does the sshd care what happens to
// its parent's pipes. `stdio` decides who READS the output, not whether the
// process survives. So this is not a deviation from the reproduction; it is the
// reproduction, with the explanation attached.
const child = spawn(
  'cmd',
  ['/c', 'node', 'host/sshd_setup.mjs', '--port', String(port)],
  { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], detached: false },
);
// Forwarded, not buffered: sshd_setup may print a lot before it exits, and a
// pipe nobody reads fills and blocks the child -- which would turn "sshd said
// something" into "sshd hung", a second and much worse lie.
child.stdout.on('data', (d) => process.stdout.write(d));
child.stderr.on('data', (d) => process.stderr.write(d));
child.on('error', (e) => process.stderr.write(`starter: spawn failed: ${e.message}\n`));
child.unref();                      // <- as in verify_loop40
// Deliberately NOT killing or awaiting `child`. Same as the gate.

const deadline = Date.now() + 30000;
let up = false;
while (Date.now() < deadline) {
  if (await portOpen(port)) { up = true; break; }
  await new Promise((r) => setTimeout(r, 250));
}

if (pidFile) {
  // Best effort: the sshd's own pid is what the outer probe needs to clean up.
  writeFileSync(pidFile, String(child.pid ?? ''), 'utf8');
}

console.log(up ? 'STARTER: port open' : 'STARTER: port never opened');
process.exit(up ? 0 : 1);
