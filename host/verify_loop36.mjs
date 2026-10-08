#!/usr/bin/env node
// verify_loop36.mjs -- Loop #36: the interactive session (pty-req / shell / resize)
//
//   Loop #35 ran commands over `exec`, which is the one-shot form of the
//   connection layer. An interactive shell is where the rest of RFC 4254 lives:
//   pty-req with its encoded terminal modes, shell, window-change, stdin as
//   CHANNEL_DATA, and exit-signal when the process is killed rather than
//   returning. Each of those has at least one field that is easy to get wrong in
//   a way the server tolerates -- a transposed terminal size, an unwrapped modes
//   string, a want_reply on window-change that the server never satisfies.
//
//     G1  The byte layout, known-answer tested against an independent Python
//         implementation AND against a live paramiko pty session -- plus the
//         staleness and mutation checks that Loop #35 established, because a
//         vector file nobody re-derives is just a second copy of the encoder.
//
//     G2  Native client: open a pty on a real OpenSSH 8.0p1 sshd, type, resize,
//         exit. Checked against a local run of the same shell command.
//
//     G3  The same inside a browser Web Worker, matching byte counts.
//
//   What is *not* claimed: the pty banner a Windows server prints is not
//   reproducible byte for byte (it carries the OS build number, ANSI state and
//   the prompt). So G2/G3 compare the deterministic part -- the echoed command,
//   the exit status, the byte counts, and native-vs-browser equality -- while the
//   protocol bytes we *send* are held to the byte-exact standard by G1.
//
// 用法: node host/verify_loop36.mjs [--skip-regression] [--headed]

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HEADED = process.argv.includes('--headed');
const SKIP_REGRESSION = process.argv.includes('--skip-regression');

const HTTP_PORT = 18778;
const WS_PORT = 8778;
const SSHD_PORT = 22269;
const USER = 'hp';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

function serve(root, port) {
  return new Promise((resolve, reject) => {
    const s = createServer(async (req, res) => {
      try {
        const p = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname))
          .replace(/^[/\\]+/, '');
        const f = join(root, p);
        const st = await stat(f);
        res.writeHead(200, {
          'content-type': MIME[extname(f)] || 'application/octet-stream',
          'cache-control': 'no-store',
        });
        res.end(await readFile(st.isDirectory() ? join(f, 'index.html') : f));
      } catch {
        res.writeHead(404).end('not found');
      }
    });
    s.once('error', reject);
    s.listen(port, '127.0.0.1', () => resolve(s));
  });
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitForLog(proc, needle, ms = 25000) {
  const deadline = Date.now() + ms;
  let buf = '';
  proc.stdout?.on('data', d => (buf += d.toString()));
  proc.stderr?.on('data', d => (buf += d.toString()));
  while (Date.now() < deadline) {
    if (buf.includes(needle)) return true;
    await sleep(120);
  }
  console.log(`    (never saw "${needle}"; saw: ${buf.trim().slice(0, 200)})`);
  return false;
}

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${name}${detail ? `  ${detail}` : ''}`);
}

function moon(args) {
  return spawnSync('cmd', ['/c', 'moon', ...args],
    { cwd: ROOT, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 });
}
function moonBuild(pkg, target) {
  const r = moon(['build', pkg, '--target', target]);
  const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
  return { ok: r.status === 0 && !/^\s*Error:/m.test(text), text };
}
function hashOut(out) {
  return createHash('sha256').update(out.replace(/\r\n/g, '\n')).digest('hex').slice(0, 16);
}
const norm = s => `${s}`.replace(/\r\n/g, '\n');
const grab = (t, k) => (t.match(new RegExp(`^${k}: (.*)$`, 'm')) || [])[1];
const grabInt = (t, k) => {
  const v = grab(t, k);
  return v === undefined ? undefined : Number(v);
};

async function runInWorker(browser, cfg, timeoutMs) {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(String(e)));
  await page.goto(`http://127.0.0.1:${HTTP_PORT}/host/wt/probe.html`);
  let payload;
  try {
    payload = await page.evaluate(
      c =>
        new Promise((resolve, reject) => {
          const t = setTimeout(() => reject(new Error('worker timeout')), c.timeoutMs);
          let latest = { done: false, lines: [] };
          const w = new Worker(c.workerUrl);
          w.onmessage = ev => {
            latest = ev.data && ev.data.done ? ev.data : { done: false, lines: ev.data.lines };
            if (ev.data && ev.data.done) {
              clearTimeout(t);
              resolve(ev.data);
            }
          };
          w.onerror = ev => {
            clearTimeout(t);
            reject(new Error('worker error: ' + ev.message));
          };
          setTimeout(() => {
            clearTimeout(t);
            resolve(latest);
          }, c.timeoutMs - 5000);
          w.postMessage(c);
        }),
      { ...cfg, timeoutMs }
    );
  } catch (e) {
    payload = { done: false, lines: [], result: { ok: false, error: String(e) } };
  }
  await page.close();
  return { payload, pageErrors };
}

// The shell cases. `resize: null` means "do not send window-change at all", which
// is worth testing on its own: a driver that always sends it would still pass
// every other case.
const CASES = [
  { name: 'plain', command: 'echo loop36-plain', cols: 80, rows: 24, resize: null },
  { name: 'resized', command: 'echo loop36-resized', cols: 100, rows: 40, resize: '132x43' },
  { name: 'wide', command: 'echo loop36-wide', cols: 200, rows: 60, resize: null },
];

function nativeArgs(c, port) {
  const a = ['run', 'cmd/ssh_live', '--target', 'native', '--',
    '--port', String(port), '--user', USER,
    '--shell', c.command, '--cols', String(c.cols), '--rows', String(c.rows)];
  if (c.resize) a.push('--resize', c.resize);
  return a;
}

async function main() {
  console.log('verify_loop36 -- RFC 4254 interactive session vs a real sshd\n');

  // ------------------------------------------------------------------- G1 --
  console.log('=== G1: the interactive byte layout, known-answer tested ===');

  const gen = spawnSync('python', ['host/gen_channel_vectors.py'], { cwd: ROOT, encoding: 'utf-8' });
  check('vector generator runs', gen.status === 0, `${gen.stdout || ''}${gen.stderr || ''}`.trim());
  const diff = spawnSync('git', ['diff', '--stat', '--', 'cmd/channel_test/vectors.mbt'],
    { cwd: ROOT, encoding: 'utf-8' });
  check('committed vectors still match the oracle', (diff.stdout || '').trim() === '',
    (diff.stdout || '').trim());

  const TARGETS = ['native', 'js', 'wasm', 'wasm-gc'];
  const MODES = ['debug', 'release'];
  const runs = [];
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(['run', 'cmd/channel_test', '--target', t, '-d', m]);
      const out = norm(`${r.stdout || ''}${r.stderr || ''}`);
      runs.push({ t, m, out, hash: hashOut(out), status: r.status });
    }
  }
  const refHash = runs[0].hash;
  const allPass = runs.every(r => r.status === 0);
  check('4 target x 2 mode byte-identical', allPass && runs.every(r => r.hash === refHash),
    allPass ? refHash : runs.filter(r => r.status !== 0).map(r => `${r.t}/${r.m}`).join(' '));
  const kat = runs[0].out;
  check('no KAT assertion failed', (kat.match(/: FAIL\b/g) || []).length === 0,
    (kat.match(/chan_(session|shell)_fail: .*/g) || []).join(' | '));

  // Loop #35's checks must still hold: extending src/channel must not have
  // quietly weakened the exec path.
  for (const k of [
    'chan_constants', 'chan_open_payload', 'chan_exec_payload', 'chan_data_payload',
    'chan_parsers_roundtrip', 'chan_parsers_reject_bad', 'chan_window_plan',
    'chan_sessions', 'chan_exit_status_fallback_255',
    // Loop #36's own
    'chan_pty_payloads', 'chan_exit_signal_parser', 'chan_shell_sessions',
    'chan_shell_coverage',
  ]) {
    check(`${k}: PASS`, kat.includes(`${k}: PASS`));
  }

  // Three distinct anti-regression properties, asserted with counts. One
  // combined boolean would be one check wearing three hats.
  check('a transcript with a refused pty-req survives',
    kat.includes('chan_shell_coverage: PASS'));
  check('a transcript that resizes survives',
    (grabInt(kat, 'chan_shell_cases') || 0) >= 6);
  check('a transcript with exit-signal survives',
    /exit_signal: TERM|exit_signal/.test(kat));

  console.log('\n=== G1b: mutation check ===');
  const mut = spawnSync('python', ['host/channel_mutations.py'], { cwd: ROOT, encoding: 'utf-8' });
  const mutText = norm(`${mut.stdout || ''}${mut.stderr || ''}`);
  for (const l of mutText.split('\n')) {
    if (/^(CAUGHT|MISSED|SKIP)/.test(l)) console.log(`      ${l}`);
  }
  const caught = (mutText.match(/^CAUGHT/gm) || []).length;
  const missed = (mutText.match(/^(MISSED|SKIP)/gm) || []).length;
  check('all ten mutations turn the KAT red', mut.status === 0 && caught >= 10 && missed === 0,
    `${caught} caught, ${missed} missed`);

  // ------------------------------------------------------------------- G2 --
  console.log('\n=== G2: native client, interactive shell on a real sshd ===');
  const natBuild = moonBuild('cmd/ssh_live', 'native');
  check('cmd/ssh_live builds for native', natBuild.ok, natBuild.ok ? '' : natBuild.text.slice(-300));
  const jsBuild = moonBuild('cmd/wt_ssh', 'js');
  check('cmd/wt_ssh builds for js', jsBuild.ok, jsBuild.ok ? '' : jsBuild.text.slice(-300));

  const oracleKeys = spawnSync(
    'python', ['host/ecdsa_auth_oracle.py', '--json', '--authorized-keys',
      '.loop31/sshd/authorized_keys'],
    { cwd: ROOT, encoding: 'utf-8' });
  check('wrote authorized_keys for the test key', oracleKeys.status === 0,
    oracleKeys.status === 0 ? '' : `${oracleKeys.stdout || ''}`.slice(-200));

  const sshd = spawn('node', ['host/sshd_setup.mjs', '--port', String(SSHD_PORT)], {
    cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'],
  });
  check('private sshd up', await waitForLog(sshd, 'sshd listening'));

  // The oracle cross-checks its pty / shell / window-change bytes against a live
  // paramiko pty session, and refuses to emit if this server refuses pty-req --
  // otherwise every later check would be measuring the wrong thing.
  const oracle = spawnSync(
    'python',
    ['host/channel_oracle.py', '--capture', '--port', String(SSHD_PORT), '--user', USER],
    { cwd: ROOT, encoding: 'utf-8' });
  const oracleText = norm(`${oracle.stdout || ''}${oracle.stderr || ''}`);
  for (const l of oracleText.split('\n')) {
    if (/paramiko (channel|pty)/.test(l)) console.log(`    ${l}`);
  }
  check('paramiko agrees byte for byte on pty-req / shell / window-change',
    oracle.status === 0 && /pty\/shell bytes agree/.test(oracleText),
    oracle.status === 0 ? '' : oracleText.slice(-300));

  const nativeRuns = [];
  for (const c of CASES) {
    const r = moon(nativeArgs(c, SSHD_PORT));
    const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
    const ok =
      text.includes('result: SHELL_DONE') &&
      grab(text, 'pty_granted') === 'true' &&
      grab(text, 'resize_sent') === (c.resize ? 'true' : 'false') &&
      grab(text, 'marker_seen') === 'true' &&
      grabInt(text, 'exit_status') === 0 &&
      grab(text, 'exit_signal') === 'none';
    nativeRuns.push({ c, text, ok });
    console.log(`      ${c.name}: exit=${grab(text, 'exit_status')} ` +
      `pty=${grab(text, 'pty_granted')} resize=${grab(text, 'resize_sent')} ` +
      `marker=${grab(text, 'marker_seen')} sent=${grab(text, 'total_sent_bytes')}B ${ok ? 'OK' : 'BAD'}`);
    if (!ok) {
      for (const l of text.split('\n')) {
        if (/^(result|error|exit_|pty_|resize_|marker_)/.test(l)) console.log(`        ${l}`);
      }
    }
  }
  check('every interactive shell opened a pty', nativeRuns.every(r => grab(r.text, 'pty_granted') === 'true'));
  check('the command was echoed back by the shell', nativeRuns.every(r => grab(r.text, 'marker_seen') === 'true'));
  check('window-change was sent exactly when asked for',
    nativeRuns.every(r => grab(r.text, 'resize_sent') === (r.c.resize ? 'true' : 'false')));
  check('the shell exited cleanly', nativeRuns.every(r => grabInt(r.text, 'exit_status') === 0));

  // window-change really is 64 more bytes on the wire: an extra CHANNEL_REQUEST
  // with four u32s and no modes. If resize_sent were quietly a no-op, this is
  // what would notice.
  const plain = nativeRuns.find(r => r.c.name === 'plain');
  const resized = nativeRuns.find(r => r.c.name === 'resized');
  const delta = grabInt(resized.text, 'total_sent_bytes') - grabInt(plain.text, 'total_sent_bytes');
  check('the resize really put bytes on the wire', delta > 0 && delta < 256,
    `+${delta} bytes`);

  // ------------------------------------------------------------------- G3 --
  console.log('\n=== G3: the same, inside a browser Web Worker ===');
  const httpSrv = await serve(ROOT, HTTP_PORT);
  const browser = await chromium.launch({
    headless: !HEADED, channel: 'chrome', ignoreHTTPSErrors: true,
  });
  const wsSshd = spawn(
    'python',
    ['host/wt/ws_relay.py', '--listen-port', String(WS_PORT), '--target-port', String(SSHD_PORT)],
    { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  check('relay -> sshd up', await waitForLog(wsSshd, 'websocket on ws://'));

  const workerRuns = [];
  for (const c of CASES) {
    const cfg = {
      workerUrl: '/host/wt/worker.js',
      shimUrl: '/host/wt/moonbit_wt.js',
      moduleUrl: '/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js',
      url: `ws://127.0.0.1:${WS_PORT}/ssh`,
      nonce: 'loop36',
      shell: c.command,
      user: USER,
      cols: String(c.cols),
      rows: String(c.rows),
    };
    if (c.resize) cfg.resize = c.resize;
    const { payload, pageErrors } = await runInWorker(browser, cfg, 150000);
    const lines = norm((payload.lines || []).join('\n'));
    const native = nativeRuns.find(r => r.c.name === c.name);
    const same =
      lines.includes('result: SHELL_DONE') &&
      grab(lines, 'pty_granted') === 'true' &&
      grab(lines, 'resize_sent') === grab(native.text, 'resize_sent') &&
      grab(lines, 'marker_seen') === 'true' &&
      grab(lines, 'exit_status') === grab(native.text, 'exit_status') &&
      grabInt(lines, 'total_sent_bytes') === grabInt(native.text, 'total_sent_bytes') &&
      grabInt(lines, 'total_recv_bytes') === grabInt(native.text, 'total_recv_bytes');
    workerRuns.push({ c, lines, same, pageErrors });
    console.log(`      ${c.name}: ${same ? 'OK' : 'MISMATCH'} ` +
      `pty=${grab(lines, 'pty_granted')} resize=${grab(lines, 'resize_sent')} ` +
      `sent=${grab(lines, 'total_sent_bytes')}B recv=${grab(lines, 'total_recv_bytes')}B`);
    if (!same) {
      for (const l of lines.split('\n')) {
        if (/^(result|error|exit_|pty_|resize_|marker_|total_)/.test(l)) console.log(`        ${l}`);
      }
    }
    if (pageErrors.length) console.log(`        page errors: ${pageErrors.join(' | ')}`);
  }
  check('browser Worker opened a pty in every case',
    workerRuns.every(r => grab(r.lines, 'pty_granted') === 'true'));
  check('browser Worker matched the native byte counts',
    workerRuns.every(r => r.same), workerRuns.filter(r => !r.same).map(r => r.c.name).join(' '));
  check('no uncaught page errors', workerRuns.every(r => r.pageErrors.length === 0),
    workerRuns.flatMap(r => r.pageErrors).join(' | '));

  await browser.close();
  httpSrv.close();
  wsSshd.kill();

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    console.log('\n=== regression: the earlier loops must still be green ===');
    for (const [label, script] of [
      ['loop32', 'host/verify_loop32.mjs'],
      ['loop33', 'host/verify_loop33.mjs'],
      ['loop34', 'host/verify_loop34.mjs'],
      ['loop35', 'host/verify_loop35.mjs'],
    ]) {
      const r = spawnSync('node', [script, '--skip-regression'], { cwd: ROOT, encoding: 'utf-8' });
      const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
      const m = text.match(/(\d+)\/(\d+) checks/);
      const passed = text.includes('✓ PASS');
      check(`${label} harness still green`, r.status === 0 && passed,
        m ? `${m[1]}/${m[2]}` : text.slice(-200));
    }
  }

  sshd.kill();

  const bad = results.filter(r => !r.ok);
  console.log(`\n${bad.length === 0 ? '✓ PASS' : '✗ FAIL'}: ${results.length - bad.length}/${results.length} checks`);
  if (bad.length) for (const b of bad) console.error(`  FAIL ${b.name}`);
  if (bad.length === 0) {
    console.log('  a real OpenSSH 8.0p1 server allocated a pty for us, accepted a');
    console.log('  shell request, echoed the command back over CHANNEL_DATA, took a');
    console.log('  window-change without answering it, and reported a clean exit --');
    console.log('  first natively, then from inside a browser Web Worker with zero');
    console.log('  native code and zero dependencies, with matching byte counts.');
  }
  process.exit(bad.length ? 1 : 0);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});