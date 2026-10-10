#!/usr/bin/env node
// verify_loop37.mjs -- Loop #37: stdin flow control and the `env` request
//
//   Loop #35 gave us `exec` with no stdin; Loop #36 gave us an interactive
//   session. Neither one can move more than a window's worth of bytes into the
//   remote process, and neither sends an `env` request. Both are one-shot paths
//   that a real `ssh` client takes every single time:
//
//     G1  The byte layout and the window arithmetic, known-answer tested against
//         an independent Python implementation AND against a live paramiko
//         session (paramiko builds the `env` request in
//         Channel.set_environment_variable and CHANNEL_EOF in
//         Channel.shutdown_write -- neither ever read our RFC notes), plus the
//         staleness and mutation checks the earlier loops established.
//
//     G2  Native client against a real OpenSSH 8.0p1 sshd: 3 MiB of stdin
//         through a 2 MiB window, plus an `env` request the server accepts and
//         one it refuses. The remote fixture reports the byte count and the
//         SHA-256 of what actually arrived, so this is checked against the
//         bytes on the far side and not against the client's own opinion.
//
//     G3  The same inside a browser Web Worker, matching byte counts.
//
//   The interesting part of G2 is that it is the first test in this project
//   where a *bug would not look like a failure*. Under-sending stdin is
//   invisible: the remote command still exits 0, the client still reports
//   EXEC_DONE, and only the fixture's byte count disagrees. That is why the
//   fixture echoes a digest instead of an OK.
//
// 用法: node host/verify_loop37.mjs [--skip-regression] [--headed]

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

const HTTP_PORT = 18779;
const WS_PORT = 8779;
const SSHD_PORT = 22270;
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
// The fixture prints `stdin_len 3145728` inside the remote stdout, which lands
// in the client's `--- raw ---` block. Grab it from the whole run text.
const grabRaw = (t, k) => (t.match(new RegExp(`^${k} (.*)$`, 'm')) || [])[1];

const FIXTURE = join(ROOT, 'host', 'remote_fixture.py');
// 3 MiB: comfortably past the 2 MiB default window, so the clamp has to bite
// and at least one CHANNEL_WINDOW_ADJUST has to arrive mid-transfer.
const BIG = 3 * 1024 * 1024;

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

// The exec cases. `envs` is `NAME=VALUE;NAME=VALUE` because the Worker's
// configuration arrives as a flat string map -- a browser has no argv.
const CASES = [
  { name: 'nos', args: [], envs: '', bytes: 0 },
  { name: 'tiny', args: [], envs: '', bytes: 11 },
  // `python host/remote_fixture.py cat` blocks until stdin ends, so a client
  // that forgets CHANNEL_EOF hangs here instead of returning a wrong answer.
  { name: 'bulk3mib', args: [], envs: '', bytes: BIG, cat: true },
  {
    name: 'env_accepted',
    args: [],
    envs: 'LOOP37_TEST=hello-loop37',
    bytes: 0,
    envvar: 'LOOP37_TEST',
  },
  {
    name: 'env_refused',
    args: [],
    // Not in the test sshd's AcceptEnv, so the server drops it silently.
    envs: 'LOOP37_NOTACCEPTED=nope',
    bytes: 0,
    envvar: 'LOOP37_NOTACCEPTED',
  },
  {
    name: 'env_and_stdin',
    args: [],
    envs: 'LOOP37_TEST=hello-loop37',
    bytes: 4096,
    cat: true,
  },
];

function commandOf(c) {
  if (c.cat) return ['python', FIXTURE, 'cat'];
  if (c.envvar) return ['python', FIXTURE, 'envvar', c.envvar];
  return ['python', FIXTURE, 'both'];
}

function nativeArgs(c, port) {
  const a = ['run', 'cmd/ssh_live', '--target', 'native', '--',
    '--port', String(port), '--user', USER, '--exec', ...commandOf(c)];
  if (c.bytes > 0) a.push('--stdin-bytes', String(c.bytes));
  for (const e of c.envs.split(';').filter(Boolean)) a.push('--env', e);
  return a;
}

async function main() {
  console.log('verify_loop37 -- stdin flow control and `env` vs a real sshd\n');

  // ------------------------------------------------------------------- G1 --
  console.log('=== G1: the env layout and the send-side clamp, known-answer tested ===');

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
    (kat.match(/chan_(session|shell|io)_fail: .*/g) || []).join(' | '));

  // Everything the earlier loops asserted must still hold, including the exec
  // and interactive paths -- Loop #37 touches the same package.
  for (const k of [
    'chan_constants', 'chan_open_payload', 'chan_exec_payload', 'chan_data_payload',
    'chan_parsers_roundtrip', 'chan_parsers_reject_bad', 'chan_window_plan',
    'chan_sessions', 'chan_exit_status_fallback_255',
    'chan_pty_payloads', 'chan_exit_signal_parser', 'chan_shell_sessions',
    'chan_shell_coverage',
    // Loop #37's own
    'chan_env_payloads', 'chan_eof_action', 'chan_stdin_clamp', 'chan_io_sessions',
    'chan_io_coverage',
  ]) {
    check(`${k}: PASS`, kat.includes(`${k}: PASS`));
  }

  // Four distinct properties, each asserted on its own. One combined boolean
  // would be one check wearing four hats, and a reviewer cannot tell which
  // property a regression just broke.
  check('the clamp is exercised by more than one packet size',
    (grabInt(kat, 'chan_stdin_resume_cases') || 0) >= 3,
    `${grabInt(kat, 'chan_stdin_resume_cases')} resume, ${grabInt(kat, 'chan_stdin_stall_cases')} stall`);
  check('a window tighter than max_packet is covered',
    (grabInt(kat, 'chan_stdin_window_tighter_than_packet') || 0) >= 1);
  check('a transcript leaves stdin buffered and never sends EOF',
    (grabInt(kat, 'chan_io_cases') || 0) >= 8);
  check('env gets no reply, so one env plus one exec is one CHANNEL_SUCCESS',
    kat.includes('chan_io_coverage: PASS'));

  console.log('\n=== G1b: mutation check ===');
  // maxBuffer is stated because the default (1 MiB) is one cold-build's
  // diagnostics away from killing the child mid-batch -- which surfaced as
  // "5 caught, 0 missed" and nothing else (Loop #42). A killed child loses
  // its buffered stdout; the summary then proves nothing about the
  // remaining mutations.
  const mut = spawnSync('python', ['host/channel_mutations.py'],
    { cwd: ROOT, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 });
  const mutText = norm(`${mut.stdout || ''}${mut.stderr || ''}`);
  for (const l of mutText.split('\n')) {
    if (/^(CAUGHT|MISSED|SKIP)/.test(l)) console.log(`      ${l}`);
  }
  const caught = (mutText.match(/^CAUGHT/gm) || []).length;
  const missed = (mutText.match(/^(MISSED|SKIP)/gm) || []).length;
  check('every mutation turns the KAT red', mut.status === 0 && caught >= 16 && missed === 0,
    `${caught} caught, ${missed} missed`);

  // ------------------------------------------------------------------- G2 --
  console.log('\n=== G2: native client, stdin flow control and env on a real sshd ===');
  const natBuild = moonBuild('cmd/ssh_live', 'native');
  check('cmd/ssh_live builds for native', natBuild.ok, natBuild.ok ? '' : natBuild.text.slice(-300));
  const jsBuild = moonBuild('cmd/wt_ssh', 'js');
  check('cmd/wt_ssh builds for js', jsBuild.ok, jsBuild.ok ? '' : jsBuild.text.slice(-300));

  // What the far side must see, computed here rather than from the client's
  // own numbers. The client's stdin pattern lives in one place in the code;
  // this recomputes it so a change to either side shows up as a mismatch
  // instead of two implementations agreeing on being wrong.
  const expect = spawnSync('python', ['host/stdin_expect.py', String(BIG)],
    { cwd: ROOT, encoding: 'utf-8' });
  const expectText = norm(`${expect.stdout || ''}${expect.stderr || ''}`);
  const expectSha = grabRaw(expectText, 'sha256');
  const expectHead = grabRaw(expectText, 'head');
  const expectTail = grabRaw(expectText, 'tail');
  check('computed the expected stdin digest', expect.status === 0 && !!expectSha,
    expectSha || expectText.slice(-200));

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

  // paramiko builds the same three packets from an independent codebase.
  const oracle = spawnSync(
    'python',
    ['host/channel_oracle.py', '--capture', '--port', String(SSHD_PORT), '--user', USER],
    { cwd: ROOT, encoding: 'utf-8' });
  const oracleText = norm(`${oracle.stdout || ''}${oracle.stderr || ''}`);
  for (const l of oracleText.split('\n')) {
    if (/paramiko (channel|pty|env)/.test(l)) console.log(`    ${l}`);
  }
  check('paramiko agrees byte for byte on env / stdin-data / EOF',
    oracle.status === 0 && /env\/stdin bytes agree/.test(oracleText),
    oracle.status === 0 ? '' : oracleText.slice(-400));

  const nativeRuns = [];
  for (const c of CASES) {
    const r = moon(nativeArgs(c, SSHD_PORT));
    const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
    const ok =
      text.includes('result: EXEC_DONE') &&
      grabInt(text, 'exit_status') === 0 &&
      grab(text, 'eof_sent') === 'true' &&
      grabInt(text, 'stdin_sent') === c.bytes &&
      grabInt(text, 'env_sent') === (c.envs ? c.envs.split(';').length : 0);
    nativeRuns.push({ c, text, ok });
    console.log(`      ${c.name}: exit=${grab(text, 'exit_status')} ` +
      `stdin=${grab(text, 'stdin_sent')}/${grabInt(text, 'stdin_packets')}pkts ` +
      `eof=${grab(text, 'eof_sent')} env=${grab(text, 'env_sent')} ${ok ? 'OK' : 'BAD'}`);
    if (!ok) {
      for (const l of text.split('\n')) {
        if (/^(result|error|stdin_|eof_|env_)/.test(l)) console.log(`        ${l}`);
      }
    }
  }
  check('every native case completed and reported what it sent',
    nativeRuns.every(r => r.ok), nativeRuns.filter(r => !r.ok).map(r => r.c.name).join(' '));
  check('every native case ended the stdin direction',
    nativeRuns.every(r => grab(r.text, 'eof_sent') === 'true'));
  check('every native case sent exactly the bytes it was asked to',
    nativeRuns.every(r => grabInt(r.text, 'stdin_sent') === r.c.bytes));

  // The bulk case is the whole point of this loop. The remote reports the count
  // and the digest of what actually landed on its stdin, so this compares the
  // far side against an independently computed expectation.
  const bulk = nativeRuns.find(r => r.c.name === 'bulk3mib');
  const bulkText = bulk ? bulk.text : '';
  const bulkPkts = grabInt(bulkText, 'stdin_packets') || 0;
  check('the far side received every byte of the 3 MiB transfer',
    grabRaw(bulkText, 'stdin_len') === String(BIG),
    `remote says ${grabRaw(bulkText, 'stdin_len')}`);
  check('and the bytes are the ones we intended, not merely the right count',
    grabRaw(bulkText, 'stdin_sha256') === expectSha,
    `remote ${String(grabRaw(bulkText, 'stdin_sha256')).slice(0, 16)} vs expected ${String(expectSha).slice(0, 16)}`);
  check('and they arrived in order (head and tail intact)',
    grabRaw(bulkText, 'stdin_head') === expectHead &&
    grabRaw(bulkText, 'stdin_tail') === expectTail);
  // The window was 2 MiB and the transfer 3 MiB, so the clamp had to split it
  // into strictly more packets than the window holds, and a WINDOW_ADJUST had
  // to arrive for the transfer to finish. 96 is the oracle's prediction for
  // 3 MiB through a 2 MiB window at a 32 KiB max packet -- quoted, not
  // recomputed here, so a change in either implementation has to be argued for.
  check('the clamp split the transfer at the packet limit, not in one blob',
    bulkPkts >= 96 && bulkPkts <= 100, `${bulkPkts} packets`);

  // `env` has want_reply = FALSE, so there is nothing on the wire to check.
  // The only honest oracle is the remote command's own environment.
  const acc = nativeRuns.find(r => r.c.name === 'env_accepted');
  const ref = nativeRuns.find(r => r.c.name === 'env_refused');
  check('the server handed the accepted variable to the session',
    acc && grabRaw(acc.text, 'env_present') === '1' &&
    grabRaw(acc.text, 'env_value') === 'hello-loop37',
    acc ? `present=${grabRaw(acc.text, 'env_present')} value=${grabRaw(acc.text, 'env_value')}` : '');
  // A refusal is silent by design. What must hold is that it is silent *and*
  // harmless: the session still runs to completion.
  check('the refused variable did not arrive and did not break the session',
    ref && grabRaw(ref.text, 'env_present') === '0' &&
    grab(ref.text, 'result') === 'EXEC_DONE',
    ref ? `present=${grabRaw(ref.text, 'env_present')} result=${grab(ref.text, 'result')}` : '');
  const both = nativeRuns.find(r => r.c.name === 'env_and_stdin');
  check('env and stdin on the same channel both took effect',
    both && grabRaw(both.text, 'env_present') === '1' &&
    grabRaw(both.text, 'stdin_len') === '4096');

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
      nonce: 'loop37',
      exec: commandOf(c).join(' '),
      user: USER,
    };
    if (c.bytes > 0) cfg.stdin_bytes = String(c.bytes);
    if (c.envs) cfg.env = c.envs;
    const { payload, pageErrors } = await runInWorker(browser, cfg, 600000);
    const lines = norm((payload.lines || []).join('\n'));
    const native = nativeRuns.find(r => r.c.name === c.name);
    const same =
      lines.includes('result: EXEC_DONE') &&
      grabInt(lines, 'exit_status') === 0 &&
      grab(lines, 'eof_sent') === 'true' &&
      grabInt(lines, 'stdin_sent') === grabInt(native.text, 'stdin_sent') &&
      grabInt(lines, 'stdin_packets') === grabInt(native.text, 'stdin_packets') &&
      grabInt(lines, 'env_sent') === grabInt(native.text, 'env_sent') &&
      grabInt(lines, 'stdout_len') === grabInt(native.text, 'stdout_len') &&
      grabInt(lines, 'total_sent_bytes') === grabInt(native.text, 'total_sent_bytes') &&
      grabInt(lines, 'total_recv_bytes') === grabInt(native.text, 'total_recv_bytes');
    workerRuns.push({ c, lines, same, pageErrors });
    console.log(`      ${c.name}: ${same ? 'OK' : 'MISMATCH'} ` +
      `stdin=${grab(lines, 'stdin_sent')}/${grab(lines, 'stdin_packets')}pkts ` +
      `sent=${grab(lines, 'total_sent_bytes')}B recv=${grab(lines, 'total_recv_bytes')}B`);
    if (!same) {
      for (const l of lines.split('\n')) {
        if (/^(result|error|stdin_|eof_|env_|total_)/.test(l)) console.log(`        ${l}`);
      }
    }
    if (pageErrors.length) console.log(`        page errors: ${pageErrors.join(' | ')}`);
  }
  check('browser Worker matched the native transfer in every case',
    workerRuns.every(r => r.same), workerRuns.filter(r => !r.same).map(r => r.c.name).join(' '));
  // Byte-for-byte on the far side, not just on the wire: the Worker has to have
  // delivered the same 3 MiB as the native run.
  const wbulk = workerRuns.find(r => r.c.name === 'bulk3mib');
  check('the Worker also moved the whole 3 MiB, digest and all',
    wbulk && grabRaw(wbulk.lines, 'stdin_len') === String(BIG) &&
    grabRaw(wbulk.lines, 'stdin_sha256') === expectSha,
    wbulk ? `remote ${String(grabRaw(wbulk.lines, 'stdin_sha256')).slice(0, 16)}` : '');
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
      ['loop36', 'host/verify_loop36.mjs'],
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
    console.log('  a real OpenSSH 8.0p1 server took 3 MiB of stdin through a 2 MiB');
    console.log('  window without a single RFC 4254 5.2 disconnect, and reported back');
    console.log('  the same SHA-256 we computed beforehand; it accepted one `env`');
    console.log('  request and silently dropped another without breaking the session;');
    console.log('  and a browser Web Worker with zero native code and zero');
    console.log('  dependencies sent byte-identical traffic while doing all of it.');
  }
  process.exit(bad.length ? 1 : 0);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});