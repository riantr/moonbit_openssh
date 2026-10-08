#!/usr/bin/env node
// verify_loop35.mjs -- Loop #35: the SSH connection layer (RFC 4254), end to end
//
//   Loops #31-#34 got as far as USERAUTH_SUCCESS over an encrypted session. That
//   proves we can talk to a server and prove who we are, but it still has not run
//   a single byte of the *channel* protocol -- which is where SSH actually lives.
//   `ssh host command` opens a session channel, sends "exec", and reads DATA back
//   until the peer sends exit-status. This loop does exactly that against a real
//   OpenSSH server, natively and then inside a browser Web Worker.
//
//     G1  The RFC 4254 byte layout, known-answer tested against an independent
//         Python implementation across 4 target x 2 mode -- plus a staleness
//         check that re-derives the committed vectors from the oracle, and a
//         mutation check that puts each real bug back and requires the KAT to go
//         red. A KAT that cannot fail is not evidence.
//
//     G2  Native client against a real OpenSSH 8.0p1 sshd: run commands, read
//         back stdout, stderr and exit-status, byte for byte against Python.
//
//     G3  The same inside a browser Web Worker, with byte counts and payload
//         digests identical to G2.
//
//   Two of the three bugs this loop found are worth writing down, because both
//   are invisible to the obvious tests and one of them is invisible to *every*
//   local test:
//
//     * `maybe_adjust` dropped the window on the no-adjust path, so
//       `local_consumed` never accumulated and not a single WINDOW_ADJUST was
//       ever sent. The connection still completed for any output that fits in
//       2 MiB, which is everything anyone tries first.
//
//     * `maybe_adjust` read the amount off the window *after* `take_adjust` had
//       zeroed `consumed`, so every adjust carried 0 bytes. Again: the transfer
//       "works", it just never gets its window back.
//
//     * inbound packets were matched against `remote_id`. RFC 4254 section 5.2
//       says the recipient field of an inbound packet names *our* channel. Both
//       ids are 0 on a first channel, so this was wrong in a way that could not
//       be observed until a vector used local=3 / remote=7.
//
//   All three are the same shape as Loop #34's signature-blob bug: locally
//   self-consistent, wrong, and only a real counterpart notices.
//
// 用法: node host/verify_loop35.mjs [--skip-regression] [--headed]

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

const HTTP_PORT = 18776;
const WS_PORT = 8776;
const SSHD_PORT = 22265;
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
  // The bulk case prints a 1.5 MB payload as hex, which overruns spawnSync's
  // 1 MB default and truncates everything printed after it -- including the
  // exit-status line the comparison needs. Silent truncation that drops exactly
  // the fields under test is worse than a crash.
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

// moon's diagnostics and the program output both arrive on this side of the
// pipe, and on Windows the lines end CRLF. Normalize once at the edge instead
// of writing \r?$ six times.
const norm = s => `${s}`.replace(/\r\n/g, '\n');

const grab = (t, k) => (t.match(new RegExp(`^${k}: (.*)$`, 'm')) || [])[1];
const grabInt = (t, k) => {
  const v = grab(t, k);
  return v === undefined ? undefined : Number(v);
};

// The remote side of the connection is a Windows shell, so `echo` terminates
// lines with CRLF. Everything below therefore compares against bytes produced by
// running the same fixture locally, not against a hand-written expectation --
// "hello\n" would be the wrong reference and would have sent us hunting a bug
// that is actually correct behaviour.
function sha256Hex(bytes) {
  return createHash('sha256').update(Buffer.from(bytes)).digest('hex');
}

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

// ------------------------------------------------------------------- helpers --
// Commands the remote side actually runs, and how to reproduce each one's output
// *locally* so "expected" and "actual" come from the same programs rather than
// from a hand-written guess.
//
// The local reference deliberately goes through the same Windows shell the server
// uses: `cmd /c echo` terminates with CRLF, so a hand-written "hello\n" would be
// the wrong reference and would send someone hunting a bug that is correct
// behaviour. That mistake actually happened once while writing this.
const FIXTURE = join(ROOT, 'host', 'remote_fixture.py');

const COMMANDS = [
  { name: 'echo', argv: ['echo', 'hello-loop35'], ref: ['cmd', '/c', 'echo', 'hello-loop35'] },
  { name: 'stdout', argv: ['python', FIXTURE, 'stdout', '1000', 'A'], ref: ['python', FIXTURE, 'stdout', '1000', 'A'] },
  { name: 'stderr', argv: ['python', FIXTURE, 'stderr', '13'], ref: ['python', FIXTURE, 'stderr', '13'] },
  { name: 'both', argv: ['python', FIXTURE, 'both'], ref: ['python', FIXTURE, 'both'] },
  { name: 'exit7', argv: ['python', FIXTURE, 'exit', '7'], ref: ['python', FIXTURE, 'exit', '7'] },
  // 1.5 MiB, past the 2 MiB window's half point: the shape that starves a client
  // which never sends WINDOW_ADJUST, and the one that caught the window bug.
  { name: 'bulk', argv: ['python', FIXTURE, 'stdout', '1500000', 'A'], ref: ['python', FIXTURE, 'stdout', '1500000', 'A'] },
];

function localExpectation(cmd) {
  const r = spawnSync(cmd.ref[0], cmd.ref.slice(1),
    { cwd: ROOT, encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
  return { out: r.stdout || Buffer.alloc(0), err: r.stderr || Buffer.alloc(0), code: r.status };
}

async function main() {
  console.log('verify_loop35 -- RFC 4254 channel layer against a real sshd\n');

  // ------------------------------------------------------------------- G1 --
  console.log('=== G1: the channel byte layout, known-answer tested against Python ===');

  // Staleness: regenerate and require the committed vectors to be unchanged.
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
    (kat.match(/chan_session_fail: .*/g) || []).join(' | '));
  for (const k of [
    'chan_constants', 'chan_open_payload', 'chan_exec_payload', 'chan_data_payload',
    'chan_extdata_payload', 'chan_adjust_payload', 'chan_bare_payload',
    'chan_exit_status_payload', 'chan_open_failure_payload', 'chan_parsers_roundtrip',
    'chan_parsers_reject_bad', 'chan_window_plan', 'chan_window_cases_diverse',
    'chan_sessions',
    'chan_exit_status_fallback_255',
  ]) {
    check(`${k}: PASS`, kat.includes(`${k}: PASS`));
  }

  // A suite that never exercises the interesting branch is testing the part that
  // was already easy. These three assert, with counts, that the vector set still
  // contains the shapes which separate a correct implementation from a plausible
  // one -- and they are separate checks rather than one combined boolean, because
  // two checks on the same boolean is one check wearing a hat.
  const nCases = grabInt(kat, 'chan_session_cases') || 0;
  check('vectors still cover at least 8 session transcripts', nCases >= 8, `${nCases} cases`);
  check('a case with local_channel != remote_channel survives',
    (grabInt(kat, 'chan_session_ids_split_cases') || 0) >= 1,
    `${grabInt(kat, 'chan_session_ids_split_cases')} case(s)`);
  check('a case needing several WINDOW_ADJUSTs survives',
    (grabInt(kat, 'chan_session_multi_adjust_cases') || 0) >= 1,
    `${grabInt(kat, 'chan_session_multi_adjust_cases')} case(s)`);
  check('a case with no exit-status survives',
    (grabInt(kat, 'chan_session_no_status_cases') || 0) >= 1,
    `${grabInt(kat, 'chan_session_no_status_cases')} case(s)`);

  // Mutation check: put each real bug back, require the KAT to notice, restore.
  console.log('\n=== G1b: mutation check -- every bug this loop found must turn the KAT red ===');
  const mut = spawnSync('python', ['host/channel_mutations.py'], { cwd: ROOT, encoding: 'utf-8' });
  const mutText = norm(`${mut.stdout || ''}${mut.stderr || ''}`);
  for (const l of mutText.split('\n')) {
    if (/^(CAUGHT|MISSED|SKIP)/.test(l)) console.log(`      ${l}`);
  }
  const caught = (mutText.match(/^CAUGHT/gm) || []).length;
  const missed = (mutText.match(/^(MISSED|SKIP)/gm) || []).length;
  check('all three window/id bugs turn the KAT red', mut.status === 0 && caught >= 4 && missed === 0,
    `${caught} caught, ${missed} missed`);

  // ------------------------------------------------------------------- G2 --
  console.log('\n=== G2: native client runs commands on a real OpenSSH 8.0p1 sshd ===');
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

  // The oracle needs the same server, so re-run the paramiko cross-check now that
  // it is up. A green run here means our CHANNEL_OPEN / exec bytes are the ones a
  // real, independent SSH implementation puts on the wire.
  const oracleLive = spawnSync(
    'python',
    ['host/channel_oracle.py', '--capture', '--port', String(SSHD_PORT), '--user', USER],
    { cwd: ROOT, encoding: 'utf-8' });
  const oracleLiveText = norm(`${oracleLive.stdout || ''}${oracleLive.stderr || ''}`);
  console.log(`    ${(oracleLiveText.match(/paramiko channel bytes agree:.*/) || [oracleLiveText.trim().split('\n')[0] || '(no output)'])[0]}`);
  check('paramiko agrees byte for byte on CHANNEL_OPEN / exec',
    oracleLive.status === 0 && /agree/.test(oracleLiveText),
    oracleLive.status === 0 ? '' : oracleLiveText.slice(-200));

  const nativeRuns = [];
  for (const cmd of COMMANDS) {
    const r = moon(['run', 'cmd/ssh_live', '--target', 'native', '--',
      '--port', String(SSHD_PORT), '--user', USER, '--exec', ...cmd.argv]);
    const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
    const want = localExpectation(cmd);
    const okOut = text.includes('result: EXEC_DONE') &&
      grabInt(text, 'stdout_len') === want.out.length &&
      (text.match(/^stdout_sha256: (\w+)$/m) || [])[1] === sha256Hex(want.out).toUpperCase() &&
      grabInt(text, 'stderr_len') === want.err.length &&
      (text.match(/^stderr_sha256: (\w+)$/m) || [])[1] === sha256Hex(want.err).toUpperCase() &&
      grabInt(text, 'exit_status') === want.code;
    nativeRuns.push({ cmd, text, okOut, want });
    console.log(`      ${cmd.name}: exit=${grabInt(text, 'exit_status')} ` +
      `out=${grabInt(text, 'stdout_len')}B err=${grabInt(text, 'stderr_len')}B ` +
      `adjusts=${grabInt(text, 'adjusts_sent')} ${okOut ? 'OK' : 'MISMATCH'}`);
    if (!okOut) {
      for (const l of text.split('\n')) if (/^(result|error|stdout_|stderr_)/.test(l)) console.log(`        ${l}`);
    }
  }
  check('every remote command matched the Python reference byte for byte',
    nativeRuns.every(r => r.okOut));
  const bulk = nativeRuns.find(r => r.cmd.name === 'bulk');
  check('1.5 MiB transfer adjusted the window more than once',
    grabInt(bulk?.text || '', 'adjusts_sent') > 1,
    `adjusts_sent=${grabInt(bulk?.text || '', 'adjusts_sent')}`);
  check('1.5 MiB of output survived intact',
    grabInt(bulk?.text || '', 'stdout_len') === 1500000);

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
  for (const cmd of COMMANDS) {
    const { payload, pageErrors } = await runInWorker(
      browser,
      {
        workerUrl: '/host/wt/worker.js',
        shimUrl: '/host/wt/moonbit_wt.js',
        moduleUrl: '/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js',
        url: `ws://127.0.0.1:${WS_PORT}/ssh`,
        nonce: 'loop35',
        exec: cmd.argv.join(' '),
        user: USER,
      },
      cmd.name === 'bulk' ? 240000 : 120000
    );
    const lines = norm((payload.lines || []).join('\n'));
    const native = nativeRuns.find(r => r.cmd.name === cmd.name);
    const same =
      lines.includes('result: EXEC_DONE') &&
      grab(lines, 'stdout_len') === grab(native.text, 'stdout_len') &&
      grab(lines, 'stderr_len') === grab(native.text, 'stderr_len') &&
      grab(lines, 'stdout_sha256') === grab(native.text, 'stdout_sha256') &&
      grab(lines, 'stderr_sha256') === grab(native.text, 'stderr_sha256') &&
      grab(lines, 'exit_status') === grab(native.text, 'exit_status');
    workerRuns.push({ cmd, lines, same, pageErrors });
    console.log(`      ${cmd.name}: ${same ? 'OK' : 'MISMATCH'} ` +
      `out=${grab(lines, 'stdout_len')}B err=${grab(lines, 'stderr_len')}B ` +
      `exit=${grab(lines, 'exit_status')}`);
    if (!same) {
      for (const l of lines.split('\n')) if (/^(result|error|stdout_|stderr_)/.test(l)) console.log(`        ${l}`);
    }
    if (pageErrors.length) console.log(`        page errors: ${pageErrors.join(' | ')}`);
  }
  check('browser Worker ran every command', workerRuns.every(r => r.lines.includes('result: EXEC_DONE')));
  check('browser Worker bytes identical to the native client',
    workerRuns.every(r => r.same),
    workerRuns.filter(r => !r.same).map(r => r.cmd.name).join(' '));
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
    ]) {
      const r = spawnSync('node', [script], { cwd: ROOT, encoding: 'utf-8' });
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
    console.log('  a real OpenSSH 8.0p1 server opened a session channel, accepted an');
    console.log('  exec request, streamed stdout and stderr back over CHANNEL_DATA and');
    console.log('  CHANNEL_EXTENDED_DATA, and reported exit-status -- first natively, then');
    console.log('  from inside a browser Web Worker with zero native code and zero');
    console.log('  dependencies, with byte counts and payload digests matching.');
  }
  process.exit(bad.length ? 1 : 0);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
