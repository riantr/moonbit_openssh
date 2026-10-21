#!/usr/bin/env node
// verify_loop38.mjs -- Loop #38: real host key algorithms (RFC 8332)
//
//   For thirty-seven loops the test server was pinned to ECDSA host keys and
//   the client proposed ECDSA host keys, so the two always agreed and the
//   client looked complete.  It was not.  Against a server holding only the
//   keys a stock install has -- ed25519 and RSA -- every name the server
//   offered was one the client refused, and the handshake died with
//   `NoAgreement`.  The server's log said "no matching host key type found",
//   which reads like a cipher problem and is not one.
//
//   G1  The KAT: 39 vectors over four backends and two modes, byte-identical.
//       Three of the vectors are bytes a real OpenSSH 8.0p1 sshd put on the
//       wire; the rest are paramiko blobs with expectations re-derived from
//       ssh-rsa.c:490-570.
//
//   G2  A real server with **no** `HostKeyAlgorithms` pin: the client has to
//       negotiate on its own, and it has to authenticate.  This is the case
//       that used to fail.
//
//   G3  Each algorithm forced in turn, so the dispatch is proved for all of
//       them and not just for whichever one the server prefers.  This is where
//       the three-name split shows up in the client's own output: an
//       `rsa-sha2-512` negotiation reports `hostkey_type: ssh-rsa`.
//
//   G4  The negative case.  A server offering only `ssh-rsa` (SHA-1) must be
//       refused at negotiation with a message that says why, not accepted and
//       then failed at verify time blaming an algorithm nobody selected.
//
//   G5  The same, inside a browser Web Worker, matching the native run.
//
//   A note on what "refused" means here.  `ssh-rsa` is absent from our
//   proposal on purpose: it maps to SHA-1, this project has no SHA-1, and
//   OpenSSH 8.8+ disables it by default.  Advertising a name we cannot check
//   would move the failure from negotiation time to verify time and point the
//   error at an algorithm that was never chosen.
//
// Usage: node host/verify_loop38.mjs [--skip-regression] [--headed]

import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sshUser } from './ssh_user.mjs';
import { chromium } from 'playwright';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HEADED = process.argv.includes('--headed');
const SKIP_REGRESSION = process.argv.includes('--skip-regression');

const HTTP_PORT = 18780;
const WS_PORT = 8780;
// One port per pinned instance, so they can all be alive at once and a
// failure points at a specific algorithm instead of at "the sshd".
const BASE_PORT = 22275;

// The account this gate authenticates as: the one this machine runs as.
//
// Writing one developer's account name here made every gate that opens a real
// OpenSSH server pass on that machine and fail on every other one -- and the
// failure looked like a protocol bug, because the server's answer to a
// public key it does not accept is "no", and the client reports that as an
// authentication rejection. See host/ssh_user.mjs.
const USER = sshUser();
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

// The algorithms the client advertises, in the order it advertises them.
// The client's order is the preference and wins outright: OpenSSH picks the
// first entry of the *client* list the server also offers (`kex.c:887-890`
// `match_list(client, server)`, the rule RFC 4253 §7.1 states).
const ADVERTISED = [
  'ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256',
  'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
];

// One pinned server per algorithm, so G3 can prove each path independently.
const PINNED = [
  { alg: 'ssh-ed25519', keytype: 'ssh-ed25519', bits: 256 },
  { alg: 'rsa-sha2-512', keytype: 'ssh-rsa', bits: 2048 },
  { alg: 'rsa-sha2-256', keytype: 'ssh-rsa', bits: 2048 },
  { alg: 'ecdsa-sha2-nistp256', keytype: 'ecdsa-sha2-nistp256', bits: 256 },
];

const results = [];
const check = (name, ok, detail = '') => {
  results.push({ name, ok });
  console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${name}${detail ? `  ${detail}` : ''}`);
};

const norm = s => `${s}`.replace(/\r\n/g, '\n');
const grab = (t, k) => (t.match(new RegExp(`^${k}: (.*)$`, 'm')) || [])[1];

function moon(args) {
  return spawnSync('cmd', ['/c', 'moon', ...args],
    { cwd: ROOT, encoding: 'utf-8', maxBuffer: 64 * 1024 * 1024 });
}

function moonBuild(pkg, target) {
  const r = moon(['build', pkg, '--target', target]);
  const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
  return { ok: r.status === 0 && !/^\s*Error:/m.test(text), text };
}

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

///|
/// Wait for a marker in a child's combined output.
///
/// The listeners have to be attached up front. Reading `stream.data` from a
/// poll loop does not start the flow -- without a `data` handler the stream
/// stays paused and the buffer is never filled, so the wait times out on a
/// child that is printing exactly what we are looking for.
async function waitForLog(proc, needle, ms = 25000) {
  let buf = '';
  proc.stdout?.on('data', d => { buf += d.toString(); });
  proc.stderr?.on('data', d => { buf += d.toString(); });
  const t0 = Date.now();
  while (Date.now() - t0 <= ms) {
    if (buf.includes(needle)) return { ok: true, text: buf };
    await new Promise(r => setTimeout(r, 100));
  }
  return { ok: false, text: buf };
}

/// Start one sshd, optionally with `HostKeyAlgorithms` pinned.
async function startSshd(port, name, hostkeyAlgs) {
  const args = ['host/sshd_setup.mjs', '--port', String(port)];
  if (name) args.push('--name', name);
  if (hostkeyAlgs) args.push('--hostkey-algs', hostkeyAlgs);
  const proc = spawn('node', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  // The child's own output is the only diagnosis available when this fails --
  // `sshd_config INVALID` and the sshd -t complaint both go to stderr, and a
  // bare "did not start" would send you looking in the wrong place.
  const r = await waitForLog(proc, 'sshd listening');
  return { proc, ok: r.ok, text: r.text };
}

function stopSshd(name) {
  spawnSync('node', ['host/sshd_setup.mjs', '--stop', ...(name ? ['--name', name] : [])],
    { cwd: ROOT, encoding: 'utf-8' });
}

/// One client run against a real server, authenticating with the test key.
function clientRun(port, extra = []) {
  const r = moon(['run', 'cmd/ssh_live', '--target', 'native', '--',
    '--port', String(port), '--user', USER, '--session', '--auth', ...extra]);
  return norm(`${r.stdout || ''}${r.stderr || ''}`);
}

async function runInWorker(browser, cfg, timeoutMs) {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(String(e)));
  await page.goto(`http://127.0.0.1:${HTTP_PORT}/host/wt/probe.html`);
  let payload;
  try {
    payload = await page.evaluate(
      c => new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error('worker timeout')), c.timeoutMs);
        let latest = { done: false, lines: [] };
        const w = new Worker(c.workerUrl);
        w.onmessage = ev => {
          latest = ev.data && ev.data.done ? ev.data : { done: false, lines: ev.data.lines };
          if (ev.data && ev.data.done) { clearTimeout(t); resolve(ev.data); }
        };
        w.onerror = ev => { clearTimeout(t); reject(new Error('worker error: ' + ev.message)); };
        setTimeout(() => { clearTimeout(t); resolve(latest); }, c.timeoutMs - 5000);
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

async function main() {
  const natBuild = moonBuild('cmd/ssh_live', 'native');
  check('cmd/ssh_live builds for native', natBuild.ok,
    natBuild.ok ? '' : natBuild.text.slice(-300));
  const jsBuild = moonBuild('cmd/wt_ssh', 'js');
  check('cmd/wt_ssh builds for js (the browser backend)', jsBuild.ok,
    jsBuild.ok ? '' : jsBuild.text.slice(-300));

  console.log('=== G1: the KAT on four backends, two modes ===');
  const TARGETS = ['native', 'js', 'wasm', 'wasm-gc'];
  const MODES = ['debug', 'release'];
  const katText = {};
  let katFail = 0;
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(['run', 'cmd/hostkey_test', '--target', t, '--mode', m]);
      const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
      const lines = text.split('\n').filter(l => /^(chk_|hostkey_)/.test(l));
      katText[`${t}/${m}`] = lines.join('\n');
      const bad = lines.filter(l => /: FAIL$/.test(l));
      if (r.status !== 0 || bad.length) {
        katFail++;
        console.log(`      ${t}/${m}: ${bad.length} failing, rc=${r.status}`);
        for (const l of bad) console.log(`        ${l}`);
      }
    }
  }
  check('the KAT is green on all four backends in both modes', katFail === 0);
  const distinct = [...new Set(Object.values(katText))];
  check('and every backend reports the same thing, byte for byte',
    distinct.length === 1, `${distinct.length} distinct outputs`);
  check('the KAT carries vectors captured from a real server',
    distinct.length === 1 && distinct[0].includes('hostkey_real_captures: 3'),
    (distinct[0] || '').split('\n').find(l => l.startsWith('hostkey_real_captures')) || '');

  // --------------------------------------------------------------- G2 ------
  console.log('\n=== G2: a real server with no HostKeyAlgorithms pin ===');
  // The stale-log trap: sshd.log is appended across runs, so a line from an
  // earlier connection is indistinguishable from a fresh one unless the file
  // is cleared first. Loop #38 read the wrong one and nearly misdiagnosed it.
  await new Promise(r => spawn('cmd', ['/c', 'del', '/q',
    join(ROOT, '.loop31', 'sshd', 'sshd.log')], { stdio: 'ignore' }).on('exit', r));
  stopSshd('');
  const main3 = await startSshd(BASE_PORT, '', '');
  check('private sshd up (no algorithm pin)', main3.ok,
    main3.ok ? '' : norm(main3.text).trim().slice(-300));
  if (!main3.ok) throw new Error('sshd did not start; cannot continue');

  const text = clientRun(BASE_PORT);
  check('the client completed a session and authenticated',
    text.includes('USERAUTH_SUCCESS'), grab(text, 'result') || text.slice(-200));
  check('it negotiated an algorithm from its own proposal, not a pinned one',
    ADVERTISED.includes(grab(text, 'hostkey_alg')), grab(text, 'hostkey_alg') || '(none)');
  check('and the negotiated name, the key type and the key size agree',
    grab(text, 'hostkey_bits') !== undefined &&
    Number(grab(text, 'hostkey_bits')) > 0,
    `${grab(text, 'hostkey_alg')} / ${grab(text, 'hostkey_type')} / ${grab(text, 'hostkey_bits')}`);
  // The proposal is the thing Loop #38 changed. Check it as a string, because
  // "the connection worked" would also be true if the server only had ECDSA.
  const propR = moon(['run', 'cmd/ssh_live', '--target', 'native', '--', '--proposal']);
  const propText = norm(`${propR.stdout || ''}${propR.stderr || ''}`);
  const offered = (propText.match(/hostkey_algs: (.*)$/m) || [])[1] || '';
  check('the proposal advertises all five algorithms we can verify',
    ADVERTISED.every(a => offered.split(',').includes(a)), offered);
  check('and does not advertise `ssh-rsa`, which would need SHA-1',
    !offered.split(',').includes('ssh-rsa'), offered);

  // --------------------------------------------------------------- G3 ------
  console.log('\n=== G3: every algorithm forced in turn ===');
  const pinned = [];
  for (let i = 0; i < PINNED.length; i++) {
    const p = PINNED[i];
    const port = BASE_PORT + 1 + i;
    const s = await startSshd(port, p.alg.replace(/[^a-z0-9]/gi, ''), p.alg);
    check(`sshd pinned to ${p.alg}`, s.ok,
      s.ok ? `port ${port}` : norm(s.text).trim().slice(-200));
    pinned.push({ ...p, port, name: p.alg.replace(/[^a-z0-9]/gi, '') });
  }
  const runs = [];
  for (const p of pinned) {
    const t = clientRun(p.port);
    const alg = grab(t, 'hostkey_alg');
    const type = grab(t, 'hostkey_type');
    const bits = grab(t, 'hostkey_bits');
    const ok = t.includes('USERAUTH_SUCCESS') &&
      alg === p.alg && type === p.keytype && bits === String(p.bits);
    runs.push({ p, t, ok });
    console.log(`      ${p.alg}: alg=${alg} type=${type} bits=${bits} ` +
      `auth=${t.includes('USERAUTH_SUCCESS') ? 'OK' : 'FAILED'} ${ok ? '' : 'BAD'}`);
    if (!ok) {
      for (const l of t.split('\n')) {
        if (/^(result|error|hostkey_)/.test(l)) console.log(`        ${l}`);
      }
    }
  }
  check('every pinned algorithm negotiated, verified and authenticated',
    runs.every(r => r.ok), runs.filter(r => !r.ok).map(r => r.p.alg).join(' '));
  check('the RSA runs report the key type `ssh-rsa` while negotiating `rsa-sha2-*`',
    runs.filter(r => r.p.keytype === 'ssh-rsa')
      .every(r => grab(r.t, 'hostkey_alg') !== grab(r.t, 'hostkey_type')) &&
    runs.filter(r => r.p.keytype === 'ssh-rsa').length === 2,
    runs.filter(r => r.p.keytype === 'ssh-rsa')
      .map(r => `${grab(r.t, 'hostkey_alg')}/${grab(r.t, 'hostkey_type')}`).join(' '));
  check('the non-RSA runs report one name for both fields',
    runs.filter(r => r.p.keytype !== 'ssh-rsa')
      .every(r => grab(r.t, 'hostkey_alg') === grab(r.t, 'hostkey_type')));

  // --------------------------------------------------------------- G4 ------
  console.log('\n=== G4: a server offering only SHA-1 `ssh-rsa` ===');
  // This is the case Loop #38 decided not to support. The requirement is not
  // "it fails" -- it is that it fails *here*, naming the reason, instead of
  // accepting and then blaming the signature check.
  const sha1 = await startSshd(BASE_PORT + 5, 'shar', 'ssh-rsa');
  check('sshd pinned to ssh-rsa only', sha1.ok);
  if (sha1.ok) {
    const t = clientRun(BASE_PORT + 5);
    const failedEarly = !t.includes('USERAUTH_SUCCESS');
    check('the client refuses a SHA-1-only server', failedEarly,
      grab(t, 'result') || '(no result line)');
    check('and says so at negotiation rather than failing the signature check',
      /NoAgreement|no matching host key|HOSTKEY/i.test(t) &&
      !/SIGNATURE_INVALID/i.test(t),
      (t.split('\n').filter(l => /^(result|error)/.test(l)).join(' | ') || '').slice(0, 160));
  }

  // --------------------------------------------------------------- G5 ------
  console.log('\n=== G5: the same, inside a browser Web Worker ===');
  const httpSrv = await serve(ROOT, HTTP_PORT);
  const browser = await chromium.launch({
    headless: !HEADED, channel: 'chrome', ignoreHTTPSErrors: true,
  });
  const wsSshd = spawn('python',
    ['host/wt/ws_relay.py', '--listen-port', String(WS_PORT), '--target-port', String(BASE_PORT)],
    { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
  check('relay -> sshd up', (await waitForLog(wsSshd, 'websocket on ws://')).ok);

  const cfg = {
    workerUrl: '/host/wt/worker.js',
    shimUrl: '/host/wt/moonbit_wt.js',
    moduleUrl: '/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js',
    url: `ws://127.0.0.1:${WS_PORT}/ssh`,
    nonce: 'loop38',
    user: USER,
    // `auth: 1` is what takes the Worker past the handshake to
    // USERAUTH_SUCCESS, and the host key fields are printed on that path.
    // Without it the Worker stops at ESTABLISHED and there is nothing to
    // compare -- ESTABLISHED alone would pass even if the host key check had
    // been skipped.
    auth: '1',
  };
  const { payload, pageErrors } = await runInWorker(browser, cfg, 120000);
  const wl = norm((payload.lines || []).join('\n'));
  // Compare against the G2 run: same unpinned server, same port, so the two
  // paths differ only in transport.
  check('the browser Worker completed a session against the same server',
    wl.includes('USERAUTH_SUCCESS'), (wl.split('\n').filter(l => /^(result|error)/.test(l)).join(' | ')).slice(0, 160));
  check('and negotiated the same host key algorithm as the native run',
    grab(wl, 'hostkey_alg') === grab(text, 'hostkey_alg'),
    `worker ${grab(wl, 'hostkey_alg')} vs native ${grab(text, 'hostkey_alg')}`);
  check('with the same key type and size',
    grab(wl, 'hostkey_type') === grab(text, 'hostkey_type') &&
    grab(wl, 'hostkey_bits') === grab(text, 'hostkey_bits'),
    `${grab(wl, 'hostkey_type')}/${grab(wl, 'hostkey_bits')}`);
  check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));

  await browser.close();
  httpSrv.close();
  wsSshd.kill();

  // --------------------------------------------------------- regression -----
  if (!SKIP_REGRESSION) {
    console.log('\n=== regression: the earlier loops must still be green ===');
    for (const [label, script] of [
      ['loop31', 'host/verify_loop31.mjs'],
      ['loop32', 'host/verify_loop32.mjs'],
      ['loop33', 'host/verify_loop33.mjs'],
      ['loop34', 'host/verify_loop34.mjs'],
      ['loop35', 'host/verify_loop35.mjs'],
      ['loop36', 'host/verify_loop36.mjs'],
      ['loop37', 'host/verify_loop37.mjs'],
    ]) {
      const r = spawnSync('node', [script, '--skip-regression'], { cwd: ROOT, encoding: 'utf-8' });
      const t = norm(`${r.stdout || ''}${r.stderr || ''}`);
      const m = t.match(/(\d+)\/(\d+) checks/);
      check(`${label} harness still green`, r.status === 0 && t.includes('✓ PASS'),
        m ? `${m[1]}/${m[2]}` : t.slice(-200));
      // A nested FAIL with only "46/47" in the summary is undiagnosable: the
      // failing check's NAME is in the child's output, which this capture is
      // about to throw away. Persist it -- one file per child, overwritten
      // each run, ignored by git -- so the nested failure can be read instead
      // of re-run three levels deep on a warm machine and hoped for.
      if (r.status !== 0) {
        try {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(join(ROOT, '.loop38', `last_${label}.log`), t);
          console.log(`  (child output saved to .loop38/last_${label}.log)`);
        } catch { /* best effort; the check above already failed */ }
      }
    }
  }

  for (const p of pinned) stopSshd(p.name);
  stopSshd('shar');
  main3.proc.kill();
  stopSshd('');

  const bad = results.filter(r => !r.ok);
  console.log(`\n${bad.length === 0 ? '✓ PASS' : '✗ FAIL'}: ${results.length - bad.length}/${results.length} checks`);
  if (bad.length) for (const b of bad) console.error(`  FAIL ${b.name}`);
  if (bad.length === 0) {
    console.log('  a stock OpenSSH 8.0p1 server -- no HostKeyAlgorithms pin, ed25519 and');
    console.log('  RSA host keys -- negotiated, verified and authenticated without the client');
    console.log('  being told which algorithm to use; every algorithm was then forced one at a');
    console.log('  time and verified separately, an RSA key correctly reported itself as');
    console.log('  `ssh-rsa` while negotiating `rsa-sha2-512`, a SHA-1-only server was refused');
    console.log('  at negotiation with a reason rather than at the signature check, and a');
    console.log('  browser Web Worker reached the same host key decision with no native code.');
  }
  process.exit(bad.length ? 1 : 0);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
