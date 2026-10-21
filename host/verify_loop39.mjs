#!/usr/bin/env node
// verify_loop39.mjs -- Loop #39: SFTP over a subsystem channel
//
//   Exec and the interactive shell both worked against a real sshd.  SFTP is
//   the third channel request type and it was missing entirely -- which meant
//   "this client can talk to a server" had never included the thing most
//   deployments actually use.
//
//   G1  The KAT: 14 session cases + 7 buffer cases over four backends and two
//       modes, byte-identical.  Every inbound packet is a real OpenSSH 8.0p1
//       `internal-sftp` reply recorded by host/sftp_capture.py, and the
//       expected requests were cross-checked against the frames paramiko
//       actually sent in the same session.
//
//   G2  Nineteen mutations of src/sftp, each of them one decision this loop
//       argued about, all of them must turn the KAT red.
//
//   G3  A real `internal-sftp` with the realpath / listdir / read /
//       missing-file script, and every answer compared against what paramiko's
//       own SFTPClient returned for the same fixture.
//
//   G4  A subsystem name the server does not have.  `subsystem` is
//       want_reply=TRUE (clientloop.c:2799-2811), so the refusal is a
//       CHANNEL_FAILURE and it is the *only* signal that the name was wrong
//       (session.c:1945-1948).  If the driver did not wait for it, a typo in
//       sshd_config would present as "SFTP hangs after connecting", which is
//       the single most common SFTP deployment mistake.
//
//   G5  The same script inside a browser Web Worker, against the same server,
//       matching the native transfer field for field.
//
//   Usage: node host/verify_loop39.mjs [--skip-regression] [--headed]
//          [--skip-worker]

import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { readFile, stat, writeFile, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sshUser } from './ssh_user.mjs';
import { chromium } from 'playwright';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HEADED = process.argv.includes('--headed');
const SKIP_REGRESSION = process.argv.includes('--skip-regression');
const SKIP_WORKER = process.argv.includes('--skip-worker');

// Loop #37 used 18779 / 8779 / 22270, Loop #38 used 18780 / 8780 / 22275-22280.
const HTTP_PORT = 18782;
const WS_PORT = 8782;
const SSHD_PORT = 18781;
// The account this gate authenticates as: the one this machine runs as.
//
// Writing one developer's account name here made every gate that opens a real
// OpenSSH server pass on that machine and fail on every other one -- and the
// failure looked like a protocol bug, because the server's answer to a
// public key it does not accept is "no", and the client reports that as an
// authentication rejection. See host/ssh_user.mjs.
const USER = sshUser();

// The host key pin, for both drivers.
//
// Loop #50 made REFUSING an unpinned host the default, so a client that
// reaches a real server without a pin is turned away before it can
// authenticate. The gates in this tier were written before that default
// existed and were never updated, so every one of them has been failing
// with `HostkeyUnknown` since -- a failure about pinning, reported as a
// failure about the thing each gate is here to test.
//
// `--known-hosts-text ''` is the explicit "do not pin this time": the key is
// accepted, nothing is stored, and the developer's own known_hosts is never
// touched. The browser side says the same thing with `kh_tofu`, and keeps
// its pin in the IndexedDB store the Worker owns.
const PIN_ARGS = ['--kh-tofu', '--kh-host', '127.0.0.1', '--known-hosts-text', ''];
const FIXTURE_DIR = join(ROOT, '.loop39', 'sftp');

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };

let pass = 0;
const failures = [];
const skipped = [];
function check(name, ok, detail = '') {
  if (ok) {
    pass += 1;
    console.log(`  PASS  ${name}`);
  } else {
    failures.push(name);
    console.log(`  FAIL  ${name}${detail ? `\n        ${String(detail).trim()}` : ''}`);
  }
}

function moon(args) {
  const r = spawnSync('cmd', ['/c', 'moon', ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}
const norm = s => `${s}`.replace(/\r\n/g, '\n');
const runText = r => norm(`${r.stdout}${r.stderr}`);
const grab = (t, k) => (t.match(new RegExp(`^${k}: (.*)$`, 'm')) || [])[1];
const grabInt = (t, k) => {
  const v = grab(t, k);
  return v === undefined ? undefined : Number(v);
};
const hashOut = out =>
  createHash('sha256').update(norm(out)).digest('hex').slice(0, 16);

// The fields both transports must agree on, byte for byte.  Anything not in
// this list is deliberately excluded: `total_*_bytes` count the encrypted
// stream, and the two transports carry the same SFTP bytes inside different
// SSH packets and a different number of WebSocket frames.
const TRANSFER_FIELDS = [
  'result',
  'version',
  'extensions',
  'requests_sent',
  'replies_recv',
  'sftp_bytes_in',
];
const OP_PREFIX = /^op\d+(_[a-z0-9_]+)?: /;

function transferFields(text) {
  const out = [];
  for (const key of TRANSFER_FIELDS) {
    const v = grab(text, key);
    if (v !== undefined) out.push(`${key}: ${v}`);
  }
  for (const line of text.split('\n')) {
    if (OP_PREFIX.test(line)) out.push(line.trim());
  }
  return out;
}

function serve(root, port) {
  return new Promise((resolve, reject) => {
    const s = createServer(async (req, res) => {
      try {
        const p = normalize(decodeURIComponent(new URL(req.url, 'http://x').pathname))
          .replace(/^[/\\]+/, '');
        const f = join(root, p);
        if (!f.startsWith(root)) {
          res.writeHead(403);
          res.end();
          return;
        }
        const st = await stat(f);
        if (!st.isFile()) {
          res.writeHead(404);
          res.end();
          return;
        }
        res.writeHead(200, { 'Content-Type': MIME[extname(f)] || 'application/octet-stream' });
        res.end(await readFile(f));
      } catch {
        res.writeHead(404);
        res.end();
      }
    });
    s.on('error', reject);
    s.listen(port, '127.0.0.1', () => resolve(s));
  });
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

// ---------------------------------------------------------------------------

///| 起一个 sshd 并**等到它真的在监听**。
///|
///| 固定 sleep 是一个会在冷编译时咬人的做法:变异检查刚把 `_build` 打冷,
///| 前面那一步比平时慢好几秒,2.5 秒之后 sshd 还没 listen,于是 G3 整段
///| 报 CONNECT_FAILED ——而报告看起来像客户端坏了。探测端口把「等到了服务」
///| 变成一个事实,而不是一个猜测。
async function startSshd(port) {
  /// 这里**必须**是异步 `spawn` 而不是 `spawnSync`:sshd_setup.mjs 起的是
  // `sshd -D`,前台永驻,收尾是 `await new Promise(() => {})`,自己永不返回。
  // spawnSync 会一直等它退出,于是整条门禁停在那里、CPU 为零、没有任何输出——
  // 看起来像在跑,其实已经死了(实测卡了 27 分钟)。异步 spawn 把收尾留给 --stop。
  const child = spawn(
    'cmd',
    ['/c', 'node', 'host/sshd_setup.mjs', '--port', String(port)],
    { cwd: ROOT, stdio: 'ignore', detached: false },
  );
  child.unref();
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const up = await new Promise(resolve => {
      const sock = net.connect({ host: '127.0.0.1', port });
      sock.once('connect', () => {
        sock.destroy();
        resolve(true);
      });
      sock.once('error', () => resolve(false));
      sock.setTimeout(500, () => {
        sock.destroy();
        resolve(false);
      });
    });
    if (up) return true;
    await new Promise(r => setTimeout(r, 250));
  }
  return false;
}

const SSH_DIR = join(ROOT, '.loop31', 'sshd');

async function main() {
  console.log('=== Loop #39: SFTP / subsystem ===\n');
  console.log('A note on why the KAT is built from a capture rather than from the');
  console.log('draft.  Two facts this loop would have gotten wrong otherwise are');
  console.log('only visible on the wire:');
  console.log('  * the reply numbers are 101 STATUS / 102 HANDLE / 103 DATA /');
  console.log('    104 NAME / 105 ATTRS -- the same five numbers the draft lists');
  console.log('    sorted by name, which is what an implementer writes from memory;');
  console.log('  * STATUS carries a language tag after the message, so demanding');
  console.log('    end-of-packet before reading it fails on every STATUS a real');
  console.log('    server sends, including the FX_EOF that ends a read.');
  console.log('');

  // ---- the fixture ------------------------------------------------------
  await mkdir(FIXTURE_DIR, { recursive: true });
  await mkdir(join(FIXTURE_DIR, 'sub'), { recursive: true });
  const small = Buffer.from('hello sftp\n');
  const big = Buffer.alloc(200000);
  for (let i = 0; i < big.length; i += 1) big[i] = (i * 7 + 3) % 251;
  await writeFile(join(FIXTURE_DIR, 'small.txt'), small);
  await writeFile(join(FIXTURE_DIR, 'big.txt'), big);
  await writeFile(join(FIXTURE_DIR, 'sub', 'a.txt'), Buffer.from('A'.repeat(10)));
  await writeFile(join(FIXTURE_DIR, 'sub', 'b.txt'), Buffer.from('B'.repeat(20)));
  const fixtureAbs = FIXTURE_DIR.replace(/\\/g, '/');
  const smallPath = `${fixtureAbs}/small.txt`;
  const bigPath = `${fixtureAbs}/big.txt`;

  // ---- G1: the KAT ------------------------------------------------------
  console.log('--- G1: SFTP KAT, 4 backends x 2 modes ---');
  // The capture is the whole point of this loop, so regenerate it when it is
  // missing: a fresh clone has no bytes from a real server, and a KAT built
  // from our own encoder would be testing our encoder against itself.
  const capturePath = join(ROOT, '.loop39', 'capture.json');
  if (!existsSync(capturePath)) {
    const sshdUp = await startSshd(SSHD_PORT);
    check('sshd came up for the capture', sshdUp, 'port ' + SSHD_PORT);
    const cap = spawnSync('python', ['host/sftp_capture.py', String(SSHD_PORT), capturePath, fixtureAbs], {
      cwd: ROOT,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    check('recaptured a live internal-sftp session', cap.status === 0,
      `${cap.stdout || ''}${cap.stderr || ''}`.split('\n').slice(-8).join('\n'));
    spawnSync('cmd', ['/c', 'node', 'host/sshd_setup.mjs', '--stop'], { cwd: ROOT, stdio: 'ignore' });
  }
  const gen = spawnSync('python', ['host/gen_sftp_vectors.py', '--capture', capturePath], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  check('vector generator runs', gen.status === 0, `${gen.stdout || ''}${gen.stderr || ''}`);
  const diff = spawnSync('git', ['diff', '--stat', '--', 'cmd/sftp_test/vectors.mbt'], {
    cwd: ROOT,
    encoding: 'utf8',
  });
  check(
    'committed vectors still match the oracle',
    (diff.stdout || '').trim() === '',
    (diff.stdout || '').trim()
  );

  const TARGETS = ['native', 'js', 'wasm', 'wasm-gc'];
  const MODES = ['debug', 'release'];
  const runs = [];
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(['run', 'cmd/sftp_test', '--target', t, '-d', m]);
      const out = runText(r);
      runs.push({ t, m, out, hash: hashOut(out), status: r.status });
    }
  }
  const refHash = runs[0].hash;
  check(
    '4 target x 2 mode byte-identical',
    runs.every(r => r.status === 0) && runs.every(r => r.hash === refHash),
    runs.every(r => r.hash === refHash) ? refHash : runs.filter(r => r.hash !== refHash).map(r => `${r.t}/${r.m}`).join(' ')
  );
  const kat = runs[0].out;
  const katFails = (kat.match(/^FAIL /gm) || []).length;
  check('no KAT assertion failed', katFails === 0, (kat.match(/^FAIL .*/gm) || []).join('\n'));
  check('KAT covers the framing boundaries', (kat.match(/PASS  boundary_/g) || []).length >= 4);
  check('KAT covers the negative cases', (kat.match(/PASS  negative_/g) || []).length >= 3);
  check('the capture really was replayed', /PASS  live_readfile_eof_status/.test(kat));

  // ---- G2: mutations ----------------------------------------------------
  console.log('\n--- G2: mutation check ---');
  const mut = spawnSync('python', ['host/sftp_mutations.py'], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const mutText = `${mut.stdout || ''}${mut.stderr || ''}`;
  const missed = (mutText.match(/^MISSED.*$/gm) || []).length;
  // Named ..._count because line 61 declares the global `skipped` ARRAY this
  // summary appends to. Naming this counter `skipped` shadowed the array with
  // a Number for the whole of main(), and the ending's
  // `for (const s of skipped)` then threw "TypeError: skipped is not
  // iterable" -- but ONLY on the ALL-PASS path, which is why every gate
  // before this saw loop39 print ALL PASS and still exit 1.
  const skippedCount = (mutText.match(/^SKIP.*$/gm) || []).length;
  check('every mutation turned the KAT red', mut.status === 0 && missed === 0 && skippedCount === 0,
    mutText.trim().split('\n').slice(-12).join('\n'));

  // ---- G3: a real internal-sftp ---------------------------------------
  console.log('\n--- G3: real sshd, real internal-sftp ---');
  const sshdUp = await startSshd(SSHD_PORT);
  check('sshd came up before the live run', sshdUp, 'port ' + SSHD_PORT);

  const native = moon([
    'run', 'cmd/ssh_live', '--target', 'native', String(SSHD_PORT),
    '--user', USER, ...PIN_ARGS,
    '--sftp', fixtureAbs,
    '--sftp-read', smallPath,
    '--sftp-read', bigPath,
    '--sftp-missing',
  ]);
  const natText = runText(native);
  console.log(natText.split('\n').filter(l => /^(result|version|extensions|requests_sent|replies_recv|sftp_bytes_in|op\d)/.test(l)).map(l => `    ${l}`).join('\n'));

  check('native SFTP session completed', /result: SFTP_DONE/.test(natText), natText.slice(-600));
  check('server protocol version is 3', grabInt(natText, 'version') === 3, grab(natText, 'version'));
  // Six on OpenSSH 8.0p1.  Asserted rather than hard-coded into the parser:
  // the count is the server's, and a newer one sends more.
  check('VERSION extension pairs were consumed, not rejected',
    grabInt(natText, 'extensions') === 6, grab(natText, 'extensions'));

  check('REALPATH answered', /^op0: REALPATH$/m.test(natText));
  // The realpath is printed as hex, so decode before comparing.  paramiko
  // reported `/C:/Users/hp` for `normalize('.')` on this server.
  const rpHex = grab(natText, 'op0_hex') || '';
  const rpText = /^[0-9a-fA-F]*$/.test(rpHex) && rpHex.length % 2 === 0
    ? Buffer.from(rpHex, 'hex').toString('utf8')
    : rpHex;
  // Loop #71: this was /^\/C:\/Users\/hp$/i -- one developer's home directory,
  // asserted as if paramiko would report it on every machine. paramiko's
  // normalize('.') resolves the process's OWN home, so the expectation is not
  // a literal at all: it is whatever this machine's home is, in the
  // /C:/Users/<name> shape sftp converts it to.
  //
  // That makes the check STRICTER as well as portable: before, a machine with
  // a different home passed or failed for reasons unrelated to the code; now
  // the only way to pass is for the client's realpath to match this machine's,
  // and an unset USERPROFILE shows up as a mismatch with both sides printed
  // rather than as a silent pass.
  const homeFwd = (process.env.USERPROFILE || '').replace(/\\/g, '/');
  const expectedRp = '/C:/' + homeFwd.replace(/^[A-Za-z]:\//, '');
  check('the realpath is the one paramiko reported',
    homeFwd !== '' && rpText.toLowerCase() === expectedRp.toLowerCase(),
    `${rpText} vs ${expectedRp}`);

  check('LISTING answered', /^op1: LISTING$/m.test(natText));
  check('the directory has the three entries we created', grabInt(natText, 'op1_count') === 3,
    grab(natText, 'op1_count'));
  const entries = (natText.match(/^op1_entry\d+: (.*)$/gm) || []).map(s => s.replace(/^op1_entry\d+: /, ''));
  const names = entries.map(e => Buffer.from(e.split(' ')[0], 'hex').toString());
  check('every expected name is listed',
    ['big.txt', 'small.txt', 'sub'].every(n => names.includes(n)), names.join(' '));
  check('the sizes are the ones on disk',
    entries.some(e => e.endsWith(' 11 file')) && entries.some(e => e.endsWith(' 200000 file')),
    entries.join(' | '));
  check('the subdirectory is reported as a directory',
    entries.some(e => e.endsWith(' 0 dir')), entries.join(' | '));

  check('the small file was read whole', grabInt(natText, 'op2_len') === small.length,
    grab(natText, 'op2_len'));
  check('the small file has the right digest',
    grab(natText, 'op2_sha256') === createHash('sha256').update(small).digest('hex').toUpperCase(),
    grab(natText, 'op2_sha256'));

  // The 200 KB read is the interesting one: it has to span many READs, many
  // CHANNEL_DATA packets, and at least one WINDOW_ADJUST back from the server.
  check('the 200 KB file was read whole', grabInt(natText, 'op3_len') === big.length,
    grab(natText, 'op3_len'));
  check('the 200 KB file has the right digest',
    grab(natText, 'op3_sha256') === createHash('sha256').update(big).digest('hex').toUpperCase(),
    grab(natText, 'op3_sha256'));
  check('it really took many round trips', grabInt(natText, 'requests_sent') >= 10,
    grab(natText, 'requests_sent'));

  check('a missing file is a STATUS, not a transport failure', /^op4: FAILED$/m.test(natText));
  check('and the status code is SSH2_FX_NO_SUCH_FILE', grabInt(natText, 'op4_code') === 2,
    grab(natText, 'op4_code'));

  // ---- G4: a subsystem the server does not have ------------------------
  console.log('\n--- G4: subsystem refused (the only signal there is) ---');
  const bad = moon([
    'run', 'cmd/ssh_live', '--target', 'native', String(SSHD_PORT),
    '--user', USER, ...PIN_ARGS, '--subsystem', 'sftp-server', '--sftp-read', smallPath,
  ]);
  const badText = runText(bad);
  check('a wrong subsystem name is refused', /result: SFTP_FAILED/.test(badText), badText.slice(-400));
  check('and the refusal is named as such, not as a dead channel',
    /CHANNEL_FAILED SubsystemRejected/.test(badText),
    (badText.match(/^error: .*$/m) || [])[0] || badText.slice(-400));

  // ---- G5: the same in a browser Worker --------------------------------
  if (!SKIP_WORKER) {
    console.log('\n--- G5: inside a browser Web Worker ---');
    const jsBuild = moon(['build', 'cmd/wt_ssh', '--target', 'js']);
    check('cmd/wt_ssh builds for js', jsBuild.status === 0 && !/^\s*Error:/m.test(jsBuild.stdout + jsBuild.stderr),
      runText(jsBuild).slice(-300));

    const server = await serve(ROOT, HTTP_PORT);
    // The Worker talks WebSocket, the server speaks TCP, and nothing in this
    // file bridged them: G5 pointed the Worker at ws://...:8782/ssh with no
    // listener behind it.  The Worker then simply never finished, which looks
    // exactly like a browser-side bug.  Loop #40 fixes this properly; the same
    // relay belongs here too so the section is not decorative.
    let relay = null;
    // The browser is a prerequisite, not a verdict.  If Playwright's Chromium
    // was never downloaded, say so and keep going -- silently passing a
    // section that never ran would be the one outcome worse than a failure,
    // because it would report the browser path as verified.
    let browser = null;
    try {
      browser = await chromium.launch({ headless: !HEADED });
    } catch (e) {
      console.log(`  SKIP  the Worker run: ${String(e).split('\n')[0]}`);
      console.log('        (install it with: node node_modules/playwright/cli.js install chromium)');
      skipped.push('G5 browser Worker (chromium not installed)');
    }
    if (browser) {
      relay = spawn('python',
        ['host/wt/ws_relay.py', '--listen-port', String(WS_PORT), '--target-port', String(SSHD_PORT)],
        { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
      let relayText = '';
      const relayUp = await new Promise(resolve => {
        const t = setTimeout(() => resolve(false), 20000);
        relay.stdout.on('data', d => {
          relayText += d.toString();
          if (relayText.includes('websocket on ws://')) {
            clearTimeout(t);
            resolve(true);
          }
        });
        relay.on('exit', () => { clearTimeout(t); resolve(false); });
      });
      check('the websocket relay to sshd came up', relayUp, relayText.slice(-200));
      if (!relayUp) {
        // Without the relay the Worker would start, never connect and never
        // finish -- reported as a browser failure.  Say what actually failed.
        skipped.push('G5 browser Worker (relay never came up)');
        await browser.close();
        relay.kill();
        server.close();
        browser = null;
      }
    }
    if (browser) {
    const cfg = {
      workerUrl: '/host/wt/worker.js',
      shimUrl: '/host/wt/moonbit_wt.js',
      moduleUrl: '/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js',
      url: `ws://127.0.0.1:${WS_PORT}/ssh`,
      nonce: 'loop39',
      user: USER,
      // Loop #50: the same default, on the browser side. The Worker
      // has to be told to accept a key explicitly, exactly like the native
      // driver above.
      kh_tofu: '1',
      kh_host: '127.0.0.1',
      sftp: fixtureAbs,
      sftp_read: smallPath,
      sftp_missing: '1',
      timeoutMs: 240000,
    };
    const { payload, pageErrors } = await runInWorker(browser, cfg, 240000);
    const wtLines = (payload.lines || []).join('\n');
    console.log(wtLines.split('\n').filter(l => /^(result|version|extensions|requests_sent|replies_recv|sftp_bytes_in|op\d)/.test(l)).map(l => `    ${l}`).join('\n'));

    // Field-for-field on the part of the script both sides ran.  The native
    // run reads one extra file (the 200 KB one) purely to force many round
    // trips, so `op3` onward is native-only by construction rather than by
    // agreement -- and the Worker's `op3` is the missing-file STATUS.
    const same = [];
    if (grab(wtLines, 'version') !== grab(natText, 'version')) same.push('version');
    if (grab(wtLines, 'extensions') !== grab(natText, 'extensions')) same.push('extensions');
    for (const key of ['op0_hex', 'op1_count', 'op1_entry0', 'op1_entry1', 'op1_entry2',
      'op2_sha256', 'op2_hex', 'op4_code']) {
      const a = grab(wtLines, key);
      const b = grab(natText, key);
      if (a === undefined || b === undefined) continue;
      if (a !== b) same.push(`${key}: ${a} != ${b}`);
    }
    check('the Worker matched the native transfer on every shared field',
      same.length === 0, same.join(' | '));
    check('the Worker finished', payload.done === true, JSON.stringify(payload.result || {}).slice(0, 300));
    check('the Worker did the whole script',
      /op2: CONTENTS/.test(wtLines) && /op3: FAILED/.test(wtLines),
      wtLines.split('\n').filter(l => /^op\d/.test(l)).join('\n'));
    check('the Worker read the file byte for byte',
      grab(wtLines, 'op2_len') === String(small.length) &&
        grab(wtLines, 'op2_sha256') === createHash('sha256').update(small).digest('hex').toUpperCase(),
      `${grab(wtLines, 'op2_len')} / ${grab(wtLines, 'op2_sha256')}`);
    check('the Worker saw the same protocol version and extension count',
      grab(wtLines, 'version') === '3' && grab(wtLines, 'extensions') === '6',
      `${grab(wtLines, 'version')} / ${grab(wtLines, 'extensions')}`);
    check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));

    await browser.close();
    }
    if (relay) relay.kill();
    server.close();
  }

  // ---- regression -------------------------------------------------------
  if (!SKIP_REGRESSION) {
    console.log('\n--- regression: Loop #31 .. #38 ---');
    const scripts = [31, 32, 33, 34, 35, 36, 37, 38];
    for (const n of scripts) {
      const path = join(ROOT, 'host', `verify_loop${n}.mjs`);
      if (!existsSync(path)) {
        check(`loop${n} present`, false, path);
        continue;
      }
      const r = spawnSync('cmd', ['/c', 'node', path], {
        cwd: ROOT,
        encoding: 'utf8',
        maxBuffer: 128 * 1024 * 1024,
      });
      const text = `${r.stdout || ''}${r.stderr || ''}`;
      const m = text.match(/(\d+)\/(\d+) passed/);
      check(`loop${n} still passes`, r.status === 0, m ? m[0] : text.slice(-400));
    }
  }

  // ---- stop the server ---------------------------------------------------
  // `sshd_setup.mjs --stop` owns the pid file and the teardown; the gate used
  // to keep its own handle and kill it here, which was a second way to stop
  // the same process and could only ever disagree with the pid file.
  spawnSync('cmd', ['/c', 'node', 'host/sshd_setup.mjs', '--stop'], { cwd: ROOT, stdio: 'ignore' });

  console.log('');
  if (failures.length === 0) {
    console.log(`ALL PASS (${pass} checks)`);
    for (const s of skipped) console.log(`  (skipped: ${s})`);
    return 0;
  }
  console.log(`${failures.length} FAILURES of ${pass + failures.length}`);
  for (const f of failures) console.log(`  - ${f}`);
  return 1;
}

main().then(
  code => process.exit(code),
  err => {
    console.error(err);
    process.exit(1);
  }
);