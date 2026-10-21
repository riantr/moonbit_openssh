#!/usr/bin/env node
// verify_loop40.mjs -- Loop #40: the SFTP write side
//
//   Loop #39 could read.  It could not write, which for an SFTP client is
//   roughly half the protocol: a transfer tool that only downloads is a
//   different tool from one that syncs.
//
//   G1  The KAT: 24 session cases + 7 buffer cases over four backends and two
//       modes, byte-identical.  The write-side inbound packets are real
//       OpenSSH 8.0p1 `internal-sftp` replies recorded by
//       host/sftp_write_capture.py.
//
//   G2  The write capture and the independent Python oracle agree with the
//       committed vectors.  Regenerating must produce no diff, or the KAT has
//       quietly stopped describing the protocol.
//
//   G3  Thirty mutations of src/sftp -- eleven of them the write-side
//       decisions this loop argued about -- all of them must turn the KAT red.
//
//   G4  A real `internal-sftp` doing a real round trip: create, write 40 KB,
//       read it back and compare the digest against the same bytes computed
//       here in JavaScript, rename, overwrite the renamed file through
//       `posix-rename@openssh.com`, read *that* back, then remove and rmdir.
//
//   G5  The same write side inside a browser Web Worker, over a WebSocket
//       relay to the same sshd.
//
//   G6  Loop #31 .. #39 still pass.
//
//   Usage: node host/verify_loop40.mjs [--skip-regression] [--headed]
//          [--skip-worker]

import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import net from 'node:net';
import { createHash } from 'node:crypto';
import { readFile, stat, writeFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sshUser } from './ssh_user.mjs';
import { chromium } from 'playwright';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HEADED = process.argv.includes('--headed');
const SKIP_REGRESSION = process.argv.includes('--skip-regression');
const SKIP_WORKER = process.argv.includes('--skip-worker');

// Loop #39 used 18782 / 8782; loop40 takes the next pair so a stray listener
// from a previous run cannot silently satisfy this one.
const HTTP_PORT = 18784;
const WS_PORT = 8784;
const SSHD_PORT = 18783;
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
const LIVE_DIR = join(ROOT, '.loop40', 'live');

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
const hashOut = out => createHash('sha256').update(norm(out)).digest('hex').slice(0, 16);

// The payload `cmd/ssh_live` and `cmd/wt_ssh` build from a length alone.
//
// This has to be the *same* rule, not merely a similar one: the digests below
// are what prove the client's bytes survived the round trip, and a rule that
// drifted by one constant would produce a digest mismatch that looks exactly
// like a transport bug.  If this ever has to change, change both drivers in
// the same commit -- the KAT's `wrote=` counts will not notice, only this.
function payload(n) {
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i += 1) b[i] = (i * 31 + 7) % 256;
  return b;
}
const sha = b => createHash('sha256').update(b).digest('hex').toUpperCase();

const OP_PREFIX = /^op\d+(_[a-z0-9_]+)?: /;
function opLines(text) {
  return text.split('\n').filter(l => OP_PREFIX.test(l)).map(l => l.trim());
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

///| 起一个 sshd 并**等到它真的在监听**。
///|
/// 固定 sleep 是一个会在冷编译时咬人的做法:变异检查刚把 `_build` 打冷,
/// 前面那一步比平时慢好几秒,2.5 秒之后 sshd 还没 listen,于是整段报
/// CONNECT_FAILED——而报告看起来像客户端坏了。
///
/// 这里**必须**是异步 `spawn`:sshd_setup.mjs 起的是 `sshd -D`,前台永驻,
/// 收尾是 `await new Promise(() => {})`,自己永不返回。`spawnSync` 会一直
/// 等它退出,整条门禁就停在那里、CPU 为零、没有任何输出(实测卡了 27 分钟)。
/// Loop #39 换过一次,换成了 spawnSync;这里是从根上修掉。
async function startSshd(port) {
  const child = spawn('cmd',
    ['/c', 'node', 'host/sshd_setup.mjs', '--port', String(port)],
    { cwd: ROOT, stdio: 'ignore', detached: false });
  child.unref();
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    const up = await new Promise(resolve => {
      const sock = net.connect({ host: '127.0.0.1', port });
      sock.once('connect', () => { sock.destroy(); resolve(true); });
      sock.once('error', () => resolve(false));
      sock.setTimeout(500, () => { sock.destroy(); resolve(false); });
    });
    if (up) return true;
    await new Promise(r => setTimeout(r, 250));
  }
  return false;
}

///| 等一个子进程在 stdout 里打出某个标记,而不是猜它起好了没有。
function waitForLog(child, needle, timeoutMs = 20000) {
  return new Promise(resolve => {
    let buf = '';
    const done = ok => resolve({ ok });
    const t = setTimeout(() => done(false), timeoutMs);
    const onData = d => {
      buf += d.toString();
      if (buf.includes(needle)) {
        clearTimeout(t);
        child.stdout.off('data', onData);
        done(true);
      }
    };
    child.stdout.on('data', onData);
    child.on('exit', () => { clearTimeout(t); done(false); });
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
            // The config goes to the Worker **flat**, which is what loop38 does
            // and what loop39 does. `worker.js` assigns `e.data` straight to
            // `__wt_cfg` and MoonBit reads keys off it via `cfg("url")`, so
            // wrapping it as `{..., cfg: c}` makes every lookup miss and the
            // run dies on an empty transport URL -- indistinguishable, from
            // the outside, from a relay that never came up.
            w.postMessage(c);
            latest = { done: false, lines: [] };
          }, 50);
          const w2 = setTimeout(() => {
            if (!latest.done) {
              clearTimeout(t);
              resolve(latest);
            }
          }, c.timeoutMs - 5000);
          void w2;
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
  console.log('=== Loop #40: SFTP write side ===\n');
  console.log('The load-bearing claim on this side is the WRITE offset.  A wrong');
  console.log('offset is not a rejected request -- `process_write` does');
  console.log('lseek(fd, off, SEEK_SET) first (sftp-server.c:865-866), so the');
  console.log('server writes the bytes somewhere else and answers STATUS(OK).');
  console.log('The file then has a plausible length and the wrong contents, and');
  console.log('every status code on the wire says everything worked.');
  console.log('');

  await mkdir(LIVE_DIR, { recursive: true });
  const liveAbs = LIVE_DIR.replace(/\\/g, '/');
  const big = payload(40000);
  const small = payload(11);

  // ---- G1: the KAT ------------------------------------------------------
  console.log('--- G1: SFTP KAT, 4 backends x 2 modes ---');
  const capturePath = join(ROOT, '.loop39', 'capture.json');
  const writeCapture = join(ROOT, '.loop40', 'write_capture.json');
  const sshdUp = await startSshd(SSHD_PORT);
  check('sshd came up', sshdUp, 'port ' + SSHD_PORT);

  // Both captures are the point of this loop, so regenerate whichever is
  // missing: a fresh clone has no bytes from a real server, and a KAT built
  // from our own encoder would be testing our encoder against itself.
  if (!existsSync(capturePath)) {
    const cap = spawnSync('python', ['host/sftp_capture.py', String(SSHD_PORT), capturePath],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    check('recaptured the read side', cap.status === 0,
      `${cap.stdout || ''}${cap.stderr || ''}`.split('\n').slice(-6).join('\n'));
  }
  if (!existsSync(writeCapture)) {
    const cap = spawnSync('python',
      ['host/sftp_write_capture.py', String(SSHD_PORT), writeCapture],
      { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    check('recaptured the write side', cap.status === 0,
      `${cap.stdout || ''}${cap.stderr || ''}`.split('\n').slice(-10).join('\n'));
  }

  const gen = spawnSync('python', [
    'host/gen_sftp_vectors.py',
    '--capture', capturePath,
    '--write-capture', writeCapture,
  ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const genText = `${gen.stdout || ''}${gen.stderr || ''}`;
  check('the oracle selfcheck is clean', gen.status === 0 && /selfcheck clean/.test(genText),
    genText.split('\n').slice(-12).join('\n'));
  // The generator's own claim that it wrote the same file it would have
  // written last time is the only thing standing between the KAT and a slow
  // drift away from the capture.
  //
  // **The regeneration happens in place, at the package's own path, and the
  // original bytes are restored afterwards.** The first version of this
  // generated to a scratch path and compared the two files byte for byte --
  // and that comparison could never succeed, because of a fact about the
  // toolchain rather than about the generator:
  //
  //   `moon fmt` only formats files that belong to a package of the current
  //   module. For a file anywhere else it exits 0, prints nothing, and
  //   changes nothing. So the committed file (inside `cmd/sftp_test`, a
  //   package) is formatted, and the scratch file (in `.loop40`, which is in
  //   no package at all) is not -- and the two differed by exactly the
  //   formatter's line wrapping, 1290 bytes' worth.
  //
  // Regenerating at the package path means the formatter applies to both
  // sides, so the comparison is about the vectors rather than about the
  // formatting convention. The committed bytes are restored in a `finally`,
  // so the gate never leaves the tree dirty -- including when it fails,
  // which is when leaving it dirty would be least welcome.
  //
  // `git diff` would answer the same question, but only once the file is
  // committed, and on the very first run of a new loop it is by definition
  // not.
  const committedPath = join(ROOT, 'cmd', 'sftp_test', 'vectors.mbt');
  const committedBytes = await readFile(committedPath, 'utf8');
  const gen2 = spawnSync('python', [
    'host/gen_sftp_vectors.py',
    '--capture', capturePath,
    '--write-capture', writeCapture,
  ], { cwd: ROOT, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  check('the generator is deterministic', gen2.status === 0,
    `${gen2.stdout || ''}${gen2.stderr || ''}`.split('\n').slice(-8).join('\n'));
  let regenerated = null;
  try {
    if (gen2.status === 0) {
      regenerated = await readFile(committedPath, 'utf8');
    }
    // Say where they differ, not only that they did.
    let where = '';
    if (regenerated !== null && regenerated !== committedBytes) {
      let i = 0;
      const a = committedBytes;
      const b = regenerated;
      while (i < a.length && i < b.length && a[i] === b[i]) i += 1;
      where = `diverge at char ${i} (committed ${a.length} bytes, regenerated ${b.length})`;
    }
    check(
      'committed vectors still match the oracle',
      regenerated !== null && regenerated === committedBytes,
      where
    );
  } finally {
    // Put the file back exactly as it was. A gate that leaves a generated
    // source file rewritten is a gate that can turn a later run green.
    await writeFile(committedPath, committedBytes, 'utf8');
  }

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
  check('4 target x 2 mode byte-identical',
    runs.every(r => r.status === 0) && runs.every(r => r.hash === refHash),
    runs.every(r => r.hash === refHash)
      ? refHash
      : runs.filter(r => r.hash !== refHash).map(r => `${r.t}/${r.m}=${r.hash}`).join(' '));
  const kat = runs[0].out;
  const katFails = (kat.match(/^FAIL /gm) || []).length;
  check('no KAT assertion failed', katFails === 0, (kat.match(/^FAIL .*/gm) || []).join('\n'));
  check('the KAT covers the write cases', (kat.match(/PASS  (live_write|negative_write|negative_open)/g) || []).length >= 5,
    (kat.match(/PASS  (live_write|negative_write|negative_open)\S*/g) || []).join(' | '));
  check('the two-chunk write is in there', /PASS  live_writefile_two_chunks/.test(kat));
  check('the empty write is in there', /PASS  live_writefile_empty_sends_no_write/.test(kat));
  check('the extension rename is in there', /PASS  live_posix_rename_extension/.test(kat));
  check('the unsupported extension is in there', /PASS  negative_rename_op_unsupported/.test(kat));

  // ---- G2: the capture agrees with paramiko ----------------------------
  console.log('\n--- G2: what the write capture established ---');
  if (existsSync(writeCapture)) {
    const wcap = JSON.parse(await readFile(writeCapture, 'utf8'));
    check('the server advertised posix-rename',
      (wcap.version_ext_names || []).includes('posix-rename@openssh.com'),
      JSON.stringify(wcap.version_ext_names));
    check('posix-rename replaced an existing target',
      wcap.posix_rename_onto_existing && wcap.posix_rename_onto_existing.code === 0,
      JSON.stringify(wcap.posix_rename_onto_existing));
    check('and the file that was in the way really changed',
      wcap.posix2_overwritten === true, JSON.stringify(wcap.posix2_overwritten));
    check('an unknown extension is a clean STATUS(8), not a hang',
      wcap.unknown_extended && wcap.unknown_extended.code === 8,
      JSON.stringify(wcap.unknown_extended));
    // The offsets: strictly increasing, resetting to 0 for the second file.
    // `body` here has the type byte already stripped, so the layout is
    // id(4) + handle string(4 len + 4 data) + offset(8) -- 24 hex chars of
    // header before the offset, not 16.
    const offs = (wcap.c2s_packets || [])
      .filter(p => p.type === 6)
      .map(p => parseInt(p.body.slice(24, 40), 16));
    check('the capture shows WRITE offsets walking the file',
      offs.length > 0 && offs[0] === 0 && offs.slice(1, 8).every((v, i) => v === (i + 1) * 8192),
      offs.slice(0, 8).join(' '));
  } else {
    check('write capture present', false, writeCapture);
  }

  // ---- G3: mutations ----------------------------------------------------
  console.log('\n--- G3: mutation check ---');
  const mut = spawnSync('python', ['host/sftp_mutations.py'],
    { cwd: ROOT, encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 });
  const mutText = `${mut.stdout || ''}${mut.stderr || ''}`;
  const missed = (mutText.match(/^MISSED.*$/gm) || []).length;
  const skippedMut = (mutText.match(/^SKIP.*$/gm) || []).length;
  check('every mutation turned the KAT red',
    mut.status === 0 && missed === 0 && skippedMut === 0,
    mutText.trim().split('\n').slice(-12).join('\n'));
  const caughtCount = (mutText.match(/^CAUGHT/gm) || []).length;
  check('and there are at least thirty of them', caughtCount >= 30, `${caughtCount} caught`);

  // ---- G4: a real internal-sftp, writing --------------------------------
  console.log('\n--- G4: real sshd, real write side ---');
  const d = `${liveAbs}/d`;
  const native = moon([
    'run', 'cmd/ssh_live', '--target', 'native', String(SSHD_PORT),
    '--user', USER, ...PIN_ARGS,
    // Command-line order is the script order: the driver builds the op list
    // while scanning argv.  Get this wrong and the write below runs before
    // the mkdir that creates its directory.
    '--sftp-mkdir', d,
    '--sftp-write', `${d}/a.bin@${big.length}`,
    '--sftp-read', `${d}/a.bin`,
    '--sftp-rename', `${d}/a.bin@${d}/b.bin`,
    '--sftp-write', `${d}/c.bin@${small.length}`,
    // The whole point of the extension: v3 RENAME must refuse this.
    '--sftp-rename', `${d}/c.bin@${d}/b.bin`,
    '--sftp-read', `${d}/b.bin`,
    '--sftp-remove', `${d}/b.bin`,
    '--sftp-rmdir', d,
    '--sftp-missing',
  ]);
  const natText = runText(native);
  console.log(opLines(natText).map(l => `    ${l}`).join('\n'));

  check('the write-side session completed', /result: SFTP_DONE/.test(natText), natText.slice(-700));
  check('MKDIR was accepted', /^op1: CHANGED$/m.test(natText), opLines(natText).join(' | '));
  check('the 40 KB write reports every byte',
    /^op2: WROTE$/m.test(natText) && grabInt(natText, 'op2_bytes') === big.length,
    `${grab(natText, 'op2')} / ${grab(natText, 'op2_bytes')}`);
  check('the read-back is the right length',
    /^op3: CONTENTS$/m.test(natText) && grabInt(natText, 'op3_len') === big.length,
    `${grab(natText, 'op3')} / ${grab(natText, 'op3_len')}`);
  // The single most important assertion in this file.  If the client had sent
  // "bytes still to send" as the offset, or restarted the offset each chunk,
  // the file would still be 40000 bytes long and this digest would differ.
  check('the read-back digest matches bytes computed independently here',
    grab(natText, 'op3_sha256') === sha(big),
    `${grab(natText, 'op3_sha256')} != ${sha(big)}`);
  check('the v3-style rename was accepted (it becomes the extension)',
    /^op4: CHANGED$/m.test(natText), opLines(natText).join(' | '));
  check('the 11-byte overwrite was accepted',
    /^op5: WROTE$/m.test(natText) && grabInt(natText, 'op5_bytes') === small.length,
    `${grab(natText, 'op5')} / ${grab(natText, 'op5_bytes')}`);
  check('renaming onto an existing target was accepted',
    /^op6: CHANGED$/m.test(natText), opLines(natText).join(' | '));
  // ...and the target really is the 11-byte file now.  This is what makes
  // "accepted" mean something: a v3 RENAME that was quietly ignored would
  // leave the 40000-byte file in place and read *that* back.
  check('the overwritten target is now the 11-byte file',
    /^op7: CONTENTS$/m.test(natText) && grabInt(natText, 'op7_len') === small.length,
    `${grab(natText, 'op7')} / ${grab(natText, 'op7_len')}`);
  check('and its digest is the 11-byte one',
    grab(natText, 'op7_sha256') === sha(small),
    `${grab(natText, 'op7_sha256')} != ${sha(small)}`);
  check('REMOVE was accepted', /^op8: CHANGED$/m.test(natText), opLines(natText).join(' | '));
  check('RMDIR was accepted', /^op9: CHANGED$/m.test(natText), opLines(natText).join(' | '));
  check('a missing file is still a STATUS, not a transport failure',
    /^op10: FAILED$/m.test(natText) && grabInt(natText, 'op10_code') === 2,
    `${grab(natText, 'op10')} / ${grab(natText, 'op10_code')}`);
  // One write of 40 KB at a 32768-byte chunk is two WRITEs plus an OPEN and a
  // CLOSE; the whole script is well over that, and a client that silently
  // wrote everything in one packet would show up here.
  check('the 40 KB write really took more than one WRITE',
    grabInt(natText, 'requests_sent') >= 20, grab(natText, 'requests_sent'));

  // ---- G5: the same in a browser Worker --------------------------------
  if (!SKIP_WORKER) {
    console.log('\n--- G5: inside a browser Web Worker ---');
    const jsBuild = moon(['build', 'cmd/wt_ssh', '--target', 'js']);
    check('cmd/wt_ssh builds for js',
      jsBuild.status === 0 && !/^\s*Error:/m.test(jsBuild.stdout + jsBuild.stderr),
      runText(jsBuild).slice(-300));

    const server = await serve(ROOT, HTTP_PORT);
    let browser = null;
    try {
      browser = await chromium.launch({ headless: !HEADED });
    } catch (e) {
      console.log(`  SKIP  the Worker run: ${String(e).split('\n')[0]}`);
      console.log('        (install it with: node node_modules/playwright/cli.js install chromium)');
      skipped.push('G5 browser Worker (chromium not installed)');
    }
    // The relay has to exist before the Worker is started, and its absence
    // is a silent failure: the Worker just never finishes and the run looks
    // like a browser bug.  Loop #39 forgot to start it, which is why its G5
    // had never actually passed.
    let relay = null;
    if (browser) {
      relay = spawn('python',
        ['host/wt/ws_relay.py', '--listen-port', String(WS_PORT), '--target-port', String(SSHD_PORT)],
        { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
      const up = await waitForLog(relay, 'websocket on ws://');
      check('the websocket relay to sshd came up', up.ok,
        'python host/wt/ws_relay.py --listen-port ' + WS_PORT + ' --target-port ' + SSHD_PORT);
    }
    if (browser && relay) {
      const wd = `${liveAbs}/w`;
      const cfg = {
        workerUrl: '/host/wt/worker.js',
        shimUrl: '/host/wt/moonbit_wt.js',
        moduleUrl: '/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js',
        url: `ws://127.0.0.1:${WS_PORT}/ssh`,
        nonce: 'loop40',
        user: USER,
        // Loop #50: the same default, on the browser side. The Worker
        // has to be told to accept a key explicitly, exactly like the native
        // driver above.
        kh_tofu: '1',
        kh_host: '127.0.0.1',
        sftp_mkdir: wd,
        sftp_write: `${wd}/f.bin`,
        sftp_write_size: String(big.length),
        sftp_read: `${wd}/f.bin`,
        sftp_remove: `${wd}/f.bin`,
        sftp_rmdir: wd,
        sftp_missing: '1',
        timeoutMs: 240000,
      };
      const { payload, pageErrors } = await runInWorker(browser, cfg, 240000);
      const wtLines = (payload.lines || []).join('\n');
      console.log(opLines(wtLines).map(l => `    ${l}`).join('\n'));
      // On failure the op lines are usually *absent*, because the run died
      // before the first one -- so print the head too.  "no op lines" and
      // "the ops were not reached" are different bugs and the difference
      // lives in these first few lines.
      if (!/^op\d/m.test(wtLines)) {
        console.log('    (no op lines; the Worker output was:)');
        console.log(wtLines.split('\n').slice(0, 12).map(l => `    ${l}`).join('\n'));
      }

      check('the Worker finished', payload.done === true,
        JSON.stringify(payload.result || {}).slice(0, 300));
      check('the Worker created the directory', /^op1: CHANGED$/m.test(wtLines),
        opLines(wtLines).join(' | '));
      check('the Worker wrote every byte',
        /^op2: WROTE$/m.test(wtLines) && grabInt(wtLines, 'op2_bytes') === big.length,
        `${grab(wtLines, 'op2')} / ${grab(wtLines, 'op2_bytes')}`);
      check('the Worker read the file back at the right length',
        /^op3: CONTENTS$/m.test(wtLines) && grabInt(wtLines, 'op3_len') === big.length,
        `${grab(wtLines, 'op3')} / ${grab(wtLines, 'op3_len')}`);
      // The browser path is the reason the payload rule is duplicated: this
      // digest can only match if the Worker produced the same bytes the
      // native path did, from the same short arithmetic.
      check('the Worker read it back byte for byte',
        grab(wtLines, 'op3_sha256') === sha(big),
        `${grab(wtLines, 'op3_sha256')} != ${sha(big)}`);
      check('the Worker removed and rmdir-ed',
        /^op4: CHANGED$/m.test(wtLines) && /^op5: CHANGED$/m.test(wtLines),
        opLines(wtLines).join(' | '));
      check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));

      // Field-for-field on what both transports ran.  `total_*_bytes` are
      // excluded on purpose: they count the encrypted stream, and the two
      // transports carry the same SFTP bytes inside different SSH packets and
      // a different number of WebSocket frames.
      const same = [];
      for (const key of ['result', 'version', 'extensions', 'op1', 'op2', 'op2_bytes', 'op3', 'op3_len', 'op3_sha256']) {
        const a = grab(wtLines, key);
        const b = grab(natText, key);
        if (a === undefined || b === undefined) continue;
        if (a !== b) same.push(`${key}: ${a} != ${b}`);
      }
      check('the Worker matched the native write side on every shared field',
        same.length === 0, same.join(' | '));
    }
    if (browser) await browser.close();
    if (relay) relay.kill();
    server.close();
  }

  // ---- regression -------------------------------------------------------
  if (!SKIP_REGRESSION) {
    console.log('\n--- G6: regression, Loop #31 .. #39 ---');
    for (const n of [31, 32, 33, 34, 35, 36, 37, 38, 39]) {
      const path = join(ROOT, 'host', `verify_loop${n}.mjs`);
      if (!existsSync(path)) {
        check(`loop${n} present`, false, path);
        continue;
      }
      const r = spawnSync('cmd', ['/c', 'node', path], {
        cwd: ROOT, encoding: 'utf8', maxBuffer: 128 * 1024 * 1024,
      });
      const text = `${r.stdout || ''}${r.stderr || ''}`;
      const m = text.match(/(\d+)\/(\d+) passed/) || text.match(/ALL PASS \((\d+) checks\)/);
      check(`loop${n} still passes`, r.status === 0, m ? m[0] : text.slice(-400));
      // loop39 runs its own regression (loop31..38, each of which runs its
      // own browser section and mutation pass). When it fails, its stdout is
      // the only place the real cause lives -- and the summary line above
      // says nothing about which grandchild broke. Persist the whole thing,
      // one file per child, before the diagnosis needs a third re-run.
      if (r.status !== 0) {
        try {
          const { writeFileSync } = await import('node:fs');
          writeFileSync(join(ROOT, '.loop40', `last_loop${n}.log`), text);
          console.log(`  (child output saved to .loop40/last_loop${n}.log)`);
        } catch { /* best effort; the check above already failed */ }
      }
    }
  }

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