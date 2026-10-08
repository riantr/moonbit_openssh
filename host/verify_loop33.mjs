#!/usr/bin/env node
// verify_loop33.mjs -- Loop #33: past NEWKEYS, into the encrypted session
//
//   Loop #31 proved we could compute the same exchange hash a real OpenSSH server
//   computed. Loop #32 proved the same code runs inside a browser. Both stopped
//   at NEWKEYS, with everything on the wire still in plaintext. This loop adds
//   the aes128-ctr + hmac-sha2-256 encrypt-and-MAC layer and then actually uses
//   it, bottom-up so a failure names its own layer:
//
//     G1  The packet layer is byte-exact against two independent SSH
//         implementations, across 4 target x 2 mode.
//         Vectors come from host/ssh_ctrhmac_oracle.py, which refuses to emit
//         anything until its from-spec construction matches paramiko's
//         Packetizer byte for byte. MoonBit is the third opinion.
//
//     G2  Native client against a real OpenSSH 8.0p1 sshd: SERVICE_ACCEPTED.
//         The server decrypted an AES-CTR packet and verified our HMAC-SHA256.
//         No self-consistent local bug can fake this -- a wrong key, counter or
//         MAC shows up as a dropped connection, not a success.
//
//     G3  The same in a browser Web Worker, and the byte counts must match G2
//         exactly. They share every layer except the transport, so any
//         difference means one of them drifted.
//
//   plus the Loop #30/#31 crypto suites and the Loop #32 packet tests re-run, so
//   adding encryption cannot have quietly moved anything it should not have.
//
// 用法: node host/verify_loop33.mjs [--skip-regression] [--headed]

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

const HTTP_PORT = 18771;
const WS_PORT = 8771;
const SSHD_PORT = 22257;

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
  return spawnSync('cmd', ['/c', 'moon', ...args], { cwd: ROOT, encoding: 'utf-8' });
}
function moonCheck(pkg, target) {
  const r = moon(['check', '--target', target, '-p', pkg]);
  const text = `${r.stdout || ''}${r.stderr || ''}`;
  const m = text.match(/(\d+)\s+warnings?,\s*(\d+)\s+errors?/);
  const failed = /^\s*Error:/m.test(text) || (r.status !== 0 && r.status !== null);
  return {
    errors: failed ? (m ? Number(m[2]) : 1) : 0,
    warnings: m ? Number(m[1]) : -1,
    text,
  };
}
function hashOut(out) {
  return createHash('sha256').update(out.replace(/\r\n/g, '\n')).digest('hex').slice(0, 16);
}

// moon 的诊断和程序输出都走这一侧管道,Windows 下又是 CRLF。所有带锚点的
// 正则都假设 LF,所以在边界统一归一化一次,而不是在每处写 \r?$。
const norm = s => `${s}`.replace(/\r\n/g, '\n');

// ------------------------------------------------------------------ oracle --
// Ask Python for the reference wires. The oracle itself refuses to print
// anything unless paramiko agrees with it, so reaching this point already
// means two implementations concur.
function oracleWires() {
  const r = spawnSync('python', ['host/ssh_ctrhmac_oracle.py', '--json'], {
    cwd: ROOT,
    encoding: 'utf-8',
  });
  if (r.status !== 0) throw new Error(`oracle failed: ${r.stderr || r.stdout}`);
  const doc = JSON.parse(r.stdout);
  // Keep the whole case, not just the joined hex: the fixture's shape is part
  // of what these checks mean (see the counter-continuity check below).
  const byCase = {};
  const byName = {};
  for (const c of doc.cases) {
    byCase[c.name] = c.wires.join('');
    byName[c.name] = c;
  }
  return { doc, byCase, byName };
}

async function runInWorker(browser, cfg, timeoutMs) {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', e => pageErrors.push(String(e)));
  await page.goto(`http://127.0.0.1:${HTTP_PORT}/host/wt/probe.html`);
  let payload;
  try {
    // page.evaluate passes exactly one argument into the browser function, so
    // everything it needs travels inside the config object.
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
          // Report progress shortly before the hard timeout so a hang shows the
          // last line MoonBit printed.
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

// --------------------------------------------------------------- regression --
const BASELINE = {
  u128_test: '1bbbc364fb3d5e51',
  fastpow_test: '9707cf997769eddb',
  bigint_test: '12ff7ed89fd9d856',
  kexdh_test: 'afbca72be34dfba2',
  rsa_test: '7382ee95fe7d6677',
  rsa2048_test: 'dffb73d5452ae5e6',
  // Moved in Loop #34 (0e3ec3f7e954bd98 -> d78cd820e9ea2317). The ECDSA
  // signature blob gained the outer `string` wrapper it should always have had
  // (ssh-ecdsa.c:431-432), and cmd/ecdsa_test's build_sig was corrected to
  // construct its negative cases in the same layout -- without that second
  // half every "must be rejected" case would have kept passing for the wrong
  // reason, which is worse than a red suite.
  ecdsa_test: 'd78cd820e9ea2317',
};
const TARGETS = ['native', 'js', 'wasm', 'wasm-gc'];
const MODES = ['debug', 'release'];

async function main() {
  console.log('verify_loop33 -- past NEWKEYS, into the encrypted session\n');

  // ------------------------------------------------------------------- G1 --
  console.log('=== G1: aes128-ctr + hmac-sha2-256 packet layer ===');
  const { byCase, byName } = oracleWires();
  const runs = [];
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(['run', 'cmd/ctrmac_test', '--target', t, '-d', m]);
      const out = `${r.stdout || ''}`;
      runs.push({ t, m, out, hash: hashOut(out) });
    }
  }
  const refHash = runs[0].hash;
  const uniform = runs.every(r => r.hash === refHash);
  check('4 target x 2 mode byte-identical', uniform, refHash);

  const text = runs[0].out;
  const fails = (text.match(/: FAIL\b/g) || []).length;
  check('no KAT assertion failed', fails === 0, `${fails} FAIL`);

  // Compare the emitted wire bytes to the two-implementation oracle, case by
  // case. This is the check that makes "PASS" mean something: self-consistency
  // would pass even if the framing, the MAC input or the MAC length were wrong.
  let wireOk = true;
  const wireDetail = [];
  for (const [name, want] of Object.entries(byCase)) {
    const m = text.match(new RegExp(`ctr_mac_wire_${name}: ([0-9a-f]+)`));
    if (!m || m[1] !== want) {
      wireOk = false;
      wireDetail.push(name);
    }
  }
  check('wire bytes match paramiko-cross-checked oracle', wireOk,
    wireOk ? `${Object.keys(byCase).length} cases` : `differs: ${wireDetail.join(', ')}`);

  for (const probe of ['ctr_mac_tamper_all', 'ctr_mac_emit_all', 'ctr_mac_recv_all', 'ctr_mac_stream_all']) {
    check(`${probe}: PASS`, text.includes(`${probe}: PASS`));
  }
  // Counter continuity is a property of the FIXTURE as much as of the code.
  //
  // If every case only ever emitted one packet, then re-seeding the CTR
  // counter from the IV before each packet would be byte-identical to the
  // correct behaviour -- packet 1 is right either way -- and every check above
  // would still be green. The old version of this line asserted
  // `ctr_mac_emit_svc_request: PASS` and the presence of a wire line, both of
  // which were already implied by the two checks above it, so it could not fail
  // for any reason at all. What actually has to hold:
  //
  //   1. the vector set really contains multi-packet cases, and
  //   2. inside one, the packets are pairwise distinct (a re-seeded counter
  //      would emit packet 2 identical to packet 1), and
  //   3. MoonBit's concatenated stream is the oracle's, packet for packet.
  //
  // (3) is the wire-bytes check above. (1) and (2) are new, and they are what
  // turns (3) into a statement about counter continuity.
  const multi = Object.entries(byName).filter(([, c]) => c.count > 1);
  check('the vector set contains multi-packet cases', multi.length > 0,
    `${multi.length}/${Object.keys(byName).length} cases`);
  const notDistinct = multi.filter(([n, c]) => new Set(c.wires).size !== c.wires.length);
  check('multi-packet cases have pairwise-distinct packets', notDistinct.length === 0,
    notDistinct.length === 0
      ? multi.map(([n, c]) => `${n}x${c.count}`).join(' ')
      : `identical packets in: ${notDistinct.map(([n]) => n).join(', ')}`);
  // And prove the claim end-to-end on the largest case, by cutting MoonBit's
  // concatenated stream into per-packet pieces and comparing each one.
  if (multi.length) {
    const [name, c] = multi.sort((a, b) => b[1].count - a[1].count)[0];
    const got = (text.match(new RegExp(`ctr_mac_wire_${name}: ([0-9a-f]+)`)) || [])[1] || '';
    const slices = [];
    let at = 0;
    let sliceOk = got.length === c.wires.join('').length;
    for (const w of c.wires) {
      slices.push(got.slice(at, at + w.length));
      at += w.length;
    }
    sliceOk = sliceOk && slices.every((s, i) => s === c.wires[i]);
    check(`${name}: ${c.count} packets recovered one by one`, sliceOk,
      sliceOk ? `${c.count} packets` : `stream ${got.length}B vs expected ${c.wires.join('').length}B`);
  }

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    console.log('\n=== regression: earlier crypto suites must not move ===');
    for (const t of TARGETS) {
      const c = moonCheck('src/bpacket', t);
      check(`src/bpacket type-checks on ${t}`, c.errors === 0, `${c.warnings} warnings`);
    }
    // `moon test -p <pkg>` 在这个 moon 版本上把 -p 当成别的选项,恒定报
    // "0 tests",而 0/0 恰好满足下面那个断言——所以这层回归一直在空跑。
    // 正确写法是 PATH 形式,并且要求 total > 0,否则一个「没跑到任何测试」
    // 的包会伪装成全绿。
    const unit = moon(['test', 'src/bpacket']);
    const unitText = norm(`${unit.stdout || ''}${unit.stderr || ''}`);
    const m = unitText.match(/Total tests: (\d+), passed: (\d+), failed: (\d+)/);
    check('src/bpacket unit tests', !!m && Number(m[1]) > 0 && m[2] === m[1] && m[3] === '0',
      m ? `${m[2]}/${m[1]} passed` : unitText.slice(-200));

    for (const [name, want] of Object.entries(BASELINE)) {
      const r = moon(['run', `cmd/${name}`, '--target', 'native']);
      const got = hashOut(`${r.stdout || ''}`);
      check(`${name} unchanged`, got === want, `${got}${got === want ? '' : ` (baseline ${want})`}`);
    }
  }

  // ------------------------------------------------------------------- G2 --
  console.log('\n=== G2: native client past NEWKEYS vs real sshd ===');
  spawnSync('node', ['host/sshd_setup.mjs', '--stop'], { cwd: ROOT });
  const sshd = spawn('node', ['host/sshd_setup.mjs', '--port', String(SSHD_PORT)], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  check('private sshd up', await waitForLog(sshd, 'sshd listening'));

  const nat = moon(['run', 'cmd/ssh_live', '--target', 'native', '--', '--session', String(SSHD_PORT)]);
  const natText = norm(`${nat.stdout || ''}${nat.stderr || ''}`);
  for (const l of natText.split('\n')) if (/^(result|service|accepted|we_need|cipher_ctos|mac_ctos|total_|handshake_)/.test(l)) console.log(`      ${l.trim()}`);
  check('result: SERVICE_ACCEPTED', natText.includes('result: SERVICE_ACCEPTED'));
  check('we_need = 32 (max of key/block/iv/mac)',
    natText.includes('we_need: 32'));
  check('aes128-ctr + hmac-sha2-256 negotiated',
    natText.includes('cipher_ctos: aes128-ctr') && natText.includes('mac_ctos: hmac-sha2-256'));
  check('handshake transcript unchanged (509/753)',
    natText.includes('handshake_sent_bytes: 509') && natText.includes('handshake_recv_bytes: 753'));
  // SERVICE_REQUEST is a 32-byte frame plus a 32-byte MAC; SERVICE_ACCEPT is
  // the same shape. If the MAC were missing these would be 541/805 instead,
  // which is the cheapest way to catch "encrypted except for the tag".
  check('encrypted payloads carry a 32-byte MAC (573/817)',
    natText.includes('total_sent_bytes: 573') && natText.includes('total_recv_bytes: 817'));

  // ------------------------------------------------------------------- G3 --
  console.log('\n=== G3: the same, inside a browser Web Worker ===');
  const httpSrv = await serve(ROOT, HTTP_PORT);
  const browser = await chromium.launch({
    headless: !HEADED,
    channel: 'chrome',
    ignoreHTTPSErrors: true,
  });
  const wsSshd = spawn(
    'python',
    ['host/wt/ws_relay.py', '--listen-port', String(WS_PORT), '--target-port', String(SSHD_PORT)],
    { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] }
  );
  check('relay -> sshd up', await waitForLog(wsSshd, 'websocket on ws://'));

  const { payload, pageErrors } = await runInWorker(
    browser,
    {
      workerUrl: '/host/wt/worker.js',
      shimUrl: '/host/wt/moonbit_wt.js',
      moduleUrl: '/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js',
      url: `ws://127.0.0.1:${WS_PORT}/ssh`,
      nonce: 'loop33',
      session: '1',
    },
    90000
  );
  const lines = (payload.lines || []).join('\n');
  console.log('    --- Worker transcript ---');
  for (const l of payload.lines || []) console.log(`      ${l}`);
  check('result: SERVICE_ACCEPTED in a browser Worker', lines.includes('result: SERVICE_ACCEPTED'));
  check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));
  check('browser byte counts identical to the native driver',
    lines.includes('handshake_sent_bytes: 509') &&
    lines.includes('handshake_recv_bytes: 753') &&
    lines.includes('total_sent_bytes: 573') &&
    lines.includes('total_recv_bytes: 817'));
  // The handshake is NOT reproducible across connections: the server draws a
  // fresh DH exponent every time, so K, the exchange hash and therefore
  // session_id differ between any two runs -- native vs browser included. What
  // must hold is the shape of what each side derived: a 32-hex session_id
  // (16 bytes of a SHA-256) and a key_tag of <enc>/<mac>, both 12 hex chars
  // of a SHA-256 over the session keys.
  // Asserting equality here would be asserting a coincidence, and it would
  // fail the moment the server rotated keys.
  const sidOk = s => /^[0-9a-f]{32}$/.test(s || '');
  const keyOk = s => /^[0-9a-f]{12}\/[0-9a-f]{12}$/.test(s || '');
  const natSid = (natText.match(/session_id_head: ([0-9a-f]+)/) || [])[1];
  const wtSid = (lines.match(/session_id_head: ([0-9a-f]+)/) || [])[1];
  const natKey = (natText.match(/key_tag: ([0-9a-f/]+)/) || [])[1];
  const wtKey = (lines.match(/key_tag: ([0-9a-f/]+)/) || [])[1];
  check('both transports derived a well-formed session_id',
    sidOk(natSid) && sidOk(wtSid), `${natSid} / ${wtSid}`);
  check('both transports derived a well-formed key tag',
    keyOk(natKey) && keyOk(wtKey), `${natKey} / ${wtKey}`);
  // The two directions must not be the same key. A tag cannot prove that on
  // its own -- equality across a fresh connection is a coincidence -- but a
  // client that handed c2s and s2c the same key would print the same tag on
  // both sides of the slash, and that IS a real, checkable failure.
  check('the two directions did not get the same key',
    !!natKey && natKey.split('/')[0] !== natKey.split('/')[1] &&
    !!wtKey && wtKey.split('/')[0] !== wtKey.split('/')[1],
    `${natKey} / ${wtKey}`);

  await browser.close();
  httpSrv.close();
  wsSshd.kill();
  sshd.kill();

  const bad = results.filter(r => !r.ok);
  console.log(`\n${bad.length === 0 ? '✓ PASS' : '✗ FAIL'}: ${results.length - bad.length}/${results.length} checks`);
  if (bad.length) for (const b of bad) console.error(`  FAIL ${b.name}`);
  if (bad.length === 0) {
    console.log('  a real OpenSSH 8.0p1 server decrypted an aes128-ctr packet and');
    console.log('  verified its hmac-sha2-256 MAC -- first natively, then from inside');
    console.log('  a browser Web Worker with zero native code and zero dependencies');
    console.log('  + packet layer byte-exact against paramiko, 4 target x 2 mode');
    console.log('  + handshake transcript (509/753) unchanged from Loop #31/#32');
  }
  process.exit(bad.length ? 1 : 0);
}

main().catch(e => {
  console.error('harness error:', e);
  process.exit(2);
});
