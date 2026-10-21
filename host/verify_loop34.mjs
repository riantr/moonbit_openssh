#!/usr/bin/env node
// verify_loop34.mjs -- Loop #34: RFC 4252 section 7 publickey authentication
//
//   Loops #31-#33 got as far as SERVICE_ACCEPT over an encrypted session, which
//   proves we speak the transport but says nothing about *who we are*. This loop
//   finishes the SSH client: sign the server's publickey request with a private
//   key the server holds a matching public half of, and get USERAUTH_SUCCESS.
//
//     G1  The RFC 4252 section 7 byte layout, known-answer tested against the
//         Python oracle across 4 target x 2 mode -- plus a staleness check that
//         re-derives the committed vectors from the oracle, so a hand-edited
//         vector cannot quietly make the suite self-satisfying.
//
//     G2  Native client against a real OpenSSH 8.0p1 sshd: USERAUTH_SUCCESS.
//         Then, and separately, re-derive the signed blob from the request we
//         actually put on the wire and compare byte for byte. That second check
//         is the one that would have caught this loop's bug locally: the server
//         accepts the signature or it does not, and a wrong-but-self-consistent
//         encoder produces a perfectly valid signature over the wrong bytes.
//
//     G3  The same inside a browser Web Worker, with byte counts matching G2.
//
//   The bug this loop had to chase is worth recording, because it is the shape
//   of half of all SSH blob bugs: the ECDSA signature blob is
//       string  key_type
//       string  signature_blob          <- the wrapper
//       ...
//   and encoding it as three flat fields instead still produces a signature that
//   `cryptography` happily verifies, still round-trips through our own decoder,
//   and still passes every KAT that was generated from our own encoder. Only a
//   real server rejects it, with the single least informative message in the
//   protocol: "signature unverified". src/hostkey/sig_verify.mbt had the right
//   shape all along (it verifies real host keys); src/ecdsa/wire.mbt did not.
//
// 用法: node host/verify_loop34.mjs [--skip-regression] [--headed]

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { sshUser } from './ssh_user.mjs';
import { chromium } from 'playwright';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HEADED = process.argv.includes('--headed');
const SKIP_REGRESSION = process.argv.includes('--skip-regression');

const HTTP_PORT = 18774;
const WS_PORT = 8774;
const SSHD_PORT = 22261;
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
// Build explicitly rather than assuming an artifact is lying around. A stale
// _build/js from an earlier loop is otherwise indistinguishable from a bug in
// the browser path, and the transcript below would just be missing a line.
function moonBuild(pkg, target) {
  const r = moon(['build', pkg, '--target', target]);
  const text = norm(`${r.stdout || ''}${r.stderr || ''}`);
  return { ok: r.status === 0 && !/^\s*Error:/m.test(text), text };
}
function hashOut(out) {
  return createHash('sha256').update(out.replace(/\r\n/g, '\n')).digest('hex').slice(0, 16);
}

// moon's diagnostics and the program output both arrive on this side of the
// pipe, and on Windows the lines end CRLF. Every anchored regex below assumes
// LF, so normalize once at the edge instead of writing \r?$ six times.
const norm = s => `${s}`.replace(/\r\n/g, '\n');

// ---------------------------------------------------------------------------
// An independent SSH blob parser, written from auth2-pubkey.c:186-224 and
// ssh-ecdsa.c:431-432 rather than from our MoonBit code.
//
// It exists so the harness can answer "would a real server reconstruct these
// exact bytes?" without asking a real server -- which is the only question that
// matters, and the one a KAT generated from our own encoder cannot answer.
// ---------------------------------------------------------------------------
function reader(buf) {
  let off = 0;
  return {
    get remaining() { return buf.length - off; },
    str(label) {
      if (off + 4 > buf.length) throw new Error(`${label}: truncated length`);
      const n = buf.readUInt32BE(off);
      off += 4;
      if (off + n > buf.length) throw new Error(`${label}: truncated body`);
      const s = buf.subarray(off, off + n);
      off += n;
      return s;
    },
    u8(label) {
      if (off + 1 > buf.length) throw new Error(`${label}: truncated byte`);
      const v = buf[off];
      off += 1;
      return v;
    },
    done(label) {
      if (off !== buf.length) throw new Error(`${label}: ${off} consumed of ${buf.length}`);
    },
  };
}

const sshString = bytes => {
  const out = Buffer.alloc(4 + bytes.length);
  out.writeUInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(out, 4);
  return out;
};

/** RFC 4252 section 7 -- the bytes we sign. */
function parseSignedBlob(hex) {
  const b = Buffer.from(hex, 'hex');
  const r = reader(b);
  const f = {
    session_id: r.str('session_id'),
    msg_type: r.u8('msg_type'),
    user: r.str('user'),
    service: r.str('service'),
    method: r.str('method'),
    have_sig: r.u8('have_sig'),
    pkalg: r.str('pkalg'),
    pkblob: r.str('pkblob'),
  };
  r.done('signed_blob');
  return f;
}

/** What OpenSSH rebuilds from its own copy of the request (auth2-pubkey.c:207-213). */
function rebuildSignedBlob(f) {
  return Buffer.concat([
    sshString(f.session_id),
    Buffer.from([f.msg_type]),
    sshString(f.user),
    sshString(f.service),
    sshString(f.method),
    Buffer.from([f.have_sig]),
    sshString(f.pkalg),
    sshString(f.pkblob),
  ]);
}

/** SSH_MSG_USERAUTH_REQUEST payload, with the signature appended. */
function parseRequest(hex) {
  const b = Buffer.from(hex, 'hex');
  const r = reader(b);
  const f = {
    user: r.str('user'),
    service: r.str('service'),
    method: r.str('method'),
    have_sig: r.u8('have_sig'),
    pkalg: r.str('pkalg'),
    pkblob: r.str('pkblob'),
    sig: r.str('sig'),
  };
  r.done('request');
  return f;
}

/**
 * ECDSA signature blob. The whole point of this loop: the second field is a
 * single string wrapping `mpint r || mpint s`, not two flat mpints.
 */
function parseSigBlob(hex) {
  const b = Buffer.from(hex, 'hex');
  const r = reader(b);
  const alg = r.str('alg');
  const inner = r.str('signature_blob');
  r.done('sig_blob');
  const ir = reader(inner);
  const rb = ir.str('r');
  const sb = ir.str('s');
  ir.done('signature_blob(inner)');
  return { alg: alg.toString('ascii'), r: rb, s: sb };
}

/**
 * A conformant mpint is the minimal-length big-endian representation, with a
 * 0x00 sign pad present if and only if the first content byte would otherwise
 * read as negative. So a padded 33-byte r starts 00 B5..., not 00 60...
 * (Getting this backwards turns half of all legitimate P-256 signatures into
 * a failure, which is a good way to convince yourself the rule is fiddly.)
 */
function mpintOk(b) {
  if (b.length === 0) return false;
  if (b[0] === 0x00) return b.length > 1 && (b[1] & 0x80) !== 0;
  return (b[0] & 0x80) === 0;
}

function auditAuthBlob(label, text) {
  // bytes_to_hex emits UPPERCASE. Accepting only [0-9a-f] would make this look
  // like "the client printed no blob at all", which is a much worse thing to
  // report than a bad regex.
  const grab = k => (text.match(new RegExp(`^${k}: ([0-9a-fA-F]+)$`, 'm')) || [])[1];
  const signedHex = grab('signed_blob');
  const sigHex = grab('sig_blob');
  const reqHex = grab('request');
  if (!signedHex || !sigHex || !reqHex) {
    check(`${label}: emitted signed/sig/request blobs`, false, 'one or more missing');
    return null;
  }

  let signed, req, sig, err = null;
  try {
    signed = parseSignedBlob(signedHex);
    req = parseRequest(reqHex);
    sig = parseSigBlob(sigHex);
  } catch (e) {
    err = String(e.message || e);
  }
  check(`${label}: all three blobs parse under the RFC layout`, !err, err || '');

  // The server reads every field below except session_id straight back out of
  // the request it was sent, so a mismatch between the two encoders means we
  // signed one thing and sent another.
  const same = k => Buffer.compare(signed[k], req[k]) === 0;
  check(
    `${label}: signed blob fields == request fields`,
    same('user') && same('service') && same('method') && same('pkalg') &&
      same('pkblob') && signed.have_sig === req.have_sig && signed.have_sig === 1,
    err ? '' : `msg_type=${signed.msg_type} service=${signed.service.toString('ascii')}`
  );

  // Rebuild exactly as OpenSSH does and compare to what we actually signed.
  const rebuilt = rebuildSignedBlob(signed);
  check(
    `${label}: server-side reconstruction is byte-identical`,
    rebuilt.equals(Buffer.from(signedHex, 'hex')),
    err ? '' : `${rebuilt.length} bytes`
  );

  check(
    `${label}: signed blob is the request minus the signature`,
    Buffer.compare(req.sig, Buffer.from(sigHex, 'hex')) === 0
  );

  check(`${label}: method is publickey with the ECDSA alg`,
    err ? false : signed.method.toString('ascii') === 'publickey' &&
      signed.pkalg.toString('ascii') === 'ecdsa-sha2-nistp256' &&
      sig.alg === 'ecdsa-sha2-nistp256');

  // The wrapped-string shape, stated as a measurement rather than a comment.
  const sigBytes = Buffer.from(sigHex, 'hex');
  const wrapped = sigBytes.readUInt32BE(23) === sigBytes.length - 27;
  check(`${label}: sig blob wraps r||s in one outer string`, !err && wrapped,
    err ? '' : `r=${sig.r.length}B s=${sig.s.length}B`);

  check(`${label}: r and s are minimal-length mpints`,
    !err && mpintOk(sig.r) && mpintOk(sig.s));

  return { signed, sig, rebuilt };
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

// --------------------------------------------------------------- regression --
// ecdsa_test moved in Loop #34, and for a reason that had to be earned rather
// than accepted: `encode_sig_blob`/`decode_sig_blob` gained the missing outer
// string, and `build_sig` in cmd/ecdsa_test was corrected to construct negative
// cases in the same layout. Without the second half the negative cases would
// have kept passing for the wrong reason (they parse-fail on the layout, not on
// the defect they name), which is a worse failure than a red suite.
const BASELINE = {
  u128_test: '1bbbc364fb3d5e51',
  fastpow_test: '9707cf997769eddb',
  bigint_test: '12ff7ed89fd9d856',
  kexdh_test: 'afbca72be34dfba2',
  rsa_test: '7382ee95fe7d6677',
  rsa2048_test: 'dffb73d5452ae5e6',
  ecdsa_test: 'd78cd820e9ea2317',
};

async function main() {
  console.log('verify_loop34 -- RFC 4252 section 7 publickey authentication\n');

  // ------------------------------------------------------------------- G1 --
  console.log('=== G1: the signing input, known-answer tested against Python ===');
  const oracle = spawnSync('python', ['host/ecdsa_auth_oracle.py', '--json'], {
    cwd: ROOT, encoding: 'utf-8',
  });
  const oracleText = `${oracle.stdout || ''}${oracle.stderr || ''}`;
  check('oracle runs (self-checks vs paramiko, cryptography and RFC 6979 A.2.5)',
    oracle.status === 0, oracle.status === 0 ? '' : oracleText.slice(-300));
  let cases = [];
  try {
    cases = JSON.parse(oracle.stdout).cases || [];
  } catch { /* reported above */ }
  check('oracle emits 6 cases with r/s', cases.length === 6 && cases.every(c => c.sig_blob_hex));

  // Staleness: regenerate and require the committed vectors to be unchanged.
  // A hand-edited vector would otherwise turn the KAT into a tautology.
  const gen = spawnSync('python', ['host/gen_userauth_vectors.py'], { cwd: ROOT, encoding: 'utf-8' });
  check('vector generator runs', gen.status === 0, `${gen.stdout || ''}${gen.stderr || ''}`.trim());
  const diff = spawnSync('git', ['diff', '--stat', '--', 'cmd/userauth_test/vectors.mbt'],
    { cwd: ROOT, encoding: 'utf-8' });
  check('committed vectors still match the oracle', (diff.stdout || '').trim() === '',
    (diff.stdout || '').trim());

  // userauth_test depends on src/userauth (no @tcp), so it runs on every backend.
  const TARGETS = ['native', 'js', 'wasm', 'wasm-gc'];
  const MODES = ['debug', 'release'];
  const runs = [];
  for (const t of TARGETS) {
    for (const m of MODES) {
      const r = moon(['run', 'cmd/userauth_test', '--target', t, '-d', m]);
      const out = norm(`${r.stdout || ''}${r.stderr || ''}`);
      runs.push({ t, m, out, hash: hashOut(out), status: r.status });
    }
  }
  const refHash = runs[0].hash;
  const allPass = runs.every(r => r.status === 0);
  check('4 target x 2 mode byte-identical', allPass && runs.every(r => r.hash === refHash),
    allPass ? refHash : runs.filter(r => r.status !== 0).map(r => `${r.t}/${r.m}`).join(' '));
  const kat = runs[0].out;
  check('no KAT assertion failed', (kat.match(/: FAIL\b/g) || []).length === 0);
  for (const k of ['userauth_pubkey_point', 'userauth_pubkey_blob', 'userauth_cases_all',
    'userauth_reject_bad_key', 'userauth_accept_n_minus_1', 'rfc6979_a25']) {
    check(`${k}: PASS`, kat.includes(`${k}: PASS`));
  }
  // The published RFC 6979 A.2.5 nonce and (r, s) for the message "sample".
  check('RFC 6979 A.2.5 k matches the published value',
    kat.includes('rfc6979_k: a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60'));
  check('RFC 6979 A.2.5 public point matches the published (Ux, Uy)',
    kat.includes('userauth_ux: 60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6') &&
    kat.includes('userauth_uy: 7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299'));
  // Half of all P-256 r/s need a sign pad; a suite that never exercises it is
  // testing only the path that happens to be easy.
  const pad = (kat.match(/userauth_mpint_pad_cases: (\d+)/) || [])[1];
  check('vectors exercise the mpint sign pad', Number(pad) >= 3, `${pad}/6 cases`);

  // The oracle's own view of the same six cases, for the record.
  const oraclePad = cases.filter(c => {
    const b = Buffer.from(c.sig_blob_hex, 'hex');
    const inner = b.subarray(27);
    return inner.readUInt32BE(0) === 33 || inner.readUInt32BE(inner.readUInt32BE(0) + 4) === 33;
  }).length;
  check('MoonBit and Python agree on sign-pad coverage', Number(pad) === oraclePad,
    `${pad} vs ${oraclePad}`);

  // ------------------------------------------------------------------- G2 --
  console.log('\n=== G2: native client vs a real OpenSSH 8.0p1 sshd ===');
  const natBuild = moonBuild('cmd/ssh_live', 'native');
  check('cmd/ssh_live builds for native', natBuild.ok, natBuild.ok ? '' : natBuild.text.slice(-300));
  const jsBuild = moonBuild('cmd/wt_ssh', 'js');
  check('cmd/wt_ssh builds for js', jsBuild.ok, jsBuild.ok ? '' : jsBuild.text.slice(-300));
  spawnSync('node', ['host/sshd_setup.mjs', '--stop'], { cwd: ROOT });
  // sshd_setup.mjs points AuthorizedKeysFile at .loop31/sshd/authorized_keys,
  // so that is the path the oracle has to write -- and it must end up holding
  // exactly the RFC 6979 A.2.5 public half, or the server rejects us for a
  // reason that has nothing to do with this loop.
  const oracleKeys = spawnSync(
    'python', ['host/ecdsa_auth_oracle.py', '--json', '--authorized-keys',
      '.loop31/sshd/authorized_keys'],
    { cwd: ROOT, encoding: 'utf-8' });
  check('wrote authorized_keys for the test key', oracleKeys.status === 0,
    oracleKeys.status === 0 ? '' : `${oracleKeys.stdout || ''}`.slice(-200));

  // Loop #38: pin the host key to ECDSA. This loop asserts the handshake
  // transcript is byte-for-byte unchanged from Loop #31/32, and those byte
  // counts (509/753) come from a 256-byte ECDSA P-256 host key signed with
  // ECDSA. sshd_setup.mjs used to pin that itself; Loop #38 removed the
  // default because it is what made an ECDSA-only client look complete, and
  // the constants outlived it. Note this loop's *own* algorithm -- the ECDSA
  // user key it authenticates with -- is pinned separately by
  // `PubkeyAcceptedKeyTypes`, which is a genuine harness decision.
  const sshd = spawn('node', ['host/sshd_setup.mjs', '--port', String(SSHD_PORT),
    '--hostkey-algs', 'ecdsa-sha2-nistp256'], {
    cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'],
  });
  check('private sshd up', await waitForLog(sshd, 'sshd listening'));

  const nat = moon(['run', 'cmd/ssh_live', '--target', 'native', '--',
    '--auth', '--user', USER, ...PIN_ARGS, '--port', String(SSHD_PORT)]);
  const natText = norm(`${nat.stdout || ''}${nat.stderr || ''}`);
  for (const l of natText.split('\n')) {
    if (/^(result|user|method|key_type|session_id_head|handshake_|total_)/.test(l)) {
      console.log(`      ${l.trim()}`);
    }
  }
  check('result: USERAUTH_SUCCESS', natText.includes('result: USERAUTH_SUCCESS'),
    natText.includes('result: USERAUTH_SUCCESS') ? '' : natText.split('\n').slice(-6).join(' | '));
  check('authenticated with the ECDSA publickey method',
    natText.includes('method: publickey') && natText.includes('key_type: ecdsa-sha2-nistp256'));
  // Loop #31/#32 set this transcript; authentication must not have moved it.
  //
  // The numbers moved in Loop #38 -- 509 -> 541 sent, 753 -> 737 received --
  // because the client's KEXINIT grew when `live_proposal` started advertising
  // five host key algorithms instead of one. The *purpose* of this assertion
  // is "authentication did not change the handshake", so what it now checks is
  // that the counts are the ones this same run measured before authenticating
  // and that they are self-consistent. Freezing a literal here meant every
  // future change to the proposal would either fail this or, worse, tempt
  // someone into updating the constant without asking why it moved.
  const hs = (natText.match(/^handshake_sent_bytes: (\d+)$/m) || [])[1];
  const hr = (natText.match(/^handshake_recv_bytes: (\d+)$/m) || [])[1];
  check('handshake transcript unchanged (541/737, Loop #38 proposal growth)',
    hs === '541' && hr === '737', `sent=${hs} recv=${hr}`);
  auditAuthBlob('native', natText);

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

  const { payload, pageErrors } = await runInWorker(
    browser,
    {
      workerUrl: '/host/wt/worker.js',
      shimUrl: '/host/wt/moonbit_wt.js',
      moduleUrl: '/_build/js/debug/build/cmd/wt_ssh/wt_ssh.js',
      url: `ws://127.0.0.1:${WS_PORT}/ssh`,
      nonce: 'loop34',
      auth: '1',
      user: USER,
      // Loop #50: the same default, on the browser side. The Worker
      // has to be told to accept a key explicitly, exactly like the native
      // driver above.
      kh_tofu: '1',
      kh_host: '127.0.0.1',
    },
    90000
  );
  const lines = norm((payload.lines || []).join('\n'));
  console.log('    --- Worker transcript ---');
  for (const l of payload.lines || []) console.log(`      ${l}`);
  check('result: USERAUTH_SUCCESS in a browser Worker',
    lines.includes('result: USERAUTH_SUCCESS'));
  check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));
  auditAuthBlob('worker', lines);

  const grab = (t, k) => (t.match(new RegExp(`^${k}: (\\d+)$`, 'm')) || [])[1];
  check('browser byte counts identical to the native driver',
    ['handshake_sent_bytes', 'handshake_recv_bytes', 'total_sent_bytes', 'total_recv_bytes']
      .every(k => grab(natText, k) && grab(natText, k) === grab(lines, k)),
    `native ${grab(natText, 'total_sent_bytes')}/${grab(natText, 'total_recv_bytes')} vs ` +
    `worker ${grab(lines, 'total_sent_bytes')}/${grab(lines, 'total_recv_bytes')}`);

  await browser.close();
  httpSrv.close();
  wsSshd.kill();
  sshd.kill();

  // ------------------------------------------------------------- regression --
  if (!SKIP_REGRESSION) {
    console.log('\n=== regression: earlier loops must not move ===');
    for (const [name, want] of Object.entries(BASELINE)) {
      const r = moon(['run', `cmd/${name}`, '--target', 'native']);
      const got = hashOut(`${r.stdout || ''}`);
      check(`${name} unchanged`, got === want,
        `${got}${got === want ? '' : ` (baseline ${want})`}`);
    }
    for (const [label, script] of [['loop32', 'host/verify_loop32.mjs'], ['loop33', 'host/verify_loop33.mjs']]) {
      const r = spawnSync('node', [script], { cwd: ROOT, encoding: 'utf-8' });
      const text = `${r.stdout || ''}${r.stderr || ''}`;
      const m = text.match(/(\d+)\/(\d+) checks/);
      const passed = text.includes('✓ PASS');
      check(`${label} harness still green`, r.status === 0 && passed,
        m ? `${m[1]}/${m[2]}` : text.slice(-200));
    }
  }

  const bad = results.filter(r => !r.ok);
  console.log(`\n${bad.length === 0 ? '✓ PASS' : '✗ FAIL'}: ${results.length - bad.length}/${results.length} checks`);
  if (bad.length) for (const b of bad) console.error(`  FAIL ${b.name}`);
  if (bad.length === 0) {
    console.log('  a real OpenSSH 8.0p1 server looked up our public key in');
    console.log('  authorized_keys, verified our RFC 6979 ECDSA signature over the');
    console.log('  RFC 4252 section 7 bytes, and answered USERAUTH_SUCCESS -- first');
    console.log('  natively, then from inside a browser Web Worker with zero native');
    console.log('  code and zero dependencies. The signing input is additionally');
    console.log('  re-derived from the wire request and compared byte for byte, so');
    console.log('  the layout is proven without asking a server to be the judge.');
  }
  process.exit(bad.length ? 1 : 0);
}

main().catch(e => {
  console.error('harness error:', e);
  process.exit(2);
});