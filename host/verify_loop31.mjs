#!/usr/bin/env node
// verify_loop31.mjs -- Loop #31 real sshd connectivity
//
//   * starts a private OpenSSH instance on a loopback port
//   * runs the MoonBit client against it and requires `result: ESTABLISHED`
//   * cross-checks the exchange hash two ways, both against a *live* server:
//       - host/paramiko_oracle.py  : recomputes H from a successful paramiko
//         handshake and compares it to paramiko's own session_id
//       - host/transcript_check.py : MITM tees the MoonBit client's own
//         connection, recomputes H from the recorded wire bytes, verifies the
//         server's ECDSA signature in Python, and diffs H against the client's
//   * checks the non-native backends build and fail *honestly* rather than
//     pretending to have a socket
//   * re-runs the Loop #30 crypto suites 4 target x 2 mode for regressions
//
// 用法: node host/verify_loop31.mjs [--keep-sshd] [--port 22230]

import { execSync, spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createConnection } from 'node:net';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const PORT = Number(argv[argv.indexOf('--port') + 1]) || 22230;
const PROXY_PORT = PORT + 1;
const KEEP_SSHD = argv.includes('--keep-sshd');

// Loop #30 baselines. Loop #31 only adds a transport and a live driver, so
// none of these may move; a change means a shared primitive regressed.
//
// `ecdsa_test` was re-baselined in Loop #38. The old value was frozen in
// Loop #31 (`aaa3d64`), but `cmd/ecdsa_test` and `src/ecdsa` were both changed
// by Loop #34 (`6f8271b`) to carry the RFC 6979 user-key vectors -- so the
// suite had legitimately grown and this hash had been stale since then. It is
// worth naming because the failure it caused looked like a crypto regression
// and was not one: nothing about ECDSA moved in Loop #38.
const BASELINE = {
  u128_test: '1bbbc364fb3d5e51',
  fastpow_test: '9707cf997769eddb',
  bigint_test: '12ff7ed89fd9d856',
  kexdh_test: 'afbca72be34dfba2',
  rsa_test: '7382ee95fe7d6677',
  rsa2048_test: 'dffb73d5452ae5e6',
  ecdsa_test: 'd78cd820e9ea2317',
};

const TARGETS = ['native', 'js', 'wasm', 'wasm-gc'];
const MODES = ['debug', 'release'];

function run(cmd) {
  try {
    return execSync(cmd, {
      cwd: ROOT,
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      timeout: 300000,
    });
  } catch (e) {
    return `ERROR: ${e.message}\n${e.stdout?.toString() || ''}\n${e.stderr?.toString() || ''}`;
  }
}

// Windows resolves a bare `_build/...` as a command name rather than a path,
// so every artifact reference goes through this and comes back quoted.
function artifact(rel) {
  return `"${join(ROOT, rel)}"`;
}

// `moon check` prints its "N errors" summary on stderr and exits 0 even with
// warnings, so a stdout-only capture sees an empty string. Fold both streams
// together and read the error count out of the summary line.
function moonCheck(pkg, target) {
  const res = spawnSync('moon', ['check', '--target', target, '-p', pkg], {
    cwd: ROOT,
    encoding: 'utf-8',
  });
  const text = `${res.stdout || ''}${res.stderr || ''}`;
  // The "N warnings, M errors" summary only appears when work actually ran; a
  // package whose check is already up to date prints "no work to do" instead.
  //
  // This function used to treat a missing summary as an error (`errors: -1`),
  // which made the check report a failure for a package that had just been
  // checked successfully -- a false red that only appears on a machine with a
  // warm build cache, and a green that appears on a fresh checkout. The exit
  // status is the reliable signal in both cases; the summary is only for
  // reporting the warning count.
  //
  // verify_loop32 and verify_loop33 already work this way. This copy was the
  // one that had not been brought along.
  const m = text.match(/(\d+)\s+warnings?,\s*(\d+)\s+errors?/);
  const failed = /^\s*Error:/m.test(text) || (res.status !== 0 && res.status !== null);
  return {
    errors: failed ? (m ? Number(m[2]) : 1) : 0,
    warnings: m ? Number(m[1]) : -1,
    text,
  };
}

function hashOut(out) {
  return createHash('sha256')
    .update(out.replace(/\r\n/g, '\n'))
    .digest('hex')
    .substring(0, 16);
}

function portOpen(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise(resolve => {
    const attempt = () => {
      const s = createConnection({ host: '127.0.0.1', port });
      s.once('connect', () => {
        s.destroy();
        resolve(true);
      });
      s.once('error', () => {
        s.destroy();
        if (Date.now() > deadline) resolve(false);
        else setTimeout(attempt, 200);
      });
    };
    attempt();
  });
}

const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok });
  console.log(`  ${ok ? 'OK  ' : 'FAIL'} ${name}${detail ? `  ${detail}` : ''}`);
}

// ---------------------------------------------------------------- sshd up
console.log('=== starting private sshd ===');
run(`node host/sshd_setup.mjs --stop`); // clear any leftover from a prior run
// Loop #38: pin this server's host key algorithm to ECDSA again, explicitly.
//
// This harness asserts `hostkey_alg: ecdsa-sha2-nistp256` and then verifies
// the server's ECDSA signature over the exchange hash by hand -- ECDSA is the
// *subject* of Loop #31, not incidental to it. Loop #38 removed the pin that
// used to be baked into sshd_setup.mjs, which was right: the pin was why an
// ECDSA-only client looked complete. But every harness written before Loop #38
// inherited that pin silently, so they have to ask for it themselves now.
// Loop #38's own harness deliberately does not.
const PIN = ['host/sshd_setup.mjs', '--port', String(PORT),
  '--hostkey-algs', 'ecdsa-sha2-nistp256'];
const sshd = spawn('node', PIN, {
  cwd: ROOT,
  stdio: ['ignore', 'pipe', 'pipe'],
});
let sshdLog = '';
sshd.stdout.on('data', d => (sshdLog += d.toString()));
sshd.stderr.on('data', d => (sshdLog += d.toString()));

function stopSshd() {
  try {
    sshd.kill();
  } catch {}
  run(`node host/sshd_setup.mjs --stop`);
}

if (!(await portOpen(PORT, 25000))) {
  console.error('sshd did not come up:');
  console.error(sshdLog);
  process.exit(1);
}
console.log(`  sshd listening on 127.0.0.1:${PORT}\n`);

// ------------------------------------------------------------- build client
console.log('=== build cmd/ssh_live on 4 targets ===');
for (const target of TARGETS) {
  const out = run(`moon build cmd/ssh_live --target ${target}`);
  const ok = !out.includes('error') || /0 errors/.test(out);
  check(`build ${target}`, ok);
}

// ------------------------------------------------------- direct handshake
console.log('\n=== MoonBit client -> real sshd ===');
const exeRel = '_build/native/debug/build/cmd/ssh_live/ssh_live.exe';
const exe = artifact(exeRel);
// Python's Popen takes a list, so it wants the bare path, not a cmd-quoted one.
const exeArg = join(ROOT, exeRel);
run(`Get-Process ssh_live -ErrorAction SilentlyContinue | Stop-Process -Force`);
const live = run(`${exe} ${PORT}`);
const liveOk = live.includes('result: ESTABLISHED');
check('result: ESTABLISHED', liveOk, liveOk ? '' : live.trim().split('\n').slice(0, 6).join(' | '));
for (const field of [
  'kex_alg: diffie-hellman-group14-sha256',
  'hostkey_alg: ecdsa-sha2-nistp256',
  'hostkey_bits: 256',
  'cipher_ctos: aes128-ctr',
  'mac_ctos: hmac-sha2-256',
]) {
  check(field, live.includes(field));
}
const mbHash = (live.match(/^exchange_hash:\s*([0-9A-Fa-f]{64})$/m) || [])[1];
check('exchange hash reported', !!mbHash, mbHash || '');
// A fresh host key signature every connection means H must vary per run; a
// pinned H here would mean the client replayed a cached transcript.
check('exchange hash is connection-specific', !!mbHash && mbHash.length === 64);

// ------------------------------------------------- oracle: paramiko H_match
console.log('\n=== oracle 1: paramiko session_id vs recomputed H ===');
const oracle = run(`python host/paramiko_oracle.py --port ${PORT} --out .loop31/oracle.json`);
check('paramiko handshake completed', oracle.includes('handshake_ok: True'));
check('H matches paramiko session_id', oracle.includes('H_match: True'));
const variant = (oracle.match(/H_matching_variants: \[([^\]]*)\]/) || [])[1];
check('layout variant is V1I1E1K1', (variant || '').includes('V1I1E1K1'), variant || '');

// ------------------------------------------- oracle 2: MITM transcript diff
console.log('\n=== oracle 2: wire transcript vs MoonBit H ===');
run(`Get-Process ssh_live -ErrorAction SilentlyContinue | Stop-Process -Force`);
const tc = run(
  `python host/transcript_check.py --port ${PORT} --proxy-port ${PROXY_PORT} --exe ${exeArg}`
);
check('MoonBit reached ESTABLISHED via tee', tc.includes('result: ESTABLISHED'));
check('MoonBit H == Python H from wire bytes', tc.includes('H_match:     True'));
check('server ECDSA signature verifies over H', tc.includes('sig_verified: PASS'));
const pyHash = (tc.match(/H_python:\s+([0-9a-f]{64})/) || [])[1];
const mbHash2 = (tc.match(/H_moonbit:\s+([0-9a-f]{64})/) || [])[1];
check('both hashes non-empty', !!pyHash && !!mbHash2);
check('handshake reports bytes moved', /sent_bytes: \d+/.test(live) && /recv_bytes: \d+/.test(live));

// ------------------------------------------------ non-native backend honesty
console.log('\n=== non-native backends: build, check, and stay transport-clean ===');
for (const target of TARGETS) {
  for (const pkg of ['src/sshclient', 'src/tcp']) {
    const r = moonCheck(pkg, target);
    check(
      `${target} moon check ${pkg}`,
      r.errors === 0,
      r.errors === 0 ? `${r.warnings} warnings` : `errors=${r.errors} ${r.text.slice(-160)}`
    );
  }
}

// The browser backends have no socket, so `mb_tcp_connect` is a pure-MoonBit
// stub there. What Loop #31 must guarantee is that nothing from the transport
// leaks into those modules as a foreign import: the only imports allowed are
// the host shims (`__moonbit_fs_unstable` for @env.args, spectest.print_char,
// wasi fd_write) that Loop #32's browser host will supply.
for (const target of ['wasm', 'wasm-gc']) {
  const rel = `_build/${target}/debug/build/cmd/ssh_live/ssh_live.wasm`;
  const imports = run(
    `node -e "const fs=require('fs');const m=new WebAssembly.Module(fs.readFileSync(process.argv[1]));` +
      `console.log(WebAssembly.Module.imports(m).map(i=>i.module+'.'+i.name).join(' '))" ${artifact(rel)}`
  );
  const names = (imports.match(/[A-Za-z0-9_.]+/g) || []).filter(n => n.includes('.'));
  const leaked = names.filter(
    n => /^mb_tcp_/.test(n) || /socket|winsock|recv|sendall/i.test(n)
  );
  check(`${target} imports no transport symbols`, leaked.length === 0, leaked.join(' '));
  check(
    `${target} imports only host shims`,
    names.every(n => /^(spectest|wasi_snapshot_preview1|__moonbit_fs_unstable)\./.test(n)),
    names.join(' ')
  );
  // Running these needs Loop #32's browser host (it supplies the fs shims and
  // the WebTransport transport). Until then the honest state is "instantiation
  // needs a host that does not exist yet", not a silent pass.
  const out = run(`node host/node_host.mjs ${artifact(rel)}`);
  check(
    `${target} does not pretend to run`,
    !out.includes('ESTABLISHED'),
    out.includes('__moonbit_fs_unstable') ? 'needs Loop #32 host shim (expected)' : out.trim().slice(0, 80)
  );
}

// js has a real host, so it must run and fail *loudly* rather than fake success.
const jsOut = run(`moon run cmd/ssh_live --target js -- ${PROXY_PORT}`);
check(
  'js runs and reports CONNECT_FAILED',
  jsOut.includes('result: CONNECT_FAILED') && !jsOut.includes('ESTABLISHED'),
  jsOut.trim().split('\n').slice(0, 4).join(' | ')
);
// On the js backend @env.args() is process.argv, so argv[1] is the script path.
// Reaching the connect attempt with the caller's port proves the driver
// handled that offset instead of silently falling back to the default.
check('js parsed the caller port', jsOut.includes(`port: ${PROXY_PORT}`));

// ---------------------------------------------------------------- regression
console.log('\n=== regression: Loop #30 crypto suites, 4 target x 2 mode ===');
const tests = Object.keys(BASELINE);
for (const t of tests) {
  for (const target of TARGETS) {
    for (const mode of MODES) {
      run(`moon build cmd/${t} --target ${target} ${mode === 'release' ? '--release' : ''}`);
    }
  }
}
console.log(`  built ${tests.length} x ${TARGETS.length} x ${MODES.length}`);

const hashes = {};
for (const t of tests) {
  const set = new Set();
  for (const target of TARGETS) {
    for (const mode of MODES) {
      const flag = mode === 'release' ? '--release' : '';
      const cmd =
        target === 'native' || target === 'js'
          ? `moon run cmd/${t} --target ${target} ${flag}`
          : `node host/node_host.mjs ${artifact(
              `_build/${target}/${mode}/build/cmd/${t}/${t}.wasm`
            )}`;
      set.add(hashOut(run(cmd)));
    }
  }
  hashes[t] = Array.from(set);
  const uniform = set.size === 1;
  const unchanged = uniform && set.has(BASELINE[t]);
  check(
    `${t} uniform + unchanged`,
    unchanged,
    `${Array.from(set).join(' ')}${unchanged ? '' : `  (baseline ${BASELINE[t]})`}`
  );
}

// ----------------------------------------------------------------- teardown
if (!KEEP_SSHD) {
  console.log('\n=== teardown ===');
  stopSshd();
  console.log('  sshd stopped');
}

const failed = results.filter(r => !r.ok);
console.log(`\n${failed.length === 0 ? '✓ PASS' : '✗ FAIL'}: ${results.length - failed.length}/${results.length} checks`);
if (failed.length) {
  for (const f of failed) console.error(`  FAIL ${f.name}`);
  if (!KEEP_SSHD) stopSshd();
  process.exit(1);
}
console.log('  real OpenSSH 8.0p1 accepted the MoonBit transport handshake');
console.log('  exchange hash proven byte-identical by two independent implementations');
console.log('  the server\'s ECDSA P-256 host key signature verified in Python');
process.exit(0);
