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
import { readFileSync, existsSync } from 'node:fs';
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

// Run the client with an argv array.
//
// `run()` builds a shell command string, and a shell cannot carry an empty
// argument (see the PIN_ARGS comment above). The exit status is kept as well
// as the output, because "the client said ESTABLISHED" and "the client exited
// 0" are different claims and the gate wants both.
function runClient(args) {
  const res = spawnSync(exeArg, args, {
    cwd: ROOT,
    encoding: 'utf-8',
    timeout: 300000,
  });
  if (res.error) return `ERROR: ${res.error.message}`;
  return `${res.stdout || ''}${res.stderr || ''}`;
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

// moon's diagnostics and the program's output both arrive with CRLF on
// Windows, and every anchored regex below assumes LF. Normalize once at the
// edge rather than writing \r?$ five times.
function norm(s) {
  return String(s || '').replace(/\r\n/g, '\n');
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
//
// Loop #68 made this driver native-only (`supported_targets: "+native"` in
// `cmd/ssh_live/moon.pkg`), because the browser path has its own driver
// (`cmd/wt_ssh`, js-only) and the two must not pretend to be one thing.
//
// So the expectation here is **inverted** for the three non-native backends:
// they must be REFUSED, loudly, by the toolchain. A driver that cannot run
// where it is not supported is the honest outcome; a driver that builds
// everywhere and then has no socket is the dishonest one.
//
// The first version of this check looked for the string "error" in the build
// output. moon says "Error: failed to run build for target Js" -- capital E --
// and a case-sensitive search for "error" does not match it, so a build that
// FAILED was reported as a build that succeeded. The three checks below it
// then read a `.wasm` left over from before Loop #68 and measured that.
// A gate that cannot fail is worse than a gate that fails, and this one had
// been unable to fail for a long time without anyone noticing.
for (const target of TARGETS) {
  const res = spawnSync('moon', ['build', 'cmd/ssh_live', '--target', target], {
    cwd: ROOT,
    encoding: 'utf-8',
  });
  const text = norm(`${res.stdout || ''}${res.stderr || ''}`);
  if (target === 'native') {
    check('build native', res.status === 0, text.trim().split('\n').slice(-2).join(' | '));
  } else {
    // The refusal has to *name* the backend. "failed" alone is a rumour; a
    // message that says which backend is unsupported and which ones are
    // supported is a measurement.
    const refused = res.status !== 0 &&
      /does not support target backend/i.test(text) &&
      text.includes(`'${target}'`);
    check(
      `build ${target} is refused, and says why`,
      refused,
      text.trim().split('\n').filter(l => /backend|Error/i.test(l)).slice(0, 2).join(' | ')
    );
  }
}

// ------------------------------------------------------- direct handshake
console.log('\n=== MoonBit client -> real sshd ===');
const exeRel = '_build/native/debug/build/cmd/ssh_live/ssh_live.exe';
const exe = artifact(exeRel);
// Python's Popen takes a list, so it wants the bare path, not a cmd-quoted one.
const exeArg = join(ROOT, exeRel);
run(`Get-Process ssh_live -ErrorAction SilentlyContinue | Stop-Process -Force`);

// The host key pin.
//
// Loop #50 made REFUSING an unpinned host the default, so a client that
// reaches a real server without a pin is turned away before the handshake can
// be judged. This gate was written before that default existed and was never
// updated, so it has been failing with `HostkeyUnknown` since -- a failure
// about pinning, reported as a failure about the handshake.
//
// `--kh-tofu` is the explicit "accept this key" (= `accept-new`). Nothing is
// written to disk: the write-back only happens when `--kh-file` is given, and
// this driver is given neither, so the developer's own known_hosts is never
// touched.
//
// The arguments travel as an argv array, not as a command string. `run()`
// hands its argument to a shell, and a Windows shell has no empty-string
// argument: `--known-hosts-text ''` arrives as the two characters `''`, which
// is a *non-empty* known_hosts text that parses to zero entries -- and the
// client refuses that with "known_hosts parsed to nothing". A gate that
// quotes its own arguments wrongly fails in a way that reads like a client
// bug, so the array form is used wherever an argument can be empty.
const PIN_ARGS = ['--kh-tofu', '--kh-host', '127.0.0.1'];
const live = runClient([String(PORT), ...PIN_ARGS]);
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
// `--client-arg=<value>`, not `--client-arg <value>`: the values are switches
// that begin with a dash, and argparse would read `--kh-tofu` as an option
// name rather than as a value. The first version of this line used the space
// form and the oracle died with "expected one argument" -- a failure that
// reads like the transcript tool being broken.
// `--client-arg=--fixed-kex` is not optional.  The oracle recomputes the shared
// secret as `f^x mod p`, and it can only do that if it knows the client's
// private exponent -- which it cannot learn from the wire, because recovering
// it from `e = g^x mod p` is the discrete logarithm.  Since Loop #84 the
// client draws that exponent from the CSPRNG, so the oracle has to ask for the
// reproducible one by name.  The flag is a testing premise, never the default.
const tc = run(
  `python host/transcript_check.py --port ${PORT} --proxy-port ${PROXY_PORT} --exe ${exeArg} ` +
  PIN_ARGS.map(a => `--client-arg=${a}`).join(' ') +
  ' --client-arg=--fixed-kex'
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

// The browser path has no socket. What Loop #31 must guarantee is that
// nothing from the native transport leaks into it -- and that is now measured
// on the artifact that actually runs in a browser.
//
// This used to inspect `_build/wasm/.../cmd/ssh_live/ssh_live.wasm` and
// compare its import list against an allowlist of host shims. Two things
// broke it, and neither was visible from the failure:
//
//   1. `cmd/ssh_live` has been native-only since Loop #68, so `moon build` for
//      wasm/wasm-gc/js **fails** -- and the check above that was supposed to
//      notice could not fail (it searched for a lowercase "error" in a message
//      that starts with a capital "Error"). The `.wasm` it then read was
//      left over from before Loop #68. It was a stale artifact being measured
//      as if it were the current one.
//   2. the driver that runs in a browser is not `cmd/ssh_live` at all. It is
//      `cmd/wt_ssh`, and it is js-only.
//
// So the property is now stated where it is true: the browser driver's own
// bundle must not contain the native socket, and must contain the browser
// transport instead. `mb_tcp_connect` is the native entry point (`extern "c"`
// into `src/tcp/winsock.c`); `__moonbit_wt` is the byte-stream shim the
// browser side talks to.
{
  const b = spawnSync('moon', ['build', 'cmd/wt_ssh', '--target', 'js'], {
    cwd: ROOT,
    encoding: 'utf-8',
  });
  const bText = norm(`${b.stdout || ''}${b.stderr || ''}`);
  check('build cmd/wt_ssh (js)', b.status === 0, bText.trim().split('\n').slice(-2).join(' | '));

  const bundleRel = '_build/js/debug/build/cmd/wt_ssh/wt_ssh.js';
  const bundlePath = join(ROOT, bundleRel);
  if (!existsSync(bundlePath)) {
    check('browser driver bundle exists', false, bundleRel);
  } else {
    const bundle = readFileSync(bundlePath, 'utf-8');
    check('browser driver bundle exists', true, `${bundle.length} bytes`);
    const nativeSymbols = ['mb_tcp_connect', 'mb_tcp_send', 'mb_tcp_recv', 'winsock']
      .filter(sym => bundle.includes(sym));
    check(
      'browser driver links no native socket',
      nativeSymbols.length === 0,
      nativeSymbols.join(' ')
    );
    check(
      'browser driver uses the browser transport',
      bundle.includes('__moonbit_wt'),
      '__moonbit_wt'
    );
  }
}

// The driver that has no browser backend must say so rather than run
// something else.
//
// This used to ask `cmd/ssh_live` to run under js and to report
// `CONNECT_FAILED` -- a real check at the time, when the driver built for
// every backend and the js one had no socket to reach. Since Loop #68 the
// driver is native-only, so the honest question is the other way round: the
// toolchain must refuse it, and name the backend it refused.
{
  const jsRun = spawnSync('moon', ['run', 'cmd/ssh_live', '--target', 'js', '--', String(PROXY_PORT)], {
    cwd: ROOT,
    encoding: 'utf-8',
    timeout: 300000,
  });
  const jsText = norm(`${jsRun.stdout || ''}${jsRun.stderr || ''}`);
  check(
    'js is refused by the toolchain, and says why',
    jsRun.status !== 0 &&
      /does not support target backend/i.test(jsText) &&
      jsText.includes("'js'") &&
      !jsText.includes('ESTABLISHED'),
    jsText.trim().split('\n').filter(l => /backend|Error/i.test(l)).slice(0, 2).join(' | ')
  );
}

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
