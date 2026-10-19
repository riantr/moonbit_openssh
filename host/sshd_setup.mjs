// host/sshd_setup.mjs -- start a private OpenSSH server for Loop #31
//
// The server is deliberately narrow so the handshake is deterministic:
//   * KexAlgorithms      forced to diffie-hellman-group14-sha256, the group the
//     MoonBit client implements (RFC 3526 group 14).
//   * Ciphers/MACs       fixed, so a mismatch is our bug and not negotiation.
//
// Loop #38 removed the `HostKeyAlgorithms` pin. It had been forcing the server
// to ECDSA, which for thirty-seven loops made an ECDSA-only client look
// sufficient -- against a server holding only ed25519/rsa keys, every name the
// server offered was one we refused and the handshake died with `NoAgreement`.
// A client that cannot talk to a default-configured host is not a client.
//
// The pin is available again, but as a *test* lever (`--hostkey-algs`) rather
// than as a default: Loop #38 needs to force each algorithm in turn to prove
// the dispatch works for all of them instead of only for whichever one the
// server happens to prefer. `--name` gives each such instance its own config,
// pid and log so they can run side by side.
//
// Keys and logs live under .loop31/ (gitignored). Nothing here touches the
// machine's real OpenSSH install or the user's ~/.ssh.
//
// Usage:
//   node host/sshd_setup.mjs [--port 22222] [--stop]
//                           [--hostkey-algs a,b,c] [--name suffix]
//   node host/sshd_setup.mjs --stop --name suffix

import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, rmSync, openSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import net from 'node:net';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Two OpenSSH installations exist on Windows and they are not the same thing.
//
//   C:\Program Files\OpenSSH-Win64\  the portable Win32-OpenSSH build. This
//                                    is the one these gates were developed
//                                    against, on a developer machine.
//   C:\Windows\System32\OpenSSH\      the inbox Windows optional feature.
//                                    This is what a GitHub `windows-latest`
//                                    runner has.
//
// Hardcoding the first one made this file work on exactly one machine and
// fail everywhere else -- measured on GitHub run 39194939821, where every gate
// that needs an sshd (loop31, loop40, loop47, loop48, loop50, loop51, loop54,
// loop55, loop62, loop65, loop66) died without ever starting a server. The
// error named the missing `.exe`, which is why it read as "sshd is not
// installed" rather than "this file knows one developer's install prefix".
//
// So: probe the known locations, in order, and take the first pair that
// exists. A location list rather than a PATH lookup because the OpenSSH
// binaries are not on PATH by default and `where sshd` finds neither.
// machine-path-exempt: each entry below is a CANDIDATE, probed in order until
// one exists. None is asserted to exist, and when none does the script names
// all three and exits 3. verify_loop71.mjs flags any drive-letter path it finds
// in code; this marker is how a file declares that its paths are a probe rather
// than a claim, and it is an obligation to say why, not a mute button.
const SSHD_DIRS = [
  'C:\\Program Files\\OpenSSH-Win64',
  'C:\\Windows\\System32\\OpenSSH',
  'C:\\Program Files\\OpenSSH',
];
const found = SSHD_DIRS.find((d) => existsSync(join(d, 'sshd.exe')));
const SSHD_BIN = found ? join(found, 'sshd.exe') : null;
// ssh-keygen is a separate binary in the same directory; it is allowed to be
// missing from a pair that has sshd, but if it is missing too there is nothing
// to fall back on and the caller should hear about it once, clearly.
const KEYGEN_BIN = found && existsSync(join(found, 'ssh-keygen.exe'))
  ? join(found, 'ssh-keygen.exe')
  : 'ssh-keygen';
const DIR = join(ROOT, '.loop31', 'sshd');

const argv = process.argv.slice(2);
const PORT = Number(argv[argv.indexOf('--port') + 1]) || 22222;
const STOP = argv.includes('--stop');
const HOSTKEY_ALGS = (() => {
  const i = argv.indexOf('--hostkey-algs');
  return i >= 0 && argv[i + 1] ? argv[i + 1] : '';
})();
// Every per-instance file is namespaced so several pinned servers can run at
// once. The default name is empty, which keeps the original filenames.
const NAME = (() => {
  const i = argv.indexOf('--name');
  return i >= 0 && argv[i + 1] ? argv[i + 1] : '';
})();
const tagged = s => (NAME ? `${s}_${NAME}` : s);

function sh(cmd, args) {
  return execFileSync(cmd, args, { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
}

function waitForPort(port, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolveWait, rejectWait) => {
    const attempt = () => {
      const s = net.connect({ host: '127.0.0.1', port }, () => { s.destroy(); resolveWait(true); });
      s.on('error', () => {
        s.destroy();
        if (Date.now() > deadline) rejectWait(new Error(`port ${port} never opened`));
        else setTimeout(attempt, 150);
      });
    };
    attempt();
  });
}

if (STOP) {
  const pidFile = join(DIR, tagged('sshd.pid'));
  if (existsSync(pidFile)) {
    const pid = Number(readFileSafe(pidFile));
    try { process.kill(pid); console.log(`stopped pid ${pid}`); } catch (e) { console.log(`no process ${pid}: ${e.message}`); }
    rmSync(pidFile, { force: true });
  } else {
    console.log('no pid file');
  }
  process.exit(0);
}

function readFileSafe(p) {
  try { return readFileSync(p, 'utf8').trim(); } catch { return '0'; }
}

// One loud failure, naming the three places that were looked at. Previously
// this surfaced as an ENOENT from deep inside `spawn`, which reads as a bug
// in this file rather than as "this machine has no sshd server".
if (!SSHD_BIN) {
  console.error('no sshd.exe in any of:');
  for (const d of SSHD_DIRS) console.error('  ' + d);
  console.error('install one, or add its directory to SSHD_DIRS in ' +
                'host/sshd_setup.mjs');
  process.exit(3);
}

mkdirSync(DIR, { recursive: true });

// ---- host keys: every algorithm the client actually supports.
// Loop #38 stopped pinning `HostKeyAlgorithms`, so this list is what decides
// the negotiation. A server that only had ECDSA keys made the ECDSA-only
// proposal look sufficient for thirty-seven loops.
const KEYS = [
  ['ecdsa', 256, 'hostkey_ecdsa_256'],
  ['ecdsa', 384, 'hostkey_ecdsa_384'],
  ['ed25519', null, 'hostkey_ed25519'],
  ['rsa', 2048, 'hostkey_rsa_2048'],
];
for (const [type, bits, name] of KEYS) {
  const priv = join(DIR, name);
  if (!existsSync(priv)) {
    const args = ['-t', type, '-f', priv, '-q', '-C', 'loop31 test host key'];
    // ssh-keygen 8.0p1 takes -b for RSA/ECDSA but not for ed25519, whose size
    // is fixed at 256. Passing -b there is an error, not a warning.
    if (bits !== null) args.splice(3, 0, '-b', String(bits));
    // -N must be an actually-empty argument. The two-character string `""`
    // is accepted as "no passphrase" by the old PEM formats and silently
    // becomes the passphrase for the newer OpenSSH private key format --
    // sshd then refuses the key with "incorrect passphrase supplied to
    // decrypt private key", which only shows up at `sshd -t`, not at keygen.
    args.splice(args.length, 0, '-N', '');
    sh(KEYGEN_BIN, args);
    console.log(`generated ${name}`);
  }
}

// ---- authorized_keys: the test client's public key (empty for now; we use
// ---- password/none auth for the first milestone)
const authKeys = join(DIR, 'authorized_keys');
if (!existsSync(authKeys)) writeFileSync(authKeys, '');

const conf = join(DIR, tagged('sshd_config'));
writeFileSync(conf, [
  `Port ${PORT}`,
  'AddressFamily any',
  'ListenAddress 127.0.0.1',
  ...KEYS.map(([_type, _bits, name]) => `HostKey ${join(DIR, name)}`),
  `PidFile ${join(DIR, tagged('sshd.pid'))}`,
  `LogLevel DEBUG3`,
  `Subsystem sftp internal-sftp`,

  // Deterministic negotiation surface. Note the option name: 8.0p1 predates
  // the PubkeyAcceptedAlgorithms rename and only knows the KeyTypes spelling.
  'KexAlgorithms diffie-hellman-group14-sha256',
  // Loop #38: no HostKeyAlgorithms pin by default. Pinning it to ECDSA is what
  // hid the fact that the client could not talk to anything else -- the
  // server said "no matching host key type found" and the client said
  // "NoAgreement", which reads like a cipher problem and is not one.
  // `--hostkey-algs` re-enables the pin for one instance at a time so each
  // algorithm can be forced in turn and proved independently.
  ...(HOSTKEY_ALGS ? [`HostKeyAlgorithms ${HOSTKEY_ALGS}`] : []),
  //
  // `PubkeyAcceptedKeyTypes` (the 8.0p1 spelling of the user key algorithm)
  // stays pinned: that one really is a test-harness decision, not a
  // client limitation -- the client signs with ECDSA P-256.
  'PubkeyAcceptedKeyTypes ecdsa-sha2-nistp256,ecdsa-sha2-nistp384',
  'Ciphers aes128-ctr,aes256-ctr',
  'MACs hmac-sha2-256',

  // Auth surface for an automated test.
  'PubkeyAuthentication yes',
  'PasswordAuthentication yes',
  'PermitEmptyPasswords yes',
  'KbdInteractiveAuthentication no',
  'StrictModes no',
  `AuthorizedKeysFile ${authKeys}`,
  'PermitRootLogin yes',
  'MaxStartups 10:30:60',

  // Loop #37. `AcceptEnv` is empty by default, so a `env` request is silently
  // dropped and there is no wire-level evidence either way (RFC 4254 6.4: no
  // response).  Naming one variable gives the test the only honest oracle:
  // the remote command can look at its own environment and report whether the
  // request arrived.  Two variables is deliberate -- the second name is *not*
  // here, so the same run also covers the refusal branch.
  'AcceptEnv LOOP37_TEST LOOP37_SECOND',
  '',
].join('\n'));

// Validate before launching, so a bad option fails loudly here and not as a
// mysterious connection reset later.
try {
  sh(SSHD_BIN, ['-t', '-f', conf]);
  console.log('sshd_config OK');
} catch (e) {
  console.error('sshd_config INVALID');
  console.error(e.stderr?.toString() || e.stdout?.toString() || e.message);
  process.exit(1);
}

const logPath = join(DIR, tagged('sshd.log'));
const logFd = openSync(logPath, 'a');
const child = spawn(SSHD_BIN, ['-D', '-e', '-f', conf], {
  cwd: ROOT,
  stdio: ['ignore', logFd, logFd],
  detached: false,
});

child.on('error', (e) => {
  console.error('failed to spawn sshd:', e.message);
  process.exit(1);
});

child.on('exit', (code, sig) => {
  console.error(`sshd exited early code=${code} sig=${sig}`);
  console.error(readFileSync(logPath, 'utf8').split('\n').slice(-25).join('\n'));
  process.exit(1);
});

try {
  await waitForPort(PORT);
  console.log(`sshd listening on 127.0.0.1:${PORT}`);
  if (HOSTKEY_ALGS) console.log(`  hostkeys pinned to: ${HOSTKEY_ALGS}`);
  console.log(`  config: ${conf}`);
  console.log(`  log:    ${logPath}`);
  console.log(`  pid:    ${child.pid}`);
  // Keep the server alive for the client run; the caller kills it via --stop.
  await new Promise(() => {});
} catch (e) {
  console.error(e.message);
  console.error(readFileSync(logPath, 'utf8').split('\n').slice(-25).join('\n'));
  process.exit(1);
}
