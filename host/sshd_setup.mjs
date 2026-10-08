// host/sshd_setup.mjs -- start a private OpenSSH server for Loop #31
//
// The server is deliberately narrow so the handshake is deterministic:
//   * HostKeyAlgorithms  forced to ECDSA, so the Loop #30 host key path is
//     what actually runs against a real sshd rather than an RSA shortcut.
//   * KexAlgorithms      forced to diffie-hellman-group14-sha256, the group the
//     MoonBit client implements (RFC 3526 group 14).
//   * Ciphers/MACs       fixed, so a mismatch is our bug and not negotiation.
//
// Keys and logs live under .loop31/ (gitignored). Nothing here touches the
// machine's real OpenSSH install or the user's ~/.ssh.
//
// Usage: node host/sshd_setup.mjs [--port 22222] [--stop]

import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync, rmSync, openSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import net from 'node:net';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SSHD_BIN = 'C:\\Program Files\\OpenSSH-Win64\\sshd.exe';
const KEYGEN_BIN = 'C:\\Program Files\\OpenSSH-Win64\\ssh-keygen.exe';
const DIR = join(ROOT, '.loop31', 'sshd');

const argv = process.argv.slice(2);
const PORT = Number(argv[argv.indexOf('--port') + 1]) || 22222;
const STOP = argv.includes('--stop');

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
  const pidFile = join(DIR, 'sshd.pid');
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

mkdirSync(DIR, { recursive: true });

// ---- host keys: ECDSA P-256 + P-384 (what we want to verify) and RSA (spare)
const KEYS = [
  ['ecdsa', 256, 'hostkey_ecdsa_256'],
  ['ecdsa', 384, 'hostkey_ecdsa_384'],
  ['rsa', 2048, 'hostkey_rsa_2048'],
];
for (const [type, bits, name] of KEYS) {
  const priv = join(DIR, name);
  if (!existsSync(priv)) {
    sh(KEYGEN_BIN, ['-t', type, '-b', String(bits), '-f', priv, '-N', '""', '-q',
                    '-C', 'loop31 test host key']);
    console.log(`generated ${name}`);
  }
}

// ---- authorized_keys: the test client's public key (empty for now; we use
// ---- password/none auth for the first milestone)
const authKeys = join(DIR, 'authorized_keys');
if (!existsSync(authKeys)) writeFileSync(authKeys, '');

const conf = join(DIR, 'sshd_config');
writeFileSync(conf, [
  `Port ${PORT}`,
  'AddressFamily any',
  'ListenAddress 127.0.0.1',
  `HostKey ${join(DIR, 'hostkey_ecdsa_256')}`,
  `HostKey ${join(DIR, 'hostkey_ecdsa_384')}`,
  `PidFile ${join(DIR, 'sshd.pid')}`,
  `LogLevel DEBUG3`,
  `Subsystem sftp internal-sftp`,

  // Deterministic negotiation surface. Note the option name: 8.0p1 predates
  // the PubkeyAcceptedAlgorithms rename and only knows the KeyTypes spelling.
  'KexAlgorithms diffie-hellman-group14-sha256',
  'HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp384',
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

const logPath = join(DIR, 'sshd.log');
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
