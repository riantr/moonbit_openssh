#!/usr/bin/env node
// verify_loop22.mjs — Loop #22 G1 SSH client full write path 4 target × 2 mode byte-exact 验证
//
// 用法: node host/verify_loop22.mjs
//
// 跑 cmd/ssh_full 4 target × 2 mode = 8 outputs,验证 byte-exact 一致
//   cmd/ssh_full 跑 ssh_client_full_unencrypted:
//     VERSION → KEXINIT → KEXECDH_INIT → NEWKEYS → USERAUTH(password)
//     → CHANNEL_OPEN(session) → CHANNEL_REQUEST(exec)
//     → 收 USERAUTH_SUCCESS + CHANNEL_OPEN_CONFIRMATION
//     → 收 CHANNEL_SUCCESS + CHANNEL_DATA + EOF + exit-status + CLOSE
//
// 不破 cmd/main (Loop #20 hash 230bfd5b0c02d682) — 单独跑 cmd/ssh_full

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function hashOut(out) {
  // 规范化 line ending: native target 在 Windows 用 CRLF,其他 target 用 LF
  const normalized = out.replace(/\r\n/g, '\n');
  return createHash('sha256').update(normalized).digest('hex').substring(0, 16);
}

function run(cmd, opts = {}) {
  try {
    return execSync(cmd, { cwd: ROOT, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], ...opts });
  } catch (e) {
    return `ERROR: ${e.message}\nstderr: ${e.stderr?.toString() || ''}`;
  }
}

async function buildAll() {
  console.log('[build] ssh_full native...');
  run('moon build cmd/ssh_full --target native');
  console.log('[build] ssh_full js...');
  run('moon build cmd/ssh_full --target js');
  console.log('[build] ssh_full wasm debug...');
  run('moon build cmd/ssh_full --target wasm');
  console.log('[build] ssh_full wasm release...');
  run('moon build cmd/ssh_full --target wasm --release');
  console.log('[build] ssh_full wasm-gc debug...');
  run('moon build cmd/ssh_full --target wasm-gc');
  console.log('[build] ssh_full wasm-gc release...');
  run('moon build cmd/ssh_full --target wasm-gc --release');
}

const configs = [
  { target: 'native', mode: 'debug', runner: () => `moon run cmd/ssh_full --target native` },
  { target: 'native', mode: 'release', runner: () => `moon run cmd/ssh_full --target native --release` },
  { target: 'js', mode: 'debug', runner: () => `moon run cmd/ssh_full --target js` },
  { target: 'js', mode: 'release', runner: () => `moon run cmd/ssh_full --target js --release` },
  { target: 'wasm', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm/debug/build/cmd/ssh_full/ssh_full.wasm` },
  { target: 'wasm', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm/release/build/cmd/ssh_full/ssh_full.wasm` },
  { target: 'wasm-gc', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm-gc/debug/build/cmd/ssh_full/ssh_full.wasm` },
  { target: 'wasm-gc', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm-gc/release/build/cmd/ssh_full/ssh_full.wasm` },
];

await buildAll();

const outputs = {};
for (const cfg of configs) {
  const cmd = cfg.runner();
  console.log(`[run ${cfg.target}/${cfg.mode}] ${cmd}`);
  const out = run(cmd);
  outputs[`${cfg.target}-${cfg.mode}`] = out;
}

// 计算 hash
const hashes = {};
for (const [k, v] of Object.entries(outputs)) {
  hashes[k] = hashOut(v);
}

// 打印每个 target hash
console.log('\nPer-target SHA-256 (16 chars):');
for (const [k, h] of Object.entries(hashes)) {
  console.log(`  ${k.padEnd(20)} ${h}`);
}

// 检查所有 hash 一致
const hashSet = new Set(Object.values(hashes));
const allMatch = hashSet.size === 1;
const uniqueHash = Array.from(hashSet)[0];

if (allMatch) {
  console.log(`\n✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: ${uniqueHash})`);
  console.log('  Loop #22 G1: SSH client full write path (USERAUTH/CHANNEL/DATA/EXIT) 完成');

  // 额外验证 stdout 字段
  const sampleOut = outputs['native-debug'];
  if (!sampleOut.includes('stdout: hello from mock server')) {
    console.error('✗ FAIL: stdout field missing');
    process.exit(1);
  }
  if (!sampleOut.includes('exit_code: 0')) {
    console.error('✗ FAIL: exit_code field missing');
    process.exit(1);
  }
  if (!sampleOut.includes('remote_channel: 100')) {
    console.error('✗ FAIL: remote_channel field missing');
    process.exit(1);
  }
  console.log('  + stdout byte-exact: "hello from mock server"');
  console.log('  + exit_code byte-exact: 0');
  console.log('  + remote_channel byte-exact: 100');
  console.log('  + 协议字段: 8 行 (sent_bytes / recv_bytes / stdout / exit_code / ...)');

  process.exit(0);
} else {
  console.error(`\n✗ FAIL: hash mismatch`);
  console.error(`  unique hashes: ${Array.from(hashSet).join(', ')}`);
  process.exit(1);
}