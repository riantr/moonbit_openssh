#!/usr/bin/env node
// verify_loop27.mjs -- Loop #27 RSA host key verify + sign (PKCS#1 v1.5 + SHA-256)
//                    4 target × 2 mode byte-exact 验证
//
// 用法: node host/verify_loop27.mjs

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function hashOut(out) {
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
  for (const mode of ['', '--release']) {
    for (const target of ['native', 'js', 'wasm', 'wasm-gc']) {
      const flag = mode ? `--target ${target} ${mode}` : `--target ${target}`;
      console.log(`[build rsa_test ${flag}]`);
      run(`moon build cmd/rsa_test ${flag}`);
    }
  }
}

const configs = [
  { target: 'native', mode: 'debug', runner: () => `moon run cmd/rsa_test --target native` },
  { target: 'native', mode: 'release', runner: () => `moon run cmd/rsa_test --target native --release` },
  { target: 'js', mode: 'debug', runner: () => `moon run cmd/rsa_test --target js` },
  { target: 'js', mode: 'release', runner: () => `moon run cmd/rsa_test --target js --release` },
  { target: 'wasm', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm/debug/build/cmd/rsa_test/rsa_test.wasm` },
  { target: 'wasm', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm/release/build/cmd/rsa_test/rsa_test.wasm` },
  { target: 'wasm-gc', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm-gc/debug/build/cmd/rsa_test/rsa_test.wasm` },
  { target: 'wasm-gc', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm-gc/release/build/cmd/rsa_test/rsa_test.wasm` },
];

await buildAll();

const outputs = {};
for (const cfg of configs) {
  const cmd = cfg.runner();
  console.log(`[run ${cfg.target}/${cfg.mode}] ${cmd}`);
  outputs[`${cfg.target}-${cfg.mode}`] = run(cmd);
}

const hashes = {};
for (const [k, v] of Object.entries(outputs)) {
  hashes[k] = hashOut(v);
}

console.log('\nPer-target SHA-256 (16 chars):');
for (const [k, h] of Object.entries(hashes)) {
  console.log(`  ${k.padEnd(20)} ${h}`);
}

const hashSet = new Set(Object.values(hashes));
const allMatch = hashSet.size === 1;

if (allMatch) {
  const uniqueHash = Array.from(hashSet)[0];
  console.log(`\n✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: ${uniqueHash})`);
  console.log('  Loop #27 G3: RSA host key verify + sign (PKCS#1 v1.5 + SHA-256) 完成');

  const sampleOut = outputs['native-debug'];
  const checks = [
    ['rsa_verify', 'PASS'],
    ['sig2_len', '64'],
    ['rsa_verify_after_sign', 'PASS'],
    ['rsa_wrong_msg_reject', 'CORRECT_FAIL'],
  ];

  for (const [key, expected] of checks) {
    if (sampleOut.includes(`${key}: ${expected}`)) {
      console.log(`  ✓ ${key}: ${expected}`);
    } else {
      console.error(`  ✗ ${key}: expected "${expected}" not in output`);
      process.exit(1);
    }
  }

  console.log('\n  + RSA verify: sig^e mod n + PKCS#1 v1.5 parse + SHA-256 compare');
  console.log('  + RSA sign: PKCS#1 v1.5 padding + sig^d mod n');
  console.log('  + 512-bit RSA test vector (Loop #28+ for 2048/4096-bit with Montgomery REDC)');

  process.exit(0);
} else {
  console.error(`\n✗ FAIL: hash mismatch`);
  console.error(`  unique hashes: ${Array.from(hashSet).join(', ')}`);
  process.exit(1);
}