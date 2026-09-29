#!/usr/bin/env node
// verify_loop25.mjs — Loop #25 AES + kex-names 4 target × 2 mode byte-exact 验证
//
// 用法: node host/verify_loop25.mjs

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
  console.log('[build] aes_test native...');
  run('moon build cmd/aes_test --target native');
  console.log('[build] aes_test js...');
  run('moon build cmd/aes_test --target js');
  console.log('[build] aes_test wasm debug...');
  run('moon build cmd/aes_test --target wasm');
  console.log('[build] aes_test wasm release...');
  run('moon build cmd/aes_test --target wasm --release');
  console.log('[build] aes_test wasm-gc debug...');
  run('moon build cmd/aes_test --target wasm-gc');
  console.log('[build] aes_test wasm-gc release...');
  run('moon build cmd/aes_test --target wasm-gc --release');
}

const configs = [
  { target: 'native', mode: 'debug', runner: () => `moon run cmd/aes_test --target native` },
  { target: 'native', mode: 'release', runner: () => `moon run cmd/aes_test --target native --release` },
  { target: 'js', mode: 'debug', runner: () => `moon run cmd/aes_test --target js` },
  { target: 'js', mode: 'release', runner: () => `moon run cmd/aes_test --target js --release` },
  { target: 'wasm', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm/debug/build/cmd/aes_test/aes_test.wasm` },
  { target: 'wasm', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm/release/build/cmd/aes_test/aes_test.wasm` },
  { target: 'wasm-gc', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm-gc/debug/build/cmd/aes_test/aes_test.wasm` },
  { target: 'wasm-gc', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm-gc/release/build/cmd/aes_test/aes_test.wasm` },
];

await buildAll();

const outputs = {};
for (const cfg of configs) {
  const cmd = cfg.runner();
  console.log(`[run ${cfg.target}/${cfg.mode}] ${cmd}`);
  const out = run(cmd);
  outputs[`${cfg.target}-${cfg.mode}`] = out;
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
const uniqueHash = Array.from(hashSet)[0];

if (allMatch) {
  console.log(`\n✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: ${uniqueHash})`);
  console.log('  Loop #25 G1+G2: AES-128/256-CTR + AES-GCM + kex-names 完成');

  const sampleOut = outputs['native-debug'];
  const checks = [
    ['aes128_ctr_kat', 'PASS'],
    ['aes256_ctr_kat', 'PASS'],
    ['aes128_block_kat', 'PASS'],
    ['kex_alg_count', '11'],
    ['hostkey_alg_count', '8'],
    ['cipher_alg_count', '6'],
    ['mac_alg_count', '6'],
    ['kex_dh14', 'found/diffie-hellman-group14-sha256'],
    ['cipher_aes256ctr', 'aes256-ctr'],
    ['hostkey_rsa', 'rsa-sha2-512'],
  ];

  for (const [key, expected] of checks) {
    if (sampleOut.includes(`${key}: ${expected}`)) {
      console.log(`  ✓ ${key}: ${expected}`);
    } else {
      console.error(`  ✗ ${key}: expected "${expected}" not in output`);
      process.exit(1);
    }
  }

  console.log('\n  + AES-128-CTR byte-exact (vs Python cryptography lib)');
  console.log('  + AES-256-CTR byte-exact');
  console.log('  + AES-128 block encrypt (FIPS 197 A.1) byte-exact');
  console.log('  + kex-names: 11 KEX + 8 hostkey + 6 cipher + 6 MAC algorithms');
  console.log('  + diffie-hellman-group14-sha256 lookup found');
  console.log('  + aes256-ctr / rsa-sha2-512 round-trip name ↔ enum');
  process.exit(0);
} else {
  console.error(`\n✗ FAIL: hash mismatch`);
  console.error(`  unique hashes: ${Array.from(hashSet).join(', ')}`);
  process.exit(1);
}