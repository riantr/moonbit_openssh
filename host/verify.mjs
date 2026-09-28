#!/usr/bin/env node
// 4 target × 2 mode = 8 outputs byte-exact diff 验证。
//
// 用法:  node host/verify.mjs
//
// 输出 8 个 stdout,计算 SHA-256,若 8 个 hash 完全相同 → PASS
//
// 注意:本脚本依赖 moon CLI 已编译各 target。

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function hashOut(out) {
  // 规范化 line ending: native target 在 Windows 用 CRLF,其他 target 用 LF
  // 算法输出 byte-exact 一致,只是 line ending 不同
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
  console.log('[build] native...');
  run('moon build cmd/main --target native');
  console.log('[build] js...');
  run('moon build cmd/main --target js');
  console.log('[build] wasm debug...');
  run('moon build cmd/main --target wasm');
  console.log('[build] wasm release...');
  run('moon build cmd/main --target wasm --release');
  console.log('[build] wasm-gc debug...');
  run('moon build cmd/main --target wasm-gc');
  console.log('[build] wasm-gc release...');
  run('moon build cmd/main --target wasm-gc --release');
}

const configs = [
  { target: 'native', mode: 'debug', runner: (m) => `moon run cmd/main --target native` },
  { target: 'native', mode: 'release', runner: (m) => `moon run cmd/main --target native --release` },
  { target: 'js', mode: 'debug', runner: (m) => `moon run cmd/main --target js` },
  { target: 'js', mode: 'release', runner: (m) => `moon run cmd/main --target js --release` },
  { target: 'wasm', mode: 'debug', runner: (m) => `node host/node_host.mjs _build/wasm/${m}/build/cmd/main/main.wasm` },
  { target: 'wasm', mode: 'release', runner: (m) => `node host/node_host.mjs _build/wasm/${m}/build/cmd/main/main.wasm` },
  { target: 'wasm-gc', mode: 'debug', runner: (m) => `node host/node_host.mjs _build/wasm-gc/${m}/build/cmd/main/main.wasm` },
  { target: 'wasm-gc', mode: 'release', runner: (m) => `node host/node_host.mjs _build/wasm-gc/${m}/build/cmd/main/main.wasm` },
];

await buildAll();

const outputs = {};
for (const cfg of configs) {
  const cmd = cfg.runner(cfg.mode);
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
console.log('Per-target SHA-256 (16 chars):');
for (const [k, h] of Object.entries(hashes)) {
  console.log(`  ${k.padEnd(20)} ${h}`);
}

// 写所有 output 到磁盘
await writeFile(join(ROOT, 'host', 'outputs.json'),
  JSON.stringify(Object.fromEntries(Object.entries(outputs).map(([k, v]) => [k, v])), null, 2));

// 验证唯一性
const uniqueHashes = new Set(Object.values(hashes));
if (uniqueHashes.size === 1) {
  console.log(`\n✓ PASS: 4 target × 2 mode = ${configs.length} outputs byte-exact 一致 (hash: ${[...uniqueHashes][0]})`);
  console.log('  (line endings 规范化: CRLF → LF,因 Windows native target 用 CRLF)');
  process.exit(0);
} else {
  console.log(`\n✗ FAIL: ${uniqueHashes.size} unique hashes, expected 1`);
  process.exit(1);
}