#!/usr/bin/env node
// verify_loop24.mjs — Loop #24 ssh_config fnmatch/parser/match 4 target × 2 mode byte-exact 验证
//
// 用法: node host/verify_loop24.mjs
//
// 跑 cmd/sshconfig_test 4 target × 2 mode = 8 outputs,验证 byte-exact 一致

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
  console.log('[build] sshconfig_test native...');
  run('moon build cmd/sshconfig_test --target native');
  console.log('[build] sshconfig_test js...');
  run('moon build cmd/sshconfig_test --target js');
  console.log('[build] sshconfig_test wasm debug...');
  run('moon build cmd/sshconfig_test --target wasm');
  console.log('[build] sshconfig_test wasm release...');
  run('moon build cmd/sshconfig_test --target wasm --release');
  console.log('[build] sshconfig_test wasm-gc debug...');
  run('moon build cmd/sshconfig_test --target wasm-gc');
  console.log('[build] sshconfig_test wasm-gc release...');
  run('moon build cmd/sshconfig_test --target wasm-gc --release');
}

const configs = [
  { target: 'native', mode: 'debug', runner: () => `moon run cmd/sshconfig_test --target native` },
  { target: 'native', mode: 'release', runner: () => `moon run cmd/sshconfig_test --target native --release` },
  { target: 'js', mode: 'debug', runner: () => `moon run cmd/sshconfig_test --target js` },
  { target: 'js', mode: 'release', runner: () => `moon run cmd/sshconfig_test --target js --release` },
  { target: 'wasm', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm/debug/build/cmd/sshconfig_test/sshconfig_test.wasm` },
  { target: 'wasm', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm/release/build/cmd/sshconfig_test/sshconfig_test.wasm` },
  { target: 'wasm-gc', mode: 'debug', runner: () => `node host/node_host.mjs _build/wasm-gc/debug/build/cmd/sshconfig_test/sshconfig_test.wasm` },
  { target: 'wasm-gc', mode: 'release', runner: () => `node host/node_host.mjs _build/wasm-gc/release/build/cmd/sshconfig_test/sshconfig_test.wasm` },
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
  console.log('  Loop #24 G1+G2+G3: ssh_config fnmatch/parser/match 完成');

  const sampleOut = outputs['native-debug'];
  const checks = [
    ['fnmatch_pass', '23/23'],
    ['parsed_sections', '3'],
    ['foo.example.com match', 'yes'],
    ['foo.example.com User', 'foo'],
    ['foo.example.com Port', '2222'],
    ['ngs.fi User', 'bar'],
    ['ngs.fi HostName', 'real.host'],
    ['unknown.host ForwardAgent', 'no'],
    ['foo.example.com NonExistent', 'none'],
  ];

  for (const [key, expected] of checks) {
    if (sampleOut.includes(`${key}: ${expected}`)) {
      console.log(`  ✓ ${key}: ${expected}`);
    } else {
      console.error(`  ✗ ${key}: expected "${expected}" not in output`);
      process.exit(1);
    }
  }

  console.log('\n  + fnmatch 23/23 KAT PASS (?, * wildcards)');
  console.log('  + ssh_config parser 3 sections byte-exact');
  console.log('  + Host pattern matching first-match-wins byte-exact');
  console.log('  + 9 字段 byte-exact: fnmatch_pass/parsed_sections/match + 5 个 option 匹配 + NonExistent');
  process.exit(0);
} else {
  console.error(`\n✗ FAIL: hash mismatch`);
  console.error(`  unique hashes: ${Array.from(hashSet).join(', ')}`);
  process.exit(1);
}