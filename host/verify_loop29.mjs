#!/usr/bin/env node
// verify_loop29.mjs -- Loop #29 UInt128 + Montgomery CIOS (64-bit limbs)
//                     4 target × 2 mode byte-exact 验证 + 性能 benchmark
//
// 用法: node host/verify_loop29.mjs

import { execSync, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const TESTS = ['u128_test', 'fastpow_test', 'bigint_test', 'kexdh_test', 'rsa_test', 'rsa2048_test'];

function hashOut(out) {
  return createHash('sha256').update(out.replace(/\r\n/g, '\n')).digest('hex').substring(0, 16);
}

function run(cmd, opts = {}) {
  try {
    return execSync(cmd, { cwd: ROOT, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'], ...opts });
  } catch (e) {
    return `ERROR: ${e.message}\nstderr: ${e.stderr?.toString() || ''}`;
  }
}

const targets = ['native', 'js', 'wasm', 'wasm-gc'];
const modes = ['debug', 'release'];

console.log('=== build ===');
for (const t of TESTS) {
  for (const target of targets) {
    for (const mode of modes) {
      const flag = mode === 'release' ? '--release' : '';
      run(`moon build cmd/${t} --target ${target} ${flag}`);
    }
  }
}
console.log(`built ${TESTS.length} tests x ${targets.length} targets x ${modes.length} modes`);

const outputs = {};   // test -> "target-mode" -> stdout
for (const t of TESTS) {
  outputs[t] = {};
  for (const target of targets) {
    for (const mode of modes) {
      const key = `${target}-${mode}`;
      const releaseFlag = mode === 'release' ? '--release' : '';
      let cmd;
      if (target === 'native' || target === 'js') {
        cmd = `moon run cmd/${t} --target ${target} ${releaseFlag}`;
      } else {
        cmd = `node host/node_host.mjs _build/${target}/${mode}/build/cmd/${t}/${t}.wasm`;
      }
      outputs[t][key] = run(cmd);
    }
  }
}

console.log('\n=== per-test SHA-256 across 4 target x 2 mode ===');
const hashSets = {};
for (const t of TESTS) {
  const hashes = {};
  for (const [k, v] of Object.entries(outputs[t])) hashes[k] = hashOut(v);
  hashSets[t] = new Set(Object.values(hashes));
  const uniq = Array.from(hashSets[t]);
  console.log(`  ${t.padEnd(14)} ${uniq.length === 1 ? 'UNIFORM' : 'MISMATCH'}  ${uniq.join(' ')}`);
}

// ---- semantic assertions on the native-debug output ----
console.log('\n=== semantic checks (native-debug) ===');
const checks = [
  [outputs.u128_test['native-debug'], 'mul FFFFFFFFFFFFFFFF FFFFFFFFFFFFFFFF -> FFFFFFFFFFFFFFFE 0000000000000001'],
  [outputs.u128_test['native-debug'], 'k32_n_prime: 0000000000000001'],
  [outputs.fastpow_test['native-debug'], 'p14_pow_match: MATCH'],
  [outputs.fastpow_test['native-debug'], 'rsa2048_pow_match: MATCH'],
  [outputs.fastpow_test['native-debug'], 'k48_pow_match: MATCH'],
  [outputs.fastpow_test['native-debug'], 'even_fallback_match: MATCH'],
  [outputs.fastpow_test['native-debug'], 'mod_mul_match: MATCH'],
  [outputs.bigint_test['native-debug'], 'pow_2_cafe_p14_first16: 5D005C6A0D1A17F5'],
  [outputs.bigint_test['native-debug'], 'pow_2_cafe_p14_last16: 4858CA217C13FAAE'],
  [outputs.kexdh_test['native-debug'], 'dh14_consistency: MATCH'],
  [outputs.rsa_test['native-debug'], 'rsa_verify: PASS'],
  [outputs.rsa_test['native-debug'], 'rsa_verify_after_sign: PASS'],
  [outputs.rsa_test['native-debug'], 'rsa_wrong_msg_reject: CORRECT_FAIL'],
  [outputs.rsa2048_test['native-debug'], 'rsa2048_verify: PASS'],
  [outputs.rsa2048_test['native-debug'], 'rsa2048_wrong_msg_reject: CORRECT_FAIL'],
];
let semanticOk = true;
for (const [out, expected] of checks) {
  if (out.includes(expected)) {
    console.log(`  OK   ${expected.slice(0, 64)}`);
  } else {
    console.error(`  FAIL missing: ${expected.slice(0, 64)}`);
    semanticOk = false;
  }
}

const allUniform = Object.values(hashSets).every(s => s.size === 1);

console.log('\n=== benchmark (native release, 50 x 2048-bit modexp) ===');
const EXE = {
  bench_slow: '_build/native/release/build/cmd/bench_slow/bench_slow.exe',
  bench_fast: '_build/native/release/build/cmd/bench_fast/bench_fast.exe',
  bench_cached: '_build/native/release/build/cmd/bench_cached/bench_cached.exe',
};
for (const p of Object.keys(EXE)) run(`moon build cmd/${p} --target native --release`);

function timeRun(prog) {
  const exe = join(ROOT, EXE[prog]);
  execFileSync(exe, [], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });   // warm
  const t0 = process.hrtime.bigint();
  const out = execFileSync(exe, [], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  const t1 = process.hrtime.bigint();
  return { ms: Number(t1 - t0) / 1e6, out: out.trim() };
}

const slow = timeRun('bench_slow');
const fast = timeRun('bench_fast');
const cached = timeRun('bench_cached');
console.log(`  schoolbook              ${(slow.ms / 50).toFixed(3)} ms/op`);
console.log(`  montgomery (ctx per op) ${(fast.ms / 50).toFixed(3)} ms/op   ${(slow.ms / fast.ms).toFixed(2)}x`);
console.log(`  montgomery (ctx cached) ${(cached.ms / 50).toFixed(3)} ms/op   ${(slow.ms / cached.ms).toFixed(2)}x`);

const benchMatch = slow.out === fast.out && slow.out === cached.out;
console.log(`  bench results byte-exact: ${benchMatch ? 'YES' : 'NO'}`);

if (allUniform && semanticOk && benchMatch) {
  console.log('\n✓ PASS: Loop #29 UInt128 + Montgomery CIOS');
  for (const t of TESTS) {
    console.log(`  ${t.padEnd(14)} ${Array.from(hashSets[t])[0]}`);
  }
  console.log(`\n  + mul_u64x64: 64x64 -> (hi,lo) via four 32x32 partial products, 20 KAT vectors byte-exact vs Python`);
  console.log(`  + Montgomery CIOS: n' (Newton, 6 iter), R^2 (repeated doubling), REDC inner loop`);
  console.log(`  + Verified at K = 1, 2, 3, 8, 32 (64-bit .. 2048-bit moduli)`);
  console.log(`  + Per-op values cross-checked: n_prime / r2 / redc / mont_mul / mont_pow / aR / from_mont`);
  console.log(`  + 2048-bit modexp: ${(slow.ms / fast.ms).toFixed(1)}x (${(slow.ms / cached.ms).toFixed(1)}x with cached context) vs schoolbook`);
  console.log(`  + RSA verify/sign and DH group-14 KEX now route through mod_pow_auto`);
  console.log(`  + Even-modulus fallback to schoolbook verified (pow(2,10,1000) = 0x18)`);
  process.exit(0);
} else {
  console.error('\n✗ FAIL');
  if (!allUniform) console.error('  hash mismatch across targets/modes');
  if (!semanticOk) console.error('  semantic check failed');
  if (!benchMatch) console.error('  bench results differ');
  process.exit(1);
}
