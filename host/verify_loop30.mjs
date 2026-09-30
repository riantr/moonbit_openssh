#!/usr/bin/env node
// verify_loop30.mjs -- Loop #30 ECDSA (P-256 / P-384, RFC 6979) + SSH wire
//                     4 target x 2 mode byte-exact + KAT vs Python
//                     + no-regression against the Loop #29 baselines
//
// 用法: node host/verify_loop30.mjs

import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Loop #29 baselines, re-measured at HEAD (a241c00) rather than transcribed,
// so this harness is its own reference. A change in any of these means a
// shared primitive (bigint / Montgomery / RSA / DH) regressed, which is
// exactly what the mod_mul_auto reduction fix in this loop had to avoid.
const BASELINE = {
  u128_test: '1bbbc364fb3d5e51',
  fastpow_test: '9707cf997769eddb',
  bigint_test: '12ff7ed89fd9d856',
  kexdh_test: 'afbca72be34dfba2',
  rsa_test: '7382ee95fe7d6677',
  rsa2048_test: 'dffb73d5452ae5e6',
};

const NEW_TESTS = ['ecdsa_test'];
const ALL_TESTS = [...Object.keys(BASELINE), ...NEW_TESTS];

const TARGETS = ['native', 'js', 'wasm', 'wasm-gc'];
const MODES = ['debug', 'release'];

function hashOut(out) {
  return createHash('sha256').update(out.replace(/\r\n/g, '\n')).digest('hex').substring(0, 16);
}

function run(cmd) {
  try {
    return execSync(cmd, { cwd: ROOT, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (e) {
    return `ERROR: ${e.message}\nstderr: ${e.stderr?.toString() || ''}`;
  }
}

console.log('=== build ===');
for (const t of ALL_TESTS) {
  for (const target of TARGETS) {
    for (const mode of MODES) {
      const flag = mode === 'release' ? '--release' : '';
      run(`moon build cmd/${t} --target ${target} ${flag}`);
    }
  }
}
console.log(`built ${ALL_TESTS.length} tests x ${TARGETS.length} targets x ${MODES.length} modes\n`);

const outputs = {};
for (const t of ALL_TESTS) {
  outputs[t] = {};
  for (const target of TARGETS) {
    for (const mode of MODES) {
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

console.log('=== per-test SHA-256 across 4 target x 2 mode ===');
const hashSets = {};
for (const t of ALL_TESTS) {
  const hashes = {};
  for (const [k, v] of Object.entries(outputs[t])) hashes[k] = hashOut(v);
  hashSets[t] = new Set(Object.values(hashes));
  const uniq = Array.from(hashSets[t]);
  console.log(`  ${t.padEnd(14)} ${uniq.length === 1 ? 'UNIFORM ' : 'MISMATCH'} ${uniq.join(' ')}`);
}

// ---------------------------------------------------------------- KAT
function canon(line) {
  let s = line.trim();
  if (!s) return '';
  if (s.startsWith('Warning') || s.startsWith('Error') || s.startsWith('─') ||
      s.startsWith('╭') || s.startsWith('│') || s.startsWith('╯') ||
      s.includes('unused_')) return '';
  if (/^\d+\s*[│╭╯]/.test(s)) return '';
  if (s.startsWith('===')) return '';
  const ci = s.indexOf(':');
  if (ci < 0) return s;
  const key = s.slice(0, ci).trim();
  let val = s.slice(ci + 1).trim();
  if (/^[0-9A-Fa-f]+$/.test(val)) val = val.toUpperCase().replace(/^0+(?=.)/, '');
  return `${key}: ${val}`;
}

function compareKat(actualText, expectedPath) {
  const actual = actualText.split(/\r?\n/).map(canon).filter(s => s !== '');
  const expected = readFileSync(join(ROOT, expectedPath), 'utf-8')
    .split(/\r?\n/).map(canon).filter(s => s !== '');
  const bad = [];
  const n = Math.max(actual.length, expected.length);
  for (let i = 0; i < n; i++) {
    const a = actual[i] ?? '<missing>';
    const e = expected[i] ?? '<missing>';
    if (a !== e) bad.push({ line: i + 1, exp: e, act: a });
  }
  return { n, bad, lenMatch: actual.length === expected.length };
}

console.log('\n=== KAT vs Python reference (all 8 combinations) ===');
let katOk = true;
for (const target of TARGETS) {
  for (const mode of MODES) {
    const r = compareKat(outputs.ecdsa_test[`${target}-${mode}`], 'scripts/ecdsa_kat_expected.txt');
    const ok = r.bad.length === 0 && r.lenMatch;
    if (!ok) katOk = false;
    console.log(`  ${`${target}-${mode}`.padEnd(12)} ${ok ? 'OK' : 'FAIL'}  ${r.n} lines` +
                (r.bad.length ? `  first: line ${r.bad[0].line} exp="${r.bad[0].exp.slice(0, 60)}" act="${r.bad[0].act.slice(0, 60)}"` : ''));
  }
}

// ---------------------------------------------------------------- constants
console.log('\n=== curve constants vs FIPS 186-4 ===');
const consts = run('python scripts/check_curve_consts.py');
const constsOk = consts.includes('\nPASS') || consts.trim().endsWith('PASS');
console.log(`  check_curve_consts.py: ${constsOk ? 'PASS' : 'FAIL'}`);
if (!constsOk) console.log(consts);

// ---------------------------------------------------------------- regression
console.log('\n=== no-regression vs Loop #29 baselines ===');
let regOk = true;
for (const [t, want] of Object.entries(BASELINE)) {
  const got = Array.from(hashSets[t])[0];
  const uniform = hashSets[t].size === 1;
  const ok = uniform && got === want;
  if (!ok) regOk = false;
  console.log(`  ${t.padEnd(14)} ${ok ? 'UNCHANGED' : 'CHANGED  '} ${got}` +
              (ok ? '' : `  (baseline ${want})`));
}

// ---------------------------------------------------------------- semantic
console.log('\n=== semantic checks (native-debug) ===');
const nd = outputs.ecdsa_test['native-debug'];
const checks = [
  [nd, 'p256_v0_sign_match: true'],
  [nd, 'p384_v0_sign_match: true'],
  [nd, 'p256_v2_verify_ref: true'],
  [nd, 'p384_v2_verify_ref: true'],
  [nd, 'p256_2G_x: 7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978'],
  [nd, 'p256_3G_on_curve: true'],
  [nd, 'p384_3G_on_curve: true'],
  [nd, 'p256_nG_is_inf: true'],
  [nd, 'p384_nG_is_inf: true'],
  [nd, 'p256_ladder_matches_add: true'],
  [nd, 'p384_ladder_matches_add: true'],
  [nd, 'p256_unreduced_ge_n: true'],
  [nd, 'p384_unreduced_ge_n: true'],
  [nd, 'p256_unreduced_match: MATCH'],
  [nd, 'p384_unreduced_match: MATCH'],
  [nd, 'p256_mpint_r_len: 33'],
  [nd, 'p384_mpint_r_len: 49'],
  [nd, 'p256_wire_sig_verify: true'],
  [nd, 'p384_wire_sig_verify: true'],
  [nd, 'p256_wire_pk_roundtrip: true'],
  [nd, 'p256_wire_fixed_rejected: CORRECT_FAIL'],
  [nd, 'p384_wire_fixed_rejected: CORRECT_FAIL'],
  [nd, 'p256_wire_short_mpint: true'],
  [nd, 'p256_wire_neg_badpoint: CORRECT_FAIL'],
  [nd, 'p256_wire_neg_compressed: CORRECT_FAIL'],
  [nd, 'p256_wire_neg_negmpint: CORRECT_FAIL'],
  [nd, 'p384_wire_neg_sigtrail: CORRECT_FAIL'],
  [nd, 'p256_neg_zero_r: CORRECT_FAIL'],
  [nd, 'p384_neg_big_s: CORRECT_FAIL'],
];
let semanticOk = true;
for (const [out, expected] of checks) {
  if (out.includes(expected)) {
    console.log(`  OK   ${expected}`);
  } else {
    console.error(`  FAIL missing: ${expected}`);
    semanticOk = false;
  }
}

const allUniform = Object.values(hashSets).every(s => s.size === 1);

if (allUniform && katOk && constsOk && regOk && semanticOk) {
  console.log('\n✓ PASS: Loop #30 ECDSA (P-256 / P-384) + RFC 6979 + SSH wire');
  for (const t of ALL_TESTS) console.log(`  ${t.padEnd(14)} ${Array.from(hashSets[t])[0]}`);
  console.log(`\n  + SHA-384 + HMAC-SHA-384 (RFC 5656 6.2.1 hash selection)`);
  console.log(`  + Jacobian P-256/P-384: dbl-2001-b, add-2007-bl in EFD scaling`);
  console.log(`  + RFC 6979 deterministic nonce: k/Q/r/s byte-exact vs Python, both curves`);
  console.log(`  + ECDSA sign/verify matches the reference (r, s) exactly`);
  console.log(`  + SSH wire: RFC 5656 pubkey blob + mpint r/s signature blob, byte-exact`);
  console.log(`  + mpint sign-byte path exercised (P-256 r/s are 33 bytes, P-384 are 49)`);
  console.log(`  + hostkey: EcdsaKey variant, EC_CURVE_MISMATCH / KEY_INVALID_EC_VALUE`);
  console.log(`  + FIX: mod_mul_auto / mod_pow_auto now reduce operands before CIOS`);
  console.log(`    (Montgomery CIOS needs a,b < n; ECDSA's k^-1*(e+r*d) exceeded n)`);
  console.log(`  + FIX: mod_pow_auto falls back to schoolbook when the exponent is wider than k limbs`);
  console.log(`  + Loop #29 baselines all unchanged`);
  process.exit(0);
} else {
  console.error('\n✗ FAIL');
  if (!allUniform) console.error('  hash mismatch across targets/modes');
  if (!katOk) console.error('  KAT mismatch vs Python');
  if (!constsOk) console.error('  curve constants mismatch');
  if (!regOk) console.error('  regression against Loop #29 baselines');
  if (!semanticOk) console.error('  semantic check failed');
  process.exit(1);
}
