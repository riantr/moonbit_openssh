// host/bench_modpow.mjs -- wall-clock benchmark: schoolbook vs Montgomery CIOS
//                         for 2048-bit RSA modexp.
//
// Runs the native .exe directly (no `moon run` / JVM startup overhead) so the
// number reflects real compute cost. Process spawn is still included, but it is
// amortized over ITERS modexps.
//
// Usage: node host/bench_modpow.mjs

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ITERS = 50;

const EXE = {
  bench_slow: '_build/native/release/build/cmd/bench_slow/bench_slow.exe',
  bench_fast: '_build/native/release/build/cmd/bench_fast/bench_fast.exe',
  bench_cached: '_build/native/release/build/cmd/bench_cached/bench_cached.exe',
};

function build(prog) {
  execFileSync('moon', ['build', `cmd/${prog}`, '--target', 'native', '--release'],
    { cwd: ROOT, encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
}

function timeRun(prog) {
  const exe = join(ROOT, EXE[prog]);
  // warm
  execFileSync(exe, [], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  const t0 = process.hrtime.bigint();
  const out = execFileSync(exe, [], { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] });
  const t1 = process.hrtime.bigint();
  return { ms: Number(t1 - t0) / 1e6, out: out.trim() };
}

for (const p of Object.keys(EXE)) build(p);

console.log(`Timing ${ITERS} x 2048-bit modexp per program (native .exe, no toolchain overhead)\n`);

const slow = timeRun('bench_slow');
const fast = timeRun('bench_fast');
const cached = timeRun('bench_cached');

console.log(`schoolbook                : ${slow.ms.toFixed(1)} ms total  (${(slow.ms / ITERS).toFixed(3)} ms/op)`);
console.log(`montgomery (ctx per op)   : ${fast.ms.toFixed(1)} ms total  (${(fast.ms / ITERS).toFixed(3)} ms/op)  ${(slow.ms / fast.ms).toFixed(2)}x`);
console.log(`montgomery (ctx cached)   : ${cached.ms.toFixed(1)} ms total  (${(cached.ms / ITERS).toFixed(3)} ms/op)  ${(slow.ms / cached.ms).toFixed(2)}x`);

let bad = 0;
for (const [name, r] of [['bench_fast', fast], ['bench_cached', cached]]) {
  if (r.out !== slow.out) {
    bad++;
    console.error(`\n✗ FAIL: ${name} differs from bench_slow`);
    console.error(`  slow: ${slow.out.slice(0, 80)}...`);
    console.error(`  ${name}: ${r.out.slice(0, 80)}...`);
  }
}
if (bad) process.exit(1);

console.log(`\n✓ PASS: bench_slow == bench_fast == bench_cached byte-exact`);
console.log(`  value: ${slow.out.slice(0, 64)}...`);
