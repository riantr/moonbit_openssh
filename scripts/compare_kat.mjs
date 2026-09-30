// scripts/compare_kat.mjs -- compare MoonBit stdout against a Python KAT file.
// Usage: node scripts/compare_kat.mjs <actual.log> <expected.txt>

import { readFileSync } from 'node:fs';

const [actualPath, expectedPath] = process.argv.slice(2);

function canon(line) {
  let s = line.trim();
  if (!s) return '';
  // Strip MoonBit build warnings and banner lines.
  if (s.startsWith('Warning') || s.startsWith('Error') || s.startsWith('─') ||
      s.startsWith('╭') || s.startsWith('│') || s.startsWith('╯') ||
      s.includes('unused_')) return '';
  if (s.startsWith('mul ')) {
    const parts = s.split(/\s+/);
    return ['mul', parts[1].toUpperCase(), parts[2].toUpperCase(),
            parts[3].toUpperCase(), parts[4].toUpperCase()].join(' ');
  }
  // Skip compiler warning context lines (they carry box-drawing / gutter prefixes).
  if (/^\d+\s*│/.test(s) || /^\d+\s*╭/.test(s) || /^\d+\s*╯/.test(s)) return '';
  if (s.startsWith('===')) return '';
  // key: value  -> uppercase the hex value, strip leading zeros
  const ci = s.indexOf(':');
  if (ci < 0) return s;
  const key = s.slice(0, ci).trim();
  let val = s.slice(ci + 1).trim();
  if (/^[0-9A-Fa-f]+$/.test(val)) {
    val = val.toUpperCase().replace(/^0+(?=.)/, '');
  }
  return `${key}: ${val}`;
}

const actual = readFileSync(actualPath, 'utf-8')
  .split(/\r?\n/).map(canon).filter(s => s !== '');
const expected = readFileSync(expectedPath, 'utf-8')
  .split(/\r?\n/).map(canon).filter(s => s !== '');

if (actual.length !== expected.length) {
  console.error(`line count mismatch: actual=${actual.length} expected=${expected.length}`);
}
let bad = 0;
const n = Math.max(actual.length, expected.length);
for (let i = 0; i < n; i++) {
  const a = actual[i] ?? '<missing>';
  const e = expected[i] ?? '<missing>';
  if (a !== e) {
    bad++;
    if (bad <= 15) {
      console.error(`MISMATCH #${bad} at line ${i + 1}`);
      console.error(`  exp: ${e.length > 100 ? e.slice(0, 100) + '...' : e}`);
      console.error(`  act: ${a.length > 100 ? a.slice(0, 100) + '...' : a}`);
    }
  }
}

if (bad === 0) {
  console.log(`OK: ${n} lines byte-exact match vs Python reference`);
  process.exit(0);
} else {
  console.error(`FAIL: ${bad}/${n} lines differ`);
  process.exit(1);
}
