"""Generate cmd/bench_slow and cmd/bench_fast from the existing RSA-2048 KAT."""
import re

src = open('cmd/rsa2048_test/main.mbt', encoding='utf-8').read()


def grab(name):
    m = re.search(r'let ' + name + r'\s*: FixedArray\[Byte\] = FixedArray::from_array\(\[(.*?)\]\)',
                  src, re.S)
    return m.group(0)


n_block = grab('n_bytes')
s_block = grab('sig_bytes')

PKG = '''///| cmd/%s -- Loop #29 G3 benchmark
import {
  "openssh/openssh_moonbit/src/bigint",
}

pkgtype(kind: "executable")
'''

for prog, fn, label in (('bench_slow', 'mod_pow', 'schoolbook'),
                        ('bench_fast', 'mod_pow_auto', 'Montgomery CIOS (ctx rebuilt per op)')):
    out = []
    out.append(f'///| Loop #29 G3 benchmark: {label} 2048-bit modexp x 50')
    out.append('///| Wall-clock is measured by host/verify_loop29.mjs around this process.')
    out.append('')
    out.append('fn main {')
    out.append('  ' + n_block)
    out.append('  ' + s_block)
    out.append('  let n = @bigint.BigNat::from_bytes_be(n_bytes)')
    out.append('  let sig = @bigint.BigNat::from_bytes_be(sig_bytes)')
    out.append('  let e = @bigint.BigNat::from_bytes_be(FixedArray::from_array([0x01, 0x00, 0x01]))')
    out.append('  let mut i = 0')
    out.append('  let mut acc = @bigint.BigNat::from_uint64(0UL)')
    out.append('  while i < 50 {')
    out.append(f'    acc = @bigint.BigNat::{fn}(sig, e, n)')
    out.append('    i = i + 1')
    out.append('  }')
    out.append('  // Print the accumulator so the loop cannot be elided,')
    out.append('  // and so both programs prove byte-exact agreement.')
    out.append('  println(@bigint.BigNat::to_hex(acc))')
    out.append('}')
    open(f'cmd/{prog}/main.mbt', 'w', encoding='utf-8').write('\n'.join(out) + '\n')
    open(f'cmd/{prog}/moon.pkg', 'w', encoding='utf-8').write(PKG % prog)

# ---- cached-context variant: build the Montgomery context once, reuse it ----
# This is the realistic SSH host-key pattern: the modulus is fixed for the
# session, so R^2 / n' are computed once instead of per exponentiation.
out = []
out.append('///| Loop #29 G3 benchmark: Montgomery CIOS with a cached context, 2048-bit modexp x 50')
out.append('///| The modulus is fixed for an SSH session, so n\' and R^2 are precomputed once.')
out.append('')
out.append('fn main {')
out.append('  ' + n_block)
out.append('  ' + s_block)
out.append('  let n = @bigint.BigNat::from_bytes_be(n_bytes)')
out.append('  let sig = @bigint.BigNat::from_bytes_be(sig_bytes)')
out.append('  let e = @bigint.BigNat::from_bytes_be(FixedArray::from_array([0x01, 0x00, 0x01]))')
out.append('  // One-time context setup (n\' via Newton, R^2 via repeated doubling).')
out.append('  let k = n.limb64_len()')
out.append('  let ctx = @bigint.MontCtx::new(n.to_limbs64(k), k)')
out.append('  let mut i = 0')
out.append('  let mut acc = @bigint.BigNat::from_uint64(0UL)')
out.append('  while i < 50 {')
out.append('    acc = @bigint.mont_pow_with(ctx, sig, e)')
out.append('    i = i + 1')
out.append('  }')
out.append('  println(@bigint.BigNat::to_hex(acc))')
out.append('}')
open('cmd/bench_cached/main.mbt', 'w', encoding='utf-8').write('\n'.join(out) + '\n')
open('cmd/bench_cached/moon.pkg', 'w', encoding='utf-8').write(PKG % 'bench_cached')

print('generated cmd/bench_slow, cmd/bench_fast, cmd/bench_cached')
