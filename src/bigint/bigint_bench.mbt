///| src/bigint benchmarks -- Loop #67

///|

///| `moon bench` was wired up in `ci/qa.py` long before this file existed, and

///| the row had never actually measured anything: `moon bench` on a package

///| with no benchmarks exits **0** while printing "Total tests: 0" and "Warning:

///| no test entry found". A check on the exit code alone would have reported a

///| PASS having measured nothing, which is why `verify_loop67.mjs` asserts on

///| that text rather than on the exit code.

///|

///| A MoonBit benchmark is a **test block taking a `@bench.T`**, not a

///| `bench "..." { }` block -- `bench` is not a keyword in this position, and

///| `ignore(x)` / `let _ = x` both fail to parse inside one. `b.keep()` is

///| what stops the optimiser deleting the computation.

///|

///| These are the operations an SSH client actually spends its time in:

///|

///|  * `mod_pow` / `mod_pow_auto` -- DH group 14 key exchange (RFC 4253 §8) and

///|    RSA signature verification are each one 2048-bit modular exponentiation

///|    per session.

///|  * `mod_mul` -- the inner loop of the above, measured on its own so a

///|    regression in the multiply is distinguishable from a regression in the

///|    square-and-multiply schedule.

///|  * `mpint_encode` / a bytes round trip -- wire conversion. These are cheap

///|    next to a modexp, which is exactly why they belong in the same run: a

///|    change that made encoding expensive would otherwise hide inside the

///|    modexp noise.

///|

///| **The modulus is RFC 3526 group 14, derived rather than pasted.** The prime

///| is 2^2048 - 189. 2^2048 - 1 is 255 bytes of 0xFF followed by 0xFF, and

///| 189 = 0xBC, so subtracting gives 255 bytes of 0xFF followed by 0x43. A

///| pasted constant would be 256 bytes nothing in this repository could check,

///| and a benchmark whose input is unverifiable is a number without meaning.

///|

///| The exponent is 65537, the value OpenSSH uses for RSA, which keeps the

///| square-and-multiply schedule honest: a power of two would skip every

///| multiply.

///|

///|
/// The group 14 modulus, as big-endian bytes.
fn group14_modulus() -> FixedArray[Byte] {
  let m = FixedArray::make(256, b'\xff')
  // 2^2048 - 1 minus (189 = 0xBC) puts 0x43 in the last byte.
  m[255] = b'\x43'
  m
}

///|
fn small_value() -> BigNat {
  BigNat::from_uint64(0x9e3779b97f4a7c15)
}

///|
test "mod_pow 2048-bit, e=65537 (schoolbook)" (b : @bench.T) {
  let n = BigNat::from_bytes_be(group14_modulus())
  let e = BigNat::from_uint64(65537)
  b.bench(fn() { b.keep(BigNat::mod_pow(small_value(), e, n)) })
}

///|
test "mod_pow_auto 2048-bit, e=65537 (cached Montgomery ctx)" (b : @bench.T) {
  let n = BigNat::from_bytes_be(group14_modulus())
  let e = BigNat::from_uint64(65537)
  b.bench(fn() { b.keep(BigNat::mod_pow_auto(small_value(), e, n)) })
}

///|
test "mod_mul 2048-bit x 2048-bit" (b : @bench.T) {
  let n = BigNat::from_bytes_be(group14_modulus())
  b.bench(fn() {
    b.keep(
      BigNat::mod_mul(small_value(), BigNat::from_uint64(0x0123456789abcdef), n),
    )
  })
}

///|
test "mpint_encode 2048-bit (RFC 4251 section 5 wire)" (b : @bench.T) {
  let n = BigNat::from_bytes_be(group14_modulus())
  b.bench(fn() { b.keep(n.mpint_encode()) })
}

///|
test "to_bytes_be + from_bytes_be round trip" (b : @bench.T) {
  let n = BigNat::from_bytes_be(group14_modulus())
  b.bench(fn() { b.keep(BigNat::from_bytes_be(n.to_bytes_be())) })
}
