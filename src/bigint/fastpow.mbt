///| BigNat <-> 64-bit limb bridge + Montgomery fast-path exponentiation
///   (Loop #29 G3)
///
/// The 32-bit-limb BigNat from Loop #26/27 stays the public data model
/// (RFC 4251 mpint, to_bytes_be, etc). This file converts to native 64-bit
/// limbs, runs Montgomery CIOS, and converts back.

///| Number of 64-bit limbs needed to hold this BigNat.
pub fn BigNat::limb64_len(self : BigNat) -> Int {
  let bits = self.bit_length()
  let k = (bits + 63) / 64
  if k < 1 { 1 } else { k }
}

///| BigNat -> 64-bit limbs (little-endian), zero-padded to `k` entries.
pub fn BigNat::to_limbs64(self : BigNat, k : Int) -> FixedArray[UInt64] {
  let out : FixedArray[UInt64] = FixedArray::make(k, 0UL)
  let mut i = 0
  while i < k {
    let lo32 = if (i * 2) < self.len { self.limbs[i * 2].to_uint64() } else { 0UL }
    let hi32 = if (i * 2 + 1) < self.len { self.limbs[i * 2 + 1].to_uint64() } else { 0UL }
    out[i] = lo32 | (hi32 << 32)
    i = i + 1
  }
  out
}

///| 64-bit limbs -> BigNat (little-endian 32-bit limbs), length normalized.
pub fn limbs64_to_bignat(l : FixedArray[UInt64], k : Int) -> BigNat {
  let n32 = k * 2
  let out : FixedArray[UInt] = FixedArray::make(n32, 0U)
  let mut i = 0
  while i < n32 {
    let w = l[i / 2]
    out[i] = if i % 2 == 0 {
      (w & 0xFFFFFFFFUL).to_uint()
    } else {
      ((w >> 32) & 0xFFFFFFFFUL).to_uint()
    }
    i = i + 1
  }
  let mut len = n32
  while len > 0 && out[len - 1] == 0U {
    len = len - 1
  }
  { limbs: out, len }
}

///| True when the low 32-bit limb is odd.
pub fn BigNat::is_odd(self : BigNat) -> Bool {
  if self.len == 0 { return false }
  (self.limbs[0] & 1U) == 1U
}

///| mod_pow with an explicit Montgomery context (fast path).
///   Caller guarantees n is odd and ctx was built from n.
pub fn mont_pow_with(
  ctx : MontCtx,
  base : BigNat,
  exp : BigNat
) -> BigNat {
  let k = ctx.k
  let base_limbs = base.to_limbs64(k)
  let exp_limbs = exp.to_limbs64(k)
  let r = MontCtx::pow(ctx, base_limbs, exp_limbs)
  limbs64_to_bignat(r, k)
}

///| mod_pow with an explicit Montgomery context, returning the raw REDC result
///   (a * b * R^(-1) mod n) instead of a * b mod n. Test-only.
pub fn mont_redc_with(
  ctx : MontCtx,
  a : BigNat,
  b : BigNat
) -> BigNat {
  let k = ctx.k
  let r = MontCtx::redc(ctx, a.to_limbs64(k), b.to_limbs64(k))
  limbs64_to_bignat(r, k)
}

///| mod_pow that automatically picks the fast path.
///   - odd modulus  -> Montgomery CIOS in 64-bit limbs
///   - even modulus -> schoolbook mul + binary long division
///   Exponent length drives the work: odd exponents are unchanged, even ones
///   are halved by one trailing shift so the extra bit costs nothing.
pub fn BigNat::mod_pow_auto(base : BigNat, exp : BigNat, n : BigNat) -> BigNat {
  if exp.len == 0 {
    return BigNat::from_uint64(1UL)
  }
  if !n.is_odd() {
    return BigNat::mod_pow(base, exp, n)
  }
  let k = n.limb64_len()
  let n_limbs = n.to_limbs64(k)
  let ctx = MontCtx::new(n_limbs, k)
  mont_pow_with(ctx, base, exp)
}

///| mod_mul that automatically picks the fast path.
pub fn BigNat::mod_mul_auto(a : BigNat, b : BigNat, n : BigNat) -> BigNat {
  if !n.is_odd() {
    return BigNat::mod_mul(a, b, n)
  }
  let k = n.limb64_len()
  let ctx = MontCtx::new(n.to_limbs64(k), k)
  let r = MontCtx::mul(ctx, a.to_limbs64(k), b.to_limbs64(k))
  limbs64_to_bignat(r, k)
}
