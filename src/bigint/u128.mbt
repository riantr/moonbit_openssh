///| UInt128 arithmetic via 32×32 split (Loop #29 G1)
///
/// MoonBit has no native UInt128. A 128-bit value is represented as a pair
/// of UInt64: `(hi, lo)` where value = hi * 2^64 + lo.
///
/// mul_u64x64 is the core primitive: it splits both 64-bit operands into
/// 32-bit halves and recombines the four partial 64-bit products, carrying
/// across 32-bit word boundaries so no 64-bit intermediate ever overflows.
///
/// Reference: HAC §2.5 (MUL64), and the classic "double-and-add with
/// word-level carry propagation" formulation used by OpenSSL bn_mul_mont.

///| Struct representing a 128-bit unsigned integer as (hi, lo).
pub struct U128 {
  hi : UInt64
  lo : UInt64
}

///| 64x64 -> 128 multiply, implemented as four 32x32 partial products.
///
/// Partial products (a = a1*2^32 + a0, b = b1*2^32 + b0):
///   p0 = a0*b0    occupies bits [0, 64)
///   p1 = a0*b1    occupies bits [32, 96)
///   p2 = a1*b0    occupies bits [32, 96)
///   p3 = a1*b1    occupies bits [64, 128)
///
/// Each recombination step adds at most 3 values below 2^33, so the
/// intermediate sums stay well inside UInt64 and the carry extraction is exact.
pub fn mul_u64x64(a : UInt64, b : UInt64) -> U128 {
  let a_lo = a & 0xFFFFFFFFUL
  let a_hi = a >> 32
  let b_lo = b & 0xFFFFFFFFUL
  let b_hi = b >> 32
  let p0 = a_lo * b_lo
  let p1 = a_lo * b_hi
  let p2 = a_hi * b_lo
  let p3 = a_hi * b_hi
  // word 0: low 32 bits of p0
  let w0 = p0 & 0xFFFFFFFFUL
  // word 1: p0_hi + p1_lo + p2_lo  (< 3 * 2^32, safe)
  let s1 = (p0 >> 32) + (p1 & 0xFFFFFFFFUL) + (p2 & 0xFFFFFFFFUL)
  let w1 = s1 & 0xFFFFFFFFUL
  // word 2: carry1 + p1_hi + p2_hi + p3_lo  (< 3 * 2^32 + 2, safe)
  let s2 = (s1 >> 32) + (p1 >> 32) + (p2 >> 32) + (p3 & 0xFFFFFFFFUL)
  let w2 = s2 & 0xFFFFFFFFUL
  // word 3: carry2 + p3_hi  (< 2^32, safe)
  let s3 = (s2 >> 32) + (p3 >> 32)
  let w3 = s3 & 0xFFFFFFFFUL
  { hi: (w3 << 32) | w2, lo: (w1 << 32) | w0 }
}

///| UInt64 + U128 -> U128 with carry-out.
pub fn add_u128(a : U128, b : U128) -> (U128, UInt64) {
  let lo = a.lo + b.lo
  let c1 = if lo < a.lo { 1UL } else { 0UL }
  let hi = a.hi + b.hi + c1
  let c2 = if hi < a.hi { 1UL } else { 0UL }
  ({ hi, lo }, c2)
}

///| U128 + UInt64 -> U128 with carry-out.
pub fn add_u128_u64(a : U128, b : UInt64) -> (U128, UInt64) {
  let lo = a.lo + b
  let c1 = if lo < b { 1UL } else { 0UL }
  let hi = a.hi + c1
  ({ hi, lo }, 0UL)
}
