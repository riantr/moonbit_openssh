///| Montgomery REDC with 64-bit limbs (Loop #29 G2)
///
/// This replaces the 32-bit-limb CIOS prototype from Loop #28, which could
/// not handle k > 1 because the 32-bit accumulator's carry slot overflowed.
/// Working in native UInt64 limbs removes the overflow entirely: the inner
/// loop's carry is a full 64-bit word, so no accumulator limb ever exceeds
/// 2^64 - 1.
///
/// Algorithm (CIOS, Koç et al. 1996):
///   Given n with k 64-bit limbs and n' = -n^(-1) mod 2^64,
///   REDC(T) = T * R^(-1) mod n, where R = 2^(64*k).
///
///   T = 0                              (k+2 limbs)
///   for i in 0..k-1:
///     T = T + a[i]*b                  (limb-scalar mul + carry)
///     m = T[0] * n' mod 2^64
///     T = T + m*n                      (limb-scalar mul + carry)
///     T = T >> 64                      (shift right one limb)
///   if T >= n: T -= n
///   return T
///
/// Reference: HAC §14.3.2; Koç, Acar, Kaliski, "Analyzing and Comparing
/// Montgomery Multiplication Algorithms" (Lowrance-Wagner survey, 1997).

///|
/// n' = -n^(-1) mod 2^64 for an odd 64-bit limb n0.
///   Newton/Hensel doubling: x_{k+1} = x_k * (2 - n*x_k) mod 2^64.
///   6 iterations from x_0 = 1 give full 64-bit precision
///   (1 -> 2 -> 4 -> 8 -> 16 -> 32 -> 64 bits).
pub fn mont_n_prime(n0 : UInt64) -> UInt64 {
  let mut x : UInt64 = 1UL
  let mut it = 0
  while it < 6 {
    x = x * (2UL - n0 * x)
    it = it + 1
  }
  0UL - x
}

///|
/// 64-bit limb array helpers.
pub fn limbs64_from_bytes_be(bytes : FixedArray[Byte]) -> FixedArray[UInt64] {
  let n64 = (bytes.length() + 7) / 8
  let out : FixedArray[UInt64] = FixedArray::make(
    if n64 < 1 {
      1
    } else {
      n64
    },
    0UL,
  )
  let mut i = 0
  while i < bytes.length() {
    let bi = bytes.length() - 1 - i
    let byte_i = i / 8
    let shift = i % 8 * 8
    out[byte_i] = out[byte_i] | (bytes[bi].to_uint64() << shift)
    i = i + 1
  }
  out
}

///|
/// 64-bit limbs -> big-endian bytes (exact length = k * 8, no trimming).
pub fn limbs64_to_bytes_be(
  l : FixedArray[UInt64],
  count : Int32,
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(count * 8, b'\x00')
  let mut i = 0
  while i < count {
    let w = l[i]
    let base = count - 1 - i
    out[base * 8 + 0] = ((w >> 56) & 0xFFUL).to_byte()
    out[base * 8 + 1] = ((w >> 48) & 0xFFUL).to_byte()
    out[base * 8 + 2] = ((w >> 40) & 0xFFUL).to_byte()
    out[base * 8 + 3] = ((w >> 32) & 0xFFUL).to_byte()
    out[base * 8 + 4] = ((w >> 24) & 0xFFUL).to_byte()
    out[base * 8 + 5] = ((w >> 16) & 0xFFUL).to_byte()
    out[base * 8 + 6] = ((w >> 8) & 0xFFUL).to_byte()
    out[base * 8 + 7] = (w & 0xFFUL).to_byte()
    i = i + 1
  }
  out
}

///|
/// Compare limb arrays a[0..alen) vs b[0..blen), both little-endian.
///   Returns -1 / 0 / +1.
pub fn limbs64_cmp(
  a : FixedArray[UInt64],
  alen : Int32,
  b : FixedArray[UInt64],
  blen : Int32,
) -> Int32 {
  let m = if alen > blen { alen } else { blen }
  let mut i = m - 1
  while i >= 0 {
    let av = if i < alen { a[i] } else { 0UL }
    let bv = if i < blen { b[i] } else { 0UL }
    if av != bv {
      if av < bv {
        return -1
      } else {
        return 1
      }
    }
    i = i - 1
  }
  0
}

///|
/// Subtract b from a in place. Requires a >= b.
pub fn limbs64_sub(
  a : FixedArray[UInt64],
  alen : Int32,
  b : FixedArray[UInt64],
  blen : Int32,
) -> Int32 {
  let mut borrow : UInt64 = 0UL
  let mut i = 0
  while i < alen {
    let bv = if i < blen { b[i] } else { 0UL }
    let ai = a[i]
    let d1 = ai - bv
    let b1 = if ai < bv { 1UL } else { 0UL }
    let d2 = d1 - borrow
    let b2 = if d1 < borrow { 1UL } else { 0UL }
    a[i] = d2
    borrow = b1 + b2
    i = i + 1
  }
  borrow.to_int()
}

///|
/// Montgomery context: modulus + precomputed constants.
pub struct MontCtx {
  n : FixedArray[UInt64]
  k : Int32 // number of 64-bit limbs
  n_prime : UInt64 // -n^(-1) mod 2^64
  r2 : FixedArray[UInt64] // R^2 mod n, k limbs
}

///|
/// Build a Montgomery context for an odd modulus given as k 64-bit limbs.
///   `n` must have exactly `k` limbs with n[k-1] != 0 and n odd.
pub fn MontCtx::new(n : FixedArray[UInt64], k : Int32) -> MontCtx {
  let n0 = n[0]
  let n_prime = mont_n_prime(n0)
  // r2 = R^2 mod n, computed as: start c = R mod n, then square k times via
  // doubling in the Montgomery domain. Cheaper and safer than building a huge
  // intermediate:  c_{i+1} = 2^(64*(2i+1)) mod n  ->  we need 2^(128k) mod n.
  //
  // Straightforward approach: c = 1; for i in 0..(2*64*k): c = (c*2) mod n.
  // That is O(k) doublings * 2*64*k iterations, fine since it runs once.
  let r2 = limbs64_compute_r2(n, k)
  { n, k, n_prime, r2, }
}

///|
/// Compute R^2 mod n = 2^(128*k) mod n by repeated doubling.
fn limbs64_compute_r2(n : FixedArray[UInt64], k : Int32) -> FixedArray[UInt64] {
  let acc : FixedArray[UInt64] = FixedArray::make(k + 1, 0UL)
  acc[0] = 1UL
  let total_bits = 128 * k
  let mut b = 0
  while b < total_bits {
    // acc = acc << 1, then conditional subtract n
    let mut carry : UInt64 = 0UL
    let mut i = 0
    while i < k {
      let nc = acc[i] >> 63
      acc[i] = (acc[i] << 1) | carry
      carry = nc
      i = i + 1
    }
    acc[k] = carry
    if limbs64_cmp(acc, k + 1, n, k) >= 0 {
      ignore(limbs64_sub(acc, k + 1, n, k))
    }
    b = b + 1
  }
  // acc has k+1 limbs but the value is < n < 2^(64k), so acc[k] must be 0.
  let out : FixedArray[UInt64] = FixedArray::make(k, 0UL)
  let mut i = 0
  while i < k {
    out[i] = acc[i]
    i = i + 1
  }
  out
}

///|
/// Core CIOS REDC: returns a * b * R^(-1) mod n.
///   `a` and `b` must already be reduced (< n) and padded to k limbs.
///
///   Performance note: the inner 64x64->128 multiply-accumulate is written out
///   inline rather than calling a helper, because a MoonBit function returning
///   `(UInt64, UInt64)` compiles to a *heap-allocated tuple*. At k=32 that inner
///   step runs 32 * 64 = 2048 times per modular multiplication, so boxing it
///   would dominate the runtime. The arithmetic below is identical to the
///   KAT-verified `mac_u64`.
fn mont_cios(
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
  ctx : MontCtx,
) -> FixedArray[UInt64] {
  let k = ctx.k
  let n = ctx.n
  let t : FixedArray[UInt64] = FixedArray::make(k + 2, 0UL)

  let mut i = 0
  while i < k {
    let ai = a[i]
    // Split the multiplier once per outer iteration; the inner loop reuses
    // al/ah for all 2k limb multiplications.
    let al = ai & 0xFFFFFFFFUL
    let ah = ai >> 32

    // --- Step 1: T += a[i] * b ---
    let mut carry : UInt64 = 0UL
    let mut j = 0
    while j < k {
      let bj = b[j]
      let bl = bj & 0xFFFFFFFFUL
      let bh = bj >> 32
      // four 32x32 partial products
      let p0 = al * bl
      let p1 = al * bh
      let p2 = ah * bl
      let p3 = ah * bh
      // recombine into plo / phi (the 32-bit words are masked exactly as the
      // KAT-verified mul_u64x64 does)
      let plo0 = p0 & 0xFFFFFFFFUL
      let x1 = (p0 >> 32) + (p1 & 0xFFFFFFFFUL) + (p2 & 0xFFFFFFFFUL)
      let x2 = (x1 >> 32) + (p1 >> 32) + (p2 >> 32) + (p3 & 0xFFFFFFFFUL)
      let phi = (((x2 >> 32) + (p3 >> 32)) << 32) | (x2 & 0xFFFFFFFFUL)
      let plo = plo0 | ((x1 & 0xFFFFFFFFUL) << 32)
      // add t[j] and carry into the 128-bit product
      let s = t[j] + carry
      let c1 : UInt64 = if s < carry { 1UL } else { 0UL }
      let lo = plo + s
      let c2 : UInt64 = if lo < s { 1UL } else { 0UL }
      t[j] = lo
      carry = phi + c1 + c2
      j = j + 1
    }
    let s1 = t[k] + carry
    let e1 : UInt64 = if s1 < carry { 1UL } else { 0UL }
    t[k] = s1
    t[k + 1] = e1

    // --- Step 2: m = T[0] * n' mod 2^64 ---
    let m = t[0] * ctx.n_prime
    let ml = m & 0xFFFFFFFFUL
    let mh = m >> 32

    // --- Step 3: T += m * n ---
    let mut carry2 : UInt64 = 0UL
    let mut j2 = 0
    while j2 < k {
      let nj = n[j2]
      let nl = nj & 0xFFFFFFFFUL
      let nh = nj >> 32
      let q0 = ml * nl
      let q1 = ml * nh
      let q2 = mh * nl
      let q3 = mh * nh
      let q1m = q1 & 0xFFFFFFFFUL
      let q2m = q2 & 0xFFFFFFFFUL
      let y1 = (q0 >> 32) + q1m + q2m
      let y2 = (y1 >> 32) + (q1 >> 32) + (q2 >> 32) + (q3 & 0xFFFFFFFFUL)
      let qhi = (((y2 >> 32) + (q3 >> 32)) << 32) | (y2 & 0xFFFFFFFFUL)
      let qlo = (q0 & 0xFFFFFFFFUL) | ((y1 & 0xFFFFFFFFUL) << 32)
      let s2 = t[j2] + carry2
      let d1 : UInt64 = if s2 < carry2 { 1UL } else { 0UL }
      let lo2 = qlo + s2
      let d2 : UInt64 = if lo2 < s2 { 1UL } else { 0UL }
      t[j2] = lo2
      carry2 = qhi + d1 + d2
      j2 = j2 + 1
    }
    let s3 = t[k] + carry2
    let e2 : UInt64 = if s3 < carry2 { 1UL } else { 0UL }
    t[k] = s3
    t[k + 1] = t[k + 1] + e2

    // --- Step 4: shift right by 64 bits ---
    let mut s = 0
    while s < k + 1 {
      t[s] = t[s + 1]
      s = s + 1
    }
    t[k + 1] = 0UL

    i = i + 1
  }

  // --- Final conditional subtraction (at most 2 subtractions needed) ---
  if limbs64_cmp(t, k + 1, n, k) >= 0 {
    ignore(limbs64_sub(t, k + 1, n, k))
  }
  let out : FixedArray[UInt64] = FixedArray::make(k, 0UL)
  let mut q = 0
  while q < k {
    out[q] = t[q]
    q = q + 1
  }
  out
}

///|
/// Raw Montgomery REDC primitive: returns a * b * R^(-1) mod n.
///   Exposed for KAT cross-checks; normal code should use `MontCtx::mul`.
pub fn MontCtx::redc(
  ctx : MontCtx,
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  mont_cios(a, b, ctx)
}

///|
/// Montgomery multiplication: returns a * b mod n.
pub fn MontCtx::mul(
  ctx : MontCtx,
  a : FixedArray[UInt64],
  b : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  let k = ctx.k
  // Convert to Montgomery domain: aR = REDC(a, R^2)
  let aR = mont_cios(a, ctx.r2, ctx)
  let bR = mont_cios(b, ctx.r2, ctx)
  // abR = REDC(aR, bR)
  let abR = mont_cios(aR, bR, ctx)
  // result = REDC(abR, 1)
  let one : FixedArray[UInt64] = FixedArray::make(k, 0UL)
  one[0] = 1UL
  mont_cios(abR, one, ctx)
}

///|
/// Montgomery-domain value of aR for a (used to enter/exit the domain).
pub fn MontCtx::to_mont(
  ctx : MontCtx,
  a : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  mont_cios(a, ctx.r2, ctx)
}

///|
/// Convert out of Montgomery domain.
pub fn MontCtx::from_mont(
  ctx : MontCtx,
  aR : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  let k = ctx.k
  let one : FixedArray[UInt64] = FixedArray::make(k, 0UL)
  one[0] = 1UL
  mont_cios(aR, one, ctx)
}

///|
/// Montgomery exponentiation: returns a^e mod n via square-and-multiply.
///   Operates entirely in the Montgomery domain.
pub fn MontCtx::pow(
  ctx : MontCtx,
  a : FixedArray[UInt64],
  e : FixedArray[UInt64],
) -> FixedArray[UInt64] {
  let k = ctx.k
  let one : FixedArray[UInt64] = FixedArray::make(k, 0UL)
  one[0] = 1UL
  let oneR = mont_cios(one, ctx.r2, ctx) // 1 * R mod n

  let bits = limbs64_bit_length(e, k)
  let mut result = oneR
  let b = MontCtx::to_mont(ctx, a)
  let mut i = bits - 1
  while i >= 0 {
    let w = i / 64
    let sh = i % 64
    let bit = (e[w] >> sh) & 1UL
    result = mont_cios(result, result, ctx)
    if bit != 0UL {
      result = mont_cios(result, b, ctx)
    }
    i = i - 1
  }
  MontCtx::from_mont(ctx, result)
}

///|
/// Bit length of a little-endian 64-bit limb array.
pub fn limbs64_bit_length(l : FixedArray[UInt64], len : Int32) -> Int32 {
  let mut i = len - 1
  while i >= 0 {
    let v = l[i]
    if v != 0UL {
      let mut bits = i * 64
      let mut w = v
      while w > 0UL {
        bits = bits + 1
        w = w >> 1
      }
      return bits
    }
    i = i - 1
  }
  0
}
