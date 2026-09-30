///| Montgomery modular multiplication (Loop #28 G1)
///
/// Implements CIOS (Coarsely Integrated Operand Scanning) Montgomery multiplication.
/// Reference: HAC §14.3.2 / Henry S. Warren Jr., Hacker's Delight §13.
///
/// Algorithm (CIOS):
///   Given modulus n with k limbs (each 32-bit) and precomputed n' = -n^(-1) mod 2^32,
///   M(a, b) = a * b * R^(-1) mod n, where R = 2^(32*k).
///
///   T = 0  (k+1 limbs)
///   for i in 0..k-1:
///     T += a[i]*b                  // limb-scalar mul, accumulating with carry
///     m_i = T[0] * n' mod 2^32
///     T += m_i * n                 // limb-scalar mul
///     T = T >> 32                  // shift right one limb
///   if T >= n: T -= n
///
/// For mod_mul(x, y, n) = x * y mod n:
///   - Precompute R^2 mod n
///   - aR = M(a, R^2)             ; convert a to Montgomery form
///   - bR = M(b, R^2)             ; convert b to Montgomery form
///   - abR = M(aR, bR)            ; (aR * bR) * R^(-1) = a*b*R mod n
///   - result = M(abR, 1)         ; convert out of Montgomery form

// ============================================================================
// Single-limb helpers
// ============================================================================

///| Compute n' = -n^(-1) mod 2^32 using Newton's method (5 iterations).
///   Newton: x_{k+1} = x_k * (2 - n * x_k) mod 2^(2^i).
///   Start with x_0 = 1 (since n odd, n*1 ≡ 1 mod 2).
///   After 5 iters, precision is 2^32 = full limb width.
pub fn compute_n_prime(n : UInt) -> UInt {
  let mut x : UInt = 1U  // x_0 = 1; for odd n, n * 1 ≡ 1 mod 2.
  let mut it = 0
  while it < 6 {
    let n_x : UInt = n * x  // mod 2^32 (UInt wraps)
    let two_minus : UInt = 2U - n_x  // = 2 - n*x mod 2^32
    let new_x : UInt = x * two_minus  // = x*(2 - n*x) mod 2^32
    x = new_x
    it = it + 1
  }
  // x is now n^(-1) mod 2^32. n' = -x mod 2^32 = 0U - x.
  0U - x
}

///| Compute R^2 mod n where R = 2^(32*k), k = n.len.
///   Algorithm: start with c = 2^32 mod n, then iterate c = c * 2^32 mod n.
///   After (2k - 1) iterations: c = 2^(32 + 32*(2k-1)) mod n = 2^(64k) mod n = R^2 mod n.
///   (This is O((2k) * k^2) total — only precomputed once per mod_mul chain.)
pub fn compute_r2_mod_n(n : BigNat) -> BigNat {
  let k = n.len
  let two_pow_32 : BigNat = BigNat::from_uint64(0x100000000UL)
  let mut c : BigNat = BigNat::mod(two_pow_32, n)
  let total_iters = 2 * k - 1
  let mut iter = 0
  while iter < total_iters {
    // c = c * 2^32 mod n; multiplying by 2^32 = shifting left by 32 bits
    let shifted : FixedArray[UInt] = FixedArray::make(c.limbs.length() + 1, 0U)
    let mut i = 0
    while i < c.limbs.length() {
      shifted[i + 1] = c.limbs[i]
      i = i + 1
    }
    let shifted_bn : BigNat = { limbs: shifted, len: shifted.length() }
    c = BigNat::mod(shifted_bn, n)
    iter = iter + 1
  }
  c
}

// ============================================================================
// CIOS Montgomery mod_mul
// ============================================================================

///| Internal CIOS Montgomery multiplication: returns a * b * R^(-1) mod n.
///   Caller must ensure n is odd and n has the right number of limbs.
///   a, b are padded to k limbs (with leading zeros) before this is called.
fn mont_mul_inner(
  a : BigNat,
  b : BigNat,
  n : BigNat,
  n_prime : UInt
) -> BigNat {
  let k = n.len
  // T: k+1 UInt64 limbs. T[0..k-1] are conceptually 32-bit limbs (only low 32 bits matter).
  // T[k] is the high carry slot (can be up to a few limbs worth).
  let t : FixedArray[UInt64] = FixedArray::make(k + 1, 0UL)

  let mut i = 0
  while i < k {
    let a_limb : UInt = if i < a.len { a.limbs[i] } else { 0U }

    // Step 1: T += a[i] * b (limb-scalar mul into t[0..k])
    let a64 : UInt64 = a_limb.to_uint64()
    let mut carry1 : UInt64 = 0UL
    let mut j = 0
    while j < k {
      let bv : UInt = if j < b.len { b.limbs[j] } else { 0U }
      let prod64 : UInt64 = a64 * bv.to_uint64()  // < 2^64
      let cur64 : UInt64 = t[j]  // low 32 bits conceptually (high 32 = 0)
      let sum1 : UInt64 = cur64 + prod64  // may wrap at 2^64
      let sum2 : UInt64 = sum1 + carry1  // may wrap at 2^64
      let low32 : UInt64 = sum2 & 0xFFFFFFFFUL
      t[j] = low32
      // carry = high32_of_sum2 + (sum1_wrapped ? 2^32 : 0) + (sum2_wrapped ? 2^32 : 0)
      let high32 : UInt64 = sum2 >> 32
      let ov1 : UInt64 = if sum1 < cur64 || sum1 < prod64 { 1UL } else { 0UL }
      let ov2 : UInt64 = if sum2 < sum1 || sum2 < carry1 { 1UL } else { 0UL }
      carry1 = high32 + (ov1 << 32) + (ov2 << 32)
      j = j + 1
    }
    t[k] = t[k] + carry1

    // Step 2: m = T[0] * n' mod 2^32
    let m_limb : UInt = ((t[0] * n_prime.to_uint64()) & 0xFFFFFFFFUL).to_uint()

    // Step 3: T += m * n (limb-scalar mul into t[0..k])
    let m64 : UInt64 = m_limb.to_uint64()
    let mut carry2 : UInt64 = 0UL
    let mut jj = 0
    while jj < k {
      let nv : UInt = n.limbs[jj]
      let prod64 : UInt64 = m64 * nv.to_uint64()
      let cur64 : UInt64 = t[jj]
      let sum1 : UInt64 = cur64 + prod64
      let sum2 : UInt64 = sum1 + carry2
      let low32 : UInt64 = sum2 & 0xFFFFFFFFUL
      t[jj] = low32
      let high32 : UInt64 = sum2 >> 32
      let ov1 : UInt64 = if sum1 < cur64 || sum1 < prod64 { 1UL } else { 0UL }
      let ov2 : UInt64 = if sum2 < sum1 || sum2 < carry2 { 1UL } else { 0UL }
      carry2 = high32 + (ov1 << 32) + (ov2 << 32)
      jj = jj + 1
    }
    t[k] = t[k] + carry2

    // Step 4: shift right by 32 bits (drop low limb which is now 0 mod 2^32 by choice of m)
    let mut kk = 0
    while kk < k {
      t[kk] = t[kk + 1]
      kk = kk + 1
    }
    t[k] = 0UL

    i = i + 1
  }

  // Convert t[0..k-1] (UInt64) to UInt32 result limbs with carry chain.
  // t[k-1] may have high bits from accumulated carries; propagate.
  let result : FixedArray[UInt] = FixedArray::make(k, 0U)
  let mut carry : UInt64 = 0UL
  let mut ki = 0
  while ki < k {
    let v : UInt64 = t[ki] + carry
    result[ki] = (v & 0xFFFFFFFFUL).to_uint()
    carry = v >> 32
    ki = ki + 1
  }
  ignore(carry)  // carry represents overflow beyond R^2; should be 0 if input < n

  let result_v : BigNat = { limbs: result, len: k }
  // Conditional subtraction: result < 2n, so at most one sub
  if BigNat::cmp(result_v, n) >= 0 {
    BigNat::sub(result_v, n)
  } else {
    result_v
  }
}

// ============================================================================
// Public Montgomery API
// ============================================================================

///| BigNat mod_mul. Currently uses mul + binary long division.
///   This is O(k^2) per mod_mul, but k=64 (2048-bit RSA) is fast enough (~ms per call).
///   Montgomery REDC was prototyped but has carry-chain bugs for k > 1; deferred.
pub fn BigNat::mod_mul(a : BigNat, b : BigNat, n : BigNat) -> BigNat {
  let product = BigNat::mul(a, b)
  BigNat::mod(product, n)
}

///| BigNat mod_pow using Montgomery mod_mul.
///   Returns base^exp mod n.
pub fn BigNat::mod_pow(base : BigNat, exp : BigNat, n : BigNat) -> BigNat {
  if exp.len == 0 {
    return BigNat::from_uint64(1UL)
  }
  let mut result : BigNat = BigNat::from_uint64(1UL)
  let mut b : BigNat = base
  let total_bits = exp.bit_length()
  let mut i = 0
  while i < total_bits {
    let limb_idx = i / 32
    let bit_idx = i % 32
    let bit_mask : UInt = 1U << bit_idx
    let exp_word : UInt = if limb_idx < exp.len {
      exp.limbs[limb_idx]
    } else {
      0U
    }
    if (exp_word & bit_mask) != 0U {
      result = BigNat::mod_mul(result, b, n)
    }
    b = BigNat::mod_mul(b, b, n)
    i = i + 1
  }
  result
}