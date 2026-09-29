///| Modular arithmetic (Loop #26 G1b)
///
/// BigNat modular multiplication + modular exponentiation.
/// Used for DH group 14 KEX (Loop #26), RSA host key (Loop #27+), ECDSA (Loop #28+).
///
/// Implementation: BigNat::mul + BigNat::mod (Knuth Algorithm D simplified).
/// Knuth D is O(n*m) per mod call, vs binary long division's O(n*b_bits).
///
/// Future optimization (Loop #27+): proper Montgomery REDC for ~10x speedup.

///| BigNat mod mul (mod_mul): a * b mod n
pub fn BigNat::mod_mul(a : BigNat, b : BigNat, n : BigNat) -> BigNat {
  let product = BigNat::mul(a, b)
  BigNat::mod(product, n)
}

///| BigNat mod pow (modular exponentiation): base^exp mod n
///   Binary exponentiation + mod_mul
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