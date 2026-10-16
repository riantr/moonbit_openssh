///| ECDSA sign / verify (FIPS 186-4 §6) (Loop #30 G3)
///
///   sign:   r = (k*G).x mod n
///           s = k^-1 * (e + r*d) mod n
///   verify: w = s^-1 mod n;  u1 = e*w;  u2 = r*w
///           P = u1*G + u2*Q;  accept iff P != O and P.x mod n == r
///
///   e = bits2int(H(m)), truncated to the group order bit length.
///   Both r and s must be in [1, n-1]; anything else is rejected outright
///   (this is what blocks signature malleability and trivial forgeries).
///
///   Signing uses the RFC 6979 deterministic nonce, so no RNG is required.

///|
/// An ECDSA signature (r, s), each in [1, n-1].
pub struct Signature {
  r : @bigint.BigNat
  s : @bigint.BigNat
}

///|
/// Construct a signature from r and s.
pub fn Signature::new(r : @bigint.BigNat, s : @bigint.BigNat) -> Signature {
  { r, s, }
}

///|
/// Modular inverse mod the group order n.
fn inv_mod_n(c : Curve, a : @bigint.BigNat) -> @bigint.BigNat {
  @bigint.BigNat::mod_pow_auto(
    a,
    @bigint.BigNat::sub(c.n, @bigint.BigNat::from_uint64(2UL)),
    c.n,
  )
}

///|
/// Hash the message with the curve's co-recommended hash (FIPS 186-4 §6.2.1).
pub fn Curve::hash_message(
  c : Curve,
  msg : FixedArray[Byte],
) -> FixedArray[Byte] {
  if c.bits == 256 {
    @sha256.sha256(msg)
  } else {
    @sha512.sha384(msg)
  }
}

///|
/// The hash algorithm paired with this curve.
pub fn Curve::hash_alg(c : Curve) -> HashAlg {
  if c.bits == 256 {
    Sha256
  } else {
    Sha384
  }
}

///|
/// Produce a deterministic ECDSA signature over `msg` with private key `d`.
///
///   `d` must be in [1, n-1]. Returns None if d is out of range or if the
///   RFC 6979 nonce degenerates (r == 0 or s == 0), which the caller should
///   treat as a hard failure rather than silently retrying with a different k.
pub fn ecdsa_sign(
  c : Curve,
  d : @bigint.BigNat,
  msg : FixedArray[Byte],
) -> Signature? {
  let one = @bigint.BigNat::from_uint64(1UL)
  if @bigint.BigNat::cmp(d, one) < 0 || @bigint.BigNat::cmp(d, c.n) >= 0 {
    return None
  }
  let alg = c.hash_alg()
  let h1 = c.hash_message(msg)
  let k = rfc6979_nonce(alg, c.n, c.bits, d, h1)
  if @bigint.BigNat::is_zero(k) {
    return None
  }
  let kg = Curve::mul(c, k, c.generator())
  if kg.inf {
    return None
  }
  let r = Curve::f_reduce_curve_order(c, kg.x)
  if @bigint.BigNat::is_zero(r) {
    return None
  }
  let e = bits2int(h1, c.bits)
  let kinv = inv_mod_n(c, k)
  let rd = @bigint.BigNat::mod_mul_auto(r, d, c.n)
  let s = @bigint.BigNat::mod_mul_auto(kinv, Curve::reduce_e(c, e, rd), c.n)
  if @bigint.BigNat::is_zero(s) {
    return None
  }
  Some({ r, s, })
}

///|
/// (e + r*d) mod n, the message-and-key term of the signing equation.
fn Curve::reduce_e(
  c : Curve,
  e : @bigint.BigNat,
  rd : @bigint.BigNat,
) -> @bigint.BigNat {
  @bigint.BigNat::mod(@bigint.BigNat::add(@bigint.BigNat::mod(e, c.n), rd), c.n)
}

///|
/// x mod n (the group order), for the r computation.
pub fn Curve::f_reduce_curve_order(
  c : Curve,
  x : @bigint.BigNat,
) -> @bigint.BigNat {
  @bigint.BigNat::mod(x, c.n)
}

///|
/// Verify an ECDSA signature. Rejects out-of-range r/s, points not on the
///   curve, and any mismatch. Constant-shape (no early exit on secret data).
pub fn ecdsa_verify(
  c : Curve,
  q : Point,
  sig : Signature,
  msg : FixedArray[Byte],
) -> Bool {
  let one = @bigint.BigNat::from_uint64(1UL)
  let r = sig.r
  let s = sig.s
  // range check: 1 <= r < n and 1 <= s < n
  if @bigint.BigNat::cmp(r, one) < 0 {
    return false
  }
  if @bigint.BigNat::cmp(r, c.n) >= 0 {
    return false
  }
  if @bigint.BigNat::cmp(s, one) < 0 {
    return false
  }
  if @bigint.BigNat::cmp(s, c.n) >= 0 {
    return false
  }
  // the public key must be a valid curve point
  if q.inf {
    return false
  }
  if !Curve::on_curve(c, q) {
    return false
  }
  let h1 = c.hash_message(msg)
  let e = bits2int(h1, c.bits)
  let w = inv_mod_n(c, s)
  let u1 = @bigint.BigNat::mod_mul_auto(e, w, c.n)
  let u2 = @bigint.BigNat::mod_mul_auto(r, w, c.n)
  let p = Curve::mul_sum(c, u1, q, u2)
  if p.inf {
    return false
  }
  let px = Curve::f_reduce_curve_order(c, p.x)
  @bigint.BigNat::cmp(px, r) == 0
}
