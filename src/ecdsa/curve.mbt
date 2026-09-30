///| NIST P-256 / P-384 short Weierstrass curve arithmetic (Loop #30 G1)
///
///   y^2 = x^3 + a*x + b  (mod p),  a = -3 for both curves
///
///   Point operations use Jacobian projective coordinates so that the inner
///   loop needs no modular inversion; a single inversion is done at the end
///   (Fermat: z^(p-2) mod p) using the Montgomery ladder already in
///   `bigint/mont64.mbt`.
///
///   Reference: FIPS 186-4 §A / SEC 2 v1.0 §3; Hankerson, Menezes, Vanstone,
///   "Guide to Elliptic Curve Cryptography" ch. 3.

///| A short Weierstrass curve with a = -3.
pub struct Curve {
  p : @bigint.BigNat
  n : @bigint.BigNat
  b : @bigint.BigNat
  gx : @bigint.BigNat
  gy : @bigint.BigNat
  bits : Int
  ctx : @bigint.MontCtx   // Montgomery context modulo p
}

///| Affine curve point. `inf = true` denotes the point at infinity.
pub struct Point {
  x : @bigint.BigNat
  y : @bigint.BigNat
  inf : Bool
}

///| Jacobian projective point (X : Y : Z) with x = X/Z^2, y = Y/Z^3.
pub struct JacPoint {
  x : @bigint.BigNat
  y : @bigint.BigNat
  z : @bigint.BigNat
}

///| Construct an affine point.
pub fn Point::new(
  x : @bigint.BigNat,
  y : @bigint.BigNat
) -> Point {
  { x, y, inf: false }
}

///| The point at infinity in affine form.
pub fn Point::infinity() -> Point {
  { x: @bigint.BigNat::from_uint64(0UL), y: @bigint.BigNat::from_uint64(0UL), inf: true }
}

// ============================================================================
// Modular helpers bound to a curve's Montgomery context
// ============================================================================

// The field operations are expressed as dedicated helpers rather than routed
// through mod_pow (which would do a full exponentiation). They call the
// Montgomery multiplication directly.

///| a * b mod p
pub fn Curve::f_mul(c : Curve, a : @bigint.BigNat, b : @bigint.BigNat) -> @bigint.BigNat {
  let k = c.ctx.k
  let r = @bigint.MontCtx::mul(c.ctx, a.to_limbs64(k), b.to_limbs64(k))
  @bigint.limbs64_to_bignat(r, k)
}

///| a + b mod p
pub fn Curve::f_add(c : Curve, a : @bigint.BigNat, b : @bigint.BigNat) -> @bigint.BigNat {
  let s = @bigint.BigNat::add(a, b)
  if @bigint.BigNat::cmp(s, c.p) >= 0 {
    @bigint.BigNat::sub(s, c.p)
  } else {
    s
  }
}

///| a - b mod p
pub fn Curve::f_sub(c : Curve, a : @bigint.BigNat, b : @bigint.BigNat) -> @bigint.BigNat {
  if @bigint.BigNat::cmp(a, b) >= 0 {
    @bigint.BigNat::sub(a, b)
  } else {
    @bigint.BigNat::add(a, @bigint.BigNat::sub(c.p, b))
  }
}

///| a^2 mod p
pub fn Curve::f_sqr(c : Curve, a : @bigint.BigNat) -> @bigint.BigNat {
  Curve::f_mul(c, a, a)
}

///| a^e mod p  (e is a BigNat; used for the final modular inversion)
pub fn Curve::f_pow(c : Curve, a : @bigint.BigNat, e : @bigint.BigNat) -> @bigint.BigNat {
  @bigint.mont_pow_with(c.ctx, a, e)
}

///| a^(-1) mod p, via Fermat's little theorem: a^(p-2) mod p.
pub fn Curve::f_inv(c : Curve, a : @bigint.BigNat) -> @bigint.BigNat {
  let e = @bigint.BigNat::sub(c.p, @bigint.BigNat::from_uint64(2UL))
  Curve::f_pow(c, a, e)
}

///| a mod p (reduce an integer that may exceed p)
pub fn Curve::f_reduce(c : Curve, a : @bigint.BigNat) -> @bigint.BigNat {
  @bigint.BigNat::mod(a, c.p)
}

// ============================================================================
// Jacobian point arithmetic (a = -3)
// ============================================================================

///| The point at infinity in Jacobian form (Z = 0).
pub fn Curve::jac_inf(_c : Curve) -> JacPoint {
  { x: @bigint.BigNat::from_uint64(1UL), y: @bigint.BigNat::from_uint64(1UL), z: @bigint.BigNat::from_uint64(0UL) }
}

///| Convert an affine point to Jacobian form.
pub fn Curve::to_jac(c : Curve, p : Point) -> JacPoint {
  if p.inf {
    return Curve::jac_inf(c)
  }
  { x: p.x, y: p.y, z: @bigint.BigNat::from_uint64(1UL) }
}

///| Convert a Jacobian point to affine form (one inversion).
pub fn Curve::to_affine(c : Curve, j : JacPoint) -> Point {
  if @bigint.BigNat::is_zero(j.z) {
    return { x: @bigint.BigNat::from_uint64(0UL), y: @bigint.BigNat::from_uint64(0UL), inf: true }
  }
  let zinv = Curve::f_inv(c, j.z)
  let zinv2 = Curve::f_sqr(c, zinv)
  let zinv3 = Curve::f_mul(c, zinv2, zinv)
  let x = Curve::f_mul(c, j.x, zinv2)
  let y = Curve::f_mul(c, j.y, zinv3)
  { x, y, inf: false }
}

///| Jacobian point doubling, a = -3 (dbl-2001-b).
pub fn Curve::jac_double(c : Curve, pt : JacPoint) -> JacPoint {
  if @bigint.BigNat::is_zero(pt.z) {
    return pt
  }
  let two = @bigint.BigNat::from_uint64(2UL)
  let three = @bigint.BigNat::from_uint64(3UL)
  let four = @bigint.BigNat::from_uint64(4UL)
  let eight = @bigint.BigNat::from_uint64(8UL)
  // delta = Z^2, gamma = Y^2, beta = X * gamma
  let delta = Curve::f_sqr(c, pt.z)
  let gamma = Curve::f_sqr(c, pt.y)
  let beta = Curve::f_mul(c, pt.x, gamma)
  // alpha = 3 * (X - delta) * (X + delta)
  let t1 = Curve::f_sub(c, pt.x, delta)
  let t2 = Curve::f_add(c, pt.x, delta)
  let t3 = Curve::f_mul(c, t1, t2)
  let alpha = Curve::f_mul(c, three, t3)
  // X' = alpha^2 - 8*beta
  let alpha2 = Curve::f_sqr(c, alpha)
  let beta8 = Curve::f_mul(c, eight, beta)
  let x3 = Curve::f_sub(c, alpha2, beta8)
  // Z' = (Y + Z)^2 - gamma - delta
  let yz = Curve::f_add(c, pt.y, pt.z)
  let yz2 = Curve::f_sqr(c, yz)
  let z3 = Curve::f_sub(c, Curve::f_sub(c, yz2, gamma), delta)
  // Y' = alpha * (4*beta - X') - 8*gamma^2
  let beta4 = Curve::f_mul(c, four, beta)
  let t4 = Curve::f_sub(c, beta4, x3)
  let t5 = Curve::f_mul(c, alpha, t4)
  let gamma2 = Curve::f_sqr(c, gamma)
  let gamma8 = Curve::f_mul(c, eight, gamma2)
  let y3 = Curve::f_sub(c, t5, gamma8)
  ignore(two)
  { x: x3, y: y3, z: z3 }
}

///| Jacobian point addition, handling doubling and infinity cases
///   (add-2007-bl from the Explicit-Formulas Database).
///
///   The formulas must stay in the EFD's own scaling: I = (2H)^2, J = H*I,
///   r = 2*(S2-S1). Using a "halved" variant (I = H^2) computes the same
///   affine point but leaves X, Y and Z scaled by *different* factors (4, 8, 1),
///   which destroys the projective equivalence.
pub fn Curve::jac_add(c : Curve, p1 : JacPoint, p2 : JacPoint) -> JacPoint {
  if @bigint.BigNat::is_zero(p1.z) {
    return p2
  }
  if @bigint.BigNat::is_zero(p2.z) {
    return p1
  }
  let two = @bigint.BigNat::from_uint64(2UL)
  let z1z1 = Curve::f_sqr(c, p1.z)
  let z2z2 = Curve::f_sqr(c, p2.z)
  let u1 = Curve::f_mul(c, p1.x, z2z2)
  let u2 = Curve::f_mul(c, p2.x, z1z1)
  let s1 = Curve::f_mul(c, Curve::f_mul(c, p1.y, p2.z), z2z2)
  let s2 = Curve::f_mul(c, Curve::f_mul(c, p2.y, p1.z), z1z1)
  let h = Curve::f_sub(c, u2, u1)
  let rr = Curve::f_sub(c, s2, s1)
  if @bigint.BigNat::is_zero(h) {
    if @bigint.BigNat::is_zero(rr) {
      return Curve::jac_double(c, p1)
    }
    // P1 = -P2 -> point at infinity
    return Curve::jac_inf(c)
  }
  // I = (2H)^2, J = H*I, r = 2*(S2-S1)
  let hh = Curve::f_sqr(c, h)
  let i_v = Curve::f_sqr(c, Curve::f_mul(c, two, h))
  let j_v = Curve::f_mul(c, h, i_v)
  let r_v = Curve::f_mul(c, two, rr)
  let v = Curve::f_mul(c, u1, i_v)
  let x3 = Curve::f_sub(c, Curve::f_sub(c, Curve::f_sqr(c, r_v), j_v), Curve::f_mul(c, two, v))
  let y3 = Curve::f_sub(c,
    Curve::f_mul(c, r_v, Curve::f_sub(c, v, x3)),
    Curve::f_mul(c, two, Curve::f_mul(c, s1, j_v)))
  // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
  let zsum = Curve::f_sqr(c, Curve::f_add(c, p1.z, p2.z))
  let zfac = Curve::f_sub(c, Curve::f_sub(c, zsum, z1z1), z2z2)
  let z3 = Curve::f_mul(c, zfac, h)
  ignore(hh)
  { x: x3, y: y3, z: z3 }
}

///| Scalar multiplication k * P using a fixed left-to-right double-and-add.
///   Deterministic (no random blinding) so results are byte-reproducible.
pub fn Curve::mul(
  c : Curve,
  k : @bigint.BigNat,
  p : Point
) -> Point {
  if @bigint.BigNat::is_zero(k) {
    return { x: @bigint.BigNat::from_uint64(0UL), y: @bigint.BigNat::from_uint64(0UL), inf: true }
  }
  let jp = Curve::to_jac(c, p)
  let bits = k.bit_length()
  let mut acc = Curve::jac_inf(c)
  let mut i = bits - 1
  while i >= 0 {
    acc = Curve::jac_double(c, acc)
    let limb_idx = i / 32
    let bit_idx = i % 32
    let word = if limb_idx < k.len { k.limbs[limb_idx] } else { 0U }
    let bit = (word >> bit_idx) & 1U
    if bit != 0U {
      acc = Curve::jac_add(c, acc, jp)
    }
    i = i - 1
  }
  Curve::to_affine(c, acc)
}

///| Scalar multiplication with two scalars: u1*G + u2*Q (Shamir's trick).
pub fn Curve::mul_sum(
  c : Curve,
  u1 : @bigint.BigNat,
  q : Point,
  u2 : @bigint.BigNat
) -> Point {
  let g = { x: c.gx, y: c.gy, inf: false }
  // Simple, clearly-correct version: two independent multiplications added.
  let p1 = Curve::mul(c, u1, g)
  let p2 = Curve::mul(c, u2, q)
  Curve::point_add(c, p1, p2)
}

///| Affine point addition (uses one inversion via `to_affine`).
pub fn Curve::point_add(c : Curve, p1 : Point, p2 : Point) -> Point {
  let j = Curve::jac_add(c, Curve::to_jac(c, p1), Curve::to_jac(c, p2))
  Curve::to_affine(c, j)
}

///| Is the point on the curve? Verifies y^2 == x^3 - 3x + b (mod p).
pub fn Curve::on_curve(c : Curve, pt : Point) -> Bool {
  if pt.inf {
    return false
  }
  let x3 = Curve::f_mul(c, Curve::f_sqr(c, pt.x), pt.x)
  let three_x = Curve::f_mul(c, @bigint.BigNat::from_uint64(3UL), pt.x)
  let rhs = Curve::f_add(c, Curve::f_sub(c, x3, three_x), c.b)
  let lhs = Curve::f_sqr(c, pt.y)
  @bigint.BigNat::cmp(lhs, rhs) == 0
}
