///| X25519 modular inverse via Fermat's little theorem

///| 对应 OpenBSD smult_curve25519_ref.c 第 180-245 行

///|

///| z^(p-2) mod p where p = 2^255 - 19

///| p - 2 = 2^255 - 21 = 0b11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111_11101011

///| = sum(2^i for i in 0..254) - 2^5 + 2^3 + 2^1 + 2^0

///| = 2^255 - 32 + 11 = 2^255 - 21 ✓

///| 计算 z^(p-2) mod p(z 是 32-limb field element)

///|
/// 输出也是 32-limb field element
pub fn recip(out : FixedArray[UInt], z : FixedArray[UInt]) -> Unit {
  // 局部变量(32-limb)
  let z2 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let z9 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let z11 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let z2_5_0 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let z2_10_0 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let z2_20_0 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let z2_50_0 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let z2_100_0 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let t0 : FixedArray[UInt] = FixedArray::make(32, 0U)
  let t1 : FixedArray[UInt] = FixedArray::make(32, 0U)

  // z^2
  fe_square(z2, z)
  // z^4
  fe_square(t1, z2)
  // z^8
  fe_square(t0, t1)
  // z^9 = z^8 * z
  fe_mult(z9, t0, z)
  // z^11 = z^9 * z^2
  fe_mult(z11, z9, z2)
  // z^22 = (z^11)^2
  fe_square(t0, z11)
  // z^(2^5 - 2^0) = z^31 = z^22 * z^9
  fe_mult(z2_5_0, t0, z9)

  // z^(2^6 - 2^1)
  fe_square(t0, z2_5_0)
  // z^(2^7 - 2^2)
  fe_square(t1, t0)
  // z^(2^8 - 2^3)
  fe_square(t0, t1)
  // z^(2^9 - 2^4)
  fe_square(t1, t0)
  // z^(2^10 - 2^5)
  fe_square(t0, t1)
  // z^(2^10 - 2^0) = z^1023 = z^(2^10-2^5) * z^(2^5-2^0)
  fe_mult(z2_10_0, t0, z2_5_0)

  // z^(2^11 - 2^1)
  fe_square(t0, z2_10_0)
  // z^(2^12 - 2^2)
  fe_square(t1, t0)
  // z^(2^20 - 2^10): 4 轮 square 循环
  let mut i : Int = 2
  while i < 10 {
    fe_square(t0, t1)
    fe_square(t1, t0)
    i = i + 2
  }
  // z^(2^20 - 2^0)
  fe_mult(z2_20_0, t1, z2_10_0)

  // z^(2^21 - 2^1)
  fe_square(t0, z2_20_0)
  // z^(2^22 - 2^2)
  fe_square(t1, t0)
  // z^(2^40 - 2^20): 9 轮 square 循环
  i = 2
  while i < 20 {
    fe_square(t0, t1)
    fe_square(t1, t0)
    i = i + 2
  }
  // z^(2^40 - 2^0)
  fe_mult(t0, t1, z2_20_0)

  // z^(2^41 - 2^1)
  fe_square(t1, t0)
  // z^(2^42 - 2^2)
  fe_square(t0, t1)
  // z^(2^50 - 2^10): 4 轮
  i = 2
  while i < 10 {
    fe_square(t1, t0)
    fe_square(t0, t1)
    i = i + 2
  }
  // z^(2^50 - 2^0)
  fe_mult(z2_50_0, t0, z2_10_0)

  // z^(2^51 - 2^1)
  fe_square(t0, z2_50_0)
  // z^(2^52 - 2^2)
  fe_square(t1, t0)
  // z^(2^100 - 2^50): 24 轮
  i = 2
  while i < 50 {
    fe_square(t0, t1)
    fe_square(t1, t0)
    i = i + 2
  }
  // z^(2^100 - 2^0)
  fe_mult(z2_100_0, t1, z2_50_0)

  // z^(2^101 - 2^1)
  fe_square(t1, z2_100_0)
  // z^(2^102 - 2^2)
  fe_square(t0, t1)
  // z^(2^200 - 2^100): 49 轮
  i = 2
  while i < 100 {
    fe_square(t1, t0)
    fe_square(t0, t1)
    i = i + 2
  }
  // z^(2^200 - 2^0)
  fe_mult(t1, t0, z2_100_0)

  // z^(2^201 - 2^1)
  fe_square(t0, t1)
  // z^(2^202 - 2^2)
  fe_square(t1, t0)
  // z^(2^250 - 2^50): 24 轮
  i = 2
  while i < 50 {
    fe_square(t0, t1)
    fe_square(t1, t0)
    i = i + 2
  }
  // z^(2^250 - 2^0)
  fe_mult(t0, t1, z2_50_0)

  // z^(2^251 - 2^1)
  fe_square(t1, t0)
  // z^(2^252 - 2^2)
  fe_square(t0, t1)
  // z^(2^253 - 2^3)
  fe_square(t1, t0)
  // z^(2^254 - 2^4)
  fe_square(t0, t1)
  // z^(2^255 - 2^5)
  fe_square(t1, t0)
  // z^(2^255 - 21) = z^(2^255 - 2^5) * z^16 (即 z^(2^5) 应该是 z^16? 不,z^11 = z^16 - 5, 链中保留 z11 用作最后一乘)
  // OpenBSD 注释: 2^255 - 21, mult(out, t1, z11)
  fe_mult(out, t1, z11)
}
