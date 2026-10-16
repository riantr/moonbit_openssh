///| Field arithmetic mod p = 2^255 - 19

///| 对应 OpenSSH ed25519.c (TweetNaCl ref10, 32-limb variant)

///|

///| 内部表示:32 个 8-bit limbs,存储在 UInt64 中

///| 32 × 8 = 256 bits,前 255 bits 表数值,第 256 bit 留作 carry

///|

///| 关键约束:

///| - limb 之间 carry 用 `>> 8` 传播(不是 `>> 32`),匹配 8-bit limb

///| - mul 中间值 (8-bit × 8-bit) ≤ 16-bit,累加 32 项 ≤ 21-bit,fits in UInt64

///| - 2p - y 减法技巧(避免 0 - y 借位):0x1DA / 0x1FE / 0xFE

///|
/// Field element,32 个 UInt64 limbs(每个 limb 实际值 0..255)
type Fe = FixedArray[UInt64]

///|
/// 创建 32-limb 全零 Field element
fn fe_new() -> Fe {
  FixedArray::make(32, 0UL)
}

///| 从 32 字节 LE 输入创建 Field element

///|
/// 第一个字节放 limb 0,最后一个字节的高位被清掉(bit 255)
pub fn fe_unpack(bytes : FixedArray[Byte]) -> Fe {
  let r : Fe = fe_new()
  for i = 0; i < 32; i = i + 1 {
    r[i] = bytes[i].to_uint64()
  }
  r[31] = r[31] & 0x7FUL // 清掉 bit 255
  r
}

///| 序列化为 32 字节 LE

///|
/// 假设输入已 mod p 归约(< 2^255)
pub fn fe_pack(x : Fe) -> FixedArray[Byte] {
  let y : Fe = fe_new()
  for i = 0; i < 32; i = i + 1 {
    y[i] = x[i]
  }
  fe_freeze_inplace(y)
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = y[i].to_byte()
  }
  out
}

///|
/// fe = 1
pub fn fe_one() -> Fe {
  let r : Fe = fe_new()
  r[0] = 1UL
  r
}

///|
/// fe = 0
pub fn fe_zero() -> Fe {
  fe_new()
}

///|
/// 就地写零:r = 0
pub fn fe_setzero(r : Fe) -> Unit {
  for i = 0; i < 32; i = i + 1 {
    r[i] = 0UL
  }
}

///|
/// 就地写一:r = 1
pub fn fe_setone(r : Fe) -> Unit {
  r[0] = 1UL
  for i = 1; i < 32; i = i + 1 {
    r[i] = 0UL
  }
}

///| 16-bit 输入比较: a == b ? 1 : 0

///| 对应 C: fe25519_equal

///|
/// C 中 32-bit shift >> 31 给出 0 或 1,UInt64 需要 >> 63 + & 1
fn fe_equal16(a : UInt64, b : UInt64) -> UInt64 {
  let x = a ^ b
  let x = x - 1UL
  (x >> 63) & 1UL
}

///| 16-bit 输入比较: a >= b ? 1 : 0

///|
/// 对应 C: ge
fn fe_ge16(a : UInt64, b : UInt64) -> UInt64 {
  let x = a - b
  let x = (x >> 63) & 1UL
  x ^ 1UL
}

///|
/// 19*a
fn times19(a : UInt64) -> UInt64 {
  (a << 4) + (a << 1) + a
}

///|
/// 38*a
fn times38(a : UInt64) -> UInt64 {
  (a << 5) + (a << 2) + (a << 1)
}

///| 4 轮 add_sub reduction

///| 4 轮 propagation(消除所有 carry,确保 r < 2^255)

///|
/// 对应 C: fe25519_reduce_add_sub
fn fe_reduce_add_sub(r : Fe) -> Unit {
  for _rep = 0; _rep < 4; _rep = _rep + 1 {
    let t = r[31] >> 7
    r[31] = r[31] & 0x7FUL
    let t = times19(t)
    r[0] = r[0] + t
    for i = 0; i < 31; i = i + 1 {
      let t2 = r[i] >> 8
      r[i + 1] = r[i + 1] + t2
      r[i] = r[i] & 0xFFUL
    }
  }
}

///| 2 轮 mul reduction(供 fe_mul 使用)

///|
/// 对应 C: reduce_mul
fn fe_reduce_mul(r : Fe) -> Unit {
  for _rep = 0; _rep < 2; _rep = _rep + 1 {
    let t = r[31] >> 7
    r[31] = r[31] & 0x7FUL
    let t = times19(t)
    r[0] = r[0] + t
    for i = 0; i < 31; i = i + 1 {
      let t2 = r[i] >> 8
      r[i + 1] = r[i + 1] + t2
      r[i] = r[i] & 0xFFUL
    }
  }
}

///| 完整 mod p 归约

///|
/// 对应 C: fe25519_freeze
fn fe_freeze_inplace(r : Fe) -> Unit {
  let mut m = fe_equal16(r[31], 0x7FUL)
  for i = 30; i > 0; i = i - 1 {
    m = m & fe_equal16(r[i], 0xFFUL)
  }
  m = m & fe_ge16(r[0], 0xEDUL)
  // m = -m: m 是 0 或 1,-m 是 0 或 0xFFFFFFFFFFFFFFFF
  m = 0UL - m
  r[31] = r[31] - (m & 0x7FUL)
  for i = 30; i > 0; i = i - 1 {
    r[i] = r[i] - (m & 0xFFUL)
  }
  r[0] = r[0] - (m & 0xEDUL)
}

///|
/// 连续 n 次 squaring: r = x^(2^n)
fn fe_square_n(x : Fe, n : Int32) -> Fe {
  let mut r = x
  for _i = 0; _i < n; _i = _i + 1 {
    r = fe_square(r)
  }
  r
}

///|
/// r = x + y
pub fn fe_add(x : Fe, y : Fe) -> Fe {
  let r : Fe = fe_new()
  for i = 0; i < 32; i = i + 1 {
    r[i] = x[i] + y[i]
  }
  fe_reduce_add_sub(r)
  r
}

///| r = -x

///|
/// 对应 C: fe25519_neg (用 fe25519_sub(0, x))
pub fn fe_neg(x : Fe) -> Fe {
  let r : Fe = fe_new()
  fe_sub_into(r, r, x)
  r
}

///|
/// r = x - y(用 2p - y 技巧避免 0 - y 借位)
pub fn fe_sub(x : Fe, y : Fe) -> Fe {
  let r : Fe = fe_new()
  fe_sub_into(r, x, y)
  r
}

///|
/// 就地:r = x - y,使用 2p + x - y 减法
fn fe_sub_into(r : Fe, x : Fe, y : Fe) -> Unit {
  // 2p = 2^256 - 38,32-limb 表示: [0x1DA, 0x1FE, 0x1FE, ..., 0x1FE, 0xFE]
  // 加上 x 然后减 y
  let t0 = x[0] + 0x1DAUL
  let t31 = x[31] + 0xFEUL
  for i = 0; i < 32; i = i + 1 {
    let t : UInt64 = if i == 0 {
      t0
    } else if i == 31 {
      t31
    } else {
      x[i] + 0x1FEUL
    }
    r[i] = t - y[i]
  }
  fe_reduce_add_sub(r)
}

///|
/// r = x * y
pub fn fe_mul(x : Fe, y : Fe) -> Fe {
  let r : Fe = fe_new()
  // 63 个 32-bit 中间累加器
  let t : FixedArray[UInt64] = FixedArray::make(63, 0UL)
  for i = 0; i < 32; i = i + 1 {
    for j = 0; j < 32; j = j + 1 {
      t[i + j] = t[i + j] + x[i] * y[j]
    }
  }
  // 合并: r[i-32] = t[i-32] + 38 * t[i]  for i in 32..63
  for i = 32; i < 63; i = i + 1 {
    r[i - 32] = t[i - 32] + times38(t[i])
  }
  r[31] = t[31]
  fe_reduce_mul(r)
  r
}

///|
/// r = x^2(reuses fe_mul)
pub fn fe_square(x : Fe) -> Fe {
  fe_mul(x, x)
}

///| constant-time conditional move: r = b ? x : r

///| b: 0 或 1

///|
/// 对应 C: fe25519_cmov
pub fn fe_cmov(r : Fe, x : Fe, b : UInt64) -> Unit {
  let mask = 0UL - b
  for i = 0; i < 32; i = i + 1 {
    r[i] = r[i] ^ (mask & (x[i] ^ r[i]))
  }
}

///|
/// vartime: r 是否 == 0 (mod p)
pub fn fe_iszero_vartime(x : Fe) -> Bool {
  let t : Fe = fe_new()
  for i = 0; i < 32; i = i + 1 {
    t[i] = x[i]
  }
  fe_freeze_inplace(t)
  let mut r = fe_equal16(t[0], 0UL)
  for i = 1; i < 32; i = i + 1 {
    r = r & fe_equal16(t[i], 0UL)
  }
  r == 1UL
}

///|
/// vartime: x == y (mod p)
pub fn fe_iseq_vartime(x : Fe, y : Fe) -> Bool {
  let t1 : Fe = fe_new()
  let t2 : Fe = fe_new()
  for i = 0; i < 32; i = i + 1 {
    t1[i] = x[i]
    t2[i] = y[i]
  }
  fe_freeze_inplace(t1)
  fe_freeze_inplace(t2)
  let mut eq = true
  for i = 0; i < 32; i = i + 1 {
    if t1[i] != t2[i] {
      eq = false
    }
  }
  eq
}

///|
/// vartime: 返回 t[0] 的最低 bit(供 ge25519_pack 用)
pub fn fe_getparity(x : Fe) -> UInt64 {
  let t : Fe = fe_new()
  for i = 0; i < 32; i = i + 1 {
    t[i] = x[i]
  }
  fe_freeze_inplace(t)
  t[0] & 1UL
}

///| r = x^(p-2) mod p (Fermat's little theorem)

///| 对应 C: fe25519_invert

///|

///| 关键:C 中的双 squaring 循环 `for (i = 2; i < N; i += 2) { sq(t0, t1); sq(t1, t0); }`

///|
/// 执行 (N-2)/2 次迭代 × 2 squarings = N-2 squarings
pub fn fe_invert(x : Fe) -> Fe {
  let z2 = fe_square(x) // 2
  let t1 = fe_square(z2) // 4
  let t0 = fe_square(t1) // 8
  let z9 = fe_mul(t0, x) // 9
  let z11 = fe_mul(z9, z2) // 11
  let t2 = fe_square(z11) // 22
  let z2_5_0 = fe_mul(t2, z9) // 2^5 - 2^0 = 31
  let t3 = fe_square(z2_5_0) // 2^6 - 2^1
  let t4 = fe_square(t3) // 2^7 - 2^2
  let t5 = fe_square(t4) // 2^8 - 2^3
  let t6 = fe_square(t5) // 2^9 - 2^4
  let t7 = fe_square(t6) // 2^10 - 2^5
  let z2_10_0 = fe_mul(t7, z2_5_0) // 2^10 - 2^0
  let t8 = fe_square(z2_10_0) // 2^11 - 2^1
  let t9 = fe_square(t8) // 2^12 - 2^2
  let t10 = fe_square_n(t9, 8) // 2^12 → 2^20 - 2^10 (4 iter × 2 sq = 8 sq)
  let z2_20_0 = fe_mul(t10, z2_10_0) // 2^20 - 2^0
  let t11 = fe_square(z2_20_0) // 2^21 - 2^1
  let t12 = fe_square(t11) // 2^22 - 2^2
  let t13 = fe_square_n(t12, 18) // 2^22 → 2^40 - 2^20 (9 iter × 2 sq = 18 sq)
  let t14 = fe_mul(t13, z2_20_0) // 2^40 - 2^0
  let t15 = fe_square(t14) // 2^41 - 2^1
  let t16 = fe_square(t15) // 2^42 - 2^2
  let t17 = fe_square_n(t16, 8) // 2^42 → 2^50 - 2^10 (4 iter × 2 sq = 8 sq)
  let z2_50_0 = fe_mul(t17, z2_10_0) // 2^50 - 2^0
  let t18 = fe_square(z2_50_0) // 2^51 - 2^1
  let t19 = fe_square(t18) // 2^52 - 2^2
  let t20 = fe_square_n(t19, 48) // 2^52 → 2^100 - 2^50 (24 iter × 2 sq = 48 sq)
  let z2_100_0 = fe_mul(t20, z2_50_0) // 2^100 - 2^0
  let t21 = fe_square(z2_100_0) // 2^101 - 2^1
  let t22 = fe_square(t21) // 2^102 - 2^2
  let t23 = fe_square_n(t22, 98) // 2^102 → 2^200 - 2^100 (49 iter × 2 sq = 98 sq)
  let t24 = fe_mul(t23, z2_100_0) // 2^200 - 2^0
  let t25 = fe_square(t24) // 2^201 - 2^1
  let t26 = fe_square(t25) // 2^202 - 2^2
  let t27 = fe_square_n(t26, 48) // 2^202 → 2^250 - 2^50 (24 iter × 2 sq = 48 sq)
  let t28 = fe_mul(t27, z2_50_0) // 2^250 - 2^0
  let t29 = fe_square(t28) // 2^251 - 2^1
  let t30 = fe_square(t29) // 2^252 - 2^2
  let t31 = fe_square(t30) // 2^253 - 2^3
  let t32 = fe_square(t31) // 2^254 - 2^4
  let t33 = fe_square(t32) // 2^255 - 2^5
  fe_mul(t33, z11) // 2^255 - 21 = p - 2
}

///| r = x^((p-5)/8) mod p

///|
/// 对应 C: fe25519_pow2523
pub fn fe_pow2523(x : Fe) -> Fe {
  let z2 = fe_square(x) // 2
  let t1 = fe_square(z2) // 4
  let t2 = fe_square(t1) // 8
  let z9 = fe_mul(t2, x) // 9
  let z11 = fe_mul(z9, z2) // 11
  let t3 = fe_square(z11) // 22
  let z2_5_0 = fe_mul(t3, z9) // 31
  let t4 = fe_square(z2_5_0) // 62
  let t5 = fe_square_n(t4, 4) // 62 → 2^10 - 2^5
  let z2_10_0 = fe_mul(t5, z2_5_0) // 2^10 - 2^0
  let t6 = fe_square(z2_10_0) // 2^11 - 2^1
  let t7 = fe_square_n(t6, 9) // 2^11 → 2^20 - 2^10
  let z2_20_0 = fe_mul(t7, z2_10_0) // 2^20 - 2^0
  let t8 = fe_square(z2_20_0) // 2^21 - 2^1
  let t9 = fe_square_n(t8, 19) // 2^21 → 2^40 - 2^20
  let t10 = fe_mul(t9, z2_20_0) // 2^40 - 2^0
  let t11 = fe_square(t10) // 2^41 - 2^1
  let t12 = fe_square_n(t11, 9) // 2^41 → 2^50 - 2^10
  let z2_50_0 = fe_mul(t12, z2_10_0) // 2^50 - 2^0
  let t13 = fe_square(z2_50_0) // 2^51 - 2^1
  let t14 = fe_square_n(t13, 49) // 2^51 → 2^100 - 2^50
  let z2_100_0 = fe_mul(t14, z2_50_0) // 2^100 - 2^0
  let t15 = fe_square(z2_100_0) // 2^101 - 2^1
  let t16 = fe_square_n(t15, 99) // 2^101 → 2^200 - 2^100
  let t17 = fe_mul(t16, z2_100_0) // 2^200 - 2^0
  let t18 = fe_square(t17) // 2^201 - 2^1
  let t19 = fe_square_n(t18, 49) // 2^201 → 2^250 - 2^50
  let t20 = fe_mul(t19, z2_50_0) // 2^250 - 2^0
  let t21 = fe_square(t20) // 2^251 - 2^1
  let t22 = fe_square(t21) // 2^252 - 2^2
  fe_mul(t22, x) // 2^252 - 3 = (p-5)/8
}
