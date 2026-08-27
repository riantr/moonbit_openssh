///| Scalar arithmetic mod L (group order of Curve25519)

///| 对应 OpenSSH ed25519.c (TweetNaCl ref10, 32-limb variant)

///|

///| 内部表示:32 个 8-bit limbs,存储在 UInt64 中

///| 与 Field 同结构,但 mod L 不同(用 Barrett 归约)
///

///| Group order L (8 × 32-bit LE):

///|   L = 2^252 + 27742317777372353535851937790883648493

///|     = 0xEDD3F55C1A631258D69CF7A2DE9F130D5DB00280485A829B121A62D9F4D6D815

///|

///| Barrett mu:用于 Barrett reduction,见 HAC Alg. 14.42

///|
/// Scalar element,32 个 UInt64 limbs(每个 limb 实际值 0..255)
type Sc = FixedArray[UInt64]

///| L 模数常量(32 × 8-bit LE)

///|
/// 对应 C: sc25519_m
let sc_l : FixedArray[UInt64] = [
  0xEDUL, 0xD3UL, 0xF5UL, 0x5CUL, 0x1AUL, 0x63UL, 0x12UL, 0x58UL, 0xD6UL, 0x9CUL,
  0xF7UL, 0xA2UL, 0xDEUL, 0xF9UL, 0xDEUL, 0x14UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL,
  0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL,
  0x00UL, 0x10UL,
]

///| Barrett reduction mu 常量(33 × 8-bit)

///|
/// 对应 C: sc25519_mu
let sc_mu : FixedArray[UInt64] = [
  0x1BUL, 0x13UL, 0x2CUL, 0x0AUL, 0xA3UL, 0xE5UL, 0x9CUL, 0xEDUL, 0xA7UL, 0x29UL,
  0x63UL, 0x08UL, 0x5DUL, 0x21UL, 0x06UL, 0x21UL, 0xEBUL, 0xFFUL, 0xFFUL, 0xFFUL,
  0xFFUL, 0xFFUL, 0xFFUL, 0xFFUL, 0xFFUL, 0xFFUL, 0xFFUL, 0xFFUL, 0xFFUL, 0xFFUL,
  0xFFUL, 0xFFUL, 0x0FUL,
]

///|
/// 创建 32-limb 全零 Scalar
fn sc_new() -> Sc {
  FixedArray::make(32, 0UL)
}

///| 16-bit 输入比较: a < b ? 1 : 0

///|
/// 对应 C: lt
fn sc_lt16(a : UInt64, b : UInt64) -> UInt64 {
  let x = a - b
  (x >> 63) & 1UL
}

///| 还原 r (mod L) — 当 r 略大于 L 时使用

///|
/// 对应 C: sc25519_reduce_add_sub
fn sc_reduce_add_sub(r : Sc) -> Unit {
  let mut pb : UInt64 = 0
  let mut b : UInt64 = 0
  let t : FixedArray[UInt64] = FixedArray::make(32, 0UL)
  for i = 0; i < 32; i = i + 1 {
    pb = pb + sc_l[i]
    b = sc_lt16(r[i], pb)
    t[i] = r[i] - pb + (b << 8)
    pb = b
  }
  let mask = b - 1UL
  for i = 0; i < 32; i = i + 1 {
    r[i] = r[i] ^ (mask & (r[i] ^ t[i]))
  }
}

///| Barrett reduction (HAC Alg. 14.42)

///| 输入:x 是 64 个 8-bit limbs

///| 输出:r 是 mod L 归约后的 32-limb scalar

///|
/// 对应 C: barrett_reduce
fn sc_barrett_reduce(r : Sc, x : FixedArray[UInt64]) -> Unit {
  let q2 : FixedArray[UInt64] = FixedArray::make(66, 0UL)
  let r2 : FixedArray[UInt64] = FixedArray::make(33, 0UL)
  // q2[i+j] += mu[i] * x[j+31]  for i,j in 0..33 with i+j >= 31
  for i = 0; i < 33; i = i + 1 {
    for j = 0; j < 33; j = j + 1 {
      if i + j >= 31 {
        q2[i + j] = q2[i + j] + sc_mu[i] * x[j + 31]
      }
    }
  }
  // carry propagation on q2[31..33]
  let mut carry = q2[31] >> 8
  q2[32] = q2[32] + carry
  carry = q2[32] >> 8
  q2[33] = q2[33] + carry
  // r1 = x[0..33]
  let r1 : FixedArray[UInt64] = FixedArray::make(33, 0UL)
  for i = 0; i < 33; i = i + 1 {
    r1[i] = x[i]
  }
  // r2[i+j] += L[i] * q3[j]  for i,j with i+j < 33
  // q3 = q2 + 33
  for i = 0; i < 32; i = i + 1 {
    for j = 0; j < 33; j = j + 1 {
      if i + j < 33 {
        r2[i + j] = r2[i + j] + sc_l[i] * q2[j + 33]
      }
    }
  }
  // r2 carry propagation
  for i = 0; i < 32; i = i + 1 {
    let c = r2[i] >> 8
    r2[i + 1] = r2[i + 1] + c
    r2[i] = r2[i] & 0xFFUL
  }
  // r1 - r2 → r->v[0..32]
  let mut pb : UInt64 = 0
  let mut b : UInt64 = 0
  for i = 0; i < 32; i = i + 1 {
    pb = pb + r2[i]
    b = sc_lt16(r1[i], pb)
    r[i] = r1[i] - pb + (b << 8)
    pb = b
  }
  // r might be < 0; do reduce_add_sub twice
  sc_reduce_add_sub(r)
  sc_reduce_add_sub(r)
}

///| 从 32 字节 LE 创建 Scalar(mod L 归约)

///|
/// 对应 C: sc25519_from32bytes
pub fn sc_from32bytes(bytes : FixedArray[Byte]) -> Sc {
  let r : Sc = sc_new()
  let t : FixedArray[UInt64] = FixedArray::make(64, 0UL)
  for i = 0; i < 32; i = i + 1 {
    t[i] = bytes[i].to_uint64()
  }
  sc_barrett_reduce(r, t)
  r
}

///| 从 64 字节 LE 创建 Scalar(取 mod L)

///|
/// 对应 C: sc25519_from64bytes
pub fn sc_from64bytes(bytes : FixedArray[Byte]) -> Sc {
  let r : Sc = sc_new()
  let t : FixedArray[UInt64] = FixedArray::make(64, 0UL)
  for i = 0; i < 64; i = i + 1 {
    t[i] = bytes[i].to_uint64()
  }
  sc_barrett_reduce(r, t)
  r
}

///| 序列化为 32 字节 LE

///|
/// 对应 C: sc25519_to32bytes
pub fn sc_to32bytes(s : Sc) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = s[i].to_byte()
  }
  out
}

///| r = x + y(就地,然后 reduce_add_sub mod L)

///|
/// 对应 C: sc25519_add
pub fn sc_add(x : Sc, y : Sc) -> Sc {
  let r : Sc = sc_new()
  for i = 0; i < 32; i = i + 1 {
    r[i] = x[i] + y[i]
  }
  // carry propagation
  for i = 0; i < 31; i = i + 1 {
    let carry = r[i] >> 8
    r[i + 1] = r[i + 1] + carry
    r[i] = r[i] & 0xFFUL
  }
  sc_reduce_add_sub(r)
  r
}

///| r = x * y(mod L,使用 Barrett reduction)

///|
/// 对应 C: sc25519_mul
pub fn sc_mul(x : Sc, y : Sc) -> Sc {
  let r : Sc = sc_new()
  let t : FixedArray[UInt64] = FixedArray::make(64, 0UL)
  for i = 0; i < 32; i = i + 1 {
    for j = 0; j < 32; j = j + 1 {
      t[i + j] = t[i + j] + x[i] * y[j]
    }
  }
  // carry propagation
  for i = 0; i < 63; i = i + 1 {
    let carry = t[i] >> 8
    t[i + 1] = t[i + 1] + carry
    t[i] = t[i] & 0xFFUL
  }
  sc_barrett_reduce(r, t)
  r
}

///| 转换 s 为 85 个 signed 3-bit window(-4..3)用于 scalarmult_base

///|
/// 对应 C: sc25519_window3
pub fn sc_window3(s : Sc) -> FixedArray[Int] {
  let r : FixedArray[Int] = FixedArray::make(85, 0)
  // 11 full iterations (3 bytes each) + 1 partial (4 bytes)
  for i = 0; i < 10; i = i + 1 {
    r[8 * i + 0] = s[3 * i + 0].to_int() & 7
    r[8 * i + 1] = (s[3 * i + 0] >> 3).to_int() & 7
    r[8 * i + 2] = ((s[3 * i + 0] >> 6).to_int() ^ (s[3 * i + 1] << 2).to_int()) &
      7
    r[8 * i + 3] = (s[3 * i + 1] >> 1).to_int() & 7
    r[8 * i + 4] = (s[3 * i + 1] >> 4).to_int() & 7
    r[8 * i + 5] = ((s[3 * i + 1] >> 7).to_int() ^ (s[3 * i + 2] << 1).to_int()) &
      7
    r[8 * i + 6] = (s[3 * i + 2] >> 2).to_int() & 7
    r[8 * i + 7] = (s[3 * i + 2] >> 5).to_int() & 7
  }
  // 11th iteration (partial, only 4 bits of byte 30)
  let i = 10
  r[8 * i + 0] = s[3 * i + 0].to_int() & 7
  r[8 * i + 1] = (s[3 * i + 0] >> 3).to_int() & 7
  r[8 * i + 2] = ((s[3 * i + 0] >> 6).to_int() ^ (s[3 * i + 1] << 2).to_int()) &
    7
  r[8 * i + 3] = (s[3 * i + 1] >> 1).to_int() & 7
  r[8 * i + 4] = (s[3 * i + 1] >> 4).to_int() & 7
  // sign conversion: turn into signed representation
  let mut carry : Int = 0
  for j = 0; j < 84; j = j + 1 {
    r[j] = r[j] + carry
    let rj1 = r[j + 1] + (r[j] >> 3)
    r[j + 1] = rj1
    r[j] = r[j] & 7
    carry = r[j] >> 2
    r[j] = r[j] - (carry << 3)
  }
  r[84] = r[84] + carry
  r
}

///| 转换两个 scalar 为 interleaved 5-bit windows for double_scalarmult_vartime

///| 输出: 127 字节,每字节是 (s1 的 2 bits) ^ (s2 的 2 bits << 2)

///|
/// 对应 C: sc25519_2interleave2
pub fn sc_2interleave2(s1 : Sc, s2 : Sc) -> FixedArray[UInt64] {
  let r : FixedArray[UInt64] = FixedArray::make(127, 0UL)
  for i = 0; i < 31; i = i + 1 {
    r[4 * i + 0] = (s1[i] & 3UL) ^ ((s2[i] & 3UL) << 2)
    r[4 * i + 1] = ((s1[i] >> 2) & 3UL) ^ (((s2[i] >> 2) & 3UL) << 2)
    r[4 * i + 2] = ((s1[i] >> 4) & 3UL) ^ (((s2[i] >> 4) & 3UL) << 2)
    r[4 * i + 3] = ((s1[i] >> 6) & 3UL) ^ (((s2[i] >> 6) & 3UL) << 2)
  }
  r[124] = (s1[31] & 3UL) ^ ((s2[31] & 3UL) << 2)
  r[125] = ((s1[31] >> 2) & 3UL) ^ (((s2[31] >> 2) & 3UL) << 2)
  r[126] = ((s1[31] >> 4) & 3UL) ^ (((s2[31] >> 4) & 3UL) << 2)
  r
}

///| 检查 s 是否 < L(变长时间,因为 sig 是 public)

///| 对应 C: sc25519_inrange (OpenSSH 加的检查)

///|
/// 返回 true 表示 in range (valid)
pub fn sc_is_in_range(s : Sc) -> Bool {
  for i = 0; i < 32; i = i + 1 {
    if s[31 - i] > sc_l[31 - i] {
      return false
    }
    if s[31 - i] < sc_l[31 - i] {
      return true
    }
  }
  false // 严格 < (s == L 是 invalid)
}

///| 字节级范围检查:s 的原始 LE 字节是否严格小于 L

///| 对应 C: sc25519_inrange(sm+32) —— 必须在 barrett_reduce **之前**对原始字节调用!

///| 如果先做 sc_from32bytes(barrett_reduce),任何输入都会被映射到 [0,L),

///|
/// 范围检查就永远为 true,s >= L 的伪造签名(malleability)会被错误接受。
pub fn sc_is_in_range_bytes(bytes : FixedArray[Byte]) -> Bool {
  if bytes.length() != 32 {
    return false
  }
  for i = 0; i < 32; i = i + 1 {
    let b = bytes[31 - i].to_uint64()
    let l = sc_l[31 - i]
    if b > l {
      return false
    } // s > L → out of range
    if b < l {
      return true
    } // s < L → in range
  }
  false // s == L 精确相等 → invalid
}
