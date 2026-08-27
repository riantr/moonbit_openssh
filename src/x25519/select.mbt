///| X25519 constant-time conditional swap

///| 对应 OpenBSD smult_curve25519_ref.c 第 110-122 行

///|

///| select(p, q, r, s, b):

///|   若 b=1: p=s, q=r

///|   若 b=0: p=r, q=s

///| 完全位运算,无分支,constant-time

///|

///| 算法 (bit-trick):

///|   bminus1 = b - 1 (mod 2^32,wrap-around)

///|   当 b=0: bminus1 = 0xFFFFFFFF

///|   当 b=1: bminus1 = 0

///|   t = bminus1 & (r[j] ^ s[j])

///|   p[j] = s[j] ^ t  → 当 b=0 (mask=0xFF) t = r[j]^s[j], p = r;  当 b=1 (mask=0) p = s

///|   q[j] = r[j] ^ t  → 当 b=0 q = s;  当 b=1 q = r

///| 计算 b - 1(模 2^32,wrap-around 自动处理)

///| b=0 → 0xFFFFFFFF; b=1 → 0

///|
/// 直接 b - 1:UInt 减法自然 wrap,b=0 时 wrap 到 0xFFFFFFFF
fn bminus1(b : UInt) -> UInt {
  b - 1U
}

///| select(p, q, r, s, b)

///|
/// p, q, r, s 长度必须都是 64(group element + z)
pub fn fe_select(
  p : FixedArray[UInt],
  q : FixedArray[UInt],
  r : FixedArray[UInt],
  s : FixedArray[UInt],
  b : UInt,
) -> Unit {
  let bm : UInt = bminus1(b)
  for j = 0; j < 64; j = j + 1 {
    let t : UInt = bm & (r[j] ^ s[j])
    p[j] = s[j] ^ t
    q[j] = r[j] ^ t
  }
}
