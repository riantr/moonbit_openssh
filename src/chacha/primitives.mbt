///| ChaCha20 primitives — 最底层的纯算术算子

///| 本文件所有函数都应该是"纯函数",无副作用,易于 moon prove 形式化验证

///|

///| 关键不变量(供 Architect/Reviewer 验证):

///|   - UInt 算术在 MoonBit 中是模 2^32,与 C `u32` 回绕语义一致

///|   - rotl32 是对合(rotl32(rotl32(x, n), 32 - n) == x)

///|   - quarterround 是对合(qr(qr(a,b,c,d)) == (a,b,c,d))

///|   - quarterround 保持字和:(a+b+c+d) mod 2^32 不变

///| 32-bit 循环左移

///| 对应 C: `ROTL32(v, n) = (v << n) | (v >> (32 - n))`

///|

///| 性质:rotl32(rotl32(x, n), 32 - n) == x  (对合)

///|       rotl32(x, 0) == x

///|
///       rotl32(0, n) == 0
pub fn rotl32(x : UInt32, n : Int32) -> UInt32 {
  // 规范 n 在 0..32 范围
  let n_norm = n % 32
  if n_norm == 0 {
    x
  } else {
    (x << n_norm) | (x >> (32 - n_norm))
  }
}

///| ChaCha20 quarterround —— 算法核心

///| 对应 C 宏:

///|   QUARTERROUND(a,b,c,d):

///|     a += b; d ^= a; d <<<= 16

///|     c += d; b ^= c; b <<<= 12

///|     a += b; d ^= a; d <<<=  8

///|     c += d; b ^= c; b <<<=  7

///|

///| 返回: (a', b', c', d')

///|

///| 性质:

///|   - 对合:quarterround ∘ quarterround == id(量子位逐个反演)

///|   - 能量守恒:(a' + b' + c' + d') mod 2^32 == (a + b + c + d) mod 2^32

///|     (因为 step 1 的 a+=b 和 step 4 的 a+=b' 是 b,b' 的累加,加上 step 3 的 c+=d

///|      和 step 7 的 c+=d',d,d' 是原值,总守恒;但 step 6 涉及 a 的累加所以严格

///|
///      说是 word_sum 不变)
pub fn quarterround(
  a : UInt32,
  b : UInt32,
  c : UInt32,
  d : UInt32,
) -> (UInt32, UInt32, UInt32, UInt32) {
  let a1 = a + b // a += b
  let d1 = rotl32(d ^ a1, 16) // d = rotl(d ^ a, 16)
  let c1 = c + d1 // c += d
  let b1 = rotl32(b ^ c1, 12) // b = rotl(b ^ c, 12)
  let a2 = a1 + b1 // a += b
  let d2 = rotl32(d1 ^ a2, 8) // d = rotl(d ^ a, 8)
  let c2 = c1 + d2 // c += d
  let b2 = rotl32(b1 ^ c2, 7) // b = rotl(b ^ c, 7)
  (a2, b2, c2, d2)
}

///| 从 FixedArray[Byte] 的指定偏移读 4 字节,按 little-endian 解为 UInt

///|
/// 对应 C 宏: `U8TO32_LITTLE(p)`
pub fn u8_to_32_le(bytes : FixedArray[Byte], offset : Int32) -> UInt32 {
  // 字节序:byte[offset] 是低字节
  let b0 = bytes[offset].to_uint()
  let b1 = bytes[offset + 1].to_uint()
  let b2 = bytes[offset + 2].to_uint()
  let b3 = bytes[offset + 3].to_uint()
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

///| 将 UInt 按 little-endian 写入 FixedArray[Byte] 的指定偏移

///|
/// 对应 C 宏: `U32TO8_LITTLE(p, v)`
pub fn u32_to_8_le(
  bytes : FixedArray[Byte],
  offset : Int32,
  value : UInt32,
) -> Unit {
  bytes[offset] = ((value >> 0) & 0xFFU).to_byte()
  bytes[offset + 1] = ((value >> 8) & 0xFFU).to_byte()
  bytes[offset + 2] = ((value >> 16) & 0xFFU).to_byte()
  bytes[offset + 3] = ((value >> 24) & 0xFFU).to_byte()
}
