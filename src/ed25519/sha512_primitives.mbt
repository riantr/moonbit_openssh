///| SHA-512 辅助函数

///| 对应 OpenBSD sha2.c 第 162-182 行 (S64 macros)

///|

///| 关键:所有函数都在 UInt64 域(64-bit)操作,匹配 FIPS 180-4 + OpenBSD

///| 64-bit 循环右移

///|
/// C: S64(b, x) = (x >> b) | (x << (64 - b))
pub fn rotr(n : Int32, x : UInt64) -> UInt64 {
  (x >> n) | (x << (64 - n))
}

///|
/// Ch(x, y, z) = (x & y) ^ (~x & z)
pub fn ch(x : UInt64, y : UInt64, z : UInt64) -> UInt64 {
  (x & y) ^ ((x ^ 0xFFFFFFFFFFFFFFFFUL) & z)
}

///|
/// Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
pub fn maj(x : UInt64, y : UInt64, z : UInt64) -> UInt64 {
  (x & y) ^ (x & z) ^ (y & z)
}

///|
/// Sigma0(x) = ROTR(28, x) ^ ROTR(34, x) ^ ROTR(39, x)
pub fn big_sigma0(x : UInt64) -> UInt64 {
  rotr(28, x) ^ rotr(34, x) ^ rotr(39, x)
}

///|
/// Sigma1(x) = ROTR(14, x) ^ ROTR(18, x) ^ ROTR(41, x)
pub fn big_sigma1(x : UInt64) -> UInt64 {
  rotr(14, x) ^ rotr(18, x) ^ rotr(41, x)
}

///|
/// sigma0(x) = ROTR(1, x) ^ ROTR(8, x) ^ (x >> 7)
pub fn small_sigma0(x : UInt64) -> UInt64 {
  rotr(1, x) ^ rotr(8, x) ^ (x >> 7)
}

///|
/// sigma1(x) = ROTR(19, x) ^ ROTR(61, x) ^ (x >> 6)
pub fn small_sigma1(x : UInt64) -> UInt64 {
  rotr(19, x) ^ rotr(61, x) ^ (x >> 6)
}

///| 从 FixedArray[Byte] 的指定偏移读 8 字节,按 big-endian 解为 UInt64

///|
/// SHA-512 内部用 BE 解析 input block
pub fn be8_to_64(bytes : FixedArray[Byte], offset : Int32) -> UInt64 {
  let b0 = bytes[offset].to_uint64()
  let b1 = bytes[offset + 1].to_uint64()
  let b2 = bytes[offset + 2].to_uint64()
  let b3 = bytes[offset + 3].to_uint64()
  let b4 = bytes[offset + 4].to_uint64()
  let b5 = bytes[offset + 5].to_uint64()
  let b6 = bytes[offset + 6].to_uint64()
  let b7 = bytes[offset + 7].to_uint64()
  (b0 << 56) |
  (b1 << 48) |
  (b2 << 40) |
  (b3 << 32) |
  (b4 << 24) |
  (b5 << 16) |
  (b6 << 8) |
  b7
}

///|
/// 把 UInt64 按 big-endian 写入 FixedArray[Byte] 的指定偏移
pub fn be64_to_8(
  bytes : FixedArray[Byte],
  offset : Int32,
  value : UInt64,
) -> Unit {
  bytes[offset] = ((value >> 56) & 0xFFUL).to_byte()
  bytes[offset + 1] = ((value >> 48) & 0xFFUL).to_byte()
  bytes[offset + 2] = ((value >> 40) & 0xFFUL).to_byte()
  bytes[offset + 3] = ((value >> 32) & 0xFFUL).to_byte()
  bytes[offset + 4] = ((value >> 24) & 0xFFUL).to_byte()
  bytes[offset + 5] = ((value >> 16) & 0xFFUL).to_byte()
  bytes[offset + 6] = ((value >> 8) & 0xFFUL).to_byte()
  bytes[offset + 7] = (value & 0xFFUL).to_byte()
}
