// inlined from E:\src\moon\openssh_moonbit\src\sha256\primitives.mbt (moon 0.1.20260608: no cross-package import)
// content unchanged; provenance tracked in docs/kex_c25519/

///| SHA-256 辅助函数

///| 对应 OpenBSD sha2.c 第 162-182 行

///|

///| 关键:所有函数都在 UInt 域(32-bit)操作,匹配 FIPS 180-4 与 OpenBSD

///| 32-bit 循环右移

///| C: S32(b, x) = (x >> b) | (x << (32 - b))

///|
/// 注意:MoonBit 的 `>>` 在 UInt 域上自动按 32-bit 截断(Loop #2 教训)
pub fn rotr(n : Int, x : UInt) -> UInt {
  (x >> n) | (x << (32 - n))
}

///|
/// Ch(x, y, z) = (x & y) ^ (~x & z)
pub fn ch(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ ((x ^ 0xFFFFFFFFU) & z)
}

///|
/// Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)
pub fn maj(x : UInt, y : UInt, z : UInt) -> UInt {
  (x & y) ^ (x & z) ^ (y & z)
}

///|
/// Sigma0(x) = ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x)
pub fn sigma0_big(x : UInt) -> UInt {
  rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)
}

///|
/// Sigma1(x) = ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x)
pub fn sigma1_big(x : UInt) -> UInt {
  rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)
}

///|
/// sigma0(x) = ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x)
pub fn sigma0_small(x : UInt) -> UInt {
  rotr(7, x) ^ rotr(18, x) ^ (x >> 3)
}

///|
/// sigma1(x) = ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x)
pub fn sigma1_small(x : UInt) -> UInt {
  rotr(17, x) ^ rotr(19, x) ^ (x >> 10)
}

///| 从 FixedArray[Byte] 的指定偏移读 4 字节,按 big-endian 解为 UInt

///|
/// SHA-256 内部用 BE 解析 input block
pub fn be8_to_32(bytes : FixedArray[Byte], offset : Int) -> UInt {
  let b0 = bytes[offset].to_uint()
  let b1 = bytes[offset + 1].to_uint()
  let b2 = bytes[offset + 2].to_uint()
  let b3 = bytes[offset + 3].to_uint()
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
/// 把 UInt 按 big-endian 写入 FixedArray[Byte] 的指定偏移
pub fn be32_to_8(bytes : FixedArray[Byte], offset : Int, value : UInt) -> Unit {
  bytes[offset] = ((value >> 24) & 0xFFU).to_byte()
  bytes[offset + 1] = ((value >> 16) & 0xFFU).to_byte()
  bytes[offset + 2] = ((value >> 8) & 0xFFU).to_byte()
  bytes[offset + 3] = (value & 0xFFU).to_byte()
}
