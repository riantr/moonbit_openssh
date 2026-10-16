///| Poly1305 clamp 函数 —— 将 128-bit key 转为 5 个 26-bit limb

///| 对应 OpenBSD poly1305.c 44-60 行

///|

///| 关键:clamp 清掉 r 的特定 bit,保证 r 在 mod 2^130 - 5 上可逆

///| 安全:这是公开算法,clamp 模式固定

///| 把 32 字节 key 拆成 5 个 26-bit limb(r0..r4),并预计算 s1..s4 = ri * 5

///|
/// 返回:(r0, r1, r2, r3, r4, s1, s2, s3, s4) — 共 9 个 u32
pub fn clamp_key(
  key : FixedArray[Byte],
) -> (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32) {
  if key.length() != key_len {
    abort("poly1305 clamp_key: key must be 32 bytes")
  }
  // 把 16 字节 key 拆为 4 个 u32
  let t0 : UInt32 = u8_to_32_le(key, 0)
  let t1 : UInt32 = u8_to_32_le(key, 4)
  let t2 : UInt32 = u8_to_32_le(key, 8)
  let t3 : UInt32 = u8_to_32_le(key, 12)

  // 按 OpenBSD poly1305.c 的位运算切出 5 个 26-bit limb
  // 注:t0,t1 在 mask 提取 limb 前先 "shift" 一下,使得切出的 limb 是连续的 26-bit 段
  let r0 : UInt32 = t0 & 0x3ffffffU
  let t0_shifted : UInt32 = (t0 >> 26) | (t1 << 6)
  let r1 : UInt32 = t0_shifted & 0x3ffff03U
  let t1_shifted : UInt32 = (t1 >> 20) | (t2 << 12)
  let r2 : UInt32 = t1_shifted & 0x3ffc0ffU
  let t2_shifted : UInt32 = (t2 >> 14) | (t3 << 18)
  let r3 : UInt32 = t2_shifted & 0x3f03fffU
  let r4 : UInt32 = (t3 >> 8) & 0x00fffffU

  // s_i = r_i * 5 (32-bit,可能溢出但 wrap-around 跟 C 一致)
  let s1 : UInt32 = r1 * 5U
  let s2 : UInt32 = r2 * 5U
  let s3 : UInt32 = r3 * 5U
  let s4 : UInt32 = r4 * 5U

  (r0, r1, r2, r3, r4, s1, s2, s3, s4)
}

///|
/// 从 FixedArray[Byte] 的指定偏移读 4 字节,按 little-endian 解为 UInt
fn u8_to_32_le(bytes : FixedArray[Byte], offset : Int32) -> UInt32 {
  let b0 = bytes[offset].to_uint()
  let b1 = bytes[offset + 1].to_uint()
  let b2 = bytes[offset + 2].to_uint()
  let b3 = bytes[offset + 3].to_uint()
  b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}
