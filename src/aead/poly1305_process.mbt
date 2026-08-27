///| Poly1305 单 block 处理:把 16 字节 message 装入 5 个 limb

///| 对应 OpenBSD poly1305.c 70-101 行

///|

///| 数学:把 128-bit block 视作 130-bit 整数(末位填 0x01 在 bit 128)

///| h = (h + block) mod 2^130,然后 mul_mod

///| 把 16 字节 block 装入 5 个 limb 并加到 h(0..4)

///| is_last=true 时若是部分 block(< 16 字节),前面字节填充,末尾加 0x01 pad

///|

///|
/// 返回:加 block 后的新 h
pub fn add_block(
  h0 : UInt,
  h1 : UInt,
  h2 : UInt,
  h3 : UInt,
  h4 : UInt,
  block : FixedArray[Byte],
  is_last : Bool,
) -> (UInt, UInt, UInt, UInt, UInt) {
  // 把 16 字节读为 4 个 u32(若是部分 block,需先 pad)
  // 完整 block:is_last=false 或 block.length() == 16
  // 部分 block:block.length() < 16,is_last 必须 = true
  let (t0, t1, t2, t3, set_high_bit) = if is_last && block.length() < 16 {
    // 部分 block:填充 0x01 + 0x00
    let mp : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    let mut j = 0
    while j < block.length() {
      mp[j] = block[j]
      j = j + 1
    }
    mp[j] = b'\x01' // 0x01 pad
    (
      u8_to_32_le(mp, 0),
      u8_to_32_le(mp, 4),
      u8_to_32_le(mp, 8),
      u8_to_32_le(mp, 12),
      false,
    )
  } else {
    // 完整 16 字节 block
    (
      u8_to_32_le(block, 0),
      u8_to_32_le(block, 4),
      u8_to_32_le(block, 8),
      u8_to_32_le(block, 12),
      true,
    )
  }

  // 把 128-bit m 拆为 5 个 26-bit limb 加到 h
  // h0 = m & 0x3ffffff  =  t0 & 0x3ffffff
  // h1 = (m >> 26) & 0x3ffffff
  // h2 = (m >> 52) & 0x3ffffff
  // h3 = (m >> 78) & 0x3ffffff
  // h4 = m >> 104
  let new_h0 : UInt = h0 + (t0 & 0x3ffffffU)
  let m_low_64 : UInt64 = (t1.to_uint64() << 32) | t0.to_uint64()
  let new_h1 : UInt = h1 + ((m_low_64 >> 26) & 0x3ffffffUL).to_uint()
  let m_mid_64 : UInt64 = (t2.to_uint64() << 32) | t1.to_uint64()
  let new_h2 : UInt = h2 + ((m_mid_64 >> 20) & 0x3ffffffUL).to_uint()
  let m_high_64 : UInt64 = (t3.to_uint64() << 32) | t2.to_uint64()
  let new_h3 : UInt = h3 + ((m_high_64 >> 14) & 0x3ffffffUL).to_uint()
  let mut new_h4 : UInt = h4 + (t3 >> 8)
  if set_high_bit {
    new_h4 = new_h4 + 0x1000000U // 1 << 24
  }

  (new_h0, new_h1, new_h2, new_h3, new_h4)
}
