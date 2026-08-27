///| Poly1305 final 归一化 + 加 s 输出

///| 对应 OpenBSD poly1305.c 125-156 行

///|

///| 关键:constant-time 实现 mod p(用位运算而非 if)

///| 安全:这一段必须保持 constant-time,否则侧信道泄漏 tag 信息

///| 把累加器 h 归一化(每 limb < 2^26),然后 mod p,加 s(来自 key[16..32])

///|
/// 返回 16 字节 tag
pub fn finalize(
  h0 : UInt,
  h1 : UInt,
  h2 : UInt,
  h3 : UInt,
  h4 : UInt,
  s : FixedArray[Byte],
) -> FixedArray[Byte] {
  // 第一轮:carry propagation(让每个 limb < 2^26)
  let mut hh0 : UInt = h0
  let mut hh1 : UInt = h1
  let mut hh2 : UInt = h2
  let mut hh3 : UInt = h3
  let mut hh4 : UInt = h4
  let mut b : UInt = hh0 >> 26
  hh0 = hh0 & 0x3ffffffU
  hh1 = hh1 + b
  b = hh1 >> 26
  hh1 = hh1 & 0x3ffffffU
  hh2 = hh2 + b
  b = hh2 >> 26
  hh2 = hh2 & 0x3ffffffU
  hh3 = hh3 + b
  b = hh3 >> 26
  hh3 = hh3 & 0x3ffffffU
  hh4 = hh4 + b
  b = hh4 >> 26
  hh4 = hh4 & 0x3ffffffU
  hh0 = hh0 + b * 5U
  b = hh0 >> 26
  hh0 = hh0 & 0x3ffffffU
  hh1 = hh1 + b

  // 现在 hh < 2^130 严格(mod p 的归一化完成)
  // 计算 g = hh + 2^130 - 5(注意 OpenBSD 写法是 h + 5 然后 carry 到 limb 4 减 1<<26)
  let mut g0 : UInt = hh0 + 5U
  let mut b2 : UInt = g0 >> 26
  g0 = g0 & 0x3ffffffU
  let mut g1 : UInt = hh1 + b2
  b2 = g1 >> 26
  g1 = g1 & 0x3ffffffU
  let mut g2 : UInt = hh2 + b2
  b2 = g2 >> 26
  g2 = g2 & 0x3ffffffU
  let mut g3 : UInt = hh3 + b2
  b2 = g3 >> 26
  g3 = g3 & 0x3ffffffU
  // g4 = h4 + b - (1 << 26)
  let g4 : UInt = hh4 + b2 - 0x4000000U

  // CONSTANT-TIME 选择:如果 h >= p,选 g(= h - p);否则选 h
  // b = (g4 >> 31) - 1
  //   g4 是 UInt,>> 31 取最高 bit
  //   g4 = h4 + b - 0x4000000 ∈ [-0x4000000, 0x4000001]
  //   g4 >= 0x4000000 时 >>31 = 0, b = -1 = 0xFFFFFFFF
  //   g4 <  0x4000000 时 >>31 = 1, b = 0
  // 我们要 h >= p 时选 g
  //   h >= p => h4 >= 0x4000000 => g4 >= 0 => b = -1 => 选 g  ✓
  let sel : UInt = (g4 >> 31) - 1U
  let nb : UInt = sel ^ 0xFFFFFFFFU // ~sel(UInt 取反 = XOR 0xFFFFFFFF)
  let f0_limb : UInt = (hh0 & nb) | (g0 & sel)
  let f1_limb : UInt = (hh1 & nb) | (g1 & sel)
  let f2_limb : UInt = (hh2 & nb) | (g2 & sel)
  let f3_limb : UInt = (hh3 & nb) | (g3 & sel)
  let f4_limb : UInt = (hh4 & nb) | (g4 & sel)

  // 重组:f[k] = (f[k] | (f[k+1] << 26))  (调整 shift)
  // 实际 OpenBSD:
  //   f0 = (h0 | (h1 << 26)) + s[0..4]
  //   f1 = (h1 >> 6 | (h2 << 20)) + s[4..8]
  //   f2 = (h2 >> 12 | (h3 << 14)) + s[8..12]
  //   f3 = (h3 >> 18 | (h4 << 8)) + s[12..16]
  // 然后 carry propagation
  let s0 : UInt64 = u8_to_32_le(s, 0).to_uint64()
  let s1u : UInt64 = u8_to_32_le(s, 4).to_uint64()
  let s2u : UInt64 = u8_to_32_le(s, 8).to_uint64()
  let s3u : UInt64 = u8_to_32_le(s, 12).to_uint64()

  // 关键:移位要在 UInt 域内做(模拟 C 的 uint32_t shift,截断高位)
  // 然后 promote 到 UInt64 跟 s 相加
  // 这样 f0_limb 之外的 f1_limb 位会自然丢失(进位到下一个 f_k)
  let f0 : UInt64 = (f0_limb | (f1_limb << 26)).to_uint64() + s0
  let f1 : UInt64 = ((f1_limb >> 6) | (f2_limb << 20)).to_uint64() +
    s1u +
    (f0 >> 32)
  let f2 : UInt64 = ((f2_limb >> 12) | (f3_limb << 14)).to_uint64() +
    s2u +
    (f1 >> 32)
  let f3 : UInt64 = ((f3_limb >> 18) | (f4_limb << 8)).to_uint64() +
    s3u +
    (f2 >> 32)

  let out : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  put_u32_le(out, 0, (f0 & 0xFFFFFFFFUL).to_uint())
  put_u32_le(out, 4, (f1 & 0xFFFFFFFFUL).to_uint())
  put_u32_le(out, 8, (f2 & 0xFFFFFFFFUL).to_uint())
  put_u32_le(out, 12, (f3 & 0xFFFFFFFFUL).to_uint())
  out
}

///|
/// 把 UInt 按 little-endian 写入 FixedArray[Byte] 的指定偏移
fn put_u32_le(bytes : FixedArray[Byte], offset : Int, value : UInt) -> Unit {
  bytes[offset] = ((value >> 0) & 0xFFU).to_byte()
  bytes[offset + 1] = ((value >> 8) & 0xFFU).to_byte()
  bytes[offset + 2] = ((value >> 16) & 0xFFU).to_byte()
  bytes[offset + 3] = ((value >> 24) & 0xFFU).to_byte()
}
