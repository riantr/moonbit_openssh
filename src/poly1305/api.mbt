///| Poly1305 公开 API

///|

///| poly1305_auth(key, message) -> 16 字节 authentication tag

///| 符合 RFC 8439 § 2.5

///| 公开 API:计算 message 在 key 下的 Poly1305 MAC

///|

///| 输入:

///|   key:32 字节(前 16 字节 → clamped r,后 16 字节 → 加性 s)

///|   message:任意长度字节序列

///|
/// 输出:16 字节 tag
pub fn poly1305_auth(
  key : FixedArray[Byte],
  message : FixedArray[Byte],
) -> FixedArray[Byte] {
  if key.length() != key_len {
    abort("poly1305_auth: key must be 32 bytes")
  }

  // 1. Clamp key
  let (r0, r1, r2, r3, r4, s1, s2, s3, s4) = clamp_key(key)

  // 2. 累加器初始化为 0
  let mut h0 : UInt = 0U
  let mut h1 : UInt = 0U
  let mut h2 : UInt = 0U
  let mut h3 : UInt = 0U
  let mut h4 : UInt = 0U

  // 3. 处理完整 16 字节 block
  let mut offset : Int = 0
  while message.length() - offset >= 16 {
    let block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for i = 0; i < 16; i = i + 1 {
      block[i] = message[offset + i]
    }
    let (nh0, nh1, nh2, nh3, nh4) = add_block(h0, h1, h2, h3, h4, block, false)
    h0 = nh0
    h1 = nh1
    h2 = nh2
    h3 = nh3
    h4 = nh4
    let (mh0, mh1, mh2, mh3, mh4) = mul_mod(
      h0, h1, h2, h3, h4, r0, r1, r2, r3, r4, s1, s2, s3, s4,
    )
    h0 = mh0
    h1 = mh1
    h2 = mh2
    h3 = mh3
    h4 = mh4
    offset = offset + 16
  }

  // 4. 处理末尾部分 block(若有)
  let remaining : Int = message.length() - offset
  if remaining > 0 {
    let last_block : FixedArray[Byte] = FixedArray::make(remaining, b'\x00')
    for i = 0; i < remaining; i = i + 1 {
      last_block[i] = message[offset + i]
    }
    let (nh0, nh1, nh2, nh3, nh4) = add_block(
      h0, h1, h2, h3, h4, last_block, true,
    )
    h0 = nh0
    h1 = nh1
    h2 = nh2
    h3 = nh3
    h4 = nh4
    let (mh0, mh1, mh2, mh3, mh4) = mul_mod(
      h0, h1, h2, h3, h4, r0, r1, r2, r3, r4, s1, s2, s3, s4,
    )
    h0 = mh0
    h1 = mh1
    h2 = mh2
    h3 = mh3
    h4 = mh4
  }

  // 5. Final 归一化 + 加 s
  let s : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    s[i] = key[16 + i]
  }
  finalize(h0, h1, h2, h3, h4, s)
}
