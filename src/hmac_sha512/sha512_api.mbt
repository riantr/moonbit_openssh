///| SHA-512 公开 API

///|

///| sha512(message) -> 64 字节 hash

///| 符合 FIPS 180-4 § 4 + RFC 6234

///|
/// 计算 message 的 SHA-512 哈希
pub fn sha512(message : FixedArray[Byte]) -> FixedArray[Byte] {
  // 1. 初始化 state 为 init_h
  let state : FixedArray[UInt64] = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    state[i] = init_h[i]
  }
  // 2. 增量 update
  let buffer : FixedArray[Byte] = FixedArray::make(block_len, b'\x00')
  let (buf2, buf_len, bc) = update(state, buffer, 0, 0UL, message)
  // 3. Pad
  pad(state, buf2, buf_len, bc)
  // 4. 序列化输出
  serialize_state(state)
}
