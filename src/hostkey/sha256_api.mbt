///| SHA-256 公开 API

///|

///| sha256(message) -> 32 字节 hash

///| 符合 FIPS 180-4 § 6.2

///|
/// 计算 message 的 SHA-256 哈希
pub fn sha256(message : FixedArray[Byte]) -> FixedArray[Byte] {
  // 1. 初始化 state 为 init_H
  let state : FixedArray[UInt] = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state[i] = init_H[i]
  }
  // 2. 增量 s256_update
  let buffer : FixedArray[Byte] = FixedArray::make(s256_block_len, b'\x00')
  let (buf2, buf_len, bc) = s256_update(state, buffer, 0, 0UL, message)
  // 3. Pad
  s256_pad(state, buf2, buf_len, bc)
  // 4. 序列化输出
  s256_serialize_state(state)
}
