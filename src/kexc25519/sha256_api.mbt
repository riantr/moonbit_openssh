// inlined from E:\src\moon\openssh_moonbit\src\sha256\api.mbt (moon 0.1.20260608: no cross-package import)
// content unchanged; provenance tracked in docs/kex_c25519/

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
  // 2. 增量 update
  let buffer : FixedArray[Byte] = FixedArray::make(block_len, b'\x00')
  let (buf2, buf_len, bc) = update(state, buffer, 0, 0UL, message)
  // 3. Pad
  pad(state, buf2, buf_len, bc)
  // 4. 序列化输出
  serialize_state(state)
}
