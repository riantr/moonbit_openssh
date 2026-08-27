// inlined from E:\src\moon\openssh_moonbit\src\sha256\final.mbt (moon 0.1.20260608: no cross-package import)
// content unchanged; provenance tracked in docs/kex_c25519/

///| SHA-256 final - 输出 32 字节大端 hash

///| 对应 OpenBSD sha2.c SHA256Final

///|
/// 把 8 个 state u32 按大端序列化到 32 字节 output
pub fn serialize_state(state : FixedArray[UInt]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(hash_len, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    be32_to_8(out, i * 4, state[i])
  }
  out
}
