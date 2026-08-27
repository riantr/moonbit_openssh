///| SHA-512 final - 输出 64 字节大端 hash

///| 对应 OpenBSD sha2.c SHA512Final

///|
/// 把 8 个 state u64 按大端序列化到 64 字节 output
pub fn serialize_state(state : FixedArray[UInt64]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(hash_len, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    be64_to_8(out, i * 8, state[i])
  }
  out
}
