// inlined from E:\src\moon\openssh_moonbit\src\x25519\api.mbt (moon 0.1.20260608: no cross-package import)
// content unchanged; provenance tracked in docs/kex_c25519/

///| X25519 公开 API

///| 对应 RFC 7748 § 5 + OpenBSD smult_curve25519_ref.c

///| X25519(scalar, point) -> 32 字节 shared secret

///| scalar: 32 字节(API 会自动 clamp per RFC 7748 § 5)

///|
/// point: 32 字节(API 会自动清高位 bit per RFC 7748 § 5)
pub fn x25519(
  scalar : FixedArray[Byte],
  point : FixedArray[Byte],
) -> FixedArray[Byte] {
  if scalar.length() != scalar_len || point.length() != ge_len {
    abort("x25519: scalar and point must be 32 bytes each")
  }

  // 1. 准备 scalar e[32](clamp per RFC 7748 § 5)
  let e : FixedArray[UInt] = FixedArray::make(32, 0U)
  for i = 0; i < 32; i = i + 1 {
    e[i] = scalar[i].to_uint()
  }
  e[0] = e[0] & 248U // 清低 3 bit
  e[31] = e[31] & 127U // 清最高 bit
  e[31] = e[31] | 64U // 置 bit 6

  // 2. 准备 work[64] = (P_x, P_z=1)
  let work : FixedArray[UInt] = FixedArray::make(64, 0U)
  for i = 0; i < 32; i = i + 1 {
    work[i] = point[i].to_uint()
  }
  // RFC 7748 § 5: clear high bit of point
  work[31] = work[31] & 127U

  // 3. Montgomery ladder
  mainloop(work, e)

  // 4. recip: z^(-1) mod p → work[32..64]
  recip_from(work, 32)

  // 5. mult: x * z^(-1) → work[64..96]
  let result : FixedArray[UInt] = FixedArray::make(32, 0U)
  fe_mult(result, work, slice_at(work, 32))

  // 6. freeze: mod p 归约
  freeze(result)

  // 7. 序列化为 32 字节
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = (result[i] & 0xFFU).to_byte()
  }
  out
}

///|
/// recip 但带偏移(输入输出在 work[offset..offset+32))
fn recip_from(work : FixedArray[UInt], offset : Int) -> Unit {
  let z : FixedArray[UInt] = FixedArray::make(32, 0U)
  for j = 0; j < 32; j = j + 1 {
    z[j] = work[offset + j]
  }
  let out : FixedArray[UInt] = FixedArray::make(32, 0U)
  recip(out, z)
  for j = 0; j < 32; j = j + 1 {
    work[offset + j] = out[j]
  }
}

///|
/// 辅助:复制 FixedArray[UInt] 一段
fn slice_at(src : FixedArray[UInt], offset : Int) -> FixedArray[UInt] {
  let dst : FixedArray[UInt] = FixedArray::make(32, 0U)
  for j = 0; j < 32; j = j + 1 {
    dst[j] = src[offset + j]
  }
  dst
}
