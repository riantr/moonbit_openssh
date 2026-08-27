///| 交换哈希(对应 kexgen.c:48 kex_gen_hash,curve25519-sha256 用 SHA-256)

///|

///| 输入布局(kexgen.c:67-82,字段序严格):

///|   string(V_C) ‖ string(V_S)

///|   u32(|I_C|+1) ‖ u8(20) ‖ I_C      ← fake header:len 覆盖类型字节

///|   u32(|I_S|+1) ‖ u8(20) ‖ I_S

///|   string(K_S) ‖ string(e) ‖ string(f)

///|   K(mpint 编码全文原样追加,C: sshbuf_putb)

///| → SHA-256

///|
/// SSH2_MSG_KEXINIT = 20(ssh2.h)
const KX_MSG_KEXINIT : UInt = 20U

///| 版本串与 kexinit payload。

///| 注意 client/server_kexinit 对应 C 的 kex->my / kex->peer:

///|
/// 是 **类型字节之后** 的 kexinit 内容(fake header 会补回 len+type)。
pub struct ExchangeInputs {
  client_version : FixedArray[Byte] // V_C
  server_version : FixedArray[Byte] // V_S
  client_kexinit : FixedArray[Byte] // I_C(type 字节后)
  server_kexinit : FixedArray[Byte] // I_S(type 字节后)
}

///|
/// 公开构造器(跨包字面量构造 readonly struct 受限)
pub fn ExchangeInputs::make(
  client_version : FixedArray[Byte],
  server_version : FixedArray[Byte],
  client_kexinit : FixedArray[Byte],
  server_kexinit : FixedArray[Byte],
) -> ExchangeInputs {
  { client_version, server_version, client_kexinit, server_kexinit }
}

///|
/// 构造哈希输入缓冲(独立导出供白盒逐字节验证)
pub fn build_exchange_input(
  inputs : ExchangeInputs,
  hostkey_blob : FixedArray[Byte],
  client_pub : FixedArray[Byte],
  server_pub : FixedArray[Byte],
  shared_secret_mpint : FixedArray[Byte],
) -> FixedArray[Byte] {
  let b = KxBuf::new()
  b.put_string(inputs.client_version)
  b.put_string(inputs.server_version)
  // fake header:u32 长度含 type 字节本身(+1),再补 type=SSH2_MSG_KEXINIT
  b.put_u32(inputs.client_kexinit.length().reinterpret_as_uint() + 1U)
  b.put_u8(KX_MSG_KEXINIT)
  b.put_bytes(inputs.client_kexinit)
  b.put_u32(inputs.server_kexinit.length().reinterpret_as_uint() + 1U)
  b.put_u8(KX_MSG_KEXINIT)
  b.put_bytes(inputs.server_kexinit)
  b.put_string(hostkey_blob)
  b.put_string(client_pub)
  b.put_string(server_pub)
  // C: sshbuf_putb(b, shared_secret)——已编码 mpint 全文原样追加,不再包装
  b.put_bytes(shared_secret_mpint)
  b.to_bytes()
}

///|
/// 交换哈希 H = SHA-256(exchange input)
pub fn kex_gen_hash(
  inputs : ExchangeInputs,
  hostkey_blob : FixedArray[Byte],
  client_pub : FixedArray[Byte],
  server_pub : FixedArray[Byte],
  shared_secret_mpint : FixedArray[Byte],
) -> FixedArray[Byte] {
  sha256(
    build_exchange_input(
      inputs, hostkey_blob, client_pub, server_pub, shared_secret_mpint,
    ),
  )
}
