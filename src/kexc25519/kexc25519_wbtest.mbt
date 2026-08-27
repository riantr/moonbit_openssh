///| KEX c25519 白盒测试(可访问包内私有函数)

///| 期望值由 verify_c/kex_c25519_python_ref.py 生成

///|
/// 严格 16 进制字符串转 FixedArray[Byte](非法字符 abort)
fn hex_to_bytes(hex : String) -> FixedArray[Byte] {
  if hex.length() % 2 != 0 {
    abort("hex_to_bytes: odd length")
  }
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hx(hex[i * 2])
    let lo = hx(hex[i * 2 + 1])
    arr[i] = ((hi * 16 + lo).reinterpret_as_uint() & 0xFFU).to_byte()
  }
  arr
}

///|
fn hx(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("hx: invalid character")
  }
}

///|
fn assert_eq_bytes(
  actual : FixedArray[Byte],
  expected : FixedArray[Byte],
  label : String,
) -> Unit {
  if actual.length() != expected.length() {
    abort("\{label}: length \{actual.length()} != \{expected.length()}")
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if actual[i] != expected[i] {
      abort("\{label}: byte \{i} mismatch")
    }
  }
}

///|
test "put_u32_layout" {
  let buf = KxBuf::new()
  buf.put_u32(0x01020304U)
  assert_eq_bytes(buf.to_bytes(), hex_to_bytes("01020304"), "put_u32")
}

///|
test "put_string_layout" {
  let buf = KxBuf::new()
  buf.put_string(hex_to_bytes("deadbeef"))
  assert_eq_bytes(
    buf.to_bytes(),
    hex_to_bytes("00000004deadbeef"),
    "put_string",
  )
}

///|
test "mpint_no_prepend_branch" {
  // RFC 7748 §6.1 共享密钥首字节 0x4a 高位为 0 → 无前置零
  let ss = hex_to_bytes(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  assert_eq_bytes(
    kx_mpint(ss),
    hex_to_bytes(
      "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ),
    "mpint no-prepend",
  )
}

///|
test "mpint_prepend_branch" {
  // 首字节 0xb7 高位为 1 → 前置 0x00,len 变 0x21
  let ss = hex_to_bytes(
    "b7157392fe559875efb25f56dc0258aa44e6cfa47be51df654884d61281c7815",
  )
  assert_eq_bytes(
    kx_mpint(ss),
    hex_to_bytes(
      "0000002100b7157392fe559875efb25f56dc0258aa44e6cfa47be51df654884d61281c7815",
    ),
    "mpint prepend",
  )
}

///|
test "mpint_all_zero_and_empty" {
  // 全零 → 仅 u32(0)(C: 跳过所有前导零后 len==0)
  let zeros : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  assert_eq_bytes(kx_mpint(zeros), hex_to_bytes("00000000"), "mpint zeros")
  let empty : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  assert_eq_bytes(kx_mpint(empty), hex_to_bytes("00000000"), "mpint empty")
}

///|
test "mpint_strips_leading_zeros" {
  // 前导零被折叠:00 00 80 xx → 有效首字节 0x80 高位为 1 → 还要前置 0x00
  let v = hex_to_bytes("00008011")
  assert_eq_bytes(kx_mpint(v), hex_to_bytes("00000003008011"), "mpint strip")
}

///|
test "exchange_input_fake_header_length" {
  // fake header 的 u32 是 |kexinit|+1(覆盖 type 字节)——off-by-one 高危点
  let inputs : ExchangeInputs = {
    client_version: hex_to_bytes("5353482d322e30"),
    server_version: hex_to_bytes("5353482d322e30"),
    client_kexinit: hex_to_bytes("aabbccdd"),
    server_kexinit: hex_to_bytes("1122"),
  }
  let wire = build_exchange_input(
    inputs,
    hex_to_bytes("beef"),
    hex_to_bytes("01"),
    hex_to_bytes("02"),
    hex_to_bytes("0000000000"),
  )
  // 手工拼完整期望:string(vc) ‖ string(vs) ‖ [len+1,type,ic] ‖ [同] ‖ string(KS) ‖ string(e) ‖ string(f) ‖ mpint
  let expect = hex_to_bytes(
    "000000075353482d322e30000000075353482d322e30" +
    "0000000514aabbccdd" +
    "00000003141122" +
    "00000002beef" +
    "00000001010000000102" +
    "0000000000",
  )
  assert_eq_bytes(wire, expect, "exchange_input layout")
}
