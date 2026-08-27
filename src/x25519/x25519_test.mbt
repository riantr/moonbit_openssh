///| X25519 黑盒测试

///| 跑法:`moon test`

///|
/// 16 进制字符串转 FixedArray[Byte]
fn hex_to_bytes(hex : String) -> FixedArray[Byte] {
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut i = 0
  while i < n {
    arr[i] = parse_byte(hex[i * 2], hex[i * 2 + 1])
    i = i + 1
  }
  arr
}

///|
/// 解析 "ab" 形式的两个 hex char 为 1 byte
fn parse_byte(hi : UInt16, lo : UInt16) -> Byte {
  let h : Int = hex_digit(hi)
  let l : Int = hex_digit(lo)
  ((h * 16 + l).reinterpret_as_uint() & 0xFFU).to_byte()
}

///|
fn hex_digit(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    0
  }
}

///|
test "rfc7748_alice" {
  // RFC 7748 § 5.2 Vector 1 (Alice)
  let scalar = hex_to_bytes(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  )
  let point = hex_to_bytes(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  )
  let expected = hex_to_bytes(
    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
  )
  let actual = x25519(scalar, point)
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "rfc7748_bob" {
  // RFC 7748 § 5.2 Vector 2 (Bob) - 这条 OpenBSD smult_curve25519_ref.c 内部 buggy
  // 但 OpenBSD C 跑 RFC 7748 § 6.1 ECDH 是对的(见 ECDH test)
  // 我们用 Python cryptography 当 golden reference 验证 MoonBit
  let scalar = hex_to_bytes(
    "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
  )
  let point = hex_to_bytes(
    "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
  )
  let expected = hex_to_bytes(
    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
  )
  let actual = x25519(scalar, point)
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "deterministic" {
  let scalar = hex_to_bytes(
    "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
  )
  let point = hex_to_bytes(
    "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
  )
  let a = x25519(scalar, point)
  let b = x25519(scalar, point)
  let mut diff = false
  for i = 0; i < 32; i = i + 1 {
    if a[i] != b[i] {
      diff = true
    }
  }
  assert_eq(diff, false)
}

///|
test "output_is_32_bytes" {
  let scalar : FixedArray[Byte] = FixedArray::make(32, 0x42)
  let point : FixedArray[Byte] = FixedArray::make(32, 0x09)
  let out = x25519(scalar, point)
  assert_eq(out.length(), 32)
}
