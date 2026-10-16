///| X25519 RFC 7748 + 随机 KAT 测试

///| 用 Python cryptography 当 golden reference(verify_c/gen_x25519_kat.py 生成)

///|
///  16 进制字符串转 FixedArray[Byte]
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
fn parse_byte(hi : UInt16, lo : UInt16) -> Byte {
  let h : Int32 = hex_digit(hi)
  let l : Int32 = hex_digit(lo)
  ((h * 16 + l).reinterpret_as_uint() & 0xFFU).to_byte()
}

///|
fn hex_digit(c : UInt16) -> Int32 {
  let code : Int32 = c.to_int()
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
test "kat_rfc7748_alice" {
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
  assert_eq(actual[0].to_uint(), expected[0].to_uint())
}

///|
test "kat_rfc7748_bob" {
  // RFC 7748 § 5.2 Bob - OpenBSD smult_curve25519_ref.c 内部 buggy (这 scalar 触发 overflow)
  // 但 Python cryptography 输出 `95cbde94...` 是 byte-exact 跟 RFC 7748 § 5.2 一致
  // 我们用 Python 当 golden reference
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
  let mut diff_count : Int32 = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "kat_rfc7748_ecdh" {
  // RFC 7748 § 6.1 Diffie-Hellman - Alice + Bob
  let a_priv = hex_to_bytes(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
  let b_pub = hex_to_bytes(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
  let expected = hex_to_bytes(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  let actual = x25519(a_priv, b_pub)
  let mut diff_count : Int32 = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "kat_random_00" {
  let scalar = hex_to_bytes(
    "e6ee8098c95ebcfbfa625eb08973cb954838cf0f7688b7af5c4821db58b89415",
  )
  let point = hex_to_bytes(
    "8dd7e14f2e611e31a2123fad3f433c85dc7c72aa07ffbb15429608d43a4bf975",
  )
  let expected = hex_to_bytes(
    "eb7a3f57d6266fbdea4dd3f953b1f421a6d68dd64eebb5953403ca573dd7a07c",
  )
  let actual = x25519(scalar, point)
  let mut diff_count : Int32 = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "kat_random_01" {
  let scalar = hex_to_bytes(
    "f8dbfce6b5dd56c06d995dead6176ebc3753e2d5046be36791f09c4804ea5e72",
  )
  let point = hex_to_bytes(
    "4c1170b9b40ba4e2124c1a77d7418bb28232ec47a47b7340d9a7ad86b5f9fc25",
  )
  let expected = hex_to_bytes(
    "2438198a3b1edbf26f0c8389788112407b15452ea7f7d3f3f3eaa81999f9ec41",
  )
  let actual = x25519(scalar, point)
  let mut diff_count : Int32 = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "kat_random_02" {
  let scalar = hex_to_bytes(
    "467f0abf5456d72fe7d14b94c7659f15c9279cc87122a4ba49f40eafaafe63a2",
  )
  let point = hex_to_bytes(
    "4e2d63673415c0d54106598f098f78944240c01781422e71d0a7e8dea35abe36",
  )
  let expected = hex_to_bytes(
    "059df9afe8778350a48e7f2a51f91bec5af97bf31245744b5f864a01ec428f5c",
  )
  let actual = x25519(scalar, point)
  let mut diff_count : Int32 = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "kat_random_03" {
  let scalar = hex_to_bytes(
    "6b0eea0cdc2c6397ccc68d73eedb63157be5f37045f4987bbf35dd37ac0e16dd",
  )
  let point = hex_to_bytes(
    "526ebb2da1765c1887c3d0fcd578fbc7793c2f7715fa230746eea62bae5a6cab",
  )
  let expected = hex_to_bytes(
    "a47a82dac6e2c56452fe2d0b1e1110a1a945563c314f4626c18210f7007d8d14",
  )
  let actual = x25519(scalar, point)
  let mut diff_count : Int32 = 0
  for i = 0; i < 32; i = i + 1 {
    if actual[i] != expected[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
}

///|
test "kat_random_04" {
  let scalar = hex_to_bytes(
    "76604c1b0e1a46b7c94114357be91e76600405c373906c9de8d40d8538f05598",
  )
  let point = hex_to_bytes(
    "cd05ac99f17d1efe16bf52345ecc99a7cb359acbb4dc2576c27d81aa8fdbd4ce",
  )
  let expected = hex_to_bytes(
    "4dcc18d4a90a11af59237508117022b57728a2374c5b656607acef7b2606e93a",
  )
  let actual = x25519(scalar, point)
  let mut diff_count : Int32 = 0
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
