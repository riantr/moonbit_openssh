///| Ed25519 RFC 8032 KAT 内部测试 + 内部函数验证

///| 跑法:`moon test`

///|

///| 主要验证:用 Python `cryptography` 库或 OpenSSL 生成的 KAT 当 golden reference。

///| 这里复用 3 个 OpenSSH 自带的 KAT(RFC 8032 Tests 1, 2, 3)。

///|

///| 这些是 wbtest:可以访问内部函数,确保 byte-exact 匹配。

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

///| RFC 8032 § 7.1 Test 1: empty msg

///| seed = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60

///| expected pk = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a

///|
/// expected sig = e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
test "kat_rfc8032_test1" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let expected_pk = hex_to_bytes(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let expected_sig = hex_to_bytes(
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
  )
  let msg : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let (pk, sk) = keypair_from_seed(seed)
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if pk[i] != expected_pk[i] {
      diff_count = diff_count + 1
    }
  }
  let sig = sign(msg, sk)
  for i = 0; i < 64; i = i + 1 {
    if sig[i] != expected_sig[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  assert_eq(verify(sig, msg, pk), true)
}

///| RFC 8032 § 7.1 Test 2: 1-byte msg "72"

///| seed = 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb

///| expected pk = 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c

///|
/// expected sig = 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
test "kat_rfc8032_test2" {
  let seed = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let expected_pk = hex_to_bytes(
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
  )
  let expected_sig = hex_to_bytes(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
  )
  let msg = hex_to_bytes("72")
  let (pk, sk) = keypair_from_seed(seed)
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if pk[i] != expected_pk[i] {
      diff_count = diff_count + 1
    }
  }
  let sig = sign(msg, sk)
  for i = 0; i < 64; i = i + 1 {
    if sig[i] != expected_sig[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  assert_eq(verify(sig, msg, pk), true)
}

///| RFC 8032 § 7.1 Test 3: 2-byte msg "af82"

///| seed = c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7

///| expected pk = fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025

///|
/// expected sig = 6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a
test "kat_rfc8032_test3" {
  let seed = hex_to_bytes(
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
  )
  let expected_pk = hex_to_bytes(
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
  )
  let expected_sig = hex_to_bytes(
    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
  )
  let msg = hex_to_bytes("af82")
  let (pk, sk) = keypair_from_seed(seed)
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if pk[i] != expected_pk[i] {
      diff_count = diff_count + 1
    }
  }
  let sig = sign(msg, sk)
  for i = 0; i < 64; i = i + 1 {
    if sig[i] != expected_sig[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  assert_eq(verify(sig, msg, pk), true)
}

///|
/// 内部:fe_unpack → fe_pack 应该是 identity
test "fe_roundtrip" {
  let bytes = hex_to_bytes(
    "48656c6c6f576f726c6400000000000000000000000000000000000000000000",
  )
  let fe = fe_unpack(bytes)
  let out = fe_pack(fe)
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if out[i] != bytes[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///| 内部:sc_from32bytes → sc_to32bytes roundtrip

///| L in LE bytes: ED D3 F5 5C 1A 63 12 58 D6 9C F7 A2 DE F9 DE 14

///|               00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10

///| L-1 in LE bytes: EC D3 F5 5C 1A 63 12 58 D6 9C F7 A2 DE F9 DE 14

///|
///                  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
test "sc_roundtrip" {
  let bytes = hex_to_bytes(
    "ecd3f55c1a631258d69cf7a2de9f130dde14000000000000000000000000000010",
  )
  let sc = sc_from32bytes(bytes)
  let out = sc_to32bytes(sc)
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if out[i] != bytes[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///|
/// 内部:sc_from32bytes(0) 应该返回 0
test "sc_zero" {
  let bytes = hex_to_bytes(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  let sc = sc_from32bytes(bytes)
  let out = sc_to32bytes(sc)
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if out[i] != bytes[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///|
/// 内部:sc_from32bytes(1) 应该返回 1
test "sc_one" {
  let bytes = hex_to_bytes(
    "0100000000000000000000000000000000000000000000000000000000000000",
  )
  let sc = sc_from32bytes(bytes)
  let out = sc_to32bytes(sc)
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if out[i] != bytes[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///|
/// 内部:sc_reduce_add_sub(L-1) 应该保持 L-1 不变(L-1 < L)
test "sc_reduce_add_sub_l1" {
  let r : Sc = sc_from32bytes(
    hex_to_bytes(
      "ecd3f55c1a631258d69cf7a2de9f130dde14000000000000000000000000000010",
    ),
  )
  sc_reduce_add_sub(r)
  let expected = hex_to_bytes(
    "ecd3f55c1a631258d69cf7a2de9f130dde14000000000000000000000000000010",
  )
  let out = sc_to32bytes(r)
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if out[i] != expected[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///| 内部:ge_pack → ge_unpackneg_vartime roundtrip

///| 注意:unpackneg 返回的是 -P(负点),重打包后 y 不变但 x 的符号位翻转,

///|
/// 所以正确预期是:前 31 字节相同,byte 31 只差最高 bit(sign bit)
test "ge_pack_unpack_roundtrip" {
  // Use the known pk from Test 1
  let pk_bytes = hex_to_bytes(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  )
  let result = ge_unpackneg_vartime(pk_bytes)
  let (a_neg, ok) = result
  assert_eq(ok, true)
  // Re-pack
  let re_packed = ge_pack(a_neg)
  // 前 31 字节必须完全一致(y 坐标不变)
  for i = 0; i < 31; i = i + 1 {
    assert_eq(re_packed[i], pk_bytes[i])
  }
  // byte 31:只允许 sign bit (0x80) 翻转,低 7 位必须一致
  assert_eq(re_packed[31] & 0x7f, pk_bytes[31] & 0x7f)
  // 且符号位确实翻转了(x != 0 时 -x 的 parity 必然相反)
  assert_eq((re_packed[31] >> 7) ^ (pk_bytes[31] >> 7), 1)
}

///|
/// 内部:ge_pack(ge25519_base) 应该等于 base point 的 LE 编码
test "ge_pack_base" {
  let packed = ge_pack(ge25519_base)
  let expected_hex = "5866666666666666666666666666666666666666666666666666666666666666"
  let expected = hex_to_bytes(expected_hex)
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if packed[i] != expected[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///| 内部:ge_scalarmult_base(1) 应该等于 B

///|
/// 验证: pack(scalarmult_base(1)) == pack(B)
test "scalarmult_base_one" {
  let s : Sc = sc_from32bytes(
    hex_to_bytes(
      "0100000000000000000000000000000000000000000000000000000000000000",
    ),
  )
  let r : Ge_p3 = ge_scalarmult_base(s)
  let packed_r = ge_pack(r)
  let expected_hex = "5866666666666666666666666666666666666666666666666666666666666666"
  let expected = hex_to_bytes(expected_hex)
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if packed_r[i] != expected[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///|
/// 内部:test fe_cmov directly
test "fe_cmov_test" {
  let r : Fe = fe_zero()
  let x : Fe = fe_new()
  x[0] = 42UL
  fe_cmov(r, x, 1UL)
  assert_eq(r[0], 42UL)
  // b=0 时 r 不变
  let y : Fe = fe_zero()
  fe_cmov(y, x, 0UL)
  assert_eq(y[0], 0UL)
}
