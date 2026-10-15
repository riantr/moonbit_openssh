///| Ed25519 黑盒测试

///| 跑法:`moon test`

///|

///| 这些测试只用公开 API(keypair_from_seed / sign / verify),

///| 验证 RFC 8032 行为 + 边界情况

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
/// 解析两个 hex char 为 1 byte
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

///| seed = 9d61b19d...f60

///| expected pk = d75a9801...511a

///|
/// expected sig = e5564300...100b
test "rfc8032_test1_empty" {
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
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  // check pk matches
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if pk[i] != expected_pk[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  // sign
  let sig = @ed25519.sign(msg, sk)
  for i = 0; i < 64; i = i + 1 {
    if sig[i] != expected_sig[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  // verify
  assert_eq(@ed25519.verify(sig, msg, pk), true)
}

///| RFC 8032 § 7.1 Test 2: 1-byte msg "72" (0x72)

///|
/// seed = 4ccd089b...a6fb
test "rfc8032_test2_1byte" {
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
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if pk[i] != expected_pk[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  let sig = @ed25519.sign(msg, sk)
  for i = 0; i < 64; i = i + 1 {
    if sig[i] != expected_sig[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  assert_eq(@ed25519.verify(sig, msg, pk), true)
}

///| RFC 8032 § 7.1 Test 3: 2-byte msg "af82"

///|
/// seed = c5aa8df4...58f7
test "rfc8032_test3_2byte" {
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
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let mut diff_count : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if pk[i] != expected_pk[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  let sig = @ed25519.sign(msg, sk)
  for i = 0; i < 64; i = i + 1 {
    if sig[i] != expected_sig[i] {
      diff_count = diff_count + 1
    }
  }
  assert_eq(diff_count, 0)
  assert_eq(@ed25519.verify(sig, msg, pk), true)
}

///|
/// Determinism: 同一 (seed, msg) 多次签名应得到相同 sig
test "deterministic" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let msg = hex_to_bytes("deadbeef")
  let (_pk, sk) = @ed25519.keypair_from_seed(seed)
  let sig1 = @ed25519.sign(msg, sk)
  let sig2 = @ed25519.sign(msg, sk)
  let mut diff : Int = 0
  for i = 0; i < 64; i = i + 1 {
    if sig1[i] != sig2[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}

///|
/// Tampered sig 验证应该失败
test "tampered_sig_rejected" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let msg = hex_to_bytes("hello world")
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let sig = @ed25519.sign(msg, sk)
  // tamper sig[0]
  sig[0] = (sig[0].to_uint64() ^ 0xFFUL).to_byte()
  assert_eq(@ed25519.verify(sig, msg, pk), false)
}

///| Tampered msg 验证应该失败

///| 注意:必须用真正的 hex 字面量!"hello world" 不是合法 hex,

///| hex_digit 会把非法字符映射为 0,导致两个不同字符串解析出相同字节。

///|
/// "hello world" = 68656c6c6f20776f726c64,"hello World" = 68656c6c6f20576f726c64
test "tampered_msg_rejected" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let msg = hex_to_bytes("68656c6c6f20776f726c64")
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let sig = @ed25519.sign(msg, sk)
  // 篡改 1 字节: 'w'(0x77) -> 'W'(0x57)
  let tampered = hex_to_bytes("68656c6c6f20576f726c64")
  assert_eq(@ed25519.verify(sig, tampered, pk), false)
}

///|
/// 错误 pk 验证应该失败
test "wrong_pk_rejected" {
  let seed1 = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let seed2 = hex_to_bytes(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
  )
  let msg = hex_to_bytes("hello")
  let (pk1, sk1) = @ed25519.keypair_from_seed(seed1)
  let (pk2, _sk2) = @ed25519.keypair_from_seed(seed2)
  let sig = @ed25519.sign(msg, sk1)
  // sig 跟 pk1 配对,用 pk2 验应该 fail
  assert_eq(@ed25519.verify(sig, msg, pk2), false)
  // 跟 pk1 配对应 ok
  assert_eq(@ed25519.verify(sig, msg, pk1), true)
}

///|
/// 大消息(1KB)签名 + 验证
test "large_msg" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let msg : FixedArray[Byte] = FixedArray::make(1024, b'\x00')
  for i = 0; i < 1024; i = i + 1 {
    msg[i] = (i & 0xFF).to_byte()
  }
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let sig = @ed25519.sign(msg, sk)
  assert_eq(@ed25519.verify(sig, msg, pk), true)
  // 改 1 byte 应该 fail
  msg[500] = (msg[500].to_uint64() ^ 0x01UL).to_byte()
  assert_eq(@ed25519.verify(sig, msg, pk), false)
}

///| s >= L 应该被拒绝(防止 signature malleability / small-subgroup attack)

///| 用真实签名的 R,只把 s 换成 L 本体 —— 确保失败路径是 s<L 检查本身,

///|
/// 而不是靠后续点运算不匹配"碰巧"返回 false
test "s_at_l_rejected" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  // "test" 不是合法 hex!用 "74657374" (ASCII "test")
  let msg = hex_to_bytes("74657374")
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  // 先做一次真签名拿到合法的 R
  let good_sig = @ed25519.sign(msg, sk)
  // s = L (LE bytes): ED D3 F5 5C ... 00 10 —— 精确等于群阶,必须被拒
  let l_bytes = hex_to_bytes(
    "edd3f55c1a631258d69cf7a2de9f130d14000000000000000000000000000010",
  )
  let sig : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    sig[i] = good_sig[i] // R 保持合法
    sig[i + 32] = l_bytes[i] // s = L
  }
  assert_eq(@ed25519.verify(sig, msg, pk), false)
}

///|
/// s = L+1 也应该被拒绝(大于群阶)
test "s_above_l_rejected" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let msg = hex_to_bytes("74657374")
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let good_sig = @ed25519.sign(msg, sk)
  // L+1: ED D3 F5 5C ... 00 10 -> EE D3 F5 5C ... (byte0 +1)
  let l_plus_1 = hex_to_bytes(
    "edd3f55c1a631258d69cf7a2de9f130d14000000000000000000000000000010",
  )
  l_plus_1[0] = 0xee
  let sig : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    sig[i] = good_sig[i]
    sig[i + 32] = l_plus_1[i]
  }
  assert_eq(@ed25519.verify(sig, msg, pk), false)
}

///|
/// 验证 keypair_from_seed 生成的 sk 格式: sk = seed || pk
test "sk_format" {
  let seed = hex_to_bytes(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  )
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  // sk[0..32] = seed
  let mut diff : Int = 0
  for i = 0; i < 32; i = i + 1 {
    if sk[i] != seed[i] {
      diff = diff + 1
    }
    if sk[i + 32] != pk[i] {
      diff = diff + 1
    }
  }
  assert_eq(diff, 0)
}
