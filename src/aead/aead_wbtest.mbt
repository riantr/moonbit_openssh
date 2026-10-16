///| AEAD 白盒测试(可访问包内私有函数)

///| 跑法:`moon test`
///

///| 注意:hex 解析是严格的——遇到非法字符直接 abort,

///| 避免有损解析让测试空洞化(Loop #7 教训)。

///|
/// 严格 16 进制字符串转 FixedArray[Byte]
fn hex_to_bytes(hex : String) -> FixedArray[Byte] {
  if hex.length() % 2 != 0 {
    abort("hex_to_bytes: odd length")
  }
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = parse_byte_strict(hex[i * 2], hex[i * 2 + 1])
  }
  arr
}

///|
/// 解析两个 hex char 为 1 byte(非法字符 abort)
fn parse_byte_strict(hi : UInt16, lo : UInt16) -> Byte {
  let h = hex_digit_strict(hi)
  let l = hex_digit_strict(lo)
  ((h * 16 + l).reinterpret_as_uint() & 0xFFU).to_byte()
}

///|
fn hex_digit_strict(c : UInt16) -> Int32 {
  let code : Int32 = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("hex_digit_strict: invalid character")
  }
}

///|
/// 字节数组相等断言
fn assert_bytes_eq_wb(
  actual : FixedArray[Byte],
  expected : FixedArray[Byte],
  label : String,
) -> Unit {
  if actual.length() != expected.length() {
    abort(
      "\{label}: length mismatch \{actual.length()} != \{expected.length()}",
    )
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if actual[i] != expected[i] {
      abort("\{label}: byte \{i} mismatch")
    }
  }
}

///|
test "seq_to_be64_zero" {
  // RFC 8439 § 2.8.2 无关;这是 OpenSSH POKE_U64 语义
  let buf = seq_to_be64(0U)
  assert_eq(buf.length(), 8)
  for i = 0; i < 8; i = i + 1 {
    assert_eq(buf[i], b'\x00')
  }
}

///|
test "seq_to_be64_mid" {
  // 0x11223344 大端 = 00 00 00 00 11 22 33 44
  let buf = seq_to_be64(0x11223344U)
  let expect = hex_to_bytes("0000000011223344")
  assert_bytes_eq_wb(buf, expect, "seq_to_be64(0x11223344)")
}

///|
test "seq_to_be64_max" {
  let buf = seq_to_be64(0xFFFFFFFFU)
  let expect = hex_to_bytes("00000000ffffffff")
  assert_bytes_eq_wb(buf, expect, "seq_to_be64(0xffffffff)")
}

///|
test "pad16_len_cases" {
  assert_eq(pad16_len(0), 0)
  assert_eq(pad16_len(16), 0)
  assert_eq(pad16_len(32), 0)
  assert_eq(pad16_len(1), 15)
  assert_eq(pad16_len(12), 4)
  assert_eq(pad16_len(15), 1)
  assert_eq(pad16_len(17), 15)
  assert_eq(pad16_len(114), 14)
}

///|
test "put_u64_le_basic" {
  let buf : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  put_u64_le(buf, 0, 0x0102030405060708UL)
  let expect = hex_to_bytes("0807060504030201") // little-endian
  assert_bytes_eq_wb(buf, expect, "put_u64_le(0x0102030405060708)")
}

///|
test "aead_mac_data_layout" {
  // RFC 8439 § 2.8: aad ‖ pad16(aad) ‖ ct ‖ pad16(ct) ‖ LE64(|aad|) ‖ LE64(|ct|)
  // 用 § 2.8.2 的 aad(12B)和一个 114B 的假 ct 验证布局
  let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
  let ct : FixedArray[Byte] = FixedArray::make(114, b'\xAB')
  let md = aead_mac_data(aad, ct)
  // 总长 = 12 + pad4 + 114 + pad14 + 8 + 8 = 160
  assert_eq(md.length(), 160)
  // 前 12 字节 = aad
  for i = 0; i < 12; i = i + 1 {
    assert_eq(md[i], aad[i])
  }
  // [12..16) 是 pad 全零
  for i = 12; i < 16; i = i + 1 {
    assert_eq(md[i], b'\x00')
  }
  // [16..130) = ct
  for i = 0; i < 114; i = i + 1 {
    assert_eq(md[16 + i], b'\xAB')
  }
  // [130..144) pad 全零
  for i = 130; i < 144; i = i + 1 {
    assert_eq(md[i], b'\x00')
  }
  // 尾部 LE64(12) ‖ LE64(114)
  assert_eq(md[144], b'\x0c') // 12
  assert_eq(md[145], b'\x00')
  assert_eq(md[152], b'\x72') // 114 = 0x72
  assert_eq(md[153], b'\x00')
}

///|
test "rfc8439_state_layout" {
  // IETF 布局:sigma @ [0..4)、key @ [4..12)、32-bit counter @ [12]、nonce @ [13..16)
  let key = hex_to_bytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_to_bytes("070000004041424344454647")
  let s = rfc8439_state(key, nonce, 0U)
  assert_eq(s[0], sigma0)
  assert_eq(s[1], sigma1)
  assert_eq(s[2], sigma2)
  assert_eq(s[3], sigma3)
  assert_eq(s[4], 0x83828180U) // LE32(key[0..4))
  assert_eq(s[5], 0x87868584U)
  assert_eq(s[11], 0x9f9e9d9cU)
  assert_eq(s[12], 0U) // counter
  assert_eq(s[13], 0x00000007U) // LE32(nonce[0..4))
  assert_eq(s[14], 0x43424140U) // LE32(nonce[4..8))
  assert_eq(s[15], 0x47464544U) // LE32(nonce[8..12))
}

///|
test "rfc8439_state_counter_slot" {
  // counter 放在 word 12,且 rfc8439_xor 用它作为起始块计数
  let key = hex_to_bytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_to_bytes("070000004041424344454647")
  let s = rfc8439_state(key, nonce, 123456789U)
  assert_eq(s[12], 123456789U)
}

///|
test "aead_poly_key_is_block_ctr0_prefix" {
  // RFC 8439 § 2.6:poly key = block(counter=0) 输出的前 32 字节
  let key = hex_to_bytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_to_bytes("070000004041424344454647")
  let pk = aead_poly_key(key, nonce)
  let blk = chacha_block(rfc8439_state(key, nonce, 0U))
  for w = 0; w < 8; w = w + 1 {
    for b = 0; b < 4; b = b + 1 {
      assert_eq(pk[w * 4 + b], ((blk[w] >> (b * 8)) & 0xFFU).to_byte())
    }
  }
}

///|
test "rfc8439_xor_self_inverse" {
  // xor 流加密再流加密一次 = 恒等(state 不可变,keystream 确定)
  let key = hex_to_bytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
  let nonce = hex_to_bytes("070000004041424344454647")
  let data : FixedArray[Byte] = FixedArray::make(200, b'\x00')
  for i = 0; i < 200; i = i + 1 {
    data[i] = ((i * 13 + 7) & 0xFF).reinterpret_as_uint().to_byte()
  }
  let once = rfc8439_xor(rfc8439_state(key, nonce, 1U), data)
  // 确认确实变了(非全等)
  let mut changed = false
  for i = 0; i < 200; i = i + 1 {
    if once[i] != data[i] {
      changed = true
    }
  }
  assert_eq(changed, true)
  let twice = rfc8439_xor(rfc8439_state(key, nonce, 1U), once)
  assert_bytes_eq_wb(twice, data, "xor self-inverse")
}
