///| AEAD 黑盒测试(公开 API + 三盲期望值)

///| 跑法:`moon test`
///

///| 期望值全部由 verify_c/aead_python_ref.py 生成

///| (cryptography 44.0.1 交叉验证),禁止手抄 RFC 文本。

///|
/// 严格 16 进制字符串转 FixedArray[Byte](非法字符 abort)
fn hex_to_bytes(hex : String) -> FixedArray[Byte] {
  if hex.length() % 2 != 0 {
    abort("hex_to_bytes: odd length")
  }
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_digit_bb(hex[i * 2])
    let lo = hex_digit_bb(hex[i * 2 + 1])
    arr[i] = ((hi * 16 + lo).reinterpret_as_uint() & 0xFFU).to_byte()
  }
  arr
}

///|
fn hex_digit_bb(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("hex_digit_bb: invalid character")
  }
}

///|
/// 字节数组相等断言(不等时 abort 并给出标签)
fn assert_bytes_eq(
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
/// RFC 8439 § 2.8.2 KAT 输入
fn kat_key() -> FixedArray[Byte] {
  hex_to_bytes(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
  )
}

///|
fn kat_nonce() -> FixedArray[Byte] {
  hex_to_bytes("070000004041424344454647")
}

///|
fn kat_aad() -> FixedArray[Byte] {
  hex_to_bytes("50515253c0c1c2c3c4c5c6c7")
}

///|
fn kat_pt() -> FixedArray[Byte] {
  hex_to_bytes(
    "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
  )
}

///|
/// Section B 共享 key material(bytes 0x00..0x3F)
fn wrap_key64() -> FixedArray[Byte] {
  hex_to_bytes(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  )
}

// ================= RFC 8439 核心 AEAD(KAT)=================

///|
test "rfc8439_kat_encrypt" {
  // § 2.8.2 官方向量,期望值由 python cryptography 生成并与 RFC 已知 tag 一致
  let ct_tag = aead_encrypt(kat_key(), kat_nonce(), kat_aad(), kat_pt())
  assert_eq(ct_tag.length(), kat_pt().length() + 16)
  let expect_ct = hex_to_bytes(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
  )
  let expect_tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691")
  for i = 0; i < expect_ct.length(); i = i + 1 {
    assert_eq(ct_tag[i], expect_ct[i])
  }
  for i = 0; i < 16; i = i + 1 {
    assert_eq(ct_tag[expect_ct.length() + i], expect_tag[i])
  }
}

///|
test "rfc8439_kat_decrypt" {
  let ct = hex_to_bytes(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
  )
  let tag = hex_to_bytes("1ae10b594f09e26a7e902ecbd0600691")
  let input : FixedArray[Byte] = FixedArray::make(ct.length() + 16, b'\x00')
  for i = 0; i < ct.length(); i = i + 1 {
    input[i] = ct[i]
  }
  for i = 0; i < 16; i = i + 1 {
    input[ct.length() + i] = tag[i]
  }
  let pt = aead_decrypt(kat_key(), kat_nonce(), kat_aad(), input)
  match pt {
    Some(p) => assert_bytes_eq(p, kat_pt(), "kat decrypt")
    None => abort("kat decrypt returned None")
  }
}

///|
test "rfc8439_kat_tamper_ciphertext" {
  let ct_tag = aead_encrypt(kat_key(), kat_nonce(), kat_aad(), kat_pt())
  ct_tag[10] = ct_tag[10] ^ b'\x01' // 翻转密文中间一比特
  assert_eq(aead_decrypt(kat_key(), kat_nonce(), kat_aad(), ct_tag), None)
}

///|
test "rfc8439_kat_tamper_tag" {
  let ct_tag = aead_encrypt(kat_key(), kat_nonce(), kat_aad(), kat_pt())
  let last = ct_tag.length() - 1
  ct_tag[last] = ct_tag[last] ^ b'\x80'
  assert_eq(aead_decrypt(kat_key(), kat_nonce(), kat_aad(), ct_tag), None)
}

///|
test "rfc8439_wrong_key" {
  let ct_tag = aead_encrypt(kat_key(), kat_nonce(), kat_aad(), kat_pt())
  let bad_key = kat_key()
  bad_key[0] = bad_key[0] ^ b'\xff'
  assert_eq(aead_decrypt(bad_key, kat_nonce(), kat_aad(), ct_tag), None)
}

///|
test "rfc8439_wrong_nonce" {
  let ct_tag = aead_encrypt(kat_key(), kat_nonce(), kat_aad(), kat_pt())
  let bad_nonce = kat_nonce()
  bad_nonce[11] = bad_nonce[11] ^ b'\x01'
  assert_eq(aead_decrypt(kat_key(), bad_nonce, kat_aad(), ct_tag), None)
}

///|
test "rfc8439_wrong_aad" {
  let ct_tag = aead_encrypt(kat_key(), kat_nonce(), kat_aad(), kat_pt())
  let bad_aad = kat_aad()
  bad_aad[0] = bad_aad[0] ^ b'\x01'
  assert_eq(aead_decrypt(kat_key(), kat_nonce(), bad_aad, ct_tag), None)
}

///|
test "rfc8439_truncated_input" {
  // 长度 < 16 直接拒绝
  let short : FixedArray[Byte] = FixedArray::make(15, b'\x00')
  assert_eq(aead_decrypt(kat_key(), kat_nonce(), kat_aad(), short), None)
  let empty : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  assert_eq(aead_decrypt(kat_key(), kat_nonce(), kat_aad(), empty), None)
}

///|
test "rfc8439_edge_empty_aad" {
  // A2:aad 空,pt 同 § 2.8.2 → ct 与 A 相同,tag 不同
  let ct_tag = aead_encrypt(
    kat_key(),
    kat_nonce(),
    FixedArray::make(0, b'\x00'),
    kat_pt(),
  )
  let expect_tag = hex_to_bytes("6a23a4681fd59456aea1d29f82477216")
  for i = 0; i < 16; i = i + 1 {
    assert_eq(ct_tag[kat_pt().length() + i], expect_tag[i])
  }
  // 解密回来
  let pt = aead_decrypt(
    kat_key(),
    kat_nonce(),
    FixedArray::make(0, b'\x00'),
    ct_tag,
  )
  assert_bytes_eq(pt.unwrap(), kat_pt(), "empty-aad decrypt")
}

///|
test "rfc8439_edge_empty_plaintext" {
  // A3:pt 空,aad 同 § 2.8.2 → 输出仅 16 字节 tag
  let ct_tag = aead_encrypt(
    kat_key(),
    kat_nonce(),
    kat_aad(),
    FixedArray::make(0, b'\x00'),
  )
  assert_eq(ct_tag.length(), 16)
  let expect_tag = hex_to_bytes("e622e5647a38d967a7ecbcb46c7f675c")
  for i = 0; i < 16; i = i + 1 {
    assert_eq(ct_tag[i], expect_tag[i])
  }
  let pt = aead_decrypt(kat_key(), kat_nonce(), kat_aad(), ct_tag)
  assert_eq(pt.unwrap().length(), 0)
}

///|
test "rfc8439_edge_both_empty" {
  // A4:aad 和 pt 全空
  let ct_tag = aead_encrypt(
    kat_key(),
    kat_nonce(),
    FixedArray::make(0, b'\x00'),
    FixedArray::make(0, b'\x00'),
  )
  assert_eq(ct_tag.length(), 16)
  let expect_tag = hex_to_bytes("a0784d7a4716f3feb4f64e7f4b39bf04")
  for i = 0; i < 16; i = i + 1 {
    assert_eq(ct_tag[i], expect_tag[i])
  }
}

///|
test "rfc8439_roundtrip_multi_block_lengths" {
  // 覆盖 0/1/63/64/65/128/129 字节,跨块边界
  let lens = [0, 1, 63, 64, 65, 128, 129]
  let data : FixedArray[Byte] = FixedArray::make(129, b'\x00')
  for i = 0; i < 129; i = i + 1 {
    data[i] = ((i * 31 + 17) & 0xFF).reinterpret_as_uint().to_byte()
  }
  for len in lens {
    let pt : FixedArray[Byte] = FixedArray::make(len, b'\x00')
    for i = 0; i < len; i = i + 1 {
      pt[i] = data[i]
    }
    let ct_tag = aead_encrypt(kat_key(), kat_nonce(), kat_aad(), pt)
    assert_eq(ct_tag.length(), len + 16)
    match aead_decrypt(kat_key(), kat_nonce(), kat_aad(), ct_tag) {
      Some(back) => assert_bytes_eq(back, pt, "roundtrip len=\{len}")
      None => abort("roundtrip len=\{len} failed")
    }
  }
}

// ================= OpenSSH wire 包装(chacha20-poly1305@openssh.com)=========

///|
/// B1:seqnr=0, header=deadbeef, payload="hello chachapoly wrapper!"
test "wrapper_b1_encrypt" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let header = hex_to_bytes("deadbeef")
  let payload = hex_to_bytes(
    "68656c6c6f20636861636861706f6c79207772617070657221",
  )
  let src : FixedArray[Byte] = FixedArray::make(4 + 25, b'\x00')
  for i = 0; i < 4; i = i + 1 {
    src[i] = header[i]
  }
  for i = 0; i < 25; i = i + 1 {
    src[4 + i] = payload[i]
  }
  let wrapped = ctx.crypt(0U, src, 4, 25, true).unwrap()
  assert_eq(wrapped.length(), 4 + 25 + 16)
  let expect = hex_to_bytes(
    "4ae8b0b670dd2e5dc2c6c5b972023400df2c225ed8c6819491dd3e2ecd727cee6cc575bba0aba1ca13106344fb",
  )
  assert_bytes_eq(wrapped, expect, "B1 wrapped")
}

///|
test "wrapper_b1_decrypt" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let wrapped = hex_to_bytes(
    "4ae8b0b670dd2e5dc2c6c5b972023400df2c225ed8c6819491dd3e2ecd727cee6cc575bba0aba1ca13106344fb",
  )
  let plain = ctx.crypt(0U, wrapped, 4, 25, false).unwrap()
  let expect = hex_to_bytes(
    "deadbeef68656c6c6f20636861636861706f6c79207772617070657221",
  )
  assert_bytes_eq(plain, expect, "B1 decrypted")
}

///|
/// B2:seqnr=0x11223344, header=0x100, payload=100B 跨块模式
test "wrapper_b2_roundtrip" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let seqnr = 0x11223344U
  let header = hex_to_bytes("00000100")
  let payload = hex_to_bytes(
    "0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0",
  )
  let datalen : Int = payload.length()
  let src : FixedArray[Byte] = FixedArray::make(4 + datalen, b'\x00')
  for i = 0; i < 4; i = i + 1 {
    src[i] = header[i]
  }
  for i = 0; i < datalen; i = i + 1 {
    src[4 + i] = payload[i]
  }
  let wrapped = ctx.crypt(seqnr, src, 4, datalen, true).unwrap()
  let expect = hex_to_bytes(
    "9e19c7b7d7d64788fb0b3e8ff985a9c2b59b0d7931f8e61f1580d338c6c434c75bf209343aca37efb8587586b8f9ec1a7aa47a304df615f5524ec6685e52c9e7c9bc79989b507c4b213e732d0c1f442dcf730e7b66254ed2be41cef5aa88e17bfa91d3b9258aa023d50233bb0081866dbdaf23e9e205b64f",
  )
  assert_bytes_eq(wrapped, expect, "B2 wrapped")
  // 解密回明文(header ‖ payload)
  let plain = ctx.crypt(seqnr, wrapped, 4, datalen, false).unwrap()
  assert_eq(plain.length(), 4 + datalen)
  for i = 0; i < 4; i = i + 1 {
    assert_eq(plain[i], header[i])
  }
  for i = 0; i < datalen; i = i + 1 {
    assert_eq(plain[4 + i], payload[i])
  }
}

///|
/// B3:seqnr=0xffffffff, 最小 payload
test "wrapper_b3_roundtrip" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let seqnr = 0xFFFFFFFFU
  let wrapped = hex_to_bytes("b90ee4ac48d34ddabce51c3dc6fda3809a06b901a68d7a2c")
  let plain = ctx.crypt(seqnr, wrapped, 4, 4, false).unwrap()
  assert_eq(plain.length(), 8)
  assert_eq(plain[0], b'\x00')
  assert_eq(plain[1], b'\x00')
  assert_eq(plain[2], b'\x00')
  assert_eq(plain[3], b'\x1c') // header = 28
  assert_eq(plain[4], b'A')
  assert_eq(plain[5], b'A')
  assert_eq(plain[6], b'A')
  assert_eq(plain[7], b'A')
}

///|
test "wrapper_get_length" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  // B2 的包头密文是 wrapped 前 4 字节
  let hdr_ct = hex_to_bytes("9e19c7b7")
  assert_eq(ctx.get_length(0x11223344U, hdr_ct), 0x00000100U)
  // B3
  let hdr_ct3 = hex_to_bytes("b90ee4ac")
  assert_eq(ctx.get_length(0xFFFFFFFFU, hdr_ct3), 0x0000001cU)
  // B1:原始 header 是 deadbeef,解出来就是 0xdeadbeef
  let hdr_ct1 = hex_to_bytes("4ae8b0b6")
  assert_eq(ctx.get_length(0U, hdr_ct1), 0xdeadbeefU)
}

///|
test "wrapper_wrong_seqnr_rejected" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let wrapped = hex_to_bytes(
    "4ae8b0b670dd2e5dc2c6c5b972023400df2c225ed8c6819491dd3e2ecd727cee6cc575bba0aba1ca13106344fb",
  )
  // 用错误序号解密 → poly key 不同 → tag 校验失败
  assert_eq(ctx.crypt(1U, wrapped, 4, 25, false), None)
}

///|
test "wrapper_tamper_body_rejected" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let wrapped = hex_to_bytes(
    "4ae8b0b670dd2e5dc2c6c5b972023400df2c225ed8c6819491dd3e2ecd727cee6cc575bba0aba1ca13106344fb",
  )
  wrapped[10] = wrapped[10] ^ b'\x40'
  assert_eq(ctx.crypt(0U, wrapped, 4, 25, false), None)
}

///|
test "wrapper_tamper_tag_rejected" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let wrapped = hex_to_bytes(
    "4ae8b0b670dd2e5dc2c6c5b972023400df2c225ed8c6819491dd3e2ecd727cee6cc575bba0aba1ca13106344fb",
  )
  let n = wrapped.length()
  wrapped[n - 1] = wrapped[n - 1] ^ b'\x01'
  assert_eq(ctx.crypt(0U, wrapped, 4, 25, false), None)
}

///|
test "wrapper_wrong_key_rejected" {
  // 注意:tag 只依赖密文和 poly_key(来自 main_key),与 header_key 无关。
  // 改 key[32..64)(header key)不会让 MAC 失败——这是 encrypt-then-MAC 的
  // 协议性质(C 行为相同)。要让 tag 校验失败必须动 main_key。
  let bad_key = wrap_key64()
  bad_key[0] = bad_key[0] ^ b'\xff'
  let bad_ctx = ChachaPolyCtx::new64(bad_key)
  let wrapped = hex_to_bytes(
    "4ae8b0b670dd2e5dc2c6c5b972023400df2c225ed8c6819491dd3e2ecd727cee6cc575bba0aba1ca13106344fb",
  )
  assert_eq(bad_ctx.crypt(0U, wrapped, 4, 25, false), None)
}

///|
test "wrapper_wrong_header_key_still_decrypts_payload" {
  // 反向锁定协议性质:改 header_key → MAC 仍通过,但包头解出垃圾。
  // (对应 C:chachapoly_crypt 返回 0,payload 正确,header 错)
  let bad_key = wrap_key64()
  bad_key[63] = bad_key[63] ^ b'\xff'
  let bad_ctx = ChachaPolyCtx::new64(bad_key)
  let wrapped = hex_to_bytes(
    "4ae8b0b670dd2e5dc2c6c5b972023400df2c225ed8c6819491dd3e2ecd727cee6cc575bba0aba1ca13106344fb",
  )
  match bad_ctx.crypt(0U, wrapped, 4, 25, false) {
    Some(plain) => {
      // payload 部分仍正确(main_key 未变)
      let payload = hex_to_bytes(
        "68656c6c6f20636861636861706f6c79207772617070657221",
      )
      for i = 0; i < 25; i = i + 1 {
        assert_eq(plain[4 + i], payload[i])
      }
      // 包头是垃圾(几乎必然 != deadbeef;逐字节统计不匹配数)
      let header = hex_to_bytes("deadbeef")
      let mut diff : Int = 0
      for i = 0; i < 4; i = i + 1 {
        if plain[i] != header[i] {
          diff = diff + 1
        }
      }
      assert_eq(diff > 0, true)
    }
    None => abort("header-key corruption must not fail the MAC")
  }
}

///|
test "wrapper_short_buffer_rejected" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let short : FixedArray[Byte] = FixedArray::make(4 + 25 + 15, b'\x00')
  // 少一个字节都不行(tag 不完整)
  assert_eq(ctx.crypt(0U, short, 4, 25, false), None)
}

///|
test "wrapper_large_roundtrip" {
  let ctx = ChachaPolyCtx::new64(wrap_key64())
  let datalen = 300
  let src : FixedArray[Byte] = FixedArray::make(4 + datalen, b'\x00')
  src[0] = b'\x00'
  src[1] = b'\x00'
  src[2] = b'\x01'
  src[3] = b'\x2c' // 包长字段 = 300
  for i = 0; i < datalen; i = i + 1 {
    src[4 + i] = ((i * 7 + 3) & 0xFF).reinterpret_as_uint().to_byte()
  }
  let wrapped = ctx.crypt(0x01020304U, src, 4, datalen, true).unwrap()
  let back = ctx.crypt(0x01020304U, wrapped, 4, datalen, false).unwrap()
  assert_bytes_eq(back, src, "wrapper large roundtrip")
}
