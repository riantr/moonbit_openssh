///| HMAC-SHA256 黑盒测试

///| 跑法:`moon test`

///|
/// 把字符串字面量转成 FixedArray[Byte]
fn str_to_bytes(s : String) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    arr[i] = s[i].to_byte()
  }
  arr
}

///|
test "empty_key_empty_msg" {
  // 退化 case:空 key + 空 msg
  let key : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let msg : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let tag = @hmac.hmac_sha256(key, msg)
  assert_eq(tag.length(), 32)
}

///|
test "deterministic" {
  let key = str_to_bytes("key")
  let msg = str_to_bytes("The quick brown fox jumps over the lazy dog")
  let tag1 = @hmac.hmac_sha256(key, msg)
  let tag2 = @hmac.hmac_sha256(key, msg)
  for i = 0; i < 32; i = i + 1 {
    assert_eq(tag1[i], tag2[i])
  }
}

///|
test "different_keys_different_tags" {
  let k1 = str_to_bytes("key1")
  let k2 = str_to_bytes("key2")
  let msg = str_to_bytes("hello")
  let t1 = @hmac.hmac_sha256(k1, msg)
  let t2 = @hmac.hmac_sha256(k2, msg)
  let mut different = false
  for i = 0; i < 32; i = i + 1 {
    if t1[i] != t2[i] {
      different = true
    }
  }
  assert_eq(different, true)
}

///|
test "key_shorter_than_blocksize" {
  // 短 key(< 64)
  let key = str_to_bytes("Jefe")
  let msg = str_to_bytes("what do ya want for nothing?")
  let tag = @hmac.hmac_sha256(key, msg)
  assert_eq(tag.length(), 32)
}

///|
test "key_exactly_blocksize" {
  // key 正好 64 字节
  let key : FixedArray[Byte] = FixedArray::make(64, 0xAA)
  let msg = str_to_bytes("hello")
  let tag = @hmac.hmac_sha256(key, msg)
  assert_eq(tag.length(), 32)
}

///|
test "key_longer_than_blocksize" {
  // key > 64,触发 H(key) 路径
  let key : FixedArray[Byte] = FixedArray::make(131, 0xAA)
  let msg = str_to_bytes("hello")
  let tag = @hmac.hmac_sha256(key, msg)
  assert_eq(tag.length(), 32)
}

///|
test "empty_msg" {
  let key = str_to_bytes("key")
  let msg : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let tag = @hmac.hmac_sha256(key, msg)
  assert_eq(tag.length(), 32)
}
