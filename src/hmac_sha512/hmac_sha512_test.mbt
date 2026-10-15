///| HMAC-SHA512 黑盒测试

///|
/// 字符串字面量转 FixedArray[Byte]
fn str_to_bytes(s : String) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    arr[i] = s[i].to_byte()
  }
  arr
}

///|
test "empty_key_empty_msg" {
  let key : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let msg : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let tag = @hmac_sha512.hmac_sha512(key, msg)
  assert_eq(tag.length(), 64)
}

///|
test "deterministic" {
  let key = str_to_bytes("key")
  let msg = str_to_bytes("The quick brown fox jumps over the lazy dog")
  let tag1 = @hmac_sha512.hmac_sha512(key, msg)
  let tag2 = @hmac_sha512.hmac_sha512(key, msg)
  for i = 0; i < 64; i = i + 1 {
    assert_eq(tag1[i], tag2[i])
  }
}

///|
test "different_keys_different_tags" {
  let k1 = str_to_bytes("key1")
  let k2 = str_to_bytes("key2")
  let msg = str_to_bytes("hello")
  let t1 = @hmac_sha512.hmac_sha512(k1, msg)
  let t2 = @hmac_sha512.hmac_sha512(k2, msg)
  let mut different = false
  for i = 0; i < 64; i = i + 1 {
    if t1[i] != t2[i] {
      different = true
    }
  }
  assert_eq(different, true)
}

///|
test "key_shorter_than_blocksize" {
  let key = str_to_bytes("Jefe")
  let msg = str_to_bytes("what do ya want for nothing?")
  let tag = @hmac_sha512.hmac_sha512(key, msg)
  assert_eq(tag.length(), 64)
}

///|
test "key_exactly_blocksize" {
  let key : FixedArray[Byte] = FixedArray::make(128, 0xAA)
  let msg = str_to_bytes("hello")
  let tag = @hmac_sha512.hmac_sha512(key, msg)
  assert_eq(tag.length(), 64)
}

///|
test "key_longer_than_blocksize" {
  // key > 128, 触发 H(key) 路径
  let key : FixedArray[Byte] = FixedArray::make(200, 0xAA)
  let msg = str_to_bytes("hello")
  let tag = @hmac_sha512.hmac_sha512(key, msg)
  assert_eq(tag.length(), 64)
}

///|
test "empty_msg" {
  let key = str_to_bytes("key")
  let msg : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let tag = @hmac_sha512.hmac_sha512(key, msg)
  assert_eq(tag.length(), 64)
}

///|
test "output_is_64_bytes" {
  let key : FixedArray[Byte] = FixedArray::make(64, 0x42)
  let msg : FixedArray[Byte] = FixedArray::make(100, 0x09)
  let tag = @hmac_sha512.hmac_sha512(key, msg)
  assert_eq(tag.length(), 64)
}
