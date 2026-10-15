///| Poly1305 黑盒测试

///|
/// 跑法:`moon test`
test "boundary_empty_message" {
  // 空 message:tag 应该是 key[16..32] 本身(因为 h = 0, final 加 s 不归一化)
  // 实际上 RFC 8439 Vector #2 就是测这个,见 _wbtest
  let key : FixedArray[Byte] = FixedArray::make(32, 0x00)
  for i = 0; i < 32; i = i + 1 {
    key[i] = i.to_byte()
  }
  let empty : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let tag = @poly1305.poly1305_auth(key, empty)
  assert_eq(tag.length(), 16)
}

///|
test "boundary_single_byte" {
  let key : FixedArray[Byte] = FixedArray::make(32, 0xAB)
  let msg : FixedArray[Byte] = FixedArray::make(1, 0x42)
  let tag = @poly1305.poly1305_auth(key, msg)
  assert_eq(tag.length(), 16)
}

///|
test "boundary_15_bytes" {
  // 15 字节,部分 block 路径
  let key : FixedArray[Byte] = FixedArray::make(32, 0xAB)
  let msg : FixedArray[Byte] = FixedArray::make(15, 0x42)
  let tag = @poly1305.poly1305_auth(key, msg)
  assert_eq(tag.length(), 16)
}

///|
test "boundary_exactly_16_bytes" {
  // 16 字节,刚好一个完整 block
  let key : FixedArray[Byte] = FixedArray::make(32, 0xAB)
  let msg : FixedArray[Byte] = FixedArray::make(16, 0x42)
  let tag = @poly1305.poly1305_auth(key, msg)
  assert_eq(tag.length(), 16)
}

///|
test "boundary_17_bytes" {
  // 17 字节,1 个完整 block + 1 个部分 block
  let key : FixedArray[Byte] = FixedArray::make(32, 0xAB)
  let msg : FixedArray[Byte] = FixedArray::make(17, 0x42)
  let tag = @poly1305.poly1305_auth(key, msg)
  assert_eq(tag.length(), 16)
}

///|
test "deterministic" {
  // 同一 (key, message) 总是产生同一 tag
  let key : FixedArray[Byte] = FixedArray::make(32, 0xAB)
  let msg : FixedArray[Byte] = FixedArray::make(100, 0x42)
  let tag1 = @poly1305.poly1305_auth(key, msg)
  let tag2 = @poly1305.poly1305_auth(key, msg)
  for i = 0; i < 16; i = i + 1 {
    assert_eq(tag1[i], tag2[i])
  }
}

///|
test "different_keys_different_tags" {
  // 不同 key 应该产生不同 tag(sanity check)
  let key1 : FixedArray[Byte] = FixedArray::make(32, 0xAB)
  let key2 : FixedArray[Byte] = FixedArray::make(32, 0xCD)
  let msg : FixedArray[Byte] = FixedArray::make(64, 0x42)
  let tag1 = @poly1305.poly1305_auth(key1, msg)
  let tag2 = @poly1305.poly1305_auth(key2, msg)
  let mut different = false
  for i = 0; i < 16; i = i + 1 {
    if tag1[i] != tag2[i] {
      different = true
    }
  }
  assert_eq(different, true)
}
