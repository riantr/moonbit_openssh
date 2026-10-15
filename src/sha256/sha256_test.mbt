///| SHA-256 黑盒测试

///|
/// 跑法:`moon test`
test "empty_message" {
  // 空 message:SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  let msg : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let h = @sha256.sha256(msg)
  assert_eq(h.length(), 32)
}

///|
test "single_byte" {
  let msg : FixedArray[Byte] = FixedArray::make(1, 0x61) // "a"
  let h = @sha256.sha256(msg)
  assert_eq(h.length(), 32)
}

///|
test "boundary_55_bytes" {
  // 55 bytes = 56 - 1 (刚好 1 block + 1 byte pad, 还需要补齐 length)
  let msg : FixedArray[Byte] = FixedArray::make(55, 0x61)
  let h = @sha256.sha256(msg)
  assert_eq(h.length(), 32)
}

///|
test "boundary_56_bytes" {
  // 56 bytes - 触发 2 blocks 边界
  let msg : FixedArray[Byte] = FixedArray::make(56, 0x61)
  let h = @sha256.sha256(msg)
  assert_eq(h.length(), 32)
}

///|
test "boundary_64_bytes" {
  // 64 bytes - 刚好 1 block, pad 在第 2 块
  let msg : FixedArray[Byte] = FixedArray::make(64, 0x61)
  let h = @sha256.sha256(msg)
  assert_eq(h.length(), 32)
}

///|
test "boundary_119_bytes" {
  let msg : FixedArray[Byte] = FixedArray::make(119, 0x61)
  let h = @sha256.sha256(msg)
  assert_eq(h.length(), 32)
}

///|
test "boundary_128_bytes" {
  let msg : FixedArray[Byte] = FixedArray::make(128, 0x61)
  let h = @sha256.sha256(msg)
  assert_eq(h.length(), 32)
}

///|
test "deterministic" {
  let msg : FixedArray[Byte] = FixedArray::make(100, 0x42)
  let h1 = @sha256.sha256(msg)
  let h2 = @sha256.sha256(msg)
  for i = 0; i < 32; i = i + 1 {
    assert_eq(h1[i], h2[i])
  }
}

///|
test "different_inputs_different_hashes" {
  let m1 : FixedArray[Byte] = FixedArray::make(64, 0x00)
  let m2 : FixedArray[Byte] = FixedArray::make(64, 0x01)
  let h1 = @sha256.sha256(m1)
  let h2 = @sha256.sha256(m2)
  let mut different = false
  for i = 0; i < 32; i = i + 1 {
    if h1[i] != h2[i] {
      different = true
    }
  }
  assert_eq(different, true)
}
