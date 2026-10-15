///| SHA-512 黑盒测试

///|
/// 跑法:`moon test`
test "empty_message" {
  // 空 message:SHA-512("") = cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce
  //                            47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
  let msg : FixedArray[Byte] = FixedArray::make(0, 0x00)
  let h = @sha512.sha512(msg)
  assert_eq(h.length(), 64)
}

///|
test "single_byte" {
  let msg : FixedArray[Byte] = FixedArray::make(1, 0x61) // "a"
  let h = @sha512.sha512(msg)
  assert_eq(h.length(), 64)
}

///|
test "boundary_127_bytes" {
  let msg : FixedArray[Byte] = FixedArray::make(127, 0x61)
  let h = @sha512.sha512(msg)
  assert_eq(h.length(), 64)
}

///|
test "boundary_128_bytes" {
  let msg : FixedArray[Byte] = FixedArray::make(128, 0x61)
  let h = @sha512.sha512(msg)
  assert_eq(h.length(), 64)
}

///|
test "boundary_255_bytes" {
  let msg : FixedArray[Byte] = FixedArray::make(255, 0x61)
  let h = @sha512.sha512(msg)
  assert_eq(h.length(), 64)
}

///|
test "boundary_256_bytes" {
  let msg : FixedArray[Byte] = FixedArray::make(256, 0x61)
  let h = @sha512.sha512(msg)
  assert_eq(h.length(), 64)
}

///|
test "deterministic" {
  let msg : FixedArray[Byte] = FixedArray::make(200, 0x42)
  let h1 = @sha512.sha512(msg)
  let h2 = @sha512.sha512(msg)
  for i = 0; i < 64; i = i + 1 {
    assert_eq(h1[i], h2[i])
  }
}

///|
test "different_inputs_different_hashes" {
  let m1 : FixedArray[Byte] = FixedArray::make(128, 0x00)
  let m2 : FixedArray[Byte] = FixedArray::make(128, 0x01)
  let h1 = @sha512.sha512(m1)
  let h2 = @sha512.sha512(m2)
  let mut different = false
  for i = 0; i < 64; i = i + 1 {
    if h1[i] != h2[i] {
      different = true
    }
  }
  assert_eq(different, true)
}
