///| ChaCha20 已知答案测试(KAT)—— 与 OpenSSH 原版 chacha.c 字节级对比

///| 参考输出来源:E:\src\moon\openssh_moonbit\verify_c\chacha_kat.exe

///|
/// 上述 C 工具链接 OpenSSH 原版 chacha.c + shim,以零明文测出真实 keystream
test "kat_TEST1_zero_key_iv_ctr0" {
  // key = 全 0, iv = 全 0, counter = 0(128-bit / 256-bit 模式都先验证 256-bit)
  // keystream 前 16 字节(LE u32 = 0xADE0B876):
  let key : FixedArray[Byte] = FixedArray::make(32, 0x00)
  let iv : FixedArray[Byte] = FixedArray::make(8, 0x00)
  let expected_keystream : FixedArray[Byte] = [
    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53,
    0x86, 0xbd, 0x28,
  ]
  let state = ChaChaState::new256(key)
  let state_with_iv = state.set_iv(iv)
  let zero_plaintext : FixedArray[Byte] = FixedArray::make(16, 0x00)
  let ciphertext = state_with_iv.process(zero_plaintext)
  assert_eq(ciphertext.length(), 16)
  for i = 0; i < 16; i = i + 1 {
    assert_eq(ciphertext[i], expected_keystream[i])
  }
}

///|
test "kat_TEST2_incremental_key_iv1_ctr1" {
  // key = [0..31], iv bytes = counter bytes = [0,0,0,0,0,0,0,1]
  // OpenSSH 约定:counter 是 8 字节 LE,bytes=[0,0,0,0,0,0,0,1] 等价于 UInt64 0x0100000000000000
  let key : FixedArray[Byte] = FixedArray::make(32, 0x00)
  for i = 0; i < 32; i = i + 1 {
    key[i] = i.to_byte()
  }
  let iv : FixedArray[Byte] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
  // 零明文 → ciphertext = keystream
  // C 实测:0xb9 0x76 0xcc 0xbb 0xc2 0x3b 0x32 0x25 0x0f 0xb0 0x18 0xdf 0x32 0x3a 0x68 0xaa
  let expected_keystream : FixedArray[Byte] = [
    0xb9, 0x76, 0xcc, 0xbb, 0xc2, 0x3b, 0x32, 0x25, 0x0f, 0xb0, 0x18, 0xdf, 0x32,
    0x3a, 0x68, 0xaa,
  ]
  let state = ChaChaState::new256(key)
  let state_with_iv = state.set_iv(iv, counter=0x0100000000000000UL)
  let zero_plaintext : FixedArray[Byte] = FixedArray::make(16, 0x00)
  let ciphertext = state_with_iv.process(zero_plaintext)
  assert_eq(ciphertext.length(), 16)
  for i = 0; i < 16; i = i + 1 {
    assert_eq(ciphertext[i], expected_keystream[i])
  }
}

///|
test "kat_TEST3_128bit_key_iv55" {
  // 128-bit key mode: key=[0xFF, 0xFE, ..., 0xF0], iv=[0x55]*8, counter=0
  let key : FixedArray[Byte] = FixedArray::make(16, 0x00)
  for i = 0; i < 16; i = i + 1 {
    key[i] = (0xFF - i).to_byte()
  }
  let iv : FixedArray[Byte] = FixedArray::make(8, 0x55)
  // C 实测(零明文):
  // 0xb5 0xc4 0x3f 0x9d 0x57 0xfd 0x76 0xcd 0xec 0xb7 0x37 0xa5 0x5f 0xa3 0x7c 0x8d
  let expected_keystream : FixedArray[Byte] = [
    0xb5, 0xc4, 0x3f, 0x9d, 0x57, 0xfd, 0x76, 0xcd, 0xec, 0xb7, 0x37, 0xa5, 0x5f,
    0xa3, 0x7c, 0x8d,
  ]
  let state = ChaChaState::new128(key)
  let state_with_iv = state.set_iv(iv)
  let zero_plaintext : FixedArray[Byte] = FixedArray::make(16, 0x00)
  let ciphertext = state_with_iv.process(zero_plaintext)
  assert_eq(ciphertext.length(), 16)
  for i = 0; i < 16; i = i + 1 {
    assert_eq(ciphertext[i], expected_keystream[i])
  }
}

///|
test "kat_64byte_block" {
  // 验证 64 字节整 block 也对得上 OpenSSH 输出
  // (TEST1 状态下完整的 64 字节 keystream)
  let key : FixedArray[Byte] = FixedArray::make(32, 0x00)
  let iv : FixedArray[Byte] = FixedArray::make(8, 0x00)
  let state = ChaChaState::new256(key)
  let state_with_iv = state.set_iv(iv)
  let zero_plaintext : FixedArray[Byte] = FixedArray::make(64, 0x00)
  let ciphertext = state_with_iv.process(zero_plaintext)
  // 来自 OpenSSH chacha.c 全 64 字节 keystream:
  // 76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
  // bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
  // da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
  // 6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
  let expected : FixedArray[Byte] = [
    0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53,
    0x86, 0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36,
    0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48,
    0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4,
    0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
  ]
  assert_eq(ciphertext.length(), 64)
  for i = 0; i < 64; i = i + 1 {
    assert_eq(ciphertext[i], expected[i])
  }
}
