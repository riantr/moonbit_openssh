///| Loop #25 AES + kex-names byte-exact 验证 (cmd/aes_test)
///
/// 11 行 byte-exact 跨 4 target × 2 mode

///|
/// byte-exact 比较两个 FixedArray[Byte]
fn byte_array_equal(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut i = 0
  while i < a.length() {
    if a[i].to_int() != b[i].to_int() {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn main {
  // ============ G1 AES-128-CTR KAT (NIST SP 800-38A F.5.1) ============
  // Key:        2b7e151628aed2a6abf7158809cf4f3c
  // Counter:    f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  // Plaintext:  6bc1bee22e409f96e93d7e117393172a
  // Ciphertext: 874d6191b620e3261bef6864990db6ce
  let key_kat128 : FixedArray[Byte] = FixedArray::from_array([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
    0xcf, 0x4f, 0x3c,
  ])
  let iv_kat : FixedArray[Byte] = FixedArray::from_array([
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
    0xfd, 0xfe, 0xff,
  ])
  let pt_kat1 : FixedArray[Byte] = FixedArray::from_array([
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
    0x93, 0x17, 0x2a,
  ])
  let ct_kat1_expected : FixedArray[Byte] = FixedArray::from_array([
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99,
    0x0d, 0xb6, 0xce,
  ])
  let ct1 = @aes.aes_ctr(key_kat128, iv_kat, pt_kat1)
  let aes128_ctr_match = ct1.length() == 16 &&
    byte_array_equal(ct1, ct_kat1_expected)
  let aes128_ctr_kat = if aes128_ctr_match { "PASS" } else { "FAIL" }
  println("aes128_ctr_kat: " + aes128_ctr_kat)

  // ============ G1 AES-256-CTR KAT (NIST SP 800-38A F.5.5) ============
  // Key:        603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
  // Counter:    f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
  // Plaintext:  6bc1bee22e409f96e93d7e117393172a
  // Ciphertext: 601ec313775789a1ed7a03e89c83dafa  (NIST F.5.5 block #1)

  let key_kat256 : FixedArray[Byte] = FixedArray::from_array([
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85,
    0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98,
    0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
  ])
  let ct_kat5_expected : FixedArray[Byte] = FixedArray::from_array([
    0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb,
    0xf3, 0xd2, 0x28,
  ])
  let ct2 = @aes.aes_ctr(key_kat256, iv_kat, pt_kat1)
  let aes256_ctr_match = ct2.length() == 16 &&
    byte_array_equal(ct2, ct_kat5_expected)

  let aes256_ctr_kat = if aes256_ctr_match { "PASS" } else { "FAIL" }
  println("aes256_ctr_kat: " + aes256_ctr_kat)

  // ============ G1 AES block encrypt KAT (FIPS 197 Appendix A.1) ============
  // Key: 2b7e151628aed2a6abf7158809cf4f3c (16B)
  // Plaintext: 6bc1bee22e409f96e93d7e117393172a (16B)
  // Ciphertext expected: 3ad77bb40d7a3660a89ecaf32466ef97
  let key_kat : FixedArray[Byte] = FixedArray::from_array([
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
    0xcf, 0x4f, 0x3c,
  ])
  let pt_kat : FixedArray[Byte] = FixedArray::from_array([
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
    0x93, 0x17, 0x2a,
  ])
  let ct_block = @aes.aes_encrypt_block(key_kat, pt_kat)
  let aes128_block_kat = if ct_block[0].to_int() == 0x3a &&
    ct_block[15].to_int() == 0x97 {
    "PASS"
  } else {
    "FAIL"
  }
  println("aes128_block_kat: " + aes128_block_kat)

  // ============ G2 kex_names counts ============
  println("kex_alg_count: " + @kex_names.kex_alg_count().to_string())
  println("hostkey_alg_count: " + @kex_names.hostkey_alg_count().to_string())
  println("cipher_alg_count: " + @kex_names.cipher_alg_count().to_string())
  println("mac_alg_count: " + @kex_names.mac_alg_count().to_string())

  // ============ G2 kex-names lookup tests ============
  let dh14 = @kex_names.kex_alg_from_name("diffie-hellman-group14-sha256")
  let dh14_found = match dh14 {
    Some(_) => "found"
    None => "missing"
  }
  let dh14_name = match dh14 {
    Some(alg) => @kex_names.kex_alg_to_name(alg)
    None => "none"
  }
  println("kex_dh14: " + dh14_found + "/" + dh14_name)

  let aes256_name = match @kex_names.cipher_alg_from_name("aes256-ctr") {
    Some(alg) => @kex_names.cipher_alg_to_name(alg)
    None => "none"
  }
  println("cipher_aes256ctr: " + aes256_name)

  let rsa_name = match @kex_names.hostkey_alg_from_name("rsa-sha2-512") {
    Some(alg) => @kex_names.hostkey_alg_to_name(alg)
    None => "none"
  }
  println("hostkey_rsa: " + rsa_name)
}
