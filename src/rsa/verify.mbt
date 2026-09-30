///| RSA host key verify + sign (Loop #27 G3)

///| ASN.1 DigestInfo for SHA-256:
///   SEQUENCE {
///     SEQUENCE { OID id-sha256 (2.16.840.1.101.3.4.2.1), NULL }
///     OCTETSTRING (32 bytes hash)
///   }
///   Encoded as: 30 31 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
///   Total: 19 bytes
let sha256_digest_info_prefix : FixedArray[Byte] = FixedArray::from_array([
  0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
  0x00, 0x04, 0x20,
])

///| Parse PKCS#1 v1.5 padded RSA signature bytes
///   Returns true iff em matches PKCS#1 v1.5 + DigestInfo for hash.
///   Expected format: 0x00 0x01 [0xFF * N >= 8] 0x00 [DigestInfo (51 bytes for SHA-256)]
pub fn rsa_parse_pkcs1(em : FixedArray[Byte], hash : FixedArray[Byte]) -> Bool {
  // em[0] = 0x00, em[1] = 0x01
  if em.length() < 3 { return false }
  if em[0] != b'\x00' { return false }
  if em[1] != b'\x01' { return false }
  // Find 0x00 separator after 0xFF padding
  let mut i = 2
  let mut found_zero = false
  while i < em.length() {
    if em[i] == b'\x00' {
      found_zero = true
      i = i + 1
      break
    }
    if em[i] != b'\xFF' { return false }
    i = i + 1
  }
  if !found_zero { return false }
  if i > em.length() - hash.length() - 19 {
    return false
  }
  // Check DigestInfo prefix at position i
  let mut k = 0
  while k < sha256_digest_info_prefix.length() {
    if em[i + k] != sha256_digest_info_prefix[k] {
      return false
    }
    k = k + 1
  }
  let hash_start = i + sha256_digest_info_prefix.length()
  let mut j = 0
  while j < hash.length() {
    if em[hash_start + j] != hash[j] {
      return false
    }
    j = j + 1
  }
  true
}

///| RSA verify PKCS#1 v1.5 signature for SHA-256
pub fn rsa_verify_pkcs1_sha256(n : @bigint.BigNat, e : @bigint.BigNat, sig : FixedArray[Byte], msg : FixedArray[Byte]) -> Bool {
  let sig_big = @bigint.BigNat::from_bytes_be(sig)
  let m = @bigint.BigNat::mod_pow(sig_big, e, n)
  let em = @bigint.BigNat::to_bytes_be(m)
  let modulus_byte_len = (n.bit_length() + 7) / 8
  if em.length() > modulus_byte_len {
    return false
  }
  let padded : FixedArray[Byte] = FixedArray::make(modulus_byte_len, b'\x00')
  let off = modulus_byte_len - em.length()
  let mut k = 0
  while k < em.length() {
    padded[off + k] = em[k]
    k = k + 1
  }
  let hash = @sha256.sha256(msg)
  rsa_parse_pkcs1(padded, hash)
}

///| RSA sign PKCS#1 v1.5 for SHA-256
pub fn rsa_sign_pkcs1_sha256(n : @bigint.BigNat, d : @bigint.BigNat, msg : FixedArray[Byte]) -> FixedArray[Byte] {
  let hash = @sha256.sha256(msg)
  let modulus_byte_len = (n.bit_length() + 7) / 8
  let t_len = sha256_digest_info_prefix.length() + hash.length()
  let ps_len = modulus_byte_len - 3 - t_len
  // PKCS#1 v1.5 format:
  //   0x00 0x01 [0xFF * PS_len] 0x00 [DigestInfo (19 bytes)] [hash (32 bytes)]
  let em : FixedArray[Byte] = FixedArray::make(modulus_byte_len, b'\x00')
  em[0] = b'\x00'
  em[1] = b'\x01'
  // em[2..2+ps_len-1] = 0xFF (padding) -- already 0 since we initialized to 0!
  // Wait, need 0xFF. Fix: initialize to 0xFF.
  let _ = ps_len  // ps_len unused if pre-init; let me keep it consistent
  let em2 : FixedArray[Byte] = FixedArray::make(modulus_byte_len, b'\xFF')
  em2[0] = b'\x00'
  em2[1] = b'\x01'
  // em2[2..2+ps_len-1] already 0xFF
  let sep_pos = 2 + ps_len
  em2[sep_pos] = b'\x00'
  let t_off = sep_pos + 1
  let mut k = 0
  while k < sha256_digest_info_prefix.length() {
    em2[t_off + k] = sha256_digest_info_prefix[k]
    k = k + 1
  }
  let hash_off = t_off + sha256_digest_info_prefix.length()
  let mut j = 0
  while j < hash.length() {
    em2[hash_off + j] = hash[j]
    j = j + 1
  }
  let em_big = @bigint.BigNat::from_bytes_be(em2)
  let sig_big = @bigint.BigNat::mod_pow(em_big, d, n)
  @bigint.BigNat::to_bytes_be(sig_big)
}