///| RSA host key verify + sign (Loop #27 G3; Loop #38 generalised the digest)

///| SHA-256 DigestInfo prefix. RFC 8017 §9.2 note 1 / RFC 6234:
///   SEQUENCE { SEQUENCE { OID id-sha256 (2.16.840.1.101.3.4.2.1), NULL }
///              OCTET STRING (32 bytes) }
let sha256_digest_info_prefix : FixedArray[Byte] = FixedArray::from_array([
  0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
  0x00, 0x04, 0x20,
])

///|
/// SHA-512 DigestInfo prefix. Same shape, different OID arc and a 64-byte
/// OCTET STRING:
///   SEQUENCE { SEQUENCE { OID id-sha512 (2.16.840.1.101.3.4.2.3), NULL }
///              OCTET STRING (64 bytes) }
/// The enclosing length is 0x51 = 15 (AlgId) + 2 (tag+len) + 64.
///
/// Both prefixes are 19 bytes, which is a coincidence of the DER layout rather
/// than something to rely on: the parser takes the prefix as an argument
/// instead of assuming a length.
let sha512_digest_info_prefix : FixedArray[Byte] = FixedArray::from_array([
  0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
  0x00, 0x04, 0x40,
])

///| 摘要选择(RFC 8017 允许的、SSH 主机密钥实际用到的两个)
pub const RSA_DIGEST_SHA256 : Int = 1

///|
pub const RSA_DIGEST_SHA512 : Int = 2

///| DigestInfo 前缀;未知摘要返回 None
pub fn rsa_digest_info_prefix(digest : Int) -> FixedArray[Byte]? {
  if digest == RSA_DIGEST_SHA512 {
    Some(sha512_digest_info_prefix)
  } else if digest == RSA_DIGEST_SHA256 {
    Some(sha256_digest_info_prefix)
  } else {
    None
  }
}

///| 对消息取指定摘要
pub fn rsa_digest(msg : FixedArray[Byte], digest : Int) -> FixedArray[Byte]? {
  if digest == RSA_DIGEST_SHA512 {
    Some(@sha512.sha512(msg))
  } else if digest == RSA_DIGEST_SHA256 {
    Some(@sha256.sha256(msg))
  } else {
    None
  }
}

///|
/// PKCS#1 v1.5 的填充串最少 8 个 0xFF(RFC 8017 §9.2)。
///
/// 这一条以前没查,所以一条填充短于 8 字节的签名也会被放行。OpenSSL 的
/// `RSA_verify` 会拒绝这种编码,所以我们过去比 C 更宽松——这种方向的偏差
/// 只有在对拍一个刻意构造的畸形签名时才会露出来。
pub const RSA_PKCS1_MIN_FF : Int = 8

///|
/// Parse PKCS#1 v1.5 padded RSA signature bytes, given the DigestInfo prefix.
///
///   Expected: 0x00 0x01 [0xFF * PS >= 8] 0x00 [prefix] [hash]
///
/// 返回 true 当且仅当 em 逐字节符合上面的形状。比较是逐字节提前返回的,
/// 不是常数时间——RSA 公钥验证的时序泄漏在本项目里未做处理,别把它当成
/// 已解决。
pub fn rsa_parse_pkcs1_prefix(
  em : FixedArray[Byte],
  prefix : FixedArray[Byte],
  hash : FixedArray[Byte],
) -> Bool {
  if em.length() < 3 { return false }
  if em[0] != b'\x00' { return false }
  if em[1] != b'\x01' { return false }
  // Find 0x00 separator after 0xFF padding
  let mut i = 2
  let mut found_zero = false
  while i < em.length() {
    if em[i] == b'\x00' {
      // PS 是紧贴这个分隔符的那串 0xFF,所以要在跨过分隔符**之前**数它。
      // 跨过去再数会把分隔符自己算成一个填充字节,于是 7 个 0xFF 的签名也会
      // 被放行 —— RFC 8017 §9.2 要求至少 8 个,OpenSSL 会拒。
      if i - 2 < RSA_PKCS1_MIN_FF {
        return false
      }
      found_zero = true
      i = i + 1
      break
    }
    if em[i] != b'\xFF' { return false }
    i = i + 1
  }
  if !found_zero { return false }
  let t_len = prefix.length() + hash.length()
  if i > em.length() - t_len { return false }
  // Check DigestInfo prefix at position i
  let mut k = 0
  while k < prefix.length() {
    if em[i + k] != prefix[k] {
      return false
    }
    k = k + 1
  }
  let hash_start = i + prefix.length()
  let mut j = 0
  while j < hash.length() {
    if em[hash_start + j] != hash[j] {
      return false
    }
    j = j + 1
  }
  true
}

///| SHA-256 的 `rsa_parse_pkcs1`(保留给既有调用方)
pub fn rsa_parse_pkcs1(em : FixedArray[Byte], hash : FixedArray[Byte]) -> Bool {
  rsa_parse_pkcs1_prefix(em, sha256_digest_info_prefix, hash)
}

///|
/// RSA verify PKCS#1 v1.5 signature for SHA-256
///
///   Uses the Montgomery fast path (see `bigint/mont64.mbt`) for odd moduli,
///   which is every real RSA modulus. `verify.mbt` was last measured at
///   ~0.3 ms per 2048-bit verify, down from ~7.7 ms on the schoolbook path.
pub fn rsa_verify_pkcs1_sha256(n : @bigint.BigNat, e : @bigint.BigNat, sig : FixedArray[Byte], msg : FixedArray[Byte]) -> Bool {
  rsa_verify_pkcs1(n, e, sig, msg, RSA_DIGEST_SHA256)
}

///|
/// RSA verify PKCS#1 v1.5 with an explicit digest.
///
/// `digest` 决定两件事:摘要算法和 DigestInfo 前缀。这两件事必须一起换——
/// 只换摘要会得到一个形状对不上的 EM,PKCS#1 解析直接失败。SHA-1 刻意**不在**
/// 这里:`ssh-rsa` 这个名字映射到 SHA-1(ssh-rsa.c:331-332),而本项目没有
/// SHA-1,OpenSSH 8.8 起也默认关闭该算法,所以客户端干脆不报它。
pub fn rsa_verify_pkcs1(
  n : @bigint.BigNat,
  e : @bigint.BigNat,
  sig : FixedArray[Byte],
  msg : FixedArray[Byte],
  digest : Int,
) -> Bool {
  let sig_big = @bigint.BigNat::from_bytes_be(sig)
  let m = @bigint.BigNat::mod_pow_auto(sig_big, e, n)
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
  match rsa_parse_prefixed(padded, msg, digest) {
    None => false
    Some(ok) => ok
  }
}

///| 摘要 + 前缀一起取,任一未知则 None
fn rsa_parse_prefixed(
  em : FixedArray[Byte],
  msg : FixedArray[Byte],
  digest : Int,
) -> Bool? {
  match rsa_digest_info_prefix(digest) {
    None => None
    Some(prefix) =>
      match rsa_digest(msg, digest) {
        None => None
        Some(hash) => Some(rsa_parse_pkcs1_prefix(em, prefix, hash))
      }
  }
}

///| RSA verify with a pre-built Montgomery context.
///
///   An SSH session pins one host key, so `n'` and `R^2` can be computed once
///   and reused for every verification instead of once per call.
pub fn rsa_verify_ctx(
  ctx : @bigint.MontCtx,
  n : @bigint.BigNat,
  e : @bigint.BigNat,
  sig : FixedArray[Byte],
  msg : FixedArray[Byte],
  digest : Int,
) -> Bool {
  let sig_big = @bigint.BigNat::from_bytes_be(sig)
  let m = @bigint.mont_pow_with(ctx, sig_big, e)
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
  match rsa_parse_prefixed(padded, msg, digest) {
    None => false
    Some(ok) => ok
  }
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
  let sig_big = @bigint.BigNat::mod_pow_auto(em_big, d, n)
  @bigint.BigNat::to_bytes_be(sig_big)
}