///| 签名 blob 解析与验证
///
/// 对应 sshkey.c sshkey_verify(2237-2250,外层前置)+ ssh-ed25519.c
/// ssh_ed25519_verify(232-300,精确顺序转写):
///   前置 → get_cstring/get_string_direct → alg 比较(TypeMismatch)
///   → 尾部残余(TrailingData)→ len>64(InvalidFormat)
///   → len<64 放行进 open 必败(等价捷径 SignatureInvalid)

///|
/// 验证一条签名(navigator §3 完整顺序)
pub fn HostKey::verify(
  self : HostKey,
  msg : FixedArray[Byte],
  sig_blob : FixedArray[Byte],
) -> VerifyResult {
  // sshkey.c:2244-2245 前置(先于 impl 分派)
  if sig_blob.length() == 0 || msg.length() > MAX_SIGN_DATA_SIZE {
    return Rejected(InvalidArgument)
  }
  match self {
    Ed25519Key(pk) => {
      // ssh_ed25519.c:244-247:get_cstring(alg) + get_string_direct(rs);
      // 缓冲不足/越界(MESSAGE_INCOMPLETE 族)→ InvalidFormat
      let cur = HkCursor::new(sig_blob)
      let alg = cur.get_cstring()
      if cur.err is Some(_) {
        return Rejected(InvalidFormat)
      }
      let rs = cur.get_string()
      if cur.err is Some(_) {
        return Rejected(InvalidFormat)
      }
      // ssh-ed25519.c:248-251 alg 精确匹配 —— 先于 trailing 检查
      if alg != "ssh-ed25519" {
        return Rejected(TypeMismatch)
      }
      // ssh-ed25519.c:252-255 sig blob 尾部残余
      if cur.remaining() != 0 {
        return Rejected(TrailingData)
      }
      // ssh-ed25519.c:256-259 len > crypto_sign_ed25519_BYTES
      if rs.length() > 64 {
        return Rejected(InvalidFormat)
      }
      if rs.length() != 64 {
        // C 放行 len<64 进 crypto_sign_ed25519_open,open 必败 →
        // SIGNATURE_INVALID;此处等价捷径(navigator §3 注明)
        return Rejected(SignatureInvalid)
      }
      // Loop #7 ed25519:verify(sig, msg, pk)
      if verify(rs, msg, pk) {
        Accepted
      } else {
        Rejected(SignatureInvalid)
      }
    }
    // ECDSA (ssh_ecdsa_verify, ssh-ecdsa.c) 的检查顺序:
    //   get_cstring(alg) + get_string(inner)  → InvalidFormat
    //   alg 与 key 类型不符                    → TypeMismatch (先于尾部残余)
    //   外层尾部残余                            → TrailingData
    //   inner: get_bignum2(r) + get_bignum2(s)  → InvalidFormat
    //   inner 尾部残余                          → TrailingData
    //   随后进密码学层
    EcdsaKey(bits, qbytes) => {
      let name = if bits == 256 { "nistp256" } else { "nistp384" }
      let want_alg = if bits == 256 {
        "ecdsa-sha2-nistp256"
      } else {
        "ecdsa-sha2-nistp384"
      }
      let outer = HkCursor::new(sig_blob)
      let ealg = outer.get_cstring()
      if outer.err is Some(_) {
        return Rejected(InvalidFormat)
      }
      let inner = outer.get_string()
      if outer.err is Some(_) {
        return Rejected(InvalidFormat)
      }
      if ealg != want_alg {
        return Rejected(TypeMismatch)
      }
      if outer.remaining() != 0 {
        return Rejected(TrailingData)
      }
      let icur = HkCursor::new(inner)
      let r = icur.get_bignum2()
      if icur.err is Some(_) {
        return Rejected(InvalidFormat)
      }
      let s = icur.get_bignum2()
      if icur.err is Some(_) {
        return Rejected(InvalidFormat)
      }
      if icur.remaining() != 0 {
        return Rejected(TrailingData)
      }
      match @ecdsa.Curve::from_name(name) {
        None => Rejected(UnsupportedType)
        Some(c) =>
          match @ecdsa.decode_point(c, qbytes) {
            None => Rejected(KeyInvalidEcValue)
            Some(q) => {
              let sig = @ecdsa.Signature::new(
                @bigint.BigNat::from_bytes_be(r),
                @bigint.BigNat::from_bytes_be(s),
              )
              if @ecdsa.ecdsa_verify(c, q, sig, msg) {
                Accepted
              } else {
                Rejected(SignatureInvalid)
              }
            }
          }
      }
    }
    // RSA 验证需 bignum modexp——本 loop 范围外,显式标注。
    // 注:C 的 ssh_rsa_verify 会先做自身结构解析再进密码学层;
    // 本实现不细分结构错误,一律显式 Unavailable(报告注明)。
    RsaKey(_, _) => Rejected(RsaVerifyUnavailable)
  }
}

///|
/// 便捷布尔
pub fn is_verified(res : VerifyResult) -> Bool {
  res is Accepted
}
