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
    // RSA 需要协商出来的算法名(RFC 8332 下签名名不等于密钥类型名),
    // 所以无参的 `verify` 不做这件事,明确报告不可用。
    // 完整实现见 `verify_with_alg`。
    RsaKey(_, _) => Rejected(RsaVerifyUnavailable)
  }
}

///|
/// 便捷布尔
pub fn is_verified(res : VerifyResult) -> Bool {
  res is Accepted
}

// ---------------------------------------------------------------------------
// RFC 8332: the signature algorithm name is not the key type
// ---------------------------------------------------------------------------

///|
/// 签名 blob 里的算法名 → 摘要(ssh-rsa.c:328-338 `rsa_hash_id_from_ident`)。
///
/// `ssh-rsa` 映射到 SHA-1,而本项目没有 SHA-1,所以返回 None。这一条是**主动**
/// 不支持而不是遗漏:OpenSSH 8.8 起默认关闭 `ssh-rsa`,而客户端若报了这个名字
/// 却验不了,握手的失败点会被推迟到验签那一步,报错还会指向一个根本没选中的
/// 算法。不报它,失败发生在协商阶段,信息准确得多。
pub fn rsa_digest_of_sigtype(sigtype : String) -> Int? {
  if sigtype == "rsa-sha2-256" {
    Some(@rsa.RSA_DIGEST_SHA256)
  } else if sigtype == "rsa-sha2-512" {
    Some(@rsa.RSA_DIGEST_SHA512)
  } else {
    None
  }
}

///|
/// 协商出的主机密钥算法名 → 摘要(ssh-rsa.c:345-359 `ssh_rsa_hash_id_from_keyname`)。
///
/// 非证书路径上它与 `rsa_digest_of_sigtype` 接受同样的名字,但 C 里是两个函数
/// ——keyname 那份还接受 `*-cert-v01@openssh.com`。保持两个函数,是因为把
/// 「签名类型」和「密钥类型」合成一个,正是 RFC 8332 存在之前最容易犯的那个错。
pub fn rsa_digest_of_keyname(alg : String) -> Int? {
  rsa_digest_of_sigtype(alg)
}

///|
/// 密钥自己的类型名与位数,纯报告用。
///
/// RSA 这一项返回的是 `"ssh-rsa"`——**密钥 blob 里的类型串**,不是协商出的
/// 算法名。报告里同时印着 `hostkey_alg` 和 `hostkey_type` 两个字段正是为了
/// 让这个区别看得见:RFC 8332 下它们本来就不同,只有 `rsa-sha2-*` 那一栏会变。
pub fn HostKey::describe(self : HostKey) -> (String, Int) {
  match self {
    Ed25519Key(_) => ("ssh-ed25519", 256)
    EcdsaKey(bits, _) => {
      let name = if bits == 256 {
        "ecdsa-sha2-nistp256"
      } else {
        "ecdsa-sha2-nistp384"
      }
      (name, bits)
    }
    RsaKey(_, n_bytes) => ("ssh-rsa", n_bytes.length() * 8)
  }
}

///|
/// Loop #61: the algorithm-name lists live here, once.
///
/// `agrees_with_alg` used to spell its names inline. That was fine while the
/// only consumer was the pairwise question "does this key match this name",
/// but it left no way to answer the set question -- "which names can this
/// client actually verify?" -- without a second hand-written list, which is
/// exactly the drift Loop #60 removed from `src/kex_names`. So the names are
/// named, and `verifiable_alg_names` below is their union.
///
/// `ssh-rsa` is absent on purpose: `rsa_digest_of_sigtype` maps it to SHA-1,
/// which this project does not have. Advertising it and failing later at
/// verify time would blame an algorithm that was never selected.
fn ed25519_alg_names() -> Array[String] {
  ["ssh-ed25519"]
}

fn ecdsa_p256_alg_names() -> Array[String] {
  ["ecdsa-sha2-nistp256"]
}

fn ecdsa_p384_alg_names() -> Array[String] {
  ["ecdsa-sha2-nistp384"]
}

///| RFC 8332 names only -- the blob's own type string `ssh-rsa` is not here.
fn rsa_alg_names() -> Array[String] {
  ["rsa-sha2-256", "rsa-sha2-512"]
}

///|
/// Every host key algorithm name this client can verify, in a stable order.
///
/// This is the union of the four lists above, not an independent list. If a
/// key type ever gains a name, exactly one place changes.
pub fn verifiable_alg_names() -> Array[String] {
  let out : Array[String] = []
  for n in ed25519_alg_names() {
    out.push(n)
  }
  for n in ecdsa_p256_alg_names() {
    out.push(n)
  }
  for n in ecdsa_p384_alg_names() {
    out.push(n)
  }
  for n in rsa_alg_names() {
    out.push(n)
  }
  out
}

///|
/// Is `alg` a host key algorithm name this client can verify?
pub fn is_verifiable_alg(alg : String) -> Bool {
  for n in verifiable_alg_names() {
    if n == alg {
      return true
    }
  }
  false
}

///|
/// 这个密钥与协商出的算法名 `alg` 是否配对。
///
/// 这是两条传输层驱动原来**各自**抄了一份的规则,而 RFC 8332 正好把它变成
/// 一条容易被抄错的规则:ed25519 / ECDSA 的名字由密钥类型唯一决定,RSA 的不是。
/// 所以它住在 `src/hostkey`,不在驱动里——驱动只问「配不配对」。
///
/// ed25519 / ECDSA 是精确相等;RSA 是 `ssh_rsa_hash_id_from_keyname` 认得这个名字
/// (ssh-rsa.c:345-359),也就是 RFC 8332 的两个名字。`ssh-rsa` 不在其中,因为它
/// 映射到本项目没有的 SHA-1。
pub fn HostKey::agrees_with_alg(self : HostKey, alg : String) -> Bool {
  match self {
    Ed25519Key(_) => ed25519_alg_names().contains(alg)
    EcdsaKey(bits, _) =>
      if bits == 256 {
        ecdsa_p256_alg_names().contains(alg)
      } else {
        ecdsa_p384_alg_names().contains(alg)
      }
    RsaKey(_, _) =>
      match rsa_digest_of_keyname(alg) {
        Some(_) => true
        None => false
      }
  }
}

///|
/// 带协商算法名的完整验证(Loop #38)。
///
/// `negotiated_alg` 是 KEX 协商出来的**主机密钥算法名**,不是密钥 blob 里的类型串。
/// RSA 分支需要它,因为 RFC 8332 下这三个名字可以互不相同:
///
///   * 密钥 blob 的类型串  : `ssh-rsa`(SHA-1 时代的名字,一直沿用)
///   * 协商出的算法名    : `rsa-sha2-256` / `rsa-sha2-512`
///   * 签名 blob 的算法名: 与协商结果相同
///
/// 照 `ssh-ed25519` 的模板写成「签名名必须等于密钥类型」会把每一条 RFC 8332
/// 签名都拒掉,而且拒得很干净——报 TypeMismatch,指向一个看起来没问题的名字。
/// C 的判据在 `ssh-rsa.c:526-535`:两个名字各自解析成摘要,**摘要必须相等**。
pub fn HostKey::verify_with_alg(
  self : HostKey,
  msg : FixedArray[Byte],
  sig_blob : FixedArray[Byte],
  negotiated_alg : String,
) -> VerifyResult {
  if !HostKey::agrees_with_alg(self, negotiated_alg) {
    return Rejected(TypeMismatch)
  }
  match self {
    RsaKey(e_bytes, n_bytes) =>
      rsa_verify_sig(msg, sig_blob, negotiated_alg, e_bytes, n_bytes)
    _ => self.verify(msg, sig_blob)
  }
}

///|
/// `ssh_rsa_verify` 的顺序转写(ssh-rsa.c:490-570)。逐步对应:
///
///   :509-510  n < 1024 位                   → RsaModulusTooShort
///   :514-517  get_cstring(sigtype)          → InvalidFormat
///   :518-521  rsa_hash_id_from_ident        → TypeMismatch
///   :526-535  两个名字解析出的摘要必须相等    → SignatureInvalid
///   :536-539  get_string(sigblob)           → InvalidFormat
///   :540-543  尾部残余                      → TrailingData
///   :544-560  len > modlen 报错;len < modlen 左补零
///   :568      PKCS#1 v1.5 摘要验证
fn rsa_verify_sig(
  msg : FixedArray[Byte],
  sig_blob : FixedArray[Byte],
  negotiated_alg : String,
  e_bytes : FixedArray[Byte],
  n_bytes : FixedArray[Byte],
) -> VerifyResult {
  // :509-510 —— sshkey.h:53 SSH_RSA_MINIMUM_MODULUS_SIZE = 1024
  if n_bytes.length() * 8 < RSA_MIN_MODULUS_BITS {
    return Rejected(RsaModulusTooShort)
  }
  let cur = HkCursor::new(sig_blob)
  let sigtype = cur.get_cstring()
  if cur.err is Some(_) {
    return Rejected(InvalidFormat)
  }
  // :518-521 —— 未知签名名(含 ssh-rsa / SHA-1)一律 KeyTypeMismatch
  let sig_digest = match rsa_digest_of_sigtype(sigtype) {
    None => return Rejected(TypeMismatch)
    Some(d) => d
  }
  // :526-535 —— 协商名解析不了是 InvalidArgument,不匹配是 SignatureInvalid
  let want_digest = match rsa_digest_of_keyname(negotiated_alg) {
    None => return Rejected(InvalidArgument)
    Some(d) => d
  }
  if sig_digest != want_digest {
    return Rejected(SignatureInvalid)
  }
  let rs = cur.get_string()
  if cur.err is Some(_) {
    return Rejected(InvalidFormat)
  }
  // :540-543
  if cur.remaining() != 0 {
    return Rejected(TrailingData)
  }
  // :544-560 —— 短签名左补零,长签名报错。
  // 这段不是可有可无的:签名整数的前导零在 SSH 里可能被剥掉,不补零的话一个
  // 完全合法的签名会因为 `em` 整体左移而被 PKCS#1 解析拒绝。
  let modlen = n_bytes.length()
  if rs.length() > modlen {
    return Rejected(KeyBitsMismatch)
  }
  let padded = FixedArray::make(modlen, b'\x00')
  let off = modlen - rs.length()
  for i = 0; i < rs.length(); i = i + 1 {
    padded[off + i] = rs[i]
  }
  let n = @bigint.BigNat::from_bytes_be(n_bytes)
  let e = @bigint.BigNat::from_bytes_be(e_bytes)
  if @rsa.rsa_verify_pkcs1(n, e, padded, msg, sig_digest) {
    Accepted
  } else {
    Rejected(SignatureInvalid)
  }
}
