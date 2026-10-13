///| 主机证书验证（sshkey.c sshkey_cert_check_authority）
///
///| 一张证书能代替一把裸主机密钥，条件有六条，少一条都不行：
///
///|   1. 证书的 signature key 字段**字节等于**我们 pin 的那把 CA 公钥
///|   2. CA 对 signed_data 的签名成立（signed_data 含类型名与 signature key 字段，
///|      见 cert.mbt；**不是** nonce..reserved）
///|   3. cert type 是 host（不是 user）
///|   4. now 落在 [valid_after, valid_before] 里
///|   5. principal 列表为空（对所有 principal 有效）或包含这台主机
///|   6. critical options 为空
///
///| **检查顺序是刻意的：CA 验签排在所有语义检查之前。** 证书里每一个字段都是
///| 对端给的，在验签通过之前它们全是不可信的输入。先看 cert type 再验签，听起来
///| 只是「错误信息更好看」，但它会在验签之前把对端的字节喂进分支判断；而且这种
///| 顺序一旦被后人「优化」过就没有任何测试会红——因为每一条检查各自都还是绿的。
///| 所以这里把它写成一条不可协商的规则：验签不过，后面一个字段都不读。
///
///| 时钟由调用方传入。本包没有时间源，而有效期判定必须可重放：门禁要在同一天
///| 反复跑「过期证书必须被拒」，能读到墙上时钟的话这条断言在写出来当天之后就
///| 永远为真了，等于没有。

///|
/// 证书为什么被拒
pub(all) enum CertFailure {
  /// blob 解析不出来
  Malformed
  /// 证书的 signature key 字段不是我们 pin 的那把 CA
  CaNotPinned
  /// CA 验签不过（含签名 blob 结构不对、算法名与 CA 类型不符）
  CaSignatureInvalid
  /// 这是**用户**证书，不能当主机身份用
  NotHostCertificate
  /// 还没到生效时间
  NotYetValid
  /// 已过期
  Expired
  /// principal 列表不含这台主机
  PrincipalMismatch
  /// 带了我们不实现的 critical option
  UnsupportedCriticalOption
  /// 内层公钥解析失败
  InnerKeyUnsupported
}

///|
pub(all) enum CertVerdict {
  /// 证书可信。里面是**内层**主机公钥——握手签名要用它验，而不是用 CA。
  Trusted(HostKey)
  Rejected(CertFailure)
}

///|
/// 字节相等
fn cert_bytes_eq(
  a : FixedArray[Byte],
  b : FixedArray[Byte],
) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
/// 从签名 blob 里取算法名（签名 blob 自带算法名字符串）
fn sig_blob_alg(sig : FixedArray[Byte]) -> String {
  let cur = HkCursor::new(sig)
  let alg = cur.get_cstring()
  if cur.err is Some(_) {
    return ""
  }
  alg
}

///|
/// 验一张主机证书
///
///| `ca_blob` 是 known_hosts 里 `@cert-authority` 那一行的 blob（可信输入）；
///| `principal` 是我们要连的那台主机的名字，即证书必须声称的主机名；
///| `now` 是 Unix 秒，由调用方注入。
pub fn verify_host_cert(
  cert_blob : FixedArray[Byte],
  ca_blob : FixedArray[Byte],
  principal : String,
  now : UInt64,
) -> CertVerdict {
  let cert = match HostCert::from_blob(cert_blob) {
    Rejected(_) => return CertVerdict::Rejected(Malformed)
    Parsed(c) => c
  }
  // (1) 证书声称的签发者必须就是我们 pin 的这把 CA。
  //     注意这一步也比「只比对 CA 条目的 host 模式」强：known_hosts 里的 CA 条目
  //     可能同时覆盖多台主机，但对端出示的证书必须指名它自己。
  if !cert_bytes_eq(cert.sig_key, ca_blob) {
    return CertVerdict::Rejected(CaNotPinned)
  }
  // (2) CA 签名。算法名取自签名 blob 本身，但必须与 CA 的钥匙类型配对——
  //     agrees_with_alg 就是那条配对规则（ed25519/ecdsa 精确相等，RSA 只认
  //     rsa-sha2-*），它同时挡住了「签名 blob 自称是证书类型名」这类混淆。
  let ca_key = match HostKey::from_blob(ca_blob) {
    Rejected(_) => return CertVerdict::Rejected(CaNotPinned)
    Parsed(k) => k
  }
  let alg = sig_blob_alg(cert.signature)
  if !HostKey::agrees_with_alg(ca_key, alg) {
    return CertVerdict::Rejected(CaSignatureInvalid)
  }
  match HostKey::verify_with_alg(ca_key, cert.signed_data, cert.signature, alg) {
    Rejected(_) => return CertVerdict::Rejected(CaSignatureInvalid)
    Accepted => ()
  }
  // 验签过了，从这里往下的字段才可信。
  // (3) 用户证书不是主机身份。SSH_CERT_TYPE_USER=1 / HOST=2，见 cert.mbt 的常量说明。
  if cert.cert_type != SSH_CERT_TYPE_HOST {
    return CertVerdict::Rejected(NotHostCertificate)
  }
  // (4) 有效期。两端都闭区间——OpenSSH 的判定是
  //     `now < valid_after || now > valid_before` 即失效。
  if now < cert.valid_after {
    return CertVerdict::Rejected(NotYetValid)
  }
  if now > cert.valid_before {
    return CertVerdict::Rejected(Expired)
  }
  // (5) principal。空列表 = 对所有 principal 有效（OpenSSH 的语义）。
  if cert.principals.length() > 0 {
    let mut hit = false
    for i = 0; i < cert.principals.length(); i = i + 1 {
      if cert.principals[i] == principal {
        hit = true
        break
      }
    }
    if !hit {
      return CertVerdict::Rejected(PrincipalMismatch)
    }
  }
  // (6) critical options。主机证书能带的是 force-command / source-address，
  //     两者都是**服务器**侧的东西；客户端不执行它们。放着不管等于收下一张
  //     「附带了约束条款」的证书却不兑现它，所以这里直接拒，而不是忽略。
  if cert.critical_options.length() != 0 {
    return CertVerdict::Rejected(UnsupportedCriticalOption)
  }
  // 最后才取内层钥匙。
  match HostKey::from_blob(cert.inner_key_blob) {
    Rejected(_) => CertVerdict::Rejected(InnerKeyUnsupported)
    Parsed(inner) => CertVerdict::Trusted(inner)
  }
}

///|
/// 这个 blob 是不是一张证书（只读第一个字符串，不做完整解析）
///
/// 给「先判断类型再决定走哪条路」的场景用。它**不**构成任何信任判断——
/// 真正的判断仍然在 `verify_host_cert` 里。
pub fn looks_like_cert(blob : FixedArray[Byte]) -> Bool {
  let cur = HkCursor::new(blob)
  let name = cur.get_cstring()
  if cur.err is Some(_) {
    return false
  }
  is_cert_type_name(name)
}