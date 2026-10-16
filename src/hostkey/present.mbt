///| K_S 出示的东西 → 「用来验签的那把钥匙」（Loop #53）
///

///| 握手签名永远是**内层那把钥匙**签的，即使 K_S 里是一张证书。把证书当成钥匙

///| 直接送进 `verify_with_alg` 会得到一个必然失败的验签——不是密码学出错，是

///| 拿错了钥匙。所以这条规则住在这里，两条 live 适配器共用；它们只负责翻译错误类型。
///

///| 顺带定死了另一件事：**协商出的算法名就是证书类型名**。

///| `ssh-ed25519-cert-v01@openssh.com` 这个名字既出现在 KEXINIT 里，也应该是

///| 证书 blob 的第一个字符串。两者不等就是协议违规，比「签名验不过」早一步报出来。

///|
/// 出示的主机密钥，以及验签时该用的算法名
pub(all) struct PresentedKey {
  /// 用来验 KEX 签名的钥匙（证书情形下是**内层**那把）
  key : HostKey
  /// 传给 `verify_with_alg` 的算法名。
  ///
  /// 证书情形下是内层的**普通**算法名（`ssh-ed25519`），不是协商出的证书名——
  /// 因为签名 blob 里写的也是它，而 `agrees_with_alg` 是按钥匙类型判定的。
  sig_alg : String
  /// 出示的是否是证书
  is_cert : Bool
  /// 证书类型名；非证书时为 ""
  cert_type_name : String
}

///|
/// `presented_key` 的结果
pub(all) enum PresentedResult {
  Ready(PresentedKey)
  Bad(KeyError)
}

///|
/// 这个普通算法名我们实现了对应的钥匙解析
pub fn plain_type_is_supported(name : String) -> Bool {
  name == "ssh-ed25519" ||
  name == "ssh-rsa" ||
  name == "ecdsa-sha2-nistp256" ||
  name == "ecdsa-sha2-nistp384"
}

///|
/// 从 K_S 的字节取出验签要用的钥匙
///

///|
/// `negotiated_alg` 是 KEX 协商出来的主机密钥算法名。
pub fn presented_key(
  blob : FixedArray[Byte],
  negotiated_alg : String,
) -> PresentedResult {
  if looks_like_cert(blob) {
    let cert = match HostCert::from_blob(blob) {
      CertParseResult::Rejected(_) => return Bad(CertNotAllowed)
      CertParseResult::Parsed(c) => c
    }
    // 协商出的名字必须就是这张证书的类型名。不等说明对端报了一个证书算法却
    // 递了一把裸钥匙（或反过来），两种都是协议违规。
    if cert.cert_type_name != negotiated_alg {
      return Bad(TypeMismatch)
    }
    if !plain_type_is_supported(cert.key_type_name) {
      return Bad(UnsupportedType)
    }
    match HostKey::from_blob(cert.inner_key_blob) {
      Rejected(e) => Bad(e)
      Parsed(inner) =>
        // 内层钥匙要用**普通**算法名去验签：签名 blob 的算法名写的是
        // `ssh-ed25519` 而不是证书名，这一点和 RFC 8332 下 RSA 的三元分裂同源。
        Ready({
          key: inner,
          sig_alg: cert.key_type_name,
          is_cert: true,
          cert_type_name: cert.cert_type_name,
        })
    }
  } else {
    match HostKey::from_blob(blob) {
      Rejected(e) => Bad(e)
      Parsed(k) =>
        // 非证书路径的配对判定，和证书路径一样住在 src/hostkey（RFC 8332）
        if !HostKey::agrees_with_alg(k, negotiated_alg) {
          Bad(TypeMismatch)
        } else {
          Ready({
            key: k,
            sig_alg: negotiated_alg,
            is_cert: false,
            cert_type_name: "",
          })
        }
    }
  }
}
