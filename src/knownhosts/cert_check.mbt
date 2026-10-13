///| Loop #53: `@cert-authority` 从「我不会」变成一个真正能用的信任锚
///
///| Loop #51 让 `@cert-authority` 条目**不再**被当成一把主机密钥的 pin，那是对的，
///| 但它同时把整件事停在了「认不出来就拒绝」。这条路的另一半是把这半个信任锚真的
///| 验起来：出示一张证书，只要它由本机 `@cert-authority` 里那把 CA 签发、在这台
///| 主机的有效期内、principal 包含这台主机，就认——而不是认它内层的那把钥匙。
///
///| **证书永远需要一把被 pin 的 CA，没有例外。** 这一条不能被 `--kh-tofu` 绕过，
///| 也不能被非 strict 模式绕过：证书的内层钥匙不是对端「此刻出示的东西」，而是一张
///| 由 CA 背书的凭证；没有 CA 就是没有信任来源，那和 MITM 没有区别。Loop #51 已经
///| 为同一条理由关掉了 TOFU 那个口子，这里是同一条规则的延伸。

///|
/// 证书路径的判定结果
pub(all) enum CertCheckResult {
  /// CA 条目命中且证书全项验过
  Trusted
  /// 出示了证书，但这台主机没有任何 `@cert-authority` 条目
  ///
  /// **拒绝，且与 strict 无关。** 这不是「没被 pin 过」——`Unknown` 那种情况下
  /// 非 strict 会放行，而这里不能。
  NoCaEntry
  /// 这台主机的 CA 条目命中了，但证书没过（原因在字符串里）
  CaRejected(String)
}

///|
/// 找出 `ca_blob` 对应的那条 `@cert-authority` 条目
///
///| 与裸密钥路径的 last-match-wins 不同：证书是按**签发者**找 CA 的，而一张证书
///| 只指名一个签发者，所以判据是 blob 字节相等而不是「最后一个命中的条目」。
///| host 模式仍然要匹配——同一把 CA 可以给很多台主机签证书，但那条 known_hosts 行
///| 写了哪些主机，就是它担保哪些主机。
pub fn find_ca_entry(
  entries : Array[KnownHostEntry],
  host_only : String,
  port_caller : Int,
  ca_blob : FixedArray[Byte],
) -> KnownHostEntry? {
  for i = 0; i < entries.length(); i = i + 1 {
    let e = entries[i]
    if e.marker == Marker::CertAuthority &&
      entry_matches_spec(e, host_only, port_caller) &&
      blob_eq(e.key_blob, ca_blob) {
      return Some(e)
    }
  }
  None
}

///|
/// 这台主机有没有任何 `@cert-authority` 条目覆盖
pub fn has_any_ca_entry(
  entries : Array[KnownHostEntry],
  host_only : String,
  port_caller : Int,
) -> Bool {
  has_cert_authority_match(entries, host_only, port_caller)
}

///|
/// `CertFailure` → 可读的短名
fn cert_failure_name(f : @hostkey.CertFailure) -> String {
  match f {
    Malformed => "malformed"
    CaNotPinned => "ca-not-pinned"
    CaSignatureInvalid => "ca-signature-invalid"
    NotHostCertificate => "not-a-host-certificate"
    NotYetValid => "not-yet-valid"
    Expired => "expired"
    PrincipalMismatch => "principal-mismatch"
    UnsupportedCriticalOption => "unsupported-critical-option"
    InnerKeyUnsupported => "inner-key-unsupported"
  }
}

///|
/// 证书路径的主判定（Loop #53）
///
///| `cert_blob` 是 K_S 里出示的那张证书；`now` 由调用方注入。
///| 返回 `Trusted` 时，**握手签名要用证书内层那把钥匙验**，不是用 CA。
pub fn check_host_key_cert(
  entries : Array[KnownHostEntry],
  host_str : String,
  port : Int,
  cert_blob : FixedArray[Byte],
  now : UInt64,
) -> CertCheckResult {
  let (host_only, port_from_str) = split_host_str(host_str)
  let port_caller = if port == 0 {
    match port_from_str {
      Some(p) => p
      None => 22
    }
  } else {
    port
  }
  // 先解出证书，才能知道要拿哪把 CA 去验。
  let parsed = match @hostkey.HostCert::from_blob(cert_blob) {
    @hostkey.CertParseResult::Rejected(_) => return CertCheckResult::CaRejected(
      "malformed",
    )
    @hostkey.CertParseResult::Parsed(c) => c
  }
  // 吊销检查与裸密钥路径同规则，但对象换成**签发者**：CA 被吊销了，它签的一切
  // 都不再可信。这是全局扫，不看主机名（hostfile.c check_key_not_revoked）。
  for i = 0; i < entries.length(); i = i + 1 {
    let e = entries[i]
    if e.marker == Marker::Revoked &&
      blob_eq(e.key_blob, parsed.sig_key) {
      return CertCheckResult::CaRejected("ca-revoked")
    }
  }
  if find_ca_entry(entries, host_only, port_caller, parsed.sig_key) is None {
    return CertCheckResult::NoCaEntry
  }
  match @hostkey.verify_host_cert(
    cert_blob,
    parsed.sig_key,
    host_only,
    now,
  ) {
    @hostkey.CertVerdict::Trusted(_) => CertCheckResult::Trusted
    @hostkey.CertVerdict::Rejected(f) => CertCheckResult::CaRejected(
      cert_failure_name(f),
    )
  }
}