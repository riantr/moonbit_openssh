///| known_hosts 条目结构（OpenSSH hostfile.c:91-104 hostkey_foreach_line 转写）

///|
/// Loop #14 内部表示：
/// 把每个 host pattern 拆为 (host_only, port?) —— 与 host_patterns 平行同长度。
/// port = Some(N) 表示该 pattern 显式指定端口（如 "[host]:2200"）
/// port = None 表示该 pattern 不带端口（默认 22，对应 caller port=0）。
///
/// pub 而非 priv：KnownHostEntry 是 pub(all) struct,不能依赖 priv 字段类型
/// （MoonBit 类型系统强制 pub 定义只能出现 pub 类型字段）。
/// caller 一般不需要看到 HostSpec;可通过 host_patterns 做错误消息。
pub struct HostSpec {
  host_only : String
  host_port : Int?
}

///|
/// known_hosts 行标记
pub(all) enum Marker {
  /// 普通条目（无前缀标记）：主机密钥就是这一把
  None
  /// `@cert-authority` 信任锚
  ///
  /// Loop #51 起**强制**语义,而且是往安全方向强制：这一行**不是**一把主机
  /// 密钥的 pin。它说的是「只有当该主机出示一张由这把 CA 签发的证书时才信任」,
  /// 而证书验证不在本子集内——所以这一行永远不能拿它的 blob 去和出示的主机
  /// 密钥比相等。之前它被当成普通条目比对,等于把「信任这个 CA」悄悄降级成
  /// 「信任这把钥匙就是这台主机」,见 `check_host_key`。
  CertAuthority
  /// @revoked 吊销标记
  ///
  /// Loop #14 起强制语义:全表扫,不看主机名是否命中,命中即拒。
  Revoked
} derive(Eq)

///|
/// Loop #66: `derive(Eq)` used to promote `Eq::{equal, not_equal}` to plain
/// methods on the type implicitly. That promotion is deprecated and slated for
/// removal, and it is invisible in the source -- the calls read as ordinary
/// methods on `Marker`. Naming them keeps the call sites honest and keeps the
/// package compiling when the promotion goes away.
pub extend Marker with Eq::{equal, not_equal}

///|
/// 匹配结果
pub(all) enum HostStatus {
  /// 命中且 key 匹配
  Ok
  /// hostname 命中但 key 不匹配（拒绝连接）
  Mismatch
  /// hostname 未命中（strict_kex 决定是否升级）
  Unknown
  /// 主机名只被 `@cert-authority` 条目命中,而本客户端不验证主机证书
  ///
  /// Loop #51 新增。它存在的理由是它和另外两个都**不能混用**:
  ///
  ///   * 不是 `Ok`   —— 没有比对过任何主机密钥,拿 CA 的公钥去和主机密钥比相等
  ///                   是没有意义的,而且相等时是 fail-open。
  ///   * 不是 `Mismatch` —— 我们根本没有一把可信的主机密钥可比,所以「钥匙变了」
  ///                     这个指控没有依据。而 `HOST_CHANGED` 的标准解法是用户去加
  ///                     `--kh-tofu`,也就是说把一个「我不懂这个配置」报成
  ///                     「有人在中间」,是在教用户关掉保护。
  CertAuthority
  /// entries 中有空指针或格式错误
  InvalidEntry
} derive(Eq)

///| Loop #66: same explicit promotion as `Marker` above.
pub extend HostStatus with Eq::{equal, not_equal}

///|
/// 单个 known_hosts 条目
pub(all) struct KnownHostEntry {
  marker : Marker
  /// 拆分后的 hostname 模式列表（已 trim），如 ["*.example.com", "foo"]
  host_patterns : Array[String]
  /// Loop #14 解析后的 (host_only, host_port?) 列表，与 host_patterns 平行
  host_specs : Array[HostSpec]
  /// 原始 hostname 字符串（含逗号和否定标记），如 "*.example.com,!bar.example.com"
  host_raw : String
  /// 算法名（如 "ssh-ed25519"）
  key_type : String
  /// base64-decoded SSH wire blob（直接喂给 @hostkey.HostKey::from_blob）
  key_blob : FixedArray[Byte]
  /// 整行原文（用于错误消息）
  raw_line : String
  /// 源文件行号（用于错误消息；纯字符串输入时为 caller 传入值）
  linenum : Int
}

///|
/// from_blob 辅助：构造一个最小的"匹配成功"检查入口
///（不实际构造条目，caller 用 check_host_key 函数）
pub fn KnownHostEntry::key_type_str(self : KnownHostEntry) -> String {
  self.key_type
}