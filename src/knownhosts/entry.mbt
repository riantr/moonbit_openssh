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
  /// 普通条目（无前缀标记）
  None
  /// @cert-authority 信任锚（本子集不强制 CA 语义）
  CertAuthority
  /// @revoked 吊销标记（本子集仅识别，不强制语义）
  Revoked
} derive(Eq)

///|
/// 匹配结果
pub(all) enum HostStatus {
  /// 命中且 key 匹配
  Ok
  /// hostname 命中但 key 不匹配（拒绝连接）
  Mismatch
  /// hostname 未命中（strict_kex 决定是否升级）
  Unknown
  /// entries 中有空指针或格式错误
  InvalidEntry
} derive(Eq)

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