///| OpenSSH 证书解析（PROTOCOL.certkeys，对应 sshkey.c 中
///| sshkey_from_blob_internal 的 allow_cert=1 分支）
///
///| 字段顺序（逐字节核对过 `.loop53/host-good-cert.pub`，并与 `ssh-keygen -L` 互证）：
///
///| ```
///|   string   cert type name          "ssh-ed25519-cert-v01@openssh.com"
///|   string   nonce
///|   string   inner key               **裸公钥材料，不含类型名**
///|   uint64   serial
///|   uint32   type                    1 = user, 2 = host
///|   string   key id
///|   string   valid principals        内容是若干条长度前缀子串的拼接
///|   uint64   valid after
///|   uint64   valid before
///|   string   critical options
///|   string   extensions
///|   string   reserved
///|   string   signature key           CA 的完整公钥 blob
///|   string   signature               覆盖上面**全部**字段（含类型名与 signature key）
///| ```
///
///| 三处容易写错、且写错之后**不会报错只会安静地不匹配**的地方：
///
///| 1. **内层 key 不带类型名。** 证书类型名已经蕴含了内层算法，再套一层
///|    `string "ssh-ed25519"` 会让整个游标错位。
///| 2. **principals 不是逗号分隔的 ASCII 列表。** 它是一个 string，其内容是若干条
///|    长度前缀子串首尾相接（`00 00 00 10 host.example.com`）。当普通字符串比较会
///|    永远比不上。
///| 3. **signed_data 是「去掉末尾 `string signature` 字段之前的全部内容」**，也就是
///|    它**包含** signature key 字段。直觉上很容易写成「nonce..reserved」——那样
///|    会短 55 字节，验签必然失败，而这个错误在自造向量下完全看不出来（短一字节
///|    也只是验签失败，不会报任何结构性错误）。它是拿 Node/OpenSSL 把每一种连续
///|    切片都试过一遍才定下来的，见 `host/cert_signed_data_oracle.mjs`。

///| 证书类型后缀；剥掉它就得到内层钥匙的算法名
pub const CERT_SUFFIX : String = "-cert-v01@openssh.com"

///|
/// cert type 常量（sshkey.h）
///
/// **不要凭记忆写这两个数。** 本仓库里这两个值是**从字节反推**出来的，并且和
/// `ssh-keygen -L` 的输出交叉验证过：
///
/// ```
///   ssh-keygen -s ca -h host.pub   ->  type 字段 == 2, -L 打印 "host certificate"
///   ssh-keygen -s ca     user.pub  ->  type 字段 == 1, -L 打印 "user certificate"
/// ```
///
/// 写反的后果不是「多支持一种证书」，而是**把发给 alice 的用户证书当成主机身份
/// 证明**：用户证书的 principal 是登录名，主机证书的 principal 是主机名，两者
/// 的信任含义完全不同。
pub const SSH_CERT_TYPE_USER : Int = 1

///|
pub const SSH_CERT_TYPE_HOST : Int = 2

///|
/// 证书解析失败
pub(all) enum CertError {
  /// 第一个字段的字符串不是证书类型名
  NotACertificate(String)
  /// 结构不对（截断 / 长度前缀越界 / 内嵌 \0）
  Malformed
  /// 证书尾部还有残余字节
  TrailingData
  /// principals 字段的子串列表解析不出来
  BadPrincipals
  /// 证书封装的是我们没有实现的内层钥匙类型
  UnsupportedKeyType(String)
}

///|
pub(all) enum CertParseResult {
  Parsed(HostCert)
  Rejected(CertError)
}

///|
/// 一张解析好的 OpenSSH 证书
pub(all) struct HostCert {
  /// 完整证书类型名，如 "ssh-ed25519-cert-v01@openssh.com"
  cert_type_name : String
  /// 剥掉证书后缀后的内层算法名，如 "ssh-ed25519"
  key_type_name : String
  /// CA 用来防重放的随机串
  nonce : FixedArray[Byte]
  /// 内层主机的**裸**公钥材料（32 字节 ed25519 / e+n / 曲线点）
  inner_key : FixedArray[Byte]
  /// 内层钥匙的完整 blob（类型名 + 材料），可直接喂 `HostKey::from_blob`
  inner_key_blob : FixedArray[Byte]
  serial : UInt64
  /// SSH_CERT_TYPE_HOST 或 SSH_CERT_TYPE_USER
  cert_type : Int
  key_id : String
  /// 已拆成独立字符串的 principal 列表
  principals : Array[String]
  valid_after : UInt64
  valid_before : UInt64
  critical_options : FixedArray[Byte]
  extensions : FixedArray[Byte]
  reserved : FixedArray[Byte]
  /// CA 的完整公钥 blob（与 known_hosts 里 @cert-authority 那一行的 blob 比对）
  sig_key : FixedArray[Byte]
  /// 签名 blob（自带算法名）
  signature : FixedArray[Byte]
  /// CA 签名的原文 = 去掉末尾 signature 字段之前的**全部**内容（含类型名与
  /// signature key），不是 nonce..reserved
  signed_data : FixedArray[Byte]
}

///|
/// 这个 type name 是不是证书类型名
pub fn is_cert_type_name(name : String) -> Bool {
  name.has_suffix(CERT_SUFFIX)
}

///|
/// 证书类型名 → 内层算法名
pub fn plain_type_of_cert(name : String) -> String {
  if name.has_suffix(CERT_SUFFIX) {
    name.substring(start=0, end=name.length() - CERT_SUFFIX.length())
  } else {
    name
  }
}

///|
/// principals 字段 → 字符串列表
///
/// 字段本身是一个 string，内容是若干条长度前缀子串首尾相接。空字段 = 空列表，
/// 而空列表在 OpenSSH 里表示「对所有 principal 有效」（见 cert_verify.mbt）。
pub fn parse_principals(blob : FixedArray[Byte]) -> Array[String]? {
  let out : Array[String] = []
  let cur = HkCursor::new(blob)
  while cur.remaining() > 0 {
    let raw = cur.get_string()
    if cur.err is Some(_) {
      return None
    }
    let sb = StringBuilder()
    for i = 0; i < raw.length(); i = i + 1 {
      sb.write_char(Int::unsafe_to_char(raw[i].to_int()))
    }
    out.push(sb.to_string())
  }
  Some(out)
}

///|
/// 解析一张证书 blob
pub fn HostCert::from_blob(blob : FixedArray[Byte]) -> CertParseResult {
  let cur = HkCursor::new(blob)
  let name = cur.get_cstring()
  if cur.err is Some(_) {
    return CertParseResult::Rejected(Malformed)
  }
  if !is_cert_type_name(name) {
    return CertParseResult::Rejected(NotACertificate(name))
  }
  let nonce = cur.get_string()
  let inner_key = cur.get_string()
  if cur.err is Some(_) {
    return CertParseResult::Rejected(Malformed)
  }
  let serial = cur.get_u64()
  if cur.remaining() < 4 {
    return CertParseResult::Rejected(Malformed)
  }
  let cert_type = read_u32hk(blob, cur.offset()).reinterpret_as_int()
  cur.skip(4)
  let key_id = cur.get_cstring()
  let principals_blob = cur.get_string()
  if cur.err is Some(_) {
    return CertParseResult::Rejected(Malformed)
  }
  let valid_after = cur.get_u64()
  let valid_before = cur.get_u64()
  let critical_options = cur.get_string()
  let extensions = cur.get_string()
  let reserved = cur.get_string()
  let sig_key = cur.get_string()
  if cur.err is Some(_) {
    return CertParseResult::Rejected(Malformed)
  }
  // signed_data = 证书 blob 去掉末尾 `string signature` 字段之后的**全部**内容。
  //
  // 它**包含**类型名，也**包含** signature key 字段。这一点是量出来的，不是照着
  // 记忆抄的：用 Node/OpenSSL 把 blob 的每一种连续切片都拿去验签，只有
  // `blob[0 : len-4-len(sig)]` 这一种能过（`host/cert_signed_data_oracle.mjs`，
  // 它自己先用一个自签向量自检过）。直觉上很容易写成「nonce..reserved」——
  // 那样会短 55 字节，验签必然失败。
  //
  // 顺带一个好处：signature key 字段本身在签名覆盖范围内，所以「证书指名的签发者
  // 就是我们 pin 的那把 CA」这条检查（cert_verify.mbt 第 1 条）在密码学上是被
  // 冗余保证的，而不是只靠我们自己比对两个字段。
  let signed_data = copy_range(blob, 0, cur.offset())
  let signature = cur.get_string()
  if cur.err is Some(_) {
    return CertParseResult::Rejected(Malformed)
  }
  if cur.remaining() != 0 {
    return CertParseResult::Rejected(TrailingData)
  }
  let principals = match parse_principals(principals_blob) {
    None => return CertParseResult::Rejected(BadPrincipals)
    Some(p) => p
  }
  let key_type_name = plain_type_of_cert(name)
  // 内层 blob = 类型名 + 裸材料，正好是我们 `HostKey::from_blob` 吃的那种形状。
  let inner_key_blob = build_key_blob(key_type_name, inner_key)
  if key_type_name != "ssh-ed25519" &&
    key_type_name != "ssh-rsa" &&
    key_type_name != "ecdsa-sha2-nistp256" &&
    key_type_name != "ecdsa-sha2-nistp384" {
    return CertParseResult::Rejected(UnsupportedKeyType(key_type_name))
  }
CertParseResult::Parsed({
    cert_type_name: name,
    key_type_name,
    nonce,
    inner_key,
    inner_key_blob,
    serial,
    cert_type,
    key_id,
    principals,
    valid_after,
    valid_before,
    critical_options,
    extensions,
    reserved,
    sig_key,
    signature,
    signed_data,
  })
}

///|
/// 把「类型名 + 裸材料」拼成一把普通公钥的 blob
fn build_key_blob(
  type_name : String,
  material : FixedArray[Byte],
) -> FixedArray[Byte] {
  let name_bytes : FixedArray[Byte] = FixedArray::make(type_name.length(), b'\x00')
  for i = 0; i < type_name.length(); i = i + 1 {
    name_bytes[i] = (type_name[i].to_int() & 0xFF).to_byte()
  }
  let out : FixedArray[Byte] = FixedArray::make(4 + name_bytes.length() +
  4 + material.length(), b'\x00')
  let n = name_bytes.length()
  out[0] = ((n >> 24) & 0xFF).to_byte()
  out[1] = ((n >> 16) & 0xFF).to_byte()
  out[2] = ((n >> 8) & 0xFF).to_byte()
  out[3] = (n & 0xFF).to_byte()
  for i = 0; i < n; i = i + 1 {
    out[4 + i] = name_bytes[i]
  }
  let m = material.length()
  let base = 4 + n
  out[base] = ((m >> 24) & 0xFF).to_byte()
  out[base + 1] = ((m >> 16) & 0xFF).to_byte()
  out[base + 2] = ((m >> 8) & 0xFF).to_byte()
  out[base + 3] = (m & 0xFF).to_byte()
  for i = 0; i < m; i = i + 1 {
    out[base + 4 + i] = material[i]
  }
  out
}