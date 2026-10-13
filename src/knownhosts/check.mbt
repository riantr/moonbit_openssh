///| host_key_check（OpenSSH hostfile.c:408-428 + 315-332 check_key_not_revoked 转写）
///
/// last-match-wins：遍历 entries[]，返回最后一个 hostname 命中的条目，
/// 再比较其 key_blob 与 presented_blob（按 HostKey 字节相等）。
///
/// Loop #14 增量:
/// - caller 传 host_str + port(port=0 表示 SSH default 22)
/// - host_str 可选 `[host]:port` 包装,内部 split_host_str 解包
/// - entry 用 host_specs (host_only, host_port?),pattern 匹配 + port 校验
/// - 后置全局扫所有 @revoked entries,presented_blob 字节匹配 → 强制 Mismatch
///   (对应 OpenSSH hostfile.c:399 check_key_not_revoked 全局行为)

///|
/// 测试 entry 是否命中 caller's (host_only, port_caller)
/// 支持:
///   - plain / wildcard via match_pattern_nfa
///   - `|1|<salt>|<hash>` via match_hashed_host (HMAC-SHA1)
///   - port 校验:entry 有显式 port 必须相等;None 任意
fn entry_matches_spec(
  entry : KnownHostEntry,
  host_only : String,
  port_caller : Int,
) -> Bool {
  let specs = entry.host_specs
  for i = 0; i < specs.length(); i = i + 1 {
    let spec = specs[i]
    // port 部分先行:entry 有显式 port 必须相等;entry 无 port 任意
    match spec.host_port {
      Some(p) => if p != port_caller { continue }
      None => ()
    }
    // host 部分:先检测 `|1|` 哈希;否则 NFA 通配
    let hit = if is_hashed_host(spec.host_only) {
      // 哈希条目不含 port(OpenSSH 行为) — port 已上行匹配
      match_hashed_host(host_only, spec.host_only)
    } else {
      match_pattern_nfa(host_only, spec.host_only)
    }
    if hit { return true }
  }
  false
}

///|
/// 在 entries 中查找最后一个 hostname 命中的**直接**条目 (Loop #14: port-aware)
///
/// Loop #51: `@cert-authority` 条目在这里被排除。
///
/// 它必须被排除,因为它不是一把主机密钥的 pin:它是「只有出示这张 CA 签的
/// 证书才信任」的信任锚。把它的 blob 和出示的主机密钥比相等,是一个没有意义
/// 的比较——**而且相等时是 fail-open**:对端出示 CA 的公钥当主机密钥,我们就
/// 认了。之前 `entry_matches_spec` 不看 marker,于是这一行和一条普通条目
/// 完全等价,实测确实会放行并把凭据发出去。
///
/// last-match-wins 保留在直接条目内部。一个主机上既有直接条目又有 CA 条目时,
/// 拿直接条目说话:那才是「我们钉过这把钥匙,而它变了」,是真指控。
///
/// **Loop #53: `@revoked` 也不是直接条目。** 它是「把这把钥匙永久拒绝」,不是
/// 「这把钥匙是这台主机的钥匙」。两者在 last-match-wins 里被当成同一种东西时,
/// 一条排在后面的 `@revoked *` 会盖掉前面真正的 pin,于是这台主机被报成
/// `Mismatch`。方向上是 fail-closed 所以不会漏,但报出来的原因是错的(「有人在
/// 中间」而不是「你这把钥匙被吊销了」),而且 `ssh-keygen -R` 之后的正常连接会
/// 无端失败。吊销的判定在 `check_host_key` 的第 2 步做一次全局扫,那才是它该待的
/// 地方。
fn find_last_direct_match_v2(
  entries : Array[KnownHostEntry],
  host_only : String,
  port_caller : Int,
) -> KnownHostEntry? {
  let mut found : KnownHostEntry? = None
  for i = 0; i < entries.length(); i = i + 1 {
    let e = entries[i]
    if e.marker == Marker::None && entry_matches_spec(e, host_only, port_caller) {
      found = Some(e)
    }
  }
  found
}

///|
/// 这个主机名是否被任何 `@cert-authority` 条目覆盖。
///
/// 用来区分两件都「拒绝」但原因完全不同的事:这台主机压根没人 pin 过,和这台
/// 主机是用 CA pin 的、而我们不验证证书。
fn has_cert_authority_match(
  entries : Array[KnownHostEntry],
  host_only : String,
  port_caller : Int,
) -> Bool {
  for i = 0; i < entries.length(); i = i + 1 {
    let e = entries[i]
    if e.marker == Marker::CertAuthority && entry_matches_spec(e, host_only, port_caller) {
      return true
    }
  }
  false
}

///| 字节级 blob 比较
fn blob_eq(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() { return false }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] { return false }
  }
  true
}

///|
/// Loop #14: host_key_check 主体逻辑 (含 Revoked 后置全局扫)
///
/// 输入:
///   entries : KnownHostEntry[] —— caller 提供的 known_hosts 条目
///   host_str : String —— 可以是 plain "example.com" 或 "[example.com]:2200"
///   port : Int —— 0 = SSH default 22
///   presented_blob : FixedArray[Byte] —— server 提供的 hostkey blob
///
/// 返回:
///   Ok          — hostname 命中 + key 字节匹配 + 未被 @revoked 拒绝
///   Mismatch    — hostname 命中但 key 不匹配,或 @revoked 全局扫命中
///   Unknown     — entries 为空或 hostname 未命中
///   CertAuthority — hostname 只被 @cert-authority 命中(Loop #51)
///   InvalidEntry — 内部错误(shouldn't happen in normal flow)
pub fn check_host_key(
  entries : Array[KnownHostEntry],
  host_str : String,
  port : Int,
  presented_blob : FixedArray[Byte],
) -> HostStatus {
  if entries.length() == 0 { return Unknown }
  // 1. Normalize caller
  let (host_only, port_from_str) = split_host_str(host_str)
  let port_caller = if port == 0 {
    match port_from_str {
      Some(p) => p
      None => 22
    }
  } else {
    port
  }
  // 2. 后置:全 entries @revoked 检查（OpenSSH hostfile.c:399 check_key_not_revoked）
  for i = 0; i < entries.length(); i = i + 1 {
    let e = entries[i]
    if e.marker == Marker::Revoked && blob_eq(e.key_blob, presented_blob) {
      return Mismatch  // key 在 @revoked 列表中,无论 host 匹不匹配都拒绝
    }
  }
  // 3. last-match-wins 找 host+port 命中的**直接**条目
  //
  // 只在直接条目里找,不在 CA 条目里找:CA 条目不是主机密钥的 pin。剩下的 CA
  // 命中单独用来区分「没人 pin 过」和「用 CA pin 的、而我们不验证证书」。
  let found = find_last_direct_match_v2(entries, host_only, port_caller)
  // 4. 决定最终 status
  match found {
    None =>
      // 没有直接条目。主机名若被 CA 条目覆盖,那是一个我们答不上来的问题,
      // 而不是「没被 pin 过」,更不是「钥匙变了」。
      if has_cert_authority_match(entries, host_only, port_caller) {
        CertAuthority
      } else {
        Unknown
      }
    Some(e) => if blob_eq(e.key_blob, presented_blob) { Ok } else { Mismatch }
  }
}

///|
/// Loop #14: 与 Loop #13 同名 backward-compat shim(caller 不知 port)
pub fn check_host_key_legacy(
  entries : Array[KnownHostEntry],
  host : String,
  presented_blob : FixedArray[Byte],
) -> HostStatus {
  check_host_key(entries, host, 0, presented_blob)
}

///| strict-kex 感知:strict_kex=true 时 Unknown 升级为 InvalidEntry(拒绝)
///
/// Loop #51: `CertAuthority` **不**升级。它已经是一个拒绝了,而把它变成
/// InvalidEntry 会把「用 CA pin 的」和「条目坏了」混成一类。
pub fn check_host_key_strict(
  entries : Array[KnownHostEntry],
  host_str : String,
  port : Int,
  presented_blob : FixedArray[Byte],
  strict_kex : Bool,
) -> HostStatus {
  let r = check_host_key(entries, host_str, port, presented_blob)
  match r {
    Unknown => if strict_kex { InvalidEntry } else { Unknown }
    _ => r
  }
}

///| strict backward-compat shim
pub fn check_host_key_strict_legacy(
  entries : Array[KnownHostEntry],
  host : String,
  presented_blob : FixedArray[Byte],
  strict_kex : Bool,
) -> HostStatus {
  check_host_key_strict(entries, host, 0, presented_blob, strict_kex)
}