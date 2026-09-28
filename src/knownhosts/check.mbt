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
/// 在 entries 中查找最后一个 hostname 命中的条目 (Loop #14: port-aware)
fn find_last_match_v2(
  entries : Array[KnownHostEntry],
  host_only : String,
  port_caller : Int,
) -> KnownHostEntry? {
  let mut found : KnownHostEntry? = None
  for i = 0; i < entries.length(); i = i + 1 {
    let e = entries[i]
    if entry_matches_spec(e, host_only, port_caller) {
      found = Some(e)
    }
  }
  found
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
  // 3. last-match-wins 找 host+port 命中
  let found = find_last_match_v2(entries, host_only, port_caller)
  // 4. 决定最终 status
  match found {
    None => Unknown
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