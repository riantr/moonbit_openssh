///| known_hosts 解析（OpenSSH hostfile.c:790-963 转写）
///
/// 行格式（RFC 4255 section 4 简化）：
///   [@cert-authority|@revoked] <hosts> <keytype> <base64key> [comment]
///
/// hosts 字段：
///   - 明文：example.com,foo.example.com,*.example.com
///   - 否定：!bar.example.com（语义跳过，不强制）
///   - 哈希：|1|<base64-salt>|<base64-hash>（HMAC-SHA1(salt, host)）

///|
/// 跳过前导空白（OpenSSH hostfile.c:822-823 行为）
fn skip_leading_ws(s : String) -> Int32 {
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    if c != 0x20 && c != 0x09 {
      break
    }
    i = i + 1
  }
  i
}

///|
/// 跳到下一个空白字符（终止 hostname 字段）
fn skip_to_ws(s : String, start : Int32) -> Int32 {
  let mut i = start
  while i < s.length() {
    let c = s[i].to_int()
    if c == 0x20 || c == 0x09 {
      break
    }
    i = i + 1
  }
  i
}

///|
/// 检测 @cert-authority / @revoked 标记（hostfile.c:180-213 check_markers）
fn check_marker(s : String, start : Int32) -> (Marker, Int32)? {
  if start >= s.length() || s[start] != '@' {
    return None
  }
  // 标记必须以空白终止
  let mut end = start + 1
  while end < s.length() {
    let c = s[end].to_int()
    if c == 0x20 || c == 0x09 {
      break
    }
    end = end + 1
  }
  if end >= s.length() || end == start + 1 {
    // 标记太长或紧贴 EOF → 错误
    return None
  }
  let marker_str = s[start:end].to_owned()
  // 跳过标记后的空白
  let mut after = end
  while after < s.length() {
    let c = s[after].to_int()
    if c != 0x20 && c != 0x09 {
      break
    }
    after = after + 1
  }
  // 只允许一个标记（hostfile.c:188-189）
  if after > end && s[end + 1] == '@' {
    return None
  }
  if marker_str == "@cert-authority" {
    Some((CertAuthority, after))
  } else if marker_str == "@revoked" {
    Some((Revoked, after))
  } else {
    None
  }
}

///|
/// 解析单行 known_hosts 条目
/// 返回 None 表示空行/纯注释/格式错误
pub fn parse_line(line : String, linenum : Int32) -> KnownHostEntry? {
  let raw = line
  let mut pos = skip_leading_ws(line)
  // 空行或 # 注释行
  if pos >= line.length() {
    return None
  }
  if line[pos] == '#' {
    return None
  }
  // 检测 marker（@cert-authority 或 @revoked）
  let (marker, after_marker) = match check_marker(line, pos) {
    Some(p) => p
    None => (None, pos)
  }
  pos = after_marker
  // hostname 字段：到第一个空白为止
  let host_end = skip_to_ws(line, pos)
  if host_end >= line.length() || host_end == pos {
    return None
  }
  let host_raw = line[pos:host_end].to_owned()
  // 跳过空白
  let mut p = host_end
  while p < line.length() {
    let c = line[p].to_int()
    if c != 0x20 && c != 0x09 {
      break
    }
    p = p + 1
  }
  // keytype
  let kt_end = skip_to_ws(line, p)
  if kt_end >= line.length() || kt_end == p {
    return None
  }
  let key_type = line[p:kt_end].to_owned()
  // 跳过空白
  p = kt_end
  while p < line.length() {
    let c = line[p].to_int()
    if c != 0x20 && c != 0x09 {
      break
    }
    p = p + 1
  }
  // base64 blob
  let blob_end = skip_to_ws(line, p)
  let blob_str = if blob_end < line.length() {
    line[p:blob_end].to_owned()
  } else {
    line[p:line.length()].to_owned()
  }
  if blob_str.length() == 0 {
    return None
  }
  // base64 decode
  let key_blob = match parse_base64_blob(blob_str) {
    Some(b) => b
    None => return None
  }
  // 拆分 hostname 模式（trim 后存为 Array；保留原始 host_raw）
  let patterns = split_host_patterns(host_raw)
  if patterns.length() == 0 {
    return None
  }
  // Loop #14: 平行构造 host_specs (host_only, host_port?)
  let specs : Array[HostSpec] = []
  for i = 0; i < patterns.length(); i = i + 1 {
    specs.push(split_host_pattern_spec(patterns[i]))
  }
  Some({
    marker,
    host_patterns: patterns,
    host_specs: specs,
    host_raw,
    key_type,
    key_blob,
    raw_line: raw,
    linenum,
  })
}

///|
/// 拆分逗号分隔的 hostname 模式列表
/// - 跳过 `!` 开头的否定（语义跳过，保留 pattern 用于显示）
/// - trim 每个 pattern
fn split_host_patterns(s : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = 0
  let mut i = 0
  while i <= s.length() {
    if i == s.length() || s[i] == ',' {
      if i > start {
        let raw = s[start:i].to_owned()
        let trimmed = trim_whitespace(raw)
        if trimmed.length() > 0 {
          // 保留否定标记用于显示（parse_line 之外不需要 match）
          out.push(trimmed)
        }
      }
      start = i + 1
    }
    i = i + 1
  }
  out
}

///|
/// Loop #14: 解析单个 host pattern 为 (host_only, port?)。
/// 支持 `[host]:port` 显式端口语法。
/// 规则:
///   "example.com"          -> ("example.com", None)
///   "[example.com]:2200"   -> ("example.com", Some(2200))
///   "*.example.com"        -> ("*.example.com", None)
///   "!bar.example.com"     -> ("bar.example.com", None)  // 否定前缀剥离
fn split_host_pattern_spec(p : String) -> HostSpec {
  // 剥离 `!` 否定前缀（与 split_host_patterns 行为一致）
  let s = if p.length() > 0 && p[0].to_int() == '!'.to_int() {
    p[1:p.length()].to_owned()
  } else {
    p
  }
  // 检测 "[host]" 或 "[host]:port" 形式
  if s.length() >= 2 && s[0].to_int() == '['.to_int() {
    // 找 ]'
    let mut close = -1
    let mut j = 1
    while j < s.length() {
      if s[j].to_int() == ']'.to_int() {
        close = j
        break
      }
      j = j + 1
    }
    if close > 0 {
      // s[1..close) = host_only
      let host_inner = s[1:close].to_owned()
      // 期待 close+1 == ':' 然后端口
      if close + 1 < s.length() && s[close + 1].to_int() == ':'.to_int() {
        // 解析端口字符串 s[close+2..]
        let port_str = s[close + 2:s.length()].to_owned()
        match parse_int_str(port_str) {
          Some(n) => { host_only: host_inner, host_port: Some(n), }
          None => { host_only: host_inner, host_port: None, } // 端口解析失败
        }
      } else {
        { host_only: host_inner, host_port: None, }
      }
    } else {
      // 没找到 ']' -- 整段当作 host_only（不匹配但保守）
      { host_only: s, host_port: None, }
    }
  } else {
    { host_only: s, host_port: None, }
  }
}

///|
/// Loop #14: 解析十进制整数字符串,失败返回 None
fn parse_int_str(s : String) -> Int32? {
  if s.length() == 0 {
    return None
  }
  let mut n = 0
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    if c < '0'.to_int() || c > '9'.to_int() {
      return None
    }
    n = n * 10 + (c - '0'.to_int())
    i = i + 1
  }
  Some(n)
}

///|
/// trim ASCII 空白
fn trim_whitespace(s : String) -> String {
  let mut start = 0
  let mut end = s.length()
  while start < end {
    let c = s[start].to_int()
    if c != 0x20 && c != 0x09 {
      break
    }
    start = start + 1
  }
  while end > start {
    let c = s[end - 1].to_int()
    if c != 0x20 && c != 0x09 {
      break
    }
    end = end - 1
  }
  if start >= end {
    return ""
  }
  s[start:end].to_owned()
}

///|
/// 解析完整 known_hosts 内容
pub fn parse_file(content : String) -> Array[KnownHostEntry] {
  let out : Array[KnownHostEntry] = []
  let mut linenum = 0
  let mut start = 0
  let mut i = 0
  while i <= content.length() {
    if i == content.length() || content[i] == '\n' {
      linenum = linenum + 1
      // 去掉 \r（Windows 行尾）
      let mut end = i
      if end > start && content[end - 1] == '\r' {
        end = end - 1
      }
      let line = content[start:end].to_owned()
      match parse_line(line, linenum) {
        Some(e) => out.push(e)
        None => ()
      }
      start = i + 1
    }
    i = i + 1
  }
  out
}

///|
/// base64-decode SSH wire blob（OpenSSH b64_pton 兼容）
/// 使用 moonbitlang/core/encoding/base64
pub fn parse_base64_blob(s : String) -> FixedArray[Byte]? {
  // 兼容标准 base64 和 nopad 形式（OpenSSH 在写入时无 padding）
  // moonbitlang/core/encoding/base64 decode 会自动处理 padding
  let view : StringView = s
  let result = @base64.decode(view, ignore_whitespace=false) catch {
    _ => return None
  }
  // FixedArray[Byte] from Bytes
  let arr : FixedArray[Byte] = FixedArray::make(result.length(), b'\x00')
  for i = 0; i < result.length(); i = i + 1 {
    arr[i] = result[i]
  }
  Some(arr)
}
