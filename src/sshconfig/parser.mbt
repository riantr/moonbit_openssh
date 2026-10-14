///| ssh_config 解析 (OpenSSH ssh_config(5) subset)
///|
/// Loop #24 G2: 解析 ssh_config 行级
///   - 空行 / `#` comment 跳过
///   - `Host PATTERNS...` → section header (PATTERNS 用空格分隔)
///   - `Keyword Value...` → option (Keyword 大写匹配 OpenSSH 风格)
///   - 缩进可选
///   - case-sensitive value, case-insensitive keyword
///
/// 输出: Array[SshConfigSection] (按文件中出现顺序)

///|
/// FixedArray[Byte] → String (ASCII)
fn bytes_to_ascii_string(bytes : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < bytes.length(); i = i + 1 {
    sb.write_char(bytes[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
/// ASCII string → FixedArray[Byte]
fn ascii_bytes(s : String) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    arr[i] = s[i].to_int().to_byte()
  }
  arr
}

///|
/// 字符串是否以 prefix 开头 (大小写敏感)
fn starts_with(s : String, prefix : String) -> Bool {
  if s.length() < prefix.length() {
    return false
  }
  for i = 0; i < prefix.length(); i = i + 1 {
    if s[i].to_int() != prefix[i].to_int() {
      return false
    }
  }
  true
}

///|
/// Strip a trailing comment: everything from the first `#` to end of line.
///
/// **Loop #57。** 旧实现只认**行首**的 `#`，于是 `User bob # note` 的值变成
/// `bob # note`。实测 `ssh -G` 给的是 `bob`。
///
/// 已知限制：`#` 无条件当注释起点，所以路径里带 `#` 的 IdentityFile 会被截断。
/// OpenSSH 在引号内有豁免，这里没有做——写下来，而不是假装支持。
fn strip_comment(line : String) -> String {
  let mut i = 0
  while i < line.length() {
    if line[i].to_int() == 35 {
      return slice_to(line, 0, i)
    }
    i = i + 1
  }
  line
}

///|
fn slice_to(s : String, from : Int, to : Int) -> String {
  let sb = StringBuilder()
  let mut i = from
  while i < to && i < s.length() {
    sb.write_char(s[i].unsafe_to_char())
    i = i + 1
  }
  sb.to_string()
}

///|
/// `Keyword Value` 和 `Keyword=Value` 都要认。
///
/// **Loop #57。** 旧实现按空白切，`Port=2202` 的 keyword 会变成字面量
/// `Port=2202`，于是这个选项永远匹配不上任何查询。实测 `ssh -G` 给 `port 2202`。
/// 找的是**第一个** `=`，且 keyword 与 `=` 之间的空白要先去掉。
fn split_option(line : String) -> (String, String) {
  let mut i = 0
  let mut eq = -1
  while i < line.length() {
    if line[i].to_int() == 61 {
      eq = i
      break
    }
    i = i + 1
  }
  if eq >= 0 {
    let lhs = trim(slice_to(line, 0, eq))
    let rhs = trim(slice_to(line, eq + 1, line.length()))
    // `=` 左边得像个 keyword，否则这行是个值里带 `=` 的东西（比如路径）。
    if lhs.length() > 0 && is_keyword_shaped(lhs) {
      return (lhs, rhs)
    }
  }
  let parts = split_whitespace(line)
  if parts.length() >= 2 {
    let mut value = parts[1]
    let mut k = 2
    while k < parts.length() {
      value = value + " " + parts[k]
      k = k + 1
    }
    return (parts[0], value)
  }
  if parts.length() == 1 {
    return (parts[0], "")
  }
  ("", "")
}

///|
/// keyword 只允许字母和数字（OpenSSH keyword 都是 ASCII 单词）。
///
/// 没有这道闸，`IdentityFile /tmp/a=b` 会被切成 keyword `IdentityFile /tmp/a`。
fn is_keyword_shaped(s : String) -> Bool {
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    let ok = (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57)
    if !ok {
      return false
    }
    i = i + 1
  }
  s.length() > 0
}

///|
/// 字符串 trim (leading + trailing whitespace)
fn trim(s : String) -> String {
  let mut start = 0
  while start < s.length() && (s[start].to_int() == ' '.to_int() || s[start].to_int() == '\t'.to_int()) {
    start = start + 1
  }
  let mut end = s.length()
  while end > start && (s[end - 1].to_int() == ' '.to_int() || s[end - 1].to_int() == '\t'.to_int()) {
    end = end - 1
  }
  let sb = StringBuilder()
  let mut i = start
  while i < end {
    sb.write_char(s[i].unsafe_to_char())
    i = i + 1
  }
  sb.to_string()
}

///|
/// 按分隔符拆分字符串 (whitespace)
fn split_whitespace(s : String) -> Array[String] {
  let parts : Array[String] = []
  let mut start = 0
  let mut i = 0
  while i < s.length() {
    let ch = s[i].to_int()
    if ch == ' '.to_int() || ch == '\t'.to_int() {
      if i > start {
        let sb = StringBuilder()
        let mut j = start
        while j < i {
          sb.write_char(s[j].unsafe_to_char())
          j = j + 1
        }
        parts.push(sb.to_string())
      }
      start = i + 1
    }
    i = i + 1
  }
  if start < s.length() {
    let sb = StringBuilder()
    let mut j = start
    while j < s.length() {
      sb.write_char(s[j].unsafe_to_char())
      j = j + 1
    }
    parts.push(sb.to_string())
  }
  parts
}

///|
/// SSH config section (一个 Host block)
pub struct SshConfigSection {
  patterns : Array[String]
  options : Array[SshConfigOption]
}

///|
/// SSH config option (一个 keyword=value 行)
pub struct SshConfigOption {
  keyword : String
  value : String
}

///|
/// Parse an ssh_config into `Array[SshConfigSection]`, in file order.
///
/// **Loop #57, three changes, each verified against `ssh -G`:**
///
/// 1. A trailing `# ...` comment is stripped anywhere on the line, not only
///    when `#` is the first character.
/// 2. `Keyword=Value` is accepted alongside `Keyword Value`.
/// 3. Options that appear **before the first `Host`** are kept as a leading
///    section with no patterns, instead of being dropped. readconf.c applies
///    them unconditionally and they take precedence over everything after,
///    which falls out of keeping them at index 0. A section with no patterns
///    matches every host -- see `section_applies` in resolve.mbt.
///
/// `Host` matching itself is case-sensitive (also checked against `ssh -G`:
/// `Host Web1` does not match host `web1`).
pub fn parse_ssh_config(content : String) -> Array[SshConfigSection] {
  let sections : Array[SshConfigSection] = []
  let mut current_patterns : Array[String] = []
  let mut current_options : Array[SshConfigOption] = []
  let mut in_section = false
  let mut saw_any = false

  let mut start = 0
  let mut i = 0
  while i <= content.length() {
    if i == content.length() || content[i].to_int() == 10 {
      let sb = StringBuilder()
      let mut j = start
      while j < i {
        sb.write_char(content[j].unsafe_to_char())
        j = j + 1
      }
      let mut line = sb.to_string()
      line = trim(strip_comment(line))

      if line.length() > 0 {
        if starts_with_ci(line, "Host ") || lower_eq(line, "host") {
          // Flush whatever we had. The `in_section` guard is what used to throw
          // the pre-Host options away; now they are flushed as a leading
          // pattern-less section, which applies to every host.
          if saw_any {
            sections.push({ patterns: current_patterns, options: current_options })
          }
          let sb2 = StringBuilder()
          let mut k = 4
          while k < line.length() {
            sb2.write_char(line[k].unsafe_to_char())
            k = k + 1
          }
          let rest = sb2.to_string()
          current_patterns = split_whitespace(rest)
          current_options = []
          in_section = true
          saw_any = true
        } else {
          let (keyword, value) = split_option(line)
          if keyword.length() > 0 {
            current_options.push({ keyword, value })
            saw_any = true
          }
        }
      }

      start = i + 1
    }
    i = i + 1
  }

  if saw_any {
    sections.push({ patterns: current_patterns, options: current_options })
  }

  sections
}

///| keyword 大小写不敏感（readconf.c 用 strcasecmp）。实测 `HOST` / `host` 都生效。
fn starts_with_ci(s : String, prefix : String) -> Bool {
  if s.length() < prefix.length() {
    return false
  }
  let mut i = 0
  while i < prefix.length() {
    if lower_char(s[i].to_int()) != lower_char(prefix[i].to_int()) {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn lower_eq(s : String, target : String) -> Bool {
  if s.length() != target.length() {
    return false
  }
  let mut i = 0
  while i < s.length() {
    if lower_char(s[i].to_int()) != lower_char(target[i].to_int()) {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn lower_char(c : Int) -> Int {
  if c >= 65 && c <= 90 { c + 32 } else { c }
}

///|
/// SSH config option 字符串表示 (用于调试/输出)
pub fn option_to_string(o : SshConfigOption) -> String {
  if o.value.length() > 0 {
    o.keyword + " " + o.value
  } else {
    o.keyword
  }
}

///|
/// 解析 ssh_config + 报告行数 (debug)
pub fn parse_ssh_config_debug(content : String) -> (Array[SshConfigSection], Int) {
  let sections : Array[SshConfigSection] = []
  let mut current_patterns : Array[String] = []
  let mut current_options : Array[SshConfigOption] = []
  let mut in_section = false
  let mut line_count = 0

  let mut start = 0
  let mut i = 0
  while i <= content.length() {
    if i == content.length() || content[i].to_int() == 10 {
      let sb = StringBuilder()
      let mut j = start
      while j < i {
        sb.write_char(content[j].unsafe_to_char())
        j = j + 1
      }
      let mut line = sb.to_string()
      line = trim(line)
      line_count = line_count + 1

      if line.length() > 0 && !starts_with(line, "#") {
        if starts_with(line, "Host ") || line == "Host" {
          if in_section && current_patterns.length() > 0 {
            sections.push({ patterns: current_patterns, options: current_options })
          }
          let sb2 = StringBuilder()
          let mut k = 4
          while k < line.length() {
            sb2.write_char(line[k].unsafe_to_char())
            k = k + 1
          }
          let rest = sb2.to_string()
          current_patterns = split_whitespace(rest)
          current_options = []
          in_section = true
        } else {
          let parts = split_whitespace(line)
          if parts.length() >= 2 {
            let keyword = parts[0]
            let mut value = parts[1]
            let mut k = 2
            while k < parts.length() {
              value = value + " " + parts[k]
              k = k + 1
            }
            current_options.push({ keyword, value })
          }
        }
      }

      start = i + 1
    }
    i = i + 1
  }

  if in_section && current_patterns.length() > 0 {
    sections.push({ patterns: current_patterns, options: current_options })
  }

  (sections, line_count)
}