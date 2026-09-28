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
/// 解析 ssh_config (整段文本) → Array[SshConfigSection]
pub fn parse_ssh_config(content : String) -> Array[SshConfigSection] {
  let sections : Array[SshConfigSection] = []
  let mut current_patterns : Array[String] = []
  let mut current_options : Array[SshConfigOption] = []
  let mut in_section = false

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
          } else if parts.length() == 1 {
            current_options.push({ keyword: parts[0], value: "" })
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

  sections
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