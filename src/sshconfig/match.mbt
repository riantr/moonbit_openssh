///| SSH config Host pattern matching (Loop #24 G3)
///|
/// 给定 hostname + Array[SshConfigSection],返回首个 patterns 包含 hostname 的 section
/// OpenSSH 行为: "first match wins" — 找到第一个匹配就返回

///|
/// 给定 hostname,返回首个匹配的 section (Option 类型)
pub fn match_host_section(
  hostname : String,
  sections : Array[SshConfigSection],
) -> Option[SshConfigSection] {
  for section in sections {
    for pattern in section.patterns {
      if fnmatch(pattern, hostname) {
        return Some(section)
      }
    }
  }
  None
}

///|
/// 给定 hostname + sections,返回首个匹配 section 的特定 keyword value (Option)
pub fn match_host_option(
  hostname : String,
  sections : Array[SshConfigSection],
  keyword : String,
) -> Option[String] {
  match match_host_section(hostname, sections) {
    Some(section) => {
      for opt in section.options {
        if opt.keyword == keyword {
          if opt.value.length() > 0 {
            return Some(opt.value)
          } else {
            return Some("")  // boolean true
          }
        }
      }
      None
    }
    None => None
  }
}