///| SSH config Host pattern matching (Loop #24 G3)

///|
/// 给定 hostname + Array[SshConfigSection],返回首个 patterns 包含 hostname 的 section
/// OpenSSH 行为: "first match wins" — 找到第一个匹配就返回

///|
/// 给定 hostname,返回首个匹配的 section (Option 类型)
pub fn match_host_section(
  hostname : String,
  sections : Array[SshConfigSection],
) -> SshConfigSection? {
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
/// 给定 hostname + sections,返回 keyword 的生效值 (Option)。
///
/// **Loop #57: 委托给 `resolve_host`。** 旧实现在这里只搜**首个**匹配块，
/// 所以 `Host *` 这种放在文件末尾的默认块完全看不见——而那恰恰是全世界最常见的
/// 写法。实测对拍：
///
/// ```
/// Host web1
///   User deploy
/// Host *
///   Port 2222
/// ```
///
/// `ssh -G web1` 给出 `user deploy` 和 `port 2222`；旧实现在 Port 上返回 None。
///
/// 「首个匹配块」本身没有错——`match_host_section` 保留那个语义，它是个合理的
/// 提问。错的是把「首个块里有这个 keyword」当成「这个 keyword 的生效值」。
pub fn match_host_option(
  hostname : String,
  sections : Array[SshConfigSection],
  keyword : String,
) -> String? {
  let opts = resolve_host(hostname, sections)
  let k = lower(keyword)
  let mut i = 0
  while i < opts.length() {
    if lower(opts[i].keyword) == k {
      return Some(opts[i].value)
    }
    i = i + 1
  }
  None
}

///|
fn lower(s : String) -> String {
  let b = StringBuilder()
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    b.write_char(
      if c >= 65 && c <= 90 {
        (c + 32).unsafe_to_char()
      } else {
        s[i].unsafe_to_char()
      },
    )
    i = i + 1
  }
  b.to_string()
}
