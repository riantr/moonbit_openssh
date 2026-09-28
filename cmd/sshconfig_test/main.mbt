///| Loop #24 ssh_config fnmatch/parser/match byte-exact 验证
///|
/// 10 行 byte-exact 跨 4 target × 2 mode

fn main {
  // ============ G1 fnmatch KAT tests ============
  let fnmatch_pass = fnmatch_tests()
  let fnmatch_total = 23
  println("fnmatch_pass: " + fnmatch_pass.to_string() + "/" + fnmatch_total.to_string())

  // ============ G2 ssh_config parser ============
  let sample_config = "# Sample ssh_config\n\nHost *.example.com\n    User foo\n    Port 2222\n\nHost *.ngs.fi ngs.fi\n    User bar\n    HostName real.host\n\nHost *\n    ForwardAgent no\n"
  let sections = @sshconfig.parse_ssh_config(sample_config)
  let parsed_sections = sections.length().to_string()
  println("parsed_sections: " + parsed_sections)

  // ============ G3 Host pattern matching ============
  let section_match = match @sshconfig.match_host_section("foo.example.com", sections) {
    Some(_) => "yes"
    None => "no"
  }
  println("foo.example.com match: " + section_match)

  let user_for_foo = match @sshconfig.match_host_option("foo.example.com", sections, "User") {
    Some(v) => v
    None => "none"
  }
  println("foo.example.com User: " + user_for_foo)

  let port_for_foo = match @sshconfig.match_host_option("foo.example.com", sections, "Port") {
    Some(v) => v
    None => "none"
  }
  println("foo.example.com Port: " + port_for_foo)

  let user_for_ngs = match @sshconfig.match_host_option("ngs.fi", sections, "User") {
    Some(v) => v
    None => "none"
  }
  println("ngs.fi User: " + user_for_ngs)

  let host_for_ngs = match @sshconfig.match_host_option("ngs.fi", sections, "HostName") {
    Some(v) => v
    None => "none"
  }
  println("ngs.fi HostName: " + host_for_ngs)

  let fwd_for_unknown = match @sshconfig.match_host_option("unknown.host", sections, "ForwardAgent") {
    Some(v) => v
    None => "none"
  }
  println("unknown.host ForwardAgent: " + fwd_for_unknown)

  let no_match = match @sshconfig.match_host_option("foo.example.com", sections, "NonExistent") {
    Some(v) => v
    None => "none"
  }
  println("foo.example.com NonExistent: " + no_match)
}

// ============================================================================
// fnmatch KAT tests
// ============================================================================

fn fnmatch_tests() -> Int {
  let mut pass = 0

  // Basic exact match
  if @sshconfig.fnmatch("hello", "hello") { pass = pass + 1 }
  if !@sshconfig.fnmatch("hello", "world") { pass = pass + 1 }

  // ? 匹配单字符
  if @sshconfig.fnmatch("h?llo", "hello") { pass = pass + 1 }
  if @sshconfig.fnmatch("h?llo", "hallo") { pass = pass + 1 }
  if !@sshconfig.fnmatch("h?llo", "heello") { pass = pass + 1 }

  // * 匹配任意长度
  if @sshconfig.fnmatch("h*o", "hello") { pass = pass + 1 }
  if @sshconfig.fnmatch("h*o", "ho") { pass = pass + 1 }
  if @sshconfig.fnmatch("h*o", "haooooooo") { pass = pass + 1 }
  if !@sshconfig.fnmatch("h*o", "haaa") { pass = pass + 1 }

  // 多个 *
  if @sshconfig.fnmatch("*.example.com", "foo.example.com") { pass = pass + 1 }
  if @sshconfig.fnmatch("*.example.com", "a.b.c.example.com") { pass = pass + 1 }
  if !@sshconfig.fnmatch("*.example.com", "foo.example.org") { pass = pass + 1 }

  // * 通配整个
  if @sshconfig.fnmatch("*", "") { pass = pass + 1 }
  if @sshconfig.fnmatch("*", "anything") { pass = pass + 1 }
  if @sshconfig.fnmatch("*", "a") { pass = pass + 1 }

  // 多 Host pattern (空格分隔的 patterns)
  if @sshconfig.fnmatch("*.ngs.fi", "ngs.fi") { pass = pass + 1 }
  if @sshconfig.fnmatch("ngs.fi", "ngs.fi") { pass = pass + 1 }
  if !@sshconfig.fnmatch("ngs.fi", "foo.ngs.fi") { pass = pass + 1 }

  // 复杂 Host patterns (OpenSSH ssh_config 常用)
  if @sshconfig.fnmatch("books.*", "books.com") { pass = pass + 1 }
  if @sshconfig.fnmatch("books.*", "books.org") { pass = pass + 1 }
  if !@sshconfig.fnmatch("books.*", "mybooks.com") { pass = pass + 1 }

  // 嵌套 *
  if @sshconfig.fnmatch("a*b*c", "abc") { pass = pass + 1 }
  if @sshconfig.fnmatch("a*b*c", "aXbYc") { pass = pass + 1 }
  if @sshconfig.fnmatch("a*b*c", "aXXXXXXXbXXXXXXXc") { pass = pass + 1 }
  if !@sshconfig.fnmatch("a*b*c", "abdc") { pass = pass + 1 }

  pass
}