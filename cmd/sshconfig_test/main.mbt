///| Loop #24 ssh_config fnmatch/parser/match byte-exact 验证
///|
/// 10 行 byte-exact 跨 4 target × 2 mode

fn main {
  // ============ G1 fnmatch KAT tests ============
  //
  // Loop #57: this block used to hold 25 inline `if` conditions, print how many
  // passed against a **hardcoded** 23, and exit 0 either way -- so it printed
  // "23/23" while the arithmetic behind it could not be. Two of its expectations
  // were also wrong (both checked against `ssh -G`; both are recorded in the
  // package test below).
  //
  // The block is gone rather than fixed. The same 25 expectations now live once,
  // as a table, in `src/sshconfig/sshconfig_test.mbt` t10, where a mismatch is
  // counted and asserted rather than printed. Keeping a second copy here is what
  // let the two drift apart in the first place: one of them was edited and the
  // other was not, and the copy that drifted was the one a human read.
  //
  // Run `moon test src/sshconfig` for the fnmatch cases.

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
