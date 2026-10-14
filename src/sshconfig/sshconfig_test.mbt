///| Loop #57: unit tests for the ssh_config *rules*, not just the parse.
///
/// Loop #24 left this package with **zero** `moon test` cases -- its checks lived
/// in `cmd/sshconfig_test`, which prints values and asserts nothing. So the
/// package looked exercised and was not. Every expectation below was confirmed
/// against `ssh -G` on OpenSSH_for_Windows_9.5p2 before being written down; the
/// fixture files under `verify_c/sshconfig/` carry the same confirmations in
/// prose, and `host/verify_loop57.mjs` re-checks them against the real binary.
///
/// The cases that matter are the ones the old implementation got wrong. Each one
/// has a note saying what it used to do, because a test that only records current
/// behaviour stops being evidence the moment the behaviour is wrong again.

test "t1_first_obtained_wins_across_matching_blocks" {
  // The bug this loop is about: `Host *` at the end of a file is invisible to a
  // resolver that only looks at the first matching block.
  let cfg = "Host web1\n  User deploy\n\nHost *\n  User fallback\n  Port 2222\n"
  let s = parse_ssh_config(cfg)
  assert_eq(resolved_value("web1", s, "User"), "deploy")
  // Used to be "": `Port` only appears in the *second* matching block.
  assert_eq(resolved_value("web1", s, "Port"), "2222")
}

test "t2_options_before_the_first_host_apply_globally" {
  // Used to be dropped entirely: the parser flushed a section with no patterns
  // only when `in_section` was set, which is false before the first `Host`.
  let cfg = "User topuser\nPort 2200\n\nHost web1\n  HostName h\n\nHost *\n  ServerAliveInterval 30\n"
  let s = parse_ssh_config(cfg)
  assert_eq(resolved_value("web1", s, "User"), "topuser")
  assert_eq(resolved_value("web1", s, "Port"), "2200")
  assert_eq(resolved_value("web1", s, "ServerAliveInterval"), "30")
}

test "t3_negated_pattern_vetoes_the_whole_block" {
  // Not "that one pattern is skipped": one match on a `!` pattern discards the
  // block, positive patterns included.
  let cfg = "Host !secret *\n  Compression yes\n\nHost *\n  Compression no\n"
  let s = parse_ssh_config(cfg)
  assert_eq(resolved_value("secret", s, "Compression"), "no")
  assert_eq(resolved_value("other", s, "Compression"), "yes")
}

test "t4_keyword_is_case_insensitive_and_duplicate_takes_the_first" {
  // readconf.c uses strcasecmp. Used to compare keywords with `==`.
  let cfg = "HOST alpha\n  USER u1\n  user u2\n  PoRt 2202\n"
  let s = parse_ssh_config(cfg)
  assert_eq(resolved_value("alpha", s, "User"), "u1")
  assert_eq(resolved_value("alpha", s, "user"), "u1")
  assert_eq(resolved_value("alpha", s, "PORT"), "2202")
}

test "t5_equals_separator_and_inline_comment" {
  // Used to fail both: `Port=2202` became a keyword literally named
  // "Port=2202", and `bob # note` became the value "bob # note".
  let cfg = "Host gamma\n  User bob # trailing comment\n  ConnectTimeout=7\n"
  let s = parse_ssh_config(cfg)
  assert_eq(resolved_value("gamma", s, "User"), "bob")
  assert_eq(resolved_value("gamma", s, "ConnectTimeout"), "7")
}

test "t6_host_pattern_matching_is_case_sensitive" {
  // ssh_config(5) is ambiguous here; this was checked rather than assumed.
  // `Host Web1` does NOT match host `web1` (verified with ssh -G).
  let s = parse_ssh_config("Host Web1\n  User up\n")
  assert_eq(resolved_value("web1", s, "User"), "")
  assert_eq(resolved_value("Web1", s, "User"), "up")
}

test "t7_multivalued_keywords_accumulate" {
  // IdentityFile is in readconf.c's oMultiValued list: two matching Host blocks
  // both survive. A resolver that treats everything as first-wins silently
  // drops the second key -- and one that treats everything as accumulate turns
  // `User` into a list. So the arity has to be per-keyword.
  let cfg = "Host x\n  IdentityFile /one\nHost y\n  IdentityFile /two\nHost x\n  IdentityFile /three\n"
  let s = parse_ssh_config(cfg)
  let ids = resolved_values("x", s, "IdentityFile")
  assert_eq(ids.length(), 2)
  assert_eq(ids[0], "/one")
  assert_eq(ids[1], "/three")
  // Single-valued in the same file still keeps only the first.
  let mixed = parse_ssh_config("Host x\n  User u1\nHost *\n  User u2\n")
  assert_eq(resolved_value("x", mixed, "User"), "u1")
}

test "t8_fallback_cascades_through_several_blocks" {
  let cfg = "Host *.prod.example.com\n  User u1\n  HostName h1\n\nHost *.example.com\n  Port 2223\n\nHost *\n  IdentityFile /k/three\n  ConnectTimeout 9\n"
  let s = parse_ssh_config(cfg)
  let h = "db1.prod.example.com"
  assert_eq(resolved_value(h, s, "User"), "u1")
  assert_eq(resolved_value(h, s, "HostName"), "h1")
  // Two levels of fall-through: neither is in the first matching block.
  assert_eq(resolved_value(h, s, "Port"), "2223")
  assert_eq(resolved_value(h, s, "ConnectTimeout"), "9")
  // A host that matches only the last block still gets everything from it.
  let other = "plain.example.org"
  assert_eq(resolved_value(other, s, "ConnectTimeout"), "9")
  assert_eq(resolved_value(other, s, "User"), "")
}

test "t9_match_host_option_agrees_with_the_resolver" {
  // The Loop #24 entry point now delegates, so it cannot drift from the rules.
  let cfg = "Host web1\n  User deploy\n\nHost *\n  Port 2222\n"
  let s = parse_ssh_config(cfg)
  match match_host_option("web1", s, "Port") {
    Some(v) => assert_eq(v, "2222")
    None => fail("match_host_option lost the Host * fallback")
  }
  match match_host_option("web1", s, "Nothing") {
    Some(_) => fail("a keyword that is in no block should not resolve")
    None => ()
  }
}

test "t10_fnmatch_agrees_with_openssh_on_every_loop24_case" {
  // Loop #24's fnmatch block counted passing `if` conditions and printed the
  // count against a **hardcoded** `fnmatch_total = 23`, then exited 0 either way.
  // It holds **25** conditions, so it printed "23/23" -- which reads as fully
  // green while the arithmetic behind it could not be. Nobody noticed, because
  // the number in the denominator was a constant rather than a measurement.
  //
  // It was also wrong on two of them. It counted a pass for
  // `!fnmatch("a*b*c", "abdc")`, asserting the two do NOT match; checked with
  // `ssh -G`, they do (a + "" + b + "d" + c is exactly that pattern). And it
  // counted a pass for `fnmatch("*.ngs.fi", "ngs.fi")`, asserting they DO match;
  // checked, they do not -- `*` can match the empty string, but `.ngs.fi` still
  // has to match `ngs.fi` afterwards and the lengths differ.
  //
  // Both errors were in the direction of claiming *more* matches than glob gives.
  // The implementation was right and the test was wrong, twice.
  //
  // Every expectation below is OpenSSH's, not this implementation's.
  let cases = [
    ("hello", "hello", true),
    ("hello", "world", false),
    ("h?llo", "hello", true),
    ("h?llo", "hallo", true),
    ("h?llo", "heello", false),
    ("h*o", "hello", true),
    ("h*o", "ho", true),
    ("h*o", "haooooooo", true),
    ("h*o", "haaa", false),
    ("*.example.com", "foo.example.com", true),
    ("*.example.com", "a.b.c.example.com", true),
    ("*.example.com", "foo.example.org", false),
    ("*", "", true),
    ("*", "anything", true),
    ("*", "a", true),
    ("*.ngs.fi", "a.ngs.fi", true),
    // Loop #24 asserted true here as well. `*` matching the empty string is
    // real, but it does not help: after `*` consumes "", the pattern still has
    // ".ngs.fi" to match against "ngs.fi", and those are different lengths.
    // Checked with `ssh -G` on a `Host *.ngs.fi` block: no match.
    ("*.ngs.fi", "ngs.fi", false),
    ("ngs.fi", "ngs.fi", true),
    ("ngs.fi", "foo.ngs.fi", false),
    ("books.*", "books.com", true),
    ("books.*", "books.org", true),
    ("books.*", "mybooks.com", false),
    ("a*b*c", "abc", true),
    ("a*b*c", "aXbYc", true),
    ("a*b*c", "aXXXXXXXbXXXXXXXc", true),
    ("a*b*c", "abdc", true),
  ]
  let mut mismatched = 0
  let mut i = 0
  while i < cases.length() {
    let (pat, s, expect) = cases[i]
    let got = fnmatch(pat, s)
    if got != expect {
      mismatched = mismatched + 1
      println(
        "fnmatch(" + pat + ", " + s + ") = " + got.to_string() +
        ", OpenSSH says " + expect.to_string(),
      )
    }
    i = i + 1
  }
  // Counting first and printing the offenders means a failure names the case
  // instead of collapsing 25 of them into one line number.
  assert_eq(mismatched, 0)
}