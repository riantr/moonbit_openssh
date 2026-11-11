///| Unit tests for the `scp` command-line rules.
///
/// Every expectation here is a sentence that `.loop90/probe_*.py` read out
/// of the real `scp.exe`; the probes are the source, these are the
/// regression net.  Where a test looks arbitrary it is because the real
/// tool is arbitrary at that point, and the comment says which measured
/// run it came from.
///
/// This is a **black-box** test (`*_test.mbt`, not `*_wbtest.mbt`), so
/// everything from the package is written `@scp.…`.  Only public API is
/// exercised, which is the point: the rules are public so a gate can use
/// them.

// ---------------------------------------------------------------- usage

///|
test "usage block is the measured text, with LF not CRLF" {
  let u = @scp.usage_text()
  // The three lines, with the eleven-space continuation indent that lines
  // up under "usage: scp " (7 + 4).
  assert_true(u.has_prefix("usage: scp [-346ABCOpqRrsTv] [-c cipher]"))
  assert_true(u.contains("[-D sftp_server_path] [-F ssh_config]\n"))
  assert_true(u.contains("           [-i identity_file] [-J destination]"))
  assert_true(u.contains("           [-P port] [-S program] [-X sftp_option]"))
  assert_true(u.has_suffix("source ... target\n"))
  // A `\r` here would be doubled by the Windows runtime, which turns each
  // `\n` into `\r\n` on the way out.  The real tool's captured stderr has
  // exactly one `\r\n` per line, so the string must carry none.
  assert_false(u.contains("\r"))
  // Three lines means three newlines.
  let mut newlines = 0
  for i = 0; i < u.length(); i = i + 1 {
    if u[i].to_int() == 10 {
      newlines = newlines + 1
    }
  }
  assert_eq(newlines, 3)
}

// ------------------------------------------------------- option surface

///|
test "every measured no-value option is accepted" {
  // Round 9 identified these by running `scp -<X>` with no positionals:
  // they reach the "need two args" check instead of an unknown-option
  // error.
  let cases = [
    "2", "3", "4", "6", "d", "p", "q", "r", "s", "v", "A", "B", "C", "O", "R", "T",
    "f", "t",
  ]
  for i = 0; i < cases.length(); i = i + 1 {
    let r = @scp.parse_args(["-" + cases[i], "a", "b"])
    match r {
      @scp.Options(_) => ()
      other =>
        fail(
          "option -" + cases[i] + " should be accepted, got " + describe(other),
        )
    }
  }
}

///|
test "every measured value-taking option is accepted and keeps its value" {
  let r = @scp.parse_args([
    "-c", "aes", "-i", "k1", "-i", "k2", "-o", "Opt=1", "-D", "srv.exe", "-F", "cfg",
    "-J", "jump", "-M", "m", "-P", "2222", "-S", "prog", "-X", "xopt", "a", "b",
  ])
  match r {
    @scp.Options(o) => {
      assert_eq(o.cipher, "aes")
      // -i accumulates: the real tool accepts several identity files.
      assert_eq(o.identity_files.length(), 2)
      assert_eq(o.identity_files[0], "k1")
      assert_eq(o.identity_files[1], "k2")
      assert_eq(o.ssh_options[0], "Opt=1")
      assert_eq(o.sftp_server_path, "srv.exe")
      assert_eq(o.ssh_config, "cfg")
      assert_eq(o.jump, "jump")
      assert_eq(o.extra_flag_m, "m")
      assert_eq(o.port, 2222)
      assert_true(o.port_given)
      assert_eq(o.ssh_program, "prog")
      assert_eq(o.sftp_options[0], "xopt")
    }
    other => fail("expected options, got " + describe(other))
  }
}

///|
test "unknown options carry the offending letter, and --nonsense is a dash" {
  // All three measured against the real binary (round 7).
  match @scp.parse_args(["-h"]) {
    @scp.Refused(@scp.UnknownOption(c)) => assert_eq(c.to_string(), "h")
    other => fail("expected unknown -h, got " + describe(other))
  }
  match @scp.parse_args(["-Z"]) {
    @scp.Refused(@scp.UnknownOption(c)) => assert_eq(c.to_string(), "Z")
    other => fail("expected unknown -Z, got " + describe(other))
  }
  // BSD getopt strips one '-', then reads the next character as the
  // option letter -- so the letter is '-' itself.
  match @scp.parse_args(["--nonsense"]) {
    @scp.Refused(@scp.UnknownOption(c)) => assert_eq(c.to_string(), "-")
    other => fail("expected unknown --, got " + describe(other))
  }
}

///|
test "a value-taking option at the end of argv needs its argument" {
  // Round 7: `scp -P` alone answers "option requires an argument -- P".
  let values = ["c", "i", "l", "o", "D", "F", "J", "M", "P", "S", "X"]
  for i = 0; i < values.length(); i = i + 1 {
    match @scp.parse_args(["-" + values[i]]) {
      @scp.Refused(@scp.MissingArgument(c)) =>
        assert_eq(c.to_string(), values[i])
      other =>
        fail(
          "-" + values[i] + " should need an argument, got " + describe(other),
        )
    }
  }
}

///|
test "the message text matches what getopt prints" {
  assert_eq(@scp.arg_error_text(@scp.UnknownOption('h')), "unknown option -- h")
  assert_eq(
    @scp.arg_error_text(@scp.MissingArgument('P')),
    "option requires an argument -- P",
  )
}

///|
test "-1 is a fatal refusal with its own sentence" {
  match @scp.parse_args(["-1", "a", "b"]) {
    @scp.ProtocolV1 => ()
    other => fail("expected ProtocolV1, got " + describe(other))
  }
  assert_eq(
    @scp.unsupported_protocol_v1_text(),
    "SSH protocol v.1 is no longer supported",
  )
}

// ------------------------------------------------------------ clustering

///|
test "short options cluster, and a value option takes the rest of the cluster" {
  // `-rp` is two flags (round 8: the real tool copied with both in
  // effect).
  match @scp.parse_args(["-rp", "a", "b"]) {
    @scp.Options(o) => {
      assert_true(o.recursive)
      assert_true(o.preserve)
    }
    other => fail("expected -rp to cluster, got " + describe(other))
  }
  // `-P22` attaches the value instead of consuming "22" as a positional.
  match @scp.parse_args(["-P22", "a", "b"]) {
    @scp.Options(o) => {
      assert_eq(o.port, 22)
      assert_eq(o.positionals.length(), 2)
    }
    other => fail("expected -P22 to attach, got " + describe(other))
  }
  // A cluster whose last letter takes a value takes the next argv.
  match @scp.parse_args(["-rP", "22", "a", "b"]) {
    @scp.Options(o) => {
      assert_true(o.recursive)
      assert_eq(o.port, 22)
    }
    other => fail("expected -rP 22 to work, got " + describe(other))
  }
}

// --------------------------------------------------- positionals and `--`

///|
test "option parsing stops at the first non-option" {
  // Round 8: `scp a.txt out.txt -r` treats `-r` as a THIRD POSITIONAL, so
  // there are three of them and the last must be a directory.
  match @scp.parse_args(["a.txt", "out.txt", "-r"]) {
    @scp.Options(o) => {
      assert_eq(o.positionals.length(), 3)
      assert_eq(o.positionals[2], "-r")
      assert_false(o.recursive)
    }
    other => fail("expected three positionals, got " + describe(other))
  }
}

///|
test "-- ends the options and is not itself a positional" {
  match @scp.parse_args(["--", "a", "b"]) {
    @scp.Options(o) => {
      assert_eq(o.positionals.length(), 2)
      assert_eq(o.positionals[0], "a")
    }
    other => fail("expected two positionals, got " + describe(other))
  }
  // `scp --` alone has no positionals at all.
  match @scp.parse_args(["--"]) {
    @scp.NeedUsage => ()
    other => fail("expected usage for --, got " + describe(other))
  }
}

///|
test "fewer than two positionals is a usage error" {
  // Round 7: no arguments, one positional, and any option with no
  // positionals all print the usage block and exit 1.
  let cases : Array[Array[String]] = [
    [],
    ["onlyone"],
    ["-r"],
    ["-v"],
    ["-q"],
    ["-3"],
    ["-T"],
    ["-O"],
  ]
  for i = 0; i < cases.length(); i = i + 1 {
    match @scp.parse_args(cases[i]) {
      @scp.NeedUsage => ()
      other =>
        fail(
          "expected usage for " +
          describe_args(cases[i]) +
          ", got " +
          describe(other),
        )
    }
  }
}

// ------------------------------------------------------------ validators

///|
test "-l accepts exactly the spellings strtonum accepts" {
  // Measured (round 10).  Leading whitespace and a '+' sign are fine; a
  // trailing space, a suffix, a hex prefix and a decimal point are not.
  let good = ["1", "8", "+8", " 8", "08", "999999999"]
  for i = 0; i < good.length(); i = i + 1 {
    assert_true(@scp.limit_is_valid(good[i]))
  }
  let bad = [
    "0", "-1", "8 ", "8x", "x8", "1e3", "", "0x10", "0.5", "999999999999999999999",
  ]
  for i = 0; i < bad.length(); i = i + 1 {
    assert_false(@scp.limit_is_valid(bad[i]))
  }
}

///|
test "-P refuses out-of-range and non-numeric with the bad-port sentence" {
  // Measured (round 10): valid ports pass; everything else is the fatal
  // "bad port" path with status 255, NOT the usage block.
  let good = ["1", "22", "2222", "65535", " 22", "+22"]
  for i = 0; i < good.length(); i = i + 1 {
    assert_true(@scp.port_is_valid(good[i]))
  }
  let bad = ["0", "-1", "65536", "70000", "abc", "2x", "22 ", ""]
  for i = 0; i < bad.length(); i = i + 1 {
    assert_false(@scp.port_is_valid(bad[i]))
  }
  match @scp.parse_args(["-P", "0", "a", "b"]) {
    @scp.BadPort(v) => {
      assert_eq(v, "0")
      // The embedded newline is part of the real message.
      assert_eq(@scp.port_error_text(v), "bad port \"0\"\n")
    }
    other => fail("expected BadPort, got " + describe(other))
  }
  // -l refuses by usage instead, which is a different constructor.
  match @scp.parse_args(["-l", "0", "a", "b"]) {
    @scp.NeedUsage => ()
    other => fail("expected usage for -l 0, got " + describe(other))
  }
}

// --------------------------------------------------------- spec splitting

///|
test "drive letters are local and multi-letter hosts are remote" {
  // The boundary, measured on both sides (rounds 8, 9, 10).
  //
  // machine-path-exempt: these strings are INPUTS to the is_remote rule,
  // not files this machine is expected to have -- `C:\Windows\win.ini` is
  // here because it is the shape a drive letter takes, and the rule is
  // about colons, not about that file existing.
  let local_cases = [
    "a.txt", "C:\\Windows\\win.ini", "h:x", "a:b:c", ":x", "C:x", "no-colon-here",
  ]
  for i = 0; i < local_cases.length(); i = i + 1 {
    assert_true(@scp.is_local(local_cases[i]))
  }
  let remote_cases = ["hh:x", "host:x", "host:", "host:a:b", "1.2.3.4:x"]
  for i = 0; i < remote_cases.length(); i = i + 1 {
    assert_false(@scp.is_local(remote_cases[i]))
  }
}

///|
test "a remote spec keeps its three parts exactly" {
  match @scp.split_spec("host:/tmp/x") {
    @scp.Remote(user, host, path) => {
      assert_true(user is None)
      assert_eq(host, "host")
      assert_eq(path, "/tmp/x")
    }
    other => fail("expected remote, got " + describe_spec(other))
  }
  match @scp.split_spec("user@host:/tmp/x") {
    @scp.Remote(user, host, path) => {
      assert_true(user == Some("user"))
      assert_eq(host, "host")
      assert_eq(path, "/tmp/x")
    }
    other => fail("expected remote with user, got " + describe_spec(other))
  }
  // An @ defeats the drive rule: one-letter host, still a host.
  match @scp.split_spec("user@h:x") {
    @scp.Remote(user, host, path) => {
      assert_true(user == Some("user"))
      assert_eq(host, "h")
      assert_eq(path, "x")
    }
    other => fail("expected user@h:x remote, got " + describe_spec(other))
  }
  // The path half is not rewritten: separators belong to the server.
  match @scp.split_spec("host:srv\\a/b") {
    @scp.Remote(_, _, path) => assert_eq(path, "srv\\a/b")
    other => fail("expected remote, got " + describe_spec(other))
  }
}

///|
test "a bracketed IPv6 literal is a host, colons inside included" {
  match @scp.split_spec("[::1]:x") {
    @scp.Remote(_, host, path) => {
      assert_eq(host, "[::1]")
      assert_eq(path, "x")
    }
    other => fail("expected bracketed remote, got " + describe_spec(other))
  }
}

///|
test "basenames accept both separators and ignore trailing ones" {
  assert_eq(@scp.basename_of("local/t"), "t")
  assert_eq(@scp.basename_of("local\\t"), "t")
  assert_eq(@scp.basename_of("local/t/"), "t")
  assert_eq(@scp.basename_of("t"), "t")
  assert_eq(@scp.basename_of(""), "")
}

///|
test "remote_join does not double a separator" {
  assert_eq(@scp.remote_join("srv", "x.txt"), "srv/x.txt")
  assert_eq(@scp.remote_join("srv/", "x.txt"), "srv/x.txt")
  assert_eq(@scp.remote_join("", "x.txt"), "x.txt")
}

// ------------------------------------------------------------- reporting

///|
fn describe(p : @scp.ParsedArgs) -> String {
  match p {
    @scp.Options(o) => "Options(" + describe_args(o.positionals) + ")"
    @scp.Refused(@scp.UnknownOption(c)) =>
      "Refused(unknown " + c.to_string() + ")"
    @scp.Refused(@scp.MissingArgument(c)) =>
      "Refused(missing " + c.to_string() + ")"
    @scp.ProtocolV1 => "ProtocolV1"
    @scp.BadPort(v) => "BadPort(" + v + ")"
    @scp.NeedUsage => "NeedUsage"
  }
}

///|
fn describe_args(args : Array[String]) -> String {
  let out = StringBuilder()
  out.write_char('[')
  for i = 0; i < args.length(); i = i + 1 {
    if i > 0 {
      out.write_char(',')
    }
    out.write_string(args[i])
  }
  out.write_char(']')
  out.to_string()
}

///|
fn describe_spec(s : @scp.Spec) -> String {
  match s {
    @scp.Local(p) => "Local(" + p + ")"
    @scp.Remote(u, h, p) =>
      "Remote(" + (if u is Some(x) { x } else { "-" }) + "," + h + "," + p + ")"
  }
}
