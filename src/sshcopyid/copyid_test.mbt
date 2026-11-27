///| Loop #103: the rules, pinned.
///
/// The golden values here are **upstream's own bytes**, captured from the
/// real script by `host/copyid_probe.sh` (which runs it with a stand-in
/// `ssh` and keeps every byte) and compared with the same arguments by
/// `host/verify_loop103.mjs`.  They are not written from memory and not
/// copied from `ssh-copy-id.c`: the shell script is the reference, and it
/// was read out of the script itself.
///
/// The test lives in the package it tests, so the rules are called by
/// their own names.

///|
fn assert_true(b : Bool) -> Unit {
  if !b {
    abort("expected true")
  }
}

///|
fn assert_eq(a : String, b : String) -> Unit {
  if a != b {
    abort("expected:\n" + a + "\ngot:\n" + b)
  }
}

///|
fn assert_int_eq(a : Int32, b : Int32) -> Unit {
  if a != b {
    abort("expected " + b.to_string() + ", got " + a.to_string())
  }
}

///|
fn assert_opt_eq(a : String?, b : String?) -> Unit {
  match (a, b) {
    (Some(x), Some(y)) => if x != y { abort("expected " + y + ", got " + x) }
    (None, None) => ()
    (Some(x), None) => abort("expected None, got " + x)
    (None, Some(y)) => abort("expected " + y + ", got None")
  }
}

///|
/// The command upstream sends, byte for byte.
///
/// Captured from the real script's own argv: the install call's last
/// argument, with the target path substituted the way upstream substitutes
/// it (`AUTH_KEY_FILE="${TARGET_PATH}"`).
///
/// The dollars and the backticks are written as escapes for the reason
/// `install.mbt` gives: MoonBit's JS backend would read the shell's
/// `${AUTH_KEY_FILE}` as a JavaScript interpolation.  The bytes at run time
/// are upstream's either way.
const UPSTREAM_POSIX_COMMAND : String = "exec sh -c ' cd; umask 077; AUTH_KEY_FILE=\".ssh/authorized_keys\"; [ -f /etc/openwrt_release ] && { [ \"\u{24}LOGNAME\" = \"root\" ] || [ \"\u{24}(id -u)\" = \"0\" ]; } && AUTH_KEY_FILE=/etc/dropbear/authorized_keys; [ \"\u{60}uname -s\u{60}\" = \"Haiku\" ] && AUTH_KEY_FILE=config/settings/ssh/authorized_keys; AUTH_KEY_DIR=\u{60}dirname \"\u{24}{AUTH_KEY_FILE}\"\u{60}; mkdir -p \"\u{24}{AUTH_KEY_DIR}\" && { [ -z \"\u{60}tail -1c \"\u{24}{AUTH_KEY_FILE}\" 2>/dev/null\u{60}\" ] || echo >> \"\u{24}{AUTH_KEY_FILE}\" || exit 1; } && cat >> \"\u{24}{AUTH_KEY_FILE}\" || exit 1; if type restorecon >/dev/null 2>&1; then restorecon -F \"\u{24}{AUTH_KEY_DIR}\" \"\u{24}{AUTH_KEY_FILE}\"; fi '"

///|
/// The POSIX command is upstream's, byte for byte.
///
/// The space after `sh -c '` is upstream's (the here-document's first line
/// was empty and `tr` turned its newline into that space) and so is the
/// trailing `; fi '`.
test "the posix install command is upstream's own bytes" {
  assert_eq(
    @sshcopyid.install_command_posix(".ssh/authorized_keys"),
    UPSTREAM_POSIX_COMMAND,
  )
}

///|
/// A different target path changes exactly one place.
test "the posix install command carries the target path" {
  let cmd = @sshcopyid.install_command_posix("srv/keys")
  assert_true(cmd.contains("AUTH_KEY_FILE=\"srv/keys\""))
  assert_true(cmd.contains("exec sh -c ' cd; umask 077;"))
  assert_true(@sshcopyid.has_suffix(cmd, "; fi '"))
}

///|
/// The Windows command is `powershell -NoProfile -EncodedCommand` and
/// nothing else, because `cmd.exe` eats a pipe and a quote.
test "the windows install command is base64 and nothing else" {
  let cmd = @sshcopyid.install_command_windows(".ssh/authorized_keys")
  assert_true(
    @sshcopyid.has_prefix(cmd, "powershell -NoProfile -EncodedCommand "),
  )
  // No character that `cmd.exe` would act on.
  assert_true(!cmd.contains("|"))
  assert_true(!cmd.contains("&"))
  assert_true(!cmd.contains(">"))
  assert_true(!cmd.contains("\""))
  assert_true(!cmd.contains("'"))
}

///|
/// The target path travels as base64, so the script stays ASCII and a path
/// with a non-ASCII name still works.
test "the windows command carries the target path as base64" {
  // machine-path-exempt: the drive-letter path below is a VECTOR -- the shape
  // a Windows path takes, which the base64 test needs -- and not a file this
  // machine is expected to have.
  let path = "E:\\keys\\authorized_keys"
  let b64 = @sshcopyid.base64_of(@sshcopyid.utf8_bytes_of(path))
  assert_true(b64.length() > 0)
  // The path's own bytes are in the encoded script, not in the command.
  let cmd = @sshcopyid.install_command_windows(path)
  assert_true(!cmd.contains("keys"))
}

///|
/// The script does what upstream's one-liner does: make the directory,
/// add a newline if the file does not end with one, append stdin.
test "the windows script does the three things upstream's one-liner does" {
  let body = @sshcopyid.windows_script_body()
  assert_true(body.contains("[IO.Directory]::CreateDirectory($d)"))
  assert_true(
    body.contains(
      "if($b -ne 10){[IO.File]::AppendAllText($p,[string][char]10)}",
    ),
  )
  assert_true(
    body.contains("[IO.File]::AppendAllText($p,[Console]::In.ReadToEnd())"),
  )
}

///|
/// The probe that asks the far side what it is.
test "the os probe is the one that was measured" {
  assert_eq(@sshcopyid.os_probe_command(), "echo %OS%")
  assert_true(@sshcopyid.probe_says_windows("Windows_NT\r\n"))
  assert_true(!@sshcopyid.probe_says_windows("%OS%\r\n"))
}

///|
/// The sentences, byte for byte, from the captured upstream output.
test "the sentences are upstream's own bytes" {
  assert_eq(
    @sshcopyid.info_source("/usr/bin/ssh-copy-id", "/srv/u/.ssh/id_rsa.pub"),
    "/usr/bin/ssh-copy-id: INFO: Source of key(s) to be installed: \"/srv/u/.ssh/id_rsa.pub\"",
  )
  assert_eq(
    @sshcopyid.info_filtering("/usr/bin/ssh-copy-id"),
    "/usr/bin/ssh-copy-id: INFO: attempting to log in with the new key(s), to filter out any that are already installed",
  )
  assert_eq(
    @sshcopyid.info_remaining("/usr/bin/ssh-copy-id", 1),
    "/usr/bin/ssh-copy-id: INFO: 1 key(s) remain to be installed -- if you are prompted now it is to install the new keys",
  )
}

///|
/// The closing block, line by line, including the blank lines.
test "the closing block is upstream's shape" {
  let (lines, to_stderr) = @sshcopyid.copy_id_text(
    "ssh-copy-id",
    @sshcopyid.CopyIdText::Added(1, "ssh 'u@h'"),
  )
  assert_true(!to_stderr)
  assert_int_eq(lines.length(), 6)
  assert_eq(lines[0], "")
  assert_eq(lines[1], "Number of key(s) added: 1")
  assert_eq(lines[2], "")
  assert_eq(lines[3], "Now try logging into the machine, with: \"ssh 'u@h'\"")
  assert_eq(
    lines[4],
    "and check to make sure that only the key(s) you wanted were added.",
  )
  assert_eq(lines[5], "")
}

///|
/// The "already installed" block, which upstream prints to stderr.
test "the skipped block is upstream's shape" {
  let (lines, to_stderr) = @sshcopyid.copy_id_text(
    "ssh-copy-id",
    @sshcopyid.CopyIdText::AllSkipped,
  )
  assert_true(to_stderr)
  assert_int_eq(lines.length(), 4)
  assert_eq(lines[0], "")
  assert_eq(
    lines[1],
    "ssh-copy-id: WARNING: All keys were skipped because they already exist on the remote system.",
  )
  assert_eq(
    lines[2],
    "\t\t(if you think this is a mistake, you may want to use -f option)",
  )
  assert_eq(lines[3], "")
}

///|
/// The usage block, line for line.
test "the usage block is upstream's shape" {
  let (lines, to_stderr) = @sshcopyid.copy_id_text(
    "ssh-copy-id",
    @sshcopyid.CopyIdText::Usage,
  )
  assert_true(to_stderr)
  assert_int_eq(lines.length(), 6)
  assert_eq(
    lines[0],
    "Usage: ssh-copy-id [-h|-?|-f|-n|-s|-x] [-i [identity_file]] [-t target_path] [-F ssh_config] [[-o ssh_option] ...] [-p port] [user@]hostname",
  )
  assert_eq(
    lines[1],
    "\t-f: force mode -- copy keys without trying to check if they are already installed",
  )
  assert_eq(lines[2], "\t-n: dry run    -- no keys are actually copied")
  assert_eq(
    lines[3],
    "\t-s: use sftp   -- use sftp instead of executing remote-commands. Can be useful if the remote only allows sftp",
  )
  assert_eq(
    lines[4],
    "\t-x: debug      -- enables -x in this shell, for debugging",
  )
  assert_eq(lines[5], "\t-h|-?: print this help")
}

///|
/// The private key path is upstream's `dirname(pub) + "/" + basename(pub)`,
/// mixed separators included.
test "the private path is upstream's shape" {
  // machine-path-exempt: the drive-letter paths below are VECTORS for
  // upstream's dirname/basename shape, not files this machine has.
  assert_eq(
    @sshcopyid.private_path_of("E:\\dir\\id_ecdsa.pub"),
    "E:\\dir/id_ecdsa",
  )
  assert_eq(@sshcopyid.private_path_of("id.pub"), "./id")
}

///|
/// The closing sentence's hint, with the pieces upstream puts in it.
test "the closing hint carries the options that were given" {
  let o = @sshcopyid.parse_args(
    ["ssh-copy-id", "-i", "key", "-p", "2222", "u@h"],
    fn(_ : String) -> Bool { false },
  )
  match o {
    Ok(opts) =>
      assert_eq(
        @sshcopyid.closing_hint(opts, "/srv/u/key"),
        "ssh -i /srv/u/key -p 2222 'u@h'",
      )
    Err(_) => abort("the command line should parse")
  }
}

///|
/// `-f` empties the private key path but leaves `-i` set, so upstream
/// prints `-i` with no path after it.  That is upstream's shape and this
/// build keeps it: `${SEEN_OPT_I:+-i${PRIV_ID_FILE:+ $PRIV_ID_FILE} }`
/// expands to `-i ` when `PRIV_ID_FILE` is empty, because `:+` gives
/// nothing for a variable that is empty as well as for one that is unset.
test "force keeps the -i flag and loses the path" {
  let o = @sshcopyid.parse_args(["ssh-copy-id", "-f", "-i", "key", "u@h"], fn(
    _ : String,
  ) -> Bool {
    false
  })
  match o {
    Ok(opts) => assert_eq(@sshcopyid.closing_hint(opts, ""), "ssh -i 'u@h'")
    Err(_) => abort("the command line should parse")
  }
}

///|
/// The `-o` options are in the closing sentence, in upstream's shape.
///
/// Upstream keeps them in one list (`OPTS_oF`) and prints it as
/// `-<flag> '<value>'`; the list comes after the `-p` group and before the
/// target.
test "the closing hint carries the -o options" {
  let o = @sshcopyid.parse_args(
    ["ssh-copy-id", "-o", "UserKnownHostsFile=/k", "-o", "Port=22", "u@h"],
    fn(_ : String) -> Bool { false },
  )
  match o {
    Ok(opts) =>
      assert_eq(
        @sshcopyid.closing_hint(opts, ""),
        "ssh -o 'UserKnownHostsFile=/k' -o 'Port=22' 'u@h'",
      )
    Err(_) => abort("the command line should parse")
  }
}

///|
/// `-F` and `-o` share one list, so their order is the order they were
/// given in -- that is upstream's `OPTS_oF`.
test "the closing hint keeps the order of -F and -o" {
  let o = @sshcopyid.parse_args(
    ["ssh-copy-id", "-F", "/c", "-o", "Port=22", "u@h"],
    fn(_ : String) -> Bool { false },
  )
  match o {
    Ok(opts) =>
      assert_eq(
        @sshcopyid.closing_hint(opts, ""),
        "ssh -F '/c' -o 'Port=22' 'u@h'",
      )
    Err(_) => abort("the command line should parse")
  }
}

///|
/// A port with no `-i` still gets its space: upstream's template is
/// `"${SFTP:-ssh} ${SEEN_OPT_I:+...}${SSH_PORT:+...}"`, so the space after
/// `ssh` is always there.
test "a port without -i keeps the space" {
  let o = @sshcopyid.parse_args(["ssh-copy-id", "-p", "2222", "u@h"], fn(
    _ : String,
  ) -> Bool {
    false
  })
  match o {
    Ok(opts) =>
      assert_eq(@sshcopyid.closing_hint(opts, ""), "ssh -p 2222 'u@h'")
    Err(_) => abort("the command line should parse")
  }
}

///|
/// Upstream's `quote()`: one quote becomes `'\''`.
test "a quote is quoted the way upstream quotes it" {
  assert_eq(@sshcopyid.quote_of("it's"), "it'\\''s")
  assert_eq(@sshcopyid.quote_of("plain"), "plain")
}

///|
/// The option table, as upstream's getopts reads it.
test "the option table is upstream's" {
  let o = @sshcopyid.parse_args(
    [
      "ssh-copy-id", "-i", "key", "-t", "srv/keys", "-p", "2222", "-f", "-n", "-o",
      "Port=22", "u@h",
    ],
    fn(_ : String) -> Bool { false },
  )
  match o {
    Ok(opts) => {
      assert_opt_eq(opts.identity, Some("key"))
      assert_true(opts.identity_given)
      assert_eq(opts.target_path, "srv/keys")
      assert_int_eq(opts.port, 2222)
      assert_true(opts.port_given)
      assert_true(opts.force)
      assert_true(opts.dry_run)
      assert_int_eq(opts.opt_args.length(), 1)
      assert_eq(opts.opt_args[0].flag, "o")
      assert_eq(opts.opt_args[0].value, "Port=22")
      assert_eq(opts.target, "u@h")
      assert_eq(opts.user, "u")
      assert_eq(opts.host, "h")
    }
    Err(_) => abort("the command line should parse")
  }
}

///|
/// A port in a cluster: `-p2222` is port 2222.
test "a port may be glued to its flag" {
  let o = @sshcopyid.parse_args(["ssh-copy-id", "-p2222", "u@h"], fn(
    _ : String,
  ) -> Bool {
    false
  })
  match o {
    Ok(opts) => assert_int_eq(opts.port, 2222)
    Err(_) => abort("the command line should parse")
  }
}

///|
/// `-i` twice is upstream's refusal.
test "-i twice is refused" {
  let o = @sshcopyid.parse_args(["ssh-copy-id", "-i", "a", "-i", "b", "u@h"], fn(
    _ : String,
  ) -> Bool {
    false
  })
  match o {
    Ok(_) => abort("two -i must be refused")
    Err(e) =>
      match e {
        @sshcopyid.CopyIdArgError::DuplicateIdentity => ()
        _ => abort("the refusal must be the duplicate -i")
      }
  }
}

///|
/// Two hostnames is upstream's refusal.
test "two hostnames are refused" {
  let o = @sshcopyid.parse_args(["ssh-copy-id", "a", "b"], fn(
    _ : String,
  ) -> Bool {
    false
  })
  match o {
    Ok(_) => abort("two hostnames must be refused")
    Err(e) =>
      match e {
        @sshcopyid.CopyIdArgError::TooManyArguments => ()
        _ => abort("the refusal must be the too many arguments")
      }
  }
}

///|
/// No hostname at all is the usage block.
test "no hostname is the usage" {
  let o = @sshcopyid.parse_args(["ssh-copy-id"], fn(_ : String) -> Bool {
    false
  })
  match o {
    Ok(_) => abort("no hostname must be refused")
    Err(e) =>
      match e {
        @sshcopyid.CopyIdArgError::Usage => ()
        _ => abort("the refusal must be the usage")
      }
  }
}

///|
/// `-i key.pub` with nothing after it: upstream sees a key file where the
/// hostname should be and says so.
test "a trailing -i file is the missing hostname" {
  let o = @sshcopyid.parse_args(["ssh-copy-id", "-i", "id.pub"], fn(
    path : String,
  ) -> Bool {
    path == "id.pub"
  })
  match o {
    Ok(_) => abort("a trailing key file must be refused")
    Err(e) =>
      match e {
        @sshcopyid.CopyIdArgError::MissingHostname(arg) =>
          assert_eq(arg, "id.pub")
        _ => abort("the refusal must be the missing hostname")
      }
  }
}

///|
/// The user's login name and the host, split on the last `@`.
test "the target splits into a user and a host" {
  assert_opt_eq(@sshcopyid.user_of("u@h"), Some("u"))
  assert_opt_eq(@sshcopyid.user_of("h"), None)
  assert_eq(@sshcopyid.host_of("u@h"), "h")
  assert_eq(@sshcopyid.host_of("h"), "h")
}
