///|
/// Loop #103: the sentences `ssh-copy-id` prints.
///
/// Every line here was read out of the real script's own bytes, captured by
/// `host/copyid_probe.sh` (which runs the real script with a stand-in `ssh`
/// and keeps every byte it writes) and compared, byte for byte, by
/// `host/verify_loop103.mjs`.  Nothing in this file is paraphrased:
/// upstream's words, upstream's punctuation, upstream's blank lines and
/// upstream's tabs.
///
/// ## Two of them are upstream's bugs and are kept on purpose
///
/// * `too many arguments` ends with an empty list.  Upstream prints
///   `$SAVEARGS`, and `$SAVEARGS` is never assigned anywhere in the script,
///   so the sentence really does stop at "got: ".  Fixing it would make the
///   tool *better* and no longer the same tool.
/// * `-f` empties the private key path, so upstream's closing sentence says
///   `ssh -i  'user@host'` -- with `-i`, a space, and no path.  That is
///   what `force_installs_have_no_private_path` reproduces.
pub(all) enum CopyIdText {
  /// the usage block, printed to stderr before an exit of 1.
  Usage
  /// `-i` was given twice.
  DuplicateIdentity
  /// `-i` was given with an empty word.
  NoIdentityFile
  /// a file the script needs could not be opened.
  CannotOpen(String, String, String?)
  /// `-i` took the last word on the command line and that word is a key
  /// file, so the hostname is missing.
  MissingHostname(String)
  /// more than one hostname was given.
  TooManyArguments
  /// there were no keys to install.
  NoIdentities
  /// the filter step could not decide, and the reason is the word.
  Filter(String)
  /// every key was already installed.
  AllSkipped
  /// the install is done; `n` keys were added.
  Added(Int32, String)
  /// the dry run's block, with the keys that would have been installed.
  WouldAdd(String)
  /// our own sentence: the key was written but the server did not accept
  /// it.  Upstream has no such sentence -- it reports success it did not
  /// check for.
  NotAccepted(String)
  /// our own refusal: this build has no sftp install path.
  SftpNotSupported
}

///|
/// The lines a sentence is made of, and where they go.
///
/// Upstream's INFO and ERROR lines go to stderr and its closing block goes
/// to stdout; keeping that split is what lets the gate compare the two
/// streams separately against the real script's.
pub fn copy_id_text(prog : String, t : CopyIdText) -> (Array[String], Bool) {
  let out : Array[String] = []
  let mut to_stderr = true
  match t {
    Usage => {
      out.push(
        "Usage: " +
        prog +
        " [-h|-?|-f|-n|-s|-x] [-i [identity_file]] [-t target_path] [-F ssh_config] [[-o ssh_option] ...] [-p port] [user@]hostname",
      )
      out.push(
        "\t-f: force mode -- copy keys without trying to check if they are already installed",
      )
      out.push("\t-n: dry run    -- no keys are actually copied")
      out.push(
        "\t-s: use sftp   -- use sftp instead of executing remote-commands. Can be useful if the remote only allows sftp",
      )
      out.push("\t-x: debug      -- enables -x in this shell, for debugging")
      out.push("\t-h|-?: print this help")
    }
    DuplicateIdentity => {
      out.push("")
      out.push(prog + ": ERROR: -i option must not be specified more than once")
      out.push("")
    }
    NoIdentityFile => out.push(prog + ": ERROR: no ID file found")
    CannotOpen(file, reason, hint) => {
      out.push("")
      out.push(
        prog + ": ERROR: failed to open ID file '" + file + "': " + reason,
      )
      match hint {
        Some(pub_path) =>
          out.push(
            "\t(to install the contents of '" +
            pub_path +
            "' anyway, look at the -f option)",
          )
        None => ()
      }
    }
    MissingHostname(arg) => {
      out.push("")
      out.push(
        prog +
        ": ERROR: Missing hostname. Use \"-i -- " +
        arg +
        "\" if you really mean to use this as the hostname",
      )
      out.push("")
    }
    TooManyArguments => {
      out.push("")
      out.push(
        prog +
        ": ERROR: Too many arguments.  Expecting a target hostname, got: ",
      )
      out.push("")
    }
    NoIdentities => out.push(prog + ": ERROR: No identities found")
    Filter(why) => {
      out.push("")
      out.push(prog + ": ERROR: " + why)
      out.push("")
    }
    AllSkipped => {
      out.push("")
      out.push(
        prog +
        ": WARNING: All keys were skipped because they already exist on the remote system.",
      )
      out.push(
        "\t\t(if you think this is a mistake, you may want to use -f option)",
      )
      out.push("")
    }
    Added(n, hint) => {
      to_stderr = false
      out.push("")
      out.push("Number of key(s) added: " + n.to_string())
      out.push("")
      out.push("Now try logging into the machine, with: \"" + hint + "\"")
      out.push(
        "and check to make sure that only the key(s) you wanted were added.",
      )
      out.push("")
    }
    WouldAdd(keys) => {
      to_stderr = false
      out.push("=-=-=-=-=-=-=-=")
      out.push("Would have added the following key(s):")
      out.push("")
      out.push(keys)
      out.push("=-=-=-=-=-=-=-=")
    }
    NotAccepted(why) =>
      out.push(
        prog +
        ": WARNING: the key was written but the server did not accept it" +
        why,
      )
    SftpNotSupported =>
      out.push(
        prog +
        ": ERROR: this build does not install over sftp; the default remote command is the only path it has",
      )
  }
  (out, to_stderr)
}

///|
/// The lines a refusal from the option parser is made of, and whether the
/// usage block follows.
///
/// Upstream's shape: the error line, then `usage` (which prints the block
/// and exits 1) -- except for "no ID file found", which is printed by
/// `use_id_file` and exits on its own.
pub fn copy_id_arg_error(
  prog : String,
  e : CopyIdArgError,
) -> (Array[String], Bool) {
  let out : Array[String] = []
  let mut with_usage = false
  match e {
    CopyIdArgError::Usage => with_usage = true
    CopyIdArgError::DuplicateIdentity => {
      out.push("")
      out.push(prog + ": ERROR: -i option must not be specified more than once")
      out.push("")
      with_usage = true
    }
    CopyIdArgError::NoIdentityFile =>
      out.push(prog + ": ERROR: no ID file found")
    CopyIdArgError::MissingHostname(arg) => {
      out.push("")
      out.push(
        prog +
        ": ERROR: Missing hostname. Use \"-i -- " +
        arg +
        "\" if you really mean to use this as the hostname",
      )
      out.push("")
      with_usage = true
    }
    CopyIdArgError::TooManyArguments => {
      out.push("")
      out.push(
        prog +
        ": ERROR: Too many arguments.  Expecting a target hostname, got: ",
      )
      out.push("")
      with_usage = true
    }
  }
  if with_usage {
    let (block, _) = copy_id_text(prog, CopyIdText::Usage)
    for i in 0..<block.length() {
      out.push(block[i])
    }
  }
  (out, true)
}

///|
/// The `INFO: Source of key(s) to be installed` line.
///
/// Upstream prints the path **in double quotes**, because the thing it
/// prints is the tail of `GET_ID`, and `GET_ID` is `cat "<path>"`.
pub fn info_source(prog : String, pub_path : String) -> String {
  prog + ": INFO: Source of key(s) to be installed: \"" + pub_path + "\""
}

///|
/// The `INFO: attempting to log in` line.
pub fn info_filtering(prog : String) -> String {
  prog +
  ": INFO: attempting to log in with the new key(s), to filter out any that are already installed"
}

///|
/// The `INFO: N key(s) remain` line.
pub fn info_remaining(prog : String, n : Int32) -> String {
  prog +
  ": INFO: " +
  n.to_string() +
  " key(s) remain to be installed -- if you are prompted now it is to install the new keys"
}

///|
/// The closing sentence's hint: the command the user should try next.
///
/// Upstream builds it as
/// `"${SFTP:-ssh} ${SEEN_OPT_I:+-i${PRIV_ID_FILE:+ $PRIV_ID_FILE} }${SSH_PORT:+-${PORT_OPT:-p} $SSH_PORT }${OPTS_USER_HOST}"`,
/// so four things decide it:
///
///   * `-s` turns `ssh` into `sftp`,
///   * `-i` adds `-i <path>`, and the path is upstream's `PRIV_ID_FILE`,
///     which is `dirname(pub) + "/" + basename(pub)` -- note the **mixed**
///     separators, which is what upstream prints on Windows and what the
///     captured bytes show,
///   * `-p` adds `-p <port>`, and `-P` when `-s` was given (upstream sets
///     `PORT_OPT=P` for sftp),
///   * and the `-o`/`-F` options and the target follow, the options first.
///
/// The options are upstream's `OPTS_oF`: one list holding both `-o` and
/// `-F` in the order they were given, each written as `-<flag> '<value>'`
/// with the value quoted by upstream's `quote()`.
pub fn closing_hint(o : CopyIdOptions, priv_path : String) -> String {
  let mut s = if o.use_sftp { "sftp " } else { "ssh " }
  if o.identity_given {
    s = s + "-i"
    if priv_path != "" {
      s = s + " " + priv_path
    }
    s = s + " "
  }
  if o.port_given {
    let flag = if o.use_sftp { "P" } else { "p" }
    s = s + "-" + flag + " " + o.port.to_string() + " "
  }
  for i in 0..<o.opt_args.length() {
    let a = o.opt_args[i]
    s = s + "-" + a.flag + " '" + quote_of(a.value) + "' "
  }
  s = s + "'" + quote_of(o.target) + "'"
  s
}

///|
/// Upstream's `quote()`: every single quote becomes `'\''`.
///
/// Upstream's function is `printf '%s\n' "$1" | sed -e "s/'/'\\''/g"`,
/// which replaces one quote with four characters -- a quote, a backslash
/// and two more quotes -- so the word can sit inside a single-quoted
/// shell word.
pub fn quote_of(s : String) -> String {
  let n = s.length()
  let out = StringBuilder()
  let mut i = 0
  while i < n {
    if s[i] == '\'' {
      out.write_string("'\\''")
    } else {
      out.write_char(Int32::unsafe_to_char(s[i].to_int()))
    }
    i = i + 1
  }
  out.to_string()
}

///|
/// The private key path, in upstream's own shape.
///
/// Upstream computes `PRIV_ID_FILE=$(dirname "$PUB_ID_FILE")/$(basename
/// "$PUB_ID_FILE" .pub)`, so:
///
///   * the directory keeps the separators it had,
///   * the join between the directory and the name is **always** a forward
///     slash, because that is the literal in upstream's line -- on Windows
///     that produces `E:\dir/name`, which is what the captured upstream
///     bytes show,
///   * a name with no directory gets upstream's `dirname` answer, `.`, so
///     the path is `./name`.
pub fn private_path_of(pub_path : String) -> String {
  let n = pub_path.length()
  let mut cut = -1
  let mut i = 0
  while i < n {
    let c = pub_path[i]
    if c == '/' || c == '\\' {
      cut = i
    }
    i = i + 1
  }
  let mut base = pub_path
  if cut >= 0 {
    base = substring_of(pub_path, cut + 1, n)
  }
  if has_suffix(base, ".pub") {
    base = substring_of(base, 0, base.length() - 4)
  }
  if cut < 0 {
    "./" + base
  } else {
    substring_of(pub_path, 0, cut) + "/" + base
  }
}

///|
/// Whether `s` ends with `suffix`.
pub fn has_suffix(s : String, suffix : String) -> Bool {
  let n = s.length()
  let m = suffix.length()
  if m > n {
    return false
  }
  let mut i = 0
  while i < m {
    if s[n - m + i] != suffix[i] {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// Whether `s` starts with `prefix`.
pub fn has_prefix(s : String, prefix : String) -> Bool {
  let n = s.length()
  let m = prefix.length()
  if m > n {
    return false
  }
  let mut i = 0
  while i < m {
    if s[i] != prefix[i] {
      return false
    }
    i = i + 1
  }
  true
}

///|
/// `[from, to)` of a string.
pub fn substring_of(s : String, from : Int32, to : Int32) -> String {
  let out = StringBuilder()
  let mut i = from
  while i < to && i < s.length() {
    out.write_char(Int32::unsafe_to_char(s[i].to_int()))
    i = i + 1
  }
  out.to_string()
}
