///| Loop #103: upstream's option table.
///
/// Upstream's getopts string is `"io:p:F:t:fnsxh?"`, which says three things
/// that are easy to get wrong:
///
///   * `-i` takes **no** argument as far as getopts is concerned.  The
///     script looks at the next word itself and takes it if it does not
///     look like an option -- that is why the usage line says
///     `[-i [identity_file]]` with brackets around the file name,
///   * `-o`, `-p`, `-F` and `-t` take a required argument, and getopts
///     takes the rest of the cluster first: `-p2222` is port 2222,
///   * getopts stops at the first word that is not an option, so
///     `host -i key` has two positional arguments and upstream says "Too
///     many arguments".
///
/// ## The `-i` rule, including the part that looks like a mistake
///
/// Upstream asks whether the next word "looks like an option" with
/// `expr -- "$nextarg" : "-[$(echo "$OPTS" | tr -d :)-]"`.  The pattern
/// needs three characters -- a dash, an option letter, and **another dash**
/// -- so `-p` does not match it, and `ssh-copy-id -i -p 22 host` takes
/// `-p` as the identity file.  That is upstream's behaviour and this parser
/// reproduces it: `looks_like_option` is that pattern, not a guess.
///
/// ## The "Missing hostname" case
///
/// Upstream's `-i` handling looks one word ahead and, if that word is the
/// last one on the command line and it is a readable file that mentions
/// `ssh`, concludes that the hostname is missing and says so.  The
/// captured upstream bytes show the sentence:
///
///     ERROR: Missing hostname. Use "-i -- /path/key.pub" if you really mean to use this as the hostname
pub(all) enum CopyIdArgError {
  /// anything getopts would refuse: an unknown option, a missing
  /// argument, `-h`, `-?`, or no hostname at all.
  Usage
  /// `-i` twice.
  DuplicateIdentity
  /// `-i` with an empty word.
  NoIdentityFile
  /// `-i` took the last word and that word is a key file, so the hostname
  /// is missing.
  MissingHostname(String)
  /// more than one hostname.
  TooManyArguments
}

///|
/// Parse the command line the way upstream's getopts loop does.
///
/// `args` is the whole command line, `args[0]` included.  `is_key_file` is
/// the driver's answer to "is this a readable file that mentions ssh",
/// which upstream asks about the word after `-i`.
pub fn parse_args(
  args : Array[String],
  is_key_file : (String) -> Bool,
) -> Result[CopyIdOptions, CopyIdArgError] {
  let n = args.length()
  let mut identity : String? = None
  let mut identity_given = false
  let mut target_path = DEFAULT_TARGET_PATH
  let mut port = DEFAULT_PORT
  let mut port_given = false
  let mut force = false
  let mut dry_run = false
  let mut use_sftp = false
  let mut debug = false
  // An `Array` is mutable on its own, so these bindings do not need `mut`.
  let opt_args : Array[CopyIdOptArg] = []
  let positionals : Array[String] = []
  let mut i = 1
  // getopts stops at the first word that is not an option.
  let mut parsing = true
  while parsing && i < n {
    let a = args[i]
    if a == "--" {
      i = i + 1
      parsing = false
    } else if a.length() < 2 || a[0] != '-' {
      parsing = false
    } else {
      let mut j = 1
      while j < a.length() {
        let c = a[j]
        if c == 'i' {
          if identity_given {
            return Err(CopyIdArgError::DuplicateIdentity)
          }
          identity_given = true
          // The word after the whole cluster, and whether upstream would
          // take it.
          let has_next = i + 1 < n
          let next = if has_next { args[i + 1] } else { "" }
          if has_next && next == args[n - 1] && looks_like_key_file(next, is_key_file) {
            return Err(CopyIdArgError::MissingHostname(next))
          }
          if has_next && !looks_like_option(next) {
            identity = Some(next)
            i = i + 1
          }
        } else if c == 'o' || c == 'p' || c == 'F' || c == 't' {
          // The argument is the rest of the cluster, or the next word.
          let mut arg = ""
          if j + 1 < a.length() {
            arg = substring_of(a, j + 1, a.length())
            j = a.length()
          } else if i + 1 < n {
            arg = args[i + 1]
            i = i + 1
          } else {
            return Err(CopyIdArgError::Usage)
          }
          if c == 'o' {
            opt_args.push({ flag: "o", value: arg })
          } else if c == 'p' {
            port = parse_port(arg)
            port_given = true
          } else if c == 'F' {
            opt_args.push({ flag: "F", value: arg })
          } else {
            target_path = arg
          }
        } else if c == 'f' {
          force = true
        } else if c == 'n' {
          dry_run = true
        } else if c == 's' {
          use_sftp = true
        } else if c == 'x' {
          debug = true
        } else {
          // getopts prints "illegal option" and sets OPT='?', and upstream's
          // '?' case prints the usage and exits 1.
          return Err(CopyIdArgError::Usage)
        }
        j = j + 1
      }
      i = i + 1
    }
  }
  while i < n {
    positionals.push(args[i])
    i = i + 1
  }
  if positionals.length() == 0 {
    return Err(CopyIdArgError::Usage)
  }
  if positionals.length() > 1 {
    return Err(CopyIdArgError::TooManyArguments)
  }
  let target = positionals[0]
  let user = match user_of(target) {
    Some(u) => u
    None => ""
  }
  let host = host_of(target)
  Ok({
    identity,
    identity_given,
    target_path,
    port,
    port_given,
    force,
    dry_run,
    use_sftp,
    debug,
    opt_args,
    target,
    user,
    host,
  })
}

///|
/// Whether a word looks like an option to upstream's `expr` pattern.
///
/// The pattern is `"-[iopFtfn sxh?-]"`: a dash, an option letter, and
/// **another dash**.  So `-p` does not look like an option (and upstream
/// would take it as the `-i` argument) while `-p-` does.
fn looks_like_option(word : String) -> Bool {
  if word.length() < 3 {
    return false
  }
  if word[0] != '-' || word[2] != '-' {
    return false
  }
  let c = word[1]
  c == 'i' || c == 'o' || c == 'p' || c == 'F' || c == 't' || c == 'f' ||
  c == 'n' || c == 's' || c == 'x' || c == 'h' || c == '?' || c == '-'
}

///|
/// Whether a word is a file that mentions `ssh`.
///
/// Upstream's test is `[ -r "$nextarg" ] && grep -iq ssh "$nextarg"`, and
/// the rules cannot reach the disk, so the driver answers it.  A file that
/// does not exist answers "no", which is what upstream's `-r` says.
fn looks_like_key_file(
  word : String,
  probe : (String) -> Bool,
) -> Bool {
  probe(word)
}

///|
/// `[from, to)` of a string.
///|
/// A port number, or upstream's default when the word is not one.
///
/// Upstream does not check `-p` at all -- it hands the word to `ssh` -- so
/// a word that is not a number is not this tool's business.
fn parse_port(word : String) -> Int32 {
  let mut value = 0
  let mut i = 0
  let mut any = false
  while i < word.length() {
    let c = word[i]
    if c < '0' || c > '9' {
      return DEFAULT_PORT
    }
    value = value * 10 + (c.to_int() - '0'.to_int())
    any = true
    i = i + 1
  }
  if any {
    value
  } else {
    DEFAULT_PORT
  }
}

///|
/// One ssh option's value, the last one winning, as `ssh` does.
///
/// Only the `-o` options are looked at: `-F` names a config file, not an
/// option.
pub fn ssh_option(o : CopyIdOptions, name : String) -> String? {
  let mut found : String? = None
  for i in 0..<o.opt_args.length() {
    let a = o.opt_args[i]
    if a.flag == "o" && has_prefix(a.value, name + "=") {
      found = Some(substring_of(a.value, name.length() + 1, a.value.length()))
    }
  }
  found
}

///|
/// The login name in `[user@]host`, if there is one.
pub fn user_of(target : String) -> String? {
  let n = target.length()
  let mut at = -1
  let mut i = 0
  while i < n {
    if target[i] == '@' {
      at = i
    }
    i = i + 1
  }
  if at < 0 {
    None
  } else {
    Some(substring_of(target, 0, at))
  }
}

///|
/// The host in `[user@]host`.
pub fn host_of(target : String) -> String {
  let n = target.length()
  let mut at = -1
  let mut i = 0
  while i < n {
    if target[i] == '@' {
      at = i
    }
    i = i + 1
  }
  if at < 0 {
    target
  } else {
    substring_of(target, at + 1, n)
  }
}
