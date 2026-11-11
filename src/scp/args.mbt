///| The `scp` command line: an option table, a getopt, and the two
/// validators that are not plain assignments.
///
/// ## The option surface is measured, not transcribed
///
/// Running `scp -<X>` with no positionals separates the two answers
/// cleanly: a letter that is *not* in getopt's optstring makes getopt
/// print `unknown option -- X` and the run ends there, while a letter
/// that *is* in it reaches the "need at least two arguments" check and
/// prints the usage block instead.  Sweeping every digit and letter
/// (`.loop90/probe_optstring9.py`) gives:
///
///     accepted, no value : 2 3 4 6 d p q r s v A B C O R T
///     accepted, a value  : c i l o D F J M P S X
///     `-1`               : "SSH protocol v.1 is no longer supported", 255
///     `-f` `-t`          : accepted (the legacy scp source/sink ends)
///
/// Two of those are worth naming because the usage block does not mention
/// them: `-M` takes a value and is undocumented, and `-f`/`-t` are the
/// legacy scp source and sink flags.  `-t` alone exits 1 with no output;
/// `-f` alone blocks on stdin.  They are accepted here for the same
/// reason the real tool accepts them -- a parser that rejected them would
/// disagree with the tool it is measured against -- and the driver
/// refuses to act on them.
///
/// ## `String[i]` is a `UInt16`, not a `Char`
///
/// Under the toolchain this file is checked with (`moon 0.1.20261102`,
/// `moonc v0.10.19`), indexing a `String` yields one **UTF-16 code unit**
/// as `UInt16`, not a `Char`.  Measured with a two-line program: assigning
/// `s[0]` to a `Char` is `Expr Type Mismatch: has type UInt16, wanted
/// Char`, while `s[0] == 'x'` compiles because the literal is inferred as
/// the same code-unit type.  Every character helper below therefore takes
/// a `UInt16`, and `Int::unsafe_to_char` is used only where a `Char` has
/// to be printed.  (`Int::to_char` is the safe form and returns `Char?`;
/// these are ASCII option letters, so the checked form would add an
/// unreachable branch.)

///|
/// The usage block, byte for byte.
///
/// The real tool writes it with `\n` and the Windows C runtime turns each
/// one into `\r\n`, which is why a captured stderr reads
/// `... [-F ssh_config]\r\n           [-i identity_file] ...`.  Our own
/// tools go through the same runtime: `cmd/ssh_add` from Loop #89 emits
/// `...No such file or directory\r\n` from a plain `eprintln`, byte for
/// byte what the real `ssh-add` emits (measured, see
/// `.loop90/DESIGN.md`).  So this string carries `\n` and nothing here
/// appends a `\r`.
///
/// The continuation lines are indented by eleven spaces, which is what
/// lines up under `usage: scp ` (7 + 4).
pub fn usage_text() -> String {
  "usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n" +
  "           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n" +
  "           [-P port] [-S program] [-X sftp_option] source ... target\n"
}

///|
/// The two ways getopt can refuse an option, and the sentence for each.
///
/// Both are followed by the usage block and both exit 1 (measured: `-h`,
/// `-Z`, `-P`, `-i`, `-o`, `-D`, `-c`, `-l`, `-S`, `-J`, `-F`, `-X`).
pub(all) enum ArgError {
  /// `unknown option -- <letter>`
  ///
  /// `--nonsense` lands here with the letter `-`: BSD getopt strips one
  /// leading `-`, then takes the next character as the option letter.
  UnknownOption(Char)
  /// `option requires an argument -- <letter>`
  MissingArgument(Char)
}

///|
/// The sentence getopt prints for an `ArgError`, without the `argv[0]: `
/// prefix and without the newline.
pub fn arg_error_text(e : ArgError) -> String {
  match e {
    UnknownOption(c) => "unknown option -- " + c.to_string()
    MissingArgument(c) => "option requires an argument -- " + c.to_string()
  }
}

///|
/// `-1`.  Not a parse error and not the usage block: the real tool calls
/// `fatal("SSH protocol v.1 is no longer supported")`, which prints
/// `<argv0>: SSH protocol v.1 is no longer supported` and exits **255**.
///
/// The status is why this is its own constructor: 255 is the "fatal"
/// status this tool family uses, and a parser that answered 1 here would
/// be wrong about the one flag whose entire behaviour is a refusal.
pub fn unsupported_protocol_v1_text() -> String {
  "SSH protocol v.1 is no longer supported"
}

///|
/// The port validator.  Measured: `-P 0`, `-P -1`, `-P abc`, `-P 65536`,
/// `-P 70000` and a twenty-one digit number are all refused with
///
///     <argv0>: bad port "<value>"\n\r\n
///
/// and status **255**.  Note the `\n` **inside** the message: the real
/// fatal() format string ends with `\n` and fatal() appends a newline of
/// its own, and only the second one is translated to `\r\n` by the
/// runtime.  That is why the captured bytes read `... "0"\n\r\n` and not
/// `... "0"\r\n\r\n`.  Reproducing it needs the literal `\n` to stay a
/// `\n`, so this returns the message *with* that embedded newline and the
/// driver writes it without adding a `\r`.
pub fn port_error_text(value : String) -> String {
  "bad port \"" + value + "\"\n"
}

///|
/// Whether a `-P` value is acceptable: a decimal integer in 1..=65535.
///
/// `a2port()` is a `strtonum` with those bounds, so the accepted
/// spellings are the ones `strtonum` accepts -- measured, not assumed:
/// ` 22` (leading space) and `+22` are accepted, `22 ` (trailing space)
/// and `2x` are not.
///
/// Note the refusal is a sentence, not the usage block: `-P` and `-l`
/// answer differently and both answers are measured.
pub fn port_is_valid(value : String) -> Bool {
  match parse_unsigned(value) {
    None => false
    Some(v) => v >= 1L && v <= 65535L
  }
}

///|
/// Whether a `-l` value is acceptable: a decimal integer of at least 1.
///
/// Measured: `1`, `8`, `+8`, ` 8` (leading space) and `08` are accepted;
/// `0`, `-1`, `8 ` (trailing space), `8x`, `x8`, `1e3`, `0x10`, `0.5`,
/// the empty string and a twenty-one digit number all print the usage
/// block and exit 1.  The empty string is the one worth noting: strtonum
/// requires at least one digit, so `-l ""` is not "zero", it is
/// unparseable.
///
/// The refusal is the **usage block**, not a sentence about the limit --
/// a different answer from `-P`'s, and the reason both validators live
/// here rather than in one generic "bad number" helper in the driver.
pub fn limit_is_valid(value : String) -> Bool {
  match parse_unsigned(value) {
    None => false
    Some(v) => v >= 1L
  }
}

///|
/// `strtonum(value, 1, ...)` as far as the *spelling* rules go.
///
/// What `strtonum` accepts, measured through `-l`:
///
/// * optional leading whitespace (` 8` is 8),
/// * an optional `+` or `-` sign,
/// * at least one decimal digit,
/// * nothing at all after the digits (`8x` and `8 ` are both rejected).
///
/// A negative number parses and is then refused by the *range* check,
/// which is why `-1` and `0` reach the same usage block as `abc`: the
/// user cannot tell "unparseable" from "out of range".  Returning `None`
/// for both keeps that ambiguity where it belongs -- in the validator,
/// not in every caller.
fn parse_unsigned(value : String) -> Int64? {
  let n = value.length()
  let mut at = 0
  while at < n && is_space_char(value[at]) {
    at = at + 1
  }
  let mut negative = false
  if at < n && (value[at] == '+' || value[at] == '-') {
    negative = value[at] == '-'
    at = at + 1
  }
  let digits_start = at
  let mut acc : Int64 = 0L
  let mut overflow = false
  let zero = '0'.to_int()
  let nine = '9'.to_int()
  while at < n && value[at].to_int() >= zero && value[at].to_int() <= nine {
    let d = (value[at].to_int() - zero).to_int64()
    // Step before multiplying so the bound cannot wrap.
    if acc > (9223372036854775807L - d) / 10L {
      overflow = true
    } else {
      acc = acc * 10L + d
    }
    at = at + 1
  }
  // No digits at all, or trailing junk: strtonum reports "invalid".
  if at == digits_start || at != n || overflow || negative {
    return None
  }
  Some(acc)
}

///|
fn is_space_char(c : UInt16) -> Bool {
  c == ' ' || c.to_int() == 0x09 || c.to_int() == 0x0A || c.to_int() == 0x0D
}

///|
/// Which options take a value: `c i l o D F J M P S X`.
///
/// `M` is here and is **not** in the usage block -- it is a real option
/// of the real tool (measured: `scp -M` alone answers
/// `option requires an argument -- M`), so a parser without it would
/// refuse a command line the tool accepts.
fn option_takes_value(c : UInt16) -> Bool {
  c == 'c' ||
  c == 'i' ||
  c == 'l' ||
  c == 'o' ||
  c == 'D' ||
  c == 'F' ||
  c == 'J' ||
  c == 'M' ||
  c == 'P' ||
  c == 'S' ||
  c == 'X'
}

///|
/// Which options take no value: `2 3 4 6 d p q r s v A B C O R T`, plus
/// the legacy `f` and `t`.
fn option_takes_no_value(c : UInt16) -> Bool {
  c == '2' ||
  c == '3' ||
  c == '4' ||
  c == '6' ||
  c == 'd' ||
  c == 'p' ||
  c == 'q' ||
  c == 'r' ||
  c == 's' ||
  c == 'v' ||
  c == 'A' ||
  c == 'B' ||
  c == 'C' ||
  c == 'O' ||
  c == 'R' ||
  c == 'T' ||
  c == 'f' ||
  c == 't'
}

///|
/// A code unit as a `Char`, for the messages that have to print one.
fn code_unit_to_char(c : UInt16) -> Char {
  Int32::unsafe_to_char(c.to_int())
}

///|
/// What the command line asked for, with every value still a string.
///
/// `-l` and `-P` are validated into `limit_kbps` and `port`; the rest are
/// carried as given, because what they mean is a transport decision and
/// not a rule.
pub(all) struct ScpOptions {
  /// the positionals in command-line order; the last one is the target
  mut positionals : Array[String]
  /// -r
  mut recursive : Bool
  /// -p
  mut preserve : Bool
  /// -q
  mut quiet : Bool
  /// -v
  mut verbose : Bool
  /// -3 (through the local host)
  mut through_local : Bool
  /// -4 (IPv4 only)
  mut ipv4 : Bool
  /// -6 (IPv6 only)
  mut ipv6 : Bool
  /// -A (agent)
  mut agent : Bool
  /// -B (batch)
  mut batch : Bool
  /// -C (compression)
  mut compression : Bool
  /// -O (the legacy scp protocol)
  mut legacy_protocol : Bool
  /// -R
  mut remote_to_remote : Bool
  /// -T (no strict filename checking)
  mut no_strict_filenames : Bool
  /// -d (the target has to be a directory)
  mut target_must_be_dir : Bool
  /// -s (the source is remote in the legacy protocol)
  mut legacy_sink : Bool
  /// -t (the sink end of the legacy protocol)
  mut legacy_source : Bool
  /// -c cipher
  mut cipher : String
  /// -D sftp_server_path
  mut sftp_server_path : String
  /// -F ssh_config
  mut ssh_config : String
  /// -i identity_file -- every -i, because the real tool accepts several
  mut identity_files : Array[String]
  /// -J destination
  mut jump : String
  /// -l limit, already validated
  mut limit_kbps : Int64
  /// -o ssh_option -- kept attached, the same as the real tool
  mut ssh_options : Array[String]
  /// -P port, already validated when `port_given` is true
  mut port : Int32
  /// whether -P was given at all: the real tool's default is 0, which is
  /// also the value the validator refuses, so the flag has to be kept
  mut port_given : Bool
  /// -M
  mut extra_flag_m : String
  /// -S program
  mut ssh_program : String
  /// -X sftp_option
  mut sftp_options : Array[String]
}

///|
/// The result of parsing: either options, or the one thing to say.
pub(all) enum ParsedArgs {
  Options(ScpOptions)
  /// getopt refused an option; the driver adds `argv[0]: `, then the
  /// usage block, then exits 1
  Refused(ArgError)
  /// `-1`: fatal, no usage block, exit 255
  ProtocolV1
  /// `-P <bad>`: fatal, no usage block, exit 255, message carries its own
  /// embedded newline
  BadPort(String)
  /// print the usage block alone, exit 1.  Every "not enough arguments"
  /// case lands here, and so do both `-l` refusals.
  NeedUsage
}

///|
fn empty_options() -> ScpOptions {
  {
    positionals: [],
    recursive: false,
    preserve: false,
    quiet: false,
    verbose: false,
    through_local: false,
    ipv4: false,
    ipv6: false,
    agent: false,
    batch: false,
    compression: false,
    legacy_protocol: false,
    remote_to_remote: false,
    no_strict_filenames: false,
    target_must_be_dir: false,
    legacy_sink: false,
    legacy_source: false,
    cipher: "",
    sftp_server_path: "",
    ssh_config: "",
    identity_files: [],
    jump: "",
    limit_kbps: 0L,
    ssh_options: [],
    port: 0,
    port_given: false,
    extra_flag_m: "",
    ssh_program: "",
    sftp_options: [],
  }
}

///|
/// Parse `argv`, given **without** the program name.
///
/// The getopt behaviour reproduced here is the BSD one the tool is built
/// with, and two consequences were measured rather than assumed:
///
/// * **Option parsing stops at the first non-option.**  `scp a.txt out.txt
///   -r` copies `a.txt` and `out.txt` and treats `-r` as a third
///   positional, which then has to be a directory: the real tool answers
///   `-r: No such file or directory` and exits 1.  A GNU-style parser
///   that permuted arguments would copy two files and succeed.
/// * **`--` ends the options and is not a positional.**  `scp -- a b`
///   copies; `scp --` alone prints usage.
///
/// A lone `-` is a positional (a file named `-`), which is what getopt
/// does: it is neither `--` nor a cluster.
pub fn parse_args(args : Array[String]) -> ParsedArgs {
  let o = empty_options()
  let n = args.length()
  let mut i = 0
  let mut options_done = false
  while i < n {
    let a = args[i]
    let is_option = !options_done && a.length() >= 2 && a[0] == '-' && a != "--"
    if !is_option {
      // `--` ends the options; any other non-option stops parsing for
      // good, and both are positionals from here on.
      options_done = true
      if a != "--" {
        o.positionals.push(a)
      }
      i = i + 1
      continue
    }
    // A cluster: every character after the first '-' is another option,
    // and a value-taking option consumes the rest of the cluster if there
    // is one (`-P22`), otherwise the next argv (`-P 22`).
    let mut j = 1
    let mut cluster_done = false
    while j < a.length() && !cluster_done {
      let c = a[j]
      if c == '1' {
        return ParsedArgs::ProtocolV1
      }
      if option_takes_value(c) {
        let value = if j + 1 < a.length() {
          substring_from(a, j + 1)
        } else {
          if i + 1 >= n {
            return ParsedArgs::Refused(
              ArgError::MissingArgument(code_unit_to_char(c)),
            )
          }
          i = i + 1
          args[i]
        }
        match apply_value(o, c, value) {
          Ok(_) => ()
          Err(e) => return e
        }
        cluster_done = true
      } else if option_takes_no_value(c) {
        apply_flag(o, c)
      } else {
        return ParsedArgs::Refused(
          ArgError::UnknownOption(code_unit_to_char(c)),
        )
      }
      j = j + 1
    }
    i = i + 1
  }
  // "Need at least a source and a target."
  if o.positionals.length() < 2 {
    return ParsedArgs::NeedUsage
  }
  ParsedArgs::Options(o)
}

///|
/// The tail of a string from `from` onwards.
fn substring_from(s : String, from : Int32) -> String {
  let out = StringBuilder()
  let mut i = from
  while i < s.length() {
    out.write_char(code_unit_to_char(s[i]))
    i = i + 1
  }
  out.to_string()
}

///|
/// Apply one value-taking option.  Only `-l` and `-P` can refuse, and
/// they refuse differently on purpose (see `limit_is_valid`).
fn apply_value(
  o : ScpOptions,
  c : UInt16,
  value : String,
) -> Result[Unit, ParsedArgs] {
  if c == 'c' {
    o.cipher = value
  } else if c == 'o' {
    o.ssh_options.push(value)
  } else if c == 'D' {
    o.sftp_server_path = value
  } else if c == 'F' {
    o.ssh_config = value
  } else if c == 'J' {
    o.jump = value
  } else if c == 'M' {
    o.extra_flag_m = value
  } else if c == 'S' {
    o.ssh_program = value
  } else if c == 'X' {
    o.sftp_options.push(value)
  } else if c == 'i' {
    o.identity_files.push(value)
  } else if c == 'l' {
    if !limit_is_valid(value) {
      return Err(ParsedArgs::NeedUsage)
    }
    match parse_unsigned(value) {
      None => return Err(ParsedArgs::NeedUsage)
      Some(v) => o.limit_kbps = v
    }
  } else if c == 'P' {
    if !port_is_valid(value) {
      return Err(ParsedArgs::BadPort(value))
    }
    match parse_unsigned(value) {
      None => return Err(ParsedArgs::BadPort(value))
      Some(v) => {
        o.port = v.to_int()
        o.port_given = true
      }
    }
  }
  Ok(())
}

///|
/// Apply one flag.  There is no refusal path: the caller has already
/// established that the letter is in the real optstring.
fn apply_flag(o : ScpOptions, c : UInt16) -> Unit {
  if c == 'r' {
    o.recursive = true
  } else if c == 'p' {
    o.preserve = true
  } else if c == 'q' {
    o.quiet = true
  } else if c == 'v' {
    o.verbose = true
  } else if c == '3' {
    o.through_local = true
  } else if c == '4' {
    o.ipv4 = true
  } else if c == '6' {
    o.ipv6 = true
  } else if c == 'A' {
    o.agent = true
  } else if c == 'B' {
    o.batch = true
  } else if c == 'C' {
    o.compression = true
  } else if c == 'O' {
    o.legacy_protocol = true
  } else if c == 'R' {
    o.remote_to_remote = true
  } else if c == 'T' {
    o.no_strict_filenames = true
  } else if c == 'd' {
    o.target_must_be_dir = true
  } else if c == 's' {
    o.legacy_sink = true
  } else if c == 't' {
    o.legacy_source = true
  }
}

///|
/// The sources: everything but the last positional.
pub fn sources_of(o : ScpOptions) -> Array[String] {
  let out : Array[String] = []
  let mut i = 0
  while i + 1 < o.positionals.length() {
    out.push(o.positionals[i])
    i = i + 1
  }
  out
}

///|
pub fn target_of(o : ScpOptions) -> String {
  let n = o.positionals.length()
  if n == 0 {
    ""
  } else {
    o.positionals[n - 1]
  }
}
