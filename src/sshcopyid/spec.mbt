///|
/// Loop #103: what a run of `ssh-copy-id` is made of.
///
/// The option table is upstream's: the getopts string in the real script is
/// `"io:p:F:t:fnsxh?"`, so `-i` takes an **optional** argument (the script
/// looks at the next word itself), `-o`/`-p`/`-F`/`-t` take a required one,
/// and `-f`/`-n`/`-s`/`-x`/`-h`/`-?` are flags.
///
/// The defaults are upstream's too: `TARGET_PATH=".ssh/authorized_keys"` and
/// the source of the keys is `~/.ssh/id*.pub` with the newest one winning
/// and `-cert.pub` files excluded (upstream: `ls -dt "${HOME}"/.ssh/id*.pub
/// 2>/dev/null | grep -v -- '-cert.pub$' | head -n 1`).
pub(all) struct CopyIdOptions {
  /// `-i`: the identity file as the user wrote it.  `None` means "the
  /// default", which is what upstream does when `-i` is given without a
  /// word after it.
  identity : String?
  /// whether `-i` appeared at all.  Upstream's `SEEN_OPT_I` is set by the
  /// flag, not by its word, and the closing sentence keys off the flag:
  /// `-f` empties the private key path but leaves `SEEN_OPT_I` set, so
  /// upstream then prints `ssh -i  'user@host'`.
  identity_given : Bool
  /// `-t`: where on the remote the key goes.  Upstream's default is
  /// `.ssh/authorized_keys`, relative to the remote account's home.
  target_path : String
  /// `-p`: the port.  `port_given` is separate because upstream prints the
  /// port in its closing sentence only when `-p` was given.
  port : Int32
  port_given : Bool
  /// `-f`: copy without checking whether the keys are already installed.
  force : Bool
  /// `-n`: say what would happen, and change nothing.
  dry_run : Bool
  /// `-s`: install over sftp instead of running a remote command.
  use_sftp : Bool
  /// `-x`: the debug flag.
  debug : Bool
  /// `-F` and `-o`, in the order they were given.
  ///
  /// Upstream keeps them in **one** list -- `OPTS_oF` -- and prints that
  /// list in the closing sentence, so the order and the flag of each one
  /// are part of the tool's output and cannot be split into two fields.
  opt_args : Array[CopyIdOptArg]
  /// the one positional argument: `[user@]hostname`.
  target : String
  /// the login name, or the empty string when the target carries none.
  user : String
  /// the host, without the login name.
  host : String
}

///|
/// An option that upstream hands straight to `ssh`.
///
/// Upstream's getopts has one branch for both `-o` and `-F`:
/// `OPTS_oF="${OPTS_oF:+$OPTS_oF }-$OPT '$(quote "${OPTARG}")'"`, so the
/// flag and the word after it travel together and keep their order.
pub(all) struct CopyIdOptArg {
  /// the flag: `o` or `F`.
  flag : String
  /// the word after the flag.
  value : String
}

///|
/// The default target path, upstream's `TARGET_PATH`.
pub const DEFAULT_TARGET_PATH : String = ".ssh/authorized_keys"

///|
/// The default port, upstream's `SSH_PORT` when `-p` is not given.
pub const DEFAULT_PORT : Int32 = 22

///|
/// What the driver can do on this machine and on the far side.
///
/// Everything the flow needs from the outside world arrives here as a
/// function value, so the rules can be tested with no filesystem, no peer
/// and no network -- and so a mutation can be aimed at the flow without
/// anything else moving.
pub(all) struct CopyIdIo {
  /// the local home directory, for upstream's `~/.ssh/id*.pub` default.
  home : String
  /// run a remote command with the given stdin; the answer is what came
  /// back.  The first argument is the private key path to sign with --
  /// the rules decide **which** identity, the driver knows **how** to use
  /// it.
  exec_fn : (String, String, FixedArray[Byte]) -> CopyIdExec
  /// try to authenticate with the identity; the answer is what the server
  /// said, because "the server said no" and "the connection broke" are
  /// different answers.
  auth_fn : (String) -> CopyIdAuth
  /// read a local file.
  read_fn : (String) -> FixedArray[Byte]?
  /// the names directly inside a local directory.
  list_fn : (String) -> Array[String]?
  /// stat a local path.
  stat_fn : (String) -> CopyIdStat?
  /// the sentence for the last failed local call, the way the C runtime
  /// spells it (`No such file or directory`).
  reason_fn : () -> String
}

///|
/// The answer to "run this command over there".
pub(all) enum CopyIdExec {
  /// the command ran: its stdout, its stderr and its exit status.
  Done(String, String, Int32)
  /// the command never ran: the connection failed, the key was refused, or
  /// the channel broke.  The word is the reason, in the shape `ssh` uses.
  Failed(String)
}

///|
/// The answer to "may I log in with this key".
pub(all) enum CopyIdAuth {
  /// the server accepted the key.
  Accepted
  /// the server refused the key.  The word is the first method the server
  /// still offers -- `publickey` means "your key is not in my
  /// `authorized_keys`", which is the one refusal that is about the key.
  Rejected(String)
  /// the attempt never reached a verdict: the connection broke, the host
  /// key did not match, the handshake failed.
  Failed(String)
}

///|
/// What is known about a local path.
pub(all) struct CopyIdStat {
  is_file : Bool
  is_dir : Bool
  size : Int64
  /// seconds since the epoch; upstream's `ls -t` sorts on this.
  mtime : Int64
}

///|
/// The lines a run produced and the status it leaves behind.
///
/// `stdout_lines` and `stderr_lines` hold the lines **without** their
/// terminator, and a blank line is a blank line: upstream's closing block
/// starts and ends with one, and dropping them would change the bytes the
/// tool prints.
pub(all) struct CopyIdResult {
  mut stdout_lines : Array[String]
  mut stderr_lines : Array[String]
  mut status : Int32
}

///|
pub fn CopyIdResult::new() -> CopyIdResult {
  { stdout_lines: [], stderr_lines: [], status: 0, }
}
