///| What `scp` says when it fails, and what status it leaves behind.
///
/// Every sentence here was read out of the real binary while driving the
/// local SFTP comparison bed (`.loop90/probe_scp_D5.py`), so the shapes
/// are measured rather than recalled.  The important discovery in that
/// run is that the tool does **not** have one message style -- it has
/// two, and the difference is visible in the bytes:
///
///   * a message `scp` composes itself is prefixed with `argv[0]`:
///
///         C:\Windows\System32\OpenSSH\scp.exe: stat local "local/nope.txt":
///         No such file or directory
///
///   * a message that is a bare `perror()` is **not** prefixed, and its
///     text is the operating system's:
///
///         nodir: No such file or directory
///         a.txt: Not a directory
///
/// That second group is the three-or-more-positionals check ("the target
/// of a multi-source copy has to be a directory"), and it is also where
/// the status differs: everything `perror` prints exits **1**, while a
/// missing local *source* is fatal and exits **255**.
///
/// Because `argv[0]` is added by the driver and never by this file, a
/// message returned here is exactly the part after `scp.exe: `, and a
/// comment on each constructor says whether the driver prefixes it.

///|
/// The status a run leaves behind.
///
/// Three values, all measured:
///
/// * `0` -- every source copied
/// * `1` -- an operation failed; the tool kept going where it could
/// * `255` -- a fatal error, or the connection never came up
///
/// The split between `Failure` and `Fatal` is not cosmetic.  A local
/// source that does not exist is **255**, and a remote target it could
/// not open is **1**; a reimplementation that answered 1 for both would
/// disagree with the tool on the most common mistake there is.
pub(all) enum ScpExit {
  Ok
  Failure
  Fatal
}

///|
pub fn scp_exit_code(e : ScpExit) -> Int32 {
  match e {
    Ok => 0
    Failure => 1
    Fatal => 255
  }
}

///|
/// One failure, with the words the tool actually prints.
pub(all) enum ScpError {
  /// `stat local "<path>": <reason>` -- fatal, 255.
  ///
  /// The `stat local` prefix names which side was being examined, which
  /// matters when a copy has several sources and only one is missing.
  StatLocal(String, String)
  /// `local "<path>" is not a regular file` -- 1.
  ///
  /// Raised when a directory is given as a source without `-r`.  The real
  /// tool prints this and then, for an upload, a second line:
  /// `failed to upload file <src> to <dst>`.
  NotARegularFile(String)
  /// `<remote path>: <reason>` -- 1.  Printed with the **host stripped**.
  ///
  /// Measured: `scp h:srv/nope.txt out.txt` says `srv/nope.txt: ...`, not
  /// `h:srv/nope.txt: ...`.  The path after the colon is what the server
  /// was asked for, and that is what the message names.
  RemotePath(String, String)
  /// `dest open "<path>": <reason>` -- 1, followed by
  /// `failed to upload file <src> to <dst>`.
  DestOpen(String, String)
  /// `open local "<path>": <reason>` -- 1.
  ///
  /// The **download**-side counterpart of `DestOpen`, and a different
  /// sentence because the tool really does say different words: measured,
  /// `scp host:srv/a.txt local/nodir/out.txt` prints
  /// `open local "local/nodir/out.txt": No such file or directory` and
  /// nothing else, while the same failure on the upload side prints
  /// `dest open "..."` *and* a `failed to upload` line
  /// (`.loop90/probe_scp_D6.py` scenarios 10 and 13).
  OpenLocal(String, String)
  /// `download <path>/: not a regular file` -- 1.
  ///
  /// A remote **directory** given as a source without `-r`.  The trailing
  /// slash is part of the sentence: the tool appends it to the path before
  /// printing, so the message names `srv/d/` even though the command line
  /// said `srv/d` (round 6 scenario 14).
  RemoteNotRegular(String)
  /// `Download of file <remote absolute> to <local> failed` -- 1.
  ///
  /// The **second** line of a failure inside a recursive download, and a
  /// third sentence shape (the upload side's is `failed to upload file`).
  /// The remote half is the server's *absolute* path -- the tool realpaths
  /// the source directory and joins the children onto it -- which is why
  /// it reads `/E:/.../srv/dt/x.txt` on this machine rather than
  /// `srv/dt/x.txt` (round 6 scenario 17, round 7 scenario 26).
  DownloadFailed(String, String)
  /// `remote mkdir "<path>": <reason>` -- **255**.
  ///
  /// Measured twice, and the two measurements are both surprising.  A
  /// multi-source copy makes the target directory when it is not there
  /// (round 8 scenario 29 succeeds where a single-source copy would have
  /// failed), and when that mkdir is refused the tool calls `fatal()` --
  /// so this is one of the few per-operation failures that exits 255
  /// rather than 1 (round 8 scenario 30).
  ///
  /// The reason in that case was `Failure`: the server's own text for
  /// `SSH_FX_FAILURE`, not an operating-system errno string.  That is why
  /// every `reason` here is whatever the peer said rather than a local
  /// guess.
  RemoteMkdir(String, String)
  /// `failed to upload file <src> to <dst>` -- the second line of a
  /// per-file failure.  A download says `failed to download file`; the
  /// side is part of the sentence.
  TransferFailed(String, String, String)
  /// The `perror` group: `<argument>: <reason>`, **no** `argv[0]` prefix.
  ///
  /// Only the multi-source target check prints this way.
  Perror(String, String)
}

///|
/// The sentence, without the `argv[0]: ` prefix and without a newline.
///
/// Whether the driver prefixes this is `needs_argv0_prefix`.
pub fn scp_error_text(e : ScpError) -> String {
  match e {
    StatLocal(path, why) => "stat local \"" + path + "\": " + why
    NotARegularFile(path) => "local \"" + path + "\" is not a regular file"
    RemotePath(path, why) => path + ": " + why
    DestOpen(path, why) => "dest open \"" + path + "\": " + why
    OpenLocal(path, why) => "open local \"" + path + "\": " + why
    RemoteNotRegular(path) => "download " + path + "/: not a regular file"
    DownloadFailed(abs, dst) =>
      "Download of file " + abs + " to " + dst + " failed"
    RemoteMkdir(path, why) => "remote mkdir \"" + path + "\": " + why
    TransferFailed(direction, src, dst) =>
      "failed to " + direction + " file " + src + " to " + dst
    Perror(arg, why) => arg + ": " + why
  }
}

///|
/// Whether `argv[0]: ` goes in front of this sentence.
///
/// `False` for exactly the `perror` group -- see the file comment.
pub fn needs_argv0_prefix(e : ScpError) -> Bool {
  match e {
    Perror(_, _) => false
    _ => true
  }
}

///|
/// The status this failure leaves behind.
pub fn scp_error_exit(e : ScpError) -> ScpExit {
  match e {
    // A source that is not there is fatal, not a per-file failure.
    StatLocal(_, _) => Fatal
    // A remote mkdir the server refused is fatal too -- measured, and the
    // one place where a *transfer* failure outranks the per-file status.
    RemoteMkdir(_, _) => Fatal
    // Everything else is a per-file failure that the tool survives.
    NotARegularFile(_) => Failure
    RemotePath(_, _) => Failure
    DestOpen(_, _) => Failure
    OpenLocal(_, _) => Failure
    RemoteNotRegular(_) => Failure
    DownloadFailed(_, _) => Failure
    TransferFailed(_, _, _) => Failure
    Perror(_, _) => Failure
  }
}

///|
/// The error text the platform hands back, spelled the way the C runtime
/// spells it.
///
/// These are the strings `perror` and `strerror` produce on an English
/// Windows install, and they appear verbatim inside `scp`'s own messages
/// (`stat local "x": No such file or directory`).  They are listed here
/// rather than fetched because MoonBit has no `strerror`, and a table with
/// the measured spellings is more honest than a guess at one.
///
/// **This is the one place in the loop where locale is a real risk**: the
/// C runtime localises these.  The repository has already seen that first
/// hand -- `ssh` printed a GBK message in this very session -- so a gate
/// that compares full sentences across machines has to run with an English
/// locale, or compare only the part scp composed.
pub fn reason_no_such_file() -> String {
  "No such file or directory"
}

///|
pub fn reason_not_a_directory() -> String {
  "Not a directory"
}

///|
pub fn reason_permission_denied() -> String {
  "Permission denied"
}

///|
/// Every `\n` in `text` as `\r\n`.
///
/// `scp` writes its messages through the C runtime's text-mode stream, so
/// a `\n` in the format string reaches the console as `\r\n` -- measured,
/// and the same thing `eprintln` does on this toolchain (`eprintln("A\nB")`
/// emits `A\r\nB\r\n`; `.loop90` has the capture).
///
/// The driver therefore builds every message with `\n` and passes it
/// through here exactly once, except for the `-P` refusal, whose embedded
/// newline the real tool writes **raw** and which must stay a bare `\n`
/// (`port_error_text` says why).  Keeping the conversion in one named
/// function is what makes that exception visible instead of accidental.
pub fn text_crlf(text : String) -> String {
  let out = StringBuilder()
  let mut i = 0
  while i < text.length() {
    if text[i] == '\n' {
      out.write_char('\r')
      out.write_char('\n')
    } else {
      out.write_char(Int32::unsafe_to_char(text[i].to_int()))
    }
    i = i + 1
  }
  out.to_string()
}

///|
/// `failed to upload file` / `failed to download file`.
pub fn direction_upload() -> String {
  "upload"
}

///|
pub fn direction_download() -> String {
  "download"
}
