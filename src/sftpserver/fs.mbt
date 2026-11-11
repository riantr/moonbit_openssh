///| Loop #92: the filesystem the SFTP server drives.
///
/// The server is the mirror of `src/sftp`, and like it the wire format
/// lives in one place.  What is NEW here is the other half: the thing the
/// requests act on.
///
/// ## Why an interface and not a filesystem
///
/// `src/scp` already made this move once, and the reason applies verbatim:
/// the interesting behaviour of a server is the ORDER in which it answers
/// and the WORDS it uses when it refuses, and neither can be tested
/// against a real disk without a real disk.  So the filesystem is a bundle
/// of function values, the state machine is written against it, and the
/// state machine can be tested with an in-memory filesystem on all four
/// backends.
///
/// ## What the real server does, measured
///
/// Every claim below comes from `.loop92/probe6.py` and `probe7.py` against
/// the real `sftp-server.exe` on this machine.  The ones that shape this
/// interface:
///
///   * `STAT` of a MISSING file is `2 No such file`; of an existing one it
///     is `15`-flag ATTRS.  The same `STAT` of a DIRECTORY reports size
///     4096 on this platform -- not 0 -- so "size" is whatever the
///     platform says, and this server must not normalise it.
///   * `uid`/`gid` are always `(0, 0)`.
///   * `perm` is 33152 for a plain file and 16832 for a directory, and
///     33024 for a READ-ONLY file.  That is `0100644` and `040755` and
///     `0100440` -- the Unix mode word the server synthesises from the
///     Windows attributes.  The read-only case is why `perm` cannot be
///     derived from a hard-coded constant: `0440` vs `0644` is the
///     difference between a file you may write and one you may not.
///   * `atime` and `mtime` are SEPARATE and real.  A file whose atime was
///     left alone and whose mtime was moved 30 days back reports
///     `(now, now-30d)` -- not `(now, now)`.  So an implementation that
///     answers "mtime twice" is wrong, and only a real filesystem can tell
///     the difference.
///   * A read-only file's MODE STRING is `-r--******`, a writable one is
///     `-rw-******`, a directory is `drwx******`.  The six asterisks are
///     the group and other columns, which Windows cannot fill in.
///
/// ## The failures, and the words
///
///   * opening a read-only file for write: `3 Permission denied`
///   * `REMOVE` of a DIRECTORY: `3 Permission denied` (Windows refuses)
///   * `RMDIR` of a FILE: `5 Bad message`
///   * `RENAME` onto an existing file: `4 Failure`
///   * `RENAME` of a missing source: `2 No such file`
///   * `OPENDIR` of a file: `5 Bad message`
///
/// The codes are the protocol's; the SENTENCES are what a client prints
/// when it falls back to reading the text, so they are part of the
/// contract and are pinned by the gate.

///|
/// What a `stat` reports about one path.
///
/// `is_dir` is separate from the size because the platform's notion of a
/// directory's size is its own (4096 here), and `is_readonly` is separate
/// from the mode word because the mode word is what the server REPORTS and
/// the read-only flag is what the platform KNOWS -- the two have to agree,
/// and a test that only compares the reported word would not notice when
/// they stop agreeing.
///
/// `other_bits` is the third part of the mode word, and it is the only
/// part that is not a property of the file's attributes: it is what
/// EVERYBODY is allowed to do with the file, and it comes from the
/// directory's access control list.  Measured, not guessed -- see
/// `longname.mbt`.
pub(all) struct FileStat {
  size : Int64
  is_dir : Bool
  is_readonly : Bool
  mtime : Int64
  atime : Int64
  /// What "everybody" may do with the file: 4 for read, 2 for write, 1 for
  /// execute.  Zero when the file has no access control list.
  other_bits : Int32
}

///|
/// One entry of a directory listing.
pub(all) struct DirEntry {
  name : String
  stat : FileStat
}

///|
/// Why a filesystem operation failed.
///
/// The variants are the STATUS codes the server can answer, so the
/// mapping from a failure to a wire status is a table lookup and not a
/// judgement call.  `Failure` is the catch-all.
pub(all) enum FsError {
  NoSuchFile
  PermissionDenied
  Failure
  BadMessage
}

///|
/// The filesystem operations the SFTP server needs.
///
/// Grouped the way the protocol groups them rather than one per system
/// call: the server opens a file, reads at an offset, writes at an offset
/// and closes it, and a directory is opened, listed and closed -- and both
/// of those are HANDLE-shaped, which is why the handle is a number and
/// not a path.
pub(all) struct ServerFs {
  /// The stat of one path, or `None` when there is no such path.
  stat_fn : (String) -> FileStat?
  /// Open a file for reading (`1`) and/or writing (`2`).
  ///
  /// The flags are the protocol's `FXF_*` bits.  Returns the handle, or
  /// the reason it failed.
  open_fn : (String, Int32) -> Result[Int32, FsError]
  /// Open a directory for listing.
  opendir_fn : (String) -> Result[Int32, FsError]
  /// The next entry of an open directory, or `None` when the listing ends.
  readdir_fn : (Int32) -> DirEntry?
  /// Read at most `len` bytes at `offset`.
  read_fn : (Int32, Int64, Int32) -> FixedArray[Byte]
  /// Write `data` at `offset`.
  write_fn : (Int32, Int64, FixedArray[Byte]) -> Result[Unit, FsError]
  /// Close a handle.
  close_fn : (Int32) -> Unit
  /// Set the size of an open file.
  truncate_fn : (Int32, Int64) -> Result[Unit, FsError]
  /// Set the modification time of a path.
  set_mtime_fn : (String, Int64) -> Result[Unit, FsError]
  /// Create a directory.
  mkdir_fn : (String) -> Result[Unit, FsError]
  /// Remove a directory.
  rmdir_fn : (String) -> Result[Unit, FsError]
  /// Remove a file.
  remove_fn : (String) -> Result[Unit, FsError]
  /// Rename a path.
  rename_fn : (String, String) -> Result[Unit, FsError]
  /// Rename a path, REPLACING the target if it is there.
  ///
  /// This is a different operation from `rename_fn`, and it is a different
  /// request too: the draft's `FXP_RENAME` refuses to overwrite, while the
  /// `posix-rename@openssh.com` extension is `rename(2)` and does.  The
  /// real server answers `4 Failure` for the first when the target exists
  /// and `0 Success` for the second -- measured, both on the same pair of
  /// files.
  rename_replace_fn : (String, String) -> Result[Unit, FsError]
  /// The absolute form of a path, as the server reports it.
  ///
  /// This is not a filesystem question -- it is a question about how the
  /// server spells a path, and the answer is measured: the real server
  /// answers REALPATH with `/C:/Users/...`, i.e. the drive letter is
  /// prefixed with a SLASH and the separators are forward ones.  A
  /// Windows path with backslashes is a different string, and a client
  /// that compares them byte for byte would see the difference.
  realpath_fn : (String) -> String
}
