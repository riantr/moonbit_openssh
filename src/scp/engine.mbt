///| The copy engine: the part of `scp` that moves bytes.
///
/// ## Three shapes of I/O, one of which is abstracted
///
/// The engine reads and writes two sides:
///
/// * the **remote** side is `@sftpdrive.SftpDrive`, which is already a
///   request/reply client over two function values;
/// * the **local** side is whatever the platform's filesystem is, and it
///   is abstracted here for the same reason: a unit test can then run the
///   whole recursive walk with no filesystem at all, on all four targets,
///   and a mutation aimed at "does a failed child stop the walk" lands on
///   the engine rather than on a C file.
///
/// The real local half is `localfs_native.mbt` (Win32, native only); the
/// js and wasm targets get `localfs_stub.mbt`, which refuses everything --
/// there is no filesystem there, and pretending otherwise would be a lie
/// in the one place a copy is supposed to be exact.
///
/// ## Why the failures are a list rather than a `Result`
///
/// `scp` does not stop at the first failing source (measured: round 7
/// scenario 26 prints the same two lines for all three children and then
/// exits 1), and it does not carry on after a fatal either (round 6
/// scenario 15 leaves the second source uncopied).  So the engine reports
/// **every line it would print, in order, plus whether a fatal cut it
/// short**, and the driver only prints.  A `Result` would force the driver
/// to reconstruct the lines, which is exactly the "driver decides" shape
/// this repository keeps out of drivers.
///
/// ## The one-line and two-line failures are measured, not chosen
///
/// | what failed | lines | exit |
/// |---|---|---|
/// | local source missing | `stat local "x": ...` | 255 |
/// | local dir without `-r` | `local "x" is not a regular file`, `failed to upload file ...` | 1 |
/// | remote dest open | `dest open "x": ...`, `failed to upload file ...` | 1 |
/// | local dest open (top level) | `open local "x": ...` | 1 |
/// | local dest open (inside `-r`) | `open local "x": ...`, `Download of file <abs> to <y> failed` | 1 |
/// | remote source missing | `srv/x: ...` (host stripped) | 1 |
/// | remote dir without `-r` | `download srv/d/: not a regular file` | 1 |
/// | remote mkdir refused | `remote mkdir "x": ...` | 255 |
///
/// The asymmetry between the third row and the fourth is the reason this
/// table exists: the upload side prints a second line for a *single* file,
/// the download side does not, and a reimplementation that made them
/// symmetrical would be wrong twice.
///
/// ## `lpath`, not `local`
///
/// Every parameter on this machine's half of a copy is named `lpath`.
/// `local` is a **reserved word** in this toolchain (`moon check
/// --deny-warn` refuses it: "The word `local` is reserved for possible
/// future use"), and under `--deny-warn` a warning is the build failing.

///|
/// What the local side knows about a path.
///
/// Only three facts, because they are the only three the tool acts on:
/// whether it is a directory (which decides the destination name), its
/// size, and its mtime (`-p`).
pub(all) struct LocalStat {
  is_dir : Bool
  size : Int64
  /// seconds since the epoch, the same unit SFTP's `ATTRS` carries
  mtime : Int64
}

///|
/// The local filesystem, as seven functions.
///
/// Each fallible one returns `None` when it worked and `Some(reason)`
/// otherwise, where the reason is spelled the way the C runtime spells it
/// (`No such file or directory`).  That spelling is not cosmetic: it is
/// what `scp` prints, because the real tool hands a failing call's `errno`
/// to `strerror` and prints the result.
///
/// ## Why `reason_fn` exists next to the returned reasons
///
/// Two of the calls -- `stat_fn` and `read_fn` -- have no room for a
/// reason in their result: `None` already means both "not there" and "not
/// readable", and those two sentences are **different** in the tool's own
/// output (`stat local "x": No such file or directory` versus
/// `...: Permission denied`).  So the platform parks the error code of the
/// call that just failed and `reason_fn` turns it into the sentence,
/// immediately afterwards and nowhere else.
///
/// A caller that reaches for `reason_fn` without a failed call behind it
/// gets a stale answer.  That is the cost of the shape, and it is the same
/// cost `errno` has in C, which is the shape being copied.
pub(all) struct LocalFs {
  /// `None` when the path is not there -- ask `reason_fn` whether that
  /// means missing or unreadable
  stat_fn : (String) -> LocalStat?
  /// `None` when the file could not be read
  read_fn : (String) -> FixedArray[Byte]?
  /// `None` when the bytes were written
  write_fn : (String, FixedArray[Byte]) -> String?
  /// `None` when the directory is there afterwards
  mkdir_fn : (String) -> String?
  /// the names directly inside, with no `.` or `..`
  list_fn : (String) -> Array[String]?
  /// set the mtime; `None` when it worked.  Only `-p` calls this.
  set_mtime_fn : (String, Int64) -> String?
  /// the sentence for the most recent failed call above
  reason_fn : () -> String
}

///|
/// The lines a run has produced, and whether a fatal stopped it.
///
/// `fatal` is not "a 255 was produced somewhere" -- it is "the tool would
/// have stopped here", which is what the driver has to know to decide
/// whether the next source is attempted.
pub(all) struct ScpReport {
  mut lines : Array[ScpError]
  mut fatal : Bool
}

///|
pub fn ScpReport::new() -> ScpReport {
  { lines: [], fatal: false, }
}

///|
/// Record one failure and whether the tool would stop after it.
pub fn ScpReport::push(self : ScpReport, e : ScpError) -> Unit {
  self.lines.push(e)
  match scp_error_exit(e) {
    ScpExit::Fatal => self.fatal = true
    _ => ()
  }
}

///|
/// The status this report leaves behind: fatal wins, then failure, then 0.
pub fn ScpReport::exit(self : ScpReport) -> ScpExit {
  let mut out = ScpExit::Ok
  for i = 0; i < self.lines.length(); i = i + 1 {
    match scp_error_exit(self.lines[i]) {
      ScpExit::Fatal => return ScpExit::Fatal
      ScpExit::Failure => out = ScpExit::Failure
      ScpExit::Ok => ()
    }
  }
  out
}

///|
/// The transfer chunk, 32 KiB.
///
/// The real tool's `sftp.c` allocates a `64 * 1024` buffer and moves half
/// of it per request, and the size is not observable in the result, so
/// this is a choice rather than a measurement -- said out loud because
/// everything else in this file is a measurement.
pub fn transfer_chunk() -> Int32 {
  32768
}

///|
/// Map a drive error onto the sentence `scp` would print for it.
///
/// ## The codes beat the server's message, and that was measured
///
/// Handing the server's own text through looked right until the bed
/// disagreed: for a missing file the local `sftp-server.exe` sends
/// `No such file`, while the real `scp` prints `No such file and
/// directory`.  So the tool maps the **status code** to an errno and
/// prints `strerror` of that, and the server's text is only a fallback.
///
/// Two rows are measured and they are not the same shape:
///
/// * `SSH_FX_NO_SUCH_FILE` (2) -> `No such file or directory`, which is
///   `ENOENT`'s text (round 6 scenario 13, round 5 scenario 9);
/// * `SSH_FX_FAILURE` (4) -> `Failure`, which is the server's own message
///   and also what the tool printed for a refused `remote mkdir`
///   (round 8 scenarios 30 and 31).
///
/// `LinkFailed` has no measurement -- there is no way to make the bed's
/// `sftp-server.exe` die between two packets on demand -- so it says so
/// instead of inventing an errno.
fn drive_reason(e : @sftpdrive.DriveError) -> String {
  match e {
    @sftpdrive.DriveError::Refused(code, why) => code_reason(code, why)
    @sftpdrive.DriveError::Protocol(why) => why
    @sftpdrive.DriveError::LinkFailed => "Connection lost"
  }
}

///|
/// The sentence for one non-OK status code.
///
/// Codes 2 and 3 are the two the bed produced; the rest fall back to
/// whatever the peer said, because a client that translated them would
/// have to invent words for conditions it was never shown.
fn code_reason(code : Int32, server_text : String) -> String {
  if code == 2 {
    reason_no_such_file()
  } else if code == 3 {
    reason_permission_denied()
  } else {
    server_text
  }
}

///|
/// An `ATTRS` block carrying nothing but a time.
///
/// SFTP's flag word is what makes the field mean anything, and
/// `SftpAttrs::encode` derives it from which options are `Some`, so an
/// attrs with only the times set cannot accidentally clear a permission.
fn attrs_with_time(secs : Int64) -> @sftp.SftpAttrs {
  let a = @sftp.SftpAttrs::none()
  // `Int64::to_int` is the truncating one, and `ATTRS` carries a 32-bit
  // second count -- the protocol's own 2038 limit, not ours.
  let t = secs.to_int()
  a.atime = Some(t)
  a.mtime = Some(t)
  a
}

///|
/// `data[from, to)` as its own array.
fn slice_bytes(
  data : FixedArray[Byte],
  from : UInt64,
  to : UInt64,
) -> FixedArray[Byte] {
  let n = (to - from).to_int()
  let out = FixedArray::make(n, b'\x00')
  let mut i = 0
  while i < n {
    out[i] = data[from.to_int() + i]
    i = i + 1
  }
  out
}

///|
/// The engine: one local filesystem and one remote drive.
///
/// The two are function values and a struct, so nothing here touches a
/// real filesystem or a socket -- which is what lets the same code be
/// tested against a scripted in-memory tree and a fake server, and run
/// against Win32 and a spawned `sftp-server.exe`.
pub struct CopyEngine {
  fs : LocalFs
  drive : @sftpdrive.SftpDrive
}

///|
pub fn CopyEngine::new(
  fs : LocalFs,
  drive : @sftpdrive.SftpDrive,
) -> CopyEngine {
  { fs, drive, }
}

///|
/// `True` when the remote path is a directory.
///
/// A path the server cannot stat is not a directory, which is the same
/// answer the real tool gives a missing path.
fn CopyEngine::remote_is_dir(self : CopyEngine, path : String) -> Bool {
  match self.drive.stat(path) {
    Ok(attrs) => @sftpdrive.attrs_is_dir(attrs)
    Err(_) => false
  }
}

///|
/// The local mtime of a path, or 0 when it is not there.
fn CopyEngine::mtime_of(self : CopyEngine, path : String) -> Int64 {
  match (self.fs.stat_fn)(path) {
    Some(st) => st.mtime
    None => 0L
  }
}

///|
/// The remote mtime of a path, or 0 when the server does not report one.
fn CopyEngine::remote_mtime(self : CopyEngine, path : String) -> Int64 {
  match self.drive.stat(path) {
    Ok(a) =>
      match a.mtime {
        Some(t) => t.to_int64()
        None => 0L
      }
    Err(_) => 0L
  }
}

///|
/// Create a remote directory, treating "already there" as success.
///
/// The two-step shape is the real tool's: `mkdir` first, and only if that
/// is refused ask whether the path is already a directory.  Doing it the
/// other way round would make `remote mkdir "srv/afile": Failure` (round 8
/// scenario 30) unprintable, because that path *does* exist -- as a file.
fn CopyEngine::ensure_remote_dir(
  self : CopyEngine,
  path : String,
) -> Result[Unit, String] {
  match self.drive.mkdir(path) {
    Ok(_) => Ok(())
    Err(e) =>
      if self.remote_is_dir(path) {
        Ok(())
      } else {
        Err(drive_reason(e))
      }
  }
}

///|
/// A local directory, created if need be.
///
/// **The failure is deliberately not reported.**  Measured: a recursive
/// download onto a path that is a FILE (`local/afile`) prints nothing about
/// the directory and then fails once per child with
/// `open local "local/afile/x.txt": ...` (round 7 scenario 26).  A version
/// that reported the mkdir would print one extra line the real tool does
/// not print.
fn CopyEngine::ensure_local_dir(self : CopyEngine, path : String) -> Unit {
  let _ = (self.fs.mkdir_fn)(path)
}

///|
/// Upload one local file to an exact remote path.
///
/// The caller has already decided that destination (`copy.mbt`'s
/// `plan_one`); this function never looks at the command line.
pub fn CopyEngine::upload_file(
  self : CopyEngine,
  lpath : String,
  rpath : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  let data = match (self.fs.read_fn)(lpath) {
    Some(d) => d
    None => {
      // The driver stat'ed this path a moment ago, so reaching here means
      // it went away in between -- and this is the tool's own sentence for
      // a source it cannot see.
      report.push(StatLocal(lpath, (self.fs.reason_fn)()))
      return
    }
  }
  let flags = @sftpdrive.pflag_write() |
    @sftpdrive.pflag_creat() |
    @sftpdrive.pflag_trunc()
  let handle = match self.drive.open(rpath, flags) {
    Ok(h) => h
    Err(e) => {
      report.push(DestOpen(rpath, drive_reason(e)))
      report.push(TransferFailed(direction_upload(), lpath, rpath))
      return
    }
  }
  let size = data.length().to_uint64()
  let chunk = transfer_chunk()
  let mut off = 0UL
  let mut failed = false
  while off < size && !failed {
    let end = if off + chunk.to_uint64() < size {
      off + chunk.to_uint64()
    } else {
      size
    }
    match self.drive.write(handle, off, slice_bytes(data, off, end)) {
      Ok(_) => off = end
      Err(e) => {
        report.push(DestOpen(rpath, drive_reason(e)))
        report.push(TransferFailed(direction_upload(), lpath, rpath))
        failed = true
      }
    }
  }
  let _ = self.drive.close(handle)
  if failed {
    return
  }
  if preserve {
    // `-p` on the upload side sets the remote times from the local ones.
    // A failure here is not reported: the tool's `-p` is best-effort, and
    // there is no measurement of a message for this particular refusal.
    let _ = self.drive.setstat(rpath, attrs_with_time(self.mtime_of(lpath)))
  }
}

///|
/// Upload a whole local directory tree into a remote directory.
///
/// `rpath` is the directory **whose contents** are replaced -- the caller
/// has already applied the naming rule: `-r local/t host:srv/upload`
/// copies t's contents into `upload/` when `upload` does not exist (round 5
/// scenario 3) and into `upload/t/` when it does (round 7 scenario 28).
pub fn CopyEngine::upload_tree(
  self : CopyEngine,
  lpath : String,
  rpath : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  match self.ensure_remote_dir(rpath) {
    Err(why) => {
      // Fatal, and it stops the whole run: measured round 8 scenario 30.
      report.push(RemoteMkdir(rpath, why))
      return
    }
    Ok(_) => ()
  }
  let names = match (self.fs.list_fn)(lpath) {
    Some(ns) => ns
    None => {
      report.push(StatLocal(lpath, (self.fs.reason_fn)()))
      return
    }
  }
  for i = 0; i < names.length(); i = i + 1 {
    if report.fatal {
      return
    }
    let name = names[i]
    let lchild = local_join(lpath, name)
    let rchild = remote_join(rpath, name)
    match (self.fs.stat_fn)(lchild) {
      None =>
        // A child that vanished between the listing and the stat is the
        // same "source went away" case as a missing top-level source.
        report.push(StatLocal(lchild, (self.fs.reason_fn)()))
      Some(st) =>
        if st.is_dir {
          self.upload_tree(lchild, rchild, preserve, report)
        } else {
          self.upload_file(lchild, rchild, preserve, report)
        }
    }
  }
  if preserve && !report.fatal {
    let _ = self.drive.setstat(rpath, attrs_with_time(self.mtime_of(lpath)))
  }
}

///|
/// Download one remote file to an exact local path.
///
/// `abs_remote` is the server's own absolute spelling of this file, used
/// only for the second line of a failure inside a walk -- the real tool
/// realpaths the source and its message shows that
/// (`/E:/.../srv/dt/x.txt`).  At the top level that line is not printed at
/// all, which is why `inside_walk` is an argument rather than being
/// inferred from `abs_remote`.
pub fn CopyEngine::download_file(
  self : CopyEngine,
  rpath : String,
  abs_remote : String,
  lpath : String,
  preserve : Bool,
  inside_walk : Bool,
  report : ScpReport,
) -> Unit {
  let attrs = match self.drive.stat(rpath) {
    Ok(a) => a
    Err(e) => {
      report.push(RemotePath(rpath, drive_reason(e)))
      return
    }
  }
  let handle = match self.drive.open(rpath, @sftpdrive.pflag_read()) {
    Ok(h) => h
    Err(e) => {
      report.push(RemotePath(rpath, drive_reason(e)))
      return
    }
  }
  let out : Array[Byte] = []
  let chunk = transfer_chunk()
  let mut off = 0UL
  let mut read_failed = false
  let mut done = false
  while !done {
    match self.drive.read(handle, off, chunk) {
      Ok(d) =>
        if d.length() == 0 {
          // EOF: the drive folds `SSH_FX_EOF` into an empty array.
          done = true
        } else {
          for i = 0; i < d.length(); i = i + 1 {
            out.push(d[i])
          }
          off = off + d.length().to_uint64()
        }
      Err(e) => {
        report.push(RemotePath(rpath, drive_reason(e)))
        read_failed = true
        done = true
      }
    }
  }
  let _ = self.drive.close(handle)
  if read_failed {
    return
  }
  let bytes = FixedArray::make(out.length(), b'\x00')
  for i = 0; i < out.length(); i = i + 1 {
    bytes[i] = out[i]
  }
  match (self.fs.write_fn)(lpath, bytes) {
    Some(why) => {
      report.push(OpenLocal(lpath, why))
      if inside_walk {
        report.push(DownloadFailed(abs_remote, lpath))
      }
      return
    }
    None => ()
  }
  if preserve {
    match attrs.mtime {
      Some(t) => {
        let _ = (self.fs.set_mtime_fn)(lpath, t.to_int64())
      }
      None => ()
    }
  }
}

///|
/// Download a whole remote directory tree into a local directory.
///
/// realpath happens once, here, because every child's failure line has to
/// name the absolute path -- and the real tool realpaths the *source
/// directory* and joins names onto that (round 7 scenario 26).
pub fn CopyEngine::download_tree(
  self : CopyEngine,
  rpath : String,
  lpath : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  let abs = match self.drive.realpath(rpath) {
    Ok(p) => p
    // A server that will not realpath still lists, so the failure lines
    // would then carry the command-line path.  That is a documented gap,
    // not a guess at a message.
    Err(_) => rpath
  }
  self.walk_remote_dir(rpath, abs, lpath, preserve, report)
}

///|
/// The descent itself: one directory's children, then their children.
fn CopyEngine::walk_remote_dir(
  self : CopyEngine,
  rpath : String,
  abs_remote : String,
  lpath : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  self.ensure_local_dir(lpath)
  let entries = match self.drive.list_dir(rpath) {
    Ok(es) => es
    Err(e) => {
      report.push(RemotePath(rpath, drive_reason(e)))
      return
    }
  }
  for i = 0; i < entries.length(); i = i + 1 {
    if report.fatal {
      return
    }
    let (name, attrs) = entries[i]
    let rchild = remote_join(rpath, name)
    let achild = remote_join(abs_remote, name)
    let lchild = local_join(lpath, name)
    if @sftpdrive.attrs_is_dir(attrs) {
      self.walk_remote_dir(rchild, achild, lchild, preserve, report)
    } else {
      self.download_file(rchild, achild, lchild, preserve, true, report)
    }
  }
  if preserve && !report.fatal {
    // The directory's own time is set **after** its children, because
    // writing a child moves the parent's mtime.  Measured: `-p -r`
    // preserves directory times too, and the values match the source
    // exactly (round 7 scenario 25).
    let _ = (self.fs.set_mtime_fn)(lpath, self.remote_mtime(rpath))
  }
}

///|
/// Join two local path components.
///
/// Both separators are accepted on the way in -- `basename_of` says the
/// same thing about the other direction -- and the separator written is
/// `\`, because that is the platform this repository's gates run on.
/// **This is the one place a POSIX-shaped gate would disagree**, which is
/// why the gate compares the resulting *tree* rather than these strings.
pub fn local_join(dir : String, name : String) -> String {
  let n = dir.length()
  if n == 0 {
    name
  } else if dir[n - 1] == '/' || dir[n - 1] == '\\' {
    dir + name
  } else {
    dir + "\\" + name
  }
}

///|
/// Copy one local file to another local path.
///
/// ## Why this exists at all
///
/// The Windows scp.exe hands a local-to-local copy to the **cmd
/// built-ins** (copy / xcopy), so its output is the shell's and its
/// text moves with the locale -- .loop90/DESIGN.md section 2 records the
/// GBK message that came out of that path on this machine.  There is
/// therefore no byte-for-byte target to match here, and the decision
/// recorded in the design note is that this implementation does the copy
/// itself and speaks **its own** sentences, which are the same ones the
/// remote paths use for the same failures.
///
/// So a local-to-local run is the one place where the gate asserts our own
/// documented output rather than the real tool's.  It says so out loud in
/// host/verify_loop90.mjs too, because a gate that quietly stopped
/// comparing would be worse than no gate.
/// Put one local file at another local path.
///
/// A **free function**, not a method on `CopyEngine`, because this path
/// has no remote side at all and the engine exists to hold a drive.
pub fn local_copy(
  fs : LocalFs,
  from : String,
  to : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  let data = match (fs.read_fn)(from) {
    Some(d) => d
    None => {
      report.push(StatLocal(from, (fs.reason_fn)()))
      return
    }
  }
  match (fs.write_fn)(to, data) {
    Some(why) => report.push(OpenLocal(to, why))
    None =>
      if preserve {
        match (fs.stat_fn)(from) {
          Some(st) => {
            let _ = (fs.set_mtime_fn)(to, st.mtime)
          }
          None => ()
        }
      }
  }
}

///|
/// Put a whole local directory tree inside another local directory.
///
/// `to` is the directory **whose contents** are replaced, the caller
/// having already applied `dest_for`.  The mkdir is attempted and its
/// refusal ignored, the same shape as the download side
/// (`ensure_local_dir` says why).
pub fn local_copy_tree(
  fs : LocalFs,
  from : String,
  to : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  let _ = (fs.mkdir_fn)(to)
  let names = match (fs.list_fn)(from) {
    Some(ns) => ns
    None => {
      report.push(StatLocal(from, (fs.reason_fn)()))
      return
    }
  }
  for i = 0; i < names.length(); i = i + 1 {
    if report.fatal {
      return
    }
    let lchild = local_join(from, names[i])
    let dchild = local_join(to, names[i])
    match (fs.stat_fn)(lchild) {
      None => report.push(StatLocal(lchild, (fs.reason_fn)()))
      Some(st) =>
        if st.is_dir {
          local_copy_tree(fs, lchild, dchild, preserve, report)
        } else {
          local_copy(fs, lchild, dchild, preserve, report)
        }
    }
  }
  if preserve {
    match (fs.stat_fn)(from) {
      Some(st) => {
        let _ = (fs.set_mtime_fn)(to, st.mtime)
      }
      None => ()
    }
  }
}

///|
/// Copy one remote file to another path on the same server.
///
/// Measured: scp host:srv/r1.txt host:srv/r2.txt under -D exits 0 and
/// the bytes arrive (round 5 scenario 12).  Nothing local is involved, so
/// this goes straight from one handle to the other.
pub fn CopyEngine::copy_remote(
  self : CopyEngine,
  from : String,
  to : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  let attrs = match self.drive.stat(from) {
    Ok(a) => a
    Err(e) => {
      report.push(RemotePath(from, drive_reason(e)))
      return
    }
  }
  let src = match self.drive.open(from, @sftpdrive.pflag_read()) {
    Ok(h) => h
    Err(e) => {
      report.push(RemotePath(from, drive_reason(e)))
      return
    }
  }
  let dst = match
    self.drive.open(
      to,
      @sftpdrive.pflag_write() |
      @sftpdrive.pflag_creat() |
      @sftpdrive.pflag_trunc(),
    ) {
    Ok(h) => h
    Err(e) => {
      let _ = self.drive.close(src)
      report.push(DestOpen(to, drive_reason(e)))
      report.push(TransferFailed(direction_upload(), from, to))
      return
    }
  }
  let chunk = transfer_chunk()
  let mut off = 0UL
  let mut failed = false
  let mut done = false
  while !done {
    match self.drive.read(src, off, chunk) {
      Ok(d) =>
        if d.length() == 0 {
          done = true
        } else {
          match self.drive.write(dst, off, d) {
            Ok(_) => off = off + d.length().to_uint64()
            Err(e) => {
              report.push(DestOpen(to, drive_reason(e)))
              report.push(TransferFailed(direction_upload(), from, to))
              failed = true
              done = true
            }
          }
        }
      Err(e) => {
        report.push(RemotePath(from, drive_reason(e)))
        failed = true
        done = true
      }
    }
  }
  let _ = self.drive.close(src)
  let _ = self.drive.close(dst)
  if failed {
    return
  }
  if preserve {
    match attrs.mtime {
      Some(t) => {
        let _ = self.drive.setstat(to, attrs_with_time(t.to_int64()))
      }
      None => ()
    }
  }
}

///|
/// Copy a whole remote directory tree to another place on the same server.
///
/// The caller has applied `dest_for`, so `rto` is the directory whose
/// **contents** are replaced -- the same rule as the upload tree.
pub fn CopyEngine::copy_remote_tree(
  self : CopyEngine,
  rfrom : String,
  rto : String,
  preserve : Bool,
  report : ScpReport,
) -> Unit {
  match self.ensure_remote_dir(rto) {
    Err(why) => {
      report.push(RemoteMkdir(rto, why))
      return
    }
    Ok(_) => ()
  }
  let entries = match self.drive.list_dir(rfrom) {
    Ok(es) => es
    Err(e) => {
      report.push(RemotePath(rfrom, drive_reason(e)))
      return
    }
  }
  for i = 0; i < entries.length(); i = i + 1 {
    if report.fatal {
      return
    }
    let (name, attrs) = entries[i]
    let schild = remote_join(rfrom, name)
    let dchild = remote_join(rto, name)
    if @sftpdrive.attrs_is_dir(attrs) {
      self.copy_remote_tree(schild, dchild, preserve, report)
    } else {
      self.copy_remote(schild, dchild, preserve, report)
    }
  }
  if preserve && !report.fatal {
    let _ = self.drive.setstat(rto, attrs_with_time(self.remote_mtime(rfrom)))
  }
}
