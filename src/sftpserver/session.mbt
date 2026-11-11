///| Loop #92: the SFTP server's state machine.
///
/// Given a request, produce the reply bytes.  The wire format lives in
/// `proto.mbt`; the filesystem lives behind `ServerFs`; what is here is
/// the RULES -- which request produces which reply, and in what order.
///
/// ## What is measured and what is not
///
/// Every rule below was read out of the real `sftp-server.exe` on this
/// machine.  The ones that are easy to get wrong, and where they came
/// from:
///
///   * **An enumeration ends with STATUS EOF, not with an empty NAME.**
///     Measured: the second READDIR of a directory answers `code=1 End of
///     file` (`.loop92/probe_out.txt`).  A server written from the draft
///     alone would answer an empty NAME and the client would see a
///     difference.
///   * **READ past EOF answers STATUS EOF**, not an empty DATA
///     (`.loop92/probe_out.txt`).
///   * **READDIR answers 100 entries per NAME**, then the next READDIR
///     answers the rest and then EOF.  Measured with 250 files: the batch
///     sizes were 100, 100, 50 (`.loop92/probe8_out.txt`).
///   * **A handle is a SLOT, not a counter.**  Two opens answer
///     `00000000` and `00000001`; after the first is closed the next open
///     answers `00000000` again (`.loop92/probe8_out.txt`).  A monotonic
///     counter would answer `00000002`.
///   * **An unknown request type is answered with NOTHING.**  The real
///     server neither replies nor closes; it goes on to answer the NEXT
///     request correctly (`.loop92/probe3_out.txt`).  Answering it with
///     an error would be a difference the client can see.
///   * **An unknown EXTENSION is answered with STATUS 8 "Operation
///     unsupported"** -- which is a different thing from an unknown
///     request type (`.loop92/probe3_out.txt`).
///   * **A missing file is `2 No such file`; a refused operation is `3
///     Permission denied`; a nonsensical one is `5 Bad message`; and
///     everything else that fails is `4 Failure`.**
///
/// ## The words
///
/// The STATUS sentences are a closed set, and they are what a client
/// prints when it falls back to reading the text instead of the code, so
/// they are part of the contract.
///
/// | code | sentence |
/// |---|---|
/// | 0 | `Success` |
/// | 1 | `End of file` |
/// | 2 | `No such file` |
/// | 3 | `Permission denied` |
/// | 4 | `Failure` |
/// | 5 | `Bad message` |
/// | 8 | `Operation unsupported` |
///
/// ## The clock
///
/// The date column depends on the current time, so the server has to be
/// able to tell what "now" is -- and the tests have to be able to pin
/// it.  `now_fn` is therefore a function value like the filesystem's.

///|
/// The clock the server reads.
pub(all) struct ServerClock {
  /// The current time, in seconds since the epoch.
  now_fn : () -> Int64
  /// The local offset from UTC, in seconds, at a given time.
  ///
  /// The date column is LOCAL time, and the local offset changes with
  /// daylight saving, so it is a function of the time rather than a
  /// constant.
  local_offset_fn : (Int64) -> Int64
}

///|
/// One open handle: what it refers to and how it may be used.
pub(all) struct Handle {
  /// The path it was opened from, for the operations that need it.
  path : String
  /// The open flags, so a read of a write-only handle can be refused.
  flags : Int32
  /// Whether it is a directory.
  is_dir : Bool
  /// The read-only flag of the file, for the permission word.
  is_readonly : Bool
}

///|
/// The server's state: the open handles and the clock.
pub(all) struct ServerState {
  /// The open handles, indexed by the HANDLE NUMBER the filesystem gave.
  ///
  /// The index is the filesystem's own, not one of ours: the client sends
  /// the handle back on every later request and the filesystem is the only
  /// thing that can turn it into a file.  So the server never invents a
  /// handle number of its own -- it records what it was given.
  ///
  /// A slot that is not in use is `None`, which is how a handle number
  /// becomes free again after a close.
  handles : Array[Handle?]
  /// The clock.
  clock : ServerClock
}

///|
/// A new state with no handles open.
pub fn ServerState::new(clock : ServerClock) -> ServerState {
  { handles: [], clock, }
}

///|
/// Remember what the handle `n` refers to.
///
/// The handle NUMBER is the filesystem's: the real server's handle is the
/// lowest free SLOT of its own table (`.loop92/probe8_out.txt`), and the
/// slot index is what the client is told.  So the number the filesystem
/// hands out is the number the client sees, and the table here is indexed
/// by it.
///
/// The earlier version of this file allocated a slot of its OWN and
/// ignored the filesystem's number, which meant the table and the
/// filesystem could disagree about which file a handle meant: the reply
/// said one number and the table looked up another.
fn ServerState::set_handle(self : ServerState, n : Int32, h : Handle) -> Unit {
  while self.handles.length() <= n {
    self.handles.push(None)
  }
  self.handles[n] = Some(h)
}

///|
/// The handle with a number, if it is open.
fn ServerState::handle_at(self : ServerState, n : Int32) -> Handle? {
  if n < 0 || n >= self.handles.length() {
    return None
  }
  self.handles[n]
}

///|
/// The number of a handle as the four bytes the wire carries.
///
/// The handle is 32 bits, big endian, and the real server counts up from
/// zero (`.loop92/probe_out.txt`).
pub fn handle_bytes(n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  let v = n.reinterpret_as_uint()
  out[0] = ((v >> 24) & 0xFFU).to_byte()
  out[1] = ((v >> 16) & 0xFFU).to_byte()
  out[2] = ((v >> 8) & 0xFFU).to_byte()
  out[3] = (v & 0xFFU).to_byte()
  out
}

///|
/// The number a handle's bytes stand for, or -1 when they are not four
/// bytes.
fn handle_number(h : FixedArray[Byte]) -> Int32 {
  if h.length() != 4 {
    return -1
  }
  @sshwire.read_u32(h, 0).reinterpret_as_int()
}

///|
/// How many entries one READDIR reply carries.
///
/// Measured with 250 files: the batch sizes were 100, 100, 50.
pub const READDIR_BATCH : Int32 = 100

///|
/// The reply to one request.
///
/// `None` means "send nothing", which is what the real server does for
/// a request type it does not know.
pub fn ServerState::reply(
  self : ServerState,
  fs : ServerFs,
  req : Request,
) -> FixedArray[Byte]? {
  match req {
    Init(_) => Some(reply_version())
    Stat(id, path) => Some(reply_stat(fs, id, path))
    Lstat(id, path) => Some(reply_stat(fs, id, path))
    Fstat(id, handle) => Some(self.reply_fstat(fs, id, handle))
    Realpath(id, path) => Some(reply_realpath(fs, id, path))
    Open(id, path, flags, _) => Some(self.reply_open(fs, id, path, flags))
    Opendir(id, path) => Some(self.reply_opendir(fs, id, path))
    Read(id, handle, offset, len) =>
      Some(self.reply_read(fs, id, handle, offset, len))
    Write(id, handle, offset, data) =>
      Some(self.reply_write(fs, id, handle, offset, data))
    Close(id, handle) => Some(self.reply_close(fs, id, handle))
    Readdir(id, handle) => Some(self.reply_readdir(fs, id, handle))
    Mkdir(id, path, _) => Some(reply_mkdir(fs, id, path))
    Rmdir(id, path) => Some(reply_rmdir(fs, id, path))
    Remove(id, path) => Some(reply_remove(fs, id, path))
    Rename(id, from, to) => Some(reply_rename(fs, id, from, to))
    Setstat(id, path, attrs) => Some(reply_setstat(fs, id, path, attrs))
    Fsetstat(id, handle, attrs) =>
      Some(self.reply_fsetstat(fs, id, handle, attrs))
    Extended(id, name, rest) => Some(reply_extended(fs, id, name, rest))
    // An unknown request type gets NO reply at all -- measured: the real
    // server goes on to answer the next request correctly.
    Unknown(_) => None
  }
}

///|
/// The attributes of a path, in the form the server reports them.
fn attrs_of(st : FileStat, perm : Int32) -> @sftp.SftpAttrs {
  let attrs = @sftp.SftpAttrs::none()
  attrs.size = Some(st.size.reinterpret_as_uint64())
  attrs.uid = Some(0)
  attrs.gid = Some(0)
  attrs.permissions = Some(perm)
  attrs.atime = Some(st.atime.to_int())
  attrs.mtime = Some(st.mtime.to_int())
  attrs
}

///|
/// The reply to STAT and LSTAT.
///
/// Measured: a missing path is `2 No such file`; an existing one is an
/// ATTRS reply with flags 15 and the STAT permission word.
fn reply_stat(fs : ServerFs, id : Int32, path : String) -> FixedArray[Byte] {
  match (fs.stat_fn)(path) {
    None => reply_status(id, FX_NO_SUCH_FILE)
    Some(st) =>
      reply_attrs(
        id,
        attrs_of(st, stat_perm_word(st.is_dir, st.is_readonly, st.other_bits)),
      )
  }
}

///|
/// The reply to FSTAT.
///
/// Measured: the permission word differs from STAT's -- 33206 against
/// 33152 for the same writable file -- and FSTAT on a DIRECTORY handle
/// is `4 Failure`.
fn ServerState::reply_fstat(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  handle : FixedArray[Byte],
) -> FixedArray[Byte] {
  let n = handle_number(handle)
  match self.handle_at(n) {
    None => reply_status(id, FX_FAILURE)
    Some(h) => {
      if h.is_dir {
        return reply_status(id, FX_FAILURE)
      }
      match (fs.stat_fn)(h.path) {
        None => reply_status(id, FX_FAILURE)
        Some(st) =>
          reply_attrs(id, attrs_of(st, fstat_perm_word(st.is_readonly)))
      }
    }
  }
}

///|
/// The reply to REALPATH.
///
/// Measured: a NAME with ONE entry, whose `filename` and `longname` are
/// the SAME absolute string, and whose attributes have flags 0.  The path
/// is spelled with a slash before the drive letter and forward slashes
/// throughout: `/C:/Users/...`.
fn reply_realpath(fs : ServerFs, id : Int32, path : String) -> FixedArray[Byte] {
  let abs = (fs.realpath_fn)(path)
  let entries : Array[NameEntry] = [
    { filename: abs, longname: abs, attrs: @sftp.SftpAttrs::none(), },
  ]
  reply_name(id, entries)
}

///|
/// The reply to OPEN.
///
/// Measured: an existing file answers a HANDLE; a missing one is `2 No
/// such file`; a read-only file opened for writing is `3 Permission
/// denied`.
fn ServerState::reply_open(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  path : String,
  flags : Int32,
) -> FixedArray[Byte] {
  // The real server refuses to open a read-only file for writing, and
  // answers `3 Permission denied` -- measured.
  if (flags & 2) != 0 {
    match (fs.stat_fn)(path) {
      Some(st) =>
        if st.is_readonly && !st.is_dir {
          return reply_status(id, FX_PERMISSION_DENIED)
        }
      None => ()
    }
  }
  match (fs.open_fn)(path, flags) {
    Err(e) => reply_status(id, status_code(e))
    Ok(n) => {
      let is_readonly = match (fs.stat_fn)(path) {
        Some(st) => st.is_readonly
        None => false
      }
      self.set_handle(n, { path, flags, is_dir: false, is_readonly, })
      reply_handle(id, handle_bytes(n))
    }
  }
}

///|
/// The reply to OPENDIR.
///
/// Measured: a directory answers a HANDLE, a FILE is `5 Bad message`,
/// and a missing path is `2 No such file`.
fn ServerState::reply_opendir(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  path : String,
) -> FixedArray[Byte] {
  match (fs.stat_fn)(path) {
    None => return reply_status(id, FX_NO_SUCH_FILE)
    Some(st) => if !st.is_dir { return reply_status(id, FX_BAD_MESSAGE) }
  }
  match (fs.opendir_fn)(path) {
    Err(e) => reply_status(id, status_code(e))
    Ok(n) => {
      self.set_handle(n, { path, flags: 0, is_dir: true, is_readonly: true, })
      reply_handle(id, handle_bytes(n))
    }
  }
}

///|
/// The most bytes one READ may return.
///
/// Measured against the real server on a 400000-byte file: asking for 65535
/// answered 65535 bytes, asking for 65536 answered 65536, and asking for
/// 65537, 131072 and 400000 all answered **65536**.  So the request is
/// truncated to 65536 and the server says nothing about the truncation -- a
/// client that asked for more has to take what it gets.
pub const READ_MAX : Int32 = 65536

///|
/// The reply to READ.
///
/// Measured: a READ that reaches the end of the file answers DATA with
/// the bytes and the NEXT read answers `1 End of file`.  A read past the
/// end answers `1 End of file` straight away.  A handle that is not open
/// is `4 Failure`.
fn ServerState::reply_read(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  handle : FixedArray[Byte],
  offset : UInt64,
  len : Int32,
) -> FixedArray[Byte] {
  let n = handle_number(handle)
  match self.handle_at(n) {
    None => reply_status(id, FX_FAILURE)
    Some(_) => {
      if len <= 0 {
        return reply_status(id, FX_EOF)
      }
      // The real server never returns more than READ_MAX bytes, however
      // much was asked for.
      let want = if len > READ_MAX { READ_MAX } else { len }
      let data = (fs.read_fn)(n, offset.reinterpret_as_int64(), want)
      if data.length() == 0 {
        reply_status(id, FX_EOF)
      } else {
        reply_data(id, data)
      }
    }
  }
}

///|
/// The reply to WRITE.
///
/// Measured: a write answers `0 Success`; a handle that is not open is
/// `4 Failure`.
fn ServerState::reply_write(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  handle : FixedArray[Byte],
  offset : UInt64,
  data : FixedArray[Byte],
) -> FixedArray[Byte] {
  let n = handle_number(handle)
  match self.handle_at(n) {
    None => reply_status(id, FX_FAILURE)
    Some(_) =>
      match (fs.write_fn)(n, offset.reinterpret_as_int64(), data) {
        Ok(_) => reply_status(id, FX_OK)
        Err(e) => reply_status(id, status_code(e))
      }
  }
}

///|
/// The reply to CLOSE.
///
/// Measured: `0 Success` for an open handle, and `2 No such file` for one
/// that is not -- note that CLOSE says "no such file" where READ says
/// `4 Failure`.
fn ServerState::reply_close(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  handle : FixedArray[Byte],
) -> FixedArray[Byte] {
  let n = handle_number(handle)
  match self.handle_at(n) {
    None => reply_status(id, FX_NO_SUCH_FILE)
    Some(h) => {
      (fs.close_fn)(n)
      self.handles[n] = None
      let _ = h
      reply_status(id, FX_OK)
    }
  }
}

///|
/// The reply to READDIR.
///
/// Measured: the first READDIR answers a NAME with up to 100 entries, the
/// next answers the rest, and the one after that answers `1 End of file`.
/// A handle that is not open is `4 Failure`.
fn ServerState::reply_readdir(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  handle : FixedArray[Byte],
) -> FixedArray[Byte] {
  let n = handle_number(handle)
  match self.handle_at(n) {
    None => reply_status(id, FX_FAILURE)
    Some(h) => {
      if !h.is_dir {
        return reply_status(id, FX_FAILURE)
      }
      let entries : Array[NameEntry] = []
      let now = (self.clock.now_fn)()
      let offset = (self.clock.local_offset_fn)(now)
      while entries.length() < READDIR_BATCH {
        match (fs.readdir_fn)(n) {
          None => break
          Some(e) => {
            let ln = longname(
              e.name,
              e.stat.is_dir,
              e.stat.is_readonly,
              e.stat.size,
              e.stat.mtime,
              now,
              offset,
            )
            entries.push({
              filename: e.name,
              longname: ln,
              attrs: attrs_of(
                e.stat,
                stat_perm_word(
                  e.stat.is_dir,
                  e.stat.is_readonly,
                  e.stat.other_bits,
                ),
              ),
            })
          }
        }
      }
      if entries.length() == 0 {
        // The end of the listing is STATUS EOF, not an empty NAME.
        reply_status(id, FX_EOF)
      } else {
        reply_name(id, entries)
      }
    }
  }
}

///|
/// The reply to MKDIR.
///
/// Measured: `0 Success`, and `4 Failure` when the directory is already
/// there.
fn reply_mkdir(fs : ServerFs, id : Int32, path : String) -> FixedArray[Byte] {
  match (fs.mkdir_fn)(path) {
    Ok(_) => reply_status(id, FX_OK)
    Err(e) => reply_status(id, status_code(e))
  }
}

///|
/// The reply to RMDIR.
///
/// Measured: `0 Success`, and `5 Bad message` when the path is a FILE.
fn reply_rmdir(fs : ServerFs, id : Int32, path : String) -> FixedArray[Byte] {
  match (fs.stat_fn)(path) {
    Some(st) => if !st.is_dir { return reply_status(id, FX_BAD_MESSAGE) }
    None => return reply_status(id, FX_NO_SUCH_FILE)
  }
  match (fs.rmdir_fn)(path) {
    Ok(_) => reply_status(id, FX_OK)
    Err(e) => reply_status(id, status_code(e))
  }
}

///|
/// The reply to REMOVE.
///
/// Measured: `0 Success`, `2 No such file` for a missing path, and `3
/// Permission denied` for a DIRECTORY -- Windows refuses to delete a
/// directory with DeleteFile, and the real server passes that refusal on
/// rather than reclassifying it.
fn reply_remove(fs : ServerFs, id : Int32, path : String) -> FixedArray[Byte] {
  match (fs.stat_fn)(path) {
    None => return reply_status(id, FX_NO_SUCH_FILE)
    Some(st) => if st.is_dir { return reply_status(id, FX_PERMISSION_DENIED) }
  }
  match (fs.remove_fn)(path) {
    Ok(_) => reply_status(id, FX_OK)
    Err(e) => reply_status(id, status_code(e))
  }
}

///|
/// The reply to RENAME.
///
/// Measured: `0 Success`, `2 No such file` when the source is missing,
/// and `4 Failure` when the target is already there.
fn reply_rename(
  fs : ServerFs,
  id : Int32,
  from : String,
  to : String,
) -> FixedArray[Byte] {
  match (fs.stat_fn)(from) {
    None => return reply_status(id, FX_NO_SUCH_FILE)
    Some(_) => ()
  }
  match (fs.stat_fn)(to) {
    Some(_) => return reply_status(id, FX_FAILURE)
    None => ()
  }
  match (fs.rename_fn)(from, to) {
    Ok(_) => reply_status(id, FX_OK)
    Err(e) => reply_status(id, status_code(e))
  }
}

///|
/// The reply to SETSTAT.
///
/// Measured: `0 Success`.  The attributes the client sends are the size
/// and the times; the size is applied by truncating and the times by
/// setting them.
fn reply_setstat(
  fs : ServerFs,
  id : Int32,
  path : String,
  attrs : @sftp.SftpAttrs,
) -> FixedArray[Byte] {
  if attrs.size is Some(_) {
    // A size on a PATH is applied by truncating the file, which needs
    // the file open -- and the real server does exactly that.
    match (fs.open_fn)(path, 2 | 8) {
      Err(e) => return reply_status(id, status_code(e))
      Ok(n) => {
        let r = (fs.truncate_fn)(n, attrs.size.unwrap().reinterpret_as_int64())
        (fs.close_fn)(n)
        if r is Err(_) {
          return reply_status(id, status_code(r.unwrap_err()))
        }
      }
    }
  }
  if attrs.mtime is Some(_) {
    match (fs.set_mtime_fn)(path, attrs.mtime.unwrap().to_int64()) {
      Ok(_) => ()
      Err(e) => return reply_status(id, status_code(e))
    }
  }
  reply_status(id, FX_OK)
}

///|
/// The reply to FSETSTAT.
///
/// Measured: `0 Success`, and the size IS applied -- a file written with
/// 20 bytes and then FSETSTAT'd to 5 came back as 5 bytes long.  The
/// permissions are NOT applied: a FSETSTAT with mode 0644 left the
/// reported word alone, because Windows has no such thing to set.
fn ServerState::reply_fsetstat(
  self : ServerState,
  fs : ServerFs,
  id : Int32,
  handle : FixedArray[Byte],
  attrs : @sftp.SftpAttrs,
) -> FixedArray[Byte] {
  let n = handle_number(handle)
  match self.handle_at(n) {
    None => reply_status(id, FX_FAILURE)
    Some(h) => {
      if attrs.size is Some(_) {
        match (fs.truncate_fn)(n, attrs.size.unwrap().reinterpret_as_int64()) {
          Ok(_) => ()
          Err(e) => return reply_status(id, status_code(e))
        }
      }
      if attrs.mtime is Some(_) {
        match (fs.set_mtime_fn)(h.path, attrs.mtime.unwrap().to_int64()) {
          Ok(_) => ()
          Err(e) => return reply_status(id, status_code(e))
        }
      }
      reply_status(id, FX_OK)
    }
  }
}

///|
/// The reply to an EXTENDED request.
///
/// Measured: `posix-rename@openssh.com` renames and answers `0
/// Success`; an extension the server does not know answers `8 Operation
/// unsupported` -- which is a different thing from an unknown request
/// TYPE, which gets no reply at all.
///
/// The extension's own arguments are read here rather than in the parser:
/// the parser does not know which extensions exist, and the rules about
/// which one does what are rules.
fn reply_extended(
  fs : ServerFs,
  id : Int32,
  name : String,
  rest : FixedArray[Byte],
) -> FixedArray[Byte] {
  if name == "posix-rename@openssh.com" {
    return reply_posix_rename(fs, id, rest)
  }
  reply_status(id, FX_OP_UNSUPPORTED)
}

///|
/// The reply to `posix-rename@openssh.com`.
///
/// Measured against the real server: it renames and answers `0 Success`;
/// it **replaces** a target that is already there -- which the draft's
/// `FXP_RENAME` refuses to do, answering `4 Failure` for the same pair of
/// files -- and a missing source is `2 No such file`.
fn reply_posix_rename(
  fs : ServerFs,
  id : Int32,
  rest : FixedArray[Byte],
) -> FixedArray[Byte] {
  let (from, to, ok) = read_two_paths(rest)
  if !ok {
    // The extension did not carry two paths.  The real server's word for a
    // request it cannot make sense of is `5 Bad message`.
    return reply_status(id, FX_BAD_MESSAGE)
  }
  match (fs.stat_fn)(from) {
    None => return reply_status(id, FX_NO_SUCH_FILE)
    Some(_) => ()
  }
  match (fs.rename_replace_fn)(from, to) {
    Ok(_) => reply_status(id, FX_OK)
    Err(e) => reply_status(id, status_code(e))
  }
}

///|
/// Read the two paths an extension carries; `ok` is false when they are not
/// both there.
///
/// The cursor `src/sftp` has cannot be used for this: its error flag is
/// package-private, so a caller in another package cannot tell a truncated
/// extension from an empty one -- and those two need different answers.
fn read_two_paths(rest : FixedArray[Byte]) -> (String, String, Bool) {
  let (from, at, ok1) = read_ext_string(rest, 0)
  if !ok1 {
    return ("", "", false)
  }
  let (to, _, ok2) = read_ext_string(rest, at)
  if !ok2 {
    return ("", "", false)
  }
  (from, to, true)
}

///|
/// Read one SSH string out of a byte buffer.
///
/// The bytes become a `String` byte by byte, the way `src/sftp`'s own cursor
/// does it: a path that is not UTF-8 must not take the session down.
fn read_ext_string(
  buf : FixedArray[Byte],
  off : Int32,
) -> (String, Int32, Bool) {
  if off < 0 || off + 4 > buf.length() {
    return ("", off, false)
  }
  let n = @sshwire.read_u32(buf, off).reinterpret_as_int()
  if n < 0 || off + 4 + n > buf.length() {
    return ("", off, false)
  }
  let sb = StringBuilder()
  for i = 0; i < n; i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(buf[off + 4 + i].to_int()))
  }
  (sb.to_string(), off + 4 + n, true)
}

///|
/// The STATUS code for a filesystem failure.
fn status_code(e : FsError) -> Int32 {
  match e {
    NoSuchFile => FX_NO_SUCH_FILE
    PermissionDenied => FX_PERMISSION_DENIED
    Failure => FX_FAILURE
    BadMessage => FX_BAD_MESSAGE
  }
}
