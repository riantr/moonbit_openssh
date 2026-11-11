///| The copy engine, tested without a filesystem and without a peer.
///
/// ## What is real in here
///
/// Nothing but the engine.  A `FakeSrv` answers the SFTP requests the
/// engine actually sends, and a `FakeFs` stands in for the platform's
/// file calls.  That is the whole point of the two abstractions: the
/// recursion, the chunking, the `-p` ordering and the **order and number
/// of failure lines** are all pinned here, on all four targets, and the
/// only untested part left is `localfs.c` (which the Loop #90 gate covers
/// end to end against the real `scp.exe`).
///
/// ## Why the fake server is stateful rather than scripted
///
/// A scripted peer (answer #1, answer #2, ...) would pass even if the
/// engine asked the wrong questions in the right order.  This one keeps
/// files, directories, handles and mtimes, so an upload that opens the
/// wrong path or writes at the wrong offset changes what is on the far
/// side.  `FakeSrv::log` records the request names for the tests that care
/// about *sequence* (`-p` sets a directory's time after its children).
///
/// ## The numbers
///
/// Every expected line in here comes from the measured tables in
/// `.loop90/DESIGN.md` (rounds 5-8), not from taste: `dest open` +
/// `failed to upload`, `open local` alone at top level, `open local` +
/// `Download of file ... failed` inside a walk, `remote mkdir` fatal.

// ---------------------------------------------------------------- bytes

///|
fn bin_u8(v : Int32) -> FixedArray[Byte] {
  let out = FixedArray::make(1, b'\x00')
  out[0] = (v & 0xFF).to_byte()
  out
}

///|
fn bin_u32(v : Int32) -> FixedArray[Byte] {
  let out = FixedArray::make(4, b'\x00')
  out[0] = ((v >> 24) & 0xFF).to_byte()
  out[1] = ((v >> 16) & 0xFF).to_byte()
  out[2] = ((v >> 8) & 0xFF).to_byte()
  out[3] = (v & 0xFF).to_byte()
  out
}

///|
fn bin_u64(v : UInt64) -> FixedArray[Byte] {
  let out = FixedArray::make(8, b'\x00')
  let mut i = 0
  while i < 8 {
    let shift = (7 - i) * 8
    out[i] = (v >> shift).to_int().to_byte()
    i = i + 1
  }
  out
}

///|
fn bin_cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut n = 0
  for i = 0; i < parts.length(); i = i + 1 {
    n = n + parts[i].length()
  }
  let out = FixedArray::make(n, b'\x00')
  let mut at = 0
  for i = 0; i < parts.length(); i = i + 1 {
    for j = 0; j < parts[i].length(); j = j + 1 {
      out[at + j] = parts[i][j]
    }
    at = at + parts[i].length()
  }
  out
}

///|
fn bin_str(data : FixedArray[Byte]) -> FixedArray[Byte] {
  bin_cat([bin_u32(data.length()), data])
}

///|
fn bin_ascii(s : String) -> FixedArray[Byte] {
  let out = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = s[i].to_int().to_byte()
  }
  out
}

///|
fn bin_text(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
fn bin_rd_u32(b : FixedArray[Byte], off : Int32) -> Int32 {
  (b[off].to_int() << 24) |
  (b[off + 1].to_int() << 16) |
  (b[off + 2].to_int() << 8) |
  b[off + 3].to_int()
}

///|
fn bin_rd_u64(b : FixedArray[Byte], off : Int32) -> UInt64 {
  let mut v = 0UL
  let mut i = 0
  while i < 8 {
    v = (v << 8) | b[off + i].to_int().to_uint64()
    i = i + 1
  }
  v
}

///|
/// Read a length-prefixed string: `(bytes, next offset)`.
fn bin_rd_str(b : FixedArray[Byte], off : Int32) -> (FixedArray[Byte], Int32) {
  let n = bin_rd_u32(b, off)
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = b[off + 4 + i]
  }
  (out, off + 4 + n)
}

// ------------------------------------------------------- the fake server

///|
priv struct FakeSrv {
  /// full path -> contents
  files : Array[(String, FixedArray[Byte])]
  /// full path -> child names
  dirs : Array[(String, Array[String])]
  /// full path -> mtime, as set by SETSTAT
  mtimes : Array[(String, Int32)]
  /// open handle id -> path
  handles : Array[(Int32, String)]
  mut next_handle : Int32
  /// framed replies waiting to be read
  pending : Array[FixedArray[Byte]]
  /// request names, in order
  log : Array[String]
  /// a path whose OPEN or MKDIR is refused; "" means none
  mut refuse : String
  refuse_code : Int32
  refuse_msg : String
  /// handle ids whose READDIR listing was already handed out
  served : Array[Int32]
}

///|
fn FakeSrv::new() -> FakeSrv {
  {
    files: [],
    dirs: [],
    mtimes: [],
    handles: [],
    next_handle: 0,
    pending: [],
    log: [],
    refuse: "",
    refuse_code: @sftp.FX_NO_SUCH_FILE,
    refuse_msg: "No such file or directory",
    served: [],
  }
}

///|
fn FakeSrv::find_file(self : FakeSrv, path : String) -> Int32 {
  let mut i = 0
  while i < self.files.length() {
    if self.files[i].0 == path {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn FakeSrv::find_dir(self : FakeSrv, path : String) -> Int32 {
  let mut i = 0
  while i < self.dirs.length() {
    if self.dirs[i].0 == path {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn FakeSrv::find_handle(self : FakeSrv, id : Int32) -> Int32 {
  let mut i = 0
  while i < self.handles.length() {
    if self.handles[i].0 == id {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn FakeSrv::add_file(
  self : FakeSrv,
  path : String,
  data : FixedArray[Byte],
) -> Unit {
  let at = self.find_file(path)
  if at >= 0 {
    self.files[at] = (path, data)
  } else {
    self.files.push((path, data))
  }
}

///|
fn FakeSrv::add_dir(
  self : FakeSrv,
  path : String,
  kids : Array[String],
) -> Unit {
  let at = self.find_dir(path)
  if at >= 0 {
    self.dirs[at] = (path, kids)
  } else {
    self.dirs.push((path, kids))
  }
}

///|
fn FakeSrv::content(self : FakeSrv, path : String) -> String {
  let at = self.find_file(path)
  if at < 0 {
    ""
  } else {
    bin_text(self.files[at].1)
  }
}

///|
fn FakeSrv::mtime_of(self : FakeSrv, path : String) -> Int32 {
  let mut i = 0
  while i < self.mtimes.length() {
    if self.mtimes[i].0 == path {
      return self.mtimes[i].1
    }
    i = i + 1
  }
  -1
}

// ------------------------------------------------------- reply builders

///|
fn srv_status(id : Int32, code : Int32, msg : String) -> FixedArray[Byte] {
  // SFTP v3's STATUS carries the code as a **uint32**, not the uint16 the
  // older drafts used.  Measured against this repository's own parser
  // (`src/sftp/parse.mbt`: `let code = c.u32()`); a u16 here parses as
  // `BadLength` and turns every refusal into a protocol error.
  @sftp.sftp_frame(
    bin_cat([
      bin_u8(@sftp.FXP_STATUS),
      bin_u32(id),
      bin_u32(code),
      bin_str(bin_ascii(msg)),
      bin_str(bin_ascii("")),
    ]),
  )
}

///|
fn srv_handle(id : Int32, h : Int32) -> FixedArray[Byte] {
  @sftp.sftp_frame(
    bin_cat([bin_u8(@sftp.FXP_HANDLE), bin_u32(id), bin_str(bin_u32(h))]),
  )
}

///|
fn srv_data(id : Int32, data : FixedArray[Byte]) -> FixedArray[Byte] {
  @sftp.sftp_frame(
    bin_cat([bin_u8(@sftp.FXP_DATA), bin_u32(id), bin_str(data)]),
  )
}

///|
/// An ATTRS block: flags, then the fields those flags allow, in order.
///
/// The order is fixed by the draft -- size, uid/gid, permissions, times --
/// and a server that writes them in another order is what `BadLength` and
/// silently-zero times look like from the client's side.
fn srv_attrs_block(
  is_dir : Bool,
  size : Int64,
  mtime : Int32,
) -> FixedArray[Byte] {
  if is_dir {
    // S_IFDIR | 0755, and the times: the real `sftp-server.exe` reports
    // both for directories, which is what `-p -r` reads back.
    bin_cat([
      bin_u32(@sftp.ATTR_PERMISSIONS | @sftp.ATTR_ACMODTIME),
      bin_u32(0x41ED),
      bin_u32(mtime),
      bin_u32(mtime),
    ])
  } else {
    bin_cat([
      bin_u32(@sftp.ATTR_SIZE | @sftp.ATTR_ACMODTIME),
      bin_u64(size.reinterpret_as_uint64()),
      bin_u32(mtime),
      bin_u32(mtime),
    ])
  }
}

///|
fn srv_attrs(
  id : Int32,
  is_dir : Bool,
  size : Int64,
  mtime : Int32,
) -> FixedArray[Byte] {
  @sftp.sftp_frame(
    bin_cat([
      bin_u8(@sftp.FXP_ATTRS),
      bin_u32(id),
      srv_attrs_block(is_dir, size, mtime),
    ]),
  )
}

///|
fn srv_name_list(
  id : Int32,
  names : Array[String],
  srv : FakeSrv,
  base : String,
) -> FixedArray[Byte] {
  let parts : Array[FixedArray[Byte]] = []
  parts.push(bin_u8(@sftp.FXP_NAME))
  parts.push(bin_u32(id))
  parts.push(bin_u32(names.length()))
  for i = 0; i < names.length(); i = i + 1 {
    let nm = bin_ascii(names[i])
    let child = @scp.remote_join(base, names[i])
    let is_dir = srv.find_dir(child) >= 0
    parts.push(bin_str(nm))
    parts.push(bin_str(nm))
    parts.push(srv_attrs_block(is_dir, 0L, srv.mtime_of(child)))
  }
  @sftp.sftp_frame(bin_cat(parts))
}

// -------------------------------------------------------- the fake peer

///|
/// Answer one framed request, queueing the reply.
fn FakeSrv::serve(self : FakeSrv, frame : FixedArray[Byte]) -> Unit {
  let len = bin_rd_u32(frame, 0)
  let body = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    body[i] = frame[4 + i]
  }
  let kind = body[0].to_int()
  if kind == @sftp.FXP_INIT {
    self.log.push("INIT")
    self.pending.push(
      @sftp.sftp_frame(bin_cat([bin_u8(@sftp.FXP_VERSION), bin_u32(3)])),
    )
    return
  }
  let id = bin_rd_u32(body, 1)
  if kind == @sftp.FXP_REALPATH {
    let (path, _) = bin_rd_str(body, 5)
    self.log.push("REALPATH")
    let abs = bin_cat([bin_ascii("/abs/"), path])
    let nm = bin_cat([abs, bin_ascii("")])
    self.pending.push(
      @sftp.sftp_frame(
        bin_cat([
          bin_u8(@sftp.FXP_NAME),
          bin_u32(id),
          bin_u32(1),
          bin_str(nm),
          bin_str(nm),
          srv_attrs_block(true, 0L, 0),
        ]),
      ),
    )
  } else if kind == @sftp.FXP_STAT || kind == @sftp.FXP_LSTAT {
    let (path, _) = bin_rd_str(body, 5)
    let p = bin_text(path)
    self.log.push("STAT")
    if self.find_dir(p) >= 0 {
      self.pending.push(srv_attrs(id, true, 0L, self.mtime_of(p)))
    } else if self.find_file(p) >= 0 {
      let size = self.files[self.find_file(p)].1.length().to_int64()
      self.pending.push(srv_attrs(id, false, size, self.mtime_of(p)))
    } else {
      self.pending.push(
        srv_status(id, @sftp.FX_NO_SUCH_FILE, "No such file or directory"),
      )
    }
  } else if kind == @sftp.FXP_OPEN {
    let (path, at) = bin_rd_str(body, 5)
    let p = bin_text(path)
    let pflags = bin_rd_u32(body, at)
    self.log.push("OPEN")
    if self.refuse == p {
      self.pending.push(srv_status(id, self.refuse_code, self.refuse_msg))
    } else {
      // Only a WRITE open truncates.  A read-only open that reset the
      // file would make every download read an empty file, which is what
      // this fake did until the download test caught it.
      if (pflags & @sftp.FXF_WRITE) != 0 || self.find_file(p) < 0 {
        self.add_file(p, FixedArray::make(0, b'\x00'))
      }
      let h = self.next_handle
      self.next_handle = self.next_handle + 1
      self.handles.push((h, p))
      self.pending.push(srv_handle(id, h))
    }
  } else if kind == @sftp.FXP_READ {
    let (handle, at) = bin_rd_str(body, 5)
    let h = bin_rd_u32(handle, 0)
    let off = bin_rd_u64(body, at)
    let want = bin_rd_u32(body, at + 8)
    self.log.push("READ")
    let hi = self.find_handle(h)
    if hi < 0 {
      self.pending.push(srv_status(id, @sftp.FX_FAILURE, "Failure"))
    } else {
      let p = self.handles[hi].1
      let fi = self.find_file(p)
      let data = if fi < 0 {
        FixedArray::make(0, b'\x00')
      } else {
        self.files[fi].1
      }
      if off >= data.length().to_uint64() {
        self.pending.push(srv_status(id, @sftp.FX_EOF, "End of file"))
      } else {
        let start = off.to_int()
        let mut end = start + want
        if end > data.length() {
          end = data.length()
        }
        let piece = FixedArray::make(end - start, b'\x00')
        for i = 0; i < piece.length(); i = i + 1 {
          piece[i] = data[start + i]
        }
        self.pending.push(srv_data(id, piece))
      }
    }
  } else if kind == @sftp.FXP_WRITE {
    let (handle, at) = bin_rd_str(body, 5)
    let h = bin_rd_u32(handle, 0)
    let off = bin_rd_u64(body, at)
    let (data, _) = bin_rd_str(body, at + 8)
    self.log.push("WRITE")
    let hi = self.find_handle(h)
    if hi < 0 {
      self.pending.push(srv_status(id, @sftp.FX_FAILURE, "Failure"))
    } else {
      let p = self.handles[hi].1
      let fi = self.find_file(p)
      let old = if fi < 0 {
        FixedArray::make(0, b'\x00')
      } else {
        self.files[fi].1
      }
      let start = off.to_int()
      let need = start + data.length()
      let grown = FixedArray::make(need, b'\x00')
      for i = 0; i < old.length(); i = i + 1 {
        grown[i] = old[i]
      }
      for i = 0; i < data.length(); i = i + 1 {
        grown[start + i] = data[i]
      }
      self.add_file(p, grown)
      self.pending.push(srv_status(id, @sftp.FX_OK, "Success"))
    }
  } else if kind == @sftp.FXP_CLOSE {
    let (handle, _) = bin_rd_str(body, 5)
    let h = bin_rd_u32(handle, 0)
    self.log.push("CLOSE")
    let hi = self.find_handle(h)
    if hi >= 0 {
      let _ = self.handles.remove(hi)
    }
    self.pending.push(srv_status(id, @sftp.FX_OK, "Success"))
  } else if kind == @sftp.FXP_MKDIR {
    let (path, _) = bin_rd_str(body, 5)
    let p = bin_text(path)
    self.log.push("MKDIR")
    if self.refuse == p {
      self.pending.push(srv_status(id, self.refuse_code, self.refuse_msg))
    } else if self.find_file(p) >= 0 {
      // The measured refusal: a path that exists as a file.
      self.pending.push(srv_status(id, @sftp.FX_FAILURE, "Failure"))
    } else {
      self.add_dir(p, [])
      self.pending.push(srv_status(id, @sftp.FX_OK, "Success"))
    }
  } else if kind == @sftp.FXP_OPENDIR {
    let (path, _) = bin_rd_str(body, 5)
    let p = bin_text(path)
    self.log.push("OPENDIR")
    if self.find_dir(p) >= 0 {
      let h = self.next_handle
      self.next_handle = self.next_handle + 1
      self.handles.push((h, p))
      self.pending.push(srv_handle(id, h))
    } else {
      self.pending.push(
        srv_status(id, @sftp.FX_NO_SUCH_FILE, "No such file or directory"),
      )
    }
  } else if kind == @sftp.FXP_READDIR {
    let (handle, _) = bin_rd_str(body, 5)
    let h = bin_rd_u32(handle, 0)
    self.log.push("READDIR")
    let hi = self.find_handle(h)
    let mut done = false
    for i = 0; i < self.served.length(); i = i + 1 {
      if self.served[i] == h {
        done = true
      }
    }
    if hi < 0 {
      self.pending.push(srv_status(id, @sftp.FX_FAILURE, "Failure"))
    } else {
      let p = self.handles[hi].1
      if done {
        self.pending.push(srv_status(id, @sftp.FX_EOF, "End of file"))
      } else {
        self.served.push(h)
        let di = self.find_dir(p)
        let kids = if di < 0 { [] } else { self.dirs[di].1 }
        self.pending.push(srv_name_list(id, kids, self, p))
      }
    }
  } else if kind == @sftp.FXP_SETSTAT {
    let (path, at) = bin_rd_str(body, 5)
    let p = bin_text(path)
    self.log.push("SETSTAT")
    let flags = bin_rd_u32(body, at)
    if (flags & @sftp.ATTR_ACMODTIME) != 0 {
      // size is absent here, so the two times come straight after flags
      let mt = bin_rd_u32(body, at + 4 + 4)
      self.mtimes.push((p, mt))
    }
    self.pending.push(srv_status(id, @sftp.FX_OK, "Success"))
  } else {
    self.log.push("UNKNOWN")
    self.pending.push(
      srv_status(id, @sftp.FX_OP_UNSUPPORTED, "Operation unsupported"),
    )
  }
}

///|
/// A drive wired to `srv`, with the handshake already done.
fn drive_over(srv : FakeSrv) -> @sftpdrive.SftpDrive {
  let write_fn = fn(data : FixedArray[Byte]) -> Bool {
    srv.serve(data)
    true
  }
  let read_fn = fn() -> FixedArray[Byte] {
    if srv.pending.length() == 0 {
      FixedArray::make(0, b'\x00')
    } else {
      srv.pending.remove(0)
    }
  }
  let drive = @sftpdrive.SftpDrive::new(write_fn, read_fn)
  let _ = drive.handshake()
  drive
}

// ---------------------------------------------------------- the fake fs

///|
priv struct FakeFs {
  files : Array[(String, FixedArray[Byte])]
  dirs : Array[(String, Array[String])]
  mtimes : Array[(String, Int64)]
  /// paths whose write refuses
  fail : Array[String]
  /// paths whose mkdir refuses
  fail_mkdir : Array[String]
  mut reason : String
  /// paths written, in order
  writes : Array[String]
}

///|
fn FakeFs::new() -> FakeFs {
  {
    files: [],
    dirs: [],
    mtimes: [],
    fail: [],
    fail_mkdir: [],
    reason: "No such file or directory",
    writes: [],
  }
}

///|
fn FakeFs::find_file(self : FakeFs, path : String) -> Int32 {
  let mut i = 0
  while i < self.files.length() {
    if self.files[i].0 == path {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn FakeFs::find_dir(self : FakeFs, path : String) -> Int32 {
  let mut i = 0
  while i < self.dirs.length() {
    if self.dirs[i].0 == path {
      return i
    }
    i = i + 1
  }
  -1
}

///|
fn FakeFs::add_dir(self : FakeFs, path : String, kids : Array[String]) -> Unit {
  let at = self.find_dir(path)
  if at >= 0 {
    self.dirs[at] = (path, kids)
  } else {
    self.dirs.push((path, kids))
  }
}

///|
fn FakeFs::mtime_of(self : FakeFs, path : String) -> Int64 {
  let mut i = 0
  while i < self.mtimes.length() {
    if self.mtimes[i].0 == path {
      return self.mtimes[i].1
    }
    i = i + 1
  }
  -1L
}

///|
fn FakeFs::content(self : FakeFs, path : String) -> String {
  let at = self.find_file(path)
  if at < 0 {
    ""
  } else {
    bin_text(self.files[at].1)
  }
}

///|
/// The six functions, closing over `state`.
fn fake_local_fs(state : FakeFs) -> @scp.LocalFs {
  let stat_fn = fn(path : String) -> @scp.LocalStat? {
    let d = state.find_dir(path)
    if d >= 0 {
      Some({ is_dir: true, size: 0L, mtime: state.mtime_of(path), })
    } else {
      let f = state.find_file(path)
      if f >= 0 {
        Some({
          is_dir: false,
          size: state.files[f].1.length().to_int64(),
          mtime: state.mtime_of(path),
        })
      } else {
        None
      }
    }
  }
  let read_fn = fn(path : String) -> FixedArray[Byte]? {
    let f = state.find_file(path)
    if f < 0 {
      None
    } else {
      Some(state.files[f].1)
    }
  }
  let write_fn = fn(path : String, data : FixedArray[Byte]) -> String? {
    let mut refuse = false
    for i = 0; i < state.fail.length(); i = i + 1 {
      if state.fail[i] == path {
        refuse = true
      }
    }
    if refuse {
      state.reason = "No such file or directory"
      Some(state.reason)
    } else {
      let at = state.find_file(path)
      if at >= 0 {
        state.files[at] = (path, data)
      } else {
        state.files.push((path, data))
      }
      state.writes.push(path)
      None
    }
  }
  let mkdir_fn = fn(path : String) -> String? {
    let mut refuse = false
    for i = 0; i < state.fail_mkdir.length(); i = i + 1 {
      if state.fail_mkdir[i] == path {
        refuse = true
      }
    }
    if refuse {
      state.reason = "File exists"
      Some("File exists")
    } else {
      state.add_dir(path, [])
      None
    }
  }
  let list_fn = fn(path : String) -> Array[String]? {
    let d = state.find_dir(path)
    if d < 0 {
      None
    } else {
      Some(state.dirs[d].1)
    }
  }
  let set_mtime_fn = fn(path : String, secs : Int64) -> String? {
    state.mtimes.push((path, secs))
    None
  }
  let reason_fn = fn() -> String { state.reason }
  { stat_fn, read_fn, write_fn, mkdir_fn, list_fn, set_mtime_fn, reason_fn, }
}

///|
/// An engine over a fresh fake peer and a fresh fake local tree.
fn bed(srv : FakeSrv, fs : FakeFs) -> @scp.CopyEngine {
  @scp.CopyEngine::new(fake_local_fs(fs), drive_over(srv))
}

// ------------------------------------------------------------- the tests

///|
test "an upload moves the bytes and closes the handle" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  fs.files.push(("local/a.txt", bin_ascii("hello world\n")))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_file("local/a.txt", "srv/out.txt", false, report)
  assert_true(report.lines.length() == 0)
  assert_true(srv.content("srv/out.txt") == "hello world\n")
  // The handle the server handed out was closed again: no leak.
  assert_true(srv.handles.length() == 0)
}

///|
test "a 100 KiB upload moves in 32 KiB requests" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  let size = 100 * 1024
  let body = FixedArray::make(size, b'\x00')
  for i = 0; i < size; i = i + 1 {
    body[i] = (i % 251).to_byte()
  }
  fs.files.push(("local/big.bin", body))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_file("local/big.bin", "srv/big.bin", false, report)
  assert_true(report.lines.length() == 0)
  let got = srv.files[srv.find_file("srv/big.bin")].1
  assert_true(got.length() == size)
  let mut same = true
  for i = 0; i < size; i = i + 1 {
    if got[i] != body[i] {
      same = false
    }
  }
  assert_true(same)
  // Four WRITEs: 32768 * 3 + 4096.
  let mut writes = 0
  for i = 0; i < srv.log.length(); i = i + 1 {
    if srv.log[i] == "WRITE" {
      writes = writes + 1
    }
  }
  assert_eq(writes, 4)
}

///|
test "-p on an upload sets the remote time" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  fs.files.push(("local/p.txt", bin_ascii("data\n")))
  fs.mtimes.push(("local/p.txt", 1000000000L))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_file("local/p.txt", "srv/kept.txt", true, report)
  assert_true(report.lines.length() == 0)
  assert_eq(srv.mtime_of("srv/kept.txt"), 1000000000)
}

///|
test "a refused destination open prints both measured lines" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  fs.files.push(("local/a.txt", bin_ascii("hello\n")))
  srv.refuse = "srv/nodir/out.txt"
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_file("local/a.txt", "srv/nodir/out.txt", false, report)
  assert_eq(report.lines.length(), 2)
  // Measured: dest open "..." first, then the failed-to-upload line.
  assert_true(
    @scp.scp_error_text(report.lines[0]) ==
    "dest open \"srv/nodir/out.txt\": No such file or directory",
  )
  assert_true(
    @scp.scp_error_text(report.lines[1]) ==
    "failed to upload file local/a.txt to srv/nodir/out.txt",
  )
  assert_eq(@scp.scp_exit_code(report.exit()), 1)
}

///|
test "a missing local source is fatal and names the platform's reason" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_file("local/nope.txt", "srv/x.txt", false, report)
  assert_eq(report.lines.length(), 1)
  assert_true(
    @scp.scp_error_text(report.lines[0]) ==
    "stat local \"local/nope.txt\": No such file or directory",
  )
  assert_eq(@scp.scp_exit_code(report.exit()), 255)
  assert_true(report.fatal)
}

///|
test "a tree upload creates the directory and keeps the children's names" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  fs.add_dir("local/t", ["x.txt", "sub"])
  fs.add_dir("local/t\\sub", ["y.txt"])
  fs.files.push(("local/t\\x.txt", bin_ascii("x\n")))
  fs.files.push(("local/t\\sub\\y.txt", bin_ascii("y\n")))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_tree("local/t", "srv/upload", false, report)
  assert_true(report.lines.length() == 0)
  assert_true(srv.content("srv/upload/x.txt") == "x\n")
  assert_true(srv.content("srv/upload/sub/y.txt") == "y\n")
}

///|
test "a refused remote mkdir is fatal and stops the walk" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  fs.add_dir("local/t", ["x.txt"])
  fs.files.push(("local/t\\x.txt", bin_ascii("x\n")))
  // The measured case: the target exists as a FILE, so the server answers
  // SSH_FX_FAILURE with its own text.
  srv.add_file("srv/afile", bin_ascii("in the way\n"))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_tree("local/t", "srv/afile", false, report)
  assert_eq(report.lines.length(), 1)
  assert_true(
    @scp.scp_error_text(report.lines[0]) ==
    "remote mkdir \"srv/afile\": Failure",
  )
  assert_eq(@scp.scp_exit_code(report.exit()), 255)
  // Nothing was copied into it, and nothing was opened.
  assert_true(srv.find_file("srv/afile/x.txt") < 0)
  let mut opened = false
  for i = 0; i < srv.log.length(); i = i + 1 {
    if srv.log[i] == "OPEN" {
      opened = true
    }
  }
  assert_true(!opened)
}

///|
test "-p -r sets a directory's time after its children" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  fs.add_dir("local/t", ["x.txt", "sub"])
  fs.add_dir("local/t\\sub", ["y.txt"])
  fs.files.push(("local/t\\x.txt", bin_ascii("x\n")))
  fs.files.push(("local/t\\sub\\y.txt", bin_ascii("y\n")))
  fs.mtimes.push(("local/t", 1000000002L))
  fs.mtimes.push(("local/t\\sub", 1000000003L))
  fs.mtimes.push(("local/t\\x.txt", 1000000000L))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.upload_tree("local/t", "srv/up", true, report)
  assert_true(report.lines.length() == 0)
  // The measured values: directories keep their own times, and the
  // parent's is written last so a child's write cannot move it.
  assert_eq(srv.mtime_of("srv/up"), 1000000002)
  assert_eq(srv.mtime_of("srv/up/sub"), 1000000003)
  assert_eq(srv.mtime_of("srv/up/x.txt"), 1000000000)
  let last = srv.log[srv.log.length() - 1]
  assert_true(last == "SETSTAT")
  // And the very last SETSTAT is the top directory's.
  assert_eq(srv.mtimes[srv.mtimes.length() - 1].1, 1000000002)
}

///|
test "a download writes the local file" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  srv.add_file("srv/in.txt", bin_ascii("downloaded\n"))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.download_file(
    "srv/in.txt", "/abs/srv/in.txt", "local/got.txt", false, false, report,
  )
  assert_true(report.lines.length() == 0)
  assert_true(fs.content("local/got.txt") == "downloaded\n")
}

///|
test "an empty remote file becomes an empty local file" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  srv.add_file("srv/empty.txt", FixedArray::make(0, b'\x00'))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.download_file(
    "srv/empty.txt", "/abs/srv/empty.txt", "local/empty.txt", false, false, report,
  )
  assert_true(report.lines.length() == 0)
  let at = fs.find_file("local/empty.txt")
  assert_true(at >= 0)
  assert_eq(fs.files[at].1.length(), 0)
}

///|
test "a top-level download failure prints one line, not two" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  srv.add_file("srv/a.txt", bin_ascii("hello\n"))
  fs.fail.push("local/nodir/out.txt")
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.download_file(
    "srv/a.txt", "/abs/srv/a.txt", "local/nodir/out.txt", false, false, report,
  )
  // Measured round 6 scenario 13: `open local` and nothing else.
  assert_eq(report.lines.length(), 1)
  assert_true(
    @scp.scp_error_text(report.lines[0]) ==
    "open local \"local/nodir/out.txt\": No such file or directory",
  )
  assert_eq(@scp.scp_exit_code(report.exit()), 1)
}

///|
test "a failure inside a walk prints two lines per child and keeps going" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  srv.add_dir("srv/dt", ["a.txt", "b.txt", "c.txt"])
  srv.add_file("srv/dt/a.txt", bin_ascii("a\n"))
  srv.add_file("srv/dt/b.txt", bin_ascii("b\n"))
  srv.add_file("srv/dt/c.txt", bin_ascii("c\n"))
  // The destination is a file, so every child's write fails -- measured
  // round 7 scenario 26.
  fs.files.push(("local/blocker", bin_ascii("in the way\n")))
  fs.fail.push("local/blocker\\a.txt")
  fs.fail.push("local/blocker\\b.txt")
  fs.fail.push("local/blocker\\c.txt")
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.download_tree("srv/dt", "local/blocker", false, report)
  assert_eq(report.lines.length(), 6)
  // The absolute half of the second line is the server's, not ours.
  assert_true(
    @scp.scp_error_text(report.lines[1]) ==
    "Download of file /abs/srv/dt/a.txt to local/blocker\\a.txt failed",
  )
  assert_true(
    @scp.scp_error_text(report.lines[5]) ==
    "Download of file /abs/srv/dt/c.txt to local/blocker\\c.txt failed",
  )
  assert_eq(@scp.scp_exit_code(report.exit()), 1)
}

///|
test "-p -r download sets the local directory time after its children" {
  let srv = FakeSrv::new()
  let fs = FakeFs::new()
  srv.add_dir("srv/t", ["x.txt"])
  srv.mtimes.push(("srv/t", 1000000002))
  srv.add_file("srv/t/x.txt", bin_ascii("x\n"))
  srv.mtimes.push(("srv/t/x.txt", 1000000000))
  let eng = bed(srv, fs)
  let report = @scp.ScpReport::new()
  eng.download_tree("srv/t", "local/dl", true, report)
  assert_true(report.lines.length() == 0)
  assert_eq(fs.mtime_of("local/dl"), 1000000002L)
  assert_eq(fs.mtime_of("local/dl\\x.txt"), 1000000000L)
}

///|
test "the report's exit is fatal if any line is fatal" {
  let report = @scp.ScpReport::new()
  report.push(OpenLocal("x", "No such file or directory"))
  assert_eq(@scp.scp_exit_code(report.exit()), 1)
  report.push(RemoteMkdir("y", "Failure"))
  assert_eq(@scp.scp_exit_code(report.exit()), 255)
  assert_true(report.fatal)
}

///|
test "a local join keeps exactly one separator" {
  assert_true(@scp.local_join("a", "b") == "a\\b")
  assert_true(@scp.local_join("a\\", "b") == "a\\b")
  assert_true(@scp.local_join("a/", "b") == "a/b")
  assert_true(@scp.local_join("", "b") == "b")
}
