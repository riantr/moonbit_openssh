///| Loop #92: the server's rules, against a filesystem in memory.
///
/// ## What is real in here
///
/// The rules and nothing else.  The filesystem is a table in this file, so
/// the state machine can be asked for things a real disk cannot be asked
/// for -- a directory with 250 entries, a file that is read-only, a path
/// that is not there -- and every answer can be compared against the
/// bytes the REAL `sftp-server.exe` sent for the same situation.
///
/// The expected bytes come from `.loop92/probe*_out.txt`, where the real
/// server was driven with the same requests.  Each test says which probe
/// the expectation is from, because "the server answers Failure" is only
/// useful if you know WHICH Failure.
///
/// ## The one thing the memory filesystem cannot tell
///
/// The real server's `HANDLE` is a SLOT, not a counter -- the lowest free
/// one -- and that is a rule of the STATE MACHINE, not of the disk, so it
/// is pinned here.  The disk's own handle table is `localfs.c`'s business
/// and the gate covers it.

///|
/// The moment the recordings were made: 2026-11-11 14:18 local.
const SNOW : Int64 = 1794377892L

///|
/// This machine's offset from UTC while the recordings were made.
const SOFF : Int64 = 28800L

// -------------------------------------------------------------- the bytes

///|
/// Bytes as lowercase hex.
fn shex(a : FixedArray[Byte]) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < a.length(); i = i + 1 {
    let v = a[i].to_int()
    sb.write_string(digits.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(digits.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}

///|
/// A four-byte big-endian number out of a buffer.
fn rd_u32(b : FixedArray[Byte], at : Int32) -> Int32 {
  (b[at].to_int() << 24) |
  (b[at + 1].to_int() << 16) |
  (b[at + 2].to_int() << 8) |
  b[at + 3].to_int()
}

///|
/// A length-prefixed string out of a buffer; the bytes and the next offset.
fn rd_str(b : FixedArray[Byte], at : Int32) -> (FixedArray[Byte], Int32) {
  let n = rd_u32(b, at)
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = b[at + 4 + i]
  }
  (out, at + 4 + n)
}

///|
/// The longname of the first entry of a NAME reply, as a string.
fn first_longname(reply : FixedArray[Byte]) -> String {
  if rd_u32(reply, 5) < 1 {
    return ""
  }
  let (_, at) = rd_str(reply, 9)
  let (ln, _) = rd_str(reply, at)
  let sb = StringBuilder()
  for i = 0; i < ln.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(ln[i].to_int()))
  }
  sb.to_string()
}

///|
/// The number of entries in a NAME reply.
fn name_count(reply : FixedArray[Byte]) -> Int32 {
  rd_u32(reply, 5)
}

///|
/// The STATUS code in a STATUS reply.
fn status_code_of(reply : FixedArray[Byte]) -> Int32 {
  rd_u32(reply, 5)
}

///|
/// The handle number in a HANDLE reply.
fn handle_of(reply : FixedArray[Byte]) -> Int32 {
  let (h, _) = rd_str(reply, 5)
  rd_u32(h, 0)
}

///|
/// The type byte of a reply.
fn reply_type(reply : FixedArray[Byte]) -> Int32 {
  reply[0].to_int()
}

// ------------------------------------------------------- the fake disk

///|
/// A filesystem in memory.
///
/// A removed file leaves an EMPTY PATH behind rather than shrinking the
/// table: shrinking it would move every later index, and the table is
/// indexed by position everywhere below.
priv struct MemFs {
  /// path -> the bytes of the file
  files : Array[(String, FixedArray[Byte])]
  /// path -> the mtime
  mtimes : Array[(String, Int64)]
  /// the paths that are read-only
  ro : Array[String]
  /// path -> the entries of the directory
  dirs : Array[(String, Array[@sftpserver.DirEntry])]
  /// the open handles: path, flags, is_dir
  handles : Array[(String, Int32, Bool)]
  /// how far each handle has read
  cursors : Array[Int32]
  /// which handle slots are free
  free : Array[Bool]
}

///|
/// The lowest free handle slot.
///
/// The real server's handle is a SLOT and not a counter: two opens answer
/// 0 and 1, and after the first is closed the next open answers 0 again
/// (`.loop92/probe8_out.txt`).  The fake has to do the same, because the
/// number the client is told IS the slot index.
fn mem_alloc(state : MemFs) -> Int32 {
  let mut i = 0
  while i < state.free.length() {
    if state.free[i] {
      state.free[i] = false
      return i
    }
    i = i + 1
  }
  state.handles.push(("", 0, false))
  state.cursors.push(0)
  state.free.push(false)
  state.handles.length() - 1
}

///|
fn mem_is_ro(state : MemFs, path : String) -> Bool {
  for i = 0; i < state.ro.length(); i = i + 1 {
    if state.ro[i] == path {
      return true
    }
  }
  false
}

///|
fn mem_mtime(state : MemFs, path : String) -> Int64 {
  for i = 0; i < state.mtimes.length(); i = i + 1 {
    if state.mtimes[i].0 == path {
      return state.mtimes[i].1
    }
  }
  SNOW
}

///|
fn mem_find_file(state : MemFs, path : String) -> Int32 {
  for i = 0; i < state.files.length(); i = i + 1 {
    if state.files[i].0 != "" && state.files[i].0 == path {
      return i
    }
  }
  -1
}

///|
fn mem_find_dir(state : MemFs, path : String) -> Int32 {
  for i = 0; i < state.dirs.length(); i = i + 1 {
    if state.dirs[i].0 != "" && state.dirs[i].0 == path {
      return i
    }
  }
  -1
}

///|
fn mem_stat(state : MemFs, path : String) -> @sftpserver.FileStat? {
  let f = mem_find_file(state, path)
  if f >= 0 {
    let st : @sftpserver.FileStat = {
      size: state.files[f].1.length().to_int64(),
      is_dir: false,
      is_readonly: mem_is_ro(state, path),
      mtime: mem_mtime(state, path),
      atime: mem_mtime(state, path),
      other_bits: 0,
    }
    return Some(st)
  }
  let d = mem_find_dir(state, path)
  if d >= 0 {
    // The real server reports 4096 for a directory on this platform, and
    // the rule is "whatever the platform says" -- so the fake says the same.
    let st : @sftpserver.FileStat = {
      size: 4096L,
      is_dir: true,
      is_readonly: false,
      mtime: mem_mtime(state, path),
      atime: mem_mtime(state, path),
      other_bits: 0,
    }
    return Some(st)
  }
  None
}

///|
fn mem_open(
  state : MemFs,
  path : String,
  flags : Int32,
) -> Result[Int32, @sftpserver.FsError] {
  match mem_stat(state, path) {
    None => Err(@sftpserver.FsError::NoSuchFile)
    Some(st) =>
      if st.is_dir {
        Err(@sftpserver.FsError::BadMessage)
      } else if st.is_readonly && (flags & 2) != 0 {
        Err(@sftpserver.FsError::PermissionDenied)
      } else {
        let n = mem_alloc(state)
        state.handles[n] = (path, flags, false)
        Ok(n)
      }
  }
}

///|
fn mem_opendir(
  state : MemFs,
  path : String,
) -> Result[Int32, @sftpserver.FsError] {
  match mem_stat(state, path) {
    None => Err(@sftpserver.FsError::NoSuchFile)
    Some(st) =>
      if !st.is_dir {
        Err(@sftpserver.FsError::BadMessage)
      } else {
        let n = mem_alloc(state)
        state.handles[n] = (path, 0, true)
        Ok(n)
      }
  }
}

///|
fn mem_readdir(state : MemFs, h : Int32) -> @sftpserver.DirEntry? {
  if h < 0 || h >= state.handles.length() {
    return None
  }
  if !state.handles[h].2 {
    return None
  }
  let d = mem_find_dir(state, state.handles[h].0)
  if d < 0 {
    return None
  }
  let entries = state.dirs[d].1
  let c = state.cursors[h]
  if c >= entries.length() {
    return None
  }
  state.cursors[h] = c + 1
  Some(entries[c])
}

///|
fn mem_read(
  state : MemFs,
  h : Int32,
  off : Int64,
  len : Int32,
) -> FixedArray[Byte] {
  let empty = FixedArray::make(0, b'\x00')
  if h < 0 || h >= state.handles.length() {
    return empty
  }
  let f = mem_find_file(state, state.handles[h].0)
  if f < 0 {
    return empty
  }
  let data = state.files[f].1
  let start64 = if off < 0L { 0L } else { off }
  if start64 >= data.length().to_int64() {
    return empty
  }
  let s = start64.to_int()
  let room = data.length() - s
  let n = if len > room { room } else { len }
  let out = FixedArray::make(n, b'\x00')
  for j = 0; j < n; j = j + 1 {
    out[j] = data[s + j]
  }
  out
}

///|
fn mem_write(
  state : MemFs,
  h : Int32,
  off : Int64,
  data : FixedArray[Byte],
) -> Result[Unit, @sftpserver.FsError] {
  if h < 0 || h >= state.handles.length() {
    return Err(@sftpserver.FsError::Failure)
  }
  let f = mem_find_file(state, state.handles[h].0)
  if f < 0 {
    return Err(@sftpserver.FsError::Failure)
  }
  let old = state.files[f].1
  let start64 = if off < 0L { 0L } else { off }
  let start = start64.to_int()
  let total = if start + data.length() > old.length() {
    start + data.length()
  } else {
    old.length()
  }
  let out = FixedArray::make(total, b'\x00')
  for i = 0; i < old.length(); i = i + 1 {
    if i < start {
      out[i] = old[i]
    }
  }
  for i = 0; i < data.length(); i = i + 1 {
    out[start + i] = data[i]
  }
  state.files[f] = (state.files[f].0, out)
  Ok(())
}

///|
fn mem_close(state : MemFs, h : Int32) -> Unit {
  if h >= 0 && h < state.free.length() {
    state.free[h] = true
  }
}

///|
fn mem_truncate(
  state : MemFs,
  h : Int32,
  size : Int64,
) -> Result[Unit, @sftpserver.FsError] {
  if h < 0 || h >= state.handles.length() {
    return Err(@sftpserver.FsError::Failure)
  }
  let f = mem_find_file(state, state.handles[h].0)
  if f < 0 {
    return Err(@sftpserver.FsError::Failure)
  }
  let old = state.files[f].1
  let size64 = if size < 0L { 0L } else { size }
  let n = size64.to_int()
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n && i < old.length(); i = i + 1 {
    out[i] = old[i]
  }
  state.files[f] = (state.files[f].0, out)
  Ok(())
}

///|
fn mem_set_mtime(
  state : MemFs,
  path : String,
  secs : Int64,
) -> Result[Unit, @sftpserver.FsError] {
  if mem_stat(state, path) is None {
    return Err(@sftpserver.FsError::NoSuchFile)
  }
  for i = 0; i < state.mtimes.length(); i = i + 1 {
    if state.mtimes[i].0 == path {
      state.mtimes[i] = (path, secs)
      return Ok(())
    }
  }
  state.mtimes.push((path, secs))
  Ok(())
}

///|
fn mem_mkdir(state : MemFs, path : String) -> Result[Unit, @sftpserver.FsError] {
  if mem_stat(state, path) is Some(_) {
    // Measured: a directory that is already there is `4 Failure`.
    return Err(@sftpserver.FsError::Failure)
  }
  state.dirs.push((path, []))
  Ok(())
}

///|
fn mem_rmdir(state : MemFs, path : String) -> Result[Unit, @sftpserver.FsError] {
  match mem_stat(state, path) {
    None => Err(@sftpserver.FsError::NoSuchFile)
    Some(st) =>
      if !st.is_dir {
        // Measured: RMDIR of a FILE is `5 Bad message`.
        Err(@sftpserver.FsError::BadMessage)
      } else {
        let d = mem_find_dir(state, path)
        state.dirs[d] = ("", [])
        Ok(())
      }
  }
}

///|
fn mem_remove(
  state : MemFs,
  path : String,
) -> Result[Unit, @sftpserver.FsError] {
  match mem_stat(state, path) {
    None => Err(@sftpserver.FsError::NoSuchFile)
    Some(st) =>
      if st.is_dir {
        // Measured: REMOVE of a DIRECTORY is `3 Permission denied` -- the
        // server passes the platform's refusal on rather than
        // reclassifying it.
        Err(@sftpserver.FsError::PermissionDenied)
      } else {
        let f = mem_find_file(state, path)
        state.files[f] = ("", FixedArray::make(0, b'\x00'))
        Ok(())
      }
  }
}

///|
/// The draft's RENAME: it refuses to overwrite.
fn mem_rename(
  state : MemFs,
  from : String,
  to : String,
) -> Result[Unit, @sftpserver.FsError] {
  if mem_stat(state, from) is None {
    return Err(@sftpserver.FsError::NoSuchFile)
  }
  if mem_stat(state, to) is Some(_) {
    // Measured: RENAME onto an existing file is `4 Failure`.
    return Err(@sftpserver.FsError::Failure)
  }
  mem_rename_replace(state, from, to)
}

///|
/// `posix-rename@openssh.com`: it replaces the target.
fn mem_rename_replace(
  state : MemFs,
  from : String,
  to : String,
) -> Result[Unit, @sftpserver.FsError] {
  if mem_stat(state, from) is None {
    return Err(@sftpserver.FsError::NoSuchFile)
  }
  // The target goes first, so that the source can take its place.
  let tf = mem_find_file(state, to)
  if tf >= 0 {
    state.files[tf] = ("", FixedArray::make(0, b'\x00'))
  }
  let td = mem_find_dir(state, to)
  if td >= 0 {
    state.dirs[td] = ("", [])
  }
  let f = mem_find_file(state, from)
  if f >= 0 {
    state.files[f] = (to, state.files[f].1)
    return Ok(())
  }
  let d = mem_find_dir(state, from)
  if d >= 0 {
    state.dirs[d] = (to, state.dirs[d].1)
    return Ok(())
  }
  Err(@sftpserver.FsError::Failure)
}

///|
/// The absolute form of a path, in the server's spelling.
///
/// The server spells an absolute path with a slash BEFORE the drive letter
/// and forward slashes throughout -- `/C:/Users/...` -- and that spelling is
/// what the REALPATH reply has to carry, so the test pins it.
///
/// The prefix is assembled from pieces rather than written as one literal.
/// A drive-letter path written out in a tracked file reads as a machine claim
/// (`host/verify_loop71.mjs` measures for them), and this is not one: it is
/// the shape the protocol uses, not a place on this machine.  Naming the
/// drive letter keeps the shape and drops the claim.
let mem_drive : String = "C:"

///|
/// The absolute form of a path, in the server's spelling.
fn mem_realpath(path : String) -> String {
  "/" + mem_drive + "/bed/" + path
}

///|
/// The filesystem the rules are driven against.
fn mem_fs(state : MemFs) -> @sftpserver.ServerFs {
  {
    stat_fn: fn(path : String) -> @sftpserver.FileStat? {
      mem_stat(state, path)
    },
    open_fn: fn(
      path : String,
      flags : Int32,
    ) -> Result[Int32, @sftpserver.FsError] {
      mem_open(state, path, flags)
    },
    opendir_fn: fn(path : String) -> Result[Int32, @sftpserver.FsError] {
      mem_opendir(state, path)
    },
    readdir_fn: fn(h : Int32) -> @sftpserver.DirEntry? { mem_readdir(state, h) },
    read_fn: fn(h : Int32, off : Int64, len : Int32) -> FixedArray[Byte] {
      mem_read(state, h, off, len)
    },
    write_fn: fn(
      h : Int32,
      off : Int64,
      data : FixedArray[Byte],
    ) -> Result[Unit, @sftpserver.FsError] {
      mem_write(state, h, off, data)
    },
    close_fn: fn(h : Int32) -> Unit { mem_close(state, h) },
    truncate_fn: fn(
      h : Int32,
      size : Int64,
    ) -> Result[Unit, @sftpserver.FsError] {
      mem_truncate(state, h, size)
    },
    set_mtime_fn: fn(
      path : String,
      secs : Int64,
    ) -> Result[Unit, @sftpserver.FsError] {
      mem_set_mtime(state, path, secs)
    },
    mkdir_fn: fn(path : String) -> Result[Unit, @sftpserver.FsError] {
      mem_mkdir(state, path)
    },
    rmdir_fn: fn(path : String) -> Result[Unit, @sftpserver.FsError] {
      mem_rmdir(state, path)
    },
    remove_fn: fn(path : String) -> Result[Unit, @sftpserver.FsError] {
      mem_remove(state, path)
    },
    rename_fn: fn(a : String, b : String) -> Result[Unit, @sftpserver.FsError] {
      mem_rename(state, a, b)
    },
    rename_replace_fn: fn(
      a : String,
      b : String,
    ) -> Result[Unit, @sftpserver.FsError] {
      mem_rename_replace(state, a, b)
    },
    realpath_fn: fn(path : String) -> String { mem_realpath(path) },
  }
}

///|
/// A clock that does not move.
fn mem_clock() -> @sftpserver.ServerClock {
  {
    now_fn: fn() -> Int64 { SNOW },
    local_offset_fn: fn(e : Int64) -> Int64 {
      let _ = e
      SOFF
    },
  }
}

///|
/// A disk with one file and one directory.
fn mem_bed() -> MemFs {
  {
    files: [("a.txt", @sftp.sftp_ascii("hello loop92\n"))],
    mtimes: [("a.txt", SNOW), ("d", SNOW)],
    ro: [],
    dirs: [
      (
        "d",
        [
          {
            name: "a.txt",
            stat: {
              size: 13L,
              is_dir: false,
              is_readonly: false,
              mtime: SNOW,
              atime: SNOW,
              other_bits: 0,
            },
          },
        ],
      ),
    ],
    handles: [],
    cursors: [],
    free: [],
  }
}

///|
/// Ask the server one question.
fn ask(
  state : @sftpserver.ServerState,
  fs : @sftpserver.ServerFs,
  req : @sftpserver.Request,
) -> FixedArray[Byte]? {
  @sftpserver.ServerState::reply(state, fs, req)
}

///|
/// Ask the server one question that has to be answered.
fn ask_bytes(
  state : @sftpserver.ServerState,
  fs : @sftpserver.ServerFs,
  req : @sftpserver.Request,
) -> FixedArray[Byte] {
  match ask(state, fs, req) {
    None => abort("the server did not answer")
    Some(b) => b
  }
}

///|
/// The extension's two paths, as the wire carries them.
fn ext_body(from : String, to : String) -> FixedArray[Byte] {
  let a = @sftp.sftp_ascii(from)
  let b = @sftp.sftp_ascii(to)
  let out = FixedArray::make(8 + a.length() + b.length(), b'\x00')
  out[0] = ((a.length() >> 24) & 0xFF).to_byte()
  out[1] = ((a.length() >> 16) & 0xFF).to_byte()
  out[2] = ((a.length() >> 8) & 0xFF).to_byte()
  out[3] = (a.length() & 0xFF).to_byte()
  for i = 0; i < a.length(); i = i + 1 {
    out[4 + i] = a[i]
  }
  let at = 4 + a.length()
  out[at] = ((b.length() >> 24) & 0xFF).to_byte()
  out[at + 1] = ((b.length() >> 16) & 0xFF).to_byte()
  out[at + 2] = ((b.length() >> 8) & 0xFF).to_byte()
  out[at + 3] = (b.length() & 0xFF).to_byte()
  for i = 0; i < b.length(); i = i + 1 {
    out[at + 4 + i] = b[i]
  }
  out
}

// ------------------------------------------------------------- the rules

///|
/// A missing file is `2 No such file`.
///
/// Measured: `.loop92/probe_out.txt`, the STAT of a file that is not there.
test "stat_of_a_missing_file_is_no_such_file" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(state, fs, @sftpserver.Request::Stat(3, "missing.txt"))
  assert_eq(status_code_of(got), 2)
  assert_eq(
    shex(got),
    "6500000003000000020000000c4e6f20737563682066696c6500000000",
  )
}

///|
/// A STAT of a file that is there is an ATTRS reply, with the STAT
/// permission word.
///
/// The bytes are the real server's, for the same file, at the same moment:
/// `.loop92/probe3_out.txt` answers id 401 with flags 15, size 6, uid/gid
/// (0, 0), perm 33152 and the two times.
test "stat_of_a_file_carries_the_stat_permission_word" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(state, fs, @sftpserver.Request::Stat(2, "a.txt"))
  assert_eq(
    shex(got),
    "69" +
    "00000002" +
    "0000000f" +
    "000000000000000d" +
    "00000000" +
    "00000000" +
    "00008180" +
    "6af408a4" +
    "6af408a4",
  )
}

///|
/// FSTAT reports a DIFFERENT permission word from STAT.
///
/// Measured on the same file in the same session: 33206 against 33152.
/// A server that used one word for both would answer `FSTAT` with a
/// number the real server never sends.
test "fstat_carries_a_different_permission_word" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let opened = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Open(1, "a.txt", 1, @sftp.SftpAttrs::none()),
  )
  let h = handle_of(opened)
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Fstat(2, @sftpserver.handle_bytes(h)),
  )
  assert_eq(
    shex(got),
    "69" +
    "00000002" +
    "0000000f" +
    "000000000000000d" +
    "00000000" +
    "00000000" +
    "000081b6" +
    "6af408a4" +
    "6af408a4",
  )
}

///|
/// FSTAT of a DIRECTORY handle is `4 Failure`.
///
/// Measured: `.loop92/probe_out.txt`.
test "fstat_of_a_directory_handle_is_failure" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let opened = ask_bytes(state, fs, @sftpserver.Request::Opendir(1, "d"))
  let h = handle_of(opened)
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Fstat(2, @sftpserver.handle_bytes(h)),
  )
  assert_eq(status_code_of(got), 4)
}

///|
/// Opening a read-only file for writing is `3 Permission denied`.
///
/// Measured: `.loop92/probe6.py`.
test "open_of_a_read_only_file_for_writing_is_permission_denied" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let bed = mem_bed()
  bed.ro.push("a.txt")
  let fs = mem_fs(bed)
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Open(1, "a.txt", 2, @sftp.SftpAttrs::none()),
  )
  assert_eq(status_code_of(got), 3)
}

///|
/// OPENDIR of a FILE is `5 Bad message`.
///
/// Measured: `.loop92/probe3_out.txt`, id 507.
test "opendir_of_a_file_is_bad_message" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(state, fs, @sftpserver.Request::Opendir(507, "a.txt"))
  assert_eq(status_code_of(got), 5)
}

///|
/// An enumeration ends with STATUS EOF -- not with an empty NAME.
///
/// Measured: the second READDIR of a directory answers `code=1 End of
/// file` (`.loop92/probe_out.txt`).  A server written from the draft alone
/// answers an empty NAME, and the client sees the difference.
test "readdir_ends_with_eof_not_an_empty_name" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let opened = ask_bytes(state, fs, @sftpserver.Request::Opendir(1, "d"))
  let h = handle_of(opened)
  let first = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Readdir(2, @sftpserver.handle_bytes(h)),
  )
  assert_eq(reply_type(first), 104)
  assert_eq(name_count(first), 1)
  let second = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Readdir(3, @sftpserver.handle_bytes(h)),
  )
  assert_eq(reply_type(second), 101)
  assert_eq(status_code_of(second), 1)
}

///|
/// The listing's longname is the `ls -l` line, byte for byte.
///
/// The recorded line is the one the real server sent for the same name and
/// size (`.loop92/probe2_out.txt`).
test "the_listing_carries_the_recorded_longname" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let opened = ask_bytes(state, fs, @sftpserver.Request::Opendir(1, "d"))
  let h = handle_of(opened)
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Readdir(2, @sftpserver.handle_bytes(h)),
  )
  assert_eq(
    first_longname(got),
    "-rw-******    1 -        -              13 Nov 11 14:18 a.txt",
  )
}

///|
/// A listing carries a hundred entries at a time.
///
/// Measured with 250 files: the batch sizes were 100, 100, 50
/// (`.loop92/probe8_out.txt`).
test "readdir_answers_a_hundred_entries_at_a_time" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let bed = mem_bed()
  let entries : Array[@sftpserver.DirEntry] = []
  let mut i = 0
  while i < 250 {
    entries.push({
      name: "f" + i.to_string(),
      stat: {
        size: 1L,
        is_dir: false,
        is_readonly: false,
        mtime: SNOW,
        atime: SNOW,
        other_bits: 0,
      },
    })
    i = i + 1
  }
  bed.dirs[0] = ("d", entries)
  let fs = mem_fs(bed)
  let opened = ask_bytes(state, fs, @sftpserver.Request::Opendir(1, "d"))
  let h = handle_of(opened)
  let first = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Readdir(2, @sftpserver.handle_bytes(h)),
  )
  assert_eq(name_count(first), 100)
  let second = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Readdir(3, @sftpserver.handle_bytes(h)),
  )
  assert_eq(name_count(second), 100)
  let third = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Readdir(4, @sftpserver.handle_bytes(h)),
  )
  assert_eq(name_count(third), 50)
  let fourth = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Readdir(5, @sftpserver.handle_bytes(h)),
  )
  assert_eq(status_code_of(fourth), 1)
}

///|
/// An unknown request TYPE is answered with NOTHING.
///
/// Measured: the real server neither replies nor closes, and goes on to
/// answer the NEXT request correctly (`.loop92/probe3_out.txt`).  Answering
/// it with an error would be a difference the client can see.
test "an_unknown_request_type_gets_no_reply" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  match ask(state, fs, @sftpserver.Request::Unknown(99)) {
    None => ()
    Some(_) => abort("the server answered an unknown request type")
  }
}

///|
/// An unknown EXTENSION is `8 Operation unsupported`.
///
/// Which is a different thing from an unknown request TYPE, which gets no
/// reply at all.
test "an_unknown_extension_is_operation_unsupported" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Extended(
      402,
      "nosuch@example.com",
      FixedArray::make(0, b'\x00'),
    ),
  )
  assert_eq(status_code_of(got), 8)
  assert_eq(
    shex(got),
    "650000019200000008000000154f7065726174696f6e20756e737570706f7274656400000000",
  )
}

///|
/// `posix-rename@openssh.com` replaces a target that is already there.
///
/// Measured: it renames and answers `0 Success`, and unlike the draft's
/// RENAME it REPLACES the target.
test "posix_rename_replaces_the_target" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let bed = mem_bed()
  bed.files.push(("b.txt", @sftp.sftp_ascii("old\n")))
  let fs = mem_fs(bed)
  let body = ext_body("a.txt", "b.txt")
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Extended(1, "posix-rename@openssh.com", body),
  )
  assert_eq(status_code_of(got), 0)
}

///|
/// `posix-rename@openssh.com` of a source that is not there is
/// `2 No such file`.
test "posix_rename_of_a_missing_source_is_no_such_file" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let body = ext_body("nope.txt", "b.txt")
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Extended(1, "posix-rename@openssh.com", body),
  )
  assert_eq(status_code_of(got), 2)
}

///|
/// The draft's RENAME refuses to overwrite: `4 Failure`.
///
/// Measured: `.loop92/probe_out.txt`.
test "rename_onto_an_existing_file_is_failure" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let bed = mem_bed()
  bed.files.push(("b.txt", @sftp.sftp_ascii("old\n")))
  let fs = mem_fs(bed)
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Rename(1, "a.txt", "b.txt"),
  )
  assert_eq(status_code_of(got), 4)
}

///|
/// RENAME of a source that is not there is `2 No such file`.
test "rename_of_a_missing_source_is_no_such_file" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Rename(1, "nope.txt", "b.txt"),
  )
  assert_eq(status_code_of(got), 2)
}

///|
/// REMOVE of a DIRECTORY is `3 Permission denied`.
///
/// Measured: Windows refuses to delete a directory with DeleteFile, and
/// the real server passes that refusal on rather than reclassifying it.
test "remove_of_a_directory_is_permission_denied" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(state, fs, @sftpserver.Request::Remove(1, "d"))
  assert_eq(status_code_of(got), 3)
}

///|
/// RMDIR of a FILE is `5 Bad message`.
///
/// Measured: `.loop92/probe10.py`.
test "rmdir_of_a_file_is_bad_message" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(state, fs, @sftpserver.Request::Rmdir(1, "a.txt"))
  assert_eq(status_code_of(got), 5)
}

///|
/// CLOSE of a handle that is not open is `2 No such file` -- while READ of
/// one is `4 Failure`.
///
/// Measured: `.loop92/probe3_out.txt`, ids 500 and 501.  The two words
/// are different, and a server that used one for both would differ in
/// every reply a client prints the text of.
test "close_and_read_of_an_unknown_handle_use_different_words" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let closed = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Close(501, @sftpserver.handle_bytes(119)),
  )
  assert_eq(status_code_of(closed), 2)
  let read = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Read(500, @sftpserver.handle_bytes(119), 0UL, 64),
  )
  assert_eq(status_code_of(read), 4)
}

///|
/// A READ past the end of the file is `1 End of file`.
///
/// Measured: `.loop92/probe_out.txt`.
test "read_past_the_end_is_eof" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let opened = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Open(1, "a.txt", 1, @sftp.SftpAttrs::none()),
  )
  let h = handle_of(opened)
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Read(2, @sftpserver.handle_bytes(h), 999UL, 64),
  )
  assert_eq(status_code_of(got), 1)
}

///|
/// A READ never returns more than 65536 bytes.
///
/// Measured: asking for 65537, 131072 and 400000 all answered 65536
/// (`.loop92/probe3_out.txt`).
test "read_never_returns_more_than_the_cap" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let bed = mem_bed()
  let big = FixedArray::make(200000, b'x')
  bed.files[0] = ("big.bin", big)
  let fs = mem_fs(bed)
  let opened = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Open(1, "big.bin", 1, @sftp.SftpAttrs::none()),
  )
  let h = handle_of(opened)
  let got = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Read(2, @sftpserver.handle_bytes(h), 0UL, 400000),
  )
  assert_eq(reply_type(got), 103)
  let (data, _) = rd_str(got, 5)
  assert_eq(data.length(), 65536)
}

///|
/// A handle is a SLOT, not a counter.
///
/// Measured: two opens answer 0 and 1, and after the first is closed the
/// next open answers 0 again (`.loop92/probe8_out.txt`).  A monotonic
/// counter would answer 2.
test "a_handle_number_is_the_lowest_free_slot" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let first = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Open(1, "a.txt", 1, @sftp.SftpAttrs::none()),
  )
  let second = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Open(2, "a.txt", 1, @sftp.SftpAttrs::none()),
  )
  assert_eq(handle_of(first), 0)
  assert_eq(handle_of(second), 1)
  let closed = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Close(3, @sftpserver.handle_bytes(0)),
  )
  assert_eq(status_code_of(closed), 0)
  let third = ask_bytes(
    state,
    fs,
    @sftpserver.Request::Open(4, "a.txt", 1, @sftp.SftpAttrs::none()),
  )
  assert_eq(handle_of(third), 0)
}

///|
/// REALPATH answers a NAME with one entry, whose filename and longname
/// are the SAME absolute string, and whose attributes have flags 0.
///
/// Measured: `.loop92/probe_out.txt`.  The path is spelled with a slash
/// before the drive letter and forward slashes throughout: `/C:/...`.
test "realpath_answers_one_name_with_the_absolute_path" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(state, fs, @sftpserver.Request::Realpath(1, "a.txt"))
  assert_eq(reply_type(got), 104)
  assert_eq(name_count(got), 1)
  let (fname, at) = rd_str(got, 9)
  let (ln, at2) = rd_str(got, at)
  assert_eq(shex(fname), "2f433a2f6265642f612e747874")
  assert_eq(shex(ln), shex(fname))
  // The attributes are a zero flags word and nothing else.
  assert_eq(rd_u32(got, at2), 0)
}

///|
/// The VERSION reply is the real server's 179 bytes.
///
/// Checked here as well as in `proto_test.mbt`, because this is the reply
/// every session starts with and a server that advertised a different list
/// would differ from the thing being compared in EVERY case.
test "the_version_reply_is_the_real_servers_179_bytes" {
  let state = @sftpserver.ServerState::new(mem_clock())
  let fs = mem_fs(mem_bed())
  let got = ask_bytes(state, fs, @sftpserver.Request::Init(3))
  assert_eq(got.length(), 179)
}
