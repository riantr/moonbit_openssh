///| The real local filesystem: the Win32 bindings for `localfs.c`.
///
/// Native only, and gated per file for the reason `src/khfile` gives: a
/// package-level `targets:` would stop a wasm consumer from compiling the
/// package at all, so the refusal belongs at the file that needs the
/// platform.
///
/// Paths cross as UTF-8 `Bytes` with an explicit length, because a MoonBit
/// `String` is not NUL-terminated and `localfs.c` widens them itself.

///|
/// 0 missing, 1 regular file, 2 directory, -1 something else.
#borrow(path)
extern "c" fn mb_localfs_kind(path : Bytes, len : Int32) -> Int32 = "mb_localfs_kind"

///|
/// Size in bytes, or -1.
#borrow(path)
extern "c" fn mb_localfs_size(path : Bytes, len : Int32) -> Int64 = "mb_localfs_size"

///|
/// Last-write time in seconds since the epoch, or -1.
#borrow(path)
extern "c" fn mb_localfs_mtime(path : Bytes, len : Int32) -> Int64 = "mb_localfs_mtime"

///|
/// Read up to `cap` bytes; -1 on failure.
#borrow(path, buf)
extern "c" fn mb_localfs_read(
  path : Bytes,
  len : Int32,
  buf : Bytes,
  cap : Int64,
) -> Int64 = "mb_localfs_read"

///|
/// Write the whole buffer; 0 or a Win32 code.
#borrow(path, buf)
extern "c" fn mb_localfs_write(
  path : Bytes,
  len : Int32,
  buf : Bytes,
  n : Int64,
) -> Int32 = "mb_localfs_write"

///|
/// Create one directory; 0 created, 1 already there, else a Win32 code.
#borrow(path)
extern "c" fn mb_localfs_mkdir(path : Bytes, len : Int32) -> Int32 = "mb_localfs_mkdir"

///|
/// NUL-separated names into `buf`; -2 if the buffer is too small.
#borrow(path, buf)
extern "c" fn mb_localfs_list(
  path : Bytes,
  len : Int32,
  buf : Bytes,
  cap : Int64,
) -> Int64 = "mb_localfs_list"

///|
/// Set the times; 0 or a Win32 code.
#borrow(path)
extern "c" fn mb_localfs_set_mtime(
  path : Bytes,
  len : Int32,
  secs : Int64,
) -> Int32 = "mb_localfs_set_mtime"

///|
/// The code the last count-only call left behind.
extern "c" fn mb_localfs_last_error() -> Int32 = "mb_localfs_last_error"

///|
/// The size of the listing buffer the first attempt uses, 64 KiB.
///
/// A directory with enough long names to overflow this is retried at
/// double the size, so the number is a starting point and not a limit.
const LIST_FIRST : Int64 = 65536L

///|
/// The cap on retries, so a pathological directory cannot spin forever.
const LIST_TRIES : Int32 = 8

///|
/// The stat half: one kind call, then size and mtime for a file.
fn native_stat(path : String) -> LocalStat? {
  let pb = path_bytes(path)
  let kind = mb_localfs_kind(Bytes::from_array(pb), pb.length())
  if kind == 1 {
    Some({
      is_dir: false,
      size: mb_localfs_size(Bytes::from_array(pb), pb.length()),
      mtime: mb_localfs_mtime(Bytes::from_array(pb), pb.length()),
    })
  } else if kind == 2 {
    let m = mb_localfs_mtime(Bytes::from_array(pb), pb.length())
    Some({ is_dir: true, size: 0L, mtime: m, })
  } else {
    None
  }
}

///|
fn native_read(path : String) -> FixedArray[Byte]? {
  let pb = path_bytes(path)
  let size = mb_localfs_size(Bytes::from_array(pb), pb.length())
  if size < 0L {
    return None
  }
  if size == 0L {
    return Some(FixedArray::make(0, b'\x00'))
  }
  // The buffer has to be a `Bytes` this function keeps: C fills the
  // pointer it is handed, and a `Bytes::from_array()` written inline
  // would be a temporary whose contents nobody reads back.
  let buf = Bytes::from_array(FixedArray::make(size.to_int(), b'\x00'))
  let got = mb_localfs_read(Bytes::from_array(pb), pb.length(), buf, size)
  if got < 0L {
    return None
  }
  // A short read means the file shrank between the size call and the
  // read; return what was actually there rather than the zero padding.
  let k = got.to_int()
  let out : FixedArray[Byte] = FixedArray::make(k, b'\x00')
  for i = 0; i < k; i = i + 1 {
    out[i] = buf[i]
  }
  Some(out)
}

///|
fn native_write(path : String, data : FixedArray[Byte]) -> String? {
  let pb = path_bytes(path)
  let copy : FixedArray[Byte] = FixedArray::make(data.length(), b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    copy[i] = data[i]
  }
  let code = mb_localfs_write(
    Bytes::from_array(pb),
    pb.length(),
    Bytes::from_array(copy),
    data.length().to_int64(),
  )
  if code == 0 {
    None
  } else {
    Some(win32_reason(code))
  }
}

///|
fn native_mkdir(path : String) -> String? {
  let pb = path_bytes(path)
  let code = mb_localfs_mkdir(Bytes::from_array(pb), pb.length())
  if code == 0 || code == 1 {
    None
  } else {
    Some(win32_reason(code))
  }
}

///|
/// The listing: retry with a bigger buffer while the C side says -2.
fn native_list(path : String) -> Array[String]? {
  let pb = path_bytes(path)
  let mut cap = LIST_FIRST
  let mut tries = 0
  while tries < LIST_TRIES {
    // Kept for the same reason as in `native_read`: the names are written
    // into the buffer C is handed, so it cannot be a temporary.
    let buf = Bytes::from_array(FixedArray::make(cap.to_int(), b'\x00'))
    let used = mb_localfs_list(Bytes::from_array(pb), pb.length(), buf, cap)
    if used >= 0L {
      return Some(split_nul(buf, used.to_int()))
    }
    if used != -2L {
      return None
    }
    cap = cap * 2L
    tries = tries + 1
  }
  None
}

///|
/// The NUL-separated names in `buf[0, used)` as strings.
///
/// One name at a time, each with its own builder: the C side wrote UTF-8,
/// and a name's bytes are ASCII-or-UTF-8 by construction, so this is a
/// decode and not a repair.  A byte above 0x7F is passed through as the
/// code unit it is, which is what the rest of this loop does with SFTP's
/// byte-valued names (`sftpdrive.bytes_to_text`).
fn split_nul(buf : Bytes, used : Int32) -> Array[String] {
  let out : Array[String] = []
  let mut i = 0
  while i < used {
    if buf[i] != b'\x00' {
      let sb = StringBuilder()
      while i < used && buf[i] != b'\x00' {
        sb.write_char(Int32::unsafe_to_char(buf[i].to_int()))
        i = i + 1
      }
      out.push(sb.to_string())
    } else {
      i = i + 1
    }
  }
  out
}

///|
fn native_set_mtime(path : String, secs : Int64) -> String? {
  let pb = path_bytes(path)
  let code = mb_localfs_set_mtime(Bytes::from_array(pb), pb.length(), secs)
  if code == 0 {
    None
  } else {
    Some(win32_reason(code))
  }
}

///|
/// The sentence for the call that just failed.
///
/// `localfs.c` parks the raw code because the count-only calls have no
/// room for one; `win32_reason` turns it into the words the tool prints.
fn native_reason() -> String {
  win32_reason(mb_localfs_last_error())
}

///|
/// Write raw bytes to stdout (stream 0) or stderr (stream 1).
#borrow(buf)
extern "c" fn mb_scp_emit(stream : Int32, buf : Bytes, len : Int32) -> Int32 = "mb_scp_emit"

///|
/// The bytes of `text`, unchanged, on standard output.
///
/// Only the native driver needs this (`cmd/scp` is native-only, the same
/// way `cmd/ssh_add` is), which is why it lives in this file rather than
/// behind a stub that would have to pretend a translation it cannot
/// control.
pub fn write_stdout(text : String) -> Unit {
  let b = path_bytes(text)
  if b.length() == 0 {
    return
  }
  let _ = mb_scp_emit(0, Bytes::from_array(b), b.length())
}

///|
/// The bytes of `text`, unchanged, on standard error.
pub fn write_stderr(text : String) -> Unit {
  let b = path_bytes(text)
  if b.length() == 0 {
    return
  }
  let _ = mb_scp_emit(1, Bytes::from_array(b), b.length())
}

///|
/// The local filesystem this machine actually has.
pub fn real_local_fs() -> LocalFs {
  {
    stat_fn: native_stat,
    read_fn: native_read,
    write_fn: native_write,
    mkdir_fn: native_mkdir,
    list_fn: native_list,
    set_mtime_fn: native_set_mtime,
    reason_fn: native_reason,
  }
}
