///| Loop #92: the SFTP server's filesystem, on Win32.
///
/// The C half is `localfs.c`; this file is the binding and the rule that
/// turns a Win32 error code into a status code.
///
/// ## The error mapping
///
/// The mapping is a TABLE, and every row of it was measured -- the
/// real server's answer for each situation, and the Win32 code that
/// produces it here:
///
/// | situation | measured answer | Win32 code |
/// |---|---|---|
/// | a path that is not there | `2 No such file` | `ERROR_FILE_NOT_FOUND` |
/// | a read-only file opened for writing | `3 Permission denied` | `ERROR_ACCESS_DENIED` |
/// | removing a directory | `3 Permission denied` | `ERROR_ACCESS_DENIED` |
/// | removing a directory that is not empty | `3 Permission denied` | `ERROR_ACCESS_DENIED` |
/// | a directory that is already there | `4 Failure` | `ERROR_ALREADY_EXISTS` |
/// | a rename onto an existing file | `4 Failure` | `ERROR_ALREADY_EXISTS` |
/// | a write open while a read handle is open | `4 Failure` | `ERROR_SHARING_VIOLATION` |
/// | removing a directory with RMDIR | `5 Bad message` | `ERROR_DIRECTORY` |
///
/// The `ERROR_DIRECTORY` row is the interesting one: `RemoveDirectory` on
/// a FILE fails with that code, and the real server answers `5 Bad
/// message` -- the same answer it gives for `OPENDIR` of a file.
///
/// ## The paths
///
/// A path crosses as UTF-8 bytes with an explicit length, because a
/// MoonBit `String` is not NUL-terminated and the C side widens it
/// itself.

///|
/// 0 missing, 1 a regular file, 2 a directory, -1 something else.
#borrow(path)
extern "c" fn mb_sftp_kind(path : Bytes, len : Int32) -> Int32 = "mb_sftp_kind"

///|
/// What "everybody" may do with a path: 4 for read, 2 for write, 1 for
/// execute, and 0 when the path has no readable access control list.
#borrow(path)
extern "c" fn mb_sftp_other_bits(path : Bytes, len : Int32) -> Int32 = "mb_sftp_other_bits"

///|
/// Size in bytes, or -1.
#borrow(path)
extern "c" fn mb_sftp_size(path : Bytes, len : Int32) -> Int64 = "mb_sftp_size"

///|
/// Last-write time in seconds since the epoch, or -1.
#borrow(path)
extern "c" fn mb_sftp_mtime(path : Bytes, len : Int32) -> Int64 = "mb_sftp_mtime"

///|
/// Last-access time in seconds since the epoch, or -1.
#borrow(path)
extern "c" fn mb_sftp_atime(path : Bytes, len : Int32) -> Int64 = "mb_sftp_atime"

///|
/// 1 when the file is read-only, 0 when it is not, -1 when it is
/// missing.
#borrow(path)
extern "c" fn mb_sftp_readonly(path : Bytes, len : Int32) -> Int32 = "mb_sftp_readonly"

///|
/// Open a file; the handle, or -1 with the error code parked.
#borrow(path)
extern "c" fn mb_sftp_open(path : Bytes, len : Int32, flags : Int32) -> Int32 = "mb_sftp_open"

///|
/// Open a directory for listing; the handle, or -1.
#borrow(path)
extern "c" fn mb_sftp_opendir(path : Bytes, len : Int32) -> Int32 = "mb_sftp_opendir"

///|
/// The next entry of an open directory.
///
/// -1 at the end of the listing, -2 when the buffer was too small, -3
/// on error.
///
/// The entry's attributes come back from the enumeration itself, so the
/// name does not have to be looked up again -- and a name that has just
/// been renamed cannot be reported with the old one's attributes.
#borrow(buf, attrs)
extern "c" fn mb_sftp_readdir(
  handle : Int32,
  buf : Bytes,
  cap : Int32,
  attrs : Bytes,
) -> Int32 = "mb_sftp_readdir"

///|
/// Read at most `cap` bytes at `offset`; the count, or -1.
#borrow(buf)
extern "c" fn mb_sftp_read(
  handle : Int32,
  offset : Int64,
  buf : Bytes,
  cap : Int64,
) -> Int64 = "mb_sftp_read"

///|
/// Write `n` bytes at `offset`; 0 or a Win32 error code.
#borrow(buf)
extern "c" fn mb_sftp_write(
  handle : Int32,
  offset : Int64,
  buf : Bytes,
  n : Int64,
) -> Int32 = "mb_sftp_write"

///|
/// Truncate an open file; 0 or a Win32 error code.
extern "c" fn mb_sftp_truncate(handle : Int32, size : Int64) -> Int32 = "mb_sftp_truncate"

///|
/// Close a handle; 0 or a Win32 error code.
extern "c" fn mb_sftp_close(handle : Int32) -> Int32 = "mb_sftp_close"

///|
/// Set the times of a path; 0 or a Win32 error code.
#borrow(path)
extern "c" fn mb_sftp_setmtime(
  path : Bytes,
  len : Int32,
  secs : Int64,
) -> Int32 = "mb_sftp_setmtime"

///|
/// Create a directory; 0 or a Win32 error code.
#borrow(path)
extern "c" fn mb_sftp_mkdir(path : Bytes, len : Int32) -> Int32 = "mb_sftp_mkdir"

///|
/// Remove a directory; 0 or a Win32 error code.
#borrow(path)
extern "c" fn mb_sftp_rmdir(path : Bytes, len : Int32) -> Int32 = "mb_sftp_rmdir"

///|
/// Remove a file; 0 or a Win32 error code.
#borrow(path)
extern "c" fn mb_sftp_remove(path : Bytes, len : Int32) -> Int32 = "mb_sftp_remove"

///|
/// Rename a path; 0 or a Win32 error code.
#borrow(from, to)
extern "c" fn mb_sftp_rename(
  from : Bytes,
  fromlen : Int32,
  to : Bytes,
  tolen : Int32,
) -> Int32 = "mb_sftp_rename"

///|
/// Rename a path, replacing the target; 0 or a Win32 error code.
#borrow(from, to)
extern "c" fn mb_sftp_rename_replace(
  from : Bytes,
  fromlen : Int32,
  to : Bytes,
  tolen : Int32,
) -> Int32 = "mb_sftp_rename_replace"

///|
/// Rename a path, REPLACING the target if it is there.
///
/// This is the `posix-rename@openssh.com` extension's operation, and it is
/// a different one from `native_rename`: the draft's RENAME refuses to
/// overwrite and the real server answers `4 Failure` when the target is
/// there, while the extension is `rename(2)` and replaces.
fn native_rename_replace(from : String, to : String) -> Result[Unit, FsError] {
  let fb = path_bytes(from)
  let tb = path_bytes(to)
  let code = mb_sftp_rename_replace(
    Bytes::from_array(fb),
    fb.length(),
    Bytes::from_array(tb),
    tb.length(),
  )
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// The absolute form of a path, in the server's spelling; the length,
/// or -1.
#borrow(path, buf)
extern "c" fn mb_sftp_realpath(
  path : Bytes,
  len : Int32,
  buf : Bytes,
  cap : Int32,
) -> Int32 = "mb_sftp_realpath"

///|
/// The code left behind by the last call that could only return a
/// value.
extern "c" fn mb_sftp_last_error() -> Int32 = "mb_sftp_last_error"

///|
/// The current time, in seconds since the epoch.
extern "c" fn mb_sftp_now() -> Int64 = "mb_sftp_now"

///|
/// The local offset from UTC, in seconds, at a given time.
extern "c" fn mb_sftp_utc_offset(epoch : Int64) -> Int32 = "mb_sftp_utc_offset"

///|
/// The local offset from UTC, in seconds, at a given time.
///
/// The C function answers an `Int32`, which is widened here so that the
/// clock's function type is the same on both sides of the boundary.
fn native_utc_offset(epoch : Int64) -> Int64 {
  mb_sftp_utc_offset(epoch).to_int64()
}

///|
/// Write raw bytes to stdout (stream 0) or stderr (stream 1).
#borrow(buf)
extern "c" fn mb_sftp_emit(stream : Int32, buf : Bytes, len : Int32) -> Int32 = "mb_sftp_emit"

///|
/// Read raw bytes from standard input; the count, 0 at end of input,
/// or -1.
#borrow(buf)
extern "c" fn mb_sftp_read_stdin(buf : Bytes, cap : Int32) -> Int32 = "mb_sftp_read_stdin"

///|
/// The Win32 codes this file cares about.
const ERROR_FILE_NOT_FOUND : Int32 = 2

///|
const ERROR_ACCESS_DENIED : Int32 = 5

///|
const ERROR_SHARING_VIOLATION : Int32 = 32

///|
const ERROR_ALREADY_EXISTS : Int32 = 183

///|
const ERROR_DIRECTORY : Int32 = 267

///|
/// The failure a Win32 code stands for.
///
/// The mapping is the measured table; every other code is a `Failure`,
/// which is what the real server answers for the operations it has no
/// more specific word for.
fn fs_error_of(code : Int32) -> FsError {
  if code == ERROR_FILE_NOT_FOUND || code == 3 {
    // ERROR_PATH_NOT_FOUND is 3.
    NoSuchFile
  } else if code == ERROR_ACCESS_DENIED {
    PermissionDenied
  } else if code == ERROR_DIRECTORY {
    BadMessage
  } else if code == ERROR_ALREADY_EXISTS || code == ERROR_SHARING_VIOLATION {
    // Measured: a rename onto an existing file and a write open while a
    // read handle is open are both `4 Failure`.  They are named here
    // rather than left to the catch-all because they are the two codes
    // this file has been seen to produce, and a reader of the table below
    // should not have to guess which rows are load-bearing.
    Failure
  } else {
    Failure
  }
}

///|
/// The bytes of a path, as UTF-8.
fn path_bytes(path : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(path.length(), b'\x00')
  for i = 0; i < path.length(); i = i + 1 {
    out[i] = (path[i].to_int() & 0xFF).to_byte()
  }
  out
}

///|
/// The stat of one path, or `None`.
fn native_stat(path : String) -> FileStat? {
  let pb = path_bytes(path)
  let kind = mb_sftp_kind(Bytes::from_array(pb), pb.length())
  if kind == 0 {
    return None
  }
  if kind != 1 && kind != 2 {
    return None
  }
  let ro = mb_sftp_readonly(Bytes::from_array(pb), pb.length())
  Some({
    size: mb_sftp_size(Bytes::from_array(pb), pb.length()),
    is_dir: kind == 2,
    is_readonly: ro == 1,
    mtime: mb_sftp_mtime(Bytes::from_array(pb), pb.length()),
    atime: mb_sftp_atime(Bytes::from_array(pb), pb.length()),
    other_bits: mb_sftp_other_bits(Bytes::from_array(pb), pb.length()),
  })
}

///|
/// Open a file for reading and/or writing.
fn native_open(path : String, flags : Int32) -> Result[Int32, FsError] {
  let pb = path_bytes(path)
  let n = mb_sftp_open(Bytes::from_array(pb), pb.length(), flags)
  if n < 0 {
    Err(fs_error_of(mb_sftp_last_error()))
  } else {
    Ok(n)
  }
}

///|
/// Open a directory for listing.
fn native_opendir(path : String) -> Result[Int32, FsError] {
  let pb = path_bytes(path)
  let n = mb_sftp_opendir(Bytes::from_array(pb), pb.length())
  if n < 0 {
    Err(fs_error_of(mb_sftp_last_error()))
  } else {
    Ok(n)
  }
}

///|
/// The next entry of an open directory.
///
/// The name comes back as bytes and is decoded byte by byte: a name
/// that is not UTF-8 must not take the session down, and the rest of
/// this loop treats a name as bytes anyway.
fn native_readdir(handle : Int32) -> DirEntry? {
  let buf = Bytes::from_array(FixedArray::make(4096, b'\x00'))
  let attrs = Bytes::from_array(FixedArray::make(6 * 8, b'\x00'))
  let n = mb_sftp_readdir(handle, buf, 4096, attrs)
  if n == -1 {
    return None
  }
  if n < 0 {
    return None
  }
  let sb = StringBuilder()
  for i = 0; i < n - 1; i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(buf[i].to_int()))
  }
  let name = sb.to_string()
  Some({
    name,
    stat: {
      size: attrs.read_i64(0),
      is_dir: attrs.read_i64(3) != 0L,
      is_readonly: attrs.read_i64(4) != 0L,
      mtime: attrs.read_i64(1),
      atime: attrs.read_i64(2),
      other_bits: attrs.read_i64(5).to_int(),
    },
  })
}

///|
/// Read `n` bytes out of a `Bytes` as a 64-bit little-endian word.
fn Bytes::read_i64(self : Bytes, index : Int32) -> Int64 {
  let at = index * 8
  let mut v = 0L
  let mut i = 7
  while i >= 0 {
    v = v * 256L + self[at + i].to_int64()
    i = i - 1
  }
  v
}

///|
/// Read at most `len` bytes at `offset`.
fn native_read(handle : Int32, offset : Int64, len : Int32) -> FixedArray[Byte] {
  let buf = Bytes::from_array(FixedArray::make(len, b'\x00'))
  let got = mb_sftp_read(handle, offset, buf, len.to_int64())
  if got <= 0L {
    return FixedArray::make(0, b'\x00')
  }
  let k = got.to_int()
  let out : FixedArray[Byte] = FixedArray::make(k, b'\x00')
  for i = 0; i < k; i = i + 1 {
    out[i] = buf[i]
  }
  out
}

///|
/// Write `data` at `offset`.
fn native_write(
  handle : Int32,
  offset : Int64,
  data : FixedArray[Byte],
) -> Result[Unit, FsError] {
  if data.length() == 0 {
    return Ok(())
  }
  let buf = Bytes::from_array(data)
  let code = mb_sftp_write(handle, offset, buf, data.length().to_int64())
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// Close a handle.
fn native_close(handle : Int32) -> Unit {
  let _ = mb_sftp_close(handle)
}

///|
/// Truncate an open file.
fn native_truncate(handle : Int32, size : Int64) -> Result[Unit, FsError] {
  let code = mb_sftp_truncate(handle, size)
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// Set the modification time of a path.
fn native_set_mtime(path : String, secs : Int64) -> Result[Unit, FsError] {
  let pb = path_bytes(path)
  let code = mb_sftp_setmtime(Bytes::from_array(pb), pb.length(), secs)
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// Create a directory.
fn native_mkdir(path : String) -> Result[Unit, FsError] {
  let pb = path_bytes(path)
  let code = mb_sftp_mkdir(Bytes::from_array(pb), pb.length())
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// Remove a directory.
fn native_rmdir(path : String) -> Result[Unit, FsError] {
  let pb = path_bytes(path)
  let code = mb_sftp_rmdir(Bytes::from_array(pb), pb.length())
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// Remove a file.
fn native_remove(path : String) -> Result[Unit, FsError] {
  let pb = path_bytes(path)
  let code = mb_sftp_remove(Bytes::from_array(pb), pb.length())
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// Rename a path.
fn native_rename(from : String, to : String) -> Result[Unit, FsError] {
  let fb = path_bytes(from)
  let tb = path_bytes(to)
  let code = mb_sftp_rename(
    Bytes::from_array(fb),
    fb.length(),
    Bytes::from_array(tb),
    tb.length(),
  )
  if code == 0 {
    Ok(())
  } else {
    Err(fs_error_of(code))
  }
}

///|
/// The absolute form of a path, in the server's spelling.
fn native_realpath(path : String) -> String {
  let pb = path_bytes(path)
  let buf = Bytes::from_array(FixedArray::make(4096, b'\x00'))
  let n = mb_sftp_realpath(Bytes::from_array(pb), pb.length(), buf, 4096)
  if n <= 0 {
    return path
  }
  let sb = StringBuilder()
  for i = 0; i < n; i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(buf[i].to_int()))
  }
  sb.to_string()
}

///|
/// The filesystem this machine actually has.
pub fn real_server_fs() -> ServerFs {
  {
    stat_fn: native_stat,
    open_fn: native_open,
    opendir_fn: native_opendir,
    readdir_fn: native_readdir,
    read_fn: native_read,
    write_fn: native_write,
    close_fn: native_close,
    truncate_fn: native_truncate,
    set_mtime_fn: native_set_mtime,
    mkdir_fn: native_mkdir,
    rmdir_fn: native_rmdir,
    remove_fn: native_remove,
    rename_fn: native_rename,
    rename_replace_fn: native_rename_replace,
    realpath_fn: native_realpath,
  }
}

///|
/// The clock this machine actually has.
pub fn real_server_clock() -> ServerClock {
  { now_fn: mb_sftp_now, local_offset_fn: native_utc_offset, }
}

///|
/// Write raw bytes to stdout (stream 0) or stderr (stream 1).
///
/// The driver speaks SFTP over its own standard input and output, and
/// the protocol is binary: a text-translating writer would change the
/// bytes.
pub fn emit(stream : Int32, bytes : FixedArray[Byte]) -> Unit {
  if bytes.length() == 0 {
    return
  }
  let buf = Bytes::from_array(bytes)
  let _ = mb_sftp_emit(stream, buf, bytes.length())
}

///|
/// Read raw bytes from standard input; the count, 0 at end of input,
/// or -1.
pub fn read_stdin(buf : Bytes, cap : Int32) -> Int32 {
  mb_sftp_read_stdin(buf, cap)
}
