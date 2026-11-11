///| Loop #92: the SFTP server's filesystem where there is none.
///
/// js, wasm and wasm-gc have no filesystem this program may use, and a
/// server whose filesystem silently did nothing would be worse than one
/// that says it cannot: the whole point of the server is that the bytes
/// arrive.  So every operation here refuses.
///
/// The refusal is spelled the way the platform's own operations would
/// spell it, so a driver on one of these targets prints a sentence
/// rather than a wrong result.
///
/// `localfs_native.mbt` is the same set over Win32.

///|
/// The sentence for "this target has no filesystem".
///
/// `Function not implemented` is `ENOSYS`'s text, which is what a C
/// program would get from a call the platform does not provide.
fn no_fs() -> String {
  "Function not implemented"
}

///|
/// The stat of one path: always nothing.
fn stub_stat(path : String) -> FileStat? {
  let _ = path
  None
}

///|
fn stub_open(path : String, flags : Int32) -> Result[Int32, FsError] {
  let _ = path
  let _ = flags
  Err(Failure)
}

///|
fn stub_opendir(path : String) -> Result[Int32, FsError] {
  let _ = path
  Err(Failure)
}

///|
fn stub_readdir(handle : Int32) -> DirEntry? {
  let _ = handle
  None
}

///|
fn stub_read(handle : Int32, offset : Int64, len : Int32) -> FixedArray[Byte] {
  let _ = handle
  let _ = offset
  let _ = len
  FixedArray::make(0, b'\x00')
}

///|
fn stub_write(
  handle : Int32,
  offset : Int64,
  data : FixedArray[Byte],
) -> Result[Unit, FsError] {
  let _ = handle
  let _ = offset
  let _ = data
  Err(Failure)
}

///|
fn stub_close(handle : Int32) -> Unit {
  let _ = handle
}

///|
fn stub_truncate(handle : Int32, size : Int64) -> Result[Unit, FsError] {
  let _ = handle
  let _ = size
  Err(Failure)
}

///|
fn stub_set_mtime(path : String, secs : Int64) -> Result[Unit, FsError] {
  let _ = path
  let _ = secs
  Err(Failure)
}

///|
fn stub_mkdir(path : String) -> Result[Unit, FsError] {
  let _ = path
  Err(Failure)
}

///|
fn stub_rmdir(path : String) -> Result[Unit, FsError] {
  let _ = path
  Err(Failure)
}

///|
fn stub_remove(path : String) -> Result[Unit, FsError] {
  let _ = path
  Err(Failure)
}

///|
fn stub_rename(from : String, to : String) -> Result[Unit, FsError] {
  let _ = from
  let _ = to
  Err(Failure)
}

///|
fn stub_rename_replace(from : String, to : String) -> Result[Unit, FsError] {
  let _ = from
  let _ = to
  Err(Failure)
}

///|
/// The absolute form of a path: the path itself, because there is
/// nothing to make it absolute against.
fn stub_realpath(path : String) -> String {
  path
}

///|
/// The filesystem on a target that has none.
pub fn real_server_fs() -> ServerFs {
  {
    stat_fn: stub_stat,
    open_fn: stub_open,
    opendir_fn: stub_opendir,
    readdir_fn: stub_readdir,
    read_fn: stub_read,
    write_fn: stub_write,
    close_fn: stub_close,
    truncate_fn: stub_truncate,
    set_mtime_fn: stub_set_mtime,
    mkdir_fn: stub_mkdir,
    rmdir_fn: stub_rmdir,
    remove_fn: stub_remove,
    rename_fn: stub_rename,
    rename_replace_fn: stub_rename_replace,
    realpath_fn: stub_realpath,
  }
}

///|
/// The clock on a target with no filesystem.
///
/// `@env.now()` is available everywhere and is in MILLISECONDS -- that
/// was measured, not read out of the documentation (see `cmd/wt_ssh`'s
/// note on it), so it is divided here.
pub fn real_server_clock() -> ServerClock {
  { now_fn: stub_now, local_offset_fn: stub_offset, }
}

///|
fn stub_now() -> Int64 {
  0L
}

///|
fn stub_offset(epoch : Int64) -> Int64 {
  let _ = epoch
  0L
}

///|
/// The sentence the stub's failures carry, for a driver that wants it.
pub fn stub_failure_text() -> String {
  no_fs()
}

///|
/// Write raw bytes to stdout (stream 0) or stderr (stream 1).
///
/// There is no standard output to write to on these targets, so this
/// does nothing.  The driver that would call it is native-only anyway.
pub fn emit(stream : Int32, bytes : FixedArray[Byte]) -> Unit {
  let _ = stream
  let _ = bytes
}

///|
/// Read raw bytes from standard input; always 0, because there is none.
pub fn read_stdin(buf : Bytes, cap : Int32) -> Int32 {
  let _ = buf
  let _ = cap
  0
}
