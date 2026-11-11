///| The local filesystem where there is none.
///
/// js, wasm and wasm-gc have no filesystem this program may use, and a
/// `scp` whose local half silently did nothing would be worse than one
/// that says it cannot: the whole point of the tool is that the bytes
/// arrive.  So every operation here refuses, and the refusal is spelled
/// the way the platform's own operations would spell it, so a driver on
/// one of these targets prints a sentence rather than a wrong result.
///
/// `localfs_native.mbt` is the same six functions over Win32.

///|
/// The sentence for "this target has no filesystem".
///
/// `Function not implemented` is `ENOSYS`'s text, which is what a C
/// program would get from a call the platform does not provide; the
/// message is used here because it is the true one, not because it is
/// pretty.
fn no_local_fs() -> String {
  "Function not implemented"
}

///|
/// `None` for the stat, which the engine reads as "the source is not
/// there" -- and therefore reports as a missing source rather than as a
/// copy that produced nothing.
fn stub_stat(path : String) -> LocalStat? {
  let _ = path
  None
}

///|
fn stub_read(path : String) -> FixedArray[Byte]? {
  let _ = path
  None
}

///|
fn stub_write(path : String, data : FixedArray[Byte]) -> String? {
  let _ = path
  let _ = data
  Some(no_local_fs())
}

///|
fn stub_mkdir(path : String) -> String? {
  let _ = path
  Some(no_local_fs())
}

///|
fn stub_list(path : String) -> Array[String]? {
  let _ = path
  None
}

///|
fn stub_set_mtime(path : String, secs : Int64) -> String? {
  let _ = path
  let _ = secs
  Some(no_local_fs())
}

///|
/// The sentence for the call that just failed -- on these targets every
/// call fails the same way.
fn stub_reason() -> String {
  no_local_fs()
}

///|
/// The local filesystem on a target that has none.
pub fn real_local_fs() -> LocalFs {
  {
    stat_fn: stub_stat,
    read_fn: stub_read,
    write_fn: stub_write,
    mkdir_fn: stub_mkdir,
    list_fn: stub_list,
    set_mtime_fn: stub_set_mtime,
    reason_fn: stub_reason,
  }
}
