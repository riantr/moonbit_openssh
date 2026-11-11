///| Loop #90: the js / wasm / wasm-gc side of `src/subproc`.
///
/// There is no process to start on these targets -- no `CreateProcessW`,
/// no anonymous pipes, and no portable substitute that would behave the
/// same.  So nothing here pretends: `spawn` always fails, and every other
/// operation answers the failure value.
///
/// This is the same choice `src/agentpipe` made for the named pipe, and
/// for the same reason: a stub that *appeared* to work would move the
/// failure into the SFTP driver, where it would look like a protocol bug.

///|
fn subproc_spawn_raw(
  image : Bytes,
  image_len : Int32,
  args : Bytes,
  args_len : Int32,
) -> Int64 {
  let _ = image
  let _ = image_len
  let _ = args
  let _ = args_len
  -1L
}

///|
fn subproc_write_raw(h : Int64, buf : Bytes, off : Int32, n : Int32) -> Int64 {
  let _ = h
  let _ = buf
  let _ = off
  let _ = n
  -1L
}

///|
fn subproc_read_raw(h : Int64, buf : Bytes, n : Int32) -> Int64 {
  let _ = h
  let _ = buf
  let _ = n
  -1L
}

///|
fn subproc_close_stdin_raw(h : Int64) -> Int32 {
  let _ = h
  -1
}

///|
fn subproc_wait_raw(h : Int64) -> Int32 {
  let _ = h
  -1
}

///|
fn subproc_kill_raw(h : Int64) -> Unit {
  let _ = h
}

///|
fn subproc_close_raw(h : Int64) -> Unit {
  let _ = h
}
