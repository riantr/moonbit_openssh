///| Loop #90: the native bindings for `subproc.c`.
///
/// Each of these is a thin pass-through; everything that could be decided
/// twice (retry a short write, turn a broken pipe into end of output) is
/// decided once, in the C file, because that is where the Win32 return
/// values are.
///
/// `Bytes` is a pointer in this ABI, so every buffer parameter carries
/// `#borrow`: MoonBit keeps ownership and C only reads or fills the bytes
/// in place.

///|
#borrow(image, args)
extern "c" fn mb_subproc_spawn(
  image : Bytes,
  image_len : Int32,
  args : Bytes,
  args_len : Int32,
) -> Int64 = "mb_subproc_spawn"

///|
#borrow(buf)
extern "c" fn mb_subproc_write(
  h : Int64,
  buf : Bytes,
  off : Int32,
  n : Int32,
) -> Int64 = "mb_subproc_write"

///|
#borrow(buf)
extern "c" fn mb_subproc_read(h : Int64, buf : Bytes, n : Int32) -> Int64 = "mb_subproc_read"

///|
extern "c" fn mb_subproc_close_stdin(h : Int64) -> Int32 = "mb_subproc_close_stdin"

///|
extern "c" fn mb_subproc_wait(h : Int64) -> Int32 = "mb_subproc_wait"

///|
extern "c" fn mb_subproc_kill(h : Int64) -> Int32 = "mb_subproc_kill"

///|
extern "c" fn mb_subproc_close(h : Int64) -> Int32 = "mb_subproc_close"

///|
fn subproc_spawn_raw(
  image : Bytes,
  image_len : Int32,
  args : Bytes,
  args_len : Int32,
) -> Int64 {
  mb_subproc_spawn(image, image_len, args, args_len)
}

///|
fn subproc_write_raw(h : Int64, buf : Bytes, off : Int32, n : Int32) -> Int64 {
  mb_subproc_write(h, buf, off, n)
}

///|
fn subproc_read_raw(h : Int64, buf : Bytes, n : Int32) -> Int64 {
  mb_subproc_read(h, buf, n)
}

///|
fn subproc_close_stdin_raw(h : Int64) -> Int32 {
  mb_subproc_close_stdin(h)
}

///|
fn subproc_wait_raw(h : Int64) -> Int32 {
  mb_subproc_wait(h)
}

///|
fn subproc_kill_raw(h : Int64) -> Unit {
  let _ = mb_subproc_kill(h)
}

///|
fn subproc_close_raw(h : Int64) -> Unit {
  let _ = mb_subproc_close(h)
}
