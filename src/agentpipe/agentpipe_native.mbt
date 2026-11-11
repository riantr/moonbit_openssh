///|
/// Loop #89: the native side of the named pipe transport.
///
/// The C file is `agentpipe.c`, and the comments about why a named pipe
/// and not a socket are there.
///
/// A HANDLE is a pointer-sized value, so it travels as `Int64`;
/// truncating it to `Int32` would corrupt every handle above 2^31.
/// `Bytes` is a pointer type in this ABI, so the buffers need the
/// `#borrow` annotation -- the MoonBit side keeps the ownership and C
/// only reads or fills the bytes in place.
///
/// A name comes in as bytes plus a length rather than as a String: a
/// MoonBit String carries no terminator, and handing it straight to
/// the wide-character API would read past the end of the data.
///

///|
#borrow(name)
extern "c" fn mb_agentpipe_server_create(
  name : Bytes,
  name_len : Int32,
) -> Int64 = "mb_agentpipe_server_create"

///|
#borrow(name)
extern "c" fn mb_agentpipe_client_connect(
  name : Bytes,
  name_len : Int32,
) -> Int64 = "mb_agentpipe_client_connect"

///|
extern "c" fn mb_agentpipe_accept(h : Int64) -> Int32 = "mb_agentpipe_accept"

///|
#borrow(buf)
extern "c" fn mb_agentpipe_read(h : Int64, buf : Bytes, n : Int32) -> Int64 = "mb_agentpipe_read"

///|
#borrow(buf)
extern "c" fn mb_agentpipe_write(
  h : Int64,
  buf : Bytes,
  off : Int32,
  n : Int32,
) -> Int64 = "mb_agentpipe_write"

///|
extern "c" fn mb_agentpipe_close(h : Int64) -> Int32 = "mb_agentpipe_close"

///|
fn agent_pipe_server_create_raw(name : String) -> Int64 {
  let bytes = utf8_bytes(name)
  let view = Bytes::from_array(bytes)
  mb_agentpipe_server_create(view, bytes.length())
}

///|
fn agent_pipe_connect_raw(name : String) -> Int64 {
  let bytes = utf8_bytes(name)
  let view = Bytes::from_array(bytes)
  mb_agentpipe_client_connect(view, bytes.length())
}

///|
/// The name as UTF-8 bytes.
///
/// The bytes matter and not the characters: the C side widens them
/// with `MultiByteToWideChar(CP_UTF8, ...)`, and a name that was
/// widened from the low byte of each character would be the wrong name
/// for every name that is not ASCII.
fn utf8_bytes(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}

///|
fn agent_pipe_accept_raw(h : Int64) -> Int32 {
  mb_agentpipe_accept(h)
}

///|
fn agent_pipe_read_raw(h : Int64, buf : Bytes, n : Int32) -> Int64 {
  mb_agentpipe_read(h, buf, n)
}

///|
fn agent_pipe_write_raw(
  h : Int64,
  buf : Bytes,
  off : Int32,
  n : Int32,
) -> Int64 {
  mb_agentpipe_write(h, buf, off, n)
}

///|
fn agent_pipe_close_raw(h : Int64) -> Int32 {
  mb_agentpipe_close(h)
}
