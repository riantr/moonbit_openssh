///|
/// Loop #31: wasm stand-in for the blocking TCP transport.
///
///   The wasm backends reject `extern "js"` outright, so this is plain
///   MoonBit rather than an FFI stub. A browser has no raw sockets at all --
///   Loop #32 supplies WebTransport/WebSocket, which is also why the transport
///   is kept behind a read/write contract instead of being spread through the
///   SSH layer.
fn mb_tcp_connect(host : Bytes, host_len : Int32, port : Int32) -> Int64 {
  ignore(host)
  ignore(host_len)
  ignore(port)
  -1L
}

///|
fn mb_tcp_send(h : Int64, buf : Bytes, off : Int32, n : Int32) -> Int64 {
  ignore(h)
  ignore(buf)
  ignore(off)
  ignore(n)
  -1L
}

///|
fn mb_tcp_recv(h : Int64, buf : Bytes, n : Int32) -> Int64 {
  ignore(h)
  ignore(buf)
  ignore(n)
  -1L
}

///|
fn mb_tcp_close(h : Int64) -> Int32 {
  ignore(h)
  -1
}
