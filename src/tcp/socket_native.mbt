///| Loop #31: native-only C FFI for the blocking TCP transport.

///|
///   A SOCKET is UINT_PTR, so it is 64-bit on win64 and must travel as
///   long long; truncating it to int would corrupt handles above 2^31.
///   `Bytes` and `String` are both pointer types in this ABI, so every one of
///   those parameters needs the #borrow annotation -- the MoonBit side keeps
///   ownership and C only reads or fills the bytes in place.

///|
///   The host is passed as bytes plus an explicit length rather than as a
///   String: a MoonBit String carries no terminator, and handing it straight
///   to inet_pton would read past the end of the data.
#borrow(host)
extern "c" fn mb_tcp_connect(
  host : Bytes,
  host_len : Int32,
  port : Int32,
) -> Int64 = "mb_tcp_connect"

///|
#borrow(buf)
extern "c" fn mb_tcp_send(
  h : Int64,
  buf : Bytes,
  off : Int32,
  n : Int32,
) -> Int64 = "mb_tcp_send"

///|
#borrow(buf)
extern "c" fn mb_tcp_recv(h : Int64, buf : Bytes, n : Int32) -> Int64 = "mb_tcp_recv"

///|
extern "c" fn mb_tcp_close(h : Int64) -> Int32 = "mb_tcp_close"

///|
/// Loop #79: bind and listen.
///
/// The host is passed as bytes plus a length, like `mb_tcp_connect`: a
/// MoonBit String is not NUL-terminated and inet_pton would read past it.
#borrow(host)
extern "c" fn mb_tcp_listen(
  host : Bytes,
  host_len : Int32,
  port : Int32,
) -> Int64 = "mb_tcp_listen"

///|
/// Loop #79: read the port the listening socket actually got.
///
/// The port comes back as 4 big-endian bytes, because "port 0 means you
/// pick" is only useful if the caller can find out which port was picked.
#borrow(port_out)
extern "c" fn mb_tcp_local_port(h : Int64, port_out : Bytes) -> Int32 = "mb_tcp_local_port"

///|
/// Loop #79: accept one connection, or report that the deadline passed.
///
/// `peer` is 8 bytes: 4 of IPv4 address, then 4 of big-endian port. One
/// buffer rather than two, because MoonBit's #borrow names one borrowed
/// parameter and this repository has no second borrowed pointer anywhere.
///
/// The return value is a negative code on failure. `-7` means "nothing
/// arrived before the deadline", which is NOT an error: the caller asks
/// again.
#borrow(peer)
extern "c" fn mb_tcp_accept(
  h : Int64,
  peer : Bytes,
  timeout_ms : Int32,
) -> Int64 = "mb_tcp_accept"
