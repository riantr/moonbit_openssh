///|
/// Loop #31: js stand-in for the blocking TCP transport.
///
///   Node sockets are callback-driven and there is no synchronous socket to
///   borrow, so the js backend reports "cannot connect" rather than pretending.
///   Keeping the symbols present means `sshclient` still type-checks for the
///   js target, and Loop #32 replaces this with the WebTransport transport.
#borrow(host)
extern "js" fn mb_tcp_connect(
  host : Bytes,
  host_len : Int32,
  port : Int32,
) -> Int64 = "((_h, _p) => -1n)"

///|
#borrow(buf)
extern "js" fn mb_tcp_send(
  h : Int64,
  buf : Bytes,
  off : Int32,
  n : Int32,
) -> Int64 = "((_h, _b, _o, _n) => -1n)"

///|
#borrow(buf)
extern "js" fn mb_tcp_recv(h : Int64, buf : Bytes, n : Int32) -> Int64 = "((_h, _b, _n) => -1n)"

///|
extern "js" fn mb_tcp_close(h : Int64) -> Int32 = "((_h) => -1)"
