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
extern "c" fn mb_tcp_connect(host : Bytes, host_len : Int, port : Int) -> Int64 = "mb_tcp_connect"

///|
#borrow(buf)
extern "c" fn mb_tcp_send(h : Int64, buf : Bytes, off : Int, n : Int) -> Int64 = "mb_tcp_send"

///|
#borrow(buf)
extern "c" fn mb_tcp_recv(h : Int64, buf : Bytes, n : Int) -> Int64 = "mb_tcp_recv"

///|
extern "c" fn mb_tcp_close(h : Int64) -> Int = "mb_tcp_close"
