///| Loop #31: blocking byte-stream transport.
///
///   The SSH layer above is written against a plain read/write contract
///   because SSH is a strict request/response protocol: the client cannot
///   compute anything until it has exactly the bytes the server sent. This
///   package supplies that contract for the native backend over Winsock;
///   Loop #32 supplies the same contract for wasm/browser over WebTransport.
///
///   Target gating lives in moon.pkg.json: socket_native.mbt is native-only
///   (it carries the C FFI), socket_other.mbt answers for every other target so
///   the package still type-checks everywhere.

///|
/// A connected byte stream.
pub struct TcpConn {
  handle : Int64
  mut closed : Bool
}

///|
/// Open a TCP connection. Returns None if the connect fails.
pub fn TcpConn::connect(host : String, port : Int32) -> TcpConn? {
  let hb = Bytes::from_array(ascii_bytes(host))
  match mb_tcp_connect(hb, host.length(), port) {
    h if h < 0L => None
    h => Some({ handle: h, closed: false, })
  }
}

///|
/// ASCII string to bytes. A host name is always ASCII, and the native backend
/// needs the bytes without a terminator so the length is what matters.
fn ascii_bytes(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  out
}

///|
/// Write every byte of `data`. Short writes resume at the right offset, so a
/// partial send never restarts from the beginning of the buffer.
pub fn TcpConn::send(self : TcpConn, data : FixedArray[Byte]) -> Bool {
  if self.closed {
    return false
  }
  let total = data.length()
  if total == 0 {
    return true
  }
  let view = Bytes::from_array(data)
  let mut off = 0
  while off < total {
    let n = mb_tcp_send(self.handle, view, off, total - off)
    if n <= 0L {
      return false
    }
    off = off + n.to_int()
  }
  true
}

///|
/// Read up to `n` bytes. Returns an empty array on EOF or error -- callers
/// that need to tell those apart use read_exact.
///
///   The buffer handed to C is the one read back afterwards. Building a fresh
///   FixedArray and passing Bytes::from_array of it would be a copy, and the
///   bytes C received would be written into a temporary that is then
///   discarded -- which shows up as a client that connects and then silently
///   reads nothing but zeros.
pub fn TcpConn::recv_some(self : TcpConn, n : Int32) -> FixedArray[Byte] {
  if self.closed || n <= 0 {
    return FixedArray::make(0, b'\x00')
  }
  let buf = Bytes::from_array(FixedArray::make(n, b'\x00'))
  let got = mb_tcp_recv(self.handle, buf, n)
  let k = if got <= 0L { 0 } else { got.to_int() }
  let out : FixedArray[Byte] = FixedArray::make(k, b'\x00')
  for i = 0; i < k; i = i + 1 {
    out[i] = buf[i]
  }
  out
}

///|
/// Read exactly `n` bytes. Returns None on EOF or error before that point,
/// which is how a truncated packet is distinguished from a short read.
pub fn TcpConn::read_exact(self : TcpConn, n : Int32) -> FixedArray[Byte]? {
  let out : FixedArray[Byte] = FixedArray::make(
    if n < 0 {
      0
    } else {
      n
    },
    b'\x00',
  )
  let mut off = 0
  while off < n {
    let chunk = TcpConn::recv_some(self, n - off)
    if chunk.length() == 0 {
      return None
    }
    for i = 0; i < chunk.length(); i = i + 1 {
      out[off + i] = chunk[i]
    }
    off = off + chunk.length()
  }
  Some(out)
}

///|
/// Close the connection. Safe to call twice.
pub fn TcpConn::close(self : TcpConn) -> Unit {
  if !self.closed {
    self.closed = true
    ignore(mb_tcp_close(self.handle))
  }
}

///|
/// Loop #79: a listening socket.
///
/// `ssh -L 9000:db:5432 host` is two halves. The channel half -- "open a
/// direct-tcpip channel and carry the bytes" -- is Loop #76. This is the
/// other half: a local socket that *listens*, and turns every connection it
/// accepts into one of those channels.
///
/// The reason it is a separate type and not a flag on `TcpConn` is the same
/// reason `ByteStream` is a separate trait from `Transport` (Loop #78): a
/// listening socket and a connected socket have different contracts, and
/// merging them means every use site asks "which kind is this?".
pub struct TcpListener {
  handle : Int64
  mut closed : Bool
}

///|
/// What an accept attempt produced.
///
/// Three outcomes, not two, because "nothing has arrived yet" and "the
/// accept failed" lead to different decisions: the first one means ask
/// again, the second one means stop. Collapsing them into a single `None`
/// would make a listener that cannot be stopped look like a listener that
/// is merely idle.
pub(all) enum AcceptOutcome {
  /// A connection arrived: the socket, the peer's address, the peer's port.
  Accepted(TcpConn, String, Int32)
  /// Nothing arrived before the deadline. Not an error.
  Timeout
  /// The accept failed. The number is the backend's error code.
  Failed(Int32)
}

///|
/// The backend's "nothing arrived before the deadline" code.
///
/// It is spelled out here rather than taken from the C header because the
/// js and wasm backends have to answer with the same value for the MoonBit
/// side to behave the same on every target.
const ACCEPT_TIMEOUT_CODE : Int64 = -7L

///|
/// Bind and listen.
///
/// Returns None when the socket could not be created, the address could not
/// be parsed, or the bind failed -- which is what "the port is already
/// taken" looks like from here.
pub fn TcpListener::listen(host : String, port : Int32) -> TcpListener? {
  let hb = Bytes::from_array(ascii_bytes(host))
  match mb_tcp_listen(hb, host.length(), port) {
    h if h < 0L => None
    h => Some({ handle: h, closed: false, })
  }
}

///|
/// The port this listener is actually on.
///
/// Read back off the socket, not echoed from the request: the caller asked
/// for port 0 to mean "you pick", and a caller that cannot find out which
/// port was picked cannot connect to its own listener.
pub fn TcpListener::port(self : TcpListener) -> Int32 {
  if self.closed {
    return 0
  }
  // Read the bytes back out of the **Bytes**, not out of the FixedArray.
  //
  // `Bytes::from_array` COPIES. The buffer C writes into is the Bytes, and
  // the FixedArray is a separate copy that C never sees -- so reading the
  // FixedArray back gives the zeros it was created with, and the port comes
  // out as 0.
  //
  // This is the same trap `TcpConn::recv_some` documents, and it is worth
  // spelling out twice: the first version of this function read the
  // FixedArray, reported port 0, and the symptom was a listener that
  // answered on a port nobody could connect to.
  let out = FixedArray::make(2, b'\x00')
  let b = Bytes::from_array(out)
  if mb_tcp_local_port(self.handle, b) != 0 {
    return 0
  }
  be16(b, 0)
}

///|
/// Accept one connection, waiting at most `timeout_ms`.
///
/// The timeout is what makes the listener controllable: a caller that has
/// finished its work (or has been told to stop) can come back and be told
/// "nothing yet" instead of being stuck inside an accept that never
/// returns.
pub fn TcpListener::accept(
  self : TcpListener,
  timeout_ms : Int32,
) -> AcceptOutcome {
  if self.closed {
    return Failed(-1)
  }
  let out = FixedArray::make(8, b'\x00')
  let b = Bytes::from_array(out)
  let h = mb_tcp_accept(self.handle, b, timeout_ms)
  if h == ACCEPT_TIMEOUT_CODE {
    return Timeout
  }
  if h < 0L {
    return Failed(h.to_int())
  }
  // The annotation is needed because `TcpConn` and `TcpListener` have the
  // same two field names, and a record literal with those names fits both.
  let conn : TcpConn = { handle: h, closed: false, }
  // Read back out of the Bytes, not the FixedArray -- see `port` above.
  Accepted(conn, ipv4(b, 0), be16(b, 4))
}

///|
/// Close the listening socket. Safe to call twice.
///
/// Closing it does NOT close the connections it accepted: each of those is
/// its own socket with its own lifetime, and a forward that closed the
/// accepted connection when the listener went away would cut off a transfer
/// that was in the middle of happening.
pub fn TcpListener::close(self : TcpListener) -> Unit {
  if !self.closed {
    self.closed = true
    ignore(mb_tcp_close(self.handle))
  }
}

///|
/// Big-endian u16 at `off`.
///
/// Two bytes, so the result cannot overflow: the largest value is 65535,
/// which fits an Int32 with room to spare. A four-byte reader would have
/// to hold 0xFFFFFFFF somewhere, and an Int32 that overflows is a panic in
/// a debug build.
fn be16(b : Bytes, off : Int32) -> Int32 {
  (b[off].to_int() & 0xFF) * 256 + (b[off + 1].to_int() & 0xFF)
}

///|
/// IPv4 address at `off`, in dotted-quad form.
///
/// The bytes are in network order, so the first one is the highest octet.
fn ipv4(b : Bytes, off : Int32) -> String {
  b[off].to_int().to_string() +
  "." +
  b[off + 1].to_int().to_string() +
  "." +
  b[off + 2].to_int().to_string() +
  "." +
  b[off + 3].to_int().to_string()
}
