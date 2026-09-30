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
pub fn TcpConn::connect(host : String, port : Int) -> TcpConn? {
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
pub fn TcpConn::recv_some(self : TcpConn, n : Int) -> FixedArray[Byte] {
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
pub fn TcpConn::read_exact(self : TcpConn, n : Int) -> FixedArray[Byte]? {
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
