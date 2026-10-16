///| Socket — byte stream transport (Loop #20 mock dual-mode)

///|
/// Loop #20:
///   - MockSocket (cmd/main 4 target byte-exact 验证)
///   - 真 Socket (在 src/ws_socket/ 包,浏览器 demo 用)

///|
/// 本文件只含 MockSocket。真 WebSocket Socket 见 src/ws_socket/socket.mbt

///|
/// mock Socket
pub struct MockSocket {
  recv_buffer : FixedArray[Byte]
  mut recv_pos : Int32
  sent : Array[FixedArray[Byte]]
  mut closed : Bool
}

///|
pub fn MockSocket::make(
  server_responses : Array[FixedArray[Byte]],
) -> MockSocket {
  let mut total : Int32 = 0
  for resp in server_responses {
    total = total + resp.length()
  }
  let buf : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off : Int32 = 0
  for resp in server_responses {
    for i = 0; i < resp.length(); i = i + 1 {
      buf[off + i] = resp[i]
    }
    off = off + resp.length()
  }
  { recv_buffer: buf, recv_pos: 0, sent: [], closed: false, }
}

///|
pub fn MockSocket::send(self : MockSocket, bytes : FixedArray[Byte]) -> Unit {
  if self.closed {
    abort("MockSocket::send: closed")
  }
  self.sent.push(bytes)
}

///|
pub fn MockSocket::read_n(self : MockSocket, n : Int32) -> FixedArray[Byte] {
  if self.closed {
    abort("MockSocket::read_n: closed")
  }
  if self.recv_buffer.length() - self.recv_pos < n {
    abort(
      "MockSocket::read_n: short buffer, need \{n} got \{self.recv_buffer.length() - self.recv_pos}",
    )
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = self.recv_buffer[self.recv_pos + i]
  }
  self.recv_pos = self.recv_pos + n
  out
}

///|
pub fn MockSocket::close(self : MockSocket) -> Unit {
  self.closed = true
}

///|
pub fn MockSocket::sent_bytes(self : MockSocket) -> FixedArray[Byte] {
  let mut total : Int32 = 0
  for s in self.sent {
    total = total + s.length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off : Int32 = 0
  for s in self.sent {
    for i = 0; i < s.length(); i = i + 1 {
      out[off + i] = s[i]
    }
    off = off + s.length()
  }
  out
}
