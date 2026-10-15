///| Loop #64: the byte-stream contract the SSH layer is written against.
///
///   Until now the only transport was `@tcp.TcpConn`, and every function in
///   `src/sshclient` and `src/sftp` named that type in its signature. That made
///   the SSH protocol layer and one concrete transport (Winsock) the same thing
///   at the type level: there was no way to say "run the same handshake over a
///   WebSocket" without rewriting the signature of all 24 call sites, and no
///   way to *prove* the two were equivalent because there was only one.
///
///   This package supplies the seam. The contract is deliberately the smallest
///   one `src/sshclient` actually uses -- three methods -- because SSH is a
///   strict request/response protocol: the client cannot compute anything until
///   it holds exactly the bytes the server sent, so `read_exact` is the only
///   read primitive that matters and a partial-read notion never leaks upward.
///
///   `src/tcp` is NOT modified and does not import this package; the `Transport`
///   impl for `TcpConn` lives here instead. That keeps the dependency arrow
///   pointing one way (transport -> tcp) and leaves `src/tcp` free to stay a
///   plain Winsock binding.

///|
/// A connected byte stream the SSH layer can talk to.
///
///   `wire_send` returns false when the stream is gone; the caller treats that
///   as "transport lost" and never retries, because a partial SSH packet that
///   failed to go out cannot be resumed.
///
///   `wire_read_exact` returns None on EOF or error *before* `n` bytes
///   arrived. That is the only place truncation is observable, which is why
///   `RecvOutcome` can separate a closed transport from a bad packet.
pub(open) trait Transport {
  fn wire_send(Self, FixedArray[Byte]) -> Bool
  fn wire_read_exact(Self, Int) -> FixedArray[Byte]?
  fn wire_close(Self) -> Unit
}

///|
pub impl Transport for @tcp.TcpConn with fn wire_send(
  self,
  data,
) {
  self.send(data)
}

///|
pub impl Transport for @tcp.TcpConn with fn wire_read_exact(self, n) {
  self.read_exact(n)
}

///|
pub impl Transport for @tcp.TcpConn with fn wire_close(self) {
  self.close()
}
