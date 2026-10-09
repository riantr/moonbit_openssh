///| Reassembling SFTP packets out of the channel's byte stream
///
/// This is the piece Loop #39 exists for, and it is a byte stream layered on
/// a byte stream.
///
/// On the wire an SFTP packet is `uint32 length || length bytes`. Inside the
/// SSH channel that lands in CHANNEL_DATA messages, and CHANNEL_DATA messages
/// are bounded by the peer's `max_packet` and chopped by our own window -- so
/// a single SFTP packet routinely spans several CHANNEL_DATA messages, one
/// CHANNEL_DATA routinely carries several SFTP packets, and the four bytes of
/// a length prefix can be split three-and-one across a boundary.
///
/// Both OpenSSH sides read with `atomicio6`, which loops until it has exactly
/// the requested count (sftp-client.c:185-204). That is the authority for
/// this design: the format does not care where the channel's message
/// boundaries are, so neither may we.
///
/// The tempting shortcut -- read a CHANNEL_DATA, parse a packet out of it,
/// move on -- is wrong in both directions and wrong silently: it loses the
/// tail of every packet that got split and treats the head of the next packet
/// as a new one. The KAT pins all four boundary cases because the symptom
/// otherwise only appears against a server that happens to pick an awkward
/// packet size.

///|
/// Buffered SFTP bytes, waiting to be split into packets.
pub(all) struct SftpInbuf {
  mut buf : Array[Byte]
  /// set once a length prefix has been read and the body is on its way
  mut want : Int
  /// sticky: a stream that has gone wrong stays wrong
  mut failed : SftpError?
}

pub fn SftpInbuf::new() -> SftpInbuf {
  { buf: [], want: -1, failed: None }
}

///|
/// Append the payload of one CHANNEL_DATA message.
///
/// `chunk` is the CHANNEL_DATA payload -- the SFTP bytes, with the channel
/// header already stripped. Nothing here inspects it; ordering and framing
/// are entirely the buffer's business.
pub fn SftpInbuf::feed(self : SftpInbuf, chunk : FixedArray[Byte]) -> Unit {
  for i = 0; i < chunk.length(); i = i + 1 {
    self.buf.push(chunk[i])
  }
}

///|
/// Bytes held but not yet part of a complete packet.
///
/// Reported by the harness so a test can assert the buffer really did hold a
/// partial packet across the boundary rather than accidentally getting lucky
/// with message sizes.
pub fn SftpInbuf::pending(self : SftpInbuf) -> Int {
  self.buf.length()
}

///|
/// Take the next complete packet body, if one is buffered.
///
/// Returns `None` when more bytes are needed, and leaves the buffer untouched
/// so the next `feed` can complete it. That "leaves it untouched" half is the
/// invariant Loop #37 had to learn the hard way for the send side: returning
/// `None` and *also* dropping the partial bytes turns a short read into
/// silent data loss, and the only symptom is a truncated file much later.
pub fn SftpInbuf::take(self : SftpInbuf) -> FixedArray[Byte]? {
  if self.failed is Some(_) {
    return None
  }
  if self.want < 0 {
    if self.buf.length() < 4 {
      return None
    }
    let n = (@sshwire.read_u32(self.fixed_buf(), 0)).reinterpret_as_int()
    if n < 0 || n > SFTP_MAX_MSG_LENGTH {
      // sftp-client.c:195 rejects an over-long message *before* reserving for
      // it. Same order here: the length arrived on the wire and must be
      // bounded before anything is sized from it.
      self.failed = Some(Unexpected(n))
      return None
    }
    self.want = n
    self.drop(4)
  }
  if self.buf.length() < self.want {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(self.want, b'\x00')
  for i = 0; i < self.want; i = i + 1 {
    out[i] = self.buf[i]
  }
  self.drop(self.want)
  self.want = -1
  Some(out)
}

///|
/// Every complete packet currently buffered, in order.
///
/// Convenient for the KAT, and for a driver that has already drained the
/// socket: it must not stop at the first packet just because the socket went
/// quiet, or the second packet waits for a read that will never come.
pub fn SftpInbuf::drain(self : SftpInbuf) -> Array[FixedArray[Byte]] {
  let out : Array[FixedArray[Byte]] = []
  let mut again = true
  while again {
    match self.take() {
      None => again = false
      Some(p) => out.push(p)
    }
  }
  out
}

///|
/// The parse failure that latched, if any.
pub fn SftpInbuf::failure(self : SftpInbuf) -> SftpError? {
  self.failed
}

///|
/// A zero-copy view of the first four buffered bytes, for the length prefix.
///
/// FixedArray rather than a slice, because the length is read at offset 0 and
/// four bytes is not worth allocating anything clever for.
fn SftpInbuf::fixed_buf(self : SftpInbuf) -> FixedArray[Byte] {
  let n = if self.buf.length() < 4 { self.buf.length() } else { 4 }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = self.buf[i]
  }
  out
}

fn SftpInbuf::drop(self : SftpInbuf, n : Int) -> Unit {
  let keep = self.buf.length() - n
  let next : Array[Byte] = []
  for i = 0; i < keep; i = i + 1 {
    next.push(self.buf[n + i])
  }
  self.buf = next
}
