///| Loop #92: the `sftp-server` driver -- SFTP over standard input and
/// output.
///
/// The real `sftp-server` is what `sshd` runs for the `sftp` subsystem,
/// and what `scp -D <program>` runs to speak SFTP over a pipe instead of
/// a network.  Both are the same program, and this is that program.
///
/// ## What the driver does, and what it does not
///
/// The driver reads framed requests from standard input, hands each to
/// `src/sftpserver`'s state machine, and writes the reply.  It decides
/// nothing: which reply a request gets is a rule, and the rules live in
/// `src/sftpserver` where a test can pin them and a mutation can be
/// aimed at one of them.
///
/// The one thing the driver owns is the FRAMING, because framing is a
/// property of the pipe: a four-byte big-endian length, then the body.
/// `src/sftp` already has both halves -- `SftpInbuf` takes the packets
/// out of a byte stream, and `sftp_frame` puts a body back into one --
/// so the framing keeps ONE implementation, the same way the protocol
/// does.
///
/// ## Why native only
///
/// The driver reads and writes raw bytes on a file descriptor.  A
/// browser target has no such thing, and a server that cannot read a
/// request cannot answer one.  The library it drives still builds on
/// all four targets, and that is where the rules and the tests live.

///|
/// Read one request body from standard input, or `None` at end of
/// input.
///
/// The bytes are read as they come: the protocol frames them itself,
/// and a reader that waited for a newline would corrupt every frame
/// that happened to contain one.
fn read_request() -> FixedArray[Byte]? {
  let buf = Bytes::from_array(FixedArray::make(65536, b'\x00'))
  let got = @sftpserver.read_stdin(buf, 65536)
  if got <= 0 {
    return None
  }
  let chunk : FixedArray[Byte] = FixedArray::make(got, b'\x00')
  for i = 0; i < got; i = i + 1 {
    chunk[i] = buf[i]
  }
  Some(chunk)
}

///|
/// Write raw bytes to standard output.
fn write_bytes(bytes : FixedArray[Byte]) -> Unit {
  @sftpserver.emit(0, bytes)
}

///|
/// The server loop.
///
/// The input is read in chunks and fed to the framer, because a request
/// can arrive in pieces -- a pipe carries whatever the writer flushed,
/// and a reader that assumed one read per request would lose the tail
/// of a long one.
///
/// The loop ends when standard input ends.  The real server also exits
/// then, and it says nothing on the way out: the client's exit status
/// is what it reads, not a farewell.
fn main {
  let fs = @sftpserver.real_server_fs()
  let clock = @sftpserver.real_server_clock()
  let state = @sftpserver.ServerState::new(clock)
  let inbuf = @sftp.SftpInbuf::new()
  let mut running = true
  while running {
    match read_request() {
      None => running = false
      Some(chunk) => {
        inbuf.feed(chunk)
        let mut again = true
        while again {
          match inbuf.take() {
            None => again = false
            Some(body) => {
              let req = @sftpserver.parse_request(body)
              match state.reply(fs, req) {
                // An unknown request type gets NO reply at all -- the
                // real server goes on to answer the next request.
                None => ()
                Some(reply) => write_bytes(@sftp.sftp_frame(reply))
              }
            }
          }
        }
      }
    }
  }
}
