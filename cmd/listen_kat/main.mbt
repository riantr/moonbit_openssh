///| cmd/listen_kat -- Loop #79: the local listener, on its own, without an SSH

///| server anywhere near it.
///

///|
/// `ssh -L 9000:db:5432 host` needs a local socket that LISTENS and turns
/// every connection it accepts into a channel. Loop #76 built the channel;
/// nothing listened. This program is the smallest thing that listens, and
/// it prints what it saw:
///
///     listen_port: <port>     (on stderr -- see below)
///     peer_ip: <ip>
///     peer_port: <port>
///     recv: <hex>
///     echoed: <hex>
///
/// It reads what the peer sent and writes the same bytes back, so the
/// caller can check three things at once: that the port it was told is the
/// port that is actually accepting, that the peer address is the address of
/// the machine that connected, and that the bytes survive the round trip
/// through a socket this repository owns.
///
/// ## Why the port goes to stderr
///
/// `println` writes to stdout, and stdout is block-buffered when it is a
/// pipe. The port has to be known BEFORE the caller can connect to it, and
/// a buffered line is only flushed when the process exits -- which is never,
/// because the process is waiting for a connection that only the caller can
/// make. That is a deadlock with a plausible-looking cause. `eprintln` is
/// not buffered, so the port goes out immediately, and the final report
/// goes to stdout where the process exit flushes it.
///
/// (Loop #78 hit the same thing with the port a server allocates, and the
/// fix there was the same one.)
///

///|
fn main {
  let port = if @env.args().length() > 1 {
    let p = @env.args()[1]
    parse_int(p, 0)
  } else {
    0
  }
  let listener = match @tcp.TcpListener::listen("127.0.0.1", port) {
    None => {
      eprintln("listen failed")
      return
    }
    Some(l) => l
  }
  // The port the socket actually got, read back off it. Asking for 0 means
  // "you pick", and a caller that cannot find out which port was picked
  // cannot connect to its own listener.
  let bound = listener.port()
  eprintln("listen_port: " + bound.to_string())
  match listener.accept(30000) {
    @tcp.Timeout => {
      eprintln("accept timed out")
      listener.close()
      return
    }
    @tcp.Failed(code) => {
      eprintln("accept failed: " + code.to_string())
      listener.close()
      return
    }
    @tcp.Accepted(conn, ip, peer_port) => {
      let chunk = conn.recv_some(4096)
      println("peer_ip: " + ip)
      println("peer_port: " + peer_port.to_string())
      println("recv: " + @ecdsa.bytes_to_hex(chunk))
      // Write the same bytes back. The caller checks that they arrived
      // unchanged, which is the whole point of having an echo here: a
      // listener that accepted the connection and then dropped it would look
      // the same as one that never accepted anything at all.
      let sent = conn.send(chunk)
      println(
        "echoed: " +
        (if sent { @ecdsa.bytes_to_hex(chunk) } else { "send-failed" }),
      )
      conn.close()
    }
  }
  listener.close()
}

///|
/// A decimal integer, or `fallback`.
///
/// Written out rather than borrowed: this program depends on `src/tcp` and
/// `src/ecdsa` and nothing else, and a dependency on a parser package for
/// one number is a dependency this program does not need.
fn parse_int(s : String, fallback : Int32) -> Int32 {
  if s.length() == 0 {
    return fallback
  }
  let mut n = 0
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    if c < 48 || c > 57 {
      return fallback
    }
    n = n * 10 + (c - 48)
    i = i + 1
  }
  n
}
