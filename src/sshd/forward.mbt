///| Loop #101: the server's half of a port forward.
///
/// `ssh -L 8080:db:5432 host` is one thing at the protocol level: the client
/// opens a channel of type "direct-tcpip" and asks the SERVER to connect to
/// `db:5432`; after that the channel carries the bytes of that TCP
/// connection (RFC 4254 §7.2).  The client half of it is in this repository
/// already -- `src/channel` builds the request, `src/sshclient/forward.mbt`
/// drives it -- and Loop #76 measured that half against the real server.  This
/// file is the other half.
///
/// ## What was measured, and against what
///
/// The oracle is the real `sshd.exe` on this machine.  The witness is its own
/// DEBUG3 log, which names every packet it sends and receives, plus an
/// INDEPENDENT client (paramiko), which reads the numbers out of the real
/// server's bytes.
///
/// ```
///   <- CHANNEL_OPEN          "direct-tcpip"   (the peer)
///   -> CHANNEL_OPEN_CONFIRMATION              window=2097152 max packet=32768
///   <- CHANNEL_DATA                           the peer's bytes
///   -> CHANNEL_DATA                           the target's answer
///   -> CHANNEL_EOF                            (96)
///   -> CHANNEL_CLOSE                          (97)
///   <- CHANNEL_CLOSE                          (97)
/// ```
///
/// Three things in there are not what a reading of the RFC would suggest, and
/// all three were measured rather than recalled:
///
///   * **The confirmation is sent even when the connect FAILED.**  For a
///     target that is not listening, the real server's log says:
///
///     ```
///     debug3: finish_connect - ERROR: async io completed with error: 10061
///     debug1: server_input_channel_open: confirm direct-tcpip
///     debug3: send packet: type 91
///     debug2: send eof
///     debug3: send packet: type 96
///     debug2: send close
///     debug3: send packet: type 97
///     ```
///
///     So the client gets a CONFIRMATION and then a channel that closes with
///     no data and no error message at all.  A server that answered
///     CHANNEL_OPEN_FAILURE instead would be telling the client something the
///     real server does not tell it -- and the client's behaviour would
///     differ, because a client that is refused never opens its local
///     connection, while a client whose channel closes finds out that its
///     local connection has just been closed with nothing in it.
///
///   * **The window is 2097152 and the maximum packet 32768** -- the same
///     numbers the session channel uses.  Read by paramiko out of the real
///     server's own bytes.
///
///   * **The peer's EOF half-closes the target.**  When the client closes its
///     half of the channel, the real server shuts down the target's WRITE
///     side (`chan_shutdown_write` in its log) and keeps reading.  The
///     target then sees EOF, which is what a service that reads until EOF
///     waits for.  Closing the whole target connection instead would throw
///     away the answer the target still had to give.
///
/// ## What this loop does not do
///
/// One channel at a time.  A peer that opens a second channel while the
/// first one is running -- which is what a client with two local forwards
/// does -- has its channel KEPT and served when the current one ends, rather
/// than refused; but the second channel waits its turn instead of running
/// beside the first.

///|
/// The channel type of a forward the peer asks for.
pub const CHANNEL_TYPE_DIRECT_TCPIP : String = "direct-tcpip"

///|
/// The bit that means "the SSH connection has something to read".
pub const WAIT_SSH_READABLE : Int32 = 1

///|
/// The bit that means "the target connection has something to read".
pub const WAIT_TARGET_READABLE : Int32 = 2

///|
/// How long the relay waits for one of the two connections before it looks
/// again.
///
///   The wait is not the interesting part; the DEADLINE is.  A relay that
///   waits forever cannot notice that the peer hung up, and a relay that
///   does not wait at all spins.  One second is short enough that an idle
///   forward still notices a closed peer, and long enough that an idle
///   forward costs nothing.
pub const FORWARD_WAIT_MS : Int32 = 1000

///|
/// How many bytes are read from the target in one go.
pub const FORWARD_READ_CHUNK : Int32 = 32768

///|
/// How many bytes may be waiting to go to the peer.
///
///   A target that talks faster than the peer's window allows would pile up
///   without limit.  The peer decides how much it takes, so this is a safety
///   net and not a policy: when it is reached the relay stops reading from
///   the target until the peer has made room.
pub const FORWARD_PENDING_MAX : Int32 = 4194304

///|
/// A `direct-tcpip` channel's target, read off the wire.
///
/// ```
///   string  host to connect
///   uint32  port to connect
///   string  originator IP address
///   uint32  originator port
/// ```
///
/// The first two fields are where the server connects.  The last two are the
/// address of whoever asked, and the real server only writes them into its
/// log -- measured: `server_request_direct_tcpip: originator 127.0.0.1 port 0,
/// target 127.0.0.1 port 65323`.
///
/// The originator is a STRING of text, not four bytes of address.  That is
/// worth spelling out because the RFC allows both readings of "address", and
/// the real client sends the text: the server's log prints `127.0.0.1` and
/// not four unprintable bytes.
pub(all) struct DirectTcpipOpen {
  /// The host the server has to connect to.
  host : String
  /// The port the server has to connect to.
  port : Int32
  /// The address of whoever asked for the forward.
  originator_ip : String
  /// The port of whoever asked for the forward.
  originator_port : Int32
}

///|
/// Read a `direct-tcpip` CHANNEL_OPEN payload.
///
///   The common part of a CHANNEL_OPEN is the channel type, the peer's
///   channel number, its window and its maximum packet; a `direct-tcpip`
///   open carries four more fields after that.  Returns `None` when the
///   payload is not a well-formed `direct-tcpip` open -- including when it is
///   a well-formed open of some OTHER type, because this function is about
///   one type and not about opens in general.
pub fn sd_parse_direct_tcpip(payload : FixedArray[Byte]) -> DirectTcpipOpen? {
  let (type_b, off1) = match sd_read_string(payload, 0) {
    None => return None
    Some(v) => v
  }
  if sd_bytes_to_string(type_b) != CHANNEL_TYPE_DIRECT_TCPIP {
    return None
  }
  // The peer's channel number, its window and its maximum packet.
  let _number = match sd_read_u32(payload, off1) {
    None => return None
    Some(v) => v
  }
  let _window = match sd_read_u32(payload, off1 + 4) {
    None => return None
    Some(v) => v
  }
  let _max_packet = match sd_read_u32(payload, off1 + 8) {
    None => return None
    Some(v) => v
  }
  let off = off1 + 12
  let (host_b, off2) = match sd_read_string(payload, off) {
    None => return None
    Some(v) => v
  }
  let port = match sd_read_u32(payload, off2) {
    None => return None
    Some(v) => v
  }
  let (originator_b, off3) = match sd_read_string(payload, off2 + 4) {
    None => return None
    Some(v) => v
  }
  let originator_port = match sd_read_u32(payload, off3) {
    None => return None
    Some(v) => v
  }
  Some({
    host: sd_bytes_to_string(host_b),
    port: port.reinterpret_as_int(),
    originator_ip: sd_bytes_to_string(originator_b),
    originator_port: originator_port.reinterpret_as_int(),
  })
}

///|
/// What the server needs in order to forward a channel to a target.
///
///   The rules are here; the sockets are native work, so the driver supplies
///   them -- the same shape `CommandRunner` and `SftpProvider` have.  The
///   type parameter is the driver's own target type, so the driver can hand
///   over its own connection object without this package having to know what
///   a socket is.
pub struct ForwardProvider[U] {
  /// Open a connection to `host:port`. `None` when the target could not be
  /// reached.
  dial_fn : (String, Int32) -> U?
  /// Read up to `n` bytes from the target. An empty array means EOF or
  /// error.
  read_fn : (U, Int32) -> FixedArray[Byte]
  /// Write bytes to the target.
  write_fn : (U, FixedArray[Byte]) -> Bool
  /// Stop sending to the target, keep reading from it.
  shutdown_write_fn : (U) -> Unit
  /// Close the target.
  close_fn : (U) -> Unit
  /// Wait until the SSH connection or the target has something to read.
  ///
  ///   The answer is a bitmask: `WAIT_SSH_READABLE` for the SSH connection,
  ///   `WAIT_TARGET_READABLE` for the target.  Both bits can be set at once,
  ///   and both are honoured -- answering "the SSH side" when the target is
  ///   ready too would lose the wakeup.
  wait_fn : (U, Int32) -> Int32
}

///|
/// Build a `ForwardProvider`.
pub fn[U] ForwardProvider::make(
  dial_fn : (String, Int32) -> U?,
  read_fn : (U, Int32) -> FixedArray[Byte],
  write_fn : (U, FixedArray[Byte]) -> Bool,
  shutdown_write_fn : (U) -> Unit,
  close_fn : (U) -> Unit,
  wait_fn : (U, Int32) -> Int32,
) -> ForwardProvider[U] {
  { dial_fn, read_fn, write_fn, shutdown_write_fn, close_fn, wait_fn, }
}

///|
/// The CHANNEL_OPENs that arrived while another channel was being served.
///
///   This server serves one channel at a time.  A peer that opens a second
///   channel while the first one is running -- which is what a client with two
///   local forwards does -- must not have its channel thrown away, and it
///   must not be refused either.  So the open is kept and served when the
///   current channel ends.
pub struct OpenQueue {
  items : Array[FixedArray[Byte]]
  mut head : Int32
}

///|
/// Build an empty `OpenQueue`.
pub fn OpenQueue::new() -> OpenQueue {
  { items: [], head: 0, }
}

///|
/// Keep one CHANNEL_OPEN for later.
pub fn OpenQueue::push(self : OpenQueue, payload : FixedArray[Byte]) -> Unit {
  self.items.push(payload)
}

///|
/// Take the next CHANNEL_OPEN, if there is one.
pub fn OpenQueue::pop(self : OpenQueue) -> FixedArray[Byte]? {
  if self.head >= self.items.length() {
    return None
  }
  let v = self.items[self.head]
  self.head = self.head + 1
  Some(v)
}

///|
/// How many CHANNEL_OPENs are waiting.
pub fn OpenQueue::pending(self : OpenQueue) -> Int32 {
  self.items.length() - self.head
}

///|
/// How a forwarded channel ends.
///
///   Two shapes, and the difference is which side ended it.  A peer that
///   closed the channel gets a CLOSE and nothing else -- the channel is
///   already over, and an EOF would be a message about a conversation that
///   has ended.  A target that ended gets our EOF first and our CLOSE after
///   it, which is the order the real server uses (its log: `send eof`, then
///   `send close`).
pub(all) enum ForwardClose {
  /// The peer closed: answer with a CLOSE.
  AnswerClose
  /// The target ended: our EOF, then our CLOSE.
  EofThenClose
}

///|
/// Which closing sequence a forwarded channel ends with.
pub fn sd_forward_close_plan(peer_closed : Bool) -> ForwardClose {
  if peer_closed {
    ForwardClose::AnswerClose
  } else {
    ForwardClose::EofThenClose
  }
}

///|
/// What a forwarded channel did.
pub struct ForwardOutcome {
  /// How many bytes went from the peer to the target.
  mut bytes_to_target : Int32
  /// How many bytes went from the target to the peer.
  mut bytes_to_peer : Int32
  /// Whether the target was reached at all.
  connected : Bool
  /// Whether the peer closed the channel.
  mut peer_closed : Bool
  /// Whether the target closed its side.
  mut target_eof : Bool
  /// How much of the peer's window is left.
  mut window_left : UInt32
}

///|
/// Relay one forwarded channel until it ends.
///
///   The loop has two halves that must not be separated:
///
///   * the peer's bytes go to the target, and the target's bytes go to the
///     peer;
///   * both are waited for AT THE SAME TIME.
///
///   The waiting is the part that is easy to get wrong.  Waiting for the SSH
///   connection alone loses the answer coming back from the target -- the
///   peer sends a request, waits for the reply, and the reply sits in the
///   target's socket where nobody is looking.  Waiting for the target alone
///   never sees the request.  Both are deadlocks, and neither of them looks
///   like a hang: everything is "working", just in the wrong order.
///
///   So the provider's `wait_fn` watches both, and this loop acts on
///   whichever of them is ready.
pub fn[T : @transport.Transport, U] sd_forward_loop(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  recv_ctx : @bpacket.RecvCtx,
  peer_channel : UInt32,
  our_channel : UInt32,
  peer_window_in : UInt32,
  peer_max_packet : UInt32,
  target : U,
  provider : ForwardProvider[U],
  queue : OpenQueue,
) -> ForwardOutcome {
  let outcome = {
    bytes_to_target: 0,
    bytes_to_peer: 0,
    connected: true,
    peer_closed: false,
    target_eof: false,
    window_left: peer_window_in,
  }
  // How much the peer will take from us.
  let mut peer_window = peer_window_in
  // How much the peer may send us, counted against the window this server
  // advertised in its CHANNEL_OPEN_CONFIRMATION.
  let window_max = SERVER_WINDOW.reinterpret_as_int()
  let mut recv_left = window_max
  // The target's bytes that have not gone out yet.
  let mut out : Array[Byte] = []
  let mut out_off = 0
  let mut peer_eof = false
  let mut target_eof = false
  let mut transport_gone = false
  let mut done = false
  let mut rounds = 0
  while !done {
    rounds = rounds + 1
    if rounds > 1000000 {
      // A peer that never stops talking must not keep this loop for ever.
      done = true
      break
    }
    // ---- send what is waiting, as far as the window allows ----
    while out_off < out.length() {
      let room = sd_chunk_size(peer_window, peer_max_packet)
      if room <= 0 {
        // The window is empty.  The peer has to send a WINDOW_ADJUST before
        // anything more can go out, and the wait below is where that arrives.
        break
      }
      let avail = out.length() - out_off
      let take = if avail < room { avail } else { room }
      let piece : FixedArray[Byte] = FixedArray::make(take, b'\x00')
      for i = 0; i < take; i = i + 1 {
        piece[i] = out[out_off + i]
      }
      if !sd_send_packet(
          conn,
          counters,
          send_ctx,
          @sshwire.SSH_MSG_CHANNEL_DATA,
          sd_data_payload(peer_channel, piece),
        ) {
        transport_gone = true
        done = true
        break
      }
      peer_window = peer_window - take.reinterpret_as_uint()
      outcome.bytes_to_peer = outcome.bytes_to_peer + take
      out_off = out_off + take
    }
    if done {
      break
    }
    if out_off >= out.length() {
      // Everything has gone out; start the next piece from the beginning.
      out = []
      out_off = 0
    }
    if target_eof && out.length() == 0 {
      // The target is done and everything it said has been said.
      break
    }
    // ---- wait for whichever end moves ----
    let mask = (provider.wait_fn)(target, FORWARD_WAIT_MS)
    if mask < 0 {
      transport_gone = true
      break
    }
    if (mask & WAIT_TARGET_READABLE) != 0 &&
      out.length() - out_off < FORWARD_PENDING_MAX {
      let data = (provider.read_fn)(target, FORWARD_READ_CHUNK)
      if data.length() == 0 {
        // The target closed its side.
        target_eof = true
        outcome.target_eof = true
      } else {
        for i = 0; i < data.length(); i = i + 1 {
          out.push(data[i])
        }
      }
      // NO `continue` here.  Both ends have to be served in the SAME
      // iteration, because a target that is always ready would otherwise
      // starve the SSH side for ever: the peer's bytes -- and, with them,
      // the WINDOW_ADJUST that keeps the peer's window open -- would never
      // be read, and a transfer bigger than the window would stop dead at
      // exactly the window's worth of bytes.
    }
    if (mask & WAIT_SSH_READABLE) != 0 {
      match sd_recv_packet(conn, counters, recv_ctx) {
        Closed => {
          transport_gone = true
          done = true
        }
        BadPacket(_) => {
          transport_gone = true
          done = true
        }
        Packet(t, payload) => {
          if t == @sshwire.SSH_MSG_CHANNEL_OPEN {
            // A channel for later: this server serves one channel at a time,
            // and the open is kept rather than dropped or refused.
            queue.push(payload)
            continue
          }
          // Every other message on a channel names its recipient.  A message
          // for another channel is not ours to answer.
          let recipient = match sd_read_u32(payload, 0) {
            None => UInt32(0)
            Some(v) => v
          }
          if recipient != our_channel {
            continue
          }
          if t == @sshwire.SSH_MSG_CHANNEL_WINDOW_ADJUST {
            match sd_read_u32(payload, 4) {
              None => ()
              Some(n) => peer_window = peer_window + n
            }
            continue
          }
          if t == @sshwire.SSH_MSG_CHANNEL_DATA {
            if peer_eof {
              // The peer said it would send no more bytes.  Anything that
              // arrives after that is not ours to forward.
              continue
            }
            // `uint32 recipient channel || string data`
            let data = match sd_read_string(payload, 4) {
              None => FixedArray::make(0, b'\x00')
              Some((b, _)) => b
            }
            if data.length() > 0 {
              if !(provider.write_fn)(target, data) {
                // The target is gone.  There is nowhere to put the bytes.
                outcome.target_eof = true
              } else {
                outcome.bytes_to_target = outcome.bytes_to_target +
                  data.length()
              }
            }
            recv_left = recv_left - data.length()
            if recv_left < 0 {
              recv_left = 0
            }
            // Top the peer's window back up once it is half spent, so that a
            // peer that sends more than one window's worth is not left
            // waiting for permission that never comes.
            if sd_window_needs_top_up(recv_left, window_max) {
              let give = window_max - recv_left
              let _ = sd_send_packet(
                conn,
                counters,
                send_ctx,
                @sshwire.SSH_MSG_CHANNEL_WINDOW_ADJUST,
                sd_window_adjust_payload(
                  peer_channel,
                  give.reinterpret_as_uint(),
                ),
              )
              recv_left = window_max
            }
            continue
          }
          if t == @sshwire.SSH_MSG_CHANNEL_EOF {
            // The peer will send no more bytes.  The target has to be told,
            // and told in the only way that does not throw away its answer:
            // half-close.  Measured against the real server, whose log says
            // `chan_shutdown_write` at exactly this point.
            peer_eof = true
            (provider.shutdown_write_fn)(target)
            continue
          }
          if t == @sshwire.SSH_MSG_CHANNEL_CLOSE {
            outcome.peer_closed = true
            done = true
            continue
          }
          // Anything else on this channel is not ours to answer.
        }
      }
    }
  }
  // ---- the closing sequence ----
  //
  // The order is the real server's: our EOF, then our CLOSE -- and the
  // close is followed by a READ, because the peer answers a CLOSE with its
  // own, and closing the socket while that answer is in flight turns the
  // close into a TCP RESET, which throws away whatever the peer has not
  // read yet.  Measured in Loop #94.
  if !transport_gone {
    match sd_forward_close_plan(outcome.peer_closed) {
      ForwardClose::AnswerClose => {
        let _ = sd_send_packet(
          conn,
          counters,
          send_ctx,
          @sshwire.SSH_MSG_CHANNEL_CLOSE,
          sd_bare_payload(peer_channel),
        )
      }
      ForwardClose::EofThenClose => {
        let _ = sd_send_packet(
          conn,
          counters,
          send_ctx,
          @sshwire.SSH_MSG_CHANNEL_EOF,
          sd_bare_payload(peer_channel),
        )
        let _ = sd_send_packet(
          conn,
          counters,
          send_ctx,
          @sshwire.SSH_MSG_CHANNEL_CLOSE,
          sd_bare_payload(peer_channel),
        )
        let mut drain = 0
        while drain < 64 {
          drain = drain + 1
          match sd_recv_packet(conn, counters, recv_ctx) {
            Closed => break
            BadPacket(_) => break
            Packet(t, payload) =>
              if t == @sshwire.SSH_MSG_CHANNEL_OPEN {
                // A channel that arrived while this one was closing: kept,
                // not dropped.
                queue.push(payload)
              } else if t == @sshwire.SSH_MSG_CHANNEL_CLOSE {
                outcome.peer_closed = true
                break
              }
          }
        }
      }
    }
  }
  (provider.close_fn)(target)
  outcome.window_left = peer_window
  outcome
}
