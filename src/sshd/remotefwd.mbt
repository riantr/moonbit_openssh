///| Loop #102: the server's half of a REMOTE port forward (`ssh -R`).

///|

///| `ssh -R 9000:db:5432 host` is the other direction of Loop #101.  There

///| the CLIENT opens a channel and asks the SERVER to connect somewhere; here

///| the CLIENT asks the SERVER to LISTEN, and every connection that arrives

///| on that listening port is carried to the client over a channel the

///| SERVER opens (RFC 4254 §7.1).

///|

///| ## What was measured, and against what

///|

///| The oracle is the real `sshd.exe` on this machine; the witness is the real

///| `ssh.exe` client's own DEBUG log, which prints what it received:

///|

///| ```

///|   debug1: remote forward success for: listen 55123, connect 127.0.0.1:59277

///|   debug1: client_input_channel_open: ctype forwarded-tcpip rchan 2 win 2097152 max 32768

///|   debug1: client_request_forwarded_tcpip: listen localhost port 55123, originator 127.0.0.1 port 59284

///| ```

///|

///| and, for the case where the client asks for port 0 and lets the server

///| choose:

///|

///| ```

///|   debug1: remote forward success for: listen 0, connect 127.0.0.1:59306

///|   Allocated port 59308 for remote forward to 127.0.0.1:59306

///| ```

///|

///| Four things in there are not what a reading of the RFC would suggest, and

///| all four were measured rather than recalled:

///|

///|   * **The success reply carries the allocated port, and only when the

///|     client asked for port 0.**  With a fixed port the reply has an EMPTY

///|     payload; with port 0 the port the server picked is IN the reply, which

///|     is the only way the client can learn it.  Measured on the wire: the

///|     `Allocated port 59308` line is the client's rendering of a

///|     REQUEST_SUCCESS whose payload is that port.

///|

///|   * **The channel the server opens is `forwarded-tcpip`, and its four

///|     fields are in this order: the LISTEN address and port first, then the

///|     ORIGINATOR address and port.**  The client's log prints them in that

///|     order too (`listen localhost port 55123, originator 127.0.0.1 port

///|     59284`), and both addresses are TEXT -- the originator is the address

///|     of whoever connected to the listening port, spelled as text and not

///|     as four bytes of address.

///|

///|   * **The window is 2097152 and the maximum packet 32768** -- the same

///|     numbers the session channel and the direct-tcpip confirmation use.

///|

///|   * **The SERVER opens the channel and the client confirms it.**  So the

///|     channel number this server picks is the SENDER number, and the peer's

///|     number only exists once the confirmation has arrived.

///|

///| ## The order of the messages, which is the part that decides the shape

///| of the code

///|

///| The real server's own log (`sshd.log_rf`) says, for one `ssh -N -R`:

///|

///| ```

///|   debug3: receive packet: type 80        <- GLOBAL_REQUEST  tcpip-forward

///|   debug1: server_input_global_request: rtype tcpip-forward want_reply 1

///|   debug1: server_input_global_request: tcpip-forward listen localhost port 55123

///|   debug3: send packet: type 81           -> REQUEST_SUCCESS

///|   debug3: receive packet: type 80        <- GLOBAL_REQUEST  no-more-sessions@openssh.com

///|   debug1: Connection to port 55123 forwarding to localhost port 0 requested.

///|   debug1: channel 2: new [forwarded-tcpip]

///|   debug3: send packet: type 90           -> CHANNEL_OPEN  forwarded-tcpip

///|   debug3: receive packet: type 91        <- CHANNEL_OPEN_CONFIRMATION

///| ```

///|

///| Two things follow, and both of them are load-bearing:

///|

///|   * **The `tcpip-forward` request arrives BEFORE any session channel.**

///|     It is sent right after the authentication, and `ssh -N` -- which is

///|     what a remote forward is normally used with -- never opens a session

///|     channel at all.  A server that only answers global requests inside

///|     its session loop therefore never answers them at all, and the client

///|     waits for a reply that will not come.

///|

///|   * **The bind address the client sends is the literal string

///|     `localhost`** when the user gave no bind address -- not the empty

///|     string.  The real server resolves it to two listeners (`::1` and

///|     `127.0.0.1`); its log shows both.  This server binds one address, and

///|     the driver decides which.

///|

///| ## What this loop does not do

///|

///| One remote forward at a time, and one connection on it at a time.  A

///| second `tcpip-forward` request while one is running is REFUSED (the

///| reply is a REQUEST_FAILURE) rather than silently ignored, and a second

///| connection on the same listening port waits for the first to finish.

///|
/// The channel type of a forward the peer asks the server to carry.
pub const CHANNEL_TYPE_FORWARDED_TCPIP : String = "forwarded-tcpip"

///|
/// The bit that means "the listening socket has something to read".
///
/// The same value as `WAIT_TARGET_READABLE`, and for the same reason: the
/// two waits are separate calls over separate sockets, and each one has an
/// SSH side and a socket side.  The SSH side is bit 1 in both.
pub const WAIT_LISTENER_READABLE : Int32 = 2

///|
/// How long the server waits for a connection to arrive once the listening
/// socket says there is one.
///
/// The socket has already said something is there, so this is only the
/// deadline for the accept itself; a second is far longer than an accept
/// takes and short enough that a dead listener is noticed.
pub const FORWARD_ACCEPT_TIMEOUT_MS : Int32 = 1000

///|
/// A GLOBAL_REQUEST, read off the wire.
///
/// ```
///   string   request name
///   boolean  want reply
///   ...      request-specific
/// ```
///
/// The two global requests this server answers are `tcpip-forward` (listen
/// on a port for me) and `cancel-tcpip-forward` (stop doing that).  The
/// names are case-sensitive, and the rest of the requests a client sends --
/// `no-more-sessions@openssh.com`, `hostkeys-00@openssh.com` -- are
/// answered with silence, which is what the real server does.
pub(all) struct GlobalRequest {
  /// The request's name.
  name : String
  /// Whether the peer wants an answer.
  want_reply : Bool
  /// The bytes after the name and the flag.
  data : FixedArray[Byte]
}

///|
/// Read a GLOBAL_REQUEST payload.
///
/// Returns `None` when the payload does not hold a well-formed request: a
/// name that does not fit, or a missing want-reply flag.
pub fn sd_parse_global_request(payload : FixedArray[Byte]) -> GlobalRequest? {
  let (name_b, off1) = match sd_read_string(payload, 0) {
    None => return None
    Some(v) => v
  }
  let want = match sd_read_u8(payload, off1) {
    None => return None
    Some(v) => v
  }
  let data = match sd_slice(payload, off1 + 1, payload.length() - off1 - 1) {
    None => return None
    Some(v) => v
  }
  Some({ name: sd_bytes_to_string(name_b), want_reply: want != b'\x00', data, })
}

///|
/// The address and the port of a `tcpip-forward` request.
///
/// ```
///   string   address to bind
///   uint32   port to bind
/// ```
///
/// A port of 0 means "you choose", and the server answers with the port it
/// chose.
pub(all) struct ForwardBinding {
  /// The address the peer asked the server to listen on.
  address : String
  /// The port the peer asked for.  Zero means "the server picks".
  port : Int32
}

///|
/// Read the body of a `tcpip-forward` (or `cancel-tcpip-forward`) request.
///
/// The two requests have the same body -- an address and a port -- and the
/// RFC gives them the same shape, so one reader serves both.
pub fn sd_parse_forward_binding(data : FixedArray[Byte]) -> ForwardBinding? {
  let (addr_b, off1) = match sd_read_string(data, 0) {
    None => return None
    Some(v) => v
  }
  let port = match sd_read_u32(data, off1) {
    None => return None
    Some(v) => v
  }
  Some({ address: sd_bytes_to_string(addr_b), port: port.reinterpret_as_int(), })
}

///|
/// The reply to a `tcpip-forward` request.
///
/// The payload is the port the server bound, and it is EMPTY unless the peer
/// asked for port 0.  Measured: with a fixed port the client's log says
/// `remote forward success for: listen 55123` and nothing about a port; with
/// port 0 it says `Allocated port 59308`, which is the port in the reply.
///
/// So the rule is not "put the port in the reply" but "put the port in the
/// reply WHEN THE PEER DID NOT NAME ONE" -- and a server that always sent
/// the port would be sending a payload the peer is not expecting.
pub fn sd_request_success_payload(
  requested_port : Int32,
  bound_port : Int32,
) -> FixedArray[Byte] {
  if requested_port == 0 {
    @sshwire.write_u32(bound_port.reinterpret_as_uint())
  } else {
    FixedArray::make(0, b'\x00')
  }
}

///|
/// The CHANNEL_OPEN payload for a `forwarded-tcpip` channel.
///
/// ```
///   string   channel type          "forwarded-tcpip"
///   uint32   sender channel        ours
///   uint32   initial window size   2097152
///   uint32   maximum packet size   32768
///   string   address to bind        the listening address
///   uint32   port to bind           the listening port
///   string   originator address     who connected
///   uint32   originator port
/// ```
///
/// The order of the last four fields is measured, not guessed: the real
/// server's client prints `listen localhost port 55123, originator 127.0.0.1
/// port 59284` -- the LISTEN pair first, then the ORIGINATOR pair.
pub fn sd_forwarded_tcpip_open_payload(
  our_channel : UInt32,
  window : UInt32,
  max_packet : UInt32,
  listen_address : String,
  listen_port : Int32,
  originator_address : String,
  originator_port : Int32,
) -> FixedArray[Byte] {
  // The four common fields of a CHANNEL_OPEN ...
  let head = sd_cat3(
    @sshwire.write_ssh_string(sd_ascii(CHANNEL_TYPE_FORWARDED_TCPIP)),
    @sshwire.write_u32(our_channel),
    @sshwire.write_u32(window),
  )
  // ... then the four that say what the channel is for.
  let body = sd_cat3(
    @sshwire.write_u32(max_packet),
    @sshwire.write_ssh_string(sd_ascii(listen_address)),
    @sshwire.write_u32(listen_port.reinterpret_as_uint()),
  )
  let tail = sd_cat2(
    @sshwire.write_ssh_string(sd_ascii(originator_address)),
    @sshwire.write_u32(originator_port.reinterpret_as_uint()),
  )
  sd_cat2(sd_cat2(head, body), tail)
}

///|
/// What an accept attempt produced.
///
/// Three outcomes, for the same reason `src/tcp`'s `AcceptOutcome` has three:
/// "nothing yet" and "the accept failed" lead to different decisions.
pub(all) enum RemoteAccept[U] {
  /// A connection arrived: the socket, the peer's address, the peer's port.
  Accepted(U, String, Int32)
  /// Nothing arrived before the deadline.  Not an error.
  Timeout
  /// The accept failed.  The number is the backend's error code.
  Failed(Int32)
}

///|
/// A listening socket, as the driver sees it.
///
///   The server never looks inside it: it hands it back to the provider and
///   the provider knows what it is.  The port is here because the server has
///   to put it in the `forwarded-tcpip` payload -- and because the peer may
///   have asked for port 0, in which case the port is the one the operating
///   system picked, not the one the peer named.
pub(all) struct RemoteListener {
  /// The driver's own handle for the listening socket.
  handle : Int64
  /// The port the listener is actually on.
  port : Int32
}

///|
/// What the server needs in order to serve a remote port forward.
///
///   The rules are here; the sockets are native work, so the driver supplies
///   them -- the same shape `ForwardProvider` and `CommandRunner` have.  The
///   type parameter is the driver's own connection type, so the driver can
///   hand over its own connection object without this package having to know
///   what a socket is.
pub struct RemoteForwardProvider[U] {
  /// Bind a listening socket on `address:port`.  `None` when the bind
  /// failed, which is what "the port is already taken" looks like from here.
  listen_fn : (String, Int32) -> RemoteListener?
  /// Accept one connection on the listener, waiting at most `timeout_ms`.
  accept_fn : (RemoteListener, Int32) -> RemoteAccept[U]
  /// Close the listening socket.
  close_listener_fn : (RemoteListener) -> Unit
  /// Wait until the SSH connection or the listener has something to read.
  ///
  ///   The answer is a bitmask: `WAIT_SSH_READABLE` for the SSH connection
  ///   and `WAIT_LISTENER_READABLE` for the listener.
  wait_listener_fn : (RemoteListener, Int32) -> Int32
  /// Read up to `n` bytes from the accepted connection.  An empty array
  /// means EOF or error.
  read_fn : (U, Int32) -> FixedArray[Byte]
  /// Write bytes to the accepted connection.
  write_fn : (U, FixedArray[Byte]) -> Bool
  /// Stop sending to the accepted connection, keep reading from it.
  shutdown_write_fn : (U) -> Unit
  /// Close the accepted connection.
  close_fn : (U) -> Unit
  /// Wait until the SSH connection or the accepted connection has something
  /// to read.  The same bitmask as `wait_listener_fn`.
  wait_target_fn : (U, Int32) -> Int32
}

///|
/// Build a `RemoteForwardProvider`.
pub fn[U] RemoteForwardProvider::make(
  listen_fn : (String, Int32) -> RemoteListener?,
  accept_fn : (RemoteListener, Int32) -> RemoteAccept[U],
  close_listener_fn : (RemoteListener) -> Unit,
  wait_listener_fn : (RemoteListener, Int32) -> Int32,
  read_fn : (U, Int32) -> FixedArray[Byte],
  write_fn : (U, FixedArray[Byte]) -> Bool,
  shutdown_write_fn : (U) -> Unit,
  close_fn : (U) -> Unit,
  wait_target_fn : (U, Int32) -> Int32,
) -> RemoteForwardProvider[U] {
  {
    listen_fn,
    accept_fn,
    close_listener_fn,
    wait_listener_fn,
    read_fn,
    write_fn,
    shutdown_write_fn,
    close_fn,
    wait_target_fn,
  }
}

///|
/// What a remote forward did.
pub struct RemoteForwardOutcome {
  /// How many connections were carried to the peer.
  mut accepted : Int32
  /// How many bytes went from the peer to the connection.
  mut bytes_to_target : Int32
  /// How many bytes went from the connection to the peer.
  mut bytes_to_peer : Int32
  /// Whether the peer closed the connection.
  mut peer_closed : Bool
}

///|
/// The state of the ONE remote forward this server runs.
///
///   It is a struct and not a handful of locals because the state has to
///   survive across two different phases of the connection: the peer asks
///   for the forward BEFORE it opens any session channel, and the connection
///   that arrives on the listening port may be served long before (or long
///   after) that channel exists.
pub struct RemoteForwardState {
  /// Whether a forward is running.
  mut listening : Bool
  /// The listening socket, when there is one.
  mut listener : RemoteListener?
  /// The address the peer asked to listen on, as it will be echoed back in
  /// the `forwarded-tcpip` payload.
  mut listen_address : String
  /// The port the listener is REALLY on.
  mut listen_port : Int32
}

///|
/// Build the state of a server that has no remote forward yet.
pub fn RemoteForwardState::new() -> RemoteForwardState {
  { listening: false, listener: None, listen_address: "", listen_port: 0, }
}

///|
/// What a global request did.
pub(all) enum GlobalRequestOutcome {
  /// Not a request this server answers.
  Ignored
  /// The peer asked for a forward and the server bound it.  The number is
  /// the port the listener is really on.
  Bound(Int32)
  /// The peer asked for a forward and the server could not bind it.
  BindFailed
  /// The peer asked for a forward while one was already running.
  AlreadyListening
  /// The peer asked to cancel a forward and the server stopped it.
  Cancelled
  /// The peer asked to cancel a forward the server does not have.
  NotCancelled
}

///|
/// Answer a GLOBAL_REQUEST.
///
///   The two requests this server answers are `tcpip-forward` and
///   `cancel-tcpip-forward`.  Everything else is left alone: the real server
///   answers `no-more-sessions@openssh.com` and `hostkeys-00@openssh.com`
///   with silence, and a server that answered would put a packet in the
///   peer's stream that the peer is not expecting.
///
///   The reply is sent here because the rules of the reply belong with the
///   rules of the request: an empty payload for a fixed port, and the
///   allocated port when the peer asked for port 0.
pub fn[T : @transport.Transport, U] sd_handle_global_request(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  provider : RemoteForwardProvider[U]?,
  state : RemoteForwardState,
  name : String,
  want_reply : Bool,
  data : FixedArray[Byte],
) -> GlobalRequestOutcome {
  if name == "tcpip-forward" {
    let binding = match sd_parse_forward_binding(data) {
      None => return GlobalRequestOutcome::Ignored
      Some(v) => v
    }
    let p = match provider {
      None => {
        // This server does not do remote forwards.  Saying so is better
        // than answering SUCCESS and never listening.
        sd_reply_failure(conn, counters, send_ctx, want_reply)
        return GlobalRequestOutcome::BindFailed
      }
      Some(v) => v
    }
    if state.listening {
      // One remote forward at a time.  A second one is REFUSED rather than
      // silently ignored: a peer that was told SUCCESS and then got nothing
      // would wait for ever.
      sd_reply_failure(conn, counters, send_ctx, want_reply)
      return GlobalRequestOutcome::AlreadyListening
    }
    match (p.listen_fn)(binding.address, binding.port) {
      None => {
        // The bind failed.  Measured against the real server: it answers
        // REQUEST_FAILURE, and the client says
        // `Warning: remote port forwarding failed for listen port N`.
        sd_reply_failure(conn, counters, send_ctx, want_reply)
        return GlobalRequestOutcome::BindFailed
      }
      Some(l) => {
        if want_reply {
          let payload = sd_request_success_payload(binding.port, l.port)
          let _ = sd_send_packet(
            conn,
            counters,
            send_ctx,
            @sshwire.SSH_MSG_REQUEST_SUCCESS,
            payload,
          )
        }
        state.listening = true
        state.listener = Some(l)
        // The address is echoed back AS IT WAS ASKED FOR, and that is
        // measured twice over.  The bytes a real Win32-OpenSSH 8.0p1 server
        // sent are pinned in `host/gen_remote_fwd_vectors.py`: the listen
        // address is the empty string there, because that is what the client
        // asked for.  And the real `ssh.exe` client's own log says
        // `client_request_forwarded_tcpip: listen localhost port 52943` --
        // "localhost", because that is what IT asked for.  The server does
        // not substitute an address of its own.
        state.listen_address = binding.address
        state.listen_port = l.port
        return GlobalRequestOutcome::Bound(l.port)
      }
    }
  }
  if name == "cancel-tcpip-forward" {
    let binding = match sd_parse_forward_binding(data) {
      None => return GlobalRequestOutcome::Ignored
      Some(v) => v
    }
    let mut stopped = false
    match state.listener {
      Some(l) =>
        // The peer names the port it wants stopped.  When the peer asked
        // for port 0 the server chose, the client learned the choice, and
        // the client then names THAT port -- so a cancel with port 0 also
        // means "the one you chose".
        if l.port == binding.port || binding.port == 0 {
          match provider {
            Some(p) => (p.close_listener_fn)(l)
            None => ()
          }
          state.listening = false
          state.listener = None
          state.listen_port = 0
          stopped = true
        }
      None => ()
    }
    if want_reply {
      // The real server answers SUCCESS for a forward it knows and
      // FAILURE for one it does not.
      let _ = sd_send_packet(
        conn,
        counters,
        send_ctx,
        if stopped {
          @sshwire.SSH_MSG_REQUEST_SUCCESS
        } else {
          @sshwire.SSH_MSG_REQUEST_FAILURE
        },
        FixedArray::make(0, b'\x00'),
      )
    }
    return if stopped {
      GlobalRequestOutcome::Cancelled
    } else {
      GlobalRequestOutcome::NotCancelled
    }
  }
  GlobalRequestOutcome::Ignored
}

///|
/// Answer a global request with a REQUEST_FAILURE.
///
///   A request that does not want a reply gets no reply -- not even a
///   failure.  The flag is the peer's way of saying "do not answer me", and
///   answering anyway puts a packet in the peer's stream that it has not
///   asked for.
pub fn[T : @transport.Transport] sd_reply_failure(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  want_reply : Bool,
) -> Unit {
  if !want_reply {
    return
  }
  let _ = sd_send_packet(
    conn,
    counters,
    send_ctx,
    @sshwire.SSH_MSG_REQUEST_FAILURE,
    FixedArray::make(0, b'\x00'),
  )
}

///|
/// What one turn of the remote forward did.
pub(all) struct RemoteForwardStep {
  /// What the connection did.  All zeros when no connection arrived.
  outcome : RemoteForwardOutcome
  /// The server's own channel number AFTER this turn.
  our_channel : UInt32
  /// Whether the listening socket is broken and has to be dropped.
  listener_broken : Bool
}

///|
/// Accept one connection on the listening port and carry it to the peer.
///
///   This is the half of the remote forward that has to happen while the
///   server is ALSO serving something else -- a session channel, or the
///   peer's answer to the `tcpip-forward` request.  It is a function and not
///   a block of code in the caller because it is called from two places:
///   the phase before the session channel exists, and the phase after it.
pub fn[T : @transport.Transport, U] sd_remote_forward_accept(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  recv_ctx : @bpacket.RecvCtx,
  provider : RemoteForwardProvider[U],
  state : RemoteForwardState,
  our_channel : UInt32,
  queue : OpenQueue,
) -> RemoteForwardStep {
  let nothing = {
    accepted: 0,
    bytes_to_target: 0,
    bytes_to_peer: 0,
    peer_closed: false,
  }
  let l = match state.listener {
    Some(v) => v
    None => return { outcome: nothing, our_channel, listener_broken: false, }
  }
  match (provider.accept_fn)(l, FORWARD_ACCEPT_TIMEOUT_MS) {
    RemoteAccept::Timeout =>
      { outcome: nothing, our_channel, listener_broken: false, }
    RemoteAccept::Failed(_) =>
      // The listening socket is broken.  Stop watching it rather than
      // spinning on a socket that will never work again.
      { outcome: nothing, our_channel, listener_broken: true, }
    RemoteAccept::Accepted(target, ip, port) => {
      // The server opens the channel; the peer confirms it.
      let mine = our_channel
      let outcome = sd_remote_forward_channel(
        conn,
        counters,
        send_ctx,
        recv_ctx,
        provider,
        target,
        mine,
        state.listen_address,
        state.listen_port,
        ip,
        port,
        queue,
      )
      { outcome, our_channel: our_channel + 1U, listener_broken: false, }
    }
  }
}

///|
/// Carry ONE connection on a remote forward to the peer.
///
///   The sequence is the real server's, and it is measured:
///
///   ```

///|     -> CHANNEL_OPEN            "forwarded-tcpip"

///|     <- CHANNEL_OPEN_CONFIRMATION

///|     -> CHANNEL_DATA            the connection's bytes

///|     <- CHANNEL_DATA            the peer's bytes

///|
///   ```
///
///   The CHANNEL_OPEN comes FIRST, and the peer answers it with a
///   confirmation -- so the peer's channel number, its window and its maximum
///   packet are only known after that answer arrives.  A server that opened
///   the channel and started sending data before the confirmation would be
///   sending to a channel number it does not know yet.
pub fn[T : @transport.Transport, U] sd_remote_forward_channel(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  recv_ctx : @bpacket.RecvCtx,
  provider : RemoteForwardProvider[U],
  target : U,
  our_channel : UInt32,
  listen_address : String,
  listen_port : Int32,
  originator_address : String,
  originator_port : Int32,
  queue : OpenQueue,
) -> RemoteForwardOutcome {
  let outcome = {
    accepted: 0,
    bytes_to_target: 0,
    bytes_to_peer: 0,
    peer_closed: false,
  }
  // ---- 1. open the channel ----
  let open = sd_forwarded_tcpip_open_payload(
    our_channel,
    SERVER_WINDOW,
    SERVER_MAX_PACKET,
    listen_address,
    listen_port,
    originator_address,
    originator_port,
  )
  if !sd_send_packet(
      conn,
      counters,
      send_ctx,
      @sshwire.SSH_MSG_CHANNEL_OPEN,
      open,
    ) {
    (provider.close_fn)(target)
    return outcome
  }
  // ---- 2. wait for the confirmation ----
  //
  // The peer's channel number lives in the confirmation, so the relay cannot
  // start before it arrives.  A peer that refuses the channel answers with a
  // CHANNEL_OPEN_FAILURE instead, and then there is nothing to carry.
  let confirm = sd_wait_open_confirmation(
    conn, counters, recv_ctx, our_channel, queue,
  )
  match confirm {
    None => {
      (provider.close_fn)(target)
      outcome
    }
    Some(c) => {
      // ---- 3. carry the bytes ----
      let relay : ForwardProvider[U] = {
        dial_fn: fn(_host : String, _port : Int32) -> U? { None },
        read_fn: provider.read_fn,
        write_fn: provider.write_fn,
        shutdown_write_fn: provider.shutdown_write_fn,
        close_fn: provider.close_fn,
        wait_fn: provider.wait_target_fn,
      }
      let result = sd_forward_loop(
        conn,
        counters,
        send_ctx,
        recv_ctx,
        c.peer_channel,
        our_channel,
        c.peer_window,
        c.peer_max_packet,
        target,
        relay,
        queue,
      )
      outcome.accepted = 1
      outcome.bytes_to_target = result.bytes_to_target
      outcome.bytes_to_peer = result.bytes_to_peer
      outcome.peer_closed = result.peer_closed
      outcome
    }
  }
}

///|
/// What a CHANNEL_OPEN_CONFIRMATION said.
pub(all) struct OpenConfirmation {
  /// The peer's channel number: the one we address our packets to.
  peer_channel : UInt32
  /// How much the peer will take from us.
  peer_window : UInt32
  /// The largest packet the peer wants.
  peer_max_packet : UInt32
}

///|
/// Wait for the confirmation of a channel this server opened.
///
///   The confirmation names OUR channel as its recipient, so a confirmation
///   for somebody else's channel is not ours.  A CHANNEL_OPEN that arrives
///   while we wait is a channel the peer wants: it is KEPT for later rather
///   than thrown away, which is what `OpenQueue` is for.
pub fn[T : @transport.Transport] sd_wait_open_confirmation(
  conn : T,
  counters : WireCounters,
  recv_ctx : @bpacket.RecvCtx,
  our_channel : UInt32,
  queue : OpenQueue,
) -> OpenConfirmation? {
  let mut rounds = 0
  while rounds < 256 {
    rounds = rounds + 1
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => return None
      BadPacket(_) => return None
      Packet(t, payload) => {
        if t == @sshwire.SSH_MSG_CHANNEL_OPEN {
          queue.push(payload)
          continue
        }
        if t == @sshwire.SSH_MSG_CHANNEL_OPEN_FAILURE {
          return None
        }
        if t != @sshwire.SSH_MSG_CHANNEL_OPEN_CONFIRMATION {
          continue
        }
        // uint32 recipient || uint32 sender || uint32 window || uint32 max packet
        let recipient = match sd_read_u32(payload, 0) {
          None => continue
          Some(v) => v
        }
        if recipient != our_channel {
          continue
        }
        let peer_channel = match sd_read_u32(payload, 4) {
          None => return None
          Some(v) => v
        }
        let peer_window = match sd_read_u32(payload, 8) {
          None => return None
          Some(v) => v
        }
        let peer_max_packet = match sd_read_u32(payload, 12) {
          None => return None
          Some(v) => v
        }
        return Some({ peer_channel, peer_window, peer_max_packet, })
      }
    }
  }
  None
}
