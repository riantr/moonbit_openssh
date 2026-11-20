///| Loop #94: the server's half of the connection protocol (RFC 4254).
///
/// Loop #93 finished the handshake and the authentication.  What is left
/// between a logged-in client and a command is RFC 4254, and every rule in
/// it here was MEASURED against the real OpenSSH server on this machine
/// rather than recalled from the RFC.
///
/// ## The oracle, and what it said
///
/// The peer is the real `sshd` (`C:\Program Files\OpenSSH-Win64\sshd.exe`,
/// OpenSSH_for_Windows_8.0) and the real `ssh.exe`.  Three witnesses were
/// used, because one of them lies:
///
///   * the **server's own DEBUG3 log** (`.loop94/bed-real/sshd.log_loop94v`),
///     which names every packet it sends and receives;
///   * the **real client's** `-vvv` log, which names every packet it sees;
///   * **paramiko** (an independent implementation), which reports the
///     numbers in the CHANNEL_OPEN_CONFIRMATION directly.
///
/// The client's log line `channel 0: open confirm rwindow 0 rmax 32768`
/// says the window is ZERO.  It is not: paramiko read the same bytes and
/// says the window is 2097152.  The client prints the window it has
/// AVAILABLE, not the window the server offered -- so that line is a
/// witness about the client, and believing it would have produced a server
/// that grants the peer nothing.
///
/// ## The message order, as the server actually sends it
///
/// ```
///   <- CHANNEL_OPEN          "session"          (the peer)
///   -> CHANNEL_OPEN_CONFIRMATION                 recipient=peer, sender=ours
///                                                window=2097152, max packet=32768
///   <- GLOBAL_REQUEST        no-more-sessions@openssh.com   (want_reply=FALSE)
///   <- GLOBAL_REQUEST        hostkeys-00@openssh.com        (want_reply=FALSE)
///   <- CHANNEL_REQUEST       "exec"             (want_reply=TRUE)
///   -> CHANNEL_SUCCESS                           (99)
///   -> CHANNEL_DATA           the command's stdout          (94)
///   -> CHANNEL_EXTENDED_DATA  the command's stderr          (95, code 1)
///   -> CHANNEL_EOF                              (96)
///   -> CHANNEL_REQUEST       "exit-status"       (want_reply=FALSE) + u32 code
///   -> CHANNEL_CLOSE                            (97)
///   <- CHANNEL_CLOSE                            (97)
/// ```
///
/// Two things in that list are easy to get wrong:
///
///   * **the EOF comes BEFORE the exit-status.**  The exit status is a
///     CHANNEL_REQUEST, not a byte of stdout, and the real server sends it
///     after it has closed its own output direction.  A client that waits
///     for the exit status before it reads the data deadlocks.
///   * **the exit-status request carries `want_reply = FALSE`.**  The
///     server does not wait for an answer to it.
///
/// ## What the command is
///
/// The real server runs the command through the login shell, and on Windows
/// that shell is `cmd.exe`.  Its DEBUG3 log says:
///
/// ```
///   spawn_argv[0]: "c:\windows\system32\cmd.exe" /c "cmd /c echo loop94-stdout"
/// ```
///
/// -- the command string is ONE argument, wrapped in quotes.  That detail is
/// not cosmetic.  cmd.exe's rule for the argument of `/c` is: if the first
/// character is a quote, strip it and remove the LAST quote character on the
/// command line.  So `cmd /c "cmd /c echo hello"` echoes `hello"` -- with a
/// trailing quote -- and that quote is in the bytes the client receives.
/// The same rule is why the redirections `> out 2> err` CANNOT be used to
/// separate stdout from stderr: with them on the command line the last
/// quote is the one closing `err`, the whole tail becomes the command, and
/// `echo` prints it.  Measured, in `.loop94/cmdline_probe.py`.
///
/// So the separation of the two streams has to happen in the HANDLES, and
/// that is what `src/subproc`'s third pipe is for.

///|
/// The bytes a command produced.
pub struct CommandResult {
  /// Everything the command wrote to its standard output.
  stdout : FixedArray[Byte]
  /// Everything the command wrote to its standard error.
  stderr : FixedArray[Byte]
  /// The command's exit status.
  code : Int32
}

///|
/// Build a `CommandResult`.
pub fn CommandResult::make(
  stdout : FixedArray[Byte],
  stderr : FixedArray[Byte],
  code : Int32,
) -> CommandResult {
  { stdout, stderr, code, }
}

///|
/// Runs commands for the server.
///
/// The server does not know how to start a process: that is native-only
/// work, and `src/sshd` is a package that builds for all four backends.  So
/// the driver hands the state machine a function and the state machine calls
/// it -- the same shape `src/sftpserver`'s `ServerFs` uses for the
/// filesystem.
pub struct CommandRunner {
  /// Run the command and return what it produced.
  run_fn : (String) -> CommandResult
}

///|
/// Build a `CommandRunner`.
pub fn CommandRunner::make(run_fn : (String) -> CommandResult) -> CommandRunner {
  { run_fn, }
}

///|
/// The filesystem and the clock the SFTP subsystem answers with.
///
/// The same problem `CommandRunner` solves, one layer down: the server does
/// not know how to touch a filesystem, and `src/sshd` is a package that
/// builds for all four backends.  So the driver hands the state machine the
/// two things the rules need and the state machine calls them.
///
/// The RULES are not here.  Which request produces which reply is
/// `src/sftpserver`'s, and the framing is `src/sftp`'s; this package only
/// moves bytes between the channel and that state machine.  A second copy of
/// those rules would be a second thing to keep in step with the first.
pub struct SftpProvider {
  /// The filesystem the SFTP requests are about.
  fs : @sftpserver.ServerFs
  /// The clock the SFTP replies report times from.
  clock : @sftpserver.ServerClock
}

///|
/// Build an `SftpProvider`.
pub fn SftpProvider::make(
  fs : @sftpserver.ServerFs,
  clock : @sftpserver.ServerClock,
) -> SftpProvider {
  { fs, clock, }
}

///|
/// The name of the one subsystem this server has.
///
/// The real `sshd` runs a program for a subsystem, and the program it runs
/// for `sftp` is `sftp-server`.  This server has the RULES of that program
/// (`src/sftpserver`) and not a program to run, so the subsystem is a name
/// that selects the rules rather than a name that selects an executable.
pub const SUBSYSTEM_SFTP : String = "sftp"

///|
/// What the channel phase did.
///
/// The fields are `mut` because the phase is a sequence of events and the
/// report is filled in as they happen: the channel is opened first, the
/// command is known only once the exec request arrives, and the exit status
/// only after the command has run.  A record that could not be updated in
/// place would have to be rebuilt at every step, which is three copies of
/// the same six fields and three places for them to drift apart.
pub struct ChannelReport {
  /// The channel number the peer opened.
  peer_channel : UInt32
  /// The command that was run, or "" if none was.
  mut command : String
  /// The command's exit status, or -1 if none ran.
  mut exit_status : Int32
  /// How many bytes of stdout were sent.
  mut stdout_bytes : Int32
  /// How many bytes of stderr were sent.
  mut stderr_bytes : Int32
  /// How many bytes of SFTP replies were sent on this channel.
  ///
  /// Zero unless the peer asked for the `sftp` subsystem.  It is here
  /// because "the subsystem ran" is a claim, and the number of bytes it
  /// produced is the part of that claim a gate can check against the
  /// client's own.
  mut sftp_bytes : Int32
  /// How many SFTP requests were answered.
  mut sftp_requests : Int32
  /// Whether the peer closed the channel.
  mut peer_closed : Bool
}

///|
/// The window the server advertises for the peer's data.
///
/// Measured: the real server's CHANNEL_OPEN_CONFIRMATION carried 2097152,
/// read by paramiko from the real server's own bytes.
pub const SERVER_WINDOW : UInt32 = 2097152U

///|
/// The largest packet the server accepts from the peer.
///
/// Measured: 32768, the same value the real server sends.
pub const SERVER_MAX_PACKET : UInt32 = 32768U

///|
/// The channel number this server uses for its own side.
///
/// The server opens no channels of its own in this loop, so the first one is
/// 0 -- and the peer opened 0 too, which is not a problem: the two numbers
/// live in different directions.
pub const SERVER_CHANNEL : UInt32 = 0U

///|
/// The channel type this server accepts.
pub const CHANNEL_TYPE_SESSION : String = "session"

///|
/// The data code that means "standard error" (RFC 4254 §5.2).
pub const EXTENDED_DATA_STDERR : UInt32 = 1U

///|
/// Reason code 3: the channel type is not one this server knows.
///
/// RFC 4254 §5.1 calls it `SSH_OPEN_UNKNOWN_CHANNEL_TYPE`.
pub const OPEN_UNKNOWN_CHANNEL_TYPE : UInt32 = 3U

///|
/// A CHANNEL_OPEN, read off the wire.
pub(all) struct ChannelOpen {
  /// The type the peer asked for.
  channel_type : String
  /// The channel number the peer will use.
  peer_channel : UInt32
  /// How many bytes the peer will take from us.
  peer_window : UInt32
  /// The largest packet the peer accepts.
  peer_max_packet : UInt32
}

///|
/// Read a CHANNEL_OPEN payload.
///
/// RFC 4254 §5.1, in the form the implementations actually use:
///
/// ```
///   string  channel type
///   uint32  sender channel number
///   uint32  initial window size
///   uint32  maximum packet size
/// ```
///
/// There is NO `string sender channel` field between the type and the
/// number.  Reading one is what made Loop #93's server refuse channel
/// 2097152 (the window size) instead of channel 0, and the peer answered
/// `open failure packet referred to nonexistent channel 2097152`.
///
/// Measured: the real `ssh.exe` sends a 23-byte CHANNEL_OPEN payload --
/// `00000007 "session" 00000000 00200000 00008000`.
pub fn sd_parse_channel_open(payload : FixedArray[Byte]) -> ChannelOpen? {
  let (type_b, off1) = match sd_read_string(payload, 0) {
    None => return None
    Some(v) => v
  }
  let peer_channel = match sd_read_u32(payload, off1) {
    None => return None
    Some(v) => v
  }
  let peer_window = match sd_read_u32(payload, off1 + 4) {
    None => return None
    Some(v) => v
  }
  let peer_max_packet = match sd_read_u32(payload, off1 + 8) {
    None => return None
    Some(v) => v
  }
  Some({
    channel_type: sd_bytes_to_string(type_b),
    peer_channel,
    peer_window,
    peer_max_packet,
  })
}

///|
/// The CHANNEL_OPEN_CONFIRMATION payload.
///
/// ```
///   uint32  recipient channel   (the peer's number)
///   uint32  sender channel      (ours)
///   uint32  initial window size
///   uint32  maximum packet size
/// ```
///
/// The two numbers are in the order that surprises people: the RECIPIENT is
/// the peer's number and the SENDER is ours.  Getting them the other way
/// round does not fail the handshake -- it makes every later packet address
/// a channel that does not exist, and the peer ignores all of them.
pub fn sd_open_confirmation_payload(
  peer_channel : UInt32,
  our_channel : UInt32,
  window : UInt32,
  max_packet : UInt32,
) -> FixedArray[Byte] {
  sd_cat2(
    sd_cat2(@sshwire.write_u32(peer_channel), @sshwire.write_u32(our_channel)),
    sd_cat2(@sshwire.write_u32(window), @sshwire.write_u32(max_packet)),
  )
}

///|
/// The CHANNEL_OPEN_FAILURE payload.
///
/// ```
///   uint32  recipient channel
///   uint32  reason code
///   string  description
///   string  language tag
/// ```
///
/// FOUR fields, not three.  Leaving the language tag out leaves the peer
/// reading the next packet's bytes as the tag -- which is how Loop #93's
/// server produced a refusal the client could not parse.
pub fn sd_open_failure_payload(
  peer_channel : UInt32,
  reason : UInt32,
  description : String,
) -> FixedArray[Byte] {
  sd_cat3(
    @sshwire.write_u32(peer_channel),
    @sshwire.write_u32(reason),
    sd_cat2(
      @sshwire.write_ssh_string(sd_ascii(description)),
      // the language tag: present, and empty
      @sshwire.write_ssh_string(FixedArray::make(0, b'\x00')),
    ),
  )
}

///|
/// The CHANNEL_DATA payload: `uint32 recipient || string data`.
pub fn sd_data_payload(
  peer_channel : UInt32,
  data : FixedArray[Byte],
) -> FixedArray[Byte] {
  sd_cat2(@sshwire.write_u32(peer_channel), @sshwire.write_ssh_string(data))
}

///|
/// The CHANNEL_EXTENDED_DATA payload.
///
/// ```
///   uint32  recipient channel
///   uint32  data type code
///   string  data
/// ```
///
/// The code is 1 for standard error, and that is the whole difference
/// between the two streams on the wire.
pub fn sd_extended_data_payload(
  peer_channel : UInt32,
  code : UInt32,
  data : FixedArray[Byte],
) -> FixedArray[Byte] {
  sd_cat3(
    @sshwire.write_u32(peer_channel),
    @sshwire.write_u32(code),
    @sshwire.write_ssh_string(data),
  )
}

///|
/// The payload of the messages that carry nothing but a channel number:
/// CHANNEL_SUCCESS, CHANNEL_FAILURE, CHANNEL_EOF and CHANNEL_CLOSE.
pub fn sd_bare_payload(peer_channel : UInt32) -> FixedArray[Byte] {
  @sshwire.write_u32(peer_channel)
}

///|
/// The CHANNEL_WINDOW_ADJUST payload.
///
/// ```
///   uint32  recipient channel
///   uint32  bytes to add to the window
/// ```
///
/// The number is an ADDITION and not the new size: RFC 4254 §5.2 says the
/// receiver adds it to what it has already granted.  Sending the new total
/// instead would grant the peer the window twice over.
pub fn sd_window_adjust_payload(
  peer_channel : UInt32,
  add : UInt32,
) -> FixedArray[Byte] {
  sd_cat2(@sshwire.write_u32(peer_channel), @sshwire.write_u32(add))
}

///|
/// Whether the peer's window has fallen below the half and needs topping up.
///
/// The peer may send `window_max` bytes before it has to wait for a
/// WINDOW_ADJUST, so the window is topped back up once it is BELOW half.
/// Waiting until it is empty would stop the peer in the middle of a file,
/// and topping it up on every packet would be a packet per window.
pub fn sd_window_needs_top_up(recv_left : Int32, window_max : Int32) -> Bool {
  recv_left * 2 < window_max
}

///|
/// The CHANNEL_REQUEST payload for "exit-status".
///
/// ```
///   uint32  recipient channel
///   string  "exit-status"
///   boolean FALSE
///   uint32  exit status
/// ```
///
/// `want_reply` is FALSE: the server tells the client the status and does
/// not wait for an answer.
pub fn sd_exit_status_payload(
  peer_channel : UInt32,
  code : Int32,
) -> FixedArray[Byte] {
  sd_cat3(
    @sshwire.write_u32(peer_channel),
    sd_cat2(
      @sshwire.write_ssh_string(sd_ascii("exit-status")),
      FixedArray::from_array([b'\x00']),
    ),
    @sshwire.write_u32(code.reinterpret_as_uint()),
  )
}

///|
/// A CHANNEL_REQUEST, read off the wire.
pub(all) struct ChannelRequest {
  /// The channel the request is about.
  recipient : UInt32
  /// What is being asked for.
  request_type : String
  /// Whether the peer wants an answer.
  want_reply : Bool
  /// The bytes after the common prefix.
  extra : FixedArray[Byte]
}

///|
/// Read a CHANNEL_REQUEST payload.
///
/// ```
///   uint32  recipient channel
///   string  request type
///   boolean want reply
///   ...     type-specific
/// ```
pub fn sd_parse_channel_request(payload : FixedArray[Byte]) -> ChannelRequest? {
  let recipient = match sd_read_u32(payload, 0) {
    None => return None
    Some(v) => v
  }
  let (type_b, off2) = match sd_read_string(payload, 4) {
    None => return None
    Some(v) => v
  }
  let want = match sd_read_u8(payload, off2) {
    None => return None
    Some(v) => v
  }
  let extra = match sd_slice(payload, off2 + 1, payload.length() - off2 - 1) {
    None => return None
    Some(v) => v
  }
  Some({
    recipient,
    request_type: sd_bytes_to_string(type_b),
    want_reply: want != b'\x00',
    extra,
  })
}

///|
/// How many bytes may go into one CHANNEL_DATA.
///
/// The smaller of the two limits: the peer's maximum packet size, and what
/// is left of its window.  A packet that is larger than the peer's maximum
/// is a protocol error, and one that is larger than the window is a lie
/// about the window.
pub fn sd_chunk_size(peer_window : UInt32, peer_max_packet : UInt32) -> Int32 {
  let mut n = if peer_max_packet > 32768U {
    32768
  } else {
    peer_max_packet.reinterpret_as_int()
  }
  // The window is the other limit, and it is compared against what is left
  // AFTER the 32 KiB clamp.  Comparing it against the peer's maximum packet
  // instead would let a window of 40000 and a maximum of 65536 through as
  // 40000 -- a packet bigger than the 32 KiB this server promised, and
  // bigger than the peer ever asked for.
  let w = peer_window.reinterpret_as_int()
  if w < n {
    n = w
  }
  n
}

///|
/// Send one stream as CHANNEL_DATA or CHANNEL_EXTENDED_DATA.
///
/// Returns whether the whole stream went out, and how much of the peer's
/// window is left.  The window is passed in and returned rather than kept
/// in a struct, because a struct that is passed by value would quietly
/// lose the update -- and the window is the one number in this protocol
/// that has to be right across calls.
fn[T : @transport.Transport] sd_send_stream(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  peer_channel : UInt32,
  peer_window : UInt32,
  peer_max_packet : UInt32,
  data : FixedArray[Byte],
  extended : Bool,
) -> (Bool, UInt32) {
  let mut window = peer_window
  let mut off = 0
  while off < data.length() {
    let room = sd_chunk_size(window, peer_max_packet)
    if room <= 0 {
      // The window is empty.  The caller has to wait for a WINDOW_ADJUST.
      return (false, window)
    }
    let take = if data.length() - off < room {
      data.length() - off
    } else {
      room
    }
    let piece = match sd_slice(data, off, take) {
      None => return (false, window)
      Some(v) => v
    }
    let msg_type = if extended {
      @sshwire.SSH_MSG_CHANNEL_EXTENDED_DATA
    } else {
      @sshwire.SSH_MSG_CHANNEL_DATA
    }
    let payload = if extended {
      sd_extended_data_payload(peer_channel, EXTENDED_DATA_STDERR, piece)
    } else {
      sd_data_payload(peer_channel, piece)
    }
    if !sd_send_packet(conn, counters, send_ctx, msg_type, payload) {
      return (false, window)
    }
    window = window - take.reinterpret_as_uint()
    off = off + take
  }
  (true, window)
}

///|
/// What the SFTP subsystem did on the channel.
pub(all) struct SftpOutcome {
  /// How many bytes of SFTP replies were sent.
  mut bytes_sent : Int32
  /// How many SFTP requests were answered.
  mut requests : Int32
  /// Whether the peer's CHANNEL_CLOSE was read.
  mut peer_closed : Bool
  /// How much of the peer's window is left.
  mut window_left : UInt32
}

///|
/// Run the SFTP subsystem on this channel until the peer is done.
///
/// The RULES are `src/sftpserver`'s and the FRAMING is `src/sftp`'s.  What
/// this loop owns is the part that is about the CHANNEL and not about SFTP:
///
///   * the peer's bytes go into `SftpInbuf`, which knows the two facts the
///     protocol insists on: one CHANNEL_DATA can carry several requests,
///     and one request can span several of them;
///   * the replies go out in the order the requests came in, cut to what is
///     left of the peer's window -- a READDIR or a READ can be bigger than
///     one packet, and a packet bigger than the window is a lie;
///   * the peer's own window is topped back up, because a peer that has sent
///     `SERVER_WINDOW` bytes may not send another one until it is told there
///     is room.
fn[T : @transport.Transport] sd_sftp_loop(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  recv_ctx : @bpacket.RecvCtx,
  peer_channel : UInt32,
  peer_window_in : UInt32,
  peer_max_packet : UInt32,
  provider : SftpProvider,
) -> SftpOutcome {
  let state = @sftpserver.ServerState::new(provider.clock)
  let inbuf = @sftp.SftpInbuf::new()
  // The replies that have not gone out yet, and how far into them we are.
  // A reply that does not fit in what is left of the peer's window waits
  // here until the peer says it has room, and the order is the order the
  // requests came in -- which is what the protocol requires of the replies.
  let mut out : Array[Byte] = []
  let mut out_off = 0
  let mut peer_window = peer_window_in
  // What the peer may still send us, counted against the window this server
  // advertised in its CHANNEL_OPEN_CONFIRMATION.
  let window_max = SERVER_WINDOW.reinterpret_as_int()
  let mut recv_left = window_max
  let outcome = {
    bytes_sent: 0,
    requests: 0,
    peer_closed: false,
    window_left: peer_window,
  }
  let mut peer_eof = false
  let mut transport_gone = false
  let mut done = false
  while !done {
    // ---- send what is waiting, as far as the window allows ----
    while out_off < out.length() {
      let room = sd_chunk_size(peer_window, peer_max_packet)
      if room <= 0 {
        // The window is empty.  The peer has to send a WINDOW_ADJUST
        // before anything more can go out, and the read below is where
        // that arrives.
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
      outcome.bytes_sent = outcome.bytes_sent + take
      out_off = out_off + take
    }
    if done {
      break
    }
    if out_off >= out.length() {
      // Everything has gone out; start the next reply from the beginning.
      out = []
      out_off = 0
    }
    if peer_eof && out.length() == 0 {
      // The peer will send no more requests, and everything we had to say
      // has been said.
      break
    }
    // ---- read one packet ----
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
        if t == @sshwire.SSH_MSG_CHANNEL_WINDOW_ADJUST {
          match sd_read_u32(payload, 4) {
            None => ()
            Some(n) => peer_window = peer_window + n
          }
          continue
        }
        if t == @sshwire.SSH_MSG_CHANNEL_DATA {
          // `uint32 recipient channel || string data`
          let data = match sd_read_string(payload, 4) {
            None => FixedArray::make(0, b'\x00')
            Some((b, _)) => b
          }
          inbuf.feed(data)
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
              sd_window_adjust_payload(peer_channel, give.reinterpret_as_uint()),
            )
            recv_left = window_max
          }
          // Every complete request in what just arrived.  One CHANNEL_DATA
          // can carry several, and one can be split across several.
          let mut again = true
          while again {
            match inbuf.take() {
              None => again = false
              Some(body) => {
                let req = @sftpserver.parse_request(body)
                match state.reply(provider.fs, req) {
                  // An unknown request type gets NO reply at all, and the
                  // real server goes on to answer the next one.
                  None => ()
                  Some(reply) => {
                    let framed = @sftp.sftp_frame(reply)
                    for i = 0; i < framed.length(); i = i + 1 {
                      out.push(framed[i])
                    }
                    outcome.requests = outcome.requests + 1
                  }
                }
              }
            }
          }
          continue
        }
        if t == @sshwire.SSH_MSG_CHANNEL_EOF {
          // The peer will send no more requests.
          peer_eof = true
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
  // ---- the closing sequence ----
  //
  // The order is the real server's: our EOF, then the exit status, then the
  // close.  And the close is followed by a READ, because the peer answers a
  // CLOSE with its own, and closing the socket while that answer is in
  // flight turns the close into a TCP RESET -- which throws away whatever
  // the peer has not read yet.  Measured in Loop #94.
  if !transport_gone {
    if outcome.peer_closed {
      // The peer closed first.  The answer to a CLOSE is a CLOSE and
      // nothing else: the channel is over.
      let _ = sd_send_packet(
        conn,
        counters,
        send_ctx,
        @sshwire.SSH_MSG_CHANNEL_CLOSE,
        sd_bare_payload(peer_channel),
      )
    } else {
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
        @sshwire.SSH_MSG_CHANNEL_REQUEST,
        sd_exit_status_payload(peer_channel, 0),
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
          Packet(t, _) =>
            if t == @sshwire.SSH_MSG_CHANNEL_CLOSE {
              outcome.peer_closed = true
              break
            }
        }
      }
    }
  }
  outcome.window_left = peer_window
  outcome
}

///|
/// Run the connection protocol: accept one session channel, run the command
/// the peer asks for, and report what happened.
///
/// The peer opens a channel as soon as it is authenticated, so this is where
/// the connection ends: the real server sends its data, its exit status and
/// its close, and then the session is over.
pub fn[T : @transport.Transport] serve_channels(
  conn : T,
  counters : WireCounters,
  send_ctx : @bpacket.SendCtx,
  recv_ctx : @bpacket.RecvCtx,
  runner : CommandRunner,
  sftp : SftpProvider?,
) -> ChannelReport {
  let mut peer_channel = 0U
  let mut peer_window = 0U
  let mut peer_max_packet = 0U
  let mut opened = false
  let mut tries = 0
  while !opened && tries < 16 {
    tries = tries + 1
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => break
      BadPacket(_) => break
      Packet(t, payload) => {
        if t != @sshwire.SSH_MSG_CHANNEL_OPEN {
          continue
        }
        match sd_parse_channel_open(payload) {
          None => break
          Some(o) => {
            peer_channel = o.peer_channel
            peer_window = o.peer_window
            peer_max_packet = o.peer_max_packet
            if o.channel_type != CHANNEL_TYPE_SESSION {
              // A channel type we do not have.  The peer is told which one
              // it was, so the refusal is about the channel and not about
              // the connection.
              let _ = sd_send_packet(
                conn,
                counters,
                send_ctx,
                @sshwire.SSH_MSG_CHANNEL_OPEN_FAILURE,
                sd_open_failure_payload(
                  peer_channel,
                  OPEN_UNKNOWN_CHANNEL_TYPE,
                  "only the session channel is implemented by this server",
                ),
              )
              break
            }
            let confirm = sd_open_confirmation_payload(
              peer_channel,
              SERVER_CHANNEL,
              SERVER_WINDOW,
              SERVER_MAX_PACKET,
            )
            if !sd_send_packet(
                conn,
                counters,
                send_ctx,
                @sshwire.SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
                confirm,
              ) {
              break
            }
            opened = true
          }
        }
      }
    }
  }
  let report = {
    peer_channel,
    command: "",
    exit_status: -1,
    stdout_bytes: 0,
    stderr_bytes: 0,
    sftp_bytes: 0,
    sftp_requests: 0,
    peer_closed: false,
  }
  if !opened {
    return report
  }
  // ---- the request loop ----
  //
  // `rounds` is a guard against a peer that never sends anything this loop
  // acts on: every iteration reads one packet, so the bound is "how many
  // packets will this server read before it gives up on getting an exec".
  // The name is not `guard` because that is a MoonBit keyword.
  let mut rounds = 0
  while rounds < 4096 {
    rounds = rounds + 1
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => break
      BadPacket(_) => break
      Packet(t, payload) => {
        if t == @sshwire.SSH_MSG_GLOBAL_REQUEST {
          // `no-more-sessions@openssh.com` and `hostkeys-00@openssh.com`,
          // both with want_reply=FALSE.  The real server answers neither,
          // and a server that answered would put a packet in the peer's
          // stream that the peer is not expecting.
          continue
        }
        if t == @sshwire.SSH_MSG_CHANNEL_CLOSE {
          report.peer_closed = true
          break
        }
        if t == @sshwire.SSH_MSG_CHANNEL_WINDOW_ADJUST {
          match sd_read_u32(payload, 4) {
            None => ()
            Some(n) => peer_window = peer_window + n
          }
          continue
        }
        if t == @sshwire.SSH_MSG_CHANNEL_DATA ||
          t == @sshwire.SSH_MSG_CHANNEL_EOF {
          // The peer's stdin.  This server runs the command with its stdin
          // closed, so the bytes are counted against the window and dropped.
          continue
        }
        if t != @sshwire.SSH_MSG_CHANNEL_REQUEST {
          continue
        }
        let req = match sd_parse_channel_request(payload) {
          None => break
          Some(v) => v
        }
        if req.request_type == "env" {
          // No reply: RFC 4254 §6.4 says the server returns nothing for an
          // environment request, and a reply here would be a packet the peer
          // is not expecting.
          continue
        }
        if req.request_type == "subsystem" {
          // `subsystem` is RFC 4254 §6.5: a NAME, and the name is what
          // selects what runs.  This server has exactly one subsystem --
          // `sftp` -- and it is refused by name rather than accepted and
          // then ignored, because a peer that asked for something else and
          // got a silent success would wait for bytes that never come.
          let (name_b, _) = match sd_read_string(req.extra, 0) {
            None => break
            Some(v) => v
          }
          let name = sd_bytes_to_string(name_b)
          if name != SUBSYSTEM_SFTP {
            if req.want_reply {
              let _ = sd_send_packet(
                conn,
                counters,
                send_ctx,
                @sshwire.SSH_MSG_CHANNEL_FAILURE,
                sd_bare_payload(peer_channel),
              )
            }
            continue
          }
          let provider = match sftp {
            None => {
              // The server was started without a filesystem for the
              // subsystem.  Saying so is better than answering SUCCESS and
              // then not answering a single request.
              if req.want_reply {
                let _ = sd_send_packet(
                  conn,
                  counters,
                  send_ctx,
                  @sshwire.SSH_MSG_CHANNEL_FAILURE,
                  sd_bare_payload(peer_channel),
                )
              }
              continue
            }
            Some(p) => p
          }
          if req.want_reply {
            let _ = sd_send_packet(
              conn,
              counters,
              send_ctx,
              @sshwire.SSH_MSG_CHANNEL_SUCCESS,
              sd_bare_payload(peer_channel),
            )
          }
          // The subsystem owns the channel from here on: it reads the
          // peer's requests and answers them until the peer is done.
          let outcome = sd_sftp_loop(
            conn,
            counters,
            send_ctx,
            recv_ctx,
            peer_channel,
            peer_window,
            peer_max_packet,
            provider,
          )
          peer_window = outcome.window_left
          report.command = "subsystem " + name
          report.sftp_bytes = outcome.bytes_sent
          report.sftp_requests = outcome.requests
          report.peer_closed = outcome.peer_closed
          break
        }
        if req.request_type != "exec" {
          // `shell`, `pty-req` and anything else: this server does not do
          // them yet, and saying so is better than accepting and then doing
          // nothing.
          if req.want_reply {
            let _ = sd_send_packet(
              conn,
              counters,
              send_ctx,
              @sshwire.SSH_MSG_CHANNEL_FAILURE,
              sd_bare_payload(peer_channel),
            )
          }
          continue
        }
        // ---- exec ----
        let (cmd_b, _) = match sd_read_string(req.extra, 0) {
          None => break
          Some(v) => v
        }
        let command = sd_bytes_to_string(cmd_b)
        if req.want_reply {
          let _ = sd_send_packet(
            conn,
            counters,
            send_ctx,
            @sshwire.SSH_MSG_CHANNEL_SUCCESS,
            sd_bare_payload(peer_channel),
          )
        }
        let result = (runner.run_fn)(command)
        report.command = command
        report.exit_status = result.code
        // stdout, then stderr, then the EOF, then the exit status, then the
        // close.  The order is the real server's, and it is measured.
        let (_, window_after_out) = sd_send_stream(
          conn,
          counters,
          send_ctx,
          peer_channel,
          peer_window,
          peer_max_packet,
          result.stdout,
          false,
        )
        peer_window = window_after_out
        let (_, window_after_err) = sd_send_stream(
          conn,
          counters,
          send_ctx,
          peer_channel,
          peer_window,
          peer_max_packet,
          result.stderr,
          true,
        )
        peer_window = window_after_err
        report.stdout_bytes = result.stdout.length()
        report.stderr_bytes = result.stderr.length()
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
          @sshwire.SSH_MSG_CHANNEL_REQUEST,
          sd_exit_status_payload(peer_channel, result.code),
        )
        let _ = sd_send_packet(
          conn,
          counters,
          send_ctx,
          @sshwire.SSH_MSG_CHANNEL_CLOSE,
          sd_bare_payload(peer_channel),
        )
        // ---- wait for the peer's CLOSE ----
        //
        // This is NOT politeness, and skipping it does not merely leave a
        // packet unanswered: the client answers our CLOSE with its own, and
        // if we close the socket while that answer is still in flight the
        // close is a TCP RESET rather than a FIN.  A reset throws away
        // whatever the peer has not read yet -- including the exit status we
        // just sent -- and the client reports
        //
        //     client_loop: send disconnect: Connection reset
        //
        // and exits 255 with an empty stdout, even though the command ran
        // and its output was sent.  Measured: that is exactly what happened
        // before this drain was added, and the server's own report said
        // `exit_status: 0 / stdout_bytes: 16` at the same moment.
        //
        // The same reasoning is why Loop #93's channel refusal ended with a
        // read rather than an immediate close.
        let mut drain = 0
        while drain < 64 {
          drain = drain + 1
          match sd_recv_packet(conn, counters, recv_ctx) {
            Closed => break
            BadPacket(_) => break
            Packet(t, _) =>
              if t == @sshwire.SSH_MSG_CHANNEL_CLOSE {
                report.peer_closed = true
                break
              }
          }
        }
        break
      }
    }
  }
  report
}
