///| Loop #91: an INTERACTIVE subsystem byte link.
///
/// ## Why this exists next to `run_sftp_session`
///
/// `sftp.mbt` runs a whole subsystem session **scripted**: it is handed the
/// complete op list up front and drives it to completion.  That shape is
/// what `src/sftp`'s known-answer tests want and it is exactly wrong for
/// `scp`, which must read an answer before it can decide what to ask next
/// (`stat` decides file-versus-directory, a listing decides how many
/// children to descend into).
///
/// This is the other shape: the same connect → auth → open → `subsystem` →
/// wait-for-CHANNEL_SUCCESS sequence, but it *stops* after the confirmation
/// and hands back two operations -- write these bytes, read some bytes --
/// that a caller can drive one request at a time.  `src/sftpdrive` already
/// establishes the same split one layer up, so this file is the transport
/// half of that decision and not a second protocol implementation.
///
/// ## The two things that are easy to get wrong here
///
/// 1. **A write may have to read.**  `ChanState::stdin_take` clamps to the
///    peer's window, and when the window is exhausted the only way to make
///    progress is to receive: the peer's `WINDOW_ADJUST` is what reopens
///    it.  Receiving while a write is in flight can deliver `CHANNEL_DATA`
///    the caller has not asked for yet, so it is buffered here and handed
///    out on the next `read`.  Dropping it would lose protocol bytes and
///    the failure would look like a server that stopped talking.
/// 2. **End of stream is an empty array, not an error.**  `SftpDrive`'s
///    read contract says a closed link reads as empty -- "the transports
///    cannot tell a closed pipe from a closed channel and neither can
///    this" (`src/sftpdrive/drive.mbt`) -- so a closed channel and a
///    failed one both have to arrive as empty and the drive decides.

///|
/// What can go wrong before there is a link at all.
///
/// Once the link exists, failures inside it are reported the way the drive
/// expects: a read that cannot continue returns empty.
pub(all) enum SftpLinkError {
  /// 认证没过
  AuthFailed(AuthError)
  /// 通道层出错：open 没被确认、子系统被拒、包坏了
  ChannelFailed(ExecError)
  /// 认证过了但没有 `SessionState`，后面什么也做不了
  NoSession
}

///|
/// An interactive byte link over a session channel whose subsystem is
/// already running.
///
/// The fields are mutable because the link owns the sequence numbers, the
/// receive context and the window state for as long as it lives -- that is
/// the whole difference from the scripted path, which keeps the same state
/// in local variables of one big function.
pub struct SftpLink[T] {
  priv conn : T
  priv st : SessionState
  priv mut chan : @channel.ChanState
  /// Bytes received while a write needed the window reopened.  Handed out
  /// by the next `read`.
  priv mut pending : FixedArray[Byte]
  priv mut finished : Bool
  /// How many datagrams were received in total -- the link's own idea of
  /// "the far end is still there", used only by diagnostics.
  priv mut packets_in : Int32
}

///|
/// Send bytes to the subsystem.
///
/// `false` means the link is finished and nothing more can be sent.  A
/// partial write is not possible: the loop either places every byte or
/// gives up when the link dies.
pub fn[T : @transport.Transport] SftpLink::write(
  self : SftpLink[T],
  data : FixedArray[Byte],
) -> Bool {
  let mut rest = data
  let mut spins = 0
  while rest.length() > 0 {
    if self.finished {
      return false
    }
    spins = spins + 1
    // A window that never reopens would otherwise spin forever: the peer
    // is not obliged to send WINDOW_ADJUST, and "waited a very long time"
    // and "waited forever" have to be told apart.
    if spins > 4096 {
      return false
    }
    let (c1, action, left) = self.chan.stdin_take(rest)
    self.chan = c1
    match action {
      None =>
        // Window exhausted: receive instead of retrying.  Anything that
        // arrives is data the caller has not asked for yet, so it is
        // buffered rather than dropped.
        if !self.step() {
          return false
        }
      Some(a) => {
        match self.send(a) {
          false => return false
          true => ()
        }
        rest = left
      }
    }
  }
  true
}

///|
/// Read whatever has arrived, up to one packet's worth.
///
/// An empty array means the link is finished; the caller cannot tell that
/// from "nothing arrived yet", which is the contract `SftpDrive` was built
/// for.
pub fn[T : @transport.Transport] SftpLink::read(
  self : SftpLink[T],
) -> FixedArray[Byte] {
  if self.pending.length() > 0 {
    let out = self.pending
    self.pending = FixedArray::make(0, b'\x00')
    return out
  }
  // The reply may already be sitting in the channel's buffer, in which case
  // receiving again would block waiting for a packet that has been counted
  // twice.
  let (c0, out0) = self.chan.take_stdout()
  self.chan = c0
  if out0.length() > 0 {
    return out0
  }
  let mut rounds = 0
  while rounds < 4096 {
    rounds = rounds + 1
    if self.finished {
      return FixedArray::make(0, b'\x00')
    }
    if !self.step() {
      return FixedArray::make(0, b'\x00')
    }
    let (c1, out) = self.chan.take_stdout()
    self.chan = c1
    if out.length() > 0 {
      return out
    }
    if self.chan.close_recv {
      self.finished = true
      return FixedArray::make(0, b'\x00')
    }
  }
  FixedArray::make(0, b'\x00')
}

///|
/// Whether the link is finished.
pub fn[T] SftpLink::is_finished(self : SftpLink[T]) -> Bool {
  self.finished || self.chan.close_recv
}

///|
/// How many datagrams the link received.
pub fn[T] SftpLink::packets_in(self : SftpLink[T]) -> Int32 {
  self.packets_in
}

///|
/// Receive one packet and let the channel state machine consume it.
///
/// Returns whether the link is still usable.  Data that arrives is left in
/// `chan.stdout` for `take_stdout` -- including the data this function
/// receives while a WRITE is in flight, which `write` moves into `pending`
/// so it is not lost.
fn[T : @transport.Transport] SftpLink::step(self : SftpLink[T]) -> Bool {
  match recv_packet(self.conn, self.st.counters, self.st.recv) {
    Closed => {
      self.finished = true
      false
    }
    BadPacket(_) => {
      self.finished = true
      false
    }
    Packet(t, pl) => {
      self.packets_in = self.packets_in + 1
      let (chan2, actions, err) = @channel.chan_step(self.chan, t, pl)
      self.chan = chan2
      for i = 0; i < actions.length(); i = i + 1 {
        if !self.send(actions[i]) {
          return false
        }
      }
      match err {
        None => true
        Some(_) => {
          // A channel-level error is terminal for this link: the drive will
          // see an empty read and report a link failure, which is what
          // happened.
          self.finished = true
          false
        }
      }
    }
  }
}

///|
/// Send one channel action.
fn[T : @transport.Transport] SftpLink::send(
  self : SftpLink[T],
  a : @channel.ChanAction,
) -> Bool {
  match a {
    @channel.Send(t, payload) => {
      let ok = send_packet(
        self.conn,
        self.st.counters,
        self.st.send,
        t,
        payload,
      )
      if !ok {
        self.finished = true
      }
      ok
    }
  }
}

///|
/// Authenticate, then open a session channel and start a subsystem.
///
/// The four steps are the ones `run_sftp_session` takes, in the same order,
/// and for the same reasons:
///
///  1. CHANNEL_OPEN, wait for the confirmation -- the recipient id of every
///     later request comes from it;
///  2. `subsystem` with `want_reply = TRUE`;
///  3. wait for CHANNEL_SUCCESS, because a refusal is the ONLY signal that
///     the name was wrong (session.c:1945-1948) and sending the subsystem's
///     first request into a refused channel fails much less legibly;
///  4. hand back the link.
pub fn[T : @transport.Transport] live_sftp_link(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  subsystem : String,
  kh : @knownhosts.KnownHostsPolicy,
) -> Result[SftpLink[T], SftpLinkError] {
  live_sftp_link_curve(conn, x, user, d, @ecdsa.Curve::p256(), subsystem, kh)
}

///|
/// `live_sftp_link`, with the signing curve named.
///
/// Separate rather than a default argument because the curve is a property
/// of the KEY FILE, not of the transport: a P-384 file has to sign with
/// P-384 or the server rejects the user key for being of the wrong type.
pub fn[T : @transport.Transport] live_sftp_link_curve(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  curve : @ecdsa.Curve,
  subsystem : String,
  kh : @knownhosts.KnownHostsPolicy,
) -> Result[SftpLink[T], SftpLinkError] {
  let (auth, state_opt) = live_auth_curve_with_state(
    conn, x, user, d, curve, kh,
  )
  match auth {
    Authenticated(_) => ()
    Failed(e) => return Err(SftpLinkError::AuthFailed(e))
  }
  let st = match state_opt {
    None => return Err(SftpLinkError::NoSession)
    Some(v) => v
  }
  open_link(conn, st, subsystem)
}

///|
/// Steps 1-4 above, from an already authenticated session.
fn[T : @transport.Transport] open_link(
  conn : T,
  st0 : SessionState,
  subsystem : String,
) -> Result[SftpLink[T], SftpLinkError] {
  let mut st = st0
  let mut chan = @channel.ChanState::new(@channel.LOCAL_CHANNEL)

  // 1) CHANNEL_OPEN
  match
    send_packet(
      conn,
      st.counters,
      st.send,
      0x5a,
      match chan.open_action() {
        @channel.Send(_, payload) => payload
      },
    ) {
    false => return Err(SftpLinkError::ChannelFailed(ExecError::SendFailed))
    true => ()
  }
  // 2) wait for OPEN_CONFIRMATION
  match wait_for(conn, st, chan, 0) {
    Err(e) => return Err(e)
    Ok(v) => {
      st = v.0
      chan = v.1
    }
  }
  if !chan.open_done {
    return Err(
      SftpLinkError::ChannelFailed(ExecError::Malformed("no_open_confirmation")),
    )
  }
  // 3) the subsystem request, then wait for its answer
  match chan.subsystem_action(subsystem) {
    None =>
      return Err(
        SftpLinkError::ChannelFailed(
          ExecError::Malformed("subsystem_before_open"),
        ),
      )
    Some(a) =>
      match strip_send(a) {
        None => return Err(SftpLinkError::ChannelFailed(ExecError::SendFailed))
        Some((t, payload)) =>
          if !send_packet(conn, st.counters, st.send, t, payload) {
            return Err(SftpLinkError::ChannelFailed(ExecError::SendFailed))
          }
      }
  }
  match wait_for(conn, st, chan, 1) {
    Err(e) => return Err(e)
    Ok(v) => {
      st = v.0
      chan = v.1
    }
  }
  if chan.success_count < 1 {
    return Err(SftpLinkError::ChannelFailed(ExecError::SubsystemRejected))
  }
  Ok({
    conn,
    st,
    chan,
    pending: FixedArray::make(0, b'\x00'),
    finished: false,
    packets_in: 0,
  })
}

///|
/// Pump until `mode`'s condition holds.
///
/// `mode == 0` waits for the channel to be open, `mode == 1` for the
/// subsystem answer.  A bounded number of rounds rather than a deadline:
/// the transport has no clock here, and a loop that cannot make progress
/// must end in a diagnosis rather than in a hang.
fn[T : @transport.Transport] wait_for(
  conn : T,
  st0 : SessionState,
  chan0 : @channel.ChanState,
  mode : Int32,
) -> Result[(SessionState, @channel.ChanState), SftpLinkError] {
  let st = st0
  let mut chan = chan0
  let mut rounds = 0
  while rounds < 64 {
    rounds = rounds + 1
    match recv_packet(conn, st.counters, st.recv) {
      Closed =>
        return Err(SftpLinkError::ChannelFailed(ExecError::BadPacket("closed")))
      BadPacket(why) =>
        return Err(SftpLinkError::ChannelFailed(ExecError::BadPacket(why)))
      Packet(t, pl) => {
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        for i = 0; i < actions.length(); i = i + 1 {
          match strip_send(actions[i]) {
            None =>
              return Err(SftpLinkError::ChannelFailed(ExecError::SendFailed))
            Some((at, payload)) =>
              if !send_packet(conn, st.counters, st.send, at, payload) {
                return Err(SftpLinkError::ChannelFailed(ExecError::SendFailed))
              }
          }
        }
        match err {
          None => ()
          Some(e) => return Err(SftpLinkError::ChannelFailed(chan_error(e)))
        }
        let done = if mode == 0 {
          chan.open_done
        } else {
          chan.success_count >= 1
        }
        if done {
          return Ok((st, chan))
        }
      }
    }
  }
  Err(SftpLinkError::ChannelFailed(ExecError::Malformed("no_answer")))
}

///|
/// A `ChanAction` as a type and a payload.
fn strip_send(a : @channel.ChanAction) -> (Byte, FixedArray[Byte])? {
  match a {
    @channel.Send(t, payload) => Some((t, payload))
  }
}
