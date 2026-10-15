///| Loop #39: an SFTP client, driven over a session channel
///
/// This file is the **transport adapter** and deliberately holds no protocol.
/// Everything above the socket -- which request goes out next, which reply is
/// being waited for, when a READDIR ends, how the READ offset accumulates --
/// lives in `@sftp.SftpSession`, once, for both transports. `src/wtlive` has a
/// near-copy of *this* file and shares that state machine.
///
/// Two things are worth stating here because they are channel-level, not
/// SFTP-level:
///
/// 1. `subsystem` has `want_reply = TRUE`, so the driver waits for
///    CHANNEL_SUCCESS before sending INIT. `exec` also waits; `env` does not
///    and nothing ever answers it (RFC 4254 §6.4). Sending INIT into a channel
///    whose subsystem request was refused is the failure this ordering
///    prevents -- and that refusal is the *only* signal that the name was
///    wrong (session.c:1945-1948).
///
/// 2. Requests leave through `ChanState::stdin_take`, the same window clamp
///    Loop #37 already known-answer-tested, rather than a second copy of it.
///    Clamping mid-packet is fine: the server reassembles, because SFTP framing
///    is a byte stream (`atomicio6`, sftp-client.c:185-204).

///| 驱动层失败的原因
pub(all) enum SftpError {
  /// 认证没过
  AuthFailed(AuthError)
  /// 通道层出错
  ChannelFailed(ExecError)
  /// SFTP 层出错(协议坏了,或者会话自己判定失败)
  Protocol(String)
  /// 包数超限 —— 任何「回包发不出去」没检查的地方都会变成这种死等
  TooManyPackets
  /// 连接在会话结束前被关掉
  Closed
}

///| 一次 SFTP 会话的结果
pub(all) struct SftpReport {
  /// 服务端在 VERSION 里报的协议版本
  version : Int
  /// VERSION 里跟着的扩展对数(sftp-server.c:716-727 会发十一条)
  extensions : Int
  /// 每个操作一个结果,与传入的 ops 一一对应
  ops : Array[@sftp.SftpOpResult]
  requests_sent : Int
  replies_recv : Int
  /// 收到的 SFTP 字节数(重组后的完整包,不含长度前缀)
  sftp_bytes_in : Int
  total_sent_bytes : Int
  total_recv_bytes : Int
}

pub(all) enum SftpOutcome {
  Done(SftpReport)
  Failed(SftpError)
}

///|
/// 跑完整个 SFTP 会话:认证 → 开通道 → subsystem → 等确认 → 脚本。
pub fn[T : @transport.Transport] live_sftp(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  ops : Array[@sftp.SftpOp],
  kh : @knownhosts.KnownHostsPolicy,
) -> SftpOutcome {
  live_sftp_named(conn, x, user, d, "sftp", ops, kh)
}

///|
/// 同 `live_sftp`,但子系统名可以指定。
///
/// 存在的理由只有一个:负面用例。真服务器只认它 `sshd_config` 里 `Subsystem`
/// 配过的名字,而「这个名字不存在」在 want_reply=TRUE 的规则下**必须**表现为
/// CHANNEL_FAILURE;如果驱动层把名字写死成 `sftp`,这一条路径就没法被测到,而
/// 「配置拼错」在真实部署里正是最常见的 SFTP 故障。
pub fn[T : @transport.Transport] live_sftp_named(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  subsystem : String,
  ops : Array[@sftp.SftpOp],
  kh : @knownhosts.KnownHostsPolicy,
) -> SftpOutcome {
  let (auth, state_opt) = live_auth_with_state(conn, x, user, d, kh)
  match auth {
    Authenticated(_) => ()
    Failed(e) => return SftpOutcome::Failed(SftpError::AuthFailed(e))
  }
  let st = match state_opt {
    None => {
      return SftpOutcome::Failed(
        SftpError::ChannelFailed(ExecError::NoSessionState),
      )
    }
    Some(v) => v
  }
  match run_sftp_session(conn, st, subsystem, ops) {
    Ok(r) => SftpOutcome::Done(r)
    Err(e) => SftpOutcome::Failed(e)
  }
}

///|
/// 通道之上的那一小段循环。`SftpSession` 是纯状态机,这里是它和 socket 之间
/// 唯一的接缝。
fn[T : @transport.Transport] run_sftp_session(
  conn : T,
  st0 : SessionState,
  subsystem : String,
  ops : Array[@sftp.SftpOp],
) -> Result[SftpReport, SftpError] {
  let mut st = st0
  let mut chan = @channel.ChanState::new(@channel.LOCAL_CHANNEL)
  let sess = @sftp.SftpSession::new(ops)
  let mut rounds = 0

  // 1) CHANNEL_OPEN
  match send_chan(conn, st, chan.open_action()) {
    None => return Err(SftpError::ChannelFailed(ExecError::SendFailed))
    Some(s) => st = s
  }
  // 2) 等 OPEN_CONFIRMATION
  let opened = match pump_until(conn, st, chan, sess, 0) {
    Err(e) => return Err(e)
    Ok(v) => v
  }
  if !opened.0 {
    return Err(SftpError::ChannelFailed(ExecError::Malformed("no_open_confirmation")))
  }
  st = opened.1
  chan = opened.2

  // 3) subsystem 请求。必须在确认之后 —— recipient 是对端给的号。
  match chan.subsystem_action(subsystem) {
    None => {
      return Err(
        SftpError::ChannelFailed(ExecError::Malformed("subsystem_before_open")),
      )
    }
    Some(a) => {
      match send_chan(conn, st, a) {
        None => return Err(SftpError::ChannelFailed(ExecError::SendFailed))
        Some(s) => st = s
      }
    }
  }
  // 4) **等 CHANNEL_SUCCESS**。want_reply=TRUE,而这个 FAILURE 是「没有这个
  //    子系统」的唯一信号。不等的话 INIT 会打进一个被拒绝的通道,而名字错了
  //    这件事也就永远不会被说出来。
  let acked = match pump_until(conn, st, chan, sess, 1) {
    Err(e) => return Err(e)
    Ok(v) => v
  }
  if !acked.0 {
    return Err(SftpError::ChannelFailed(ExecError::SubsystemRejected))
  }
  st = acked.1
  chan = acked.2

  // 5) 脚本。每轮:把排队的请求送出去 → 收一个包喂进去 → pump。
  while !sess.done() && !sess.failed() {
    rounds = rounds + 1
    if rounds > 200000 {
      return Err(SftpError::TooManyPackets)
    }
    let out = sess.take_out()
    let mut rest : FixedArray[Byte] = FixedArray::make(0, b'\x00')
    for i = 0; i < out.length(); i = i + 1 {
      rest = sftp_cat2(rest, out[i])
    }
    let mut stuck = false
    let mut spins = 0
    while rest.length() > 0 && spins < 4096 {
      spins = spins + 1
      let (c1, action, left) = chan.stdin_take(rest)
      chan = c1
      match action {
        None => {
          stuck = true
          break
        }
        Some(a) => {
          match send_chan(conn, st, a) {
            None => return Err(SftpError::ChannelFailed(ExecError::SendFailed))
            Some(s) => st = s
          }
          rest = left
        }
      }
    }
    // 窗口满了但还有待发字节:只能先收,让对端补窗口。
    if stuck && rest.length() > 0 {
      let step = match pump_once(conn, st, chan, sess) {
        Err(e) => return Err(e)
        Ok(v) => v
      }
      st = step.0
      chan = step.1
      continue
    }
    let step = match pump_once(conn, st, chan, sess) {
      Err(e) => return Err(e)
      Ok(v) => v
    }
    st = step.0
    chan = step.1
  }
  if sess.failed() {
    return Err(SftpError::Protocol(sess.failure_reason()))
  }
  // 6) EOF + 关闭输入方向
  let (c1, eof_a) = chan.eof_action()
  chan = c1
  match eof_a {
    None => ()
    Some(a) => {
      match send_chan(conn, st, a) {
        None => ()
        Some(s) => st = s
      }
    }
  }
  Ok({
    version: sess.version_of(),
    extensions: sess.extensions_of(),
    ops: sess.results_of(),
    requests_sent: sess.requests_sent_count(),
    replies_recv: sess.replies_recv_count(),
    sftp_bytes_in: sess.bytes_in_count(),
    total_sent_bytes: st.counters.sent,
    total_recv_bytes: st.counters.recv,
  })
}

///|
/// 收一个 SSH 包,喂给 SFTP 会话,再 pump 一次。
///
/// `pump` 在 `feed` **之外**每轮都调,而不是只在收到数据之后:应答可能已经躺在
/// 重组缓冲里,而 socket 已经空了——只在那里等,就是在等一个自己已经收到的包。
fn[T : @transport.Transport] pump_once(
  conn : T,
  st : SessionState,
  chan : @channel.ChanState,
  sess : @sftp.SftpSession,
) -> Result[(SessionState, @channel.ChanState), SftpError] {
  sess.pump()
  match recv_packet(conn, st.counters, st.recv) {
    Closed => Err(SftpError::Closed)
    BadPacket(why) => Err(SftpError::ChannelFailed(ExecError::BadPacket(why)))
    Packet(t, pl) => {
      let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
      // WINDOW_ADJUST 等回包必须真的发出去,否则对端窗口耗尽后会停发,
      // 表现成「读文件读到一半卡住」。
      let mut st2 = st
      for i = 0; i < actions.length(); i = i + 1 {
        match send_chan(conn, st2, actions[i]) {
          None => return Err(SftpError::ChannelFailed(ExecError::SendFailed))
          Some(s) => st2 = s
        }
      }
      match err {
        None => ()
        Some(chan_err) => {
          return Err(SftpError::ChannelFailed(chan_error(chan_err)))
        }
      }
      if t == 0x5e {
        match @channel.parse_data(pl) {
          None => {
            return Err(SftpError::ChannelFailed(ExecError::Malformed("channel_data")))
          }
          Some((_who, d)) => sess.feed(d)
        }
      }
      sess.pump()
      Ok((st2, chan2))
    }
  }
}

///|
/// 反复 pump 直到 `mode` 的条件成立,或者轮数用尽。
///
/// 返回值第一个分量是「到了没有」:False 表示排空 64 个包仍未见目标,调用方要
/// 区分它和「连接断了」——前者是协议没按预期走,后者是传输没了。
fn[T : @transport.Transport] pump_until(
  conn : T,
  st : SessionState,
  chan : @channel.ChanState,
  sess : @sftp.SftpSession,
  mode : Int,
) -> Result[(Bool, SessionState, @channel.ChanState), SftpError] {
  let mut rounds = 0
  let mut cur = (st, chan)
  while rounds < 64 {
    rounds = rounds + 1
    let step = match pump_once(conn, cur.0, cur.1, sess) {
      Err(e) => return Err(e)
      Ok(v) => v
    }
    cur = step
    if wait_pred(mode, step.1) {
      return Ok((true, step.0, step.1))
    }
  }
  Ok((false, cur.0, cur.1))
}

fn wait_pred(mode : Int, st : @channel.ChanState) -> Bool {
  if mode == 0 {
    st.open_done
  } else {
    st.success_count >= 1
  }
}

fn[T : @transport.Transport] send_chan(
  conn : T,
  st : SessionState,
  a : @channel.ChanAction,
) -> SessionState? {
  match a {
    @channel.Send(t, payload) => {
      let ok = send_packet(conn, st.counters, st.send, t, payload)
      if ok {
        Some(st)
      } else {
        None
      }
    }
  }
}

fn sftp_cat2(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(a.length() + b.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  out
}
