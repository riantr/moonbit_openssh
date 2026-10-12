///| Loop #39: 浏览器侧的 SFTP
///
/// 这个文件与 `src/sshclient/sftp.mbt` 是刻意近乎逐行相同的一份。原因不是
/// 「复制粘贴省事」,而是这个文件里**一行协议都没有**:下一个请求发什么、等哪个
/// id、READDIR 什么时候结束、READ 的 offset 怎么累加,全部在
/// `@sftp.SftpSession` 这个传输无关的状态机里,一份实现,两条传输共用。
///
/// 这里唯一的内容是「怎么把字节搬出去、搬回来」:
/// - `src/sshclient` 用同步的 `send_packet` / `recv_packet`
/// - 这里用 `wt_send_plain_packet` / `wt_recv_plain_packet`(异步)
///
/// 如果哪天这两份文件开始分叉,分叉的应该是传输层,而不是脚本语义。要验证这一
/// 点,`host/verify_loop39.mjs` 会把两边的报告逐字节对拍。
///
/// 另有两处是通道层的,不是 SFTP 层的,理由见 `src/sshclient/sftp.mbt` 的头部:
/// 1. subsystem 是 want_reply=TRUE,必须等 CHANNEL_SUCCESS 再发 INIT;
/// 2. 请求走 `ChanState::stdin_take`(Loop #37 已 KAT 的窗口夹取),不写第二份。

///| 浏览器侧 SFTP 的失败原因。与 `src/sshclient` 的 `SftpError` 一一对应,
/// 只是传输层那一个换成了 `WtExecError`。
pub(all) enum WtSftpError {
  /// 认证没过
  AuthFailed(WtAuthError)
  /// 通道层出错
  ChannelFailed(WtExecError)
  /// SFTP 层出错(协议坏了,或者会话自己判定失败)
  Protocol(String)
  /// 包数超限
  TooManyPackets
  /// 连接在会话结束前被关掉
  Closed
}

///| 一次浏览器侧 SFTP 会话的结果
pub(all) struct WtSftpReport {
  version : Int
  extensions : Int
  ops : Array[@sftp.SftpOpResult]
  requests_sent : Int
  replies_recv : Int
  sftp_bytes_in : Int
  total_sent_bytes : Int
  total_recv_bytes : Int
}

pub(all) enum WtSftpOutcome {
  Done(WtSftpReport)
  Failed(WtSftpError)
}

///|
/// 跑完整个 SFTP 会话:认证 → 开通道 → subsystem → 等确认 → 脚本。
///
/// 认证复用 `wt_auth_into`,与 `wt_live_exec_io` 是同一段代码。
pub async fn wt_live_sftp(
  conn : @wt.WtConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  ops : Array[@sftp.SftpOp],
  kh : @knownhosts.KnownHostsPolicy,
) -> WtSftpOutcome {
  let st = match wt_auth_into(conn, x, user, d, kh) {
    Err(e) => return WtSftpOutcome::Failed(WtSftpError::AuthFailed(e))
    Ok(v) => v
  }
  match wt_run_sftp_session(conn, st, ops) {
    Ok(r) => WtSftpOutcome::Done(r)
    Err(e) => WtSftpOutcome::Failed(e)
  }
}

///|
/// 通道之上的那一小段循环,逐行对应 `src/sshclient/sftp.mbt` 的
/// `run_sftp_session`,差别只有收发那两行的 await。
async fn wt_run_sftp_session(
  conn : @wt.WtConn,
  st0 : WtSessionState,
  ops : Array[@sftp.SftpOp],
) -> Result[WtSftpReport, WtSftpError] {
  let mut st = st0
  let mut chan = @channel.ChanState::new(@channel.LOCAL_CHANNEL)
  let sess = @sftp.SftpSession::new(ops)
  let mut rounds = 0

  // 1) CHANNEL_OPEN
  match wt_sftp_send_chan(conn, st, chan.open_action()) {
    None => {
      return Err(WtSftpError::ChannelFailed(WtExecError::SendFailed))
    }
    Some(s) => st = s
  }
  // 2) 等 OPEN_CONFIRMATION
  let opened = match wt_sftp_pump_until(conn, st, chan, sess, 0) {
    Err(e) => return Err(e)
    Ok(v) => v
  }
  if !opened.0 {
    return Err(
      WtSftpError::ChannelFailed(WtExecError::Malformed("no_open_confirmation")),
    )
  }
  st = opened.1
  chan = opened.2

  // 3) subsystem 请求。必须在确认之后 —— recipient 是对端给的号。
  match chan.subsystem_action("sftp") {
    None => {
      return Err(
        WtSftpError::ChannelFailed(WtExecError::Malformed("subsystem_before_open")),
      )
    }
    Some(a) => {
      match wt_sftp_send_chan(conn, st, a) {
        None => return Err(WtSftpError::ChannelFailed(WtExecError::SendFailed))
        Some(s) => st = s
      }
    }
  }
  // 4) **等 CHANNEL_SUCCESS**。want_reply=TRUE,而这个 FAILURE 是「没有这个
  //    子系统」的唯一信号(session.c:1945-1948)。
  let acked = match wt_sftp_pump_until(conn, st, chan, sess, 1) {
    Err(e) => return Err(e)
    Ok(v) => v
  }
  if !acked.0 {
    return Err(WtSftpError::ChannelFailed(WtExecError::SubsystemRejected))
  }
  st = acked.1
  chan = acked.2

  // 5) 脚本。每轮:把排队的请求送出去 → 收一个包喂进去 → pump。
  while !sess.done() && !sess.failed() {
    rounds = rounds + 1
    if rounds > 200000 {
      return Err(WtSftpError::TooManyPackets)
    }
    let out = sess.take_out()
    let mut rest : FixedArray[Byte] = FixedArray::make(0, b'\x00')
    for i = 0; i < out.length(); i = i + 1 {
      rest = wt_sftp_cat2(rest, out[i])
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
          match wt_sftp_send_chan(conn, st, a) {
            None => {
              return Err(WtSftpError::ChannelFailed(WtExecError::SendFailed))
            }
            Some(s) => st = s
          }
          rest = left
        }
      }
    }
    // 窗口满了但还有待发字节:只能先收,让对端补窗口。
    if stuck && rest.length() > 0 {
      let step = match wt_sftp_pump_once(conn, st, chan, sess) {
        Err(e) => return Err(e)
        Ok(v) => v
      }
      st = step.0
      chan = step.1
      continue
    }
    let step = match wt_sftp_pump_once(conn, st, chan, sess) {
      Err(e) => return Err(e)
      Ok(v) => v
    }
    st = step.0
    chan = step.1
  }
  if sess.failed() {
    return Err(WtSftpError::Protocol(sess.failure_reason()))
  }
  // 6) EOF + 关闭输入方向
  let (c1, eof_a) = chan.eof_action()
  chan = c1
  match eof_a {
    None => ()
    Some(a) => {
      match wt_sftp_send_chan(conn, st, a) {
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
/// 重组缓冲里,而通道已经空了——只在那里等,就是在等一个自己已经收到的包。
async fn wt_sftp_pump_once(
  conn : @wt.WtConn,
  st : WtSessionState,
  chan : @channel.ChanState,
  sess : @sftp.SftpSession,
) -> Result[(WtSessionState, @channel.ChanState), WtSftpError] {
  sess.pump()
  match wt_recv_plain_packet(conn, st.counters, st.recv) {
    Closed => Err(WtSftpError::Closed)
    BadPacket(why) => Err(WtSftpError::ChannelFailed(WtExecError::BadPacket(why)))
    Packet(t, pl) => {
      let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
      // WINDOW_ADJUST 等回包必须真的发出去,否则对端窗口耗尽后会停发,
      // 表现成「读文件读到一半卡住」。
      let mut st2 = st
      for i = 0; i < actions.length(); i = i + 1 {
        match wt_sftp_send_chan(conn, st2, actions[i]) {
          None => {
            return Err(WtSftpError::ChannelFailed(WtExecError::SendFailed))
          }
          Some(s) => st2 = s
        }
      }
      match err {
        None => ()
        Some(chan_err) => {
          return Err(
            WtSftpError::ChannelFailed(wt_chan_error(chan_err)),
          )
        }
      }
      if t == 0x5e {
        match @channel.parse_data(pl) {
          None => {
            return Err(
              WtSftpError::ChannelFailed(WtExecError::Malformed("channel_data")),
            )
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
/// 第一个分量是「到了没有」:False 表示排空 64 个包仍未见目标,调用方要区分它和
/// 「连接断了」——前者是协议没按预期走,后者是传输没了。
async fn wt_sftp_pump_until(
  conn : @wt.WtConn,
  st : WtSessionState,
  chan : @channel.ChanState,
  sess : @sftp.SftpSession,
  mode : Int,
) -> Result[(Bool, WtSessionState, @channel.ChanState), WtSftpError] {
  let mut rounds = 0
  let mut cur = (st, chan)
  while rounds < 64 {
    rounds = rounds + 1
    let step = match wt_sftp_pump_once(conn, cur.0, cur.1, sess) {
      Err(e) => return Err(e)
      Ok(v) => v
    }
    cur = step
    if wt_sftp_wait_pred(mode, step.1) {
      return Ok((true, step.0, step.1))
    }
  }
  Ok((false, cur.0, cur.1))
}

fn wt_sftp_wait_pred(mode : Int, st : @channel.ChanState) -> Bool {
  if mode == 0 {
    st.open_done
  } else {
    st.success_count >= 1
  }
}

async fn wt_sftp_send_chan(
  conn : @wt.WtConn,
  st : WtSessionState,
  a : @channel.ChanAction,
) -> WtSessionState? {
  match a {
    @channel.Send(t, payload) => {
      let ok = wt_send_plain_packet(conn, st.counters, st.send, t, payload)
      if ok {
        Some(st)
      } else {
        None
      }
    }
  }
}

///| `SftpSession::take_out` 可能吐出多帧,这里按字节拼起来再交给窗口夹取。
fn wt_sftp_cat2(
  a : FixedArray[Byte],
  b : FixedArray[Byte],
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(
    a.length() + b.length(),
    b'\x00',
  )
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  out
}