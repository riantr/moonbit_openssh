///| The exec flow as a pure state machine.
///
/// `chan_step` is the entire channel protocol. Feed it one packet the peer
/// sent; get back the updated state and the packets we owe the peer. The
/// transport (native TCP or browser WebSocket) only moves bytes, so the
/// browser path cannot drift from the native one in protocol terms — only in
/// which pipe the bytes went through.
///
/// The flow, in the order a real `ssh host command` performs it:
///
///   1. CHANNEL_OPEN "session"                       (we send)
///   2. <- CHANNEL_OPEN_CONFIRMATION                (peer; gives us their id)
///   3. CHANNEL_REQUEST "exec" want_reply=TRUE       (we send)
///   4. <- CHANNEL_SUCCESS                          (peer)
///   5. <- CHANNEL_DATA ...                         (peer; we consume window)
///   6. <- CHANNEL_EXTENDED_DATA                    (peer stderr, same window)
///   7. <- CHANNEL_REQUEST "exit-status" want=FALSE  (peer; a u32 follows)
///   8. <- CHANNEL_EOF, <- CHANNEL_CLOSE             (peer)
///   9. CHANNEL_WINDOW_ADJUST / CHANNEL_CLOSE        (we send)
///
/// Step 7 is the one that catches people: exit-status is a CHANNEL_REQUEST,
/// not data, and it arrives with `want_reply = FALSE`. Parsing it as DATA
/// means the exit code never arrives and the loop ends on a close with no
/// status at all — which looks like "the command produced no output".

///| 要发给对端的包(payload 已组好,不含消息号)
pub(all) enum ChanAction {
  Send(Byte, FixedArray[Byte])
}

///|
/// 通道执行过程中出错。**不是**「远端命令返回非零」——那是正常结果,
/// 走 `ExecReport::exit_status`。
pub(all) enum ChanError {
  /// 通道没能打开。对端带着 reason code 和描述回绝。
  OpenFailed(Int, String)
  /// 对端拒绝了 exec 请求
  ExecRejected
  /// 包在通道状态下无法解释(字段截断、尾部有残余、channel 号不认识)
  Malformed(String)
}

///|
/// 一次 `exec` 的最终结果
pub(all) struct ExecReport {
  remote_id : Int
  local_channel : Int
  stdout : FixedArray[Byte]
  stderr : FixedArray[Byte]
  exit_status : Int
  /// 对端通告的最大包长
  remote_max_packet : Int
  /// 我们一共发出的 WINDOW_ADJUST 次数
  adjusts_sent : Int
}

///|
/// 通道状态
pub(all) struct ChanState {
  local_channel : Int
  remote_id : Int
  remote_window : Int
  remote_max_packet : Int
  window : LocalWindow
  stdout : Array[FixedArray[Byte]]
  stderr : Array[FixedArray[Byte]]
  stdout_len : Int
  stderr_len : Int
  exit_status : Int
  exec_acked : Bool
  open_done : Bool
  close_sent : Bool
  close_recv : Bool
  adjusts_sent : Int
}

///|
/// 开始一次 exec:本地窗口已按 `CHAN_WINDOW_DEFAULT` 建立
pub fn ChanState::new(local_channel : Int) -> ChanState {
  {
    local_channel,
    remote_id: -1,
    remote_window: 0,
    remote_max_packet: 0,
    window: LocalWindow::new(),
    stdout: [],
    stderr: [],
    stdout_len: 0,
    stderr_len: 0,
    exit_status: -1,
    exec_acked: false,
    open_done: false,
    close_sent: false,
    close_recv: false,
    adjusts_sent: 0,
  }
}

///|
/// 第 1 步:要发出去的 CHANNEL_OPEN
///
/// 单独于 `chan_step`,因为它是唯一一个「还没收到任何东西就先发」的包。
pub fn ChanState::open_action(self : ChanState) -> ChanAction {
  Send(
    0x5a,
    channel_open_payload(
      self.local_channel,
      self.window.max,
      self.window.max_packet,
    ),
  )
}

///|
/// 第 3 步:CHANNEL_REQUEST "exec"。必须在收到 OPEN_CONFIRMATION 之后,
/// 因为 recipient 用的是对端给的 id。
pub fn ChanState::exec_action(
  self : ChanState,
  command : String,
) -> ChanAction? {
  if !self.open_done {
    return None
  }
  Some(Send(0x62, channel_exec_payload(self.remote_id, command)))
}

///|
/// 处理一个来自对端的包,返回 `(新状态, 要发出去的包列表)`
///
/// 返回的动作列表至多两三个,最多的是「收到 DATA 后按窗口条件补一个
/// WINDOW_ADJUST」。驱动层负责把它们发出去。
///|
///
///
/// 注意每个分支末尾没有逗号:MoonBit 的 `match` 分支以换行分隔,把嵌套
/// `match` 当分支体写时尤其容易顺手加个逗号,然后报一个和真正原因无关的
/// "cannot be implicitly ignored"。
pub fn chan_step(
  st : ChanState,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> (ChanState, Array[ChanAction], ChanError?) {
  let none : Array[ChanAction] = []
  match msg_type {
    0x5b =>
      match parse_open_confirmation(payload) {
        None => (st, none, Some(ChanError::Malformed("open_confirmation")))
        Some((sender, win, maxp)) =>
          (
            {
              ..st,
              remote_id: sender,
              remote_window: win,
              remote_max_packet: maxp,
              open_done: true,
            },
            none,
            None,
          )
      }
    0x5c =>
      match parse_open_failure(payload) {
        None => (st, none, Some(ChanError::Malformed("open_failure")))
        Some((reason, desc)) =>
          (st, none, Some(ChanError::OpenFailed(reason, desc)))
      }
    0x63 =>
      // CHANNEL_SUCCESS —— exec 被接受
      if st.open_done {
        ({ ..st, exec_acked: true }, none, None)
      } else {
        (st, none, Some(ChanError::Malformed("success_before_open")))
      }
    0x64 => (st, none, Some(ChanError::ExecRejected))
    0x5e =>
      match parse_data(payload) {
        None => (st, none, Some(ChanError::Malformed("data")))
        Some((who, d)) =>
          // RFC 4254 5.2: the recipient field of an *inbound* packet names the
          // channel we opened, i.e. our own id -- not the id the peer gave us
          // in OPEN_CONFIRMATION.  Those two are both 0 on a first channel, so
          // checking against remote_id looks right and is wrong as soon as the
          // peer picks a different number.  OpenSSH just resolves the id
          // through channel_by_id (channels.c:3474 channel_from_packet_id).
          if who != st.local_channel {
            (st, none, Some(ChanError::Malformed("data_wrong_channel")))
          } else {
            let w = st.window.consume(d.length())
            let (st2, actions) = maybe_adjust(st, w)
            (
              {
                ..st2,
                stdout: arr_append(st.stdout, d),
                stdout_len: st.stdout_len + d.length(),
              },
              actions,
              None,
            )
          }
      }
    0x5f =>
      match parse_extended_data(payload) {
        None => (st, none, Some(ChanError::Malformed("extended_data")))
        Some((who, code, d)) =>
          if who != st.local_channel {
            (st, none, Some(ChanError::Malformed("extdata_wrong_channel")))
          } else if code != EXTENDED_DATA_STDERR {
            // 非 stderr 的扩展数据(OTP 等)本轮不实现,但要**显式**跳过,
            // 不能当成解析失败——后者会误报成协议错误。
            (st, none, None)
          } else {
            // Deliberate divergence from channels.c.  Look at
            // channel_input_extended_data: line 3606 does a bare
            // `c->local_window -= data_len` and nothing else, while
            // channel_input_data (3518-3523) also does
            // `c->local_consumed += win_len`.  So in OpenSSH a peer that fills
            // our window with nothing but stderr never gets a WINDOW_ADJUST and
            // the transfer stalls.  We run the same consume() on both streams:
            // one extra WINDOW_ADJUST is always legal, a stall is not.
            let w = st.window.consume(d.length())
            let (st2, actions) = maybe_adjust(st, w)
            (
              {
                ..st2,
                stderr: arr_append(st.stderr, d),
                stderr_len: st.stderr_len + d.length(),
              },
              actions,
              None,
            )
          }
      }
    0x62 =>
      match parse_request_header(payload) {
        None => (st, none, Some(ChanError::Malformed("request")))
        Some((_, rtype, want, off)) =>
          if rtype == "exit-status" {
            match read_u32_at(payload, off) {
              None => (st, none, Some(ChanError::Malformed("exit_status")))
              Some((code, o2)) =>
                if o2 != payload.length() {
                  (
                    st,
                    none,
                    Some(ChanError::Malformed("exit_status_trailing")),
                  )
                } else {
                  // want_reply 是 FALSE:带 want_reply 的 exit-status 按 RFC 要
                  // 回 CHANNEL_SUCCESS。真 ssh 会回,这里不回只会被对端忽略,
                  // 但把分支显式写出来,免得这一差异只是碰巧。
                  let _ = want
                  ({ ..st, exit_status: code }, none, None)
                }
            }
          } else {
            // "exit-signal" / "pty-req" 之类的请求一律不回。真实客户端对
            // want_reply=FALSE 的请求本来就不回。
            (st, none, None)
          }
      }
    0x5d =>
      match parse_window_adjust(payload) {
        None => (st, none, Some(ChanError::Malformed("window_adjust")))
        Some((_, n)) =>
          ({ ..st, remote_window: st.remote_window + n }, none, None)
      }
    0x60 =>
      // CHANNEL_EOF:数据方向由发起 exec 的一方先关。我们收到对端的 EOF
      // 意味着它的 stdout 结束了;此时**不**回 EOF——真正需要回的是 CLOSE。
      match parse_channel_id(payload) {
        None => (st, none, Some(ChanError::Malformed("eof")))
        Some(_) => (st, none, None)
      }
    0x61 =>
      // CHANNEL_CLOSE:必须回一个 CLOSE(channels.c 的 CHAN_CLOSE_RCVD 路径),
      // 否则对端会一直等下去。
      if st.close_sent {
        ({ ..st, close_recv: true }, none, None)
      } else {
        (
          { ..st, close_recv: true, close_sent: true },
          one_action(Send(0x61, channel_bare_payload(st.remote_id))),
          None,
        )
      }
    _ => (st, none, None)
  }
}

///| 单个动作的数组(状态机里的动作几乎总是 0 或 1 个)
fn one_action(a : ChanAction) -> Array[ChanAction] {
  let out : Array[ChanAction] = []
  out.push(a)
  out
}

///|
/// 纯函数式追加。`Array` 是可变引用,直接 `push` 会把**上一个状态**的数组
/// 一起改掉——状态机一旦拿旧状态推演别的分支就会看到脏数据。
fn arr_append(
  a : Array[FixedArray[Byte]],
  b : FixedArray[Byte],
) -> Array[FixedArray[Byte]] {
  let out : Array[FixedArray[Byte]] = []
  for x in a {
    out.push(x)
  }
  out.push(b)
  out
}
///|
/// 窗口到了阈值就补一个 WINDOW_ADJUST(channels.c:2452-2458)
///
/// 发出去的字节数是 `local_consumed`(累积),发完清零、窗口加回去。
///
/// 两条分支都**必须**把窗口写回状态。早先这里只在要发包的那条分支里写回,
/// 不发包的分支直接返回传进来的 `st`,于是刚扣掉的 `cur` 和累计的
/// `local_consumed` 每次都被丢掉——窗口看起来永远是满的,一条 WINDOW_ADJUST
/// 也不会发。小输出根本撑不爆 2 MiB,所以连接照样「跑完」,只有把 1.5 MiB
/// 灌进 transcript 才暴露得出来。
fn maybe_adjust(
  st : ChanState,
  w : LocalWindow,
) -> (ChanState, Array[ChanAction]) {
  match w.take_adjust() {
    None => ({ ..st, window: w }, [])
    Some(w2) => (
      {
        ..st,
        window: w2,
        adjusts_sent: st.adjusts_sent + 1,
      },
      one_action(
        Send(
          0x5d,
          // `w`, not `w2`: take_adjust already reset consumed to 0, so reading
          // the amount off the post-take window sends WINDOW_ADJUST with a
          // 0-byte payload.  The connection still runs -- it just never gets
          // its window back, and only dies once the peer runs dry.
          channel_window_adjust_payload(st.remote_id, w.adjust_amount()),
        ),
      ),
    )
  }
}

///|
/// 会话是否结束:对端发了 CLOSE,且我们的 CLOSE 也已经发出去了
pub fn ChanState::finished(self : ChanState) -> Bool {
  self.close_recv && self.close_sent
}

///|
/// 收尾报告。exit_status 仍是 -1 说明对端没送 exit-status(被信号杀死、
/// 或在 exit-status 之前就断链),按 SSH 的惯例用 255。
pub fn ChanState::report(self : ChanState) -> ExecReport {
  {
    remote_id: self.remote_id,
    local_channel: self.local_channel,
    stdout: ch_cat_all(self.stdout),
    stderr: ch_cat_all(self.stderr),
    exit_status: if self.exit_status < 0 { 255 } else { self.exit_status },
    remote_max_packet: self.remote_max_packet,
    adjusts_sent: self.adjusts_sent,
  }
}