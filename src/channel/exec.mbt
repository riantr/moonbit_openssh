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

///|
/// 要发给对端的包(payload 已组好,不含消息号)
pub(all) enum ChanAction {
  Send(Byte, FixedArray[Byte])
}

///|
/// 通道执行过程中出错。**不是**「远端命令返回非零」——那是正常结果,
/// 走 `ExecReport::exit_status`。
pub(all) enum ChanError {
  /// 通道没能打开。对端带着 reason code 和描述回绝。
  OpenFailed(Int32, String)
  /// 对端拒绝了 exec 请求
  ExecRejected
  ///
  /// 对端拒绝了 subsystem 请求。
  ///
  /// 单列而不是复用 `ExecRejected`:subsystem 的 `want_reply` 是 TRUE,这个
  /// CHANNEL_FAILURE **就是**「没有这个子系统」的答案(session.c:1945-1948
  /// 在 `options.subsystem_name[]` 里找不到名字时返回失败),它和「命令被拒」
  /// 是两种诊断,混成一个报出去的话,拼错一个子系统名会看起来像远端拒绝执行。
  SubsystemRejected
  /// 包在通道状态下无法解释(字段截断、尾部有残余、channel 号不认识)
  Malformed(String)
}

///|
/// 一次 `exec` 的最终结果
pub(all) struct ExecReport {
  remote_id : Int32
  local_channel : Int32
  stdout : FixedArray[Byte]
  stderr : FixedArray[Byte]
  exit_status : Int32
  /// 对端通告的最大包长
  remote_max_packet : Int32
  /// 我们一共发出的 WINDOW_ADJUST 次数
  adjusts_sent : Int32
  /// 作为 stdin 发出的字节数
  stdin_sent : Int32
  /// 发出的 CHANNEL_DATA 包数——窗口夹取的直接证据
  stdin_packets : Int32
  /// CHANNEL_EOF 有没有在缓冲排空后发出去
  eof_sent : Bool
}

///|
/// 通道状态
pub(all) struct ChanState {
  local_channel : Int32
  remote_id : Int32
  remote_window : Int32
  remote_max_packet : Int32
  window : LocalWindow
  stdout : Array[FixedArray[Byte]]
  stderr : Array[FixedArray[Byte]]
  stdout_len : Int32
  stderr_len : Int32
  exit_status : Int32
  exec_acked : Bool
  open_done : Bool
  close_sent : Bool
  close_recv : Bool
  adjusts_sent : Int32
  ///
  /// 收到过几个 CHANNEL_SUCCESS。
  ///
  /// exec 只需要一个;pty-req + shell 是两个,而且驱动层必须知道哪一个是哪个
  /// ——靠计数推断顺序在服务器并发回包时会错位,所以计数只当「收到了几个」用,
  /// 具体对应哪个请求由驱动层自己按顺序对齐。
  success_count : Int32
  ///
  /// 收到过几个 CHANNEL_FAILURE。
  ///
  /// 只有交互式流程会用到:那里的 CHANNEL_FAILURE 通常是在说「服务端不给
  /// pty」,而 OpenSSH 客户端的做法是 `c->client_tty = 0` 然后继续开 shell
  /// (clientloop.c:2750)。exec 流程里同一个包仍然是致命的 exec 被拒,所以
  /// 那一支照旧报 `ExecRejected`。
  failure_count : Int32
  ///
  /// 交互式流程(pty-req + shell)与 exec 流程的失败语义不同,所以显式区分,
  /// 而不是让 `chan_step` 去猜哪个请求被拒了——它并不跟踪待确认的请求。
  interactive : Bool
  /// 被信号杀死时的 exit-signal(RFC 4254 §6.10):(信号名, 是否 core dump)
  exit_signal : (String, Bool)?
  /// exit-signal 里的 error message(没有 signal 时是空串)
  exit_signal_message : String
  ///
  /// 我们作为 stdin 发出去的字节数,以及为此发了多少个 CHANNEL_DATA。
  ///
  /// 两个数分开:字节数对得上只说明内容没丢,包数对得上才说明**夹取**是对的
  /// ——同一堆字节按 32 KiB 发和按 64 KiB 发,远端都照收不误。
  stdin_sent : Int32
  stdin_packets : Int32
  ///
  /// CHANNEL_EOF 发出去没有。
  ///
  /// 单独记一个布尔而不是从 `eof_sent` 反推:EOF 必须在**缓冲排空之后**才发
  /// (nchan.c:127-146 的 `chan_ibuf_empty` 先看 `sshbuf_len(c->input) != 0`
  /// 就直接 return),否则对端以为没有更多 stdin,远端命令读到的是截断的流。
  eof_sent : Bool
  ///
  /// 发过 subsystem 请求没有。
  ///
  /// 存在的唯一理由是让 `chan_step` 认出「这个 CHANNEL_FAILURE 回答的是
  /// subsystem 请求」——subsystem 的 `want_reply` 是 TRUE,而 subsystem 会话
  /// 里在收到任何数据之前只发过这一个请求,所以这个布尔足以定位,不必去跟踪
  /// 一个待确认请求队列。`interactive` 那一支用的是同一个思路。
  mut subsystem_sent : Bool
  ///
  /// 这条通道是**对端**发起的吗?
  ///
  /// Loop #78 加的。两种角色的通道在协议上**完全相反**:
  ///
  ///   * 我们发起的("session"、"direct-tcpip"):我们发 CHANNEL_OPEN,等对端回
  ///     CHANNEL_OPEN_CONFIRMATION。
  ///   * 对端发起的("forwarded-tcpip"):对端发 CHANNEL_OPEN,**我们**回
  ///     CHANNEL_OPEN_CONFIRMATION。
  ///
  /// 同一个状态机要同时走这两条路,所以必须记住自己站在哪一边:收到
  /// CHANNEL_OPEN(0x5a)时,对我们发起的通道来说那是协议错误,对对端发起的
  /// 通道来说那是这条通道的**开始**。不区分的话,0x5a 只能被当成「不认识
  /// 的包」悄悄丢掉——而那正是「服务端发来的 forwarded-tcpip 通道不见了」
  /// 这种症状。
  peer_opened : Bool
  ///
  /// 收到了对端的 CHANNEL_OPEN 吗?
  ///
  /// 和 `open_done` 分开:收到 open 和**确认**了 open 是两件事。收到的时候
  /// 我们还不知道要不要接受这条通道(类型对不对、监听地址是不是我们请求的
  /// 那一条),确认之后才是。
  open_received : Bool
  /// 对端发起的通道类型(还没收到 open 时是空串)
  open_type : String
  /// 对端发起的通道里的监听地址
  open_host : String
  /// 对端发起的通道里的监听端口
  open_port : Int32
  /// 对端发起的通道里的发起方地址
  open_originator_ip : String
  /// 对端发起的通道里的发起方端口
  open_originator_port : Int32
}

///|
/// 开始一次 exec:本地窗口已按 `CHAN_WINDOW_DEFAULT` 建立
pub fn ChanState::new(local_channel : Int32) -> ChanState {
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
    success_count: 0,
    failure_count: 0,
    interactive: false,
    exit_signal: None,
    exit_signal_message: "",
    stdin_sent: 0,
    stdin_packets: 0,
    eof_sent: false,
    subsystem_sent: false,
    peer_opened: false,
    open_received: false,
    open_type: "",
    open_host: "",
    open_port: 0,
    open_originator_ip: "",
    open_originator_port: 0,
  }
}

///|
/// 开始一条**由对端发起**的通道("forwarded-tcpip")
///
/// 和 `new` 的唯一区别是 `peer_opened`——它只影响两件事:收到 CHANNEL_OPEN
/// 时那不是协议错误而是这条通道的开始;以及我们不再发 CHANNEL_OPEN,而是
/// **回**一个 CHANNEL_OPEN_CONFIRMATION。
///
/// 通道号由调用方给:对端发起的通道里,我们的号是我们自己挑的(必须和
/// 我们已经用掉的号不冲突),而对端的号是它发来的 CHANNEL_OPEN 里带的。
pub fn ChanState::new_peer_opened(local_channel : Int32) -> ChanState {
  { ..ChanState::new(local_channel), peer_opened: true, }
}

///|
/// 确认对端发起的通道:要发出去的 CHANNEL_OPEN_CONFIRMATION
///
/// 必须在收到 CHANNEL_OPEN 之后调用。recipient 是**对端**的号(它发来的
/// open 里的 sender),sender 是**我们**的号。写反了不会立刻报错——对端会
/// 安静地忽略后面所有发给这条通道的包,而症状是「连接建立了但一个字节都
/// 不到」。
///
/// 返回 `(新状态, 要发的包?)`。已经确认过或者还没收到 open 时返回 None。
pub fn ChanState::confirm_open_action(
  self : ChanState,
) -> (ChanState, ChanAction?) {
  if self.open_done || !self.open_received {
    return (self, None)
  }
  (
    { ..self, open_done: true, },
    Some(
      Send(
        0x5b,
        channel_open_confirmation_payload(
          self.remote_id,
          self.local_channel,
          self.window.max,
          self.window.max_packet,
        ),
      ),
    ),
  )
}

///|
/// 拒绝对端发起的通道:要发出去的 CHANNEL_OPEN_FAILURE
///
/// 拒绝对端的通道是**正常**操作,不是错误:一条 forwarded-tcpip 如果不是我们
/// 请求的那一条(监听地址或端口对不上),或者是本客户端不支持的通道类型,
/// 就该明确地拒掉,而不是沉默地不确认——沉默会让对端一直等下去。
///
/// reason 用 `SSH_OPEN_ADMINISTRATIVELY_PROHIBITED`(RFC 4254 §5.1 的 1),
/// 和 OpenSSH 拒绝对端发起的通道时用的同一个码。
pub fn ChanState::refuse_open_action(
  self : ChanState,
  reason : Int32,
  description : String,
) -> (ChanState, ChanAction?) {
  if self.open_done || !self.open_received {
    return (self, None)
  }
  (
    { ..self, },
    Some(
      Send(
        0x5c,
        channel_open_failure_payload(self.remote_id, reason, description, ""),
      ),
    ),
  )
}

///|
/// 增量排空收方向的缓冲
///
/// 返回 `(新状态, 这一次排出来的字节)`。排空之后 `stdout` 里待发的部分被
/// 清空,但 `stdout_len` 仍然是**累计收到的字节数**,不因排空而减少——
/// 否则「排空过」和「一个字节都没收到」会长得一模一样,而这两个是完全不同的
/// 观测。
///
/// 为什么需要它:exec / direct-tcpip 那种一次性流程可以把收到的字节全部攒在
/// 状态里,结束时一次性取走;但**转发**不一样——转发必须把字节**边收边送**,
/// 攒着就等于把整条连接的数据都留在内存里,而且送不出去(对端在等我们送,
/// 我们在等它收完)。
pub fn ChanState::take_stdout(
  self : ChanState,
) -> (ChanState, FixedArray[Byte]) {
  let out = ch_cat_all(self.stdout)
  ({ ..self, stdout: [], }, out)
}

///|
/// 交互式会话用的初始状态。
///
/// 和 `new` 的唯一区别是 `interactive`——它只影响 CHANNEL_FAILURE 怎么算。
/// 把这个开关摆在状态里而不是让驱动去解释错误,是因为驱动层要分清
/// 「pty 被拒但还能继续」和「exec 被拒,到此为止」,而同一个包在两种流程里
/// 含义相反。
pub fn ChanState::new_interactive(local_channel : Int32) -> ChanState {
  { ..ChanState::new(local_channel), interactive: true, }
}

///|
/// 要发出去的 CHANNEL_REQUEST "subsystem"。
///
/// 必须在 OPEN_CONFIRMATION 之后调用:recipient 是对端在确认包里给的号,在那
/// 之前还是 -1。和 `exec_action` 同一个理由。
///
/// 发完就把 `subsystem_sent` 置位,之后 `chan_step` 见到 CHANNEL_FAILURE 会
/// 报 `SubsystemRejected` 而不是 `ExecRejected`。
pub fn ChanState::subsystem_action(
  self : ChanState,
  name : String,
) -> ChanAction? {
  if !self.open_done {
    return None
  }
  self.subsystem_sent = true
  Some(Send(0x62, channel_subsystem_payload(self.remote_id, name)))
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
/// 第 1 步的另一种:CHANNEL_OPEN "direct-tcpip"。
///
/// 和 `open_action` 唯一的区别是通道类型和随之多出来的四个字段。分成两个
/// 方法而不是给 `open_action` 加参数,是因为「session 通道」和
/// 「direct-tcpip 通道」在后续的流程上**也不同**:session 通道要再发一个
/// CHANNEL_REQUEST("exec"/"shell"/"subsystem"),direct-tcpip 通道不要——
/// 它开出来就直接传数据。用一个带布尔开关的方法拼这两种通道,那个开关
/// 总有一天会在某个调用点上被传反,而传反之后的症状是「服务端把通道开成了
/// 另一种类型」,不是「参数写错了」。
///
/// `dest_host` / `dest_port` 是**服务端**要连的目标,不是我们要连的目标。
/// `originator_ip` / `originator_port` 是我们自己的地址,只被服务端记日志。
pub fn ChanState::open_direct_tcpip_action(
  self : ChanState,
  dest_host : String,
  dest_port : Int32,
  originator_ip : String,
  originator_port : Int32,
) -> ChanAction {
  Send(
    0x5a,
    channel_open_direct_tcpip_payload(
      self.local_channel,
      self.window.max,
      self.window.max_packet,
      dest_host,
      dest_port,
      originator_ip,
      originator_port,
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

// ---------------------------------------------------------------------------
// Interactive session: pty-req / shell / window-change / stdin
// ---------------------------------------------------------------------------

///|
/// 交互式会话的第 1 步:CHANNEL_REQUEST "pty-req"。
///
/// 和 exec 一样必须在 OPEN_CONFIRMATION 之后。want_reply=TRUE,所以服务端会回
/// CHANNEL_SUCCESS 或 CHANNEL_FAILURE——两者都由 `chan_step` 计数,不在这儿判断。
pub fn ChanState::pty_req_action(
  self : ChanState,
  term : String,
  cols : Int32,
  rows : Int32,
  pixel_width : Int32,
  pixel_height : Int32,
  modes : FixedArray[Byte],
) -> ChanAction? {
  if !self.open_done {
    return None
  }
  Some(
    Send(
      0x62,
      channel_pty_req_payload(
        self.remote_id,
        term,
        cols,
        rows,
        pixel_width,
        pixel_height,
        modes,
      ),
    ),
  )
}

///|
/// 交互式会话的第 2 步:CHANNEL_REQUEST "shell"
pub fn ChanState::shell_action(self : ChanState) -> ChanAction? {
  if !self.open_done {
    return None
  }
  Some(Send(0x62, channel_shell_payload(self.remote_id)))
}

///|
/// 窗口尺寸变更(CHANNEL_REQUEST "window-change",want_reply=FALSE)
///
/// 任何时候都能发,不需要等 shell 起来——它用的是 `remote_id`,在
/// OPEN_CONFIRMATION 之后就一直有效。
pub fn ChanState::window_change_action(
  self : ChanState,
  cols : Int32,
  rows : Int32,
  pixel_width : Int32,
  pixel_height : Int32,
) -> ChanAction {
  Send(
    0x62,
    channel_window_change_payload(
      self.remote_id,
      cols,
      rows,
      pixel_width,
      pixel_height,
    ),
  )
}

///|
/// CHANNEL_REQUEST "env":把一个环境变量交给远端会话。
///
/// 必须在 **exec / shell 之前**发:服务端只在会话还是 LARVAL 时才处理 env
/// (session.c:2175-2192),之后到达的 env 请求会被无声丢掉。见
/// `channel_env_payload` 的完整依据。
///
/// want_reply 是 FALSE,所以正常情况下**没有**任何回包——服务端默认
/// `AcceptEnv` 为空,哪怕名字根本不在白名单里也一样静默(session.c:2064)。
/// 因此驱动层不能靠等 CHANNEL_FAILURE 来确认「被拒了」,那会永远等下去。
pub fn ChanState::env_action(
  self : ChanState,
  name : String,
  value : String,
) -> ChanAction? {
  if !self.open_done {
    return None
  }
  Some(Send(0x62, channel_env_payload(self.remote_id, name, value)))
}

///|
/// 从待发送缓冲里取出**一个**受窗口约束的 CHANNEL_DATA。
///
/// 逐字对应 `channel_output_poll_input_open`(channels.c:3085-3100):
///
///     if (len > c->remote_window)     len = c->remote_window;
///     if (len > c->remote_maxpacket)  len = c->remote_maxpacket;
///     if (len == 0)                    return 0;
///     ... 发送 len 字节 ...
///     sshbuf_consume(c->input, len);
///     c->remote_window -= len;
///
/// 三件事因此是硬的:
///
///   * **夹取,不是报错**。窗口不够就把这一包截短,而不是丢数据或断链。
///   * **先窗口后包长**。两个上限都要看,顺序不影响结果但影响你怎么读这段
///     代码——写成 `min(len, maxpacket)` 再判窗口,超发一次就是一个
///     RFC 4254 §5.2 的断链。
///   * **夹到 0 也不发包、不算错**。对端没腾出空间时这就是「还没轮到发」,
///     剩下的留在缓冲里等 CHANNEL_ADJUST。此时返回 `(原状态, None, 原缓冲)`。
///
/// 返回 `(新状态, 要发的包?, 还没发出去的剩余字节)`。一次调用最多发一个包——
/// 循环的推进完全由窗口决定,驱动层在每收到一个 CHANNEL_WINDOW_ADJUST 之后再调一次。
pub fn ChanState::stdin_take(
  self : ChanState,
  pending : FixedArray[Byte],
) -> (ChanState, ChanAction?, FixedArray[Byte]) {
  let mut n = pending.length()
  if n > self.remote_window {
    n = self.remote_window
  }
  if n > self.remote_max_packet {
    n = self.remote_max_packet
  }
  // 窗口空了就是「这轮没轮到发」,不是错误——对端还没给自己发 WINDOW_ADJUST。
  if n <= 0 {
    return (self, None, pending)
  }
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = pending[i]
  }
  let rest = FixedArray::make(pending.length() - n, b'\x00')
  for i = 0; i < rest.length(); i = i + 1 {
    rest[i] = pending[n + i]
  }
  (
    {
      ..self,
      remote_window: self.remote_window - n,
      stdin_sent: self.stdin_sent + n,
      stdin_packets: self.stdin_packets + 1,
    },
    Some(Send(0x5e, channel_data_payload(self.remote_id, out))),
    rest,
  )
}

///|
/// CHANNEL_EOF:我们的 stdin 到此为止。
///
/// payload 就是对端给的通道号(nchan.c:192-193
/// `SSH2_MSG_CHANNEL_EOF` + `sshpkt_put_u32(c->remote_id)`)。
///
/// **必须等缓冲排空再发**:`chan_ibuf_empty` 在 `sshbuf_len(c->input) != 0`
/// 时直接 return 不发(nchan.c:130-134),而提前发出去等于告诉对端「没有更多
/// stdin 了」,远端命令会读到截断的输入流还不报错。待发缓冲是驱动的状态、
/// 不是通道状态的,所以「现在该不该发」由驱动判断;这里只保证同一个通道不会
/// 发两次 EOF——发两次不会报错,但会让对端看到一个已经结束的输入方向又来了
/// 个结束标记。
pub fn ChanState::eof_action(self : ChanState) -> (ChanState, ChanAction?) {
  if self.eof_sent {
    return (self, None)
  }
  (
    { ..self, eof_sent: true, },
    Some(Send(0x60, channel_bare_payload(self.remote_id))),
  )
}

///|
/// CHANNEL_CLOSE:我们这一侧结束了
///
/// 和 `eof_action` 分开,因为它们是**两件事**:EOF 是「我的输入方向没有更多
/// 数据了」,CLOSE 是「这条通道结束了」。
///
/// 早先这里写的是「OpenSSH 的服务端在**收到**客户端的 EOF 之后才发自己的
/// CLOSE,所以一端如果只发 EOF 不发 CLOSE,另一端会一直等下去——表现是
/// 「连接还在,但永远不结束」。**那句话是错的**,而且错得有代表性:它是照着
/// 源码想象出来的,没有实测。实测(本机 Win32-OpenSSH 8.0p1,服务端日志由
/// `host/verify_loop78.mjs` 起的那台 sshd 写下)的结果相反:
///
///   * 服务端在**被代理的 socket** 读到 EOF 时就发它自己的 CHANNEL_EOF,
///     和我们发不发任何东西无关;
///   * 服务端的 CHANNEL_CLOSE 由「我们发了 EOF」或「我们发了 CLOSE」
///     **任意一个**触发。
///
/// 两条都单独测过:只发 EOF 不发 CLOSE -> 服务端照样回 CLOSE,客户端正常结束,
/// 所以「不发 CLOSE」是**等价变异**,门禁抓不到它(也抓不到才对);只发 CLOSE
/// 不发 EOF -> 服务端同样回 CLOSE,但我们没告诉对端「输入方向结束了」,协议
/// 上不完整,门禁靠 `eof_sent` 抓住。
///
/// 少发 CLOSE 之所以不会挂住,是因为状态机在收到对端的 CLOSE 时会自动回一个
/// (`chan_step` 的 0x61 分支)。EOF 和 CLOSE 还是要都发:EOF 是「输入方向结束」,
/// CLOSE 是「通道结束」,RFC 4254 §5.3 就是这两件事。
pub fn ChanState::close_action(self : ChanState) -> (ChanState, ChanAction?) {
  if self.close_sent {
    return (self, None)
  }
  (
    { ..self, close_sent: true, },
    Some(Send(0x61, channel_bare_payload(self.remote_id))),
  )
}

///|
/// 交互式会话的结果
///
/// `exit_status` 与 `exit_signal` 分开:被信号杀死时服务端发的是
/// `exit-signal` 而不是 `exit-status`,把两者混成一个字段的话「被 KILL」
/// 会和「正常返回」长得一模一样。
pub(all) struct ShellReport {
  remote_id : Int32
  stdout : FixedArray[Byte]
  stderr : FixedArray[Byte]
  exit_status : Int32
  exit_signal : (String, Bool)?
  exit_signal_message : String
  adjusts_sent : Int32
  /// 收到过几个 CHANNEL_SUCCESS(pty-req + shell 应为 2)
  success_count : Int32
}

///|
/// 交互式会话的收尾报告。
///
/// 没有 exit-status 也没有 exit-signal 时按 SSH 惯例回 255,理由同
/// `ExecReport`。
pub fn ChanState::shell_report(self : ChanState) -> ShellReport {
  {
    remote_id: self.remote_id,
    stdout: ch_cat_all(self.stdout),
    stderr: ch_cat_all(self.stderr),
    exit_status: if self.exit_status < 0 {
      255
    } else {
      self.exit_status
    },
    exit_signal: self.exit_signal,
    exit_signal_message: self.exit_signal_message,
    adjusts_sent: self.adjusts_sent,
    success_count: self.success_count,
  }
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
    0x5a =>
      // CHANNEL_OPEN —— **对端**发起的通道("forwarded-tcpip")。
      //
      // 这一支以前根本不存在:0x5a 落进 `_ =>` 那个兜底分支,被当成不认识
      // 的包悄悄丢掉。而「服务端发来的通道不见了」这件事,没有任何一个包
      // 能解释它——症状是「连接正常,但转发的那条通道从来没出现」。
      //
      // 状态机只负责**记下**这次 open,不负责决定接不接受:类型对不对、
      // 监听地址是不是我们请求的那一条,都是驱动层的判断,而接受和拒绝
      // 要发的是不同的包(`confirm_open_action` / `refuse_open_action`)。
      if !st.peer_opened {
        // 对我们自己发起的通道来说,CHANNEL_OPEN 是协议错误(RFC 4254 §5.1
        // 里没有这种用法)。以前它被静默忽略,现在它是一个明确的错误。
        (st, none, Some(ChanError::Malformed("unexpected_open")))
      } else if st.open_received {
        (st, none, Some(ChanError::Malformed("duplicate_open")))
      } else {
        match parse_channel_open(payload) {
          None => (st, none, Some(ChanError::Malformed("open")))
          Some(o) =>
            (
              {
                ..st,
                open_received: true,
                open_type: o.ctype,
                remote_id: o.sender,
                remote_window: o.window,
                remote_max_packet: o.max_packet,
                open_host: o.host,
                open_port: o.port,
                open_originator_ip: o.originator_ip,
                open_originator_port: o.originator_port,
              },
              none,
              None,
            )
        }
      }
    0x5b =>
      match parse_open_confirmation(payload) {
        None => (st, none, Some(ChanError::Malformed("open_confirmation")))
        Some((sender, win, maxp)) =>
          if st.peer_opened {
            // 对端发起的通道里,确认包是我们**发**出去的;服务端不会再回一个
            // 确认。收到了就说明两边对这条通道的理解已经不一致了。
            (
              st,
              none,
              Some(ChanError::Malformed("confirmation_for_peer_channel")),
            )
          } else {
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
      }
    0x5c =>
      match parse_open_failure(payload) {
        None => (st, none, Some(ChanError::Malformed("open_failure")))
        Some((reason, desc)) =>
          (st, none, Some(ChanError::OpenFailed(reason, desc)))
      }
    0x63 =>
      // CHANNEL_SUCCESS —— exec / pty-req / shell 被接受。只数个数:具体是哪个
      // 请求被确认由驱动层按发送顺序对齐,状态机不去猜。
      if st.open_done {
        (
          { ..st, exec_acked: true, success_count: st.success_count + 1, },
          none,
          None,
        )
      } else {
        (st, none, Some(ChanError::Malformed("success_before_open")))
      }
    0x64 =>
      // 判据的顺序有讲究:subsystem 先判,因为它的 want_reply 是 TRUE,而
      // subsystem 会话在收到任何数据之前只发过这一个请求——所以这个
      // CHANNEL_FAILURE 只可能是在回答它。判在 `interactive` 之前是因为
      // 交互式流程的「可以继续」和 subsystem 的「到此为止」不该混。
      if st.subsystem_sent {
        (st, none, Some(ChanError::SubsystemRejected))
      } else if st.interactive {
        // 交互式流程:CHANNEL_FAILURE 只说明「这个请求被拒了」。最常见的是服务端
        // 不给 pty(`PermitTTY no`),而真实客户端会退回无 pty 继续开 shell
        // (clientloop.c:2750)。当成致命错误会让整个 shell 用不了。
        ({ ..st, failure_count: st.failure_count + 1, }, none, None)
      } else {
        (st, none, Some(ChanError::ExecRejected))
      }
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
                  (st, none, Some(ChanError::Malformed("exit_status_trailing")))
                } else {
                  // want_reply 是 FALSE:带 want_reply 的 exit-status 按 RFC 要
                  // 回 CHANNEL_SUCCESS。真 ssh 会回,这里不回只会被对端忽略,
                  // 但把分支显式写出来,免得这一差异只是碰巧。
                  let _ = want
                  ({ ..st, exit_status: code, }, none, None)
                }
            }
          } else if rtype == "exit-signal" {
            // 被信号杀死时服务端发的是这个。只认 exit-status 的客户端会一直
            // 等不到退出码,最后按 255 收场——看起来就像「命令没有输出」。
            match parse_exit_signal(payload, off) {
              None => (st, none, Some(ChanError::Malformed("exit_signal")))
              Some((name, core, msg)) =>
                (
                  {
                    ..st,
                    exit_signal: Some((name, core)),
                    exit_signal_message: msg,
                  },
                  none,
                  None,
                )
            }
          } else {
            // "pty-req" 之类的请求一律不回。真实客户端对 want_reply=FALSE 的
            // 请求本来就不回。
            (st, none, None)
          }
      }
    0x5d =>
      match parse_window_adjust(payload) {
        None => (st, none, Some(ChanError::Malformed("window_adjust")))
        Some((_, n)) =>
          ({ ..st, remote_window: st.remote_window + n, }, none, None)
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
        ({ ..st, close_recv: true, }, none, None)
      } else {
        (
          { ..st, close_recv: true, close_sent: true, },
          one_action(Send(0x61, channel_bare_payload(st.remote_id))),
          None,
        )
      }
    _ => (st, none, None)
  }
}

///|
/// 单个动作的数组(状态机里的动作几乎总是 0 或 1 个)
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
    None => ({ ..st, window: w, }, [])
    Some(w2) =>
      (
        { ..st, window: w2, adjusts_sent: st.adjusts_sent + 1, },
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
    exit_status: if self.exit_status < 0 {
      255
    } else {
      self.exit_status
    },
    remote_max_packet: self.remote_max_packet,
    adjusts_sent: self.adjusts_sent,
    stdin_sent: self.stdin_sent,
    stdin_packets: self.stdin_packets,
    eof_sent: self.eof_sent,
  }
}
