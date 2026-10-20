///| direct-tcpip:客户端发起的那一半端口转发
///
/// `ssh -L 8080:host:port` 在协议层就是这一条:客户端开一个类型为
/// "direct-tcpip" 的通道,请求**服务端**去连 `host:port`,连上之后这条通道
/// 上跑的就是那个 TCP 连接的字节(RFC 4254 §7.2)。
///
/// 与它成对的是 "forwarded-tcpip"(`ssh -R` 的协议层),那个由**服务端**发起,
/// 不在本文件范围内。
///
/// ## 为什么复用 `src/channel` 的状态机而不是另写一套
///
/// 通道协议本身(`chan_step`)是共享的:它已经处理了 OPEN_CONFIRMATION、
/// OPEN_FAILURE、DATA、WINDOW_ADJUST、EOF、CLOSE,并且维护着收方向的窗口。
/// 本文件只做两件事——**发开通道的那一个包**,以及**把窗口允许的字节喂进去**。
/// 协议规则因此仍然只有一份,浏览器路径将来接上时只需要再写一个驱动,
/// 不会和这里分叉。
///
/// ## 失败必须被说出来
///
/// 服务端连不上目标时,回的是 CHANNEL_OPEN_FAILURE,reason code 3
/// (SSH_OPEN_CONNECT_FAILED)。这个失败**不能**被吞掉:吞掉之后的表现是
/// 「转发命令返回成功,但一个字节都没转发过去」——那比报错更难查。
/// 所以 `ForwardError::OpenFailed` 单列,带着 reason 和服务端的描述。

///|
/// 一次 direct-tcpip 转发的结果
pub(all) struct ForwardReport {
  /// 认证阶段的报告。
  ///
  /// 带着它是因为**记住**主机密钥是认证成功之后的事:驱动层要拿这份报告
  /// 去做 TOFU 写回(和 `live_exec` 那条路径完全同一套)。转发路径如果自己
  /// 吞掉认证报告,「接受了一把没记住的钥匙」就会和「拒绝了一把钥匙」长得
  /// 一模一样——而这两件事的后果完全相反。
  auth : AuthReport
  /// 服务端代我们连的目标
  dest_host : String
  dest_port : Int32
  /// 服务端给的通道号
  remote_id : Int32
  /// 服务端通告的最大包长
  remote_max_packet : Int32
  /// 远端送回来的字节(也就是目标服务回给我们的字节)
  stdout : FixedArray[Byte]
  stdout_len : Int32
  /// 作为 stdin 发出去的字节数
  stdin_sent : Int32
  /// 发出的 CHANNEL_DATA 包数——窗口夹取的直接证据
  stdin_packets : Int32
  /// 发出的 WINDOW_ADJUST 次数
  adjusts_sent : Int32
  /// CHANNEL_EOF 有没有在缓冲排空后发出去
  eof_sent : Bool
  /// 通道是不是正常收尾(对端 CLOSE + 我们也回了 CLOSE)
  closed : Bool
}

///|
/// direct-tcpip 失败的原因
pub(all) enum ForwardError {
  /// 认证没过,通道根本没开
  AuthFailed(AuthError)
  /// 服务端拒绝开这条通道(reason code + 服务端的描述)
  OpenFailed(Int32, String)
  /// 包在通道状态下无法解释
  Malformed(String)
  /// 连接断了
  Closed
  /// 包格式不对
  BadPacket(String)
  /// 发包失败
  SendFailed
  /// 包数超限——防止对端不停发包把内存吃光
  TooManyPackets
}

///|
/// direct-tcpip 的结果
pub(all) enum ForwardOutcome {
  /// 通道跑完了,而且**有字节回来**
  Done(ForwardReport)
  /// 通道开了又关,但**一个字节也没回来**。
  ///
  /// 单列,是因为它是最常见的那种失败:服务端连不上目标。实测 OpenSSH
  /// 8.0p1 的直连是**异步**的——它先回 CHANNEL_OPEN_CONFIRMATION,连接失败
  /// (WSAECONNREFUSED)发生在之后,所以**不会**有 CHANNEL_OPEN_FAILURE。
  /// 服务端日志里能看得很清楚:
  ///
  ///     server_input_channel_open: confirm direct-tcpip
  ///     finish_connect - ERROR: async io completed with error: 10061
  ///
  /// 协议层面没有任何东西能区分「服务端连不上」和「目标接了立刻关」。
  /// OpenSSH 自己的客户端在这两种情况下都**静默退出 0**(实测:`ssh -W` 指向
  /// 一个没人监听的端口,stdout 空、stderr 空、退出码 0)。那不是一个值得
  /// 照抄的行为:用户看到的是「转发成功了」,而实际上一个字节都没过去。
  ///
  /// 所以这里报一个**只描述观测、不猜原因**的结果。名字里没有「失败」,
  /// 因为我们确实不知道原因;但它也不是 DONE,因为 DONE 意味着「字节回来了」。
  NoData(ForwardReport)
  /// 出错了
  Failed(ForwardError)
}

///|
/// 发起一次 direct-tcpip 转发,把 `stdin_data` 送过去,收完对端的字节就返回。
///
/// 一次性的:通道在**对端关闭或断链**时结束。这不是 `ssh -L` 的完整语义
/// (那个还要在本地监听并接受多条连接),但协议层要用的东西——开通道、
/// 夹取发送、窗口回收、失败语义——全在这里,而它们才是容易写错的部分。
///
/// 认证走的是和 `live_exec` 完全相同的那段代码(`live_auth_with_state`),
/// 所以「能认证但不能转发」和「能 exec 但不能转发」这两种故障不会混在一起:
/// 认证失败会被原样翻译成 `ForwardError::AuthFailed`。
pub fn[T : @transport.Transport] live_forward(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  kh : @knownhosts.KnownHostsPolicy,
  dest_host : String,
  dest_port : Int32,
  stdin_data : FixedArray[Byte],
) -> ForwardOutcome {
  let (auth, state_opt) = live_auth_with_state(conn, x, user, d, kh)
  let auth_report = match auth {
    Authenticated(r) => r
    Failed(e) => return Failed(ForwardError::AuthFailed(e))
  }
  let st0 = match state_opt {
    None =>
      return Failed(
        ForwardError::AuthFailed(
          AuthError::Transport(SessionError::NoServiceAccept),
        ),
      )
    Some(v) => v
  }
  let mut st = st0
  let mut chan = @channel.ChanState::new(@channel.DEFAULT_LOCAL_CHANNEL)
  // ---- 1. CHANNEL_OPEN "direct-tcpip" ----
  // originator 填 127.0.0.1:0。服务端只把它记进日志,不用它连任何东西——
  // 目标地址是 dest_host/dest_port 那两个字段。填 0 端口是因为我们没有把
  // 本地 socket 的端口号拿在手上,而编一个假端口会让服务端的日志看起来
  // 像真的(那正是日志会被人当成证据的地方)。
  let open = chan.open_direct_tcpip_action(dest_host, dest_port, "127.0.0.1", 0)
  match send_action(conn, st, open) {
    None => return Failed(ForwardError::SendFailed)
    Some(s) => st = s
  }
  // ---- 2. 等 OPEN_CONFIRMATION / OPEN_FAILURE ----
  // 第一步只有一个包会来。理论上也可能有别的(比如 GLOBAL_REQUEST),所以
  // 循环而不是直接读一个包。
  let mut first = 0
  while first < 8 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return Failed(ForwardError::Closed)
      BadPacket(why) => return Failed(ForwardError::BadPacket(why))
      Packet(t, pl) => {
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(@channel.ChanError::OpenFailed(reason, desc)) =>
            return Failed(ForwardError::OpenFailed(reason, desc))
          Some(@channel.ChanError::Malformed(why)) =>
            return Failed(ForwardError::Malformed(why))
          Some(_) => return Failed(ForwardError::Malformed("unexpected"))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None => return Failed(ForwardError::SendFailed)
            Some(s) => st = s
          }
        }
        if t == 0x5b || t == 0x5c {
          first = 8
        } else {
          first = first + 1
        }
      }
    }
  }
  if !chan.open_done {
    return Failed(ForwardError::Malformed("no_open_confirmation"))
  }
  // ---- 3. 转发 ----
  // 循环体和 exec 的那一段是同一个形状:先把窗口允许的字节发完,缓冲空了
  // 才发 EOF,然后收一个包。顺序不能换——先发 EOF 再补数据,等于告诉服务端
  // 「输入到此为止」,而目标服务会拿到一份截断的数据流**并且不报错**。
  let mut pending = stdin_data
  let mut eof_pending = true
  let mut packets = 0
  let cap = 65536
  while !chan.finished() {
    if packets >= cap {
      return Failed(ForwardError::TooManyPackets)
    }
    while pending.length() > 0 {
      let (c1, action, rest) = chan.stdin_take(pending)
      chan = c1
      match action {
        None => break
        Some(a) => {
          match send_action(conn, st, a) {
            None => return Failed(ForwardError::SendFailed)
            Some(s) => st = s
          }
          pending = rest
        }
      }
    }
    if eof_pending && pending.length() == 0 {
      let (c1, a) = chan.eof_action()
      chan = c1
      match a {
        None => ()
        Some(x) =>
          match send_action(conn, st, x) {
            None => return Failed(ForwardError::SendFailed)
            Some(s) => st = s
          }
      }
      eof_pending = false
    }
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return Failed(ForwardError::Closed)
      BadPacket(why) => return Failed(ForwardError::BadPacket(why))
      Packet(t, pl) => {
        packets = packets + 1
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(@channel.ChanError::Malformed(why)) =>
            return Failed(ForwardError::Malformed(why))
          Some(@channel.ChanError::OpenFailed(reason, desc)) =>
            return Failed(ForwardError::OpenFailed(reason, desc))
          // exec / subsystem 的失败在这条流程里没有意义(我们没发过那两种
          // 请求),但也不能当成成功——对端如果回了 CHANNEL_FAILURE,说明我们
          // 理解错了这条通道的语义。
          Some(_) => return Failed(ForwardError::Malformed("unexpected"))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None => return Failed(ForwardError::SendFailed)
            Some(s) => st = s
          }
        }
      }
    }
  }
  let rep = chan.report()
  let report = {
    auth: auth_report,
    dest_host,
    dest_port,
    remote_id: rep.remote_id,
    remote_max_packet: rep.remote_max_packet,
    stdout: rep.stdout,
    stdout_len: rep.stdout.length(),
    stdin_sent: rep.stdin_sent,
    stdin_packets: rep.stdin_packets,
    adjusts_sent: rep.adjusts_sent,
    eof_sent: rep.eof_sent,
    closed: chan.finished(),
  }
  // 「一个字节都没回来」和「有字节回来」是两种结果,规则只在这里定一次。
  if report.stdout_len == 0 {
    NoData(report)
  } else {
    Done(report)
  }
}
