///| Loop #78: forwarded-tcpip —— `ssh -R` 的协议层,服务端发起的那一半。
///

///|
/// `ssh -R 9000:db:5432 host` 在协议层是两件事:
///
///   1. 客户端先请**服务端**在它那边监听 9000(RFC 4254 §7.1 的
///      "tcpip-forward" 全局请求)。
///   2. 有人连上服务端那个端口之后,服务端**反过来**开一条
///      "forwarded-tcpip" 通道给客户端(RFC 4254 §7.2),通道上跑的是那条
///      TCP 连接的字节。客户端再把字节接到自己的本地目标上。
///
/// 这和 Loop #76 的 direct-tcpip 是**镜像**关系:那边是客户端开通道、服务端
/// 去连目标;这边是服务端开通道、客户端去连目标。两边共用同一个通道状态机
/// (`src/channel`),但**号的方向是反的**——这正是本文件存在的原因。
///
/// ## 号的方向
///
/// 服务端发起的 open 里,sender 是**服务端**的号。我们回 CHANNEL_OPEN_CONFIRMATION
/// 时,recipient 用它、sender 用**我们**的号;之后服务端发来的 DATA、EOF、
/// CLOSE 的 recipient 都是我们的号。所以现有 `ChanState` 的
/// `local_channel`(我们的号)/ `remote_id`(对端的号)约定可以原样复用,
/// 只是这次是我们**回**确认包,而不是等对端回。
///
/// ## 三件只有实测才能定下来的事
///
/// 1. **回包可能没有端口。** 客户端要 port=0 时,服务端回一个 u32(它挑的
///    端口);客户端自己指定端口时,回包载荷是**空的**。无条件读 u32 的解析器
///    在后一种情况下会读出载荷末尾。实测见 `host/remote_fwd_capture.py`。
///
/// 2. **open 里的端口是「监听端口」,不是「被接受连接的临时端口」。**
///    OpenSSH 的客户端靠它和本地配置核对这条通道是不是自己请求的那一条。
///    搞错的话,一个监听 9000 的转发会被当成监听 45000 的转发。
///
/// 3. **服务端不知道我们的本地目标。** "tcpip-forward" 请求里只有监听地址
///    和端口,没有「连到哪里去」——那是客户端自己的配置。所以本地目标必须由
///    调用方给进来(`dest_host` / `dest_port`),不能从通道里推出来。
///
/// ## 这个中继不是完整双工
///
/// MoonBit 没有线程,而两个阻塞读不可能同时进行(先读哪个都会把另一个饿死),
/// 所以这里的做法是:**写完本地端才去读它**。本地目标不回话的时候,中继会
/// 停在那儿等——这是本实现的已知边界,不是协议的限制。一个真正的全双工
/// 中继需要两个方向都能「轮询」,那要求 SSH 传输层也能非阻塞读,那是另一个
/// Loop 的事。
///
/// 已知边界的准确说法:本地端**只在刚写完之后**才被读。SSH 端发来的数据
/// 在这期间会留在 socket 缓冲区里,不会丢,但会被推迟到下一次读本地端之后
/// 才处理。

///|
/// 一次远程端口转发的结果
pub(all) struct RemoteForwardReport {
  /// 认证阶段的报告。
  ///
  /// 和 `ForwardReport` 一样带着它:「认证成功但主机密钥没被记住」和
  /// 「认证被拒」是两件后果相反的事,合成一个错误名就没法处置了。
  auth : AuthReport
  /// 服务端在它那边监听的端口。
  ///
  /// 客户端要 port=0 时这是服务端挑的;客户端指定端口时这就是我们指定的
  /// 那个(回包里没有端口可读)。
  listen_port : Int32
  /// 服务端发起的通道号
  remote_id : Int32
  /// 通道类型(正常情况下是 "forwarded-tcpip")
  channel_type : String
  /// 服务端说「监听的是」那个地址
  open_host : String
  /// 服务端说「监听的是」那个端口
  open_port : Int32
  /// 连上服务端那个监听端口的人的地址
  originator_ip : String
  originator_port : Int32
  /// 写进本地连接的字节数
  to_link : Int32
  /// 从通道收到、并且写进本地连接的字节数
  from_channel : Int32
  /// 从通道收到、并且转发给服务端的字节数
  to_channel : Int32
  /// 发出的 CHANNEL_DATA 包数
  data_packets : Int32
  /// CHANNEL_EOF 有没有发出去
  eof_sent : Bool
  /// 通道是不是正常收尾
  closed : Bool
}

///|
/// 远程端口转发的失败原因
pub(all) enum RemoteForwardError {
  /// 认证没过,什么都没开始
  AuthFailed(AuthError)
  /// 服务端拒绝了 "tcpip-forward" 请求。
  ///
  /// 单列,是因为这是**服务端明确说了不行**(AllowTcpForwarding no、
  /// 权限不足等等),而且服务端**没有**给出理由——协议里没有理由字段。
  /// 把它和「连不上」混成一个错误名,用户就会去查网络而不是查配置。
  ForwardRefused
  /// 服务端发来的通道不是我们请求的那一条(监听地址或端口对不上),
  /// 或者通道类型本客户端不支持。
  ///
  /// 带着一句人话,因为拒绝的原因只有这一行能说清。
  UnexpectedChannel(String)
  /// 包在通道状态下无法解释
  Malformed(String)
  /// 连接断了
  Closed
  /// 包格式不对
  BadPacket(String)
  /// 发包失败
  SendFailed
  /// 本地目标连不上
  LinkFailed(String)
  /// 包数超限
  TooManyPackets
}

///|
/// 远程端口转发的结果
pub(all) enum RemoteForwardOutcome {
  /// 通道跑完了,而且**有字节回来**
  Done(RemoteForwardReport)
  /// 通道开了又关,但**一个字节也没回来**。
  ///
  /// 和 `ForwardOutcome::NoData` 同一个理由:沉默不能被报成成功。
  NoData(RemoteForwardReport)
  /// 出错了
  Failed(RemoteForwardError)
}

///|
/// 从本地端一次最多读多少字节。
///
/// 32 KiB 是 SSH 通道的默认最大包长(`CHAN_SES_PACKET_DEFAULT`)。再大也没有
/// 用——发出去的时候会被对端的最大包长夹回来,只是白读一次。
const LINK_CHUNK : Int32 = 32768

///|
/// 发起一次远程端口转发:请服务端监听一个端口,等它把通道开过来,接上本地
/// 目标,再把两个方向的字节搬过去。
///
/// `connect` 是打开本地目标的闭包,签名 `(host, port) -> 连接?`。
///
/// 为什么要注入而不是直接在这里连:本地目标是什么、怎么连,是**驱动**的事
/// (native 是 TCP socket,浏览器端将来是别的),协议层不该知道。注入之后
/// 这一层对「本地端是什么」一无所知,也就不必在两处各写一份。
///
/// `payload` 是写进本地目标的第一个请求(可以是空的)。它存在的理由是让
/// 「本地 → 通道」这个方向能被测到:没有它,本地目标就只会回话,不会说话。
///
/// `on_granted` 在服务端同意监听之后被调用一次,参数是那个端口。之所以要
/// 这个回调,是因为**端口是转发过程的中间结果**:客户端请求 port=0 时,
///
/// 端口要等回包才知道,而回包到达之前中继根本还没开始。调用方(命令行
/// 驱动)要靠它去连服务端的监听端口,晚一步打印就来不及了。
pub fn[T : @transport.Transport, L : @transport.ByteStream] live_remote_forward(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  kh : @knownhosts.KnownHostsPolicy,
  listen_host : String,
  listen_port : Int32,
  on_granted : (Int32) -> Unit,
  dest_host : String,
  dest_port : Int32,
  connect : (String, Int32) -> L?,
  payload : FixedArray[Byte],
) -> RemoteForwardOutcome {
  let (auth, state_opt) = live_auth_with_state(conn, x, user, d, kh)
  let auth_report = match auth {
    Authenticated(r) => r
    Failed(e) => return Failed(RemoteForwardError::AuthFailed(e))
  }
  let st0 = match state_opt {
    None =>
      return Failed(
        RemoteForwardError::AuthFailed(
          AuthError::Transport(SessionError::NoServiceAccept),
        ),
      )
    Some(v) => v
  }
  let mut st = st0
  // ---- 1. GLOBAL_REQUEST "tcpip-forward" ----
  let req = @channel.tcpip_forward_request_payload(listen_host, listen_port)
  match send_raw(conn, st, @channel.SSH_MSG_GLOBAL_REQUEST, req) {
    None => return Failed(RemoteForwardError::SendFailed)
    Some(s) => st = s
  }
  // ---- 2. 等 REQUEST_SUCCESS / REQUEST_FAILURE ----
  // 回包里**可能**没有端口(客户端自己指定端口的时候),所以两种形状都要接。
  let mut granted = -1
  let mut seen = 0
  while seen < 16 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return Failed(RemoteForwardError::Closed)
      BadPacket(why) => return Failed(RemoteForwardError::BadPacket(why))
      Packet(t, pl) => {
        seen = seen + 1
        if t == @channel.SSH_MSG_REQUEST_SUCCESS {
          granted = match @channel.parse_request_success(pl) {
            // 空载荷:服务端没有分配端口,因为端口是我们自己指定的。
            None => listen_port
            Some(p) => p
          }
        } else if t == @channel.SSH_MSG_REQUEST_FAILURE {
          return Failed(RemoteForwardError::ForwardRefused)
        } else {
          // 别的消息(服务端可能先发点别的)——继续等。
          ()
        }
      }
    }
    if granted >= 0 {
      break
    }
  }
  if granted < 0 {
    return Failed(RemoteForwardError::Malformed("no_request_success"))
  }
  // 端口到了,先告诉调用方——它要靠这个去连服务端的监听端口。
  on_granted(granted)
  // ---- 3. 等服务端的 CHANNEL_OPEN("forwarded-tcpip") ----
  // 这一步会等到「有人连上服务端那个监听端口」为止,和真的 `ssh -R` 一样:
  // 转发是**有人用**的时候才发生的,不是发起请求的时候。
  let mut chan = @channel.ChanState::new_peer_opened(@channel.LOCAL_CHANNEL)
  let mut opened = false
  let mut waits = 0
  while !opened && waits < 64 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return Failed(RemoteForwardError::Closed)
      BadPacket(why) => return Failed(RemoteForwardError::BadPacket(why))
      Packet(t, pl) => {
        waits = waits + 1
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(@channel.ChanError::Malformed(why)) =>
            return Failed(RemoteForwardError::Malformed(why))
          Some(_) => return Failed(RemoteForwardError::Malformed("unexpected"))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None => return Failed(RemoteForwardError::SendFailed)
            Some(s) => st = s
          }
        }
        if chan.open_received {
          opened = true
        }
      }
    }
  }
  if !opened {
    return Failed(RemoteForwardError::Malformed("no_channel_open"))
  }
  // ---- 4. 核对这条通道是不是我们请求的那一条 ----
  // 服务端发来的 open 里的监听地址/端口,必须和我们请求的那一条对得上。
  // 对不上就**拒掉**:一条我们没请求过的通道,轻则接到了别人的转发,重则
  // 被用来把我们引到别的地方去。OpenSSH 的客户端也是这么做的
  // (`channel_connect_by_listen_address` 找不到匹配的转发就拒绝)。
  if chan.open_type != @channel.CHANNEL_TYPE_FORWARDED_TCPIP {
    let (c1, a) = chan.refuse_open_action(
      @channel.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
      "unsupported channel type: " + chan.open_type,
    )
    chan = c1
    match a {
      None => ()
      Some(x) =>
        match send_action(conn, st, x) {
          None => return Failed(RemoteForwardError::SendFailed)
          Some(s) => st = s
        }
    }
    return Failed(
      RemoteForwardError::UnexpectedChannel(
        "unsupported channel type: " + chan.open_type,
      ),
    )
  }
  if chan.open_port != granted {
    let (c1, a) = chan.refuse_open_action(
      @channel.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
      "forwarded channel does not match the requested listener",
    )
    chan = c1
    match a {
      None => ()
      Some(x) =>
        match send_action(conn, st, x) {
          None => return Failed(RemoteForwardError::SendFailed)
          Some(s) => st = s
        }
    }
    return Failed(
      RemoteForwardError::UnexpectedChannel(
        "listener port mismatch: open says " +
        chan.open_port.to_string() +
        ", we asked for " +
        granted.to_string(),
      ),
    )
  }
  // ---- 5. 确认这条通道 ----
  let (c1, a) = chan.confirm_open_action()
  chan = c1
  match a {
    None => return Failed(RemoteForwardError::Malformed("no_open_confirmation"))
    Some(x) =>
      match send_action(conn, st, x) {
        None => return Failed(RemoteForwardError::SendFailed)
        Some(s) => st = s
      }
  }
  // ---- 6. 接上本地目标 ----
  let link = match connect(dest_host, dest_port) {
    None =>
      return Failed(
        RemoteForwardError::LinkFailed(dest_host + ":" + dest_port.to_string()),
      )
    Some(l) => l
  }
  // ---- 7. 中继 ----
  let mut to_link = 0
  let mut from_channel = 0
  let mut to_channel = 0
  let mut packets = 0
  let mut expect_link = false
  let mut link_open = true
  let mut closing = false
  if payload.length() > 0 {
    if !link.stream_send(payload) {
      link.stream_close()
      return Failed(RemoteForwardError::LinkFailed("send"))
    }
    to_link = to_link + payload.length()
    expect_link = true
  }
  while !chan.finished() {
    if packets >= 65536 {
      link.stream_close()
      return Failed(RemoteForwardError::TooManyPackets)
    }
    // 7a. 本地端 -> 通道。只在**刚写完本地端之后**才读它。
    if expect_link && link_open {
      let chunk = link.stream_recv_some(LINK_CHUNK)
      if chunk.length() == 0 {
        // 本地端关了:把 EOF 告诉服务端,这一侧到此为止。
        link_open = false
        let (c2, eof) = chan.eof_action()
        chan = c2
        match eof {
          None => ()
          Some(x) =>
            match send_action(conn, st, x) {
              None => {
                link.stream_close()
                return Failed(RemoteForwardError::SendFailed)
              }
              Some(s) => st = s
            }
        }
      } else {
        let (c2, action, rest) = chan.stdin_take(chunk)
        chan = c2
        match action {
          None => ()
          Some(x) =>
            match send_action(conn, st, x) {
              None => {
                link.stream_close()
                return Failed(RemoteForwardError::SendFailed)
              }
              Some(s) => st = s
            }
        }
        to_channel = to_channel + chunk.length() - rest.length()
        packets = packets + 1
      }
      expect_link = false
    }
    // 7b. 通道 -> 本地端
    match recv_packet(conn, st.counters, st.recv) {
      Closed => {
        link.stream_close()
        return Failed(RemoteForwardError::Closed)
      }
      BadPacket(why) => {
        link.stream_close()
        return Failed(RemoteForwardError::BadPacket(why))
      }
      Packet(t, pl) => {
        packets = packets + 1
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(@channel.ChanError::Malformed(why)) => {
            link.stream_close()
            return Failed(RemoteForwardError::Malformed(why))
          }
          Some(_) => {
            link.stream_close()
            return Failed(RemoteForwardError::Malformed("unexpected"))
          }
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None => {
              link.stream_close()
              return Failed(RemoteForwardError::SendFailed)
            }
            Some(s) => st = s
          }
        }
        // 通道里收到的字节,取出来写进本地端。
        let (chan3, got) = chan.take_stdout()
        chan = chan3
        if got.length() > 0 {
          if !link.stream_send(got) {
            link.stream_close()
            return Failed(RemoteForwardError::LinkFailed("send"))
          }
          to_link = to_link + got.length()
          from_channel = from_channel + got.length()
          // 写完了,下一轮去读本地端的回答。
          expect_link = true
        }
        // 服务端说它那边没有更多数据了:我们这一侧也该收尾。
        //
        // 顺序是先 EOF 再 CLOSE:EOF 是「我的输入方向没有更多数据了」,CLOSE
        // 是「这条通道结束了」,RFC 4254 §5.3 就是这个次序,OpenSSH 自己的
        // 客户端也是这个次序。
        //
        // 早先这里写的**理由**是错的(「OpenSSH 的服务端是**收到**我们的 EOF
        // 之后才发它自己的 CLOSE,所以只发 EOF 不发 CLOSE 的话,服务端会一直等
        // 下去——症状是「连接还在,但永远不结束」」)。那句话是照着源码想象出来
        // 的,没有实测;实测的结果相反:
        //
        //   * 服务端在**被代理的 socket** 读到 EOF 时就发它自己的 CHANNEL_EOF,
        //     和我们发不发任何东西无关;
        //   * 服务端的 CHANNEL_CLOSE 由「我们发了 EOF」或「我们发了 CLOSE」
        //     任意一个触发——只发 EOF 不发 CLOSE,服务端照样回 CLOSE,客户端
        //     正常结束。
        //
        // 少发 CLOSE 不会挂住,是因为状态机收到对端的 CLOSE 时会自动回一个。
        // EOF 和 CLOSE 仍然都要发:少发 EOF,我们就少告诉对端一件事。
        //
        // 先关本地端:它是这一侧的输入,关了它,目标服务才知道没有更多请求了
        // (echo server 就是在那一刻打印它的 ECHO 摘要)。
        if t == 0x60 && !closing {
          closing = true
          link.stream_close()
          let (c2, eof) = chan.eof_action()
          chan = c2
          match eof {
            None => ()
            Some(x) =>
              match send_action(conn, st, x) {
                None => return Failed(RemoteForwardError::SendFailed)
                Some(s) => st = s
              }
          }
          let (c3, cls) = chan.close_action()
          chan = c3
          match cls {
            None => ()
            Some(x) =>
              match send_action(conn, st, x) {
                None => return Failed(RemoteForwardError::SendFailed)
                Some(s) => st = s
              }
          }
        }
      }
    }
  }
  link.stream_close()
  let report = {
    auth: auth_report,
    listen_port: granted,
    remote_id: chan.remote_id,
    channel_type: chan.open_type,
    open_host: chan.open_host,
    open_port: chan.open_port,
    originator_ip: chan.open_originator_ip,
    originator_port: chan.open_originator_port,
    to_link,
    from_channel,
    to_channel,
    data_packets: packets,
    eof_sent: chan.eof_sent,
    closed: chan.finished(),
  }
  // 「一个字节都没回来」和「有字节回来」是两种结果,规则只在这里定一次。
  if report.from_channel == 0 && report.to_channel == 0 {
    NoData(report)
  } else {
    Done(report)
  }
}

///|
/// 发一个不是通道动作的包(这里只有全局请求)。
///
/// `send_action` 收的是 `ChanAction`,而全局请求不是通道消息——它是连接级
/// 的消息,走的是同一条传输,但没有通道号可填。分成两个函数而不是把
/// `ChanAction` 扩成「也许没有通道号」,是因为那会让**每一个**处理动作的
/// 地方都要多问一句「这个动作有通道号吗」。
fn[T : @transport.Transport] send_raw(
  conn : T,
  st : SessionState,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> SessionState? {
  if send_packet(conn, st.counters, st.send, msg_type, payload) {
    Some(st)
  } else {
    None
  }
}
