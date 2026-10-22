///| Loop #79: 本地监听器 —— `ssh -L` 的另外那一半。
///

///|
/// `ssh -L 9000:db:5432 host` 在协议层上是两件事:
///
///   1. **本地监听**:客户端在本地监听 9000(Loop #76 只做了协议那半,
///      没有人监听);
///   2. **开通道**:每有一条本地连接进来,客户端就开一条 "direct-tcpip"
///      通道,请**服务端**去连 `db:5432`,然后把两个方向的字节搬过去。
///
/// 本文件做第 2 件事的**驱动**,并把第 1 件事的接口做成注入的。
///
/// ## 为什么监听器是注入的
///
/// `src/sshclient` **不依赖** `src/tcp`(Loop #64 刻意去掉的依赖箭头,
/// 而且 loop64 的门禁断言全仓只有 `@tcp.TcpConn` 一个 Transport 实现)。
/// 所以本文件不能提到 `TcpListener`,只能拿到一个「接受一条连接」的闭包:
///
///     accept : () -> AcceptResult[连接]
///
/// `AcceptResult` 有三个取值,不是两个:
///   * `Accepted` —— 有连接进来了;
///   * `NoConnection` —— 这一轮还没有(继续等);
///   * `Failed` —— 监听器出错了(该停下)。
///
/// 「还没有」和「出错了」必须分开:前者继续等,后者该停下。合成一个 `None`
/// 的话,一个坏掉的监听器会表现成「一直没人用这个转发」,查起来完全是
/// 另一个方向。
///
/// 这和 Loop #78 的 `connect : (String, Int32) -> L?` 是同一个规矩:
/// **协议层不该知道本地端是什么**,浏览器端将来也没有本地监听器。
///
/// ## 中继的形状:严格交替
///
/// MoonBit 没有线程,两个阻塞读不可能同时进行(先读哪个都会把另一个饿死),
/// 所以中继只能**一轮一个方向**。这里的轮次是:
///
///   1. 把欠着的字节补发出去(如果有);
///   2. 读本地端 → 送进通道;
///   3. 读通道 → 写回本地端。
///
/// 「先本地后通道」不是随便挑的:`ssh -L` 的常见形状是「本地客户端先说话」
/// ——请求-响应型的协议(HTTP、数据库、SSH 自己)都是这样。而第 3 步必须在
/// 第 2 步之后:本地端发完请求之后就在等回复,如果这时候先去读本地端
/// (阻塞),回复会一直躺在通道里没人取,本地端等不到,就是一个死锁。
///
/// 这个形状的代价,写在这里而不是藏起来:
///   * **对端先说话**的目标(比如先发 banner 的 SMTP)会卡在第 2 步——
///     本地端一直安静,我们就一直等它。真正的 `ssh -L` 用 select 同时看两个
///     方向,不会这样。
///   * 要同时看两个方向,前提是**传输层能轮询**(`wire_read_exact` 得有个
///     「等不等得到」的版本)。那是另一个 Loop 的事。
///
/// ## 「读满才算还有」
///
/// 第 2 步一次要 32 KiB,读到**不满**就说明本地端暂时空了,这一轮该轮到
/// 通道那边;读满了就继续读、继续发。
///
/// 这条不是优化,是**能不能传完大文件**的分界线:SSH 通道的窗口是 2 MiB,
/// 而对端的 WINDOW_ADJUST 是**攒着**发的(OpenSSH 在消费过半之后才补)。
/// 如果每发 32 KiB 就回通道里等一个包,那么在对端攒够半窗之前我们一个包
/// 都等不到,双方互相等死——症状是「小文件正常,大文件传到 32 KiB 就停」。
///
/// ## 欠账(`pending`)必须留着
///
/// `stdin_take` 是**夹取**不是报错:窗口不够时它返回
/// `(状态, None, 全量剩余)`,意思是「这轮没轮到发,剩下的还在缓冲里」。
/// 把剩余丢掉就是**静默丢数据**:对端一慢、窗口一满,本地读来的字节就
/// 消失了,而转发看起来一切正常。
///
/// Loop #78 的中继正是这么写的(它把 `rest` 扔了),本轮一并修掉。

///|
/// 一轮 accept 的结果
pub(all) enum AcceptResult[L] {
  /// 有连接进来了:连接本身、对端地址、对端端口
  Accepted(L, String, Int32)
  /// 这一轮没有连接(继续等)
  NoConnection
  /// 监听器出错了(该停下)
  Failed(String)
}

///|
/// 一次本地端口转发的结果
pub(all) struct LocalForwardReport {
  /// 认证阶段的报告。
  ///
  /// 带着它的理由和 Loop #78 一样:「认证成功但主机密钥没被记住」和
  /// 「认证被拒」是后果相反的两件事,合成一个错误名就没法处置了。
  auth : AuthReport
  /// 服务端要连的目标
  dest_host : String
  dest_port : Int32
  /// 一共转发了多少条本地连接
  connections : Int32
  /// 从本地连接读出来、送进通道的字节数
  local_to_channel : Int32
  /// 从通道读出来、写回本地连接的字节数
  channel_to_local : Int32
  /// 发出的 CHANNEL_DATA 包数
  packets : Int32
  /// 最后一条通道的服务端通道号
  remote_id : Int32
  /// 最后一条连接的**真实**对端地址
  ///
  /// 这是 Loop #76 做不到的:那时候没有人在监听,originator 只能编一个
  /// "127.0.0.1", 0。现在它是 accept 回来的那个地址,服务端日志里的
  /// originator 可以拿它对照。
  originator_ip : String
  originator_port : Int32
  /// CHANNEL_EOF 有没有发出去
  eof_sent : Bool
  /// 最后一条通道是不是正常收尾
  closed : Bool
}

///|
/// 本地端口转发的失败原因
pub(all) enum LocalForwardError {
  /// 认证没过,什么都没开始
  AuthFailed(AuthError)
  /// 服务端拒绝开这条通道(reason code + 服务端的描述)
  OpenFailed(Int32, String)
  /// 监听器出错了
  AcceptFailed(String)
  /// 包在通道状态下无法解释
  Malformed(String)
  /// 连接断了
  Closed
  /// 包格式不对
  BadPacket(String)
  /// 发包失败
  SendFailed
  /// 本地连接写失败
  LinkFailed(String)
  /// 包数超限
  TooManyPackets
  /// 一直没有等到连接
  ///
  /// 单列,是因为它和「连上了但转发失败」是两件事:前者是**没人用**这个
  /// 转发,后者是**用了但没成功**。合成一个错误名,使用者就会去查网络,
  /// 而问题其实在「对端根本没连过来」。
  NoConnection
}

///|
/// 本地端口转发的结果
pub(all) enum LocalForwardOutcome {
  /// 转发正常结束
  Done(LocalForwardReport)
  /// 出错了
  Failed(LocalForwardError)
}

///|
/// 从本地连接一次最多读多少字节。
///
/// 32 KiB 是 SSH 通道的默认最大包长(`CHAN_SES_PACKET_DEFAULT`)。再大也没有
/// 用——发出去的时候会被对端的最大包长夹回来,只是白读一次。
///
/// 和 `remotefwd.mbt` 的 `LINK_CHUNK` 同值但**分开命名**:两个中继各有各的
/// 生命周期,常量留在各自文件里,改一个不该悄悄改另一个。
const LOCAL_LINK_CHUNK : Int32 = 32768

///|
/// 最多发多少个 CHANNEL_DATA 包。
///
/// 这是**防呆**,不是防攻击:一个对端不停回 WINDOW_ADJUST、我们不停回数据的
/// 循环会吃光内存。64K 个包 × 32 KiB ≈ 2 GiB,已经比正常转发大得多。
const PACKET_CAP : Int32 = 65536

///|
/// 发起一次本地端口转发。
///
/// 认证只做**一次**,之后每条本地连接都在同一条 SSH 连接上开一条新通道——
/// 这正是真的 `ssh -L` 的行为(一条 SSH 连接,多条通道),而不是每条连接
/// 重新认证一次。
///
/// `accept` 是「接受一条本地连接」的闭包,签名 `() -> AcceptResult[L]`。
///
/// `max_conns` 是「最多转发多少条连接」。0 表示不限——真的 `ssh -L` 就是
/// 不限的,而门禁需要一个能停下来的地方。
///
/// `max_idle_rounds` 是「连续多少轮没有连接之后放弃」。0 表示不限。
/// 它把「监听器坏了」和「暂时没人连」分得开:真的没人用的转发会安静地
/// 等下去,而一个坏掉的监听器会让 accept 一直返回 `NoConnection`。
pub fn[T : @transport.Transport, L : @transport.ByteStream] live_local_forward(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  kh : @knownhosts.KnownHostsPolicy,
  accept : () -> AcceptResult[L],
  dest_host : String,
  dest_port : Int32,
  max_conns : Int32,
  max_idle_rounds : Int32,
) -> LocalForwardOutcome {
  let (auth, state_opt) = live_auth_with_state(conn, x, user, d, kh)
  let auth_report = match auth {
    Authenticated(r) => r
    Failed(e) => return Failed(LocalForwardError::AuthFailed(e))
  }
  let mut st = match state_opt {
    None =>
      return Failed(
        LocalForwardError::AuthFailed(
          AuthError::Transport(SessionError::NoServiceAccept),
        ),
      )
    Some(v) => v
  }
  let mut connections = 0
  let mut local_to_channel = 0
  let mut channel_to_local = 0
  let mut packets = 0
  let mut remote_id = -1
  let mut originator_ip = ""
  let mut originator_port = 0
  let mut eof_sent = false
  let mut closed = false
  // 通道号逐条递增。SSH 允许复用通道号(前一条关掉之后),但递增更省心:
  // 万一前一条还没完全收尾,复用同一个号会让服务端把两条通道搞混。
  let mut local_channel = @channel.DEFAULT_LOCAL_CHANNEL
  let mut idle = 0
  while max_conns <= 0 || connections < max_conns {
    match accept() {
      NoConnection => {
        idle = idle + 1
        if max_idle_rounds > 0 && idle > max_idle_rounds {
          return Failed(LocalForwardError::NoConnection)
        }
      }
      Failed(why) => return Failed(LocalForwardError::AcceptFailed(why))
      Accepted(link, ip, port) => {
        idle = 0
        connections = connections + 1
        let (st2, rep, err) = forward_one(
          conn, st, link, ip, port, dest_host, dest_port, local_channel,
        )
        st = st2
        match err {
          Some(e) => return Failed(e)
          None => ()
        }
        local_to_channel = local_to_channel + rep.local_to_channel
        channel_to_local = channel_to_local + rep.channel_to_local
        packets = packets + rep.packets
        remote_id = rep.remote_id
        originator_ip = ip
        originator_port = port
        eof_sent = rep.eof_sent
        closed = rep.closed
        local_channel = local_channel + 1
      }
    }
  }
  let report = {
    auth: auth_report,
    dest_host,
    dest_port,
    connections,
    local_to_channel,
    channel_to_local,
    packets,
    remote_id,
    originator_ip,
    originator_port,
    eof_sent,
    closed,
  }
  Done(report)
}

///|
/// 一条本地连接的转发结果
priv struct LocalConnReport {
  remote_id : Int32
  local_to_channel : Int32
  channel_to_local : Int32
  packets : Int32
  eof_sent : Bool
  closed : Bool
}

///|
/// 转发一条本地连接:开通道、搬字节、收尾。
///
/// 返回 `(新的会话状态, 这条连接的计数, 失败原因?)`。
fn[T : @transport.Transport, L : @transport.ByteStream] forward_one(
  conn : T,
  st : SessionState,
  link : L,
  originator_ip : String,
  originator_port : Int32,
  dest_host : String,
  dest_port : Int32,
  local_channel : Int32,
) -> (SessionState, LocalConnReport, LocalForwardError?) {
  let mut st = st
  let empty = {
    remote_id: -1,
    local_to_channel: 0,
    channel_to_local: 0,
    packets: 0,
    eof_sent: false,
    closed: false,
  }
  let mut chan = @channel.ChanState::new(local_channel)
  // ---- 1. CHANNEL_OPEN "direct-tcpip" ----
  // originator 现在是**真的**:accept 回来的那个地址。Loop #76 只能填
  // "127.0.0.1", 0,因为那时候没有人监听,拿不到对端地址。
  let open = chan.open_direct_tcpip_action(
    dest_host, dest_port, originator_ip, originator_port,
  )
  match send_action(conn, st, open) {
    None => return (st, empty, Some(LocalForwardError::SendFailed))
    Some(s) => st = s
  }
  // ---- 2. 等 OPEN_CONFIRMATION / OPEN_FAILURE ----
  let mut first = 0
  while first < 8 && !chan.open_done {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return (st, empty, Some(LocalForwardError::Closed))
      BadPacket(why) =>
        return (st, empty, Some(LocalForwardError::BadPacket(why)))
      Packet(t, pl) => {
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(@channel.ChanError::OpenFailed(reason, desc)) =>
            return (
              st,
              empty,
              Some(LocalForwardError::OpenFailed(reason, desc)),
            )
          Some(@channel.ChanError::Malformed(why)) =>
            return (st, empty, Some(LocalForwardError::Malformed(why)))
          Some(_) =>
            return (st, empty, Some(LocalForwardError::Malformed("unexpected")))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None => return (st, empty, Some(LocalForwardError::SendFailed))
            Some(s) => st = s
          }
        }
        first = first + 1
      }
    }
  }
  if !chan.open_done {
    return (
      st,
      empty,
      Some(LocalForwardError::Malformed("no_open_confirmation")),
    )
  }
  // ---- 3. 中继 ----
  // 三步一轮,一轮一个方向:
  //   3a. 把欠着的字节补发出去;
  //   3b. 读本地端 → 送进通道;
  //   3c. 读通道 → 写回本地端。
  //
  // `pending` 是**还没发出去**的字节。它必须留着:`stdin_take` 是**夹取**
  // 不是报错——窗口不够时它返回 `(状态, None, 全量剩余)`,意思是「这轮没
  // 轮到发,剩下的还在缓冲里」。把剩余丢掉就是**静默丢数据**:对端一慢、
  // 窗口一满,本地读来的字节就消失了,而转发看起来一切正常。
  let mut pending : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut link_open = true
  let mut local_to_channel = 0
  let mut channel_to_local = 0
  let mut packets = 0
  let mut closing = false
  while !chan.finished() {
    if packets >= PACKET_CAP {
      link.stream_close()
      return (
        st,
        {
          remote_id: chan.remote_id,
          local_to_channel,
          channel_to_local,
          packets,
          eof_sent: chan.eof_sent,
          closed: false,
        },
        Some(LocalForwardError::TooManyPackets),
      )
    }
    // ---- 3a. 先把欠着的补上 ----
    //
    // 补发是**循环**的,不是一次:`stdin_take` 一次最多发一个包(被窗口和
    // 对端的最大包长夹着),一次只补一个包的话,窗口开着 2 MiB 的时候我们
    // 每轮只发 32 KiB,而对端的 WINDOW_ADJUST 是攒着发的——一轮一个包会
    // 把自己卡死在对端下一次 adjust 之前。
    if pending.length() > 0 {
      let mut sending = true
      while sending {
        let before = pending.length()
        let (c2, action, rest) = chan.stdin_take(pending)
        chan = c2
        pending = rest
        match action {
          None => sending = false
          Some(x) =>
            match send_action(conn, st, x) {
              None => {
                link.stream_close()
                return (
                  st,
                  {
                    remote_id: chan.remote_id,
                    local_to_channel,
                    channel_to_local,
                    packets,
                    eof_sent: chan.eof_sent,
                    closed: false,
                  },
                  Some(LocalForwardError::SendFailed),
                )
              }
              Some(s) => {
                st = s
                // 这一包带走了多少字节:读之前减去读之后。
                //
                // 这一行不是可有可无的记账。被窗口裁掉的那部分**此刻**还没
                // 有发出去(它在 `pending` 里),所以在 3b 读的时候只记了
                // 「被窗口收下的那部分」;真正发出去是在这里。不在这里补上,
                // 计数器就会**少算**被裁掉又补发的那部分——症状是「远端收到
                // 的字节是对的,客户端自己报的字节数偏小」,而且偏小的量正好
                // 等于大文件转发时被窗口裁掉的总和。
                local_to_channel = local_to_channel + before - pending.length()
                packets = packets + 1
              }
            }
        }
      }
    }
    // ---- 3b. 本地端 -> 通道 ----
    //
    // 循环读本地端,直到「本地端暂时空了」或者「窗口欠账了」。
    //
    // 「本地端暂时空了」的判据是**这一读没有读满**:一次要 32 KiB,读到
    // 不到 32 KiB 就说明 socket 里暂时没有更多了。读满了就说明后面多半
    // 还有,继续读、继续发。
    //
    // 这一条不是优化,是**能不能传完大文件**的分界线。原因是对端的
    // WINDOW_ADJUST 是**攒着**发的(OpenSSH 在消费过半之后才补窗口),而
    // SSH 通道的窗口是 2 MiB:如果每发 32 KiB 就回通道里等一个包,那么
    // 在对端攒够半窗之前我们一个包都等不到,双方互相等死。
    //
    // 欠账的时候**不读**本地端:读进来的字节只会让缓冲更长,而窗口不开就
    // 一个字节也发不出去。
    if link_open && pending.length() == 0 {
      let mut more = true
      while more && pending.length() == 0 {
        let chunk = link.stream_recv_some(LOCAL_LINK_CHUNK)
        if chunk.length() == 0 {
          // 本地端关了:告诉服务端这一侧没有更多数据了,然后收尾。
          //
          // **不关本地 socket**:本地端的 EOF 只是「我这边没数据了」,服务端
          // 还可能有回复要送回来(回声服务就是这样)。把 socket 关掉,那些
          // 字节就永远送不到了。
          link_open = false
          more = false
          let (c2, eof) = chan.eof_action()
          chan = c2
          match eof {
            None => ()
            Some(x) =>
              match send_action(conn, st, x) {
                None =>
                  return (
                    st,
                    {
                      remote_id: chan.remote_id,
                      local_to_channel,
                      channel_to_local,
                      packets,
                      eof_sent: chan.eof_sent,
                      closed: false,
                    },
                    Some(LocalForwardError::SendFailed),
                  )
                Some(s) => st = s
              }
          }
        } else {
          let (c2, action, rest) = chan.stdin_take(chunk)
          chan = c2
          pending = rest
          match action {
            None => ()
            Some(x) =>
              match send_action(conn, st, x) {
                None => {
                  link.stream_close()
                  return (
                    st,
                    {
                      remote_id: chan.remote_id,
                      local_to_channel,
                      channel_to_local,
                      packets,
                      eof_sent: chan.eof_sent,
                      closed: false,
                    },
                    Some(LocalForwardError::SendFailed),
                  )
                }
                Some(s) => {
                  st = s
                  packets = packets + 1
                }
              }
          }
          // 只有**被通道收下的**那部分才算「已经送出去了」:被窗口裁掉的
          // 还在 `pending` 里,等 3a 补发的时候才计。
          local_to_channel = local_to_channel + chunk.length() - rest.length()
          // 读满了才继续读:没读满说明本地端暂时没有更多了,这一轮该轮到
          // 通道那边了。
          more = chunk.length() == LOCAL_LINK_CHUNK
        }
      }
    }
    // ---- 3c. 通道 -> 本地端 ----
    match recv_packet(conn, st.counters, st.recv) {
      Closed => {
        link.stream_close()
        return (
          st,
          {
            remote_id: chan.remote_id,
            local_to_channel,
            channel_to_local,
            packets,
            eof_sent: chan.eof_sent,
            closed: false,
          },
          Some(LocalForwardError::Closed),
        )
      }
      BadPacket(why) => {
        link.stream_close()
        return (
          st,
          {
            remote_id: chan.remote_id,
            local_to_channel,
            channel_to_local,
            packets,
            eof_sent: chan.eof_sent,
            closed: false,
          },
          Some(LocalForwardError::BadPacket(why)),
        )
      }
      Packet(t, pl) => {
        packets = packets + 1
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(@channel.ChanError::Malformed(why)) => {
            link.stream_close()
            return (
              st,
              {
                remote_id: chan.remote_id,
                local_to_channel,
                channel_to_local,
                packets,
                eof_sent: chan.eof_sent,
                closed: false,
              },
              Some(LocalForwardError::Malformed(why)),
            )
          }
          Some(@channel.ChanError::OpenFailed(reason, desc)) => {
            link.stream_close()
            return (
              st,
              {
                remote_id: chan.remote_id,
                local_to_channel,
                channel_to_local,
                packets,
                eof_sent: chan.eof_sent,
                closed: false,
              },
              Some(LocalForwardError::OpenFailed(reason, desc)),
            )
          }
          Some(_) => {
            link.stream_close()
            return (
              st,
              {
                remote_id: chan.remote_id,
                local_to_channel,
                channel_to_local,
                packets,
                eof_sent: chan.eof_sent,
                closed: false,
              },
              Some(LocalForwardError::Malformed("unexpected")),
            )
          }
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None => {
              link.stream_close()
              return (
                st,
                {
                  remote_id: chan.remote_id,
                  local_to_channel,
                  channel_to_local,
                  packets,
                  eof_sent: chan.eof_sent,
                  closed: false,
                },
                Some(LocalForwardError::SendFailed),
              )
            }
            Some(s) => st = s
          }
        }
        // 通道里收到的字节,写进本地连接。
        let (chan3, got) = chan.take_stdout()
        chan = chan3
        if got.length() > 0 {
          if !link.stream_send(got) {
            link.stream_close()
            return (
              st,
              {
                remote_id: chan.remote_id,
                local_to_channel,
                channel_to_local,
                packets,
                eof_sent: chan.eof_sent,
                closed: false,
              },
              Some(LocalForwardError::LinkFailed("send")),
            )
          }
          channel_to_local = channel_to_local + got.length()
        }
        // 服务端说它那边没有更多数据了:目标已经收尾,本地端也该看到结束。
        //
        // 顺序是先 EOF 再 CLOSE:EOF 是「我的输入方向没有更多数据了」,CLOSE
        // 是「这条通道结束了」,RFC 4254 §5.3 就是这个次序。
        //
        // 先关本地端:它是这一侧的输入,关了它,目标服务才知道没有更多请求了
        // (回声服务就是在那一刻打印它的 ECHO 摘要)。
        if t == 0x60 && !closing {
          closing = true
          link.stream_close()
          let (c2, eof) = chan.eof_action()
          chan = c2
          match eof {
            None => ()
            Some(x) =>
              match send_action(conn, st, x) {
                None =>
                  return (
                    st,
                    {
                      remote_id: chan.remote_id,
                      local_to_channel,
                      channel_to_local,
                      packets,
                      eof_sent: chan.eof_sent,
                      closed: false,
                    },
                    Some(LocalForwardError::SendFailed),
                  )
                Some(s) => st = s
              }
          }
          let (c3, cls) = chan.close_action()
          chan = c3
          match cls {
            None => ()
            Some(x) =>
              match send_action(conn, st, x) {
                None =>
                  return (
                    st,
                    {
                      remote_id: chan.remote_id,
                      local_to_channel,
                      channel_to_local,
                      packets,
                      eof_sent: chan.eof_sent,
                      closed: false,
                    },
                    Some(LocalForwardError::SendFailed),
                  )
                Some(s) => st = s
              }
          }
        }
      }
    }
  }
  (
    st,
    {
      remote_id: chan.remote_id,
      local_to_channel,
      channel_to_local,
      packets,
      eof_sent: chan.eof_sent,
      closed: chan.finished(),
    },
    None,
  )
}
