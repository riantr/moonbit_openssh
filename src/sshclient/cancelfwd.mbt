///| Loop #81: cancel-tcpip-forward —— 远程端口转发的「撤销」那一半。
///

///|
/// `ssh -R` 在协议层是两件事:请服务端监听(RFC 4254 §7.1 的 "tcpip-forward"),
/// 和**撤销**这个监听(同节的 "cancel-tcpip-forward")。前一半是 Loop #78;
/// 后一半一直空着——`src/channel/globalreq.mbt` 里只有那个常量,没人发过它。
/// AGENTS.md 里「这个 Loop 没有关掉的缺口」那一节列着它。
///
/// ## 撤销比请求难,因为它的输入是请求的**结果**
///
/// 请求那条的载荷是自描述的:名字、want_reply、地址、端口,发出去就行。
/// 撤销那条的载荷里,地址和端口必须和当初那条请求对齐,而对齐的标准由服务端定:
///
///   * 地址是**逐字节比较**的(`strcmp(c->path, host) == 0`),服务端存的
///     `c->path` 是当初请求里那个字符串的原样;
///   * 端口比的是**服务端分配的**端口,不是 0。
///
/// 所以「撤销」的输入不是用户说的地址和端口,而是服务端当初答给我们的那个
/// 端口号,加上当初发出去的那个地址字符串。这两样都只有**做过那次请求**的
/// 客户端才有——这也是为什么这个流程是「请求 + 撤销」连在一起做的。
///
/// ## want_reply 的两种走法,和它们各自能证明什么
///
/// OpenSSH 自己的客户端发这条请求时 want_reply=0,服务端因此**不回包**。
/// 一个「发完就等回包」的客户端会永远等下去——这是这条请求最容易踩的坑。
///
/// 但 want_reply=0 也意味着**放弃了一个能证明成败的信号**:没有回包,就没法
/// 区分「服务端撤销了」和「服务端压根没收到」。本仓库两种都做,而且用
/// **第二个请求**把 want_reply=0 的那一发变成可验证的:
///
///   1. cancel(P, want_reply=0) —— 服务端不回包;
///   2. cancel(P, want_reply=1) —— 回包必须是 REQUEST_FAILURE。
///
/// 第 2 步回 FAILURE 才说明第 1 步**真的生效了**:同一个连接上的包是有序的,
/// 服务端处理到第 2 步时第 1 步早就处理完了;要是第 1 步被丢掉或者格式错了,
/// 监听器还在,第 2 步会回 SUCCESS。两种 want_reply 因此都有了确定判据,
/// 而不是一个「希望如此」。
///
/// 反过来也成立:want_reply=1 的那一发回 SUCCESS,说明服务端**找到了**
/// 监听器并把它关了(`channel_cancel_rport_listener_tcpip` 只在找到匹配项时
/// 才返回 1);对同一个端口再撤一次就回 FAILURE,因为已经没有监听器了。

///|
/// 一次撤销的结果
pub(all) struct CancelAttempt {
  /// 这一发要的是不是回包
  want_reply : Bool
  /// 服务端有没有回包(want_reply=0 时一定是 false)
  replied : Bool
  /// 服务端说的是不是「成功」(SSH_MSG_REQUEST_SUCCESS)
  success : Bool
}

///|
/// 撤销一串请求的结果
pub(all) struct ForwardCancelReport {
  /// 认证阶段的报告
  auth : AuthReport
  /// 服务端监听的地址——和当初请求里发出去的那个字符串一样
  listen_host : String
  /// 我们请求的端口(通常是 0,让服务端自己挑)
  requested_port : Int32
  /// 服务端挑的端口——**撤销要用的就是它**
  granted_port : Int32
  /// 每一发的结果
  attempts : Array[CancelAttempt]
}

///|
/// 撤销流程的失败原因
pub(all) enum ForwardCancelError {
  /// 认证没过,什么都没开始
  AuthFailed(AuthError)
  /// 服务端拒绝了 "tcpip-forward" 请求本身
  ///
  /// 单列,是因为这是**服务端明确说了不行**(AllowTcpForwarding no 之类),
  /// 和「撤销失败」是两件不同的事:请求被拒的时候压根没有监听器可撤。
  ForwardRefused
  /// 发包失败
  SendFailed
  /// 连接断了
  Closed
  /// 包格式不对
  BadPacket(String)
  /// 要回包但没等到
  ///
  /// 服务端说 want_reply 就一定会回(`serverloop.c` 末尾那个 `if (want_reply)`),
  /// 没等到就是出了问题——**不是**「它没回说明成功了」。
  NoReply(String)
}

///|
/// 撤销流程的结果
pub(all) enum ForwardCancelOutcome {
  /// 每一发都做完了
  Done(ForwardCancelReport)
  /// 出错了
  Failed(ForwardCancelError)
}

///|
/// 发起一次远程端口转发,拿到服务端分配的端口,然后按 `want_reply_steps`
/// 一发一发地撤销它。
///
/// `want_reply_steps` 的每个元素是那一发取消请求的 want_reply。常见的两种
/// 用法:
///
///   * `[true, true]` —— 第一发要回包(服务端答 SUCCESS,证明它找到了监听器),
///     第二发要回包(服务端答 FAILURE,证明监听器确实已经没了);
///   * `[false, true]` —— 第一发不要回包(和 OpenSSH 自己的客户端一样),
///     第二发要回包(必须是 FAILURE,否则说明第一发没生效)。
///
/// `on_granted` 在服务端同意监听之后、**撤销之前**被调用一次,参数是那个
/// 端口。之所以留这个回调:端口是「服务端挑的」,而探测端口开没开只能在
/// 撤销**之前**做——撤销之后就晚了。调用方要靠它去连服务端的监听端口。
pub fn[T : @transport.Transport] live_forward_cancel_ladder(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  kh : @knownhosts.KnownHostsPolicy,
  listen_host : String,
  listen_port : Int32,
  want_reply_steps : Array[Bool],
  on_granted : (Int32) -> Unit,
) -> ForwardCancelOutcome {
  let (auth, state_opt) = live_auth_with_state(conn, x, user, d, kh)
  let auth_report = match auth {
    Authenticated(r) => r
    Failed(e) => return Failed(ForwardCancelError::AuthFailed(e))
  }
  let st0 = match state_opt {
    None =>
      return Failed(
        ForwardCancelError::AuthFailed(
          AuthError::Transport(SessionError::NoServiceAccept),
        ),
      )
    Some(v) => v
  }
  let mut st = st0
  // ---- 1. GLOBAL_REQUEST "tcpip-forward":先请服务端监听 ----
  // 地址先归一化:OpenSSH 的客户端也是这么发的(`channel_rfwd_bind_host`),
  // 而撤销时要回**同一个**字符串,所以归一化必须发生在请求这一侧。
  let host = @channel.rfwd_bind_host(listen_host)
  let req = @channel.tcpip_forward_request_payload(host, listen_port)
  match send_raw(conn, st, @channel.SSH_MSG_GLOBAL_REQUEST, req) {
    None => return Failed(ForwardCancelError::SendFailed)
    Some(s) => st = s
  }
  // ---- 2. 等 REQUEST_SUCCESS:端口在这里才拿到 ----
  // 回包里**可能**没有端口(我们自己指定端口的时候),所以两种形状都要接。
  let mut granted = -1
  let mut seen = 0
  while seen < 16 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return Failed(ForwardCancelError::Closed)
      BadPacket(why) => return Failed(ForwardCancelError::BadPacket(why))
      Packet(t, pl) => {
        seen = seen + 1
        if t == @channel.SSH_MSG_REQUEST_SUCCESS {
          granted = match @channel.parse_request_success(pl) {
            // 空载荷:服务端没有分配端口,因为端口是我们自己指定的。
            None => listen_port
            Some(p) => p
          }
        } else if t == @channel.SSH_MSG_REQUEST_FAILURE {
          return Failed(ForwardCancelError::ForwardRefused)
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
    return Failed(ForwardCancelError::NoReply("no_request_success"))
  }
  // 端口到了,先告诉调用方——它要靠这个去探测监听端口还在不在。
  on_granted(granted)
  // ---- 3. 一发一发地撤销 ----
  let attempts : Array[CancelAttempt] = []
  let mut i = 0
  while i < want_reply_steps.length() {
    let want_reply = want_reply_steps[i]
    let payload = @channel.cancel_tcpip_forward_request_payload(
      host, granted, want_reply,
    )
    match send_raw(conn, st, @channel.SSH_MSG_GLOBAL_REQUEST, payload) {
      None => return Failed(ForwardCancelError::SendFailed)
      Some(s) => st = s
    }
    if !want_reply {
      // 服务端**不会**回包,而且不能等:等一个不会来的回包就是挂死。
      // 这一发有没有生效,靠后面那一发要回包的 cancel 来证明。
      attempts.push(CancelAttempt::{
        want_reply: false,
        replied: false,
        success: false,
      })
      i = i + 1
      continue
    }
    // 要回包:等 REQUEST_SUCCESS / REQUEST_FAILURE。
    let mut answered = false
    let mut success = false
    let mut waits = 0
    while waits < 16 {
      match recv_packet(conn, st.counters, st.recv) {
        Closed => return Failed(ForwardCancelError::Closed)
        BadPacket(why) => return Failed(ForwardCancelError::BadPacket(why))
        Packet(t, _pl) => {
          waits = waits + 1
          if t == @channel.SSH_MSG_REQUEST_SUCCESS {
            answered = true
            success = true
          } else if t == @channel.SSH_MSG_REQUEST_FAILURE {
            answered = true
            success = false
          } else {
            // 别的消息(比如服务端发来的通道打开)——继续等回包。
            ()
          }
        }
      }
      if answered {
        break
      }
    }
    if !answered {
      return Failed(ForwardCancelError::NoReply("no_request_reply"))
    }
    attempts.push(CancelAttempt::{ want_reply: true, replied: true, success, })
    i = i + 1
  }
  Done(ForwardCancelReport::{
    auth: auth_report,
    listen_host: host,
    requested_port: listen_port,
    granted_port: granted,
    attempts,
  })
}
