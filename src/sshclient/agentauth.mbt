///| Loop #80: 用 agent 持有的密钥做 publickey 认证。

///|

///| 这一条路径和 Loop #34 的 `live_auth` 走的是**同一个协议**,只是签名那一步

///| 不再发生在客户端里:
///

///|   Loop #34:  客户端自己拿着私钥 d → 自己签 → 发带签名的请求

///|   Loop #80:  客户端把「签这段字节」交给 agent → 拿回签名 → 发带签名的请求

///|

///| 协议侧只有一处不同:多了一个**探针**(RFC 4252 §7 的 boolean FALSE)。

///|

///| ## 为什么要探针

///|

///| 探针是「我打算用这把公钥,行不行」。服务端接受就回

///| `SSH_MSG_USERAUTH_PK_OK`(60),不接受就回 FAILURE。

///|

///| 它在本仓库里值两件事:
///

///|   * **别为一把服务端根本不认的钥匙去惊动 agent**。真 agent 可能要用户

///|     确认(摸指纹),为一个注定被拒的公钥弹一次确认框是纯粹的骚扰。

///|   * **区分「钥匙不对」和「签名不对」**。服务端把两种失败都报成同一句

///|     FAILURE,只有先探一次才知道该去查 authorized_keys 还是该去查签名。

///|

///| ## 签名是从 agent 那儿**原样**拿来的

///|

///| agent 回的 SIGN_RESPONSE 里那个 `string signature` 已经是 SSH 形态的

///| 签名 blob(算法名 + 签名),和 publickey 请求里那个字段要的东西一模一样。

///| 所以这里**不解析它、不重新编码它**,只是把它放进去。少一次编码就少一次

///| 出错的机会——签名 blob 的内部结构(ECDSA 是 `string alg` + `string(mpint r

///| || mpint s)`)一旦在这里重新拼一遍,拼错的后果是服务端一句笼统的

///| "invalid signature",没有任何线索。

///|

///| ## 挑哪一把钥匙

///|

///| agent 里可能有好几把身份。挨个探针,第一个拿到 PK_OK 的就用它;

///| 全都被拒就是 `ProbeRejected`——这基本等价于「authorized_keys 里没有

///| agent 的任何一把公钥」。

///|
/// agent 认证的结果
pub(all) enum AgentAuthResult {
  /// 服务端回了 SSH_MSG_USERAUTH_SUCCESS
  AgentAuthenticated(AgentAuthReport)
  /// 认证没能完成
  AgentFailed(AgentAuthError)
}

///|
/// agent 认证失败的原因
///

///|
/// 这套错误**不复用** `AuthError`:agent 路径多出「agent 不可用」「探针被拒」
/// 「agent 拒绝签名」这三类原因,而 `AuthError` 里那些「签名算错了」的分支在
/// 这条路径上根本不存在(签名不是我们算的)。硬塞进同一个枚举只会让每个调用点
/// 都得先判「这个错误在 agent 路径上可能出现吗」。
pub(all) enum AgentAuthError {
  /// 传输握手 / 服务协商阶段就没走通,认证还没开始
  Transport(SessionError)
  /// agent 通道本身出了问题:连不上、中途断了、或者回了一段看不懂的字节
  AgentUnreachable(String)
  /// agent 里一把身份都没有
  NoIdentity
  /// 探针被拒:服务端不认 agent 里的任何一把公钥
  ///
  /// 括号里是服务端给的理由(「公钥不对」和「签名不对」在服务端看来是同一句
  /// FAILURE,探针把它变成了一句有用的话)。
  ProbeRejected(String)
  /// agent 拒绝了签名请求
  AgentRefused(String)
  /// 请求发出去了,但既没有 SUCCESS 也没有 FAILURE
  NoAuthReply
  /// 服务端明确拒绝了带签名的请求。带上它给的原因,以及**实际签的那串字节**
  /// 和签名的十六进制。
  ///
  /// 探针已经过了(PK_OK),所以到这一步失败,嫌疑只在签名本身。
  AuthRejected(String, String, String)
  /// 认证包读回来了,但它不是一个合法的包
  BadPacket(String)
}

///|
/// agent 认证成功时带出来的东西
pub(all) struct AgentAuthReport {
  user : String
  auth_method : String
  /// 用的是 agent 里的哪把钥匙的算法名
  key_type : String
  /// agent 给这把钥匙的注释
  identity_comment : String
  /// agent 一共报了几把身份
  identity_count : Int32
  /// 探针请求的载荷(十六进制)
  probe_hex : String
  /// 签名的输入(十六进制)
  signed_blob_hex : String
  /// agent 回的签名(十六进制)
  sig_blob_hex : String
  /// 带签名的完整请求载荷(十六进制)
  request_hex : String
  session : SessionReport
}

///|
/// 握手 → 请求 ssh-userauth 服务 → 探针 → agent 签名 → publickey 认证
///
/// 直到 SSH_MSG_USERAUTH_SUCCESS。
///
/// `agent` 是已经连好的 agent 通道(见 `@agent.AgentChannel`)。它和 SSH 的
/// 连接是**两条独立的连接**:SSH 走加密层,agent 走长度前缀的明文帧。
pub fn[T : @transport.Transport] live_auth_with_agent(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  agent : @agent.AgentChannel,
  kh : @knownhosts.KnownHostsPolicy,
) -> AgentAuthResult {
  let (res, _st) = live_auth_with_agent_state(conn, x, user, agent, kh)
  res
}

///|
/// `live_auth_with_agent`,但把 `SessionState` 一并带出来。
///
/// 和 Loop #35 给 `live_auth` 加 `_state` 变体的理由一样:认证通过之后还要
/// 开通道跑命令的话,通道层的每个包都得用与握手同一套 `SendCtx` / `RecvCtx`。
fn[T : @transport.Transport] live_auth_with_agent_state(
  conn : T,
  x : @bigint.BigNat,
  user : String,
  agent : @agent.AgentChannel,
  kh : @knownhosts.KnownHostsPolicy,
) -> (AgentAuthResult, SessionState?) {
  let (res, state) = handshake_to_session(conn, x, kh)
  let handshake = match res {
    Established(rep) => rep
    Failed(e) =>
      return (
        AgentFailed(AgentAuthError::Transport(SessionError::HandshakeFailed(e))),
        None,
      )
  }
  let st = match state {
    None =>
      return (
        AgentFailed(AgentAuthError::Transport(SessionError::NoServiceAccept)),
        None,
      )
    Some(v) => v
  }
  let (accepted_opt, err) = request_userauth_service(conn, st)
  match err {
    Some(e) => return (AgentFailed(AgentAuthError::Transport(e)), None)
    None => ()
  }
  let accepted = match accepted_opt {
    None =>
      return (
        AgentFailed(AgentAuthError::Transport(SessionError::NoServiceAccept)),
        None,
      )
    Some(a) => a
  }
  // ---- 1. 问 agent 要它持有的身份 ----
  let ids = match @agent.agent_list_identities(agent) {
    None =>
      return (
        AgentFailed(
          AgentAuthError::AgentUnreachable(
            "the agent did not answer the identities request",
          ),
        ),
        None,
      )
    Some(v) => v
  }
  if ids.length() == 0 {
    return (AgentFailed(AgentAuthError::NoIdentity), None)
  }
  // ---- 2. 挨个探针,挑第一个被接受的 ----
  let mut picked : @agent.AgentIdentity? = None
  let mut picked_type = ""
  let mut probe_hex = ""
  let mut last_reason = "the server rejected every public key the agent offered"
  let mut i = 0
  while i < ids.length() {
    let id = ids[i]
    i = i + 1
    let kt = match @agent.agent_key_type(id.key_blob) {
      // 算法名都读不出来的公钥 blob 没法构造请求,跳过它。
      None => continue
      Some(v) => v
    }
    let probe = @userauth.userauth_publickey_probe_request(
      user,
      @userauth.AUTH_SERVICE_CONNECTION,
      kt,
      id.key_blob,
    )
    let verdict = match agent_probe_one(conn, st, probe) {
      Closed => return (AgentFailed(AgentAuthError::NoAuthReply), None)
      BadPacket(why) =>
        return (AgentFailed(AgentAuthError::BadPacket(why)), None)
      NoAnswer => return (AgentFailed(AgentAuthError::NoAuthReply), None)
      Answer(vtype, vbody) => (vtype, vbody)
    }
    let (vtype, vbody) = verdict
    if vtype == @sshwire.SSH_MSG_USERAUTH_PK_OK {
      picked = Some(id)
      picked_type = kt
      probe_hex = @ecdsa.bytes_to_hex(probe)
      break
    }
    if vtype == @sshwire.SSH_MSG_USERAUTH_SUCCESS {
      // 探针不带签名,服务端不可能在这儿就认证成功。回 SUCCESS 意味着
      // 对端不是按 RFC 4252 说话,继续往下走只会得到一句没法解释的失败。
      return (
        AgentFailed(
          AgentAuthError::AgentUnreachable(
            "the server answered a publickey probe with USERAUTH_SUCCESS",
          ),
        ),
        None,
      )
    }
    last_reason = userauth_failure_reason(vbody)
  }
  let identity = match picked {
    None =>
      return (AgentFailed(AgentAuthError::ProbeRejected(last_reason)), None)
    Some(v) => v
  }
  // ---- 3. 请 agent 签 ----
  let to_sign = @userauth.userauth_signed_blob(
    st.session_id,
    user,
    @userauth.AUTH_SERVICE_CONNECTION,
    picked_type,
    identity.key_blob,
  )
  let sig = match @agent.agent_sign(agent, identity.key_blob, to_sign) {
    None =>
      return (
        AgentFailed(
          AgentAuthError::AgentRefused(
            "the agent refused to sign the authentication request",
          ),
        ),
        None,
      )
    Some(s) => s
  }
  // ---- 4. 发带签名的请求 ----
  let payload = @userauth.userauth_publickey_request(
    user,
    @userauth.AUTH_SERVICE_CONNECTION,
    picked_type,
    identity.key_blob,
    sig,
  )
  if !send_packet(
      conn,
      st.counters,
      st.send,
      @sshwire.SSH_MSG_USERAUTH_REQUEST,
      payload,
    ) {
    return (AgentFailed(AgentAuthError::NoAuthReply), None)
  }
  let mut tries = 0
  let mut verdict : (Byte, FixedArray[Byte])? = None
  while tries < 32 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return (AgentFailed(AgentAuthError::NoAuthReply), None)
      BadPacket(why) =>
        return (AgentFailed(AgentAuthError::BadPacket(why)), None)
      Packet(t, pl) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_USERAUTH_SUCCESS ||
          t == @sshwire.SSH_MSG_USERAUTH_FAILURE {
          verdict = Some((t, pl))
          break
        }
      }
    }
  }
  let (msg_type, body) = match verdict {
    None => return (AgentFailed(AgentAuthError::NoAuthReply), None)
    Some(v) => v
  }
  if msg_type == @sshwire.SSH_MSG_USERAUTH_FAILURE {
    return (
      AgentFailed(
        AgentAuthError::AuthRejected(
          userauth_failure_reason(body),
          @ecdsa.bytes_to_hex(to_sign),
          @ecdsa.bytes_to_hex(sig),
        ),
      ),
      None,
    )
  }
  (
    AgentAuthenticated({
      user,
      auth_method: @userauth.AUTH_METHOD_PUBLICKEY,
      key_type: picked_type,
      identity_comment: identity.comment,
      identity_count: ids.length(),
      probe_hex,
      signed_blob_hex: @ecdsa.bytes_to_hex(to_sign),
      sig_blob_hex: @ecdsa.bytes_to_hex(sig),
      request_hex: @ecdsa.bytes_to_hex(payload),
      session: {
        handshake,
        service_name: USERAUTH_SERVICE,
        accepted_service: accepted,
        we_need: st.we_need,
        key_tag: st.key_tag,
        session_id_head: st.session_id_head,
        sent_bytes: st.counters.sent,
        recv_bytes: st.counters.recv,
      },
    }),
    Some(st),
  )
}

///|
/// 探针的回音。四种结果,不是一个可空值。
///
/// 探针失败有四种完全不同的原因,而它们对调用方的意义完全不同:对端关了、
/// 回的不是合法的包、回音迟迟不来、或者回音到了。这些在「等回音」这一步
/// 是分不开的,合成一个 `None` 就只能报一句「没有回答」——而没有回答和
/// 「说错了话」是两回事。
priv enum ProbeOutcome {
  /// 回音到了:`(消息类型, 载荷)`
  Answer(Byte, FixedArray[Byte])
  /// 对端关了连接
  Closed
  /// 读到了一段,但它不是一个合法的包
  BadPacket(String)
  /// 回音没有来
  NoAnswer
}

///|
/// 发一个探针请求,等回音。
///
/// 只认三种回音:`SSH_MSG_USERAUTH_PK_OK`、`SSH_MSG_USERAUTH_FAILURE` 和
/// `SSH_MSG_USERAUTH_SUCCESS`。别的(比如服务端发的
/// `SSH_MSG_USERAUTH_BANNER`)跳过——RFC 4252 §5 说 banner 可以在任何时候
/// 插进来。
fn[T : @transport.Transport] agent_probe_one(
  conn : T,
  st : SessionState,
  probe : FixedArray[Byte],
) -> ProbeOutcome {
  if !send_packet(
      conn,
      st.counters,
      st.send,
      @sshwire.SSH_MSG_USERAUTH_REQUEST,
      probe,
    ) {
    return Closed
  }
  let mut tries = 0
  while tries < 32 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return Closed
      BadPacket(why) => return BadPacket(why)
      Packet(t, pl) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_USERAUTH_PK_OK ||
          t == @sshwire.SSH_MSG_USERAUTH_FAILURE ||
          t == @sshwire.SSH_MSG_USERAUTH_SUCCESS {
          return Answer(t, pl)
        }
      }
    }
  }
  NoAnswer
}
