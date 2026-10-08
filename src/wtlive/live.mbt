///| Loop #32: the SSH transport handshake over an async browser transport.

///|

///|   Loop #31's `live_handshake` is the same protocol against a blocking

///|   Winsock socket. This is the same protocol against `@wt.WtConn`, which

///|   is WebTransport or WebSocket depending on the URL. What differs is that

///|   every read and write awaits; what does not differ is any of the crypto

///|   or wire logic, which lives in `framing.mbt`, `@sshclient.live_proposal` and

///|   `@kexdh.exchange_hash` and is shared verbatim.

///|

///|   Keeping the duplication to the I/O shape is deliberate: a second copy of

///|   the packet framing or the exchange-hash layout would be free to drift

///|   away from the native one, and a client that only verifies its host key

///|   on one platform is not verifying it at all.

///|

///|   js target only. `src/wt` uses `extern "js"`, which the wasm backends

///|   reject, and MoonBit's async support does not include wasm anyway.

///|

///| Why a live handshake failed. Mirrors `LiveError` so a driver can report

///|
/// either without knowing which transport it ran on.
pub(all) enum WtLiveError {
  ConnectFailed(String)
  NoServerIdent
  KexinitSendFailed
  NoPeerKexinit
  KexinitParseFailed
  NoAgreement(String)
  EcdhInitSendFailed
  NoEcdhReply
  EcdhReplyMalformed
  HostkeyInvalid
  /// The exchange hash did not verify. Either our hash inputs are wrong or
  /// the server is not who it claims to be; the caller must not continue.
  /// The computed hash is carried out so a second implementation can diff it
  /// instead of the failure being merely negative.
  SignatureInvalid(FixedArray[Byte])
  NewkeysSendFailed
  NoNewkeys
  /// 一整段字节读回来了,但它不是一个合法的包。
  ///
  /// 与原生路径的 `LiveError::BadPacket` 同名同义:两条路径对同一个故障
  /// 必须给出同一个名字,否则「浏览器复现不了」这种结论会退化成猜测。
  BadPacket(String)
}

///|

///|
/// Outcome of a browser-side handshake.
pub(all) enum WtLiveResult {
  Established(WtLiveReport)
  Failed(WtLiveError)
}

///|

///|
/// Everything a caller needs to know about a completed handshake.
pub(all) struct WtLiveReport {
  server_ident : String
  client_ident : String
  kex_alg : String
  hostkey_alg : String
  cipher_ctos : String
  cipher_stoc : String
  mac_ctos : String
  mac_stoc : String
  hostkey_blob : FixedArray[Byte]
  hostkey_type : String
  hostkey_bits : Int
  exchange_hash : FixedArray[Byte]
  shared_secret_head : String
  sent_bytes : Int
  recv_bytes : Int
}

///|

///| Byte counters, so a report can show that bytes actually moved in each

///|
/// direction rather than just that the code path was reached.
priv struct WtWireCounters {
  mut sent : Int
  mut recv : Int
}

///|
/// 穿过 NEWKEYS 之后的加密会话状态
///
/// 与 `src/sshclient` 的同名结构刻意保持字段一致:两条传输路径各自持有自己的
/// 上下文,但「需要什么、怎么算」只有一份定义。
priv struct WtSessionState {
  send : @bpacket.SendCtx
  recv : @bpacket.RecvCtx
  counters : WtWireCounters
  we_need : Int
  /// 首次 KEX 的 H。publickey 认证要拿它当签名输入(RFC 4252 §7),
  /// 必须是**完整**字节——`session_id_head` 只是给人看的十六进制摘要。
  session_id : FixedArray[Byte]
  key_tag : String
  session_id_head : String
}

///|
/// 出参盒子
///
/// 握手函数一共有二十几处 `return Failed(...)`,把返回值改成
/// `(WtLiveResult, WtSessionState?)` 就要把每一处都改一遍——而这些早期失败
/// 路径根本不需要加密状态。用一个盒子把「成功后才有」的东西带出去,比为了
/// 统一签名去动二十几行控制流要安全。
priv struct WtSessionBox {
  mut state : WtSessionState?
}

///|
/// 浏览器侧的加密会话结果
pub(all) enum WtSessionResult {
  ServiceAccepted(WtSessionReport)
  Failed(WtSessionError)
}

///|
pub(all) enum WtSessionError {
  HandshakeFailed(WtLiveError)
  NoServiceAccept
  UnexpectedService(String)
  /// 一整段字节读回来了,但它不是一个合法的包。与「等不到 SERVICE_ACCEPT」
  /// 分开,理由同 `src/sshclient` 的 `SessionError::BadPacket`。
  BadPacket(String)
}

///|
pub(all) struct WtSessionReport {
  handshake : WtLiveReport
  service_name : String
  accepted_service : String
  we_need : Int
  key_tag : String
  session_id_head : String
  sent_bytes : Int
  recv_bytes : Int
}

///|
/// 我们请求的服务名(RFC 4253 §7.1)
pub const WT_USERAUTH_SERVICE : String = "ssh-userauth"

///|
/// Write one packet. Framing, encryption and MAC all belong to the
/// `@bpacket.SendCtx`; this only moves bytes and keeps the counter honest.
///
/// The context is threaded in rather than kept here so the sequence number
/// lives in exactly one place across the handshake -- once NEWKEYS has passed,
/// seqnr feeds the MAC, and a second bookkeeping path would drift silently.
async fn wt_send_plain_packet(
  conn : @wt.WtConn,
  counters : WtWireCounters,
  s : @bpacket.SendCtx,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> Bool {
  // Zero padding keeps the transcript reproducible; see the note in
  // `src/sshclient/live.mbt` on why this is a deliberate trade.
  let pad_src : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  match s.emit(msg_type, payload, pad_src) {
    Ok(pkt) => {
      conn.send(pkt.wire) catch {
        _ => return false
      }
      counters.sent = counters.sent + pkt.wire.length()
      true
    }
    _ => false
  }
}

///|
/// Read exactly one packet.
///
/// The read must be exact. Once a packet is consumed the next read is for the
/// following message, so a reader that grabbed a chunk would sit waiting for
/// bytes nobody has asked us to receive yet.
///
/// The length comes from `RecvCtx::wire_len_from_header`: past NEWKEYS the
/// length field is itself ciphertext, so only the context can recover it.
/// Chunking by block size would have been simpler and wrong -- it works
/// precisely until the first encrypted packet arrives.
///
/// 复用 `@sshclient.RecvOutcome` 而不是自己再定一个:两条传输路径对
/// 「MAC 失败」和「对端关闭」必须给出同一个答案,否则同一个 bug 在两条
/// 路径上报出两个名字,排查时只会怀疑错方向。
async fn wt_recv_plain_packet(
  conn : @wt.WtConn,
  counters : WtWireCounters,
  r : @bpacket.RecvCtx,
) -> @sshclient.RecvOutcome {
  let hdr = conn.read_exact(4) catch { _ => return Closed }
  let rest = match r.wire_len_from_header(hdr) {
    None => return BadPacket("undecryptable_header")
    Some(v) => v
  }
  if rest < 0 || rest > 1048576 {
    return BadPacket("length_out_of_range:" + rest.to_string())
  }
  let body = if rest == 0 {
    FixedArray::make(0, b'\x00')
  } else {
    let b = conn.read_exact(rest) catch { _ => return Closed }
    b
  }
  counters.recv = counters.recv + 4 + rest
  match r.recv(@sshclient.cat2(hdr, body)).event {
    @bpacket.Packet(_, t, payload) => Packet(t, payload)
    @bpacket.NeedMore => Closed
    @bpacket.Failed(e) => BadPacket(@sshclient.packet_error_label(e))
  }
}

///|

///| Read one CRLF-terminated identification line.
///

///| The transport delivers bytes, not lines, so this accumulates until it sees

///| CRLF. Reading one byte at a time is fine here: the identification phase is

///|
/// a few dozen bytes and it happens before any bulk transfer.
async fn wt_read_ident_line(
  conn : @wt.WtConn,
  counters : WtWireCounters,
  max_bytes : Int,
) -> String? {
  let mut acc : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut total = 0
  while total < max_bytes {
    let one = conn.read_exact(1) catch { _ => return None }
    counters.recv = counters.recv + 1
    total = total + 1
    acc = @sshclient.cat2(acc, one)
    if acc.length() >= 2 &&
      acc[acc.length() - 2] == b'\r' &&
      acc[acc.length() - 1] == b'\n' {
      let n = acc.length() - 2
      let line : FixedArray[Byte] = FixedArray::make(n, b'\x00')
      let mut i = 0
      while i < n {
        line[i] = acc[i]
        i = i + 1
      }
      return Some(@sshclient.bytes_to_string(line))
    }
  }
  None
}

///|

///| The full transport handshake over an open browser transport.
///

///| `conn` is already open: the caller owns connect failure reporting, so the

///|
/// transport's own error type does not leak into the SSH layer.

///|
/// The full transport handshake over an open browser transport.
///

///| `conn` is already open: the caller owns connect failure reporting, so the
///

///|
/// transport's own error type does not leak into the SSH layer.
///

///| `box` is filled in only when the handshake gets all the way through
///

///| NEWKEYS; it stays `None` on every failure path, where there is no
///

///|
/// encrypted channel to hand over.
async fn wt_handshake_into(
  conn : @wt.WtConn,
  x : @bigint.BigNat,
  box : WtSessionBox,
) -> WtLiveResult {
  let counters = { sent: 0, recv: 0, }
  let s = @bpacket.SendCtx::new()
  let r = @bpacket.RecvCtx::new()
  let client_ident = "SSH-2.0-MoonBit_0.1"
  // ---- 1. identification exchange ----
  conn.send(
    @sshclient.cat2(@sshclient.ascii(client_ident), @sshclient.ascii("\r\n")),
  ) catch {
    _ => return Failed(ConnectFailed("ident send"))
  }
  counters.sent = counters.sent + client_ident.length() + 2
  let mut server_ident = ""
  let mut lines = 0
  while lines < 64 {
    match wt_read_ident_line(conn, counters, 255) {
      None => return Failed(NoServerIdent)
      Some(line) => {
        lines = lines + 1
        if line.has_prefix("SSH-") {
          server_ident = line
          break
        }
      }
    }
  }
  if !server_ident.has_prefix("SSH-2.0-") &&
    !server_ident.has_prefix("SSH-1.99-") {
    return Failed(NoServerIdent)
  }
  // ---- 2. KEXINIT ----
  let my = @sshclient.live_proposal()
  let ic_payload = @kexflow.kexinit_payload(@sshclient.fixed_cookie(), my)
  if !wt_send_plain_packet(
      conn,
      counters,
      s,
      @sshwire.SSH_MSG_KEXINIT,
      ic_payload,
    ) {
    return Failed(KexinitSendFailed)
  }
  let mut peer_ic_payload : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut got_kexinit = false
  let mut tries = 0
  while !got_kexinit && tries < 32 {
    match wt_recv_plain_packet(conn, counters, r) {
      Closed => return Failed(NoPeerKexinit)
      BadPacket(why) => return Failed(BadPacket(why))
      Packet(t, payload) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_KEXINIT {
          peer_ic_payload = payload
          got_kexinit = true
        }
      }
    }
  }
  if !got_kexinit {
    return Failed(NoPeerKexinit)
  }
  let peer_prop = match @kexflow.parse_kexinit(peer_ic_payload) {
    None => return Failed(KexinitParseFailed)
    Some(p) => p
  }
  let neg = match @kexflow.negotiate(my, peer_prop) {
    Err(e) => return Failed(NoAgreement(wt_neg_error_label(e)))
    Ok(n) => n
  }
  if neg.kex_alg != "diffie-hellman-group14-sha256" {
    return Failed(NoAgreement("kex_alg"))
  }
  // ---- 3. KEX_ECDH_INIT ----
  let p = @bigint.BigNat::from_bytes_be(@kexdh.group14_prime())
  let g = @bigint.BigNat::from_uint64(2UL)
  let ctx = @kexdh.dh_ctx(p)
  let e = @kexdh.dh_pub_ctx(ctx, g, x)
  let e_wire = @bigint.BigNat::mpint_encode(e)
  // mpint_encode already emits the u32 length prefix, so the SSH string IS the
  // mpint encoding; wrapping the *body* again would yield a value starting
  // with four zero bytes, which a real server rejects as "invalid public DH
  // value: >= p-1". The binary packet framing around it is still required,
  // though -- e_wire is the payload, not the packet.
  if !wt_send_plain_packet(
      conn,
      counters,
      s,
      @sshwire.SSH_MSG_KEX_ECDH_INIT,
      e_wire,
    ) {
    return Failed(EcdhInitSendFailed)
  }
  // ---- 4. KEX_ECDH_REPLY ----
  let mut reply : FixedArray[Byte]? = None
  let mut tries2 = 0
  while tries2 < 32 {
    match wt_recv_plain_packet(conn, counters, r) {
      Closed => return Failed(NoEcdhReply)
      BadPacket(why) => return Failed(BadPacket(why))
      Packet(t, payload) => {
        tries2 = tries2 + 1
        if t == @sshwire.SSH_MSG_KEX_ECDH_REPLY {
          reply = Some(payload)
          break
        }
        if t == @sshclient.KX_MSG_KEX_FAILURE {
          return Failed(EcdhReplyMalformed)
        }
      }
    }
  }
  let reply_payload = match reply {
    None => return Failed(NoEcdhReply)
    Some(r) => r
  }
  let (ks, f_wire, sig_blob) = match
    @sshclient.parse_ecdh_reply(reply_payload) {
    None => return Failed(EcdhReplyMalformed)
    Some(t) => t
  }
  // ---- 5. shared secret ----
  let f = @bigint.BigNat::from_bytes_be(f_wire)
  if @bigint.BigNat::cmp(f, @bigint.BigNat::from_uint64(1UL)) <= 0 ||
    @bigint.BigNat::cmp(f, p) >= 0 {
    return Failed(EcdhReplyMalformed)
  }
  let k = @kexdh.dh_shared_ctx(ctx, f, x)
  let k_wire = @bigint.BigNat::mpint_encode(k)
  // ---- 6. exchange hash ----
  // H = SHA256( string(V_C) || string(V_S) || string(I_C) || string(I_S)
  //           || string(K_S)  || string(mpint e) || string(mpint f)
  //           || string(mpint K) )
  //
  // All eight fields carry a u32 length prefix, K included. See the long note
  // on the native side in live.mbt; this is the same layout, proven twice
  // against a live server.
  let h = @kexdh.exchange_hash(
    @sshwire.write_ssh_string(@sshclient.ascii(client_ident)),
    @sshwire.write_ssh_string(@sshclient.ascii(server_ident)),
    @sshwire.write_ssh_string(
      @sshclient.with_type(@sshwire.SSH_MSG_KEXINIT, ic_payload),
    ),
    @sshwire.write_ssh_string(
      @sshclient.with_type(@sshwire.SSH_MSG_KEXINIT, peer_ic_payload),
    ),
    @sshwire.write_ssh_string(ks),
    e_wire,
    @sshwire.write_ssh_string(f_wire),
    k_wire,
  )
  // ---- 7. host key verification ----
  let key = match @hostkey.HostKey::from_blob(ks) {
    @hostkey.Parsed(k) => k
    _ => return Failed(HostkeyInvalid)
  }
  let (ktype, kbits) = match key {
    @hostkey.EcdsaKey(bits, _) =>
      (
        if bits == 256 {
          "ecdsa-sha2-nistp256"
        } else {
          "ecdsa-sha2-nistp384"
        },
        bits,
      )
    _ => return Failed(HostkeyInvalid)
  }
  if ktype != neg.hostkey_alg {
    return Failed(HostkeyInvalid)
  }
  match @hostkey.HostKey::verify(key, h, sig_blob) {
    @hostkey.Accepted => ()
    _ => return Failed(SignatureInvalid(h))
  }
  // ---- 8. NEWKEYS ----
  if !wt_send_plain_packet(
      conn,
      counters,
      s,
      @sshwire.SSH_MSG_NEWKEYS,
      FixedArray::make(0, b'\x00'),
    ) {
    return Failed(NewkeysSendFailed)
  }
  let mut got_newkeys = false
  let mut tries3 = 0
  while !got_newkeys && tries3 < 32 {
    match wt_recv_plain_packet(conn, counters, r) {
      Closed => return Failed(NoNewkeys)
      BadPacket(why) => return Failed(BadPacket(why))
      Packet(t, _) => {
        tries3 = tries3 + 1
        if t == @sshwire.SSH_MSG_NEWKEYS {
          got_newkeys = true
        }
      }
    }
  }
  if !got_newkeys {
    return Failed(NoNewkeys)
  }
  // ---- 9. 派生会话密钥并切换到加密模式 ----
  // 与原生路径走同一张长度表(`we_need_for` 从 src/sshclient 导入)。
  // 两条传输各写一份密钥长度表,迟早会在新增 cipher 时只改一处。
  let we_need = @sshclient.we_need_for(neg.cipher_ctos, neg.mac_ctos)
  let keys = @kexc25519.derive_keys(h, k_wire, we_need)
  // 六个密钥都按 we_need 派生,但 cipher 只取 key_len / iv_len 字节前缀。
  let ctos = @bpacket.AesCtrMacCtx::new(
    head_bytes(keys.enc_key_ctos(), 16),
    head_bytes(keys.iv_ctos(), 16),
    keys.mac_key_ctos(),
  )
  let stoc = @bpacket.AesCtrMacCtx::new(
    head_bytes(keys.enc_key_stoc(), 16),
    head_bytes(keys.iv_stoc(), 16),
    keys.mac_key_stoc(),
  )
  s.set_mode(@bpacket.MacEncrypt(ctos))
  r.set_mode(@bpacket.MacEncrypt(stoc))
  // 与原生路径同一步:kex.c:567 在 NEWKEYS 之后清 KEX_INITIAL
  s.end_initial_kex()
  r.end_initial_kex()
  box.state = Some({
    send: s,
    recv: r,
    counters,
    we_need,
    session_id: keys.session_id(),
    key_tag: @sshclient.key_tag_of(keys.enc_key_ctos(), keys.mac_key_ctos()),
    session_id_head: @sshclient.hex_bytes_head(keys.session_id(), 16),
  })
  Established({
    server_ident,
    client_ident,
    kex_alg: neg.kex_alg,
    hostkey_alg: neg.hostkey_alg,
    cipher_ctos: neg.cipher_ctos,
    cipher_stoc: neg.cipher_stoc,
    mac_ctos: neg.mac_ctos,
    mac_stoc: neg.mac_stoc,
    hostkey_blob: ks,
    hostkey_type: ktype,
    hostkey_bits: kbits,
    exchange_hash: h,
    shared_secret_head: shared_secret_head_of(k),
    sent_bytes: counters.sent,
    recv_bytes: counters.recv,
  })
}

///|
/// 前 n 个字节 —— 直接用 `@sshclient.head_bytes`。
///
/// 这里原本有一份自己的实现,和 `src/sshclient` 的逐字符相同。两份副本在
/// 「前缀取多少字节」上分叉过一次的话,只有一条传输路径会拿到正确的密钥,
/// 而且症状是对方解不开——极难定位。所以共享函数,不留副本。
fn head_bytes(b : FixedArray[Byte], n : Int) -> FixedArray[Byte] {
  @sshclient.head_bytes(b, n)
}

///|
/// 字节前缀的十六进制 —— 直接用 `@sshclient.hex_bytes_head`。
///
/// 理由同上。注意它只用于非秘密字节(session_id);会话密钥走
/// `@sshclient.key_tag_of`。
fn hex_bytes_head(b : FixedArray[Byte], n : Int) -> String {
  @sshclient.hex_bytes_head(b, n)
}

///|
/// 握手到 NEWKEYS 为止(Loop #32 的既有行为,保持不变)
pub async fn wt_live_handshake(
  conn : @wt.WtConn,
  x : @bigint.BigNat,
) -> WtLiveResult {
  let box = { state: None, }
  wt_handshake_into(conn, x, box)
}

///|
/// 握手,再在**加密**信道上做一次往返(Loop #33)
///
/// 浏览器路径与原生路径到这里已经是同一件事了:组帧、加密、MAC、密钥派生
/// 全部来自共享的 `src/bpacket` / `src/kexc25519`,两条路径只在「怎么把字节
/// 搬上传输层」上不同。这正是 Loop #32 抽出共享逻辑时想要的结果,也是为什么
/// 这里的字节数应该与原生驱动逐字节相同——不一样就说明有一边漂移了。
pub async fn wt_live_session(
  conn : @wt.WtConn,
  x : @bigint.BigNat,
) -> WtSessionResult {
  let box = { state: None, }
  let res = wt_handshake_into(conn, x, box)
  let handshake = match res {
    Established(rep) => rep
    Failed(e) => return Failed(WtSessionError::HandshakeFailed(e))
  }
  let st = match box.state {
    None => return Failed(WtSessionError::NoServiceAccept)
    Some(v) => v
  }
  let (accepted_opt, err) = wt_request_userauth_service(conn, st)
  let accepted = match accepted_opt {
    None => return Failed(WtSessionError::NoServiceAccept)
    Some(v) => v
  }
  match err {
    Some(WtSessionError::UnexpectedService(s)) =>
      return Failed(WtSessionError::UnexpectedService(s))
    _ => ()
  }
  ServiceAccepted({
    handshake,
    service_name: WT_USERAUTH_SERVICE,
    accepted_service: accepted,
    we_need: st.we_need,
    key_tag: st.key_tag,
    session_id_head: st.session_id_head,
    sent_bytes: st.counters.sent,
    recv_bytes: st.counters.recv,
  })
}

///|
/// 浏览器侧的认证结果
pub(all) enum WtAuthResult {
  Authenticated(WtAuthReport)
  Failed(WtAuthError)
}

///|
/// 失败原因与 `src/sshclient` 的 `AuthError` 一一对应,只是传输层类型不同
pub(all) enum WtAuthError {
  HandshakeFailed(WtLiveError)
  NoServiceAccept
  UnexpectedService(String)
  SignFailed
  NoAuthReply
  /// 原因 + 实际签名的字节 + 签名 blob 的十六进制。
  ///
  /// 服务端把「公钥不在 authorized_keys 里」和「签名算错了」都报成同一句
  /// FAILURE,本地不留证据就只能靠猜。Loop #34 定位那个
  /// `encode_sig_blob` 少包一层 string 的缺陷,靠的就是这三样。
  AuthRejected(String, String, String)
  /// 认证包读回来了,但它不是一个合法的包。
  BadPacket(String)
}

///|
pub(all) struct WtAuthReport {
  user : String
  method : String
  key_type : String
  signed_blob_hex : String
  sig_blob_hex : String
  request_hex : String
  session : WtSessionReport
}

///|
/// 请求 ssh-userauth 服务并等到 SERVICE_ACCEPT
///
/// 抽出来是因为 `wt_live_session` 和 `wt_live_auth` 要走同样的两步;
/// 留在调用点各写一份的话,任何一处改动都只覆盖一半路径。
async fn wt_request_userauth_service(
  conn : @wt.WtConn,
  st : WtSessionState,
) -> (String?, WtSessionError?) {
  let payload = @sshwire.write_ssh_string(@sshclient.ascii(WT_USERAUTH_SERVICE))
  if !wt_send_plain_packet(
      conn,
      st.counters,
      st.send,
      @sshwire.SSH_MSG_SERVICE_REQUEST,
      payload,
    ) {
    return (None, Some(WtSessionError::NoServiceAccept))
  }
  let mut tries = 0
  let mut answer : FixedArray[Byte]? = None
  while tries < 32 {
    match wt_recv_plain_packet(conn, st.counters, st.recv) {
      Closed => return (None, Some(WtSessionError::NoServiceAccept))
      BadPacket(why) => return (None, Some(WtSessionError::BadPacket(why)))
      Packet(t, pl) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_SERVICE_ACCEPT {
          answer = Some(pl)
          break
        }
      }
    }
  }
  let accepted_body = match answer {
    None => return (None, Some(WtSessionError::NoServiceAccept))
    Some(v) => v
  }
  let accepted = match @sshclient.read_field(accepted_body, 0) {
    None => return (None, Some(WtSessionError::UnexpectedService("malformed")))
    Some((name, _)) => @sshclient.bytes_to_string(name)
  }
  if accepted != WT_USERAUTH_SERVICE {
    return (None, Some(WtSessionError::UnexpectedService(accepted)))
  }
  (Some(accepted), None)
}

///|
/// 握手 → 请求 ssh-userauth → publickey 认证,直到 SSH_MSG_USERAUTH_SUCCESS
///
/// 组包本身来自 `src/sshclient/userauth.mbt`(浏览器与原生共用),这里只负责
/// 把字节搬上 `src/wt` 的传输层。两条路径发出的签名输入必须逐字节相同——
/// 服务端只有一把 session_id,任何一边漂移都表现为一句 FAILURE。
pub async fn wt_live_auth(
  conn : @wt.WtConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
) -> WtAuthResult {
  let box = { state: None, }
  let res = wt_handshake_into(conn, x, box)
  let handshake = match res {
    Established(rep) => rep
    Failed(e) => return Failed(WtAuthError::HandshakeFailed(e))
  }
  let st = match box.state {
    None => return Failed(WtAuthError::NoServiceAccept)
    Some(v) => v
  }
  let (accepted_opt, err) = wt_request_userauth_service(conn, st)
  let accepted = match accepted_opt {
    None => return Failed(WtAuthError::NoServiceAccept)
    Some(v) => v
  }
  match err {
    Some(WtSessionError::UnexpectedService(s)) =>
      return Failed(WtAuthError::UnexpectedService(s))
    _ => ()
  }
  // 字节计数在认证往返之后才最终确定,所以报告在这里才构造——早建一次再改字段
  // 既没地方改(WtSessionReport 的字段是 pub(all),不可变),也没必要。
  let curve = @ecdsa.Curve::p256()
  let (pk_blob, sig_blob, payload) = match
    @userauth.userauth_publickey_signed_request(
      curve,
      d,
      st.session_id,
      user,
      @userauth.AUTH_SERVICE_CONNECTION,
    ) {
    None => return Failed(WtAuthError::SignFailed)
    Some(v) => v
  }
  let to_sign = @userauth.userauth_signed_blob(
    st.session_id,
    user,
    @userauth.AUTH_SERVICE_CONNECTION,
    curve.ssh_key_type(),
    pk_blob,
  )
  if !wt_send_plain_packet(
      conn,
      st.counters,
      st.send,
      @sshwire.SSH_MSG_USERAUTH_REQUEST,
      payload,
    ) {
    return Failed(WtAuthError::NoAuthReply)
  }
  let mut tries = 0
  let mut verdict : (Byte, FixedArray[Byte])? = None
  while tries < 32 {
    match wt_recv_plain_packet(conn, st.counters, st.recv) {
      Closed => return Failed(WtAuthError::NoAuthReply)
      BadPacket(why) => return Failed(WtAuthError::BadPacket(why))
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
    None => return Failed(WtAuthError::NoAuthReply)
    Some(v) => v
  }
  if msg_type == @sshwire.SSH_MSG_USERAUTH_FAILURE {
    return Failed(
      WtAuthError::AuthRejected(
        @sshclient.userauth_failure_reason(body),
        @ecdsa.bytes_to_hex(to_sign),
        @ecdsa.bytes_to_hex(sig_blob),
      ),
    )
  }
  Authenticated({
    user,
    method: @userauth.AUTH_METHOD_PUBLICKEY,
    key_type: curve.ssh_key_type(),
    signed_blob_hex: @ecdsa.bytes_to_hex(to_sign),
    sig_blob_hex: @ecdsa.bytes_to_hex(sig_blob),
    request_hex: @ecdsa.bytes_to_hex(payload),
    session: {
      handshake,
      service_name: WT_USERAUTH_SERVICE,
      accepted_service: accepted,
      we_need: st.we_need,
      key_tag: st.key_tag,
      session_id_head: st.session_id_head,
      sent_bytes: st.counters.sent,
      recv_bytes: st.counters.recv,
    },
  })
}

///|

///| 浏览器侧的一次远端命令执行
pub(all) enum WtExecOutcome {
  Done(WtExecResult)
  AuthFailed(WtAuthError)
  ChannelFailed(WtExecError)
}

///|
/// 浏览器侧 `live_exec` 的失败原因。刻意与「远端命令返回非零」分开:后者是
/// **正常结果**,走 `WtExecResult::exit_status`。
pub(all) enum WtExecError {
  NoSessionState
  Malformed(String)
  OpenFailed(Int, String)
  ExecRejected
  SendFailed
  BadPacket(String)
  Closed
  TooManyPackets
}

///|
pub(all) struct WtExecResult {
  stdout : FixedArray[Byte]
  stderr : FixedArray[Byte]
  exit_status : Int
  remote_id : Int
  adjusts_sent : Int
  sent_bytes : Int
  recv_bytes : Int
}

///|
/// 在浏览器里跑一条远端命令,并读回 stdout / stderr / exit-status。
///
/// 和 `src/sshclient` 的 `live_exec` 一样,协议本身全部来自 `src/channel` 的
/// `chan_step`——两条路径共用同一个状态机,只换了搬字节的那一层。所以「原生和
/// 浏览器结果一致」不是靠两边都写对了来保证的,而是**协议只有一份实现**;
/// 验证脚本仍然要比一遍字节数与摘要,因为那还能同时抓住搬运层的漂移。
pub async fn wt_live_exec(
  conn : @wt.WtConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  command : String,
) -> WtExecOutcome {
  let box = { state: None, }
  let res = wt_handshake_into(conn, x, box)
  match res {
    Established(_) => ()
    Failed(e) => return WtExecOutcome::AuthFailed(WtAuthError::HandshakeFailed(e))
  }
  // box.state 只在握手收尾时写一次(`wt_handshake_into`),之后的收发都在这
  // 同一个结构体上更新计数器和 seqnr,所以一路带着它走即可。
  let st = match box.state {
    None => return WtExecOutcome::ChannelFailed(WtExecError::NoSessionState)
    Some(v) => v
  }
  let (accepted_opt, svc_err) = wt_request_userauth_service(conn, st)
  match svc_err {
    Some(WtSessionError::UnexpectedService(s)) =>
      return WtExecOutcome::AuthFailed(WtAuthError::UnexpectedService(s))
    _ => ()
  }
  match accepted_opt {
    None => return WtExecOutcome::AuthFailed(WtAuthError::NoServiceAccept)
    Some(_) => ()
  }
  let curve = @ecdsa.Curve::p256()
  let (_, _, payload) = match
    @userauth.userauth_publickey_signed_request(
      curve,
      d,
      st.session_id,
      user,
      @userauth.AUTH_SERVICE_CONNECTION,
    ) {
    None => return WtExecOutcome::AuthFailed(WtAuthError::SignFailed)
    Some(v) => v
  }
  if !wt_send_plain_packet(
      conn,
      st.counters,
      st.send,
      @sshwire.SSH_MSG_USERAUTH_REQUEST,
      payload,
    ) {
    return WtExecOutcome::AuthFailed(WtAuthError::NoAuthReply)
  }
  let mut tries = 0
  let mut ok = false
  while tries < 32 {
    match wt_recv_plain_packet(conn, st.counters, st.recv) {
      Closed => return WtExecOutcome::AuthFailed(WtAuthError::NoAuthReply)
      BadPacket(why) => return WtExecOutcome::AuthFailed(WtAuthError::BadPacket(why))
      Packet(t, _) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_USERAUTH_SUCCESS {
          ok = true
          break
        }
        if t == @sshwire.SSH_MSG_USERAUTH_FAILURE {
          return WtExecOutcome::AuthFailed(WtAuthError::NoAuthReply)
        }
      }
    }
  }
  if !ok {
    return WtExecOutcome::AuthFailed(WtAuthError::NoAuthReply)
  }
  let (chan0, failure) = wt_exec_drive(conn, st, command)
  match failure {
    Some(e) => WtExecOutcome::ChannelFailed(e)
    None => {
      let rep = chan0.report()
      WtExecOutcome::Done({
        stdout: rep.stdout,
        stderr: rep.stderr,
        exit_status: rep.exit_status,
        remote_id: rep.remote_id,
        adjusts_sent: rep.adjusts_sent,
        sent_bytes: st.counters.sent,
        recv_bytes: st.counters.recv,
      })
    }
  }
}

///|
/// 浏览器侧的通道收发循环。与 `src/sshclient` 的 `exec_drive` 是同一条控制流,
/// 只有 `wt_send_plain_packet` / `wt_recv_plain_packet` 不同——协议判断一行
/// 都没有复制过来。
async fn wt_exec_drive(
  conn : @wt.WtConn,
  st : WtSessionState,
  command : String,
) -> (@channel.ChanState, WtExecError?) {
  let open = @channel.ChanState::new(@channel.LOCAL_CHANNEL).open_action()
  if !wt_send_action(conn, st, open) {
    return (
      @channel.ChanState::new(@channel.LOCAL_CHANNEL),
      Some(WtExecError::SendFailed),
    )
  }
  let mut first = 0
  let mut chan = @channel.ChanState::new(@channel.LOCAL_CHANNEL)
  while first < 8 {
    match wt_recv_plain_packet(conn, st.counters, st.recv) {
      Closed => return (chan, Some(WtExecError::Closed))
      BadPacket(why) => return (chan, Some(WtExecError::BadPacket(why)))
      Packet(t, pl) => {
        let (chan2, _actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(chan_err) => return (chan, Some(wt_chan_error(chan_err)))
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
    return (chan, Some(WtExecError::Malformed("no_open_confirmation")))
  }
  let exec_action = match chan.exec_action(command) {
    None => return (chan, Some(WtExecError::Malformed("exec_before_open")))
    Some(a) => a
  }
  if !wt_send_action(conn, st, exec_action) {
    return (chan, Some(WtExecError::SendFailed))
  }
  let mut packets = 0
  let cap = 65536
  while !chan.finished() {
    if packets >= cap {
      return (chan, Some(WtExecError::TooManyPackets))
    }
    match wt_recv_plain_packet(conn, st.counters, st.recv) {
      Closed => return (chan, Some(WtExecError::Closed))
      BadPacket(why) => return (chan, Some(WtExecError::BadPacket(why)))
      Packet(t, pl) => {
        packets = packets + 1
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(chan_err) => return (chan, Some(wt_chan_error(chan_err)))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          if !wt_send_action(conn, st, actions[i]) {
            return (chan, Some(WtExecError::SendFailed))
          }
        }
      }
    }
  }
  (chan, None)
}

async fn wt_send_action(
  conn : @wt.WtConn,
  st : WtSessionState,
  a : @channel.ChanAction,
) -> Bool {
  match a {
    Send(t, payload) => wt_send_plain_packet(conn, st.counters, st.send, t, payload)
  }
}

fn wt_chan_error(e : @channel.ChanError) -> WtExecError {
  match e {
    OpenFailed(r, d) => WtExecError::OpenFailed(r, d)
    ExecRejected => WtExecError::ExecRejected
    Malformed(m) => WtExecError::Malformed(m)
  }
}

///| Render a prefix of the shared secret, enough to correlate two transcripts

///|
/// without printing the whole ephemeral value.
fn shared_secret_head_of(k : @bigint.BigNat) -> String {
  let h = @bigint.BigNat::to_hex(k)
  if h.length() <= 16 {
    h
  } else {
    h.unsafe_substring(start=0, end=16)
  }
}

///|

///|
/// Which name-list had no common entry.
fn wt_neg_error_label(e : @kexflow.NegotiationError) -> String {
  match e {
    @kexflow.NoKexAlg => "kex"
    @kexflow.NoHostkeyAlg => "hostkey"
    @kexflow.NoCipherAlg => "cipher"
    @kexflow.NoMacAlg => "mac"
    @kexflow.NoCompAlg => "comp"
  }
}
