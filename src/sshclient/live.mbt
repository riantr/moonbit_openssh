///| Loop #31/#33: real SSH handshake against a live server, through NEWKEYS

///| into the encrypted session.
///
///   Everything above this layer is transport agnostic, so this is where the
///   Loop #26..#30 work actually meets a real OpenSSH process:
///
///     1. identification string exchange (RFC 4253 §4.2, banner lines until one
///        starting with "SSH-")
///     2. KEXINIT in both directions, first-match negotiation (RFC 4253 §7.1)
///     3. SSH_MSG_KEX_ECDH_INIT with our DH public value e (RFC 4253 §8)
///     4. SSH_MSG_KEX_ECDH_REPLY: K_S, f, signature
///     5. shared secret K = f^x mod p
///     6. exchange hash H over V_C || V_S || I_C || I_S || K_S || e || f || K
///     7. host key signature verification -- the Loop #30 ECDSA path, against
///        a signature a real server produced rather than a KAT
///     8. SSH_MSG_NEWKEYS, then key derivation and a switch to
///        aes128-ctr + hmac-sha2-256
///     9. Loop #33: SSH_MSG_SERVICE_REQUEST over the *encrypted* channel, and
///        the SERVICE_ACCEPT that proves the server could decrypt it
///
///   Step 7 is the point of the first half: everything up to it could be right
///   and the exchange hash could still differ by one bit, in which case the
///   signature check fails and the server is (correctly) treated as a MITM.
///
///   Step 9 is the point of the second half. Until NEWKEYS the channel is
///   plaintext, so a bug in the packet layer shows up as a framing error. Past
///   NEWKEYS every byte on the wire is ciphertext plus a MAC, and the only
///   honest way to know the keys, the counter and the MAC are all right is for
///   a real server to send something back. SERVICE_ACCEPT is the cheapest such
///   message: it proves decrypt-and-verify in both directions without dragging
///   us into userauth.
///
///   Sequencing note (Loop #33): the handshake is driven through
///   `@bpacket`'s SendCtx/RecvCtx rather than the hand-rolled helpers Loop #31
///   used. Those helpers had no sequence-number accounting, which is invisible
///   while everything is plaintext -- but seqnr feeds the MAC, so the first
///   encrypted packet would have gone out with the wrong one. Going through the
///   context objects gets it right for free, and the on-wire bytes are
///   unchanged (the two padding formulas are algebraically identical; see
///   `framing.mbt` vs `SendCtx::emit`).

///|
/// Outcome of a live handshake.
pub(all) enum LiveResult {
  /// Handshake reached NEWKEYS with the host key signature verified.
  Established(LiveReport)
  /// Handshake failed; the reason is carried through for the report.
  Failed(LiveError)
}

///|
/// Why a live handshake failed.
pub(all) enum LiveError {
  ConnectFailed
  /// The server's banner never started with SSH-.
  NoServerIdent
  KexinitSendFailed
  /// Peer closed or the stream ended where a KEXINIT was expected.
  NoPeerKexinit
  KexinitParseFailed
  /// No algorithm in common on one of the ten name-lists.
  NoAgreement(String)
  EcdhInitSendFailed
  NoEcdhReply
  EcdhReplyMalformed
  /// The host key blob did not parse, or was not the algorithm we negotiated.
  HostkeyInvalid
  /// The exchange hash did not verify. Either our hash inputs are wrong or
  /// the server is not who it claims to be; the caller must not continue.
  /// The hash we computed is carried out so a diagnostic harness can diff it
  /// against an independent implementation instead of guessing.
  SignatureInvalid(FixedArray[Byte])
  NewkeysSendFailed
  NoNewkeys
  /// A packet arrived but could not be framed -- bad length, bad padding, or
  /// (post-NEWKEYS) a MAC that did not verify.
  ///
  /// 带上具体原因,因为这一类和「对端关闭」在旧版本里都塌成了 None:一条
  /// MAC 不匹配的包会让 SERVICE_ACCEPT 的等待超时,然后被报成
  /// `NoServiceAccept`,于是最可能的故障点被指向了错误的方向。
  BadPacket(String)
}

///|
/// `PacketError` 的短标签,供诊断输出与 `LiveError::BadPacket` 共用。
///
/// 放在 `src/sshclient` 而不是只留在本文件,是因为 `src/wtlive` 要给
/// 同一个错误起同样的名字——两边各写一份的话,某个 label 改了另一个不会。
pub fn packet_error_label(e : @bpacket.PacketError) -> String {
  match e {
    @bpacket.BadLength(n) => "bad_length:" + n.to_string()
    @bpacket.AlignError(n) => "align_error:" + n.to_string()
    @bpacket.AuthFailed => "auth_failed"
    @bpacket.MacInvalid => "mac_invalid"
    @bpacket.BadPadlen(n) => "bad_padlen:" + n.to_string()
    @bpacket.PadOverflow(n) => "pad_overflow:" + n.to_string()
    @bpacket.EmptyPayload => "empty_payload"
    @bpacket.BadType(n) => "bad_type:" + n.to_string()
    @bpacket.SeqnrWrapInitial => "seqnr_wrap_initial"
  }
}

///|
/// What a successful handshake observed. Kept as data rather than printed
/// inline so the test driver can assert on individual fields.
pub(all) struct LiveReport {
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
  /// Bytes the client sent and received, for the byte transcript.
  sent_bytes : Int
  recv_bytes : Int
}

///|
/// 协商出的加密参数需要派生多少字节(kex.c:1141-1152)
///
///   need = max(enc.key_len, enc.block_size, enc.iv_len, mac.key_len)
///
/// 对 aes128-ctr + hmac-sha2-256 是 max(16, 16, 16, 32) = 32。六个密钥
/// 统一按这个长度派生,短的那个取前缀——这一点在 kex.c:1155 对 A..F 一视同仁,
/// 不是只对加密密钥取 key_len。
pub fn we_need_for(cipher : String, mac : String) -> Int {
  let (key_len, block_size, iv_len) = match cipher {
    "aes128-ctr" => (16, 16, 16)
    "aes192-ctr" => (24, 16, 16)
    "aes256-ctr" => (32, 16, 16)
    "chacha20-poly1305@openssh.com" => (64, 8, 0)
    _ => abort("we_need_for: unsupported cipher " + cipher)
  }
  let mac_key_len = match mac {
    "hmac-sha2-256" => 32
    "hmac-sha2-512" => 64
    "hmac-sha1" => 20
    "hmac-sha1-96" => 20
    _ => abort("we_need_for: unsupported mac " + mac)
  }
  let m = key_len
  let m = if block_size > m { block_size } else { m }
  let m = if iv_len > m { iv_len } else { m }
  if mac_key_len > m {
    mac_key_len
  } else {
    m
  }
}

///|
/// Number of bytes of the shared secret rendered in the report, to keep the
/// output stable without dumping 512 hex characters every run.
const SHARED_HEAD_LEN : Int = 16

// ---------------------------------------------------------------------------
// Small wire helpers
// ---------------------------------------------------------------------------

// cat2 / with_type / ascii / bytes_to_string now live in framing.mbt, shared
// with Loop #32's async browser driver. Only `hex_head` remains local: it is a
// reporting helper for the driver output, not part of the protocol.

///|
fn hex_head(v : @bigint.BigNat, n : Int) -> String {
  let h = @bigint.BigNat::to_hex(v)
  if h.length() <= n {
    h
  } else {
    h.unsafe_substring(start=0, end=n)
  }
}

///|
/// 字节前缀的十六进制,用于诊断输出。
///
/// 只可用于**非秘密**字节(目前只有 session_id,也就是交换哈希,它本来就在
/// 协议里明文出现)。会话密钥请走 `key_fingerprint`。
///
/// `pub` 是因为 `src/wtlive` 需要同一个定义;各写一份的话,两边可能对
/// 「前缀取几字节」产生分歧,而那只会体现为两个传输路径的诊断字段不一致。
pub fn hex_bytes_head(b : FixedArray[Byte], n : Int) -> String {
  let m = if b.length() < n { b.length() } else { n }
  let sb = StringBuilder()
  let hex_chars : String = "0123456789abcdef"
  let mut i = 0
  while i < m {
    let hi = b[i].to_int() / 16
    let lo = b[i].to_int() % 16
    sb.write_string(hex_chars.unsafe_substring(start=hi, end=hi + 1))
    sb.write_string(hex_chars.unsafe_substring(start=lo, end=lo + 1))
    i = i + 1
  }
  sb.to_string()
}

///|
/// The algorithm set this client implements. The Loop #31 sshd is pinned to
/// exactly this, so a mismatch is our bug rather than a negotiation race --
/// except for the host key list, which is no longer pinned. See
/// `LIVE_HOSTKEY_ALGS` below for why.
///
/// Note we deliberately do **not** advertise `kex-strict-c-v00@openssh.com`.
/// OpenSSH turns strict KEX on only when the peer advertises it (kex.c:963-970),
/// so with this proposal `kex_strict` is false and the sequence number runs
/// straight through NEWKEYS instead of resetting (packet.c:1376-1379).
/// Advertising it would reset seqnr to 0 and change the handshake transcript,
/// which would invalidate the Loop #31/#32 byte-count assertions. The contexts
/// below handle either outcome, so this is a transcript-stability choice, not a
/// correctness one.
///|
/// Host key algorithms this client offers, in preference order.
///
/// Order is the client's preference and wins outright: OpenSSH picks the first
/// entry of the *client* list that the server also offers (`kex.c:887-890`
/// `match_list(client, server)`), the same rule RFC 4253 §7.1 states. So this
/// ordering alone decides which algorithm every connection uses; the server's
/// own ordering only matters for algorithms we do not list.
///
/// Loop #31 pinned the test sshd with `HostKeyAlgorithms` to work around the
/// fact that we only reported ECDSA. That pin hid the real defect: against a
/// stock sshd holding only ed25519/rsa host keys -- the default on most hosts
/// -- negotiation failed outright with `NoAgreement`, because every name the
/// server offered was one we refused. The pin is gone (host/sshd_setup.mjs)
/// and this list is now what we can actually verify.
///
/// `ssh-rsa` (RFC 4253, SHA-1) is deliberately absent. It maps to SHA-1
/// (`ssh-rsa.c:328-359` `rsa_hash_id_from_ident`), which this project does not
/// implement, and OpenSSH 8.8+ disables it by default. Advertising a name we
/// cannot check would only push the failure from negotiation time to verify
/// time, and would blame an algorithm that was never selected.
///
/// The three-way name split for RSA is why `src/hostkey` exists: the blob type
/// string is `ssh-rsa`, the negotiated name is `rsa-sha2-512`, and the
/// signature blob's inner name equals the negotiated name. The test is that the
/// two names resolve to the *same digest*, not that any two strings are equal
/// (`ssh-rsa.c:526-535`).
const LIVE_HOSTKEY_ALGS : String =
  "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384"

pub fn live_proposal() -> @kexflow.Proposal {
  {
    kex_algs: "diffie-hellman-group14-sha256",
    hostkey_algs: LIVE_HOSTKEY_ALGS,
    enc_ctos: "aes128-ctr",
    enc_stoc: "aes128-ctr",
    mac_ctos: "hmac-sha2-256",
    mac_stoc: "hmac-sha2-256",
    comp_ctos: "none",
    comp_stoc: "none",
    lang_ctos: "",
    lang_stoc: "",
  }
}

///|
/// Deterministic 16-byte KEXINIT cookie. A real client would use random
/// bytes; a fixed cookie keeps the transcript reproducible so a byte diff
/// against the paramiko capture is meaningful.
pub fn fixed_cookie() -> FixedArray[Byte] {
  let c : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let mut i = 0
  while i < 16 {
    c[i] = (0xA0 + i).to_byte()
    i = i + 1
  }
  c
}

// ---------------------------------------------------------------------------
// Transport framing
// ---------------------------------------------------------------------------

///|
/// Counters so the report can state how much actually crossed the wire.
priv struct WireCounters {
  mut sent : Int
  mut recv : Int
}

///|
/// Send one SSH packet through a `@bpacket.SendCtx`.
///
///   Wire layout (RFC 4253 §6) is entirely the context's business now: it
///   knows the block size, the padding rule and, after NEWKEYS, the cipher and
///   MAC. This function only moves bytes and keeps the counter honest.
///
///   `pad_src` is zeros. RFC 4253 §6 asks for unpredictable padding, which a
///   production client must supply from the CSPRNG -- but Loop #31's whole
///   point is a byte-exact transcript, and unpredictable padding makes the
///   transcript irreproducible. The trade is deliberate and this is the place
///   to change it.
fn send_packet(
  conn : @tcp.TcpConn,
  counters : WireCounters,
  s : @bpacket.SendCtx,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> Bool {
  let pad_src : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  match s.emit(msg_type, payload, pad_src) {
    Ok(pkt) => {
      if !conn.send(pkt.wire) {
        return false
      }
      counters.sent = counters.sent + pkt.wire.length()
      true
    }
    _ => false
  }
}

///|
/// `recv_packet` 的结果。
///
/// 以前只有 `?`,于是「对端关闭」和「MAC 不匹配」共用一个 None——前者
/// 是正常的传输终止,后者是我们和对端对同一段明文的看法不一致,必须终止
/// 连接(packet.c:1758-1769)。把两者分开之后,后者能一路走到
/// `LiveError::BadPacket` 并带上原因,诊断才不用靠猜。
pub(all) enum RecvOutcome {
  Packet(Byte, FixedArray[Byte])
  /// 对端关闭,或在一个包的中途断了
  Closed
  /// 读到了完整一段,但它不是一个合法的包
  BadPacket(String)
}

///|
/// Read exactly one SSH packet through a `@bpacket.RecvCtx`.
///
///   The read has to be *exact*, not chunked: once a packet has been consumed
///   the next read is for the following message, and a chunked reader would
///   block waiting for bytes that will not arrive until we answer. So the
///   length is asked for first -- `RecvCtx::wire_len_from_header` decrypts the
///   4-byte length field for us when the channel is encrypted -- and only then
///   is the remainder pulled in.
fn recv_packet(
  conn : @tcp.TcpConn,
  counters : WireCounters,
  r : @bpacket.RecvCtx,
) -> RecvOutcome {
  let hdr = match conn.read_exact(4) {
    None => return Closed
    Some(h) => h
  }
  let rest = match r.wire_len_from_header(hdr) {
    // 头部都解不开:加密态下这几乎总是「本该重放同一段密钥流却拿到了别的
    // 字节」,和 MAC 失败同源,所以归到 BadPacket 而不是 Closed。
    None => return BadPacket("undecryptable_header")
    Some(v) => v
  }
  if rest < 0 || rest > 1048576 {
    return BadPacket("length_out_of_range:" + rest.to_string())
  }
  let body = if rest == 0 {
    FixedArray::make(0, b'\x00')
  } else {
    match conn.read_exact(rest) {
      None => return Closed
      Some(b) => b
    }
  }
  counters.recv = counters.recv + 4 + rest
  match r.recv(cat2(hdr, body)).event {
    @bpacket.Packet(_, t, payload) => Packet(t, payload)
    @bpacket.NeedMore => Closed
    @bpacket.Failed(e) => BadPacket(packet_error_label(e))
  }
}

///|
/// Read one CRLF-terminated identification line, bounded so a hostile or
/// broken server cannot make us read forever.
fn read_ident_line(
  conn : @tcp.TcpConn,
  counters : WireCounters,
  max_bytes : Int,
) -> String? {
  let mut acc : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut total = 0
  while total < max_bytes {
    let b = match conn.read_exact(1) {
      None => return None
      Some(v) => v
    }
    counters.recv = counters.recv + 1
    total = total + 1
    let one : FixedArray[Byte] = FixedArray::make(1, b[0])
    acc = cat2(acc, one)
    if acc.length() >= 2 &&
      acc[acc.length() - 2] == b'\r' &&
      acc[acc.length() - 1] == b'\n' {
      let n = acc.length() - 2
      let line : FixedArray[Byte] = FixedArray::make(n, b'\x00')
      for i = 0; i < n; i = i + 1 {
        line[i] = acc[i]
      }
      return Some(bytes_to_string(line))
    }
  }
  None
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

///|
/// Which name-list had no common entry. Reported as a label rather than the
/// enum so the failure output stays readable and stable.
fn neg_error_label(e : @kexflow.NegotiationError) -> String {
  match e {
    @kexflow.NoKexAlg => "kex"
    @kexflow.NoHostkeyAlg => "hostkey"
    @kexflow.NoCipherAlg => "cipher"
    @kexflow.NoMacAlg => "mac"
    @kexflow.NoCompAlg => "compression"
  }
}

///| 穿过 NEWKEYS 之后继续会话所需的全部状态
///

///| 私有:里面的 WireCounters 也是私有的,整体不导出。

///|

///| 打包在一起而不是散成五个返回值,是因为它们必须**同时**从一个连接里取出来:

///|
/// 只拿到密钥而丢了对应的 SendCtx/RecvCtx,等于把 seqnr 和计数器扔在半路上。
priv struct SessionState {
  send : @bpacket.SendCtx
  recv : @bpacket.RecvCtx
  counters : WireCounters
  we_need : Int
  /// 首次 KEX 的 H。publickey 认证要拿它当签名的输入(RFC 4252 §7),
  /// 所以必须是**完整**字节——之前只留了一个 16 字节的十六进制摘要给诊断,
  /// 那是打印给人看的,不是拿来签名的。
  session_id : FixedArray[Byte]
  /// 两个方向的会话密钥指纹(各 12 个十六进制字符),`enc/mac` 分隔。
  ///
  /// 之前这里叫 `key_head`,打印的是 enc_key_ctos 的**前 8 个原始字节**和
  /// mac_key_ctos 的前 8 个原始字节——也就是每次握手往 stdout / CI 日志里
  /// 漏 32 字节会话密钥材料,注释却写着「不打印原始密钥」。它被改成了
  /// SHA-256 截断指纹:同样能用来判断「两条路径各自派生出了不同的密钥、
  /// 方向没有搞反」,但拿不回任何可用的密钥字节。
  key_tag : String
  session_id_head : String
}

///|
/// 前 n 个字节
///
/// 六个密钥都按 `we_need` 派生(aes128-ctr + hmac-sha2-256 下是 32),但交给
/// cipher 的只有 key_len / iv_len 字节——OpenSSH 在 ssh_set_newkeys 里传的是
/// `cipher_new(..., key, cipher_keylen(c), iv, cipher_ivlen(c), ...)`,
/// 也就是各取前缀。直接把 32 字节塞给 aes128-ctr 会在 cipher 初始化时就长度不符。
///
/// `pub` 是因为 `src/wtlive` 的握手做完全一样的事;两边各写一份的话,任何
/// 一处「前缀取多取少」都会只在一条路径上生效,而那正是最难发现的方向。
pub fn head_bytes(b : FixedArray[Byte], n : Int) -> FixedArray[Byte] {
  let m = if b.length() < n { b.length() } else { n }
  let out : FixedArray[Byte] = FixedArray::make(m, b'\x00')
  for i = 0; i < m; i = i + 1 {
    out[i] = b[i]
  }
  out
}

///|
/// 会话密钥的诊断指纹:SHA-256 的前 12 个十六进制字符。
///
/// 用途是「两次运行 / 两条传输路径派生出的密钥是不是同一个、两个方向有没有
/// 搞反」,这两件事 SHA-256 前 48 bit 都足够回答,而且不可逆;直接截原始字节
/// 则把密钥写进了日志。这里**不能**换成一个更短的原文前缀——任何长度的原文
/// 都是密钥材料。
pub fn key_fingerprint(k : FixedArray[Byte]) -> String {
  let h = @hostkey.sha256(k)
  let m = if h.length() < 6 { h.length() } else { 6 }
  let sb = StringBuilder()
  let hex_chars : String = "0123456789abcdef"
  for i = 0; i < m; i = i + 1 {
    let hi = h[i].to_int() / 16
    let lo = h[i].to_int() % 16
    sb.write_string(hex_chars.unsafe_substring(start=hi, end=hi + 1))
    sb.write_string(hex_chars.unsafe_substring(start=lo, end=lo + 1))
  }
  sb.to_string()
}

///|
/// 两个方向的密钥指纹,`<enc>/<mac>`。
///
/// 保留分隔符是有意的:两条方向必须能被区分,否则「两个方向拿到了同一把
/// 密钥」这种错误会被这个字段掩盖掉。
pub fn key_tag_of(
  enc_key_ctos : FixedArray[Byte],
  mac_key_ctos : FixedArray[Byte],
) -> String {
  key_fingerprint(enc_key_ctos) + "/" + key_fingerprint(mac_key_ctos)
}

///|
/// Run the handshake up to and including NEWKEYS, leaving both contexts
/// switched to the negotiated cipher.
///
/// `x` is the DH private exponent. A real client draws it from the CSPRNG;
/// taking it as a parameter keeps this run reproducible, and the caller is
/// responsible for using a fresh value per connection in production.
fn handshake_to_session(
  conn : @tcp.TcpConn,
  x : @bigint.BigNat,
) -> (LiveResult, SessionState?) {
  let counters = { sent: 0, recv: 0, }
  let s = @bpacket.SendCtx::new()
  let r = @bpacket.RecvCtx::new()
  let client_ident = "SSH-2.0-MoonBit_0.1"
  // ---- 1. identification exchange ----
  if !conn.send(cat2(ascii(client_ident), ascii("\r\n"))) {
    return (Failed(ConnectFailed), None)
  }
  counters.sent = counters.sent + client_ident.length() + 2
  // A server may emit informational lines before its SSH- line.
  let mut server_ident = ""
  let mut lines = 0
  while lines < 64 {
    match read_ident_line(conn, counters, 255) {
      None => return (Failed(NoServerIdent), None)
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
    return (Failed(NoServerIdent), None)
  }
  // ---- 2. KEXINIT ----
  let my = live_proposal()
  let ic_payload = @kexflow.kexinit_payload(fixed_cookie(), my)
  if !send_packet(conn, counters, s, @sshwire.SSH_MSG_KEXINIT, ic_payload) {
    return (Failed(KexinitSendFailed), None)
  }
  let mut peer_ic_payload : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut got_kexinit = false
  let mut tries = 0
  while !got_kexinit && tries < 32 {
    match recv_packet(conn, counters, r) {
      Closed => return (Failed(NoPeerKexinit), None)
      BadPacket(why) => return (Failed(BadPacket(why)), None)
      Packet(t, payload) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_KEXINIT {
          peer_ic_payload = payload
          got_kexinit = true
        }
        // Anything else here is pre-KEXINIT noise; a real server sends none.
      }
    }
  }
  if !got_kexinit {
    return (Failed(NoPeerKexinit), None)
  }
  let peer_prop = match @kexflow.parse_kexinit(peer_ic_payload) {
    None => return (Failed(KexinitParseFailed), None)
    Some(p) => p
  }
  let neg = match @kexflow.negotiate(my, peer_prop) {
    Err(e) => return (Failed(NoAgreement(neg_error_label(e))), None)
    Ok(n) => n
  }
  if neg.kex_alg != "diffie-hellman-group14-sha256" {
    return (Failed(NoAgreement("kex_alg")), None)
  }
  // ---- 3. KEX_ECDH_INIT ----
  let p = @bigint.BigNat::from_bytes_be(@kexdh.group14_prime())
  let g = @bigint.BigNat::from_uint64(2UL)
  let ctx = @kexdh.dh_ctx(p)
  let e = @kexdh.dh_pub_ctx(ctx, g, x)
  let e_wire = @bigint.BigNat::mpint_encode(e)
  // mpint_encode already emits the u32 length prefix, so the SSH string IS the
  // mpint encoding. Wrapping it again in write_ssh_string yields a string whose
  // value begins with four zero bytes, and the server rejects that as
  // "invalid public DH value: >= p-1".
  if !send_packet(conn, counters, s, @sshwire.SSH_MSG_KEX_ECDH_INIT, e_wire) {
    return (Failed(EcdhInitSendFailed), None)
  }
  // ---- 4. KEX_ECDH_REPLY ----
  let mut reply : FixedArray[Byte]? = None
  let mut tries2 = 0
  while tries2 < 32 {
    match recv_packet(conn, counters, r) {
      Closed => return (Failed(NoEcdhReply), None)
      BadPacket(why) => return (Failed(BadPacket(why)), None)
      Packet(t, payload) => {
        tries2 = tries2 + 1
        if t == @sshwire.SSH_MSG_KEX_ECDH_REPLY {
          reply = Some(payload)
          break
        }
        if t == KX_MSG_KEX_FAILURE {
          return (Failed(EcdhReplyMalformed), None)
        }
      }
    }
  }
  let reply_payload = match reply {
    None => return (Failed(NoEcdhReply), None)
    Some(v) => v
  }
  let parsed_reply = parse_ecdh_reply(reply_payload)
  let (ks, f_wire, sig_blob) = match parsed_reply {
    None => return (Failed(EcdhReplyMalformed), None)
    Some(t) => t
  }
  // ---- 5. shared secret ----
  let f = @bigint.BigNat::from_bytes_be(f_wire)
  if @bigint.BigNat::cmp(f, @bigint.BigNat::from_uint64(1UL)) <= 0 ||
    @bigint.BigNat::cmp(f, p) >= 0 {
    return (Failed(EcdhReplyMalformed), None)
  }
  let k = @kexdh.dh_shared_ctx(ctx, f, x)
  let k_wire = @bigint.BigNat::mpint_encode(k)
  // ---- 6. exchange hash ----
  // H = SHA256( string(V_C) || string(V_S) || string(I_C) || string(I_S)
  //           || string(K_S)  || string(mpint e) || string(mpint f)
  //           || string(mpint K) )
  //
  // All eight fields carry a u32 length prefix -- K included. Verified three
  // ways:
  //   * OpenSSH kex_gen_hash() (kexgen.c:67-79) wraps V_C/V_S/I_C/I_S/K_S and
  //     the e/f mpints with sshbuf_put_stringb, and appends shared_secret with
  //     sshbuf_putb -- but kex_dh_compute_key() (kexdh.c:105) had already stored
  //     the shared secret via sshbuf_put_bignum2, i.e. already length-prefixed.
  //   * I_C/I_S use a "fake header": u32(len+1) || 0x14 || payload-without-type
  //     (kexgen.c:70-75), which is byte-identical to the complete KEXINIT
  //     payload including its message-type byte.
  //   * host/paramiko_oracle.py sweeps all 16 prefix combinations against a
  //     real paramiko session_id; exactly one matches -- every field prefixed.
  //   * host/transcript_check.py tees a real MoonBit connection, recomputes H
  //     from the recorded wire bytes, and gets the same value this code does.
  //
  // V_C and V_S exclude the CR LF. e and K arrive from mpint_encode already
  // carrying their prefix; f and K_S are raw string bodies that need one.
  let v_c_w = @sshwire.write_ssh_string(ascii(client_ident))
  let v_s_w = @sshwire.write_ssh_string(ascii(server_ident))
  let i_c_w = @sshwire.write_ssh_string(
    with_type(@sshwire.SSH_MSG_KEXINIT, ic_payload),
  )
  let i_s_w = @sshwire.write_ssh_string(
    with_type(@sshwire.SSH_MSG_KEXINIT, peer_ic_payload),
  )
  let k_s_w = @sshwire.write_ssh_string(ks)
  let f_w = @sshwire.write_ssh_string(f_wire)
  let h = @kexdh.exchange_hash(
    v_c_w, v_s_w, i_c_w, i_s_w, k_s_w, e_wire, f_w, k_wire,
  )
  // ---- 7. host key verification ----
  // Parse once: the key value is what both the type inspection and the
  // signature check need, and re-parsing would be wasted work.
  let key = match @hostkey.HostKey::from_blob(ks) {
    @hostkey.Parsed(k) => k
    _ => return (Failed(HostkeyInvalid), None)
  }
  // 「密钥类型和协商出的算法名配不配对」这条规则住在 src/hostkey
  // (`agrees_with_alg`),不在这里抄一份:RFC 8332 让 ed25519/ECDSA 和 RSA
  // 的答案不同,两份抄件迟早会漂。类型不配对报 HostkeyInvalid,签名本身
  // 验不过报 SignatureInvalid——两者在协议上的后果相同,但诊断时完全不同。
  if !@hostkey.HostKey::agrees_with_alg(key, neg.hostkey_alg) {
    return (Failed(HostkeyInvalid), None)
  }
  let (ktype, kbits) = @hostkey.HostKey::describe(key)
  match @hostkey.HostKey::verify_with_alg(key, h, sig_blob, neg.hostkey_alg) {
    @hostkey.Accepted => ()
    _ => return (Failed(SignatureInvalid(h)), None)
  }
  // ---- 8. NEWKEYS ----
  if !send_packet(
      conn,
      counters,
      s,
      @sshwire.SSH_MSG_NEWKEYS,
      FixedArray::make(0, b'\x00'),
    ) {
    return (Failed(NewkeysSendFailed), None)
  }
  let mut got_newkeys = false
  let mut tries3 = 0
  while !got_newkeys && tries3 < 32 {
    match recv_packet(conn, counters, r) {
      Closed => return (Failed(NoNewkeys), None)
      BadPacket(why) => return (Failed(BadPacket(why)), None)
      Packet(t, _) => {
        tries3 = tries3 + 1
        if t == @sshwire.SSH_MSG_NEWKEYS {
          got_newkeys = true
        }
      }
    }
  }
  if !got_newkeys {
    return (Failed(NoNewkeys), None)
  }
  // ---- 9. 派生会话密钥并切换到加密模式 ----
  // RFC 4253 §7.3:每一端在**发出** NEWKEYS 后立刻切换自己的发送方向,
  // 在**收到** NEWKEYS 后切换接收方向。上面两个动作都已完成,现在两个方向
  // 都可以切了。
  let we_need = we_need_for(neg.cipher_ctos, neg.mac_ctos)
  if we_need != we_need_for(neg.cipher_stoc, neg.mac_stoc) {
    return (Failed(NoAgreement("asymmetric key length")), None)
  }
  let keys = @kexc25519.derive_keys(h, k_wire, we_need)
  // 每个方向用自己的 'A'/'B' 计数器与 'C'/'D' 加密密钥;共用一个会让第二个方向
  // 从错误的密钥流偏移开始解密,而且不会报错,只会安静地解出乱码。
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
  // 初始 KEX 到此结束。kex.c:567 在这里清 KEX_INITIAL:过了这个点,
  // seqnr 回绕不再是致命错误(packet.c:1363-1367 只在 KEX_INITIAL 期间
  // 终止连接)。不调用的话,这个标志会一直带着,每收一个包都白走一次
  // 「回绕是不是致命」的分支,而且语义上它已经错了。
  s.end_initial_kex()
  r.end_initial_kex()
  let report = Established({
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
    shared_secret_head: hex_head(k, SHARED_HEAD_LEN),
    sent_bytes: counters.sent,
    recv_bytes: counters.recv,
  })
  (
    report,
    Some({
      send: s,
      recv: r,
      counters,
      we_need,
      session_id: keys.session_id(),
      key_tag: key_tag_of(keys.enc_key_ctos(), keys.mac_key_ctos()),
      session_id_head: hex_bytes_head(keys.session_id(), 16),
    }),
  )
}

///|
/// Run a full handshake against `host:port`, stopping after NEWKEYS.
pub fn live_handshake(conn : @tcp.TcpConn, x : @bigint.BigNat) -> LiveResult {
  let (r, _) = handshake_to_session(conn, x)
  r
}

///|
/// Outcome of handshake + first encrypted round trip.
pub(all) enum SessionResult {
  /// The server decrypted our SERVICE_REQUEST and accepted the service.
  ServiceAccepted(SessionReport)
  Failed(SessionError)
}

///|
/// Why the encrypted phase failed.
pub(all) enum SessionError {
  /// The transport handshake never got as far as NEWKEYS.
  HandshakeFailed(LiveError)
  /// Nothing came back where SERVICE_ACCEPT was due. With encryption in play
  /// this is almost always a key/counter/MAC mistake rather than a framing one,
  /// so the report carries the byte counts to tell the two apart.
  NoServiceAccept
  /// The server answered, but not with the service we asked for.
  UnexpectedService(String)
  /// 一整段字节读回来了,但它不是一个合法的包(MAC 不匹配、对齐错、padding 非法)。
  ///
  /// 与 `NoServiceAccept` 分开是必须的:加密信道上「等不到 SERVICE_ACCEPT」
  /// 最常见的原因就是 MAC 失败,而把这个原因丢掉之后,唯一能看到的现象是
  /// 一个指向错误方向的超时。
  BadPacket(String)
}

///|
/// What the encrypted phase observed.
pub(all) struct SessionReport {
  handshake : LiveReport
  service_name : String
  accepted_service : String
  we_need : Int
  key_tag : String
  session_id_head : String
  /// Total bytes sent / received across handshake *and* encrypted phase.
  sent_bytes : Int
  recv_bytes : Int
}

///|
/// 我们请求的服务名(RFC 4253 §7.1)
pub const USERAUTH_SERVICE : String = "ssh-userauth"

///|
/// Handshake, then prove the encrypted channel works end to end.
///
/// This is the Loop #33 endpoint: a real server decrypts an aes128-ctr +
/// hmac-sha2-256 packet we produced and answers over the same channel. Nothing
/// about that can be faked by a self-consistent bug on our side -- if our keys,
/// counter or MAC were wrong the server would either drop the connection or
/// reply `MAC error`/`decryption failed`, and this function would report it.
pub fn live_session(conn : @tcp.TcpConn, x : @bigint.BigNat) -> SessionResult {
  let (res, state) = handshake_to_session(conn, x)
  let handshake = match res {
    Established(rep) => rep
    Failed(e) => return Failed(SessionError::HandshakeFailed(e))
  }
  let st = match state {
    None => return Failed(SessionError::NoServiceAccept)
    Some(v) => v
  }
  match request_userauth_service(conn, st) {
    (Some(accepted), None) =>
      ServiceAccepted({
        handshake,
        service_name: USERAUTH_SERVICE,
        accepted_service: accepted,
        we_need: st.we_need,
        key_tag: st.key_tag,
        session_id_head: st.session_id_head,
        sent_bytes: st.counters.sent,
        recv_bytes: st.counters.recv,
      })
    (_, Some(err)) => Failed(err)
    // 成功时必定带上服务名,这里是类型系统看不到的不变量;落到这里说明
    // request_userauth_service 的两个返回值被写坏了,而不是网络出错。
    (None, None) => Failed(SessionError::NoServiceAccept)
  }
}

///|
/// 请求 `ssh-userauth` 服务并等 SERVICE_ACCEPT
///
/// 返回 `(接受的服务名, 错误)`——成功时错误为 None。这样调用方既能拿到
/// 服务名(Loop #33 要报告它)又能区分失败原因,不必把错误编码进字符串。
///
/// 抽出来是因为 Loop #34 的认证流程要再走一遍同样的两步。把这段留在
/// `live_session` 里的结果是认证路径要么复制它、要么改回去——前者会漂移,
/// 后者会动到 Loop #33 已经验证过的字节数。
fn request_userauth_service(
  conn : @tcp.TcpConn,
  st : SessionState,
) -> (String?, SessionError?) {
  let payload = @sshwire.write_ssh_string(ascii(USERAUTH_SERVICE))
  if !send_packet(
      conn,
      st.counters,
      st.send,
      @sshwire.SSH_MSG_SERVICE_REQUEST,
      payload,
    ) {
    return (None, Some(SessionError::NoServiceAccept))
  }
  let mut tries = 0
  let mut answer : FixedArray[Byte]? = None
  while tries < 32 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return (None, Some(SessionError::NoServiceAccept))
      BadPacket(why) => return (None, Some(SessionError::BadPacket(why)))
      Packet(t, pl) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_SERVICE_ACCEPT {
          answer = Some(pl)
          break
        }
        if t == KX_MSG_KEX_FAILURE {
          return (None, Some(SessionError::UnexpectedService("kex_failure")))
        }
      }
    }
  }
  let accepted_body = match answer {
    None => return (None, Some(SessionError::NoServiceAccept))
    Some(v) => v
  }
  // body 是一个 string,内容应与我们请求的服务名逐字节相同
  let accepted = match read_field(accepted_body, 0) {
    None => return (None, Some(SessionError::UnexpectedService("malformed")))
    Some((name, _)) => bytes_to_string(name)
  }
  if accepted != USERAUTH_SERVICE {
    return (None, Some(SessionError::UnexpectedService(accepted)))
  }
  (Some(accepted), None)
}

///|
/// SSH_MSG_KEX_FAILURE (RFC 4253 section 7)
pub const KX_MSG_KEX_FAILURE : Byte = b'\x14'

// ---------------------------------------------------------------------------
// Loop #34: RFC 4252 publickey authentication
// ---------------------------------------------------------------------------

///|
/// 认证结果
pub(all) enum AuthResult {
  /// 服务端回了 SSH_MSG_USERAUTH_SUCCESS
  Authenticated(AuthReport)
  Failed(AuthError)
}

///|
pub(all) enum AuthError {
  /// 传输握手/服务协商阶段就没走通,认证还没开始
  Transport(SessionError)
  /// USERAUTH_REQUEST 没能构造出来(私钥越界,或 RFC 6979 的 k 退化)
  SignFailed
  /// 请求发出去了,但既没有 SUCCESS 也没有 FAILURE
  NoAuthReply
  /// 服务端明确拒绝了。带上它给的原因,以及我们**实际签名的那串字节**和
  /// 签名的十六进制。
  ///
  /// 之所以把这两样带出来:在服务端看来「公钥不在 authorized_keys 里」和
  /// 「签名算错了」是完全相同的 FAILURE,不留证据就只能靠猜。带出来之后,
  /// 第二实现可以拿同一段 session_id 重算一遍并指出到底差在哪。
  AuthRejected(String, String, String)
  /// 认证包读回来了,但它不是一个合法的包。
  ///
  /// 和 `NoAuthReply` 分开是因为后者只说明「对端没说话」,而 MAC 失败是
  /// 我们确实读到了东西、只是它不是我们以为的那段字节。
  BadPacket(String)
}

///|
pub(all) struct AuthReport {
  user : String
  method : String
  key_type : String
  /// 签名输入与签名的十六进制。带出来是为了让第二实现能逐字节复核:
  /// 认证失败在服务端看来只有一种(FAILURE),本地若不留证据就只能靠猜。
  signed_blob_hex : String
  sig_blob_hex : String
  request_hex : String
  session : SessionReport
}

///|
/// 握手 → 请求 ssh-userauth 服务 → publickey 认证,直到 SSH_MSG_USERAUTH_SUCCESS
///
/// 这是 Loop #34 的终点。走到 USERAUTH_SUCCESS 意味着服务端做了三件事:
/// 解开并校验了我们 Loop #33 的加密包、用 authorized_keys 里那把公钥验了我们
/// 的 RFC 6979 签名、然后接受了身份。三者里任何一环错,服务端都只会回一句
/// FAILURE ——所以这一步同时是对整条链路的端到端验证。
///
/// 只走 publickey:它是 SSH 里唯一不需要把**秘密**交给服务端的认证方式,
/// 对「浏览器零依赖」的客户端来说这是唯一说得通的选择。password 认证会把
/// 口令的存储、清洗与比较拖进客户端,而 Loop #33 刚把 userauth 服务协商好,
/// 这里没有任何理由去碰它。
pub fn live_auth(
  conn : @tcp.TcpConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
) -> AuthResult {
  let (res, _st) = live_auth_with_state(conn, x, user, d)
  res
}

///|
/// `live_auth`,但把 `SessionState` 一并带出来。
///
/// Loop #35 要在认证通过之后继续开通道跑远端命令,而通道层的每个包都得用
/// 与握手同一套 `SendCtx` / `RecvCtx` / 计数器(seqnr 和字节计数都活在它们里)。
/// 让 `live_auth` 多返回一个私有结构体不算破坏 API,但它本来是给 CLI 打印用的,
/// 所以这里保留原样的同时另开一个内部入口——两条路径共用同一份认证代码,
/// Loop #34 修好的签名逻辑不会被分叉出去。
fn live_auth_with_state(
  conn : @tcp.TcpConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
) -> (AuthResult, SessionState?) {
  let (res, state) = handshake_to_session(conn, x)
  let handshake = match res {
    Established(rep) => rep
    Failed(e) =>
      return (Failed(AuthError::Transport(SessionError::HandshakeFailed(e))), None)
  }
  let st = match state {
    None => return (Failed(AuthError::Transport(SessionError::NoServiceAccept)), None)
    Some(v) => v
  }
  let (accepted_opt, err) = request_userauth_service(conn, st)
  match err {
    Some(e) => return (Failed(AuthError::Transport(e)), None)
    None => ()
  }
  let accepted = match accepted_opt {
    None => return (Failed(AuthError::Transport(SessionError::NoServiceAccept)), None)
    Some(a) => a
  }
  let curve = @ecdsa.Curve::p256()
  let (pk_blob, sig_blob, payload) = match
    @userauth.userauth_publickey_signed_request(
      curve,
      d,
      st.session_id,
      user,
      @userauth.AUTH_SERVICE_CONNECTION,
    ) {
    None => return (Failed(AuthError::SignFailed), None)
    Some(v) => v
  }
  let to_sign = @userauth.userauth_signed_blob(
    st.session_id,
    user,
    @userauth.AUTH_SERVICE_CONNECTION,
    curve.ssh_key_type(),
    pk_blob,
  )
  if !send_packet(
      conn,
      st.counters,
      st.send,
      @sshwire.SSH_MSG_USERAUTH_REQUEST,
      payload,
    ) {
    return (Failed(AuthError::NoAuthReply), None)
  }
  let mut tries = 0
  let mut verdict : (Byte, FixedArray[Byte])? = None
  while tries < 32 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return (Failed(AuthError::NoAuthReply), None)
      BadPacket(why) => return (Failed(AuthError::BadPacket(why)), None)
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
    None => return (Failed(AuthError::NoAuthReply), None)
    Some(v) => v
  }
  if msg_type == @sshwire.SSH_MSG_USERAUTH_FAILURE {
    return (Failed(
      AuthError::AuthRejected(
        userauth_failure_reason(body),
        @ecdsa.bytes_to_hex(to_sign),
        @ecdsa.bytes_to_hex(sig_blob),
      ),
    ), None)
  }
  (
    Authenticated({
      user,
      method: @userauth.AUTH_METHOD_PUBLICKEY,
      key_type: curve.ssh_key_type(),
      signed_blob_hex: @ecdsa.bytes_to_hex(to_sign),
      sig_blob_hex: @ecdsa.bytes_to_hex(sig_blob),
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
/// 一次远端命令执行的结果
pub(all) enum ExecOutcome {
  /// 通道跑完了:stdout / stderr / exit-status 都在
  Done(ExecResult)
  /// 认证没过,命令根本没发出去
  AuthFailed(AuthError)
  /// 通道层出错(见 `ExecError`)
  ChannelFailed(ExecError)
}

///|
/// `live_exec` 失败的原因
///
/// 刻意和「远端命令返回非零」分开:后者是**正常结果**,走
/// `ExecResult::exit_status`。
pub(all) enum ExecError {
  /// 认证通过了,但 `SessionState` 没带出来(内部不可能,留作兜底)
  NoSessionState
  /// 对端发来的包在通道状态下解释不了,或 channel 号不认识
  Malformed(String)
  /// 通道没能打开
  OpenFailed(Int, String)
  /// 对端拒绝了 exec
  ExecRejected
  ///|
  /// 对端拒绝了 subsystem 请求——通常就是「没有这个子系统」。
  ///
  /// 单列而非复用 `ExecRejected`:subsystem 的 `want_reply` 是 TRUE,所以这个
  /// FAILURE 是**服务端明确告诉你子系统名字不对**的唯一信号
  /// (session.c:1945-1948)。把它报成「命令被拒」会把一个配置拼写错误说成
  /// 远端拒绝执行,方向完全反了。
  SubsystemRejected
  /// 包发不出去(seqnr 回绕)
  SendFailed
  /// 读包时 MAC 不匹配
  BadPacket(String)
  /// 对端把连接关了,但通道还没收尾
  Closed
  /// 收包次数超过上限还没结束
  TooManyPackets
  ///|
  /// 还有待发的 stdin,但对端的发送窗口是 0。
  ///
  /// 在**收包循环之外**的一次性投递里这是死结:要等 WINDOW_ADJUST 才能继续,
  /// 而 WINDOW_ADJUST 只会在收包时到达。所以只有「一口气把 stdin 发完」那种
  /// 用法(交互式敲一行命令)会撞上它——那时没有后续收包,窗口不会自己回来。
  StdinStalled
}

///|
/// 一条要交给远端会话的环境变量
///
/// 放在 `sshclient` 而不是 `channel`:两条传输层(原生 TCP / 浏览器 WebSocket)
/// 要的是同一个类型,在这里定义就只有一份。
pub(all) struct EnvVar {
  name : String
  value : String
}

///|
/// 远端命令的结果,形状刻意和 `ssh host cmd` 的退出码对齐
pub(all) struct ExecResult {
  stdout : FixedArray[Byte]
  stderr : FixedArray[Byte]
  exit_status : Int
  /// 对端给的通道号
  remote_id : Int
  /// 我们一共补了几次窗口
  adjusts_sent : Int
  ///| 作为 stdin 发出的字节数
  stdin_sent : Int
  ///| 发出的 CHANNEL_DATA 包数——窗口夹取的直接证据
  stdin_packets : Int
  ///| CHANNEL_EOF 有没有发出去(等价于 `ssh -n` 的那个 -n)
  eof_sent : Bool
  ///| 发出的 env 请求条数
  env_sent : Int
  /// 认证 + 通道总共发出的字节数
  sent_bytes : Int
  recv_bytes : Int
}

///|
/// 在真服务器上跑一条远端命令,并读回 stdout / stderr / exit-status。
///
/// 协议本身完全交给 `src/channel` 的 `chan_step`:这里只做三件事——把认证
/// 之后的 `SessionState` 接上、把状态机吐出来的 `ChanAction` 发出去、再把
/// 收到的包喂回去。协议语义没有第二份实现,所以原生路径和浏览器路径不可能
/// 在协议层分叉。
///
/// 循环有三个出口,都在这里显式写出来而不是靠 `break` 隐式跳出:
/// 对端发了 CLOSE 且我们也回了 CLOSE(`finished`)、连接关闭、或者包数超限。
/// 超限那条不是摆设:状态机里任何一处「回包发不出去」如果没检查,就会变成
/// 一边等 CHANNEL_CLOSE 一边永远收不到的死等。
pub fn live_exec(
  conn : @tcp.TcpConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  command : String,
) -> ExecOutcome {
  live_exec_io(conn, x, user, d, command, empty_stdin(), [])
}

///|
/// 带 stdin 和环境变量的 `exec`——`ssh host cmd < input` 和 `SendEnv` 的那一条路。
///
/// 时序(每一处都有 C 上的依据):
///
///   1. CHANNEL_OPEN "session"                      (我们发)
///   2. <- CHANNEL_OPEN_CONFIRMATION
///   3. CHANNEL_REQUEST "env" xN  want_reply=FALSE  (我们发,**必须在 4 之前**)
///   4. CHANNEL_REQUEST "exec" want_reply=TRUE      (我们发)
///   5. CHANNEL_DATA ...  按远端窗口夹取,反复       (我们发)
///   6. CHANNEL_EOF                                (我们发,缓冲排空之后)
///   7. <- DATA / EXTENDED_DATA / exit-status / EOF / CLOSE
///
/// 第 3 步的位置不是随意的:服务端只在会话还处于 LARVAL 状态时处理 env
/// (session.c:2175-2192),exec 之后就再也不看了,而 want_reply=FALSE 意味着
/// 发晚了**没有任何**报错——环境变量就是没设上,连日志都不会有。
///
/// `stdin_data` 可以是空的:那样发出去的只有一个 CHANNEL_EOF,等价于
/// `ssh -n host cmd`。EOF 一定要发,否则 `cmd` 读到的是永不结束的 stdin。
pub fn live_exec_io(
  conn : @tcp.TcpConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  command : String,
  stdin_data : FixedArray[Byte],
  envs : Array[EnvVar],
) -> ExecOutcome {
  let (auth, state_opt) = live_auth_with_state(conn, x, user, d)
  match auth {
    Authenticated(_) => ()
    Failed(e) => return ExecOutcome::AuthFailed(e)
  }
  let st = match state_opt {
    None => return ExecOutcome::ChannelFailed(ExecError::NoSessionState)
    Some(v) => v
  }
  let (chan0, failure) = exec_drive(conn, st, command, stdin_data, envs)
  match failure {
    Some(e) => ExecOutcome::ChannelFailed(e)
    None => {
      let rep = chan0.report()
      ExecOutcome::Done({
        stdout: rep.stdout,
        stderr: rep.stderr,
        exit_status: rep.exit_status,
        remote_id: rep.remote_id,
        adjusts_sent: rep.adjusts_sent,
        stdin_sent: rep.stdin_sent,
        stdin_packets: rep.stdin_packets,
        eof_sent: rep.eof_sent,
        env_sent: envs.length(),
        sent_bytes: st.counters.sent,
        recv_bytes: st.counters.recv,
      })
    }
  }
}

fn empty_stdin() -> FixedArray[Byte] {
  FixedArray::make(0, b'\x00')
}

///|
/// 造一段确定性的 stdin,给流控测试用。
///
/// **不使用随机数。** 理由不是「随机数不好」,而是两条互相独立的检查都要求这段
/// 字节在四条 target 上完全相同:一是 KAT 要断言我们**发出去的分包边界**和向量
/// 一致,二是验证脚本要比「原生与 Worker 发出的字节数与摘要」相等。任何依赖平台
/// 数值语义(浮点运算、整数宽度、`Int` 的溢出行为)的伪随机,都会让这两条断言变成
/// 在测平台而不是在测协议。取模一个固定 ASCII 串只用到长度和对正数取模,在任何
/// target 上是同一个意思。
///
/// 同时它是**位置敏感**的:字节由下标唯一决定,截断、乱序、错位都会让远端算出的
/// 字节数或 sha256 变掉——一个全 0x41 的缓冲做不到这一点。
///
/// 放在 `src/sshclient` 是因为原生 CLI 和浏览器 Worker 都要用同一份。
pub fn ssh_stdin_pattern(n : Int) -> FixedArray[Byte] {
  let src = sh_ascii("loop37-stdin-block-")
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = src[i % src.length()]
  }
  out
}

///|
/// 通道的收发循环。返回 `(结束时的状态, 失败原因)`。
///
/// 失败为 None 时状态是完整的,可以照常出报告。认证已经由 `live_exec` 处理,
/// 这里只管通道。
///
/// 三个出口都显式写出来:对端发了 CLOSE 且我们也回了 CLOSE(`finished`)、
/// 连接关闭、或者包数超限。超限那条不是摆设——任何一处「回包发不出去」如果
/// 没检查,就会变成一边等 CHANNEL_CLOSE 一边永远收不到的死等。
///
/// 循环体是「先把窗口允许的 stdin 发完 → 缓冲空了才发 EOF → 再收一个包」。
/// 顺序不能换:先发 EOF 再补数据等于告诉对端输入流到此为止,后面那些数据它
/// 不会读,而远端命令**不会报错**,只是安静地拿到一份截断的输入——比断链更难查。
fn exec_drive(
  conn : @tcp.TcpConn,
  st0 : SessionState,
  command : String,
  stdin_data : FixedArray[Byte],
  envs : Array[EnvVar],
) -> (@channel.ChanState, ExecError?) {
  let mut st = st0
  let open = @channel.ChanState::new(@channel.LOCAL_CHANNEL).open_action()
  match send_action(conn, st, open) {
    None => return (
      @channel.ChanState::new(@channel.LOCAL_CHANNEL),
      Some(ExecError::SendFailed),
    )
    Some(s) => st = s
  }
  // 第一步只有一个包:CHANNEL_OPEN_CONFIRMATION 或 CHANNEL_OPEN_FAILURE。
  let mut first = 0
  let mut chan = @channel.ChanState::new(@channel.LOCAL_CHANNEL)
  while first < 8 {
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return (chan, Some(ExecError::Closed))
      BadPacket(why) => return (chan, Some(ExecError::BadPacket(why)))
      Packet(t, pl) => {
        let (chan2, _actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(chan_err) => return (chan, Some(chan_error(chan_err)))
        }
        // 确认包到了才收工,其余的(理论上不会有)丢掉继续等。
        if t == 0x5b || t == 0x5c {
          first = 8
        } else {
          first = first + 1
        }
      }
    }
  }
  if !chan.open_done {
    return (chan, Some(ExecError::Malformed("no_open_confirmation")))
  }
  // env 必须赶在 exec 之前(见 live_exec_io 的时序说明)。
  for i = 0; i < envs.length(); i = i + 1 {
    let a = match chan.env_action(envs[i].name, envs[i].value) {
      None => return (chan, Some(ExecError::Malformed("env_before_open")))
      Some(x) => x
    }
    match send_action(conn, st, a) {
      None => return (chan, Some(ExecError::SendFailed))
      Some(s) => st = s
    }
  }
  // exec 必须在 OPEN_CONFIRMATION 之后发:recipient 用的是对端给的 id。
  let exec_action = match chan.exec_action(command) {
    None => return (chan, Some(ExecError::Malformed("exec_before_open")))
    Some(a) => a
  }
  match send_action(conn, st, exec_action) {
    None => return (chan, Some(ExecError::SendFailed))
    Some(s) => st = s
  }
  let mut pending = stdin_data
  let mut eof_pending = true
  let mut packets = 0
  let cap = 65536
  while !chan.finished() {
    if packets >= cap {
      return (chan, Some(ExecError::TooManyPackets))
    }
    // 1) 按远端窗口发 stdin。每发一包至少消费 1 字节,所以这一段必然收敛;
    //    夹到 0 时 `stdin_take` 返回 None,退出内层循环去收包——窗口只会由
    //    CHANNEL_WINDOW_ADJUST 补回来,那是收包路径的事。
    while pending.length() > 0 {
      let (c1, action, rest) = chan.stdin_take(pending)
      chan = c1
      match action {
        None => break
        Some(a) => {
          match send_action(conn, st, a) {
            None => return (chan, Some(ExecError::SendFailed))
            Some(s) => st = s
          }
          pending = rest
        }
      }
    }
    // 2) 缓冲排空才发 EOF。eof_pending 这个标志是多余的(`eof_action` 自己
    //    记得),留着是为了把「本轮没排空」和「已经发过了」分开看清楚。
    if eof_pending && pending.length() == 0 {
      let (c1, a) = chan.eof_action()
      chan = c1
      match a {
        None => ()
        Some(x) => {
          match send_action(conn, st, x) {
            None => return (chan, Some(ExecError::SendFailed))
            Some(s) => st = s
          }
        }
      }
      eof_pending = false
    }
    // 3) 收一个包。
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return (chan, Some(ExecError::Closed))
      BadPacket(why) => return (chan, Some(ExecError::BadPacket(why)))
      Packet(t, pl) => {
        packets = packets + 1
        let (chan2, actions, err) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match err {
          None => ()
          Some(chan_err) => return (chan, Some(chan_error(chan_err)))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None => return (chan, Some(ExecError::SendFailed))
            Some(s) => st = s
          }
        }
      }
    }
  }
  (chan, None)
}

///| 发一个 `ChanAction`,并把更新后的计数器带回来
fn send_action(
  conn : @tcp.TcpConn,
  st : SessionState,
  a : @channel.ChanAction,
) -> SessionState? {
  match a {
    Send(t, payload) => {
      let ok = send_packet(conn, st.counters, st.send, t, payload)
      if ok {
        Some(st)
      } else {
        None
      }
    }
  }
}

fn chan_error(e : @channel.ChanError) -> ExecError {
  match e {
    OpenFailed(r, d) => ExecError::OpenFailed(r, d)
    ExecRejected => ExecError::ExecRejected
    SubsystemRejected => ExecError::SubsystemRejected
    Malformed(m) => ExecError::Malformed(m)
  }
}

// ---------------------------------------------------------------------------
// Interactive session (Loop #36)
// ---------------------------------------------------------------------------

///| 交互式会话的结果
pub(all) enum ShellOutcome {
  Done(ShellResult)
  AuthFailed(AuthError)
  ChannelFailed(ExecError)
}

///|
/// 一次交互式会话的结果
///
/// `pty_granted` 单列出来:服务端可以合法地拒绝 pty(`PermitTTY no`、或用
/// `-T` 连进来),真实客户端的做法是退回无 pty 继续(clientloop.c:2750 把
/// `client_tty` 清零)。把这个布尔藏进错误里的话,「没有 pty 但能跑」和
/// 「彻底失败」会长得一样。
pub(all) struct ShellResult {
  stdout : FixedArray[Byte]
  stderr : FixedArray[Byte]
  exit_status : Int
  exit_signal : (String, Bool)?
  exit_signal_message : String
  pty_granted : Bool
  ///| 请求的窗口尺寸;`window-change` 是不是成功发出去了
  cols : Int
  rows : Int
  resize_sent : Bool
  adjusts_sent : Int
  sent_bytes : Int
  recv_bytes : Int
}

///|
/// 在真服务器上开一个交互式 shell,敲一条命令,收输出,再退出。
///
/// 时序是硬编码的,因为协议本身就是时序:
///
///   1. CHANNEL_OPEN                     (我们发)
///   2. <- CHANNEL_OPEN_CONFIRMATION
///   3. CHANNEL_REQUEST "pty-req" TRUE   (我们发)
///   4. <- CHANNEL_SUCCESS / FAILURE     <- 拒了就退回无 pty,不致命
///   5. CHANNEL_REQUEST "shell"  TRUE    (我们发)
///   6. <- CHANNEL_SUCCESS
///   7. CHANNEL_REQUEST "window-change"  (我们发,want_reply=FALSE,不等回复)
///   8. CHANNEL_DATA = 命令 + CRLF       (我们发,这是远端的 stdin)
///   9. <- DATA ... 直到看到命令回显
///  10. CHANNEL_DATA = "exit" + CRLF
///  11. <- ... 直到 CHANNEL_CLOSE
///
/// 第 6 步要循环而不是只收一个包:pty 的横幅往往和 CHANNEL_SUCCESS 同批甚至
/// 更早到达,只收一个包会把横幅当成「shell 已被接受」然后丢掉。
pub fn live_shell(
  conn : @tcp.TcpConn,
  x : @bigint.BigNat,
  user : String,
  d : @bigint.BigNat,
  command : String,
  term : String,
  cols : Int,
  rows : Int,
  resize_to : (Int, Int)?,
) -> ShellOutcome {
  let (auth, state_opt) = live_auth_with_state(conn, x, user, d)
  match auth {
    Authenticated(_) => ()
    Failed(e) => return ShellOutcome::AuthFailed(e)
  }
  let st = match state_opt {
    None => return ShellOutcome::ChannelFailed(ExecError::NoSessionState)
    Some(v) => v
  }
  let (chan0, failure, pty_granted, resize_sent) = shell_drive(
    conn,
    st,
    command,
    term,
    cols,
    rows,
    resize_to,
  )
  match failure {
    Some(e) => ShellOutcome::ChannelFailed(e)
    None => {
      let rep = chan0.shell_report()
      ShellOutcome::Done({
        stdout: rep.stdout,
        stderr: rep.stderr,
        exit_status: rep.exit_status,
        exit_signal: rep.exit_signal,
        exit_signal_message: rep.exit_signal_message,
        pty_granted,
        cols,
        rows,
        resize_sent,
        adjusts_sent: rep.adjusts_sent,
        sent_bytes: st.counters.sent,
        recv_bytes: st.counters.recv,
      })
    }
  }
}

///|
/// 收包直到通道被打开(OPEN_CONFIRMATION 或 OPEN_FAILURE)。
///
/// 单独写一个而不是复用 `shell_confirm`:那一个等的是 CHANNEL_SUCCESS /
/// CHANNEL_FAILURE,而开通道这一步来的是 CHANNEL_OPEN_CONFIRMATION ——
/// 拿错条件的表现不是报错,是**死等**:服务端已经把确认发完了,之后再没有
/// 任何数据,而读包是阻塞的。
fn shell_wait_open(
  conn : @tcp.TcpConn,
  st : SessionState,
  chan : @channel.ChanState,
  cap : Int,
) -> (SessionState, @channel.ChanState, ExecError?) {
  let mut s = st
  let mut c = chan
  let mut n = 0
  while n < cap {
    match recv_packet(conn, s.counters, s.recv) {
      Closed => return (s, c, Some(ExecError::Closed))
      BadPacket(why) => return (s, c, Some(ExecError::BadPacket(why)))
      Packet(t, pl) => {
        n = n + 1
        let (c1, actions, err) = @channel.chan_step(c, t, pl)
        c = c1
        match err {
          None => ()
          Some(chan_err) => return (s, c, Some(chan_error(chan_err)))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, s, actions[i]) {
            None => return (s, c, Some(ExecError::SendFailed))
            Some(x) => s = x
          }
        }
        if t == 0x5b || t == 0x5c {
          return (s, c, None)
        }
      }
    }
  }
  (s, c, Some(ExecError::TooManyPackets))
}

///|
/// 收包直到看到 CHANNEL_SUCCESS / CHANNEL_FAILURE,顺带把中间的 DATA 喂进状态机。
///
/// 交互式流程里这两个包**不是**致命的:pty-req 被拒只意味着没有 tty,shell
/// 仍然开得起来(`chan_step` 在 `interactive` 模式下只记数不报错)。
fn shell_confirm(
  conn : @tcp.TcpConn,
  st : SessionState,
  chan : @channel.ChanState,
  cap : Int,
) -> (SessionState, @channel.ChanState, ExecError?, Bool) {
  let mut s = st
  let mut c = chan
  let mut n = 0
  while n < cap {
    match recv_packet(conn, s.counters, s.recv) {
      Closed => return (s, c, Some(ExecError::Closed), false)
      BadPacket(why) => return (s, c, Some(ExecError::BadPacket(why)), false)
      Packet(t, pl) => {
        n = n + 1
        let (c1, actions, err) = @channel.chan_step(c, t, pl)
        c = c1
        match err {
          None => ()
          Some(chan_err) => return (s, c, Some(chan_error(chan_err)), false)
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, s, actions[i]) {
            None => return (s, c, Some(ExecError::SendFailed), false)
            Some(x) => s = x
          }
        }
        if t == 0x63 {
          return (s, c, None, true)
        }
        if t == 0x64 {
          // CHANNEL_FAILURE:被拒了,但 shell 还能继续。
          return (s, c, None, false)
        }
      }
    }
  }
  (s, c, Some(ExecError::TooManyPackets), false)
}

///| 收包直到字节流里出现 `needle`,或者包数超限
fn shell_read_until(
  conn : @tcp.TcpConn,
  st : SessionState,
  chan : @channel.ChanState,
  seen : FixedArray[Byte],
  needle : FixedArray[Byte],
  cap : Int,
) -> (SessionState, @channel.ChanState, FixedArray[Byte], ExecError?) {
  let mut s = st
  let mut c = chan
  let mut buf = seen
  // chan_step 从不丢弃已收的块,所以 `c.stdout` 每次都是**到目前为止的全文**。
  // 直接把它整个接上会指数增长(第 n 轮接上 n 倍),几十个包就撑爆内存。
  let mut have = c.stdout_len
  let mut n = 0
  while n < cap {
    match recv_packet(conn, s.counters, s.recv) {
      Closed => return (s, c, buf, Some(ExecError::Closed))
      BadPacket(why) => return (s, c, buf, Some(ExecError::BadPacket(why)))
      Packet(t, pl) => {
        n = n + 1
        let (c1, actions, err) = @channel.chan_step(c, t, pl)
        let grew = c1.stdout_len - have
        have = c1.stdout_len
        c = c1
        match err {
          None => ()
          Some(chan_err) => return (s, c, buf, Some(chan_error(chan_err)))
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, s, actions[i]) {
            None => return (s, c, buf, Some(ExecError::SendFailed))
            Some(x) => s = x
          }
        }
        // 只接新增的那一段:它是 `c.stdout` 末尾 `grew` 个字节。
        buf = @channel.ch_cat(buf, tail_of(c.stdout, grew))
        if sh_contains_bytes(buf, needle) {
          return (s, c, buf, None)
        }
        if c.finished() {
          return (s, c, buf, None)
        }
      }
    }
  }
  (s, c, buf, Some(ExecError::TooManyPackets))
}

///| 一个块序列里最后 `n` 个字节
fn tail_of(
  chunks : Array[FixedArray[Byte]],
  n : Int,
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut need = n
  let mut i = chunks.length() - 1
  while i >= 0 && need > 0 {
    let ch = chunks[i]
    if ch.length() <= need {
      for j = 0; j < ch.length(); j = j + 1 {
        out[j] = ch[j]
      }
      need = need - ch.length()
    } else {
      let skip = ch.length() - need
      for j = 0; j < need; j = j + 1 {
        out[j] = ch[skip + j]
      }
      need = 0
    }
    i = i - 1
  }
  out
}

fn shell_drive(
  conn : @tcp.TcpConn,
  st0 : SessionState,
  command : String,
  term : String,
  cols : Int,
  rows : Int,
  resize_to : (Int, Int)?,
) -> (@channel.ChanState, ExecError?, Bool, Bool) {
  let mut st = st0
  let mut chan = @channel.ChanState::new_interactive(
    @channel.LOCAL_CHANNEL,
  )
  let open = chan.open_action()
  match send_action(conn, st, open) {
    None => return (chan, Some(ExecError::SendFailed), false, false)
    Some(x) => st = x
  }
  // 1) CHANNEL_OPEN_CONFIRMATION
  {
    let (s, c, err) = shell_wait_open(conn, st, chan, 8)
    st = s
    chan = c
    match err {
      Some(e) => return (chan, Some(e), false, false)
      None => ()
    }
    if !chan.open_done {
      return (
        chan,
        Some(ExecError::Malformed("no_open_confirmation")),
        false,
        false,
      )
    }
  }
  // 2) pty-req。被拒不算致命。
  let pty = match chan.pty_req_action(
    term,
    cols,
    rows,
    0,
    0,
    @channel.tty_modes_bytes(38400),
  ) {
    None => return (chan, Some(ExecError::Malformed("pty_before_open")), false, false)
    Some(a) => a
  }
  match send_action(conn, st, pty) {
    None => return (chan, Some(ExecError::SendFailed), false, false)
    Some(x) => st = x
  }
  let pty_granted = {
    let (s, c, err, ok) = shell_confirm(conn, st, chan, 64)
    st = s
    chan = c
    match err {
      Some(e) => return (chan, Some(e), false, false)
      None => ok
    }
  }
  // 3) shell
  let shell = match chan.shell_action() {
    None => return (chan, Some(ExecError::Malformed("shell_before_open")), false, false)
    Some(a) => a
  }
  match send_action(conn, st, shell) {
    None => return (chan, Some(ExecError::SendFailed), false, false)
    Some(x) => st = x
  }
  {
    let (s, c, err, _ok) = shell_confirm(conn, st, chan, 64)
    st = s
    chan = c
    match err {
      Some(e) => return (chan, Some(e), pty_granted, false)
      None => ()
    }
  }
  // 4) window-change。want_reply=FALSE,服务端不回任何东西(session.c:1843),
  //    所以发完就往下走——等一个 CHANNEL_SUCCESS 会永远等下去。
  let mut resize_sent = false
  match resize_to {
    Some((c2, r2)) => {
      let a = chan.window_change_action(c2, r2, 0, 0)
      match send_action(conn, st, a) {
        None => return (chan, Some(ExecError::SendFailed), pty_granted, false)
        Some(x) => {
          st = x
          resize_sent = true
        }
      }
    }
    None => ()
  }
  // 5) 命令本身。CRLF 是因为远端是 Windows shell;LF 在 conhost 上不提交。
  let mut line = sh_ascii(command)
  line = @channel.ch_cat(line, FixedArray::from_array([b'\r', b'\n']))
  {
    let (c1, s1, e1) = send_stdin_all(conn, st, chan, line)
    st = s1
    chan = c1
    match e1 {
      Some(e) => return (chan, Some(e), pty_granted, resize_sent)
      None => ()
    }
  }
  // 6) 读到命令回显出现
  let marker = sh_ascii(command)
  let (s, c, _buf, err) = shell_read_until(
    conn,
    st,
    chan,
    sh_empty_bytes(),
    marker,
    4096,
  )
  st = s
  chan = c
  match err {
    Some(e) => return (chan, Some(e), pty_granted, resize_sent)
    None => ()
  }
  // 7) exit,收到 CLOSE 为止
  let quit = FixedArray::from_array([b'e', b'x', b'i', b't', b'\r', b'\n'])
  {
    let (c1, s1, e1) = send_stdin_all(conn, st, chan, quit)
    st = s1
    chan = c1
    match e1 {
      Some(e) => return (chan, Some(e), pty_granted, resize_sent)
      None => ()
    }
  }
  let mut n = 0
  while !chan.finished() {
    if n >= 4096 {
      return (chan, Some(ExecError::TooManyPackets), pty_granted, resize_sent)
    }
    match recv_packet(conn, st.counters, st.recv) {
      Closed => return (chan, Some(ExecError::Closed), pty_granted, resize_sent)
      BadPacket(why) =>
        return (chan, Some(ExecError::BadPacket(why)), pty_granted, resize_sent)
      Packet(t, pl) => {
        n = n + 1
        let (chan2, actions, e) = @channel.chan_step(chan, t, pl)
        chan = chan2
        match e {
          None => ()
          Some(chan_err) =>
            return (chan, Some(chan_error(chan_err)), pty_granted, resize_sent)
        }
        for i = 0; i < actions.length(); i = i + 1 {
          match send_action(conn, st, actions[i]) {
            None =>
              return (chan, Some(ExecError::SendFailed), pty_granted, resize_sent)
            Some(x) => st = x
          }
        }
      }
    }
  }
  (chan, None, pty_granted, resize_sent)
}

///|
/// 把一整段待发数据按远端窗口夹取成若干个 CHANNEL_DATA,一次发完。
///
/// 用于**没有后续收包循环**的场景(交互式敲一行命令)。窗口耗尽时报
/// `StdinStalled` 而不是等:这里等不到东西——WINDOW_ADJUST 只在收包时到达,
/// 而这个函数在收包循环之外。
///
/// 和 exec 路径的差别是有意为之:exec 的 stdin 要流式喂(可以边收包边续发),
/// shell 的一行命令必须整段到达才能被 conhost 提交,半截的行根本不回车。
fn send_stdin_all(
  conn : @tcp.TcpConn,
  st : SessionState,
  chan : @channel.ChanState,
  data : FixedArray[Byte],
) -> (@channel.ChanState, SessionState, ExecError?) {
  let mut c = chan
  let mut s = st
  let mut pending = data
  while pending.length() > 0 {
    let (c1, action, rest) = c.stdin_take(pending)
    c = c1
    match action {
      None => return (c, s, Some(ExecError::StdinStalled))
      Some(a) => {
        match send_action(conn, s, a) {
          None => return (c, s, Some(ExecError::SendFailed))
          Some(x) => {
            s = x
            pending = rest
          }
        }
      }
    }
  }
  (c, s, None)
}

///|
/// ASCII -> 字节。`client.mbt` 里已有同名私有函数,这里换个名字免得重复定义。
///
/// `pub` 是因为两个 CLI 都要用它来确认「命令确实被 shell 回显了」——
/// exit-status 0 只说明进程正常退出,回显才说明它真的收到了命令。
pub fn sh_ascii(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  out
}

fn sh_empty_bytes() -> FixedArray[Byte] {
  FixedArray::make(0, b'\x00')
}

///| 子串查找(朴素)。用于「命令回显出现了没有」,不追求快。
///
/// `pub` 的理由同上:CLI 要用它做同一个判断,两边各写一份就等于有两处可能
/// 对「回显」理解不一致的地方。
pub fn sh_contains_bytes(hay : FixedArray[Byte], needle : FixedArray[Byte]) -> Bool {
  if needle.length() == 0 || needle.length() > hay.length() {
    return false
  }
  for i = 0; i <= hay.length() - needle.length(); i = i + 1 {
    let mut ok = true
    for j = 0; j < needle.length(); j = j + 1 {
      if hay[i + j].to_int() != needle[j].to_int() {
        ok = false
        break
      }
    }
    if ok {
      return true
    }
  }
  false
}

///|
/// USERAUTH_FAILURE 的可读原因(RFC 4252 §5.1)
///
/// body 是一串 `name-list` + boolean + `name-list` + `name-list`,其中第一个
/// 是服务端的说明文字。取不出来就返回占位串——宁可说"不知道"也不要编一个。
/// 从 USERAUTH_FAILURE 的 body 里取出服务端给的 method name-list。
///
/// 浏览器路径(`src/wtlive`)要打印同一条信息,所以是 `pub`。
pub fn userauth_failure_reason(body : FixedArray[Byte]) -> String {
  match read_field(body, 0) {
    None => "unknown"
    Some((name, _)) => bytes_to_string(name)
  }
}
