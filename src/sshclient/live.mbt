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
  BadPacket
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
fn hex_bytes_head(b : FixedArray[Byte], n : Int) -> String {
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
/// exactly this, so a mismatch is our bug rather than a negotiation race.
///
/// Note we deliberately do **not** advertise `kex-strict-c-v00@openssh.com`.
/// OpenSSH turns strict KEX on only when the peer advertises it (kex.c:963-970),
/// so with this proposal `kex_strict` is false and the sequence number runs
/// straight through NEWKEYS instead of resetting (packet.c:1376-1379).
/// Advertising it would reset seqnr to 0 and change the handshake transcript,
/// which would invalidate the Loop #31/#32 byte-count assertions. The contexts
/// below handle either outcome, so this is a transcript-stability choice, not a
/// correctness one.
pub fn live_proposal() -> @kexflow.Proposal {
  {
    kex_algs: "diffie-hellman-group14-sha256",
    hostkey_algs: "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384",
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
) -> (Byte, FixedArray[Byte])? {
  let hdr = match conn.read_exact(4) {
    None => return None
    Some(h) => h
  }
  let rest = match r.wire_len_from_header(hdr) {
    None => return None
    Some(v) => v
  }
  if rest < 0 || rest > 1048576 {
    return None
  }
  let body = if rest == 0 {
    FixedArray::make(0, b'\x00')
  } else {
    match conn.read_exact(rest) {
      None => return None
      Some(b) => b
    }
  }
  counters.recv = counters.recv + 4 + rest
  match r.recv(cat2(hdr, body)).event {
    @bpacket.Packet(_, t, payload) => Some((t, payload))
    _ => None
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
  /// 'A'..'F' 的摘要,便于诊断时与独立实现对拍(不打印原始密钥)
  key_head : String
  session_id_head : String
}

///|
/// 前 n 个字节
///
/// 六个密钥都按 `we_need` 派生(aes128-ctr + hmac-sha2-256 下是 32),但交给
/// cipher 的只有 key_len / iv_len 字节——OpenSSH 在 ssh_set_newkeys 里传的是
/// `cipher_new(..., key, cipher_keylen(c), iv, cipher_ivlen(c), ...)`,
/// 也就是各取前缀。直接把 32 字节塞给 aes128-ctr 会在 cipher 初始化时就长度不符。
fn head_bytes(b : FixedArray[Byte], n : Int) -> FixedArray[Byte] {
  let m = if b.length() < n { b.length() } else { n }
  let out : FixedArray[Byte] = FixedArray::make(m, b'\x00')
  for i = 0; i < m; i = i + 1 {
    out[i] = b[i]
  }
  out
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
      None => return (Failed(NoPeerKexinit), None)
      Some((t, payload)) => {
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
      None => return (Failed(NoEcdhReply), None)
      Some((t, payload)) => {
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
    _ => return (Failed(HostkeyInvalid), None)
  }
  if ktype != neg.hostkey_alg {
    return (Failed(HostkeyInvalid), None)
  }
  match @hostkey.HostKey::verify(key, h, sig_blob) {
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
      None => return (Failed(NoNewkeys), None)
      Some((t, _)) => {
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
      key_head: hex_bytes_head(keys.enc_key_ctos(), 8) +
      "/" +
      hex_bytes_head(keys.mac_key_ctos(), 8),
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
}

///|
/// What the encrypted phase observed.
pub(all) struct SessionReport {
  handshake : LiveReport
  service_name : String
  accepted_service : String
  we_need : Int
  key_head : String
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
        key_head: st.key_head,
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
      None => return (None, Some(SessionError::NoServiceAccept))
      Some((t, pl)) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_SERVICE_ACCEPT {
          answer = Some(pl)
          break
        }
        if t == KX_MSG_KEX_FAILURE {
          return (
            None,
            Some(SessionError::UnexpectedService("kex_failure")),
          )
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
  let (res, state) = handshake_to_session(conn, x)
  let handshake = match res {
    Established(rep) => rep
    Failed(e) => return Failed(AuthError::Transport(SessionError::HandshakeFailed(e)))
  }
  let st = match state {
    None => return Failed(AuthError::Transport(SessionError::NoServiceAccept))
    Some(v) => v
  }
  let (accepted_opt, err) = request_userauth_service(conn, st)
  match err {
    Some(e) => return Failed(AuthError::Transport(e))
    None => ()
  }
  let accepted = match accepted_opt {
    None => return Failed(AuthError::Transport(SessionError::NoServiceAccept))
    Some(a) => a
  }
  let curve = @ecdsa.Curve::p256()
  let (pk_blob, sig_blob, payload) = match @userauth.userauth_publickey_signed_request(
      curve,
      d,
      st.session_id,
      user,
      @userauth.AUTH_SERVICE_CONNECTION,
    ) {
    None => return Failed(AuthError::SignFailed)
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
    return Failed(AuthError::NoAuthReply)
  }
  let mut tries = 0
  let mut verdict : (Byte, FixedArray[Byte])? = None
  while tries < 32 {
    match recv_packet(conn, st.counters, st.recv) {
      None => return Failed(AuthError::NoAuthReply)
      Some((t, pl)) => {
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
    None => return Failed(AuthError::NoAuthReply)
    Some(v) => v
  }
  if msg_type == @sshwire.SSH_MSG_USERAUTH_FAILURE {
    return Failed(
      AuthError::AuthRejected(
        userauth_failure_reason(body),
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
      service_name: USERAUTH_SERVICE,
      accepted_service: accepted,
      we_need: st.we_need,
      key_head: st.key_head,
      session_id_head: st.session_id_head,
      sent_bytes: st.counters.sent,
      recv_bytes: st.counters.recv,
    },
  })
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
