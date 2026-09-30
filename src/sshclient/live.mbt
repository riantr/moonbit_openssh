///| Loop #31: real SSH handshake against a live server.
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
///     8. SSH_MSG_NEWKEYS
///
///   Step 7 is the point of the loop: everything up to it could be right and
///   the exchange hash could still differ by one bit, in which case the
///   signature check fails and the server is (correctly) treated as a MITM.

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
/// Number of bytes of the shared secret rendered in the report, to keep the
/// output stable without dumping 512 hex characters every run.
const SHARED_HEAD_LEN : Int = 16

// ---------------------------------------------------------------------------
// Small wire helpers
// ---------------------------------------------------------------------------

///|
fn cat2(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(
    a.length() + b.length(),
    b'\x00',
  )
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  out
}

///| Prepend an SSH message-type byte to a payload, yielding the complete

///| message payload. KEXINIT is the type the exchange hash needs in front of

///|
/// I_C / I_S; OpenSSH calls this a "fake header" (kexgen.c:70-75).
fn with_type(msg_type : Byte, payload : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(payload.length() + 1, msg_type)
  for i = 0; i < payload.length(); i = i + 1 {
    out[1 + i] = payload[i]
  }
  out
}

///|
fn ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///|
fn bytes_to_string(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

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
/// The algorithm set this client implements. The Loop #31 sshd is pinned to
/// exactly this, so a mismatch is our bug rather than a negotiation race.
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
fn fixed_cookie() -> FixedArray[Byte] {
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
/// Send an unencrypted SSH packet.
///
///   Wire layout (RFC 4253 §6):
///       uint32  packet_length
///       byte    padding_length
///       byte[]  payload
///       byte[]  random padding
///
///   Two constraints are easy to get wrong and produce a packet that looks
///   plausible but desynchronises the peer: the padding is at least 4 bytes,
///   and it is the *whole packet* (length field included) that must be a
///   multiple of 8 -- so packet_length itself is congruent to 4 mod 8, not 0.
fn send_plain_packet(
  conn : @tcp.TcpConn,
  counters : WireCounters,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> Bool {
  let unpadded = 2 + payload.length() // padding_length byte + payload
  let mut pad = 4
  while (unpadded + pad) % 8 != 4 {
    pad = pad + 1
  }
  let packet_length = unpadded + pad
  let pkt : FixedArray[Byte] = FixedArray::make(4 + packet_length, b'\x00')
  pkt[0] = ((packet_length >> 24) & 0xFF).to_byte()
  pkt[1] = ((packet_length >> 16) & 0xFF).to_byte()
  pkt[2] = ((packet_length >> 8) & 0xFF).to_byte()
  pkt[3] = (packet_length & 0xFF).to_byte()
  pkt[4] = pad.to_byte()
  pkt[5] = msg_type
  // Payload starts at 6: four length bytes, one padding_length byte, one
  // message type byte. Starting it at 5 lets the first payload byte overwrite
  // the type, which the peer then reports as an unknown message type.
  for i = 0; i < payload.length(); i = i + 1 {
    pkt[6 + i] = payload[i]
  }
  // Deterministic padding keeps the byte transcript reproducible. OpenSSH
  // requires the padding to be unpredictable for traffic analysis; a test
  // client that is not protecting anything may keep it fixed, and a real
  // client must not copy this.
  let mut j = 0
  while j < pad {
    pkt[6 + payload.length() + j] = (0xD0 + j).to_byte()
    j = j + 1
  }
  let ok = conn.send(pkt)
  if ok {
    counters.sent = counters.sent + pkt.length()
  }
  ok
}

///|
/// Read one unencrypted SSH packet. Returns (type, payload).
fn recv_plain_packet(
  conn : @tcp.TcpConn,
  counters : WireCounters,
) -> (Byte, FixedArray[Byte])? {
  let head = match conn.read_exact(4) {
    None => return None
    Some(h) => h
  }
  counters.recv = counters.recv + 4
  let len = (head[0].to_int() << 24) |
    (head[1].to_int() << 16) |
    (head[2].to_int() << 8) |
    head[3].to_int()
  if len < 8 || len > 1048576 {
    return None
  }
  let rest = match conn.read_exact(len) {
    None => return None
    Some(r) => r
  }
  counters.recv = counters.recv + len
  // rest holds [padding_length][msg_type][payload][padding], so the payload
  // is len - padding_length - 2. Getting this off by one appends a padding
  // byte to the payload, which every strict parser (KEXINIT included) then
  // rejects as trailing data.
  let pad = rest[0].to_int()
  let payload_len = len - pad - 2
  if payload_len < 0 {
    return None
  }
  let msg_type = rest[1]
  // payload starts after padding_length AND the message type byte.
  let payload : FixedArray[Byte] = FixedArray::make(payload_len, b'\x00')
  for i = 0; i < payload_len; i = i + 1 {
    payload[i] = rest[2 + i]
  }
  Some((msg_type, payload))
}

///|
/// Read one CRLF-terminated identification line, bounded so a hostile or
/// broken server cannot make us read forever.
fn read_ident_line(
  conn : @tcp.TcpConn,
  counters : WireCounters,
  max_bytes : Int,
) -> String? {
  let buf : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut acc = buf
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

///|
/// Run a full handshake against `host:port`.
///
///   `x` is the DH private exponent. A real client draws it from the CSPRNG;
///   taking it as a parameter keeps this run reproducible, and the caller is
///   responsible for using a fresh value per connection in production.
pub fn live_handshake(conn : @tcp.TcpConn, x : @bigint.BigNat) -> LiveResult {
  let counters = { sent: 0, recv: 0, }
  let client_ident = "SSH-2.0-MoonBit_0.1"
  // ---- 1. identification exchange ----
  if !conn.send(cat2(ascii(client_ident), ascii("\r\n"))) {
    return Failed(ConnectFailed)
  }
  counters.sent = counters.sent + client_ident.length() + 2
  // A server may emit informational lines before its SSH- line.
  let mut server_ident = ""
  let mut lines = 0
  while lines < 64 {
    match read_ident_line(conn, counters, 255) {
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
  let my = live_proposal()
  let ic_payload = @kexflow.kexinit_payload(fixed_cookie(), my)
  if !send_plain_packet(conn, counters, @sshwire.SSH_MSG_KEXINIT, ic_payload) {
    return Failed(KexinitSendFailed)
  }
  let mut peer_ic_payload : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut got_kexinit = false
  let mut tries = 0
  while !got_kexinit && tries < 32 {
    match recv_plain_packet(conn, counters) {
      None => return Failed(NoPeerKexinit)
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
    return Failed(NoPeerKexinit)
  }
  let peer_prop = match @kexflow.parse_kexinit(peer_ic_payload) {
    None => return Failed(KexinitParseFailed)
    Some(p) => p
  }
  let neg = match @kexflow.negotiate(my, peer_prop) {
    Err(e) => return Failed(NoAgreement(neg_error_label(e)))
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
  // mpint encoding. Wrapping it again in write_ssh_string yields a string whose
  // value begins with four zero bytes, and the server rejects that as
  // "invalid public DH value: >= p-1".
  if !send_plain_packet(conn, counters, @sshwire.SSH_MSG_KEX_ECDH_INIT, e_wire) {
    return Failed(EcdhInitSendFailed)
  }
  // ---- 4. KEX_ECDH_REPLY ----
  let mut reply : FixedArray[Byte]? = None
  let mut tries2 = 0
  while tries2 < 32 {
    match recv_plain_packet(conn, counters) {
      None => return Failed(NoEcdhReply)
      Some((t, payload)) => {
        tries2 = tries2 + 1
        if t == @sshwire.SSH_MSG_KEX_ECDH_REPLY {
          reply = Some(payload)
          break
        }
        if t == KX_MSG_KEX_FAILURE {
          return Failed(EcdhReplyMalformed)
        }
      }
    }
  }
  let reply_payload = match reply {
    None => return Failed(NoEcdhReply)
    Some(r) => r
  }
  let parsed_reply = parse_ecdh_reply(reply_payload)
  let (ks, f_wire, sig_blob) = match parsed_reply {
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
  if !send_plain_packet(
      conn,
      counters,
      @sshwire.SSH_MSG_NEWKEYS,
      FixedArray::make(0, b'\x00'),
    ) {
    return Failed(NewkeysSendFailed)
  }
  let mut got_newkeys = false
  let mut tries3 = 0
  while !got_newkeys && tries3 < 32 {
    match recv_plain_packet(conn, counters) {
      None => return Failed(NoNewkeys)
      Some((t, _)) => {
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
    shared_secret_head: hex_head(k, SHARED_HEAD_LEN),
    sent_bytes: counters.sent,
    recv_bytes: counters.recv,
  })
}

///|
/// KEX_ECDH_REPLY body: exactly three strings, K_S, Q_S and the signature,
/// with nothing after them. Returns None on any shape violation.
fn parse_ecdh_reply(
  body : FixedArray[Byte],
) -> (FixedArray[Byte], FixedArray[Byte], FixedArray[Byte])? {
  let a = read_field(body, 0)
  match a {
    None => None
    Some((ks, o1)) =>
      match read_field(body, o1) {
        None => None
        Some((f, o2)) =>
          match read_field(body, o2) {
            None => None
            Some((sig, o3)) =>
              if o3 != body.length() {
                None
              } else {
                Some((ks, f, sig))
              }
          }
      }
  }
}

///|
/// SSH_MSG_KEX_FAILURE (RFC 4253 §7)
pub const KX_MSG_KEX_FAILURE : Byte = b'\x14'

///|
/// Read an SSH `string` at `off`; returns the bytes and the next offset.
fn read_field(b : FixedArray[Byte], off : Int) -> (FixedArray[Byte], Int)? {
  if off < 0 || off + 4 > b.length() {
    return None
  }
  let len = (b[off].to_int() << 24) |
    (b[off + 1].to_int() << 16) |
    (b[off + 2].to_int() << 8) |
    b[off + 3].to_int()
  if len < 0 || off + 4 + len > b.length() {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = b[off + 4 + i]
  }
  Some((out, off + 4 + len))
}
