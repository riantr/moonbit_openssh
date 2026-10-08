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
/// Write one plaintext packet. Returns false if the transport failed.
async fn wt_send_plain_packet(
  conn : @wt.WtConn,
  counters : WtWireCounters,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> Bool {
  let pkt = @sshclient.build_plain_packet(msg_type, payload, b'\x00')
  conn.send(pkt) catch {
    _ => return false
  }
  counters.sent = counters.sent + pkt.length()
  true
}

///|
/// Read one plaintext packet.
async fn wt_recv_plain_packet(
  conn : @wt.WtConn,
  counters : WtWireCounters,
) -> (Byte, FixedArray[Byte])? {
  let head = conn.read_exact(4) catch { _ => return None }
  counters.recv = counters.recv + 4
  let len = @sshclient.be32(head)
  if !@sshclient.packet_length_ok(len, 1048576) {
    return None
  }
  let body = conn.read_exact(len) catch { _ => return None }
  counters.recv = counters.recv + len
  @sshclient.parse_plain_packet(body)
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
pub async fn wt_live_handshake(
  conn : @wt.WtConn,
  x : @bigint.BigNat,
) -> WtLiveResult {
  let counters = { sent: 0, recv: 0, }
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
  if !wt_send_plain_packet(conn, counters, @sshwire.SSH_MSG_KEXINIT, ic_payload) {
    return Failed(KexinitSendFailed)
  }
  let mut peer_ic_payload : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut got_kexinit = false
  let mut tries = 0
  while !got_kexinit && tries < 32 {
    match wt_recv_plain_packet(conn, counters) {
      None => return Failed(NoPeerKexinit)
      Some((t, payload)) => {
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
      @sshwire.SSH_MSG_KEX_ECDH_INIT,
      e_wire,
    ) {
    return Failed(EcdhInitSendFailed)
  }
  // ---- 4. KEX_ECDH_REPLY ----
  let mut reply : FixedArray[Byte]? = None
  let mut tries2 = 0
  while tries2 < 32 {
    match wt_recv_plain_packet(conn, counters) {
      None => return Failed(NoEcdhReply)
      Some((t, payload)) => {
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
      @sshwire.SSH_MSG_NEWKEYS,
      FixedArray::make(0, b'\x00'),
    ) {
    return Failed(NewkeysSendFailed)
  }
  let mut got_newkeys = false
  let mut tries3 = 0
  while !got_newkeys && tries3 < 32 {
    match wt_recv_plain_packet(conn, counters) {
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
    shared_secret_head: shared_secret_head_of(k),
    sent_bytes: counters.sent,
    recv_bytes: counters.recv,
  })
}

///|

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
