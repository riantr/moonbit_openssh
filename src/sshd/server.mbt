///| Loop #93: the server's state machine.
///
/// This is the file that decides what happens, in what order.  The rules it
/// applies live next door:
///
///   * `kexserver.mbt` -- the key exchange, server role,
///   * `authserver.mbt` -- the `publickey` method and the authorized keys,
///   * `wire.mbt` -- moving packets, and
///   * `@bpacket` -- the packet layer itself (cipher, MAC, padding).
///
/// ## The order, and why each step is where it is
///
///   1. **Identification.**  Both sides send their version line before
///      anything else, and a server may print informational lines before
///      its own `SSH-` line -- so the reader loops until a line starts with
///      `SSH-` (RFC 4253 §4.2).
///   2. **KEXINIT.**  Ours first, then the peer's.  Either order works;
///      sending ours first means a peer that speaks first is never blocked
///      waiting for us.
///   3. **ECDH_INIT -> ECDH_REPLY.**  The peer sends its public value; we
///      answer with ours, the host key and the signature over the exchange
///      hash.
///   4. **NEWKEYS, both ways.**  Each side switches its own sending
///      direction as soon as it has sent NEWKEYS and its receiving
///      direction as soon as it has received one (RFC 4253 §7.1).  The
///      server's two directions are the client's two directions with the
///      names swapped: what we SEND uses the `stoc` key, what we RECEIVE
///      uses the `ctos` key.  Getting that backwards does not fail loudly --
///      it decrypts the peer's stream into noise and the MAC does not
///      verify, which reads as "the peer sent garbage".
///   5. **`ssh-userauth`.**  The peer asks for the service, we accept it,
///      and then the `publickey` exchange runs.

///|
/// What the server needs to be configured with.
pub struct ServerConfig {
  /// Our identification string, e.g. `SSH-2.0-MoonBit_sshd_0.1`.
  ident : String
  /// The 32-byte Ed25519 seed of our host key.
  hostkey_seed : FixedArray[Byte]
  /// The contents of the `authorized_keys` file.
  authorized_keys_text : String
}

///|
/// Build a `ServerConfig`.
///
/// A constructor rather than a bare literal: a struct that another package
/// has to fill in needs a way to be filled in, and the constructor is that
/// way.  It also keeps the field order out of the caller's hands, so the
/// three fields can be rearranged without touching every caller.
pub fn ServerConfig::make(
  ident : String,
  hostkey_seed : FixedArray[Byte],
  authorized_keys_text : String,
) -> ServerConfig {
  { ident, hostkey_seed, authorized_keys_text, }
}

///|
/// What the server did, for the caller and for the gate.
pub struct ServerReport {
  /// The client's identification string.
  client_ident : String
  /// The negotiated KEX algorithm.
  kex_alg : String
  /// The negotiated host key algorithm.
  hostkey_alg : String
  /// The negotiated cipher, client to server.
  cipher_ctos : String
  /// The negotiated cipher, server to client.
  cipher_stoc : String
  /// The session identifier (the exchange hash).
  session_id : FixedArray[Byte]
  /// The user that authenticated.
  user : String
  /// Whether the authentication succeeded.
  authenticated : Bool
  /// The command that was run on the channel, or "" if none was.
  command : String
  /// The command's exit status, or -1 if no command ran.
  exit_status : Int32
  /// How many bytes of the command's stdout were sent.
  stdout_bytes : Int32
  /// How many bytes of the command's stderr were sent.
  stderr_bytes : Int32
  /// How many bytes of SFTP replies were sent.
  ///
  /// Zero unless the peer asked for the `sftp` subsystem.
  sftp_bytes : Int32
  /// How many SFTP requests were answered.
  sftp_requests : Int32
  /// How many bytes were relayed to the peer on forwarded channels.
  ///
  /// Zero unless the peer asked for a port forward.
  forward_bytes : Int32
  /// How many forwarded channels this connection served.
  forward_targets : Int32
  /// Whether the peer's CHANNEL_CLOSE was read before the connection closed.
  ///
  /// This is the observable side of the drain at the end of the channel
  /// phase: without it the server closes while the peer's answering CLOSE is
  /// still in flight, the close becomes a TCP RESET, and the reset discards
  /// whatever the peer has not read yet.  A boolean is a thinner signal than
  /// "the client got its bytes", but it is the one that can be printed, and
  /// it is what a mutation that removes the drain turns to false.
  peer_closed : Bool
  /// The number of packets exchanged, for diagnostics.
  packets : Int32
}

///|
/// Why the server stopped.
pub(all) enum ServerError {
  /// The transport failed.
  Transport(String)
  /// The peer never sent an identification line.
  NoClientIdent
  /// The peer's identification line is not an SSH one.
  BadClientIdent
  /// The peer sent no KEXINIT.
  NoPeerKexinit
  /// The peer sent no ECDH_INIT.
  NoPeerEcdhInit
  /// The key exchange failed.
  KexFailed(String)
  /// A packet could not be sent.
  SendFailed
  /// The peer never answered NEWKEYS.
  NoNewkeys
  /// The peer asked for a service this server does not have.
  UnexpectedService(String)
  /// The peer's authentication request is malformed.
  MalformedUserauth
}

///|
/// Run one connection, from the identification to the authentication, and
/// then through the channel phase.
///
/// `conn` is any transport, so the whole state machine can be driven by a
/// test without a socket -- which is how the unit tests exercise the
/// handshake without a peer.
///
/// `runner` is how commands are run.  The server does not know how to start
/// a process -- that is native-only work -- so the driver supplies the
/// function; see `CommandRunner`.
///
/// `sftp` is the same kind of thing for the `sftp` subsystem: the rules are
/// in `src/sftpserver` and the driver supplies the filesystem and the clock
/// they need.  `None` means this server has no subsystem to offer, and a
/// peer that asks for one is refused.
///
/// `forward` is the same kind of thing for a port forward: the rules are in
/// `src/sshd/forward.mbt` and the driver supplies the sockets and the wait.
/// `None` means this server has no forwarding, and a peer that asks for one
/// is refused by name.
pub fn[T : @transport.Transport, U] serve(
  conn : T,
  cfg : ServerConfig,
  runner : CommandRunner,
  sftp : SftpProvider?,
  forward : ForwardProvider[U]?,
) -> Result[ServerReport, ServerError] {
  let counters = { sent: 0, recv: 0, }
  let send_ctx = @bpacket.SendCtx::new()
  let recv_ctx = @bpacket.RecvCtx::new()
  // ---- 1. identification ----
  if !conn.wire_send(sd_cat2(sd_ascii(cfg.ident), sd_ascii("\r\n"))) {
    return Err(ServerError::Transport("ident_send_failed"))
  }
  counters.sent = counters.sent + cfg.ident.length() + 2
  let mut client_ident = ""
  let mut lines = 0
  while lines < 64 {
    match sd_read_ident_line(conn, counters, 255) {
      None => return Err(ServerError::NoClientIdent)
      Some(line) => {
        lines = lines + 1
        if line.has_prefix("SSH-") {
          client_ident = line
          break
        }
      }
    }
  }
  if !client_ident.has_prefix("SSH-2.0-") &&
    !client_ident.has_prefix("SSH-1.99-") {
    return Err(ServerError::BadClientIdent)
  }
  // ---- 2. KEXINIT ----
  let proposal = @kexflow.Proposal::default_server()
  let cookie = @rng.bytes(@kexflow.KEX_COOKIE_LEN)
  let ic_payload = @kexflow.kexinit_payload(cookie, proposal)
  if !sd_send_packet(
      conn,
      counters,
      send_ctx,
      @sshwire.SSH_MSG_KEXINIT,
      ic_payload,
    ) {
    return Err(ServerError::SendFailed)
  }
  let mut peer_ic : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut got_kexinit = false
  let mut tries = 0
  while !got_kexinit && tries < 32 {
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => return Err(ServerError::NoPeerKexinit)
      BadPacket(why) => return Err(ServerError::Transport(why))
      Packet(t, payload) => {
        tries = tries + 1
        if t == @sshwire.SSH_MSG_KEXINIT {
          peer_ic = payload
          got_kexinit = true
        }
      }
    }
  }
  if !got_kexinit {
    return Err(ServerError::NoPeerKexinit)
  }
  // ---- 3. the peer's public value, then our reply ----
  let mut peer_ecdh_init : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut got_init = false
  let mut tries2 = 0
  while !got_init && tries2 < 32 {
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => return Err(ServerError::NoPeerEcdhInit)
      BadPacket(why) => return Err(ServerError::Transport(why))
      Packet(t, payload) => {
        tries2 = tries2 + 1
        if t == @sshwire.SSH_MSG_KEX_ECDH_INIT {
          peer_ecdh_init = payload
          got_init = true
        }
      }
    }
  }
  if !got_init {
    return Err(ServerError::NoPeerEcdhInit)
  }
  let kex_cfg = ServerKexConfig::make(
    sd_ascii(client_ident),
    sd_ascii(cfg.ident),
    cookie,
    cfg.hostkey_seed,
    SERVER_HOSTKEY_ALG,
  )
  let dh_private = @kexdh.dh_private_exponent(@kexdh.group14_prime_bit_length())
  let kex = match
    server_kex(kex_cfg, proposal, peer_ic, peer_ecdh_init, dh_private) {
    Err(e) => return Err(ServerError::KexFailed(sd_kex_error_label(e)))
    Ok(v) => v
  }
  if !sd_send_packet(
      conn,
      counters,
      send_ctx,
      @sshwire.SSH_MSG_KEX_ECDH_REPLY,
      kex.reply_payload,
    ) {
    return Err(ServerError::SendFailed)
  }
  // ---- 4. NEWKEYS, both ways ----
  if !sd_send_packet(
      conn,
      counters,
      send_ctx,
      @sshwire.SSH_MSG_NEWKEYS,
      FixedArray::make(0, b'\x00'),
    ) {
    return Err(ServerError::SendFailed)
  }
  let mut got_newkeys = false
  let mut tries3 = 0
  while !got_newkeys && tries3 < 32 {
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => return Err(ServerError::NoNewkeys)
      BadPacket(why) => return Err(ServerError::Transport(why))
      Packet(t, _) => {
        tries3 = tries3 + 1
        if t == @sshwire.SSH_MSG_NEWKEYS {
          got_newkeys = true
        }
      }
    }
  }
  if !got_newkeys {
    return Err(ServerError::NoNewkeys)
  }
  // The switch.  OUR sending direction is the client's `stoc`, and OUR
  // receiving direction is the client's `ctos` -- the names are the
  // client's, and from this side they are swapped.
  let (key_len, _block, iv_len, mac_len) = @bpacket.transport_params(
    kex.neg.cipher_ctos,
    kex.neg.mac_ctos,
  )
  let stoc = @bpacket.AesCtrMacCtx::new(
    sd_head_bytes(kex.keys.enc_key_stoc(), key_len),
    sd_head_bytes(kex.keys.iv_stoc(), iv_len),
    sd_head_bytes(kex.keys.mac_key_stoc(), mac_len),
  )
  let ctos = @bpacket.AesCtrMacCtx::new(
    sd_head_bytes(kex.keys.enc_key_ctos(), key_len),
    sd_head_bytes(kex.keys.iv_ctos(), iv_len),
    sd_head_bytes(kex.keys.mac_key_ctos(), mac_len),
  )
  send_ctx.set_mode(@bpacket.MacEncrypt(stoc))
  recv_ctx.set_mode(@bpacket.MacEncrypt(ctos))
  send_ctx.end_initial_kex()
  recv_ctx.end_initial_kex()
  // ---- 5. the userauth service ----
  let mut service_ok = false
  let mut tries4 = 0
  while !service_ok && tries4 < 32 {
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => return Err(ServerError::UnexpectedService("closed"))
      BadPacket(why) => return Err(ServerError::Transport(why))
      Packet(t, payload) => {
        tries4 = tries4 + 1
        if t == @sshwire.SSH_MSG_SERVICE_REQUEST {
          let name = match sd_read_string(payload, 0) {
            None => return Err(ServerError::UnexpectedService("malformed"))
            Some((b, off)) => {
              if off != payload.length() {
                return Err(ServerError::UnexpectedService("trailing"))
              }
              sd_bytes_to_string(b)
            }
          }
          if name != USERAUTH_SERVICE {
            return Err(ServerError::UnexpectedService(name))
          }
          // The reply repeats the service name (RFC 4253 §7.1).
          if !sd_send_packet(
              conn,
              counters,
              send_ctx,
              @sshwire.SSH_MSG_SERVICE_ACCEPT,
              @sshwire.write_ssh_string(sd_ascii(name)),
            ) {
            return Err(ServerError::SendFailed)
          }
          service_ok = true
        }
      }
    }
  }
  if !service_ok {
    return Err(ServerError::UnexpectedService("no_service_request"))
  }
  // ---- 6. the publickey exchange ----
  let authorized = parse_authorized_keys(cfg.authorized_keys_text)
  let mut authenticated = false
  let mut user = ""
  let mut tries5 = 0
  while !authenticated && tries5 < 32 {
    match sd_recv_packet(conn, counters, recv_ctx) {
      Closed => break
      BadPacket(why) => return Err(ServerError::Transport(why))
      Packet(t, payload) => {
        tries5 = tries5 + 1
        if t != @sshwire.SSH_MSG_USERAUTH_REQUEST {
          continue
        }
        let req = match parse_userauth_request(payload) {
          None => return Err(ServerError::MalformedUserauth)
          Some(v) => v
        }
        if req.method_name != @userauth.AUTH_METHOD_PUBLICKEY {
          // A method this server does not implement: the peer is told what
          // it can use, and nothing else happens.
          if !sd_send_packet(
              conn,
              counters,
              send_ctx,
              @sshwire.SSH_MSG_USERAUTH_FAILURE,
              sd_userauth_failure_payload(),
            ) {
            return Err(ServerError::SendFailed)
          }
          continue
        }
        if !req.has_signature {
          // The probe: is this key one we know?
          if key_is_authorized(req, authorized) {
            if !sd_send_packet(
                conn,
                counters,
                send_ctx,
                @sshwire.SSH_MSG_USERAUTH_PK_OK,
                sd_cat2(
                  @sshwire.write_ssh_string(sd_ascii(req.alg)),
                  @sshwire.write_ssh_string(req.key_blob),
                ),
              ) {
              return Err(ServerError::SendFailed)
            }
          } else if !sd_send_packet(
              conn,
              counters,
              send_ctx,
              @sshwire.SSH_MSG_USERAUTH_FAILURE,
              sd_userauth_failure_payload(),
            ) {
            return Err(ServerError::SendFailed)
          }
          continue
        }
        // The signed request.
        if verify_publickey(req, kex.session_id, authorized) {
          authenticated = true
          user = req.user
          if !sd_send_packet(
              conn,
              counters,
              send_ctx,
              @sshwire.SSH_MSG_USERAUTH_SUCCESS,
              FixedArray::make(0, b'\x00'),
            ) {
            return Err(ServerError::SendFailed)
          }
        } else if !sd_send_packet(
            conn,
            counters,
            send_ctx,
            @sshwire.SSH_MSG_USERAUTH_FAILURE,
            sd_userauth_failure_payload(),
          ) {
          return Err(ServerError::SendFailed)
        }
      }
    }
  }
  // ---- 7. the connection protocol ----
  //
  // The peer opens a channel as soon as it is authenticated, and RFC 4254 is
  // where the session happens: the channel, the `exec` request, the
  // command's two output streams, its exit status and the close.
  //
  // Loop #93 refused the channel here, with a refusal the peer could read.
  // Loop #94 implements it, and the rules it follows were measured against
  // the real server rather than recalled -- see `channelserver.mbt`.
  let mut command = ""
  let mut exit_status = -1
  let mut stdout_bytes = 0
  let mut stderr_bytes = 0
  let mut sftp_bytes = 0
  let mut sftp_requests = 0
  let mut forward_bytes = 0
  let mut forward_targets = 0
  let mut peer_closed = false
  if authenticated {
    let ch = serve_channels(
      conn, counters, send_ctx, recv_ctx, runner, sftp, forward,
    )
    command = ch.command
    exit_status = ch.exit_status
    stdout_bytes = ch.stdout_bytes
    stderr_bytes = ch.stderr_bytes
    sftp_bytes = ch.sftp_bytes
    sftp_requests = ch.sftp_requests
    forward_bytes = ch.forward_bytes
    forward_targets = ch.forward_targets
    peer_closed = ch.peer_closed
  }
  Ok({
    client_ident,
    kex_alg: kex.neg.kex_alg,
    hostkey_alg: kex.neg.hostkey_alg,
    cipher_ctos: kex.neg.cipher_ctos,
    cipher_stoc: kex.neg.cipher_stoc,
    session_id: kex.session_id,
    user,
    authenticated,
    command,
    exit_status,
    stdout_bytes,
    stderr_bytes,
    sftp_bytes,
    sftp_requests,
    forward_bytes,
    forward_targets,
    peer_closed,
    packets: tries + tries2 + tries3 + tries4 + tries5,
  })
}

///|
/// The service name the client asks for.
pub const USERAUTH_SERVICE : String = "ssh-userauth"

///|
/// The `SSH_MSG_USERAUTH_FAILURE` payload.
///
/// The list of methods that can continue is `publickey`, and the partial
/// success flag is FALSE: nothing has been authenticated yet, so a partial
/// success would be a lie the peer could act on.
pub fn sd_userauth_failure_payload() -> FixedArray[Byte] {
  sd_cat2(
    @sshwire.write_ssh_string(sd_ascii(@userauth.AUTH_METHOD_PUBLICKEY)),
    FixedArray::from_array([@userauth.SSH_BOOL_FALSE]),
  )
}

///|
/// The channel number the peer opened, read from a `SSH_MSG_CHANNEL_OPEN`
/// payload.
///
/// RFC 4254 §5.1, in the form the implementations actually use:
///
/// ```
///   string  channel type
///   uint32  sender channel number
///   uint32  initial window size
///   uint32  maximum packet size
/// ```
///
/// There is NO `string sender channel` field between the type and the
/// number.  Reading one is what made this server refuse channel 2097152
/// (the window size) instead of channel 0, and the peer answered
/// `open failure packet referred to nonexistent channel 2097152`.
///
/// Measured: the real `ssh.exe` sends a 23-byte CHANNEL_OPEN payload --
/// `00000007 "session" 00000000 00200000 00008000` -- and this
/// repository's own client (`src/channel`, which talks to the real sshd
/// every day) builds the same four fields.
///
/// Returns `None` when the payload is not a well-formed open.
pub fn sd_channel_open_number(payload : FixedArray[Byte]) -> UInt32? {
  let (_type_b, off1) = match sd_read_string(payload, 0) {
    None => return None
    Some(v) => v
  }
  sd_read_u32(payload, off1)
}

///|
/// The first `n` bytes of a byte array.
pub fn sd_head_bytes(b : FixedArray[Byte], n : Int32) -> FixedArray[Byte] {
  let take = if n < b.length() { n } else { b.length() }
  let out : FixedArray[Byte] = FixedArray::make(take, b'\x00')
  for i = 0; i < take; i = i + 1 {
    out[i] = b[i]
  }
  out
}

///|
/// The name of a server failure.
///
/// The names are stable, because the gate reads them: a failure whose name
/// changes is a failure whose diagnosis changes with it.
pub fn sd_server_error_label(e : ServerError) -> String {
  match e {
    ServerError::Transport(w) => "transport:" + w
    ServerError::NoClientIdent => "no_client_ident"
    ServerError::BadClientIdent => "bad_client_ident"
    ServerError::NoPeerKexinit => "no_peer_kexinit"
    ServerError::NoPeerEcdhInit => "no_peer_ecdh_init"
    ServerError::KexFailed(w) => "kex_failed:" + w
    ServerError::SendFailed => "send_failed"
    ServerError::NoNewkeys => "no_newkeys"
    ServerError::UnexpectedService(w) => "unexpected_service:" + w
    ServerError::MalformedUserauth => "malformed_userauth"
  }
}

///|
/// The name of a key-exchange failure.
pub fn sd_kex_error_label(e : ServerKexError) -> String {
  match e {
    ServerKexError::KexinitParseFailed => "kexinit_parse_failed"
    ServerKexError::NoAgreement(w) => "no_agreement:" + w
    ServerKexError::KexAlgNotRunnable(w) => "kex_not_runnable:" + w
    ServerKexError::HostkeyAlgNotRunnable(w) => "hostkey_not_runnable:" + w
    ServerKexError::CipherNotRunnable(w) => "cipher_not_runnable:" + w
    ServerKexError::EcdhInitMalformed => "ecdh_init_malformed"
    ServerKexError::SharedSecretInvalid => "shared_secret_invalid"
  }
}
