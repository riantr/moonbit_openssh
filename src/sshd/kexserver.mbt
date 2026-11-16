///| Loop #93: the key exchange, in the SERVER role.
///
/// `src/kexflow` is the client half: it starts a flow, it answers the
/// server's reply, and it verifies the host key's signature.  This is the
/// mirror: we propose, we answer the client's ECDH_INIT, and we are the one
/// whose host key gets signed.
///
/// ## What is shared and what is new
///
/// The hard part of a key exchange is not the arithmetic, it is the
/// AGREEMENT -- eight fields hashed in exactly one order, with exactly one
/// set of length prefixes, where a single missing prefix produces a hash
/// that is still a perfectly good hash and still fails to verify.  That
/// agreement is already implemented once, in `src/kexdh::exchange_hash`, and
/// this file calls it rather than writing a second copy:
///
///     H = SHA-256( string(V_C) || string(V_S) || string(I_C) || string(I_S)
///                  || string(K_S) || mpint(e) || mpint(f) || mpint(K) )
///
/// The client computes the same H from the other side of the same
/// conversation, so if the two disagree about a prefix the handshake fails
/// at the signature check -- which is exactly where it should fail.
///
/// ## The four prefixes, and which of them is already there
///
///   * `V_C`, `V_S` -- the identification strings, WITHOUT the CR LF.
///   * `I_C`, `I_S` -- the KEXINIT payloads with a "fake header": the
///     message-type byte in front of the payload, then the whole thing
///     length-prefixed (kexgen.c:70-75).
///   * `K_S` -- the host key blob, length-prefixed once.
///   * `e`, `f`, `K` -- the DH values, as mpints, i.e. length-prefixed ONCE.
///
/// The last line is where the subtle mistake lives.  `e` and `K` arrive and
/// leave ALREADY carrying their prefix -- `BigNat::mpint_encode` emits the
/// u32 length, so the message payload of an ECDH_INIT is that prefixed form
/// and nothing else -- while `f` is a string in the reply and so needs its
/// prefix added once.  Prefixing one of them twice is the classic
/// "invalid public DH value" failure, and prefixing `f` zero times is the
/// other one.
///
/// ## The signature
///
/// The reply carries the host key's signature over H in the SSH signature
/// format: `string(algorithm name) || string(signature bytes)`.  The
/// algorithm name is `ssh-ed25519` and the signature is the 64 raw bytes
/// RFC 8032 produces -- the same blob the client parses when it verifies us.

///|
/// What the server needs to know before the key exchange starts.
///
/// A `pub struct` with a constructor rather than a package-visible one with
/// a literal: `ServerConfig` in `server.mbt` sets the precedent, and the
/// reason is the same -- a struct another package has to fill in needs a
/// way to be filled in that does not depend on the field order.
pub struct ServerKexConfig {
  /// `V_C`: the client's identification string, without the CR LF.
  version_client : FixedArray[Byte]
  /// `V_S`: ours, without the CR LF.
  version_server : FixedArray[Byte]
  /// Our 16-byte KEXINIT cookie.
  cookie : FixedArray[Byte]
  /// The 32-byte Ed25519 seed of our host key.
  hostkey_seed : FixedArray[Byte]
  /// The host key algorithm name we offer.
  hostkey_alg : String
}

///|
/// Build a `ServerKexConfig`.
pub fn ServerKexConfig::make(
  version_client : FixedArray[Byte],
  version_server : FixedArray[Byte],
  cookie : FixedArray[Byte],
  hostkey_seed : FixedArray[Byte],
  hostkey_alg : String,
) -> ServerKexConfig {
  { version_client, version_server, cookie, hostkey_seed, hostkey_alg, }
}

///|
/// What the key exchange produced.
pub struct ServerKexResult {
  /// The `SSH_MSG_KEX_ECDH_REPLY` payload, WITHOUT the type byte.
  reply_payload : FixedArray[Byte]
  /// The exchange hash `H`, which is also the session identifier.
  session_id : FixedArray[Byte]
  /// The derived traffic keys.
  keys : @kexc25519.DerivedKeys
  /// What was negotiated.
  neg : @kexflow.Negotiated
  /// Our host key blob, `K_S`.
  hostkey_blob : FixedArray[Byte]
  /// Our KEXINIT payload, `I_S`.
  ic_payload : FixedArray[Byte]
}

///|
/// The `SSH_MSG_KEX_ECDH_REPLY` payload, without the type byte.
pub fn ServerKexResult::reply_payload(
  self : ServerKexResult,
) -> FixedArray[Byte] {
  self.reply_payload
}

///|
/// The exchange hash `H`, which is also the session identifier.
pub fn ServerKexResult::session_id(self : ServerKexResult) -> FixedArray[Byte] {
  self.session_id
}

///|
/// What was negotiated.
pub fn ServerKexResult::negotiated(
  self : ServerKexResult,
) -> @kexflow.Negotiated {
  self.neg
}

///|
/// Why a key exchange did not finish.
///
/// The variants are separate because the fixes are in different places: a
/// `NoAgreement` is about the proposal, an `EcdhInitMalformed` is about the
/// peer's bytes, and a `SignatureFailed` would be about us.
pub(all) enum ServerKexError {
  /// The client's KEXINIT did not parse.
  KexinitParseFailed
  /// No algorithm in common.
  NoAgreement(String)
  /// The peer named a KEX algorithm this server does not implement.
  KexAlgNotRunnable(String)
  /// The peer named a host key algorithm this server does not implement.
  HostkeyAlgNotRunnable(String)
  /// The negotiated cipher has no packet-layer path here.
  CipherNotRunnable(String)
  /// The client's ECDH_INIT is not a well-formed mpint.
  EcdhInitMalformed
  /// The client's public value is out of range.
  SharedSecretInvalid
}

///|
/// The KEX algorithm this server speaks, and the only one it speaks.
///
/// One algorithm, on purpose: a second one would be a second set of field
/// orderings, and the exchange hash is where a mistake is invisible until
/// a signature fails to verify.
pub const SERVER_KEX_ALG : String = "diffie-hellman-group14-sha256"

///|
/// The host key algorithm this server speaks.
pub const SERVER_HOSTKEY_ALG : String = "ssh-ed25519"

///|
/// Run the key exchange, server side.
///
/// `peer_ic_payload` is the client's KEXINIT payload (no type byte) and
/// `peer_ecdh_init` is the client's `SSH_MSG_KEX_ECDH_INIT` payload (no type
/// byte), which is the client's public value `e` as an mpint.
///
/// `dh_private` is OUR exponent for this exchange.  It is a parameter rather
/// than something drawn here so that a test can pin it and get a
/// reproducible transcript.
pub fn server_kex(
  cfg : ServerKexConfig,
  my : @kexflow.Proposal,
  peer_ic_payload : FixedArray[Byte],
  peer_ecdh_init : FixedArray[Byte],
  dh_private : @bigint.BigNat,
) -> Result[ServerKexResult, ServerKexError] {
  // ---- the peer's proposal ----
  let peer_prop = match @kexflow.parse_kexinit(peer_ic_payload) {
    None => return Err(ServerKexError::KexinitParseFailed)
    Some(p) => p
  }
  let neg = match @kexflow.negotiate(my, peer_prop) {
    Err(_) => return Err(ServerKexError::NoAgreement("no_common_algorithm"))
    Ok(n) => n
  }
  // The peer may have offered more than we do; the agreement is on the one
  // both sides have.  Anything else is a capability gap on OUR side, and it
  // is reported as such rather than as a protocol error by the peer.
  if neg.kex_alg != SERVER_KEX_ALG {
    return Err(ServerKexError::KexAlgNotRunnable(neg.kex_alg))
  }
  if neg.hostkey_alg != SERVER_HOSTKEY_ALG {
    return Err(ServerKexError::HostkeyAlgNotRunnable(neg.hostkey_alg))
  }
  // The packet layer has to be able to run what was agreed, and the only
  // path it has for a MAC is the encrypt-and-MAC one (aes128-ctr +
  // hmac-sha2-256).  An AEAD would need the other branch, which this
  // server does not drive.
  if !@bpacket.cipher_needs_mac(neg.cipher_ctos) ||
    !@bpacket.cipher_needs_mac(neg.cipher_stoc) {
    return Err(ServerKexError::CipherNotRunnable(neg.cipher_ctos))
  }
  if !@bpacket.is_runnable_mac(neg.mac_ctos) ||
    !@bpacket.is_runnable_mac(neg.mac_stoc) {
    return Err(ServerKexError::CipherNotRunnable(neg.mac_ctos))
  }
  // ---- the client's public value e ----
  // The payload of an ECDH_INIT IS the mpint: a u32 length and the bytes.
  // Trailing bytes are rejected rather than ignored -- a peer that sends
  // more than the protocol says is a peer whose next message will be
  // somewhere else than we think.
  let (e_magnitude, e_off) = match sd_read_string(peer_ecdh_init, 0) {
    None => return Err(ServerKexError::EcdhInitMalformed)
    Some(v) => v
  }
  if e_off != peer_ecdh_init.length() {
    return Err(ServerKexError::EcdhInitMalformed)
  }
  let e = @bigint.BigNat::from_bytes_be(e_magnitude)
  // ---- our public value f and the shared secret K ----
  let p = @bigint.BigNat::from_bytes_be(@kexdh.group14_prime())
  let g = @bigint.BigNat::from_uint64(2UL)
  let ctx = @kexdh.dh_ctx(p)
  // The client's value has to be in range, or the shared secret is
  // meaningless.  A value of 1 or 0, or one at or above p-1, is refused --
  // this is the check that stops a small-subgroup attack.
  if @bigint.BigNat::cmp(e, @bigint.BigNat::from_uint64(1UL)) <= 0 ||
    @bigint.BigNat::cmp(e, p) >= 0 {
    return Err(ServerKexError::SharedSecretInvalid)
  }
  let f = @kexdh.dh_pub_ctx(ctx, g, dh_private)
  let k = @kexdh.dh_shared_ctx(ctx, e, dh_private)
  // `f` goes on the wire as an mpint, so its magnitude is what the string
  // carries -- and the leading zero that keeps the value positive is part
  // of the magnitude, not an extra byte.
  let f_wire = @bigint.BigNat::mpint_encode(f)
  let f_magnitude = match sd_slice(f_wire, 4, f_wire.length() - 4) {
    None => return Err(ServerKexError::EcdhInitMalformed)
    Some(v) => v
  }
  let k_wire = @bigint.BigNat::mpint_encode(k)
  // ---- our KEXINIT and the host key ----
  let ic_payload = @kexflow.kexinit_payload(cfg.cookie, my)
  let (hostkey_pub, hostkey_sec) = @hostkey.keypair_from_seed(cfg.hostkey_seed)
  let hostkey_blob = sd_cat2(
    @sshwire.write_ssh_string(sd_ascii(SERVER_HOSTKEY_ALG)),
    @sshwire.write_ssh_string(hostkey_pub),
  )
  // ---- the exchange hash ----
  let v_c_w = @sshwire.write_ssh_string(cfg.version_client)
  let v_s_w = @sshwire.write_ssh_string(cfg.version_server)
  let i_c_w = @sshwire.write_ssh_string(
    sd_with_type(@sshwire.SSH_MSG_KEXINIT, peer_ic_payload),
  )
  let i_s_w = @sshwire.write_ssh_string(
    sd_with_type(@sshwire.SSH_MSG_KEXINIT, ic_payload),
  )
  let k_s_w = @sshwire.write_ssh_string(hostkey_blob)
  let h = @kexdh.exchange_hash(
    v_c_w,
    v_s_w,
    i_c_w,
    i_s_w,
    k_s_w,
    peer_ecdh_init,
    @sshwire.write_ssh_string(f_magnitude),
    k_wire,
  )
  // ---- the signature over H ----
  let sig = @hostkey.sign(h, hostkey_sec)
  let sig_blob = sd_cat2(
    @sshwire.write_ssh_string(sd_ascii(SERVER_HOSTKEY_ALG)),
    @sshwire.write_ssh_string(sig),
  )
  // ---- the reply ----
  //
  // RFC 4253 §7.1: `string K_S || string Q_S || string signature`.  The
  // signature field is a string whose CONTENT is the signature blob
  // (`string algorithm || string signature bytes`, RFC 4253 §6.6) -- so the
  // blob is wrapped in a string ONE more time.
  //
  // Measured against the real sshd (host/ssh_recorder.py in front of a real
  // `sshd -D`): the real reply's third field is 87 bytes on the wire, i.e.
  // `u32(83) || u32(11) "ssh-ed25519" || u32(64) || 64 signature bytes`.
  // Writing the blob unwrapped produces the same 83 bytes of CONTENT but a
  // different framing -- `u32(11) "ssh-ed25519" || u32(64) || sig` -- so the
  // peer reads an 11-byte "signature" and finds 68 bytes it did not expect.
  // The failure is total and immediate: the peer aborts the key exchange
  // before it ever sends NEWKEYS.
  let reply_payload = sd_cat3(
    @sshwire.write_ssh_string(hostkey_blob),
    @sshwire.write_ssh_string(f_magnitude),
    @sshwire.write_ssh_string(sig_blob),
  )
  // ---- the traffic keys ----
  let we_need = @bpacket.we_need_for(neg.cipher_ctos, neg.mac_ctos)
  if we_need != @bpacket.we_need_for(neg.cipher_stoc, neg.mac_stoc) {
    return Err(ServerKexError::CipherNotRunnable("asymmetric_key_length"))
  }
  let keys = @kexc25519.derive_keys(h, k_wire, we_need)
  Ok({ reply_payload, session_id: h, keys, neg, hostkey_blob, ic_payload, })
}
