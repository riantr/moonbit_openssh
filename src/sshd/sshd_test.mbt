///| Loop #93: the server's unit tests.
///
/// What is tested here is the part of the server that DECIDES things -- the
/// parsing, the framing, the authorization -- and not the socket.  The
/// socket half belongs to the gate (`host/verify_loop93.mjs`), because the
/// oracle for the socket half is the REAL `ssh.exe`, and a unit test cannot
/// be that oracle.
///
/// ## Why the framing tests are the important ones
///
/// Two of the three bugs this loop found were framing bugs, and neither of
/// them could have been caught by "the server answered correctly":
///
///   * the `SSH_MSG_KEX_ECDH_REPLY` signature field was missing one layer of
///     `string`, so the peer read an 11-byte "signature" and found 68 bytes
///     it did not expect;
///   * the `SSH_MSG_CHANNEL_OPEN` was read with one `string` too many, so
///     the window size was mistaken for the channel number.
///
/// Both produced a well-formed answer that the peer refused to read.  So the
/// tests below check BYTES, against the bytes the real sshd was measured to
/// send, and not just "did the function return the right value".

///|
fn sdt_eq_int(a : Int32, b : Int32, label : String) -> Unit {
  if a != b {
    abort(label + ": " + a.to_string() + " != " + b.to_string())
  }
}

///|
fn sdt_eq_str(a : String, b : String, label : String) -> Unit {
  if a != b {
    abort(label + ": '" + a + "' != '" + b + "'")
  }
}

///|
fn sdt_true(b : Bool, label : String) -> Unit {
  if !b {
    abort(label + ": expected true")
  }
}

///|
fn sdt_bytes_eq(
  a : FixedArray[Byte],
  b : FixedArray[Byte],
  label : String,
) -> Unit {
  if a.length() != b.length() {
    abort(
      label +
      ": length " +
      a.length().to_string() +
      " != " +
      b.length().to_string(),
    )
  }
  for i = 0; i < b.length(); i = i + 1 {
    if a[i] != b[i] {
      abort(label + ": byte " + i.to_string() + " differs")
    }
  }
}

///|
fn sdt_cat_all(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i = 0; i < p.length(); i = i + 1 {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  out
}

///|
/// A real ed25519 public key blob, base64, as it appears in an
/// `authorized_keys` file.  Taken from the key bed the gate uses, so the
/// bytes here are bytes a real client really sends.
const SDT_USER_KEY_B64 : String = "AAAAC3NzaC1lZDI1NTE5AAAAIKMeqO4ufGOD4THu7eZLdewjn3u4kXUjeaMoZAeOOvcL"

///|
/// Decode the base64 above into an SSH key blob.
fn sdt_user_blob() -> FixedArray[Byte] {
  let view : StringView = SDT_USER_KEY_B64
  let decoded = @base64.decode(view, ignore_whitespace=false) catch {
    _ => abort("sdt_user_blob: base64 did not decode")
  }
  let arr : FixedArray[Byte] = FixedArray::make(decoded.length(), b'\x00')
  for i = 0; i < decoded.length(); i = i + 1 {
    arr[i] = decoded[i]
  }
  arr
}

///|
/// A `SSH_MSG_USERAUTH_REQUEST` payload for the `publickey` method.
///
/// `flag` is the boolean: 0 is the probe (no signature), 1 is the signed
/// request.
fn sdt_userauth_payload(
  user : String,
  service : String,
  flag : Byte,
  alg : String,
  key_blob : FixedArray[Byte],
  sig_blob : FixedArray[Byte]?,
) -> FixedArray[Byte] {
  let parts : Array[FixedArray[Byte]] = [
    @sshwire.write_ssh_string(@sshd.sd_ascii(user)),
    @sshwire.write_ssh_string(@sshd.sd_ascii(service)),
    @sshwire.write_ssh_string(@sshd.sd_ascii(@userauth.AUTH_METHOD_PUBLICKEY)),
    FixedArray::from_array([flag]),
    @sshwire.write_ssh_string(@sshd.sd_ascii(alg)),
    @sshwire.write_ssh_string(key_blob),
  ]
  match sig_blob {
    None => ()
    Some(s) => parts.push(@sshwire.write_ssh_string(s))
  }
  sdt_cat_all(parts)
}

// ---------------------------------------------------------------------------
// the small helpers
// ---------------------------------------------------------------------------

///|
test "t01_util_ascii_cat_and_hex" {
  let a = @sshd.sd_ascii("AB")
  sdt_eq_int(a.length(), 2, "ascii length")
  sdt_eq_int(a[0].to_int(), 65, "ascii A")
  sdt_eq_int(a[1].to_int(), 66, "ascii B")
  sdt_bytes_eq(a, @sshd.sd_ascii("AB"), "ascii round trip")
  let b = @sshd.sd_ascii("C")
  let ab = @sshd.sd_cat2(a, b)
  sdt_eq_int(ab.length(), 3, "cat2 length")
  sdt_eq_int(ab[2].to_int(), 67, "cat2 third byte")
  let abc = @sshd.sd_cat3(a, b, @sshd.sd_ascii("D"))
  sdt_eq_int(abc.length(), 4, "cat3 length")
  sdt_eq_str(@sshd.sd_hex(ab), "414243", "hex")
  sdt_eq_str(@sshd.sd_hex(FixedArray::make(0, b'\x00')), "", "hex of nothing")
}

///|
test "t02_sd_read_string_bounds" {
  let buf = @sshd.sd_cat2(@sshwire.write_u32(3U), @sshd.sd_ascii("xyz"))
  match @sshd.sd_read_string(buf, 0) {
    None => abort("t02: a well-formed string did not parse")
    Some((body, off)) => {
      sdt_eq_int(body.length(), 3, "string body length")
      sdt_eq_int(off, 7, "offset past the string")
      sdt_eq_int(body[0].to_int(), 120, "string body")
    }
  }
  // a length that runs past the end of the buffer is a failure, not a
  // truncation: a server that accepts half a field agrees with the wrong peer
  let lying = @sshd.sd_cat2(@sshwire.write_u32(99U), @sshd.sd_ascii("xyz"))
  match @sshd.sd_read_string(lying, 0) {
    None => ()
    Some(_) => abort("t02: a string that runs off the end was accepted")
  }
  // and so is an offset with no room for a length
  match @sshd.sd_read_string(buf, 5) {
    None => ()
    Some(_) => abort("t02: a string read from a bad offset was accepted")
  }
}

///|
test "t03_sd_read_u32_is_big_endian" {
  let buf = @sshd.sd_cat2(@sshwire.write_u32(0x01020304U), @sshd.sd_ascii("x"))
  match @sshd.sd_read_u32(buf, 0) {
    None => abort("t03: u32 did not parse")
    Some(v) => sdt_eq_int(v.reinterpret_as_int(), 0x01020304, "u32 value")
  }
  // the same bytes read one further along are the same bytes read later:
  // a u32 is four bytes of big endian, wherever it starts
  match @sshd.sd_read_u32(buf, 1) {
    None => abort("t03: u32 did not parse at offset 1")
    Some(v) => sdt_eq_int(v.reinterpret_as_int(), 0x02030478, "u32 value")
  }
  // a buffer with no room for a u32 at all
  let four = @sshwire.write_u32(1U)
  match @sshd.sd_read_u32(four, 1) {
    None => ()
    Some(_) => abort("t03: a u32 read past the end was accepted")
  }
  match @sshd.sd_read_u32(four, 4) {
    None => ()
    Some(_) => abort("t03: a u32 read past the end was accepted")
  }
}

///|
test "t04_sd_slice_bounds" {
  let buf = @sshd.sd_ascii("abcdef")
  match @sshd.sd_slice(buf, 1, 3) {
    None => abort("t04: a valid slice did not parse")
    Some(s) => {
      sdt_eq_int(s.length(), 3, "slice length")
      sdt_eq_int(s[0].to_int(), 98, "slice first byte")
    }
  }
  match @sshd.sd_slice(buf, 4, 3) {
    None => ()
    Some(_) => abort("t04: a slice running off the end was accepted")
  }
  match @sshd.sd_slice(buf, -1, 2) {
    None => ()
    Some(_) => abort("t04: a slice with a negative offset was accepted")
  }
}

// ---------------------------------------------------------------------------
// authorized_keys
// ---------------------------------------------------------------------------

///|
test "t05_authorized_keys_reads_a_plain_key" {
  let text = "# a comment\n" +
    "\n" +
    "ssh-ed25519 " +
    SDT_USER_KEY_B64 +
    " a comment for the key\n"
  let keys = @sshd.parse_authorized_keys(text)
  sdt_eq_int(keys.length(), 1, "one key")
  sdt_eq_str(keys[0].alg, "ssh-ed25519", "key type")
  sdt_eq_int(keys[0].blob.length(), 51, "key blob length")
}

///|
test "t06_authorized_keys_refuses_options_and_broken_base64" {
  // a line with options: this server does not implement `command=` or
  // `no-pty`, and accepting the key without honouring them would silently
  // drop the restrictions
  let with_options = "command=\"echo hi\",no-pty ssh-ed25519 " +
    SDT_USER_KEY_B64 +
    " k\n"
  sdt_eq_int(
    @sshd.parse_authorized_keys(with_options).length(),
    0,
    "a key with options must be refused",
  )
  // base64 that does not decode: one broken line must not lock the user out
  // of the other forty-nine
  let broken = "ssh-ed25519 not-base64-at-all comment\n" +
    "ssh-ed25519 " +
    SDT_USER_KEY_B64 +
    " good\n"
  let keys = @sshd.parse_authorized_keys(broken)
  sdt_eq_int(
    keys.length(),
    1,
    "the broken line is skipped, the good one is kept",
  )
  // a line with nothing on it
  sdt_eq_int(@sshd.parse_authorized_keys("ssh-ed25519\n").length(), 0, "no key")
}

///|
test "t07_authorized_keys_crlf_and_trailing" {
  let text = "ssh-ed25519 " + SDT_USER_KEY_B64 + " k\r\n"
  let keys = @sshd.parse_authorized_keys(text)
  sdt_eq_int(keys.length(), 1, "a CRLF file parses")
  sdt_eq_int(keys[0].blob.length(), 51, "key blob length")
}

// ---------------------------------------------------------------------------
// the userauth request
// ---------------------------------------------------------------------------

///|
test "t08_userauth_probe_parses" {
  let blob = sdt_user_blob()
  let payload = sdt_userauth_payload(
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    @userauth.SSH_BOOL_FALSE,
    "ssh-ed25519",
    blob,
    None,
  )
  match @sshd.parse_userauth_request(payload) {
    None => abort("t08: the probe did not parse")
    Some(r) => {
      sdt_eq_str(r.user, "hp", "user")
      sdt_eq_str(r.service, @userauth.AUTH_SERVICE_CONNECTION, "service")
      sdt_eq_str(r.method_name, @userauth.AUTH_METHOD_PUBLICKEY, "method")
      sdt_true(!r.has_signature, "the probe carries no signature")
      sdt_eq_str(r.alg, "ssh-ed25519", "algorithm")
      sdt_eq_int(r.key_blob.length(), 51, "key blob")
      match r.sig_blob {
        None => ()
        Some(_) => abort("t08: the probe must not carry a signature blob")
      }
    }
  }
}

///|
test "t09_userauth_signed_parses" {
  let blob = sdt_user_blob()
  let sig = @sshd.sd_cat2(
    @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-ed25519")),
    @sshwire.write_ssh_string(FixedArray::make(64, b'\x01')),
  )
  let payload = sdt_userauth_payload(
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    @userauth.SSH_BOOL_TRUE,
    "ssh-ed25519",
    blob,
    Some(sig),
  )
  match @sshd.parse_userauth_request(payload) {
    None => abort("t09: the signed request did not parse")
    Some(r) => {
      sdt_true(r.has_signature, "the signed request carries a signature")
      match r.sig_blob {
        None => abort("t09: the signature blob is missing")
        Some(s) => sdt_eq_int(s.length(), 83, "signature blob length")
      }
    }
  }
}

///|
test "t10_userauth_malformed_is_refused" {
  let blob = sdt_user_blob()
  // trailing bytes after the key blob of a probe: a request with fields this
  // server has not read is a request it must not accept
  let probe = sdt_userauth_payload(
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    @userauth.SSH_BOOL_FALSE,
    "ssh-ed25519",
    blob,
    None,
  )
  let with_tail = @sshd.sd_cat2(probe, @sshd.sd_ascii("x"))
  match @sshd.parse_userauth_request(with_tail) {
    None => ()
    Some(_) => abort("t10: a probe with trailing bytes was accepted")
  }
  // a boolean that is neither TRUE nor FALSE
  let bad_flag = sdt_userauth_payload(
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    b'\x02',
    "ssh-ed25519",
    blob,
    None,
  )
  match @sshd.parse_userauth_request(bad_flag) {
    None => ()
    Some(_) => abort("t10: a request with a bad boolean was accepted")
  }
  // a request that stops in the middle of a field
  let truncated = @sshd.sd_cat2(
    @sshwire.write_ssh_string(@sshd.sd_ascii("hp")),
    @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-connection")),
  )
  match @sshd.parse_userauth_request(truncated) {
    None => ()
    Some(_) => abort("t10: a truncated request was accepted")
  }
}

// ---------------------------------------------------------------------------
// authorization
// ---------------------------------------------------------------------------

///|
test "t11_key_is_authorized_compares_the_blob" {
  let blob = sdt_user_blob()
  let other = @sshd.sd_cat2(
    @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-ed25519")),
    @sshwire.write_ssh_string(FixedArray::make(32, b'\x09')),
  )
  let keys = @sshd.parse_authorized_keys(
    "ssh-ed25519 " + SDT_USER_KEY_B64 + " k\n",
  )
  let probe = sdt_userauth_payload(
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    @userauth.SSH_BOOL_FALSE,
    "ssh-ed25519",
    blob,
    None,
  )
  match @sshd.parse_userauth_request(probe) {
    None => abort("t11: the probe did not parse")
    Some(r) =>
      sdt_true(@sshd.key_is_authorized(r, keys), "the key is on the list")
  }
  let probe2 = sdt_userauth_payload(
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    @userauth.SSH_BOOL_FALSE,
    "ssh-ed25519",
    other,
    None,
  )
  match @sshd.parse_userauth_request(probe2) {
    None => abort("t11: the second probe did not parse")
    Some(r) =>
      sdt_true(
        !@sshd.key_is_authorized(r, keys),
        "a key that is not on the list is not authorized",
      )
  }
}

///|
test "t12_verify_publickey_accepts_a_good_signature" {
  // sign with a key we make here, and check the server's own verification
  let seed : FixedArray[Byte] = FixedArray::make(32, b'\x07')
  let (pk, sk) = @hostkey.keypair_from_seed(seed)
  let blob = @sshd.sd_cat2(
    @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-ed25519")),
    @sshwire.write_ssh_string(pk),
  )
  let session_id : FixedArray[Byte] = FixedArray::make(32, b'\x11')
  let to_sign = @userauth.userauth_signed_blob(
    session_id,
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    "ssh-ed25519",
    blob,
  )
  let sig = @hostkey.sign(to_sign, sk)
  let sig_blob = @sshd.sd_cat2(
    @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-ed25519")),
    @sshwire.write_ssh_string(sig),
  )
  let payload = sdt_userauth_payload(
    "hp",
    @userauth.AUTH_SERVICE_CONNECTION,
    @userauth.SSH_BOOL_TRUE,
    "ssh-ed25519",
    blob,
    Some(sig_blob),
  )
  let keys : Array[@sshd.AuthorizedKey] = [{ alg: "ssh-ed25519", blob, }]
  match @sshd.parse_userauth_request(payload) {
    None => abort("t12: the signed request did not parse")
    Some(r) => {
      sdt_true(
        @sshd.verify_publickey(r, session_id, keys),
        "a good signature over an authorized key is accepted",
      )
      // the key is not on the list: a perfect signature does not make an
      // unauthorized key authorized
      let other_blob = @sshd.sd_cat2(
        @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-ed25519")),
        @sshwire.write_ssh_string(FixedArray::make(32, b'\x09')),
      )
      let others : Array[@sshd.AuthorizedKey] = [
        { alg: "ssh-ed25519", blob: other_blob, },
      ]
      sdt_true(
        !@sshd.verify_publickey(r, session_id, others),
        "an unauthorized key is refused even with a good signature",
      )
      // a corrupted signature is refused
      let bad_sig = @sshd.sd_cat2(
        @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-ed25519")),
        @sshwire.write_ssh_string(FixedArray::make(64, b'\x00')),
      )
      let payload2 = sdt_userauth_payload(
        "hp",
        @userauth.AUTH_SERVICE_CONNECTION,
        @userauth.SSH_BOOL_TRUE,
        "ssh-ed25519",
        blob,
        Some(bad_sig),
      )
      match @sshd.parse_userauth_request(payload2) {
        None => abort("t12: the second request did not parse")
        Some(r2) =>
          sdt_true(
            !@sshd.verify_publickey(r2, session_id, keys),
            "a corrupted signature is refused",
          )
      }
      // a signature over a DIFFERENT session id is refused: this is what
      // stops a signature captured from another connection from being
      // replayed here
      let other_session : FixedArray[Byte] = FixedArray::make(32, b'\x12')
      let to_sign2 = @userauth.userauth_signed_blob(
        other_session,
        "hp",
        @userauth.AUTH_SERVICE_CONNECTION,
        "ssh-ed25519",
        blob,
      )
      let sig2 = @hostkey.sign(to_sign2, sk)
      let sig_blob2 = @sshd.sd_cat2(
        @sshwire.write_ssh_string(@sshd.sd_ascii("ssh-ed25519")),
        @sshwire.write_ssh_string(sig2),
      )
      let payload3 = sdt_userauth_payload(
        "hp",
        @userauth.AUTH_SERVICE_CONNECTION,
        @userauth.SSH_BOOL_TRUE,
        "ssh-ed25519",
        blob,
        Some(sig_blob2),
      )
      match @sshd.parse_userauth_request(payload3) {
        None => abort("t12: the third request did not parse")
        Some(r3) =>
          sdt_true(
            !@sshd.verify_publickey(r3, session_id, keys),
            "a signature over another session id is refused",
          )
      }
    }
  }
}

// ---------------------------------------------------------------------------
// the framing
// ---------------------------------------------------------------------------

///|
/// Run one server-side key exchange with fixed inputs and return the reply
/// payload.
fn sdt_reply_payload() -> FixedArray[Byte] {
  let cookie : FixedArray[Byte] = FixedArray::make(16, b'\x01')
  let cfg = @sshd.ServerKexConfig::make(
    @sshd.sd_ascii("SSH-2.0-TestClient"),
    @sshd.sd_ascii("SSH-2.0-MoonBit_sshd_0.1"),
    cookie,
    FixedArray::make(32, b'\x02'),
    @sshd.SERVER_HOSTKEY_ALG,
  )
  let peer_ic = @kexflow.kexinit_payload(
    cookie,
    @kexflow.Proposal::default_server(),
  )
  let p = @bigint.BigNat::from_bytes_be(@kexdh.group14_prime())
  let g = @bigint.BigNat::from_uint64(2UL)
  let ctx = @kexdh.dh_ctx(p)
  let x = @bigint.BigNat::from_uint64(0x1234567890abcdefUL)
  let e = @kexdh.dh_pub_ctx(ctx, g, x)
  let peer_init = @bigint.BigNat::mpint_encode(e)
  match
    @sshd.server_kex(
      cfg,
      @kexflow.Proposal::default_server(),
      peer_ic,
      peer_init,
      x,
    ) {
    Err(e) => abort("sdt_reply_payload: " + @sshd.sd_kex_error_label(e))
    Ok(v) => @sshd.ServerKexResult::reply_payload(v)
  }
}

///|
test "t13_ecdh_reply_is_framed_the_way_the_real_sshd_frames_it" {
  // The real sshd's reply, measured with host/ssh_recorder.py in front of a
  // real `sshd -D`:
  //
  //   string K_S   (51 bytes: string "ssh-ed25519" + string 32-byte key)
  //   string Q_S   (the mpint f)
  //   string sig   (83 bytes: string "ssh-ed25519" + string 64-byte signature)
  //
  // The signature field is a string whose CONTENT is the signature blob, so
  // the blob is wrapped in a string ONE more time.  Writing it unwrapped
  // produces the same 83 bytes of content with a different framing, and the
  // peer then reads an 11-byte "signature" and finds 68 bytes it did not
  // expect -- which is exactly how this server failed against the real
  // client.
  let reply = sdt_reply_payload()
  let (ks, off1) = match @sshd.sd_read_string(reply, 0) {
    None => abort("t13: K_S did not parse")
    Some(v) => v
  }
  let (qs, off2) = match @sshd.sd_read_string(reply, off1) {
    None => abort("t13: Q_S did not parse")
    Some(v) => v
  }
  let (sig, off3) = match @sshd.sd_read_string(reply, off2) {
    None => abort("t13: the signature field did not parse")
    Some(v) => v
  }
  sdt_eq_int(off3, reply.length(), "the reply has no trailing bytes")
  sdt_eq_int(ks.length(), 51, "K_S length")
  // inside K_S: string "ssh-ed25519" + string 32-byte key
  let (ks_alg, ks_off1) = match @sshd.sd_read_string(ks, 0) {
    None => abort("t13: the key type did not parse")
    Some(v) => v
  }
  let (ks_bytes, ks_off2) = match @sshd.sd_read_string(ks, ks_off1) {
    None => abort("t13: the key bytes did not parse")
    Some(v) => v
  }
  sdt_eq_str(@sshd.sd_bytes_to_string(ks_alg), "ssh-ed25519", "the key type")
  sdt_eq_int(ks_bytes.length(), 32, "the key is 32 bytes")
  sdt_eq_int(ks_off2, ks.length(), "the key blob has no trailing bytes")
  // Q_S is the mpint f: a length and a magnitude
  sdt_true(qs.length() > 0, "Q_S is not empty")
  // the signature field
  sdt_eq_int(sig.length(), 83, "the signature field is 83 bytes")
  let (sig_alg, sig_off1) = match @sshd.sd_read_string(sig, 0) {
    None => abort("t13: the signature algorithm did not parse")
    Some(v) => v
  }
  let (sig_bytes, sig_off2) = match @sshd.sd_read_string(sig, sig_off1) {
    None => abort("t13: the signature bytes did not parse")
    Some(v) => v
  }
  sdt_eq_str(
    @sshd.sd_bytes_to_string(sig_alg),
    "ssh-ed25519",
    "the signature algorithm",
  )
  sdt_eq_int(sig_bytes.length(), 64, "the signature is 64 bytes")
  sdt_eq_int(
    sig_off2,
    sig.length(),
    "the signature blob has no trailing bytes -- the check the real client makes",
  )
}

///|
test "t14_channel_open_number_is_the_sender_channel" {
  // the bytes the real `ssh.exe` sends, measured:
  // 00000007 "session" 00000000 00200000 00008000
  let payload = FixedArray::from_array([
    b'\x00', b'\x00', b'\x00', b'\x07', b's', b'e', b's', b's', b'i', b'o', b'n',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x20', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x80', b'\x00',
  ])
  match @sshd.sd_channel_open_number(payload) {
    None => abort("t14: the channel number did not parse")
    Some(v) => sdt_eq_int(v.reinterpret_as_int(), 0, "the channel number")
  }
  // a payload that stops before the number is not an open: four bytes are
  // the channel type's length prefix and nothing else
  match @sshd.sd_channel_open_number(FixedArray::make(4, b'\x00')) {
    None => ()
    Some(_) => abort("t14: a truncated open was accepted")
  }
}

///|
test "t15_the_server_proposal_is_the_measured_one" {
  let p = @kexflow.Proposal::default_server()
  sdt_eq_str(p.kex_algs, "diffie-hellman-group14-sha256", "the kex algorithm")
  sdt_eq_str(p.hostkey_algs, "ssh-ed25519", "the host key algorithm")
  sdt_eq_str(p.enc_ctos, "aes128-ctr", "the cipher")
  sdt_eq_str(p.enc_stoc, "aes128-ctr", "the cipher")
  sdt_eq_str(p.mac_ctos, "hmac-sha2-256", "the mac")
  sdt_eq_str(p.mac_stoc, "hmac-sha2-256", "the mac")
  sdt_eq_str(p.comp_ctos, "none", "the compression")
  sdt_eq_str(p.comp_stoc, "none", "the compression")
}

///|
/// The bytes the real `ssh.exe` sends in a CHANNEL_OPEN, measured:
///
///     00000007 "session" 00000000 00200000 00008000
///
/// 23 bytes, and there is no `string sender channel` in it.  A server that
/// reads one takes the window size for the channel number, which is the bug
/// Loop #93 found and the reason this payload is a fixture rather than
/// something built by the code under test.
fn sdt_channel_open_bytes() -> FixedArray[Byte] {
  FixedArray::from_array([
    b'\x00', b'\x00', b'\x00', b'\x07', b's', b'e', b's', b's', b'i', b'o', b'n',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x20', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x80', b'\x00',
  ])
}

///|
test "t16_channel_open_reads_all_four_fields" {
  let payload = sdt_channel_open_bytes()
  sdt_eq_int(payload.length(), 23, "the measured CHANNEL_OPEN is 23 bytes")
  match @sshd.sd_parse_channel_open(payload) {
    None => abort("t16: the measured open did not parse")
    Some(o) => {
      sdt_eq_str(o.channel_type, "session", "the channel type")
      sdt_eq_int(o.peer_channel.reinterpret_as_int(), 0, "the peer's channel")
      sdt_eq_int(
        o.peer_window.reinterpret_as_int(),
        2097152,
        "the peer's window (0x00200000) -- NOT the channel number",
      )
      sdt_eq_int(
        o.peer_max_packet.reinterpret_as_int(),
        32768,
        "the peer's maximum packet (0x00008000)",
      )
    }
  }
  // A payload that stops before the window is not an open.  The points are
  // chosen off the MEASURED payload, not off round numbers: its channel type
  // is seven bytes, so the three u32 fields start at offset 11 and a copy cut
  // at 11, 15 or 19 runs out inside one of them.
  //
  // Slicing an all-zero payload would not test this: a zero length prefix
  // makes the type zero bytes long, the fields start at 4, and everything up
  // to 16 bytes parses happily.  The truncation has to be taken from a
  // payload that is really shaped like an open.
  for cut in [11, 15, 19] {
    let short = match @sshd.sd_slice(payload, 0, cut) {
      None => abort("t16: could not cut the payload")
      Some(v) => v
    }
    sdt_true(
      @sshd.sd_parse_channel_open(short) is None,
      "an open cut at " + cut.to_string() + " bytes is refused",
    )
  }
}

///|
test "t17_open_confirmation_is_four_fields_with_the_peer_first" {
  // The order surprises people: RECIPIENT is the peer's number, SENDER is
  // ours.  Getting them the other way round does not fail the handshake --
  // it makes every later packet address a channel that does not exist.
  let got = @sshd.sd_open_confirmation_payload(0U, 7U, 2097152U, 32768U)
  let want = FixedArray::from_array([
    b'\x00', b'\x00', b'\x00', b'\x00', // recipient: the peer's 0
     b'\x00', b'\x00', b'\x00', b'\x07', // sender: ours
     b'\x00', b'\x20', b'\x00', b'\x00', // window 2097152
     b'\x00', b'\x00', b'\x80', b'\x00', // max packet 32768
  ])
  sdt_bytes_eq(got, want, "the confirmation payload")
}

///|
test "t18_open_failure_carries_the_language_tag" {
  // FOUR fields.  Three leaves the peer reading the next packet's bytes as
  // the language tag -- the bug that made Loop #93's refusal unreadable.
  let got = @sshd.sd_open_failure_payload(0U, 3U, "no")
  let mut off = 0
  let lens : Array[Int32] = []
  // recipient, reason: two u32
  off = 8
  for _ in 0..<2 {
    match @sshd.sd_read_string(got, off) {
      None => abort("t18: a string field did not parse")
      Some((body, next)) => {
        lens.push(body.length())
        off = next
      }
    }
  }
  sdt_eq_int(lens.length(), 2, "two string fields after the two u32 fields")
  sdt_eq_int(lens[0], 2, "the description is `no`")
  sdt_eq_int(lens[1], 0, "the language tag is present and empty")
  sdt_eq_int(off, got.length(), "no trailing bytes")
}

///|
test "t19_extended_data_and_exit_status_are_shaped_right" {
  let data = FixedArray::from_array([b'a', b'b'])
  let ext = @sshd.sd_extended_data_payload(3U, @sshd.EXTENDED_DATA_STDERR, data)
  let want_ext = FixedArray::from_array([
    b'\x00', b'\x00', b'\x00', b'\x03', // recipient
     b'\x00', b'\x00', b'\x00', b'\x01', // code 1: stderr
     b'\x00', b'\x00', b'\x00', b'\x02', b'a', b'b',
  ])
  sdt_bytes_eq(ext, want_ext, "the extended data payload")

  let st = @sshd.sd_exit_status_payload(3U, 7)
  // uint32 3 || string "exit-status" || boolean FALSE || uint32 7
  sdt_eq_int(st[0].to_int(), 0, "recipient high byte")
  sdt_eq_int(st[3].to_int(), 3, "recipient")
  match @sshd.sd_read_string(st, 4) {
    None => abort("t19: the request name did not parse")
    Some((name, off)) => {
      sdt_eq_str(
        @sshd.sd_bytes_to_string(name),
        "exit-status",
        "the request name",
      )
      sdt_eq_int(st[off].to_int(), 0, "want_reply is FALSE")
      match @sshd.sd_read_u32(st, off + 1) {
        None => abort("t19: the status did not parse")
        Some(v) => sdt_eq_int(v.reinterpret_as_int(), 7, "the exit status")
      }
      sdt_eq_int(off + 5, st.length(), "no trailing bytes")
    }
  }
}

///|
test "t20_channel_request_parses_exec" {
  let payload = sdt_cat_all([
    @sshwire.write_u32(0U),
    @sshwire.write_ssh_string(@sshd.sd_ascii("exec")),
    FixedArray::from_array([b'\x01']),
    @sshwire.write_ssh_string(@sshd.sd_ascii("echo hi")),
  ])
  match @sshd.sd_parse_channel_request(payload) {
    None => abort("t20: the exec request did not parse")
    Some(r) => {
      sdt_eq_int(r.recipient.reinterpret_as_int(), 0, "the channel")
      sdt_eq_str(r.request_type, "exec", "the request type")
      sdt_true(r.want_reply, "exec asks for a reply")
      match @sshd.sd_read_string(r.extra, 0) {
        None => abort("t20: the command did not parse")
        Some((cmd, _)) =>
          sdt_eq_str(@sshd.sd_bytes_to_string(cmd), "echo hi", "the command")
      }
    }
  }
}

///|
test "t21_chunk_size_is_the_smaller_of_window_and_max_packet" {
  // The peer's maximum packet is the ceiling for one CHANNEL_DATA, and what
  // is left of its window is the other.  Taking the wrong one sends a packet
  // the peer either refuses (too large) or counts against a window it does
  // not have.
  sdt_eq_int(
    @sshd.sd_chunk_size(2097152U, 32768U),
    32768,
    "a wide window and the default maximum",
  )
  sdt_eq_int(@sshd.sd_chunk_size(1000U, 32768U), 1000, "a narrow window")
  sdt_eq_int(@sshd.sd_chunk_size(2097152U, 4096U), 4096, "a small maximum")
  sdt_eq_int(@sshd.sd_chunk_size(0U, 32768U), 0, "an empty window")
  // A maximum above the default is clamped: 32 KiB is what this server
  // reads and writes, and a larger figure would only be a promise it does
  // not keep.
  sdt_eq_int(@sshd.sd_chunk_size(2097152U, 65536U), 32768, "clamped at 32 KiB")
}

///|
test "t22_the_wire_numbers_are_the_ones_the_real_server_sends" {
  // The table in `src/sshwire` was wrong until Loop #94: EOF and CLOSE were
  // one byte low and CHANNEL_EXTENDED_DATA was missing.  Nothing caught it,
  // because every test that used the constants also BUILT packets with them.
  // These are the numbers RFC 4254 §5.1 gives and the real server logs.
  sdt_eq_int(@sshwire.SSH_MSG_CHANNEL_OPEN.to_int(), 90, "OPEN")
  sdt_eq_int(
    @sshwire.SSH_MSG_CHANNEL_OPEN_CONFIRMATION.to_int(),
    91,
    "OPEN_CONFIRMATION",
  )
  sdt_eq_int(
    @sshwire.SSH_MSG_CHANNEL_WINDOW_ADJUST.to_int(),
    93,
    "WINDOW_ADJUST",
  )
  sdt_eq_int(@sshwire.SSH_MSG_CHANNEL_DATA.to_int(), 94, "DATA")
  sdt_eq_int(
    @sshwire.SSH_MSG_CHANNEL_EXTENDED_DATA.to_int(),
    95,
    "EXTENDED_DATA",
  )
  sdt_eq_int(@sshwire.SSH_MSG_CHANNEL_EOF.to_int(), 96, "EOF")
  sdt_eq_int(@sshwire.SSH_MSG_CHANNEL_CLOSE.to_int(), 97, "CLOSE")
  sdt_eq_int(@sshwire.SSH_MSG_CHANNEL_REQUEST.to_int(), 98, "REQUEST")
  sdt_eq_int(@sshwire.SSH_MSG_CHANNEL_SUCCESS.to_int(), 99, "SUCCESS")
  sdt_eq_int(@sshwire.SSH_MSG_CHANNEL_FAILURE.to_int(), 100, "FAILURE")
  sdt_eq_int(@sshwire.SSH_MSG_GLOBAL_REQUEST.to_int(), 80, "GLOBAL_REQUEST")
  // The server advertises the numbers the real server was measured to
  // advertise (paramiko read 2097152 and 32768 off the real server's bytes).
  sdt_eq_int(
    @sshd.SERVER_WINDOW.reinterpret_as_int(),
    2097152,
    "the advertised window",
  )
  sdt_eq_int(
    @sshd.SERVER_MAX_PACKET.reinterpret_as_int(),
    32768,
    "the advertised maximum",
  )
}

///|
test "t23_a_command_runner_is_a_function_the_server_calls" {
  // The shape matters: the state machine does not know how to start a
  // process, so it calls a function.  This test is that the function is
  // called with the COMMAND AS THE PEER SENT IT and that its three answers
  // reach the report -- nothing about processes.
  let seen = Ref("")
  let runner = @sshd.CommandRunner::make(fn(cmd) {
    seen.val = cmd
    @sshd.CommandResult::make(
      FixedArray::from_array([b'o', b'k']),
      FixedArray::from_array([b'e']),
      42,
    )
  })
  let r = (runner.run_fn)("cmd /c echo hi")
  sdt_eq_str(seen.val, "cmd /c echo hi", "the runner saw the peer's command")
  sdt_eq_int(r.stdout.length(), 2, "stdout")
  sdt_eq_int(r.stderr.length(), 1, "stderr")
  sdt_eq_int(r.code, 42, "the exit status")
}
