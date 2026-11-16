///| Loop #93: the server's side of the byte stream.
///
/// The client has the same three functions in `src/sshclient/live.mbt`
/// (`send_packet`, `recv_packet`, `read_ident_line`).  They are written
/// again here rather than imported, for the reason `src/userauth` gives: the
/// server must not depend on the client package, which drags `src/tcp` in
/// with it and inverts the dependency arrow between the two halves of SSH.
///
/// What IS shared is the packet layer itself: `@bpacket`'s `SendCtx` and
/// `RecvCtx` do the framing, the padding rule, the cipher and the MAC, and
/// they are direction-neutral -- the server and the client differ only in
/// WHICH key each context is built from.

///|
/// How many bytes have gone each way.
///
/// The server keeps this for the same reason the client does: it is the
/// only place a truncated transfer shows up, and a truncated transfer is
/// otherwise indistinguishable from a peer that simply went quiet.
pub(all) struct WireCounters {
  mut sent : Int32
  mut recv : Int32
}

///|
/// The result of receiving one packet.
///
/// `Closed` and `BadPacket` are different answers and have to stay
/// different: the first is a peer that hung up, the second is a peer whose
/// bytes do not make sense (a MAC that does not verify is the usual one).
/// Collapsing them would report a key mismatch as a network failure.
pub(all) enum RecvOutcome {
  Packet(Byte, FixedArray[Byte])
  Closed
  BadPacket(String)
}

///|
/// Send one SSH packet.
///
/// The padding is zeros.  RFC 4253 §6 asks for unpredictable padding so that
/// packet lengths do not leak plaintext, and a production server should
/// supply it from the CSPRNG -- but the same trade this repository's client
/// makes is the right one here: a byte-exact transcript is worth more than
/// the leak, and `@bpacket`'s `pad_src` is the single place to change it.
pub fn[T : @transport.Transport] sd_send_packet(
  conn : T,
  counters : WireCounters,
  s : @bpacket.SendCtx,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> Bool {
  let pad_src : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  match s.emit(msg_type, payload, pad_src) {
    Ok(pkt) => {
      if !conn.wire_send(pkt.wire) {
        return false
      }
      counters.sent = counters.sent + pkt.wire.length()
      true
    }
    _ => false
  }
}

///|
/// Read exactly one SSH packet.
///
/// The read has to be EXACT, not chunked: once a packet has been consumed
/// the next read is for the message after it, and a chunked reader would
/// wait for bytes that will not arrive until we answer.  So the length is
/// asked for first -- `RecvCtx::wire_len_from_header` decrypts the four
/// length bytes for us once the transport is encrypted -- and only then is
/// the rest pulled in.
pub fn[T : @transport.Transport] sd_recv_packet(
  conn : T,
  counters : WireCounters,
  r : @bpacket.RecvCtx,
) -> RecvOutcome {
  let hdr = match conn.wire_read_exact(4) {
    None => return Closed
    Some(h) => h
  }
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
    match conn.wire_read_exact(rest) {
      None => return Closed
      Some(b) => b
    }
  }
  counters.recv = counters.recv + 4 + rest
  match r.recv(sd_cat2(hdr, body)).event {
    @bpacket.Packet(_, t, payload) => Packet(t, payload)
    @bpacket.NeedMore => Closed
    @bpacket.Failed(e) => BadPacket(sd_packet_error_label(e))
  }
}

///|
/// The name of a packet-layer failure.
///
/// The names are the ones the client uses, on purpose: the gate reads them,
/// and two halves of SSH that call the same failure different things are
/// two halves that will be read differently.
pub fn sd_packet_error_label(e : @bpacket.PacketError) -> String {
  match e {
    @bpacket.BadLength(n) => "bad_length:" + n.to_string()
    @bpacket.AlignError(n) => "align_error:" + n.to_string()
    @bpacket.AuthFailed => "auth_failed"
    @bpacket.MacInvalid => "mac_invalid"
    @bpacket.BadPadlen(n) => "badpadlen:" + n.to_string()
    @bpacket.PadOverflow(n) => "pad_overflow:" + n.to_string()
    @bpacket.EmptyPayload => "empty_payload"
    @bpacket.BadType(n) => "bad_type:" + n.to_string()
    @bpacket.SeqnrWrapInitial => "seqnr_wrap_initial"
  }
}

///|
/// Read one CRLF-terminated identification line.
///
/// Bounded, so a peer that never sends a newline cannot make the server
/// read forever.  The bound is 255 bytes because that is what RFC 4253 §4.2
/// allows for the identification string.
pub fn[T : @transport.Transport] sd_read_ident_line(
  conn : T,
  counters : WireCounters,
  max_bytes : Int32,
) -> String? {
  let mut acc : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  let mut total = 0
  while total < max_bytes {
    let b = match conn.wire_read_exact(1) {
      None => return None
      Some(v) => v
    }
    counters.recv = counters.recv + 1
    total = total + 1
    let one : FixedArray[Byte] = FixedArray::make(1, b[0])
    acc = sd_cat2(acc, one)
    if acc.length() >= 2 &&
      acc[acc.length() - 2] == b'\r' &&
      acc[acc.length() - 1] == b'\n' {
      let n = acc.length() - 2
      let line : FixedArray[Byte] = FixedArray::make(n, b'\x00')
      for i = 0; i < n; i = i + 1 {
        line[i] = acc[i]
      }
      return Some(sd_bytes_to_string(line))
    }
  }
  None
}
