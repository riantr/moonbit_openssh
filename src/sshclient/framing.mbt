///| SSH transport-agnostic framing (Loop #32).

///|

///|   These are the pure parts of the SSH binary packet protocol: the byte

///|   arithmetic and the field parsing. No I/O happens here, which is the whole

///|   point -- Loop #31's handshake drives a blocking Winsock socket and Loop

///|   #32's drives an async browser transport, and the framing rules are the

///|   easiest thing in the protocol to get subtly wrong. One implementation

///|   serves both, so the two cannot drift apart.
///

///|   Two rules carry most of the risk, and both were learned the hard way in

///|   Loop #31:

///|

///|     * `packet_length` is congruent to 4 (mod 8), not 0. The length field

///|       counts itself, so the multiple-of-8 requirement lands on

///|       `4 + packet_length`.

///|     * the payload begins at offset 6 of the assembled buffer -- four

///|       length bytes, one padding_length byte, one message-type byte.

///|

///| Build one complete plaintext SSH packet, ready to write to the transport.
///

///| `pad_byte` seeds the padding so a caller can keep the transcript

///| reproducible; a real client must pass unpredictable bytes (RFC 4253

///|
/// requires the padding be unpredictable, or packet lengths leak plaintext).
pub fn build_plain_packet(
  msg_type : Byte,
  payload : FixedArray[Byte],
  pad_byte : Byte,
) -> FixedArray[Byte] {
  // padding_length byte + payload, before padding
  let unpadded = 2 + payload.length()
  let mut pad = 4 // RFC 4253 section 6: padding is at least 4 bytes
  while (unpadded + pad) % 8 != 4 {
    pad = pad + 1
  }
  let packet_length = unpadded + pad
  let pkt : FixedArray[Byte] = FixedArray::make(4 + packet_length, pad_byte)
  pkt[0] = ((packet_length >> 24) & 0xFF).to_byte()
  pkt[1] = ((packet_length >> 16) & 0xFF).to_byte()
  pkt[2] = ((packet_length >> 8) & 0xFF).to_byte()
  pkt[3] = (packet_length & 0xFF).to_byte()
  pkt[4] = pad.to_byte()
  pkt[5] = msg_type
  let mut i = 0
  while i < payload.length() {
    pkt[6 + i] = payload[i]
    i = i + 1
  }
  pkt
}

///|

///| Split one packet body (everything after the 4-byte length prefix) into its

///| message type and payload.
///

///| `body` is `[padding_length][type][payload][padding]`, so the payload is

///| `body.length - padding_length - 2`. Getting that off by one appends a

///| padding byte to the payload, which every strict parser then rejects as

///|
/// trailing data -- a confusing failure that looks like a parser bug.
pub fn parse_plain_packet(body : FixedArray[Byte]) -> (Byte, FixedArray[Byte])? {
  let total = body.length()
  if total < 2 {
    return None
  }
  let pad = body[0].to_int()
  let payload_len = total - pad - 2
  if payload_len < 0 {
    return None
  }
  let msg_type = body[1]
  let payload : FixedArray[Byte] = FixedArray::make(payload_len, b'\x00')
  let mut i = 0
  while i < payload_len {
    payload[i] = body[2 + i]
    i = i + 1
  }
  Some((msg_type, payload))
}

///|

///| Validate a `packet_length` read off the wire, given the minimum packet

///|
/// size and a sanity ceiling.
pub fn packet_length_ok(len : Int32, max : Int32) -> Bool {
  len >= 8 && len <= max && len % 8 == 4
}

///|

///|
/// Interpret 4 big-endian length bytes. `head` must have at least 4 bytes.
pub fn be32(head : FixedArray[Byte]) -> Int32 {
  (head[0].to_int() << 24) |
  (head[1].to_int() << 16) |
  (head[2].to_int() << 8) |
  head[3].to_int()
}

///|

///| Copy `buf[off .. off+len]` into a new array.
///

///| MoonBit has no slice syntax on FixedArray, so every ranged read in this

///| file builds its result explicitly. Doing it one function means the bounds

///|
/// checks live in exactly one place.
pub fn slice_bytes(
  buf : FixedArray[Byte],
  off : Int32,
  len : Int32,
) -> FixedArray[Byte]? {
  if off < 0 || len < 0 || off + len > buf.length() {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  let mut i = 0
  while i < len {
    out[i] = buf[off + i]
    i = i + 1
  }
  Some(out)
}

///|

///| Read one SSH string (u32 length prefix, then that many bytes) starting at

///|
/// `off`. Returns the body and the offset just past it.
pub fn read_field(
  b : FixedArray[Byte],
  off : Int32,
) -> (FixedArray[Byte], Int32)? {
  if off < 0 || off + 4 > b.length() {
    return None
  }
  let ln = (b[off].to_int() << 24) |
    (b[off + 1].to_int() << 16) |
    (b[off + 2].to_int() << 8) |
    b[off + 3].to_int()
  match slice_bytes(b, off + 4, ln) {
    None => None
    Some(body) => Some((body, off + 4 + ln))
  }
}

///|

///| Parse an SSH_MSG_KEX_ECDH_REPLY payload:

///| `string K_S` `mpint f` `string signature` (RFC 5656 section 3.1).

///|

///| Trailing bytes are rejected rather than ignored. A strict parser is the

///| right side to err on here: the signature covers the exchange hash, and

///| quietly ignoring surplus bytes here would make a future field addition

///|
/// look like a signing bug somewhere far away.
pub fn parse_ecdh_reply(
  payload : FixedArray[Byte],
) -> (FixedArray[Byte], FixedArray[Byte], FixedArray[Byte])? {
  match read_field(payload, 0) {
    None => None
    Some((ks, off1)) =>
      match read_field(payload, off1) {
        None => None
        Some((f_wire, off2)) =>
          match read_field(payload, off2) {
            None => None
            Some((sig, off3)) =>
              if off3 != payload.length() {
                None
              } else {
                Some((ks, f_wire, sig))
              }
          }
      }
  }
}

///|

///| Find the CRLF that ends an identification line and return the line without

///| it, plus the offset just past the CRLF.
///

///| A server may send informational lines before its `SSH-` line, so the

///|
/// caller loops until one starts with `SSH-`.
pub fn take_ident_line(buf : FixedArray[Byte], off : Int32) -> (String, Int32)? {
  let mut i = off
  while i + 1 < buf.length() {
    if buf[i] == b'\r' && buf[i + 1] == b'\n' {
      return match slice_bytes(buf, off, i - off) {
        None => None
        Some(line) => Some((bytes_to_string(line), i + 2))
      }
    }
    i = i + 1
  }
  None
}

///|

///|
/// ASCII text to bytes.
pub fn ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///|

///| Prepend an SSH message-type byte to a payload, yielding the complete

///| message payload. The exchange hash needs this in front of I_C / I_S;

///|
/// OpenSSH calls it a "fake header" (kexgen.c:70-75).
pub fn with_type(
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(payload.length() + 1, msg_type)
  for i = 0; i < payload.length(); i = i + 1 {
    out[1 + i] = payload[i]
  }
  out
}

///|

///|
/// Concatenate two byte arrays.
pub fn cat2(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
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

///|

///|
/// Bytes to a String, for the identification phase (which is ASCII by spec).
pub fn bytes_to_string(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}
