///| Loop #93: the small pure helpers this package needs.
///
/// `src/userauth` sets the precedent and the reason (userauth.mbt:51): these
/// are re-written here rather than imported from `src/sshclient`, because
/// importing the client would drag `src/tcp` in behind it and make the
/// SERVER depend on the CLIENT.  Four lines of concatenation are a much
/// cheaper price than an inverted dependency arrow.
///
/// The same reasoning applies to `src/sshwire`: that one IS imported, because
/// it is the wire format and both halves of SSH speak it.  The line is drawn
/// at "the format" and not at "the other end of the connection".

///|
/// ASCII text to bytes.
///
/// The identification string and the algorithm names are ASCII by
/// specification (RFC 4253 §4.2, RFC 4251 §5), so this truncates rather
/// than fails on a byte above 0x7F.
pub fn sd_ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///|
/// Concatenate two byte arrays.
pub fn sd_cat2(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
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
/// Concatenate three byte arrays.
pub fn sd_cat3(
  a : FixedArray[Byte],
  b : FixedArray[Byte],
  c : FixedArray[Byte],
) -> FixedArray[Byte] {
  sd_cat2(sd_cat2(a, b), c)
}

///|
/// Bytes to a String, for the identification phase (ASCII by specification).
pub fn sd_bytes_to_string(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
/// A copy of `b` from `off`, `len` bytes long.
///
/// MoonBit has no slice syntax on `FixedArray`, so every ranged read builds
/// its result explicitly.  Doing it in one place means the bounds checks
/// live in exactly one place -- and the bounds are checked here rather than
/// left to the caller, because a server reads fields off the wire and the
/// wire is not to be trusted.
pub fn sd_slice(
  b : FixedArray[Byte],
  off : Int32,
  len : Int32,
) -> FixedArray[Byte]? {
  if off < 0 || len < 0 || off + len > b.length() {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = b[off + i]
  }
  Some(out)
}

///|
/// Read one SSH string (a u32 length prefix and that many bytes) at `off`.
///
/// Returns the body and the offset just past it, or `None` when the buffer
/// does not hold a well-formed string there.  A trailing byte count that
/// does not fit is a failure and not a truncation: a server that silently
/// accepts half a field is a server that will agree with the wrong peer.
pub fn sd_read_string(
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
  match sd_slice(b, off + 4, ln) {
    None => None
    Some(body) => Some((body, off + 4 + ln))
  }
}

///|
/// Read one byte at `off`, or `None`.
pub fn sd_read_u8(b : FixedArray[Byte], off : Int32) -> Byte? {
  if off < 0 || off >= b.length() {
    return None
  }
  Some(b[off])
}

///|
/// Read one big-endian u32 at `off`, or `None`.
///
/// The channel layer has fixed-width numeric fields (RFC 4254 §5.1), and a
/// server that reads them off the wire has to read them the way the peer
/// wrote them -- big endian, four bytes -- rather than guessing.
pub fn sd_read_u32(b : FixedArray[Byte], off : Int32) -> UInt32? {
  if off < 0 || off + 4 > b.length() {
    return None
  }
  Some(
    (b[off].to_uint() << 24) |
    (b[off + 1].to_uint() << 16) |
    (b[off + 2].to_uint() << 8) |
    b[off + 3].to_uint(),
  )
}

///|
/// Prepend an SSH message-type byte to a payload.
///
/// The exchange hash needs this in front of I_C / I_S: OpenSSH calls it a
/// "fake header" (kexgen.c:70-75).  The result is the complete KEXINIT
/// message, and it is length-prefixed once by the caller.
pub fn sd_with_type(
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(payload.length() + 1, msg_type)
  for i = 0; i < payload.length(); i = i + 1 {
    out[i + 1] = payload[i]
  }
  out
}

///|
/// The hex of a byte array, for diagnostics and for the gate's failure
/// messages.  Lower case, no separators -- the same shape the rest of the
/// repository prints, so a reader does not have to learn two conventions.
pub fn sd_hex(b : FixedArray[Byte]) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_char(Int32::unsafe_to_char(digits[v / 16].to_int()))
    sb.write_char(Int32::unsafe_to_char(digits[v % 16].to_int()))
  }
  sb.to_string()
}
