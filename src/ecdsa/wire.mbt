///| SSH wire encoding for ECDSA host keys (Loop #30 G3)
///
///   Public key blob (RFC 5656 3.1 + OpenSSH ssh_ecdsa_serialize_public):
///       string  "ecdsa-sha2-nistp256"
///       string  "nistp256"
///       string  Q                      ; SEC1 2.3.3 octet string
///
///   Signature blob (RFC 5656 3.1.2, OpenSSH ssh_ecdsa_sign,
///   ssh-ecdsa.c:383-388):
///       string  "ecdsa-sha2-nistp256"
///       mpint   r
///       mpint   s
///
///   RFC 5656 mandates `mpint`, and OpenSSH implements it with
///   sshbuf_put_bignum2 (sshbuf-getput-crypto.c:130-150): minimal-length
///   big-endian, with a single 0x00 prepended when the high bit of the first
///   byte is set. That detail is not cosmetic -- P-256 r and s are full-width,
///   so roughly half of all real signatures take the sign-byte path, and a
///   fixed-length encoder interoperates with OpenSSH only by luck.
///
///   Q is always emitted uncompressed. RFC 5656 says compression MAY be used,
///   but OpenSSH's get_ec() accepts only 0x04 and sshbuf_put_ec() only ever
///   emits 0x04, so this decoder is deliberately narrowed to match the
///   implementation it has to interoperate with.

///|
/// Concatenate two byte arrays.
pub fn cat(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
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
/// SSH `string`: u32 big-endian length prefix followed by the bytes.
pub fn put_string(s : FixedArray[Byte]) -> FixedArray[Byte] {
  let n = s.length()
  let out : FixedArray[Byte] = FixedArray::make(4 + n, b'\x00')
  out[0] = ((n >> 24) & 0xFF).to_byte()
  out[1] = ((n >> 16) & 0xFF).to_byte()
  out[2] = ((n >> 8) & 0xFF).to_byte()
  out[3] = (n & 0xFF).to_byte()
  for i = 0; i < n; i = i + 1 {
    out[4 + i] = s[i]
  }
  out
}

///|
/// RFC 4251 mpint body (no length prefix), matching OpenSSH sshbuf_put_bignum2.
/// Zero encodes as a zero-length string, which is what `BN_num_bytes(0) == 0`
/// produces on the OpenSSH side.
pub fn mpint_body(v : @bigint.BigNat) -> FixedArray[Byte] {
  let raw = @bigint.BigNat::to_bytes_be(v)
  if raw.length() == 0 {
    return raw
  }
  if (raw[0] & b'\x80') == b'\x00' {
    return raw
  }
  let out : FixedArray[Byte] = FixedArray::make(raw.length() + 1, b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i + 1] = raw[i]
  }
  out
}

///|
/// BigNat as a fixed-width big-endian byte string, left-padded with zeros.
/// Returns None when the value does not fit.
pub fn bignat_to_fixed_be(v : @bigint.BigNat, n : Int32) -> FixedArray[Byte]? {
  let raw = @bigint.BigNat::to_bytes_be(v)
  if raw.length() > n {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let off = n - raw.length()
  for i = 0; i < raw.length(); i = i + 1 {
    out[off + i] = raw[i]
  }
  Some(out)
}

///|
/// Field size in bytes (32 for P-256, 48 for P-384).
pub fn Curve::field_bytes(c : Curve) -> Int32 {
  c.bits / 8
}

///|
/// The SSH domain-parameter name: "nistp256" / "nistp384".
pub fn Curve::curve_name(c : Curve) -> String {
  if c.bits == 256 {
    "nistp256"
  } else {
    "nistp384"
  }
}

///|
/// Build a Curve from an SSH curve name. Returns None for unknown domains.
pub fn Curve::from_name(name : String) -> Curve? {
  if name == "nistp256" {
    Some(Curve::p256())
  } else if name == "nistp384" {
    Some(Curve::p384())
  } else {
    None
  }
}

// ============================================================================
// Point encoding
// ============================================================================

///|
/// SEC1 uncompressed point encoding: 0x04 || X || Y, always field-size wide.
pub fn encode_point(c : Curve, p : Point) -> FixedArray[Byte]? {
  if p.inf {
    return None
  }
  let fs = Curve::field_bytes(c)
  let xb = bignat_to_fixed_be(p.x, fs)
  let yb = bignat_to_fixed_be(p.y, fs)
  match (xb, yb) {
    (Some(x), Some(y)) => {
      let out : FixedArray[Byte] = FixedArray::make(1 + 2 * fs, b'\x00')
      out[0] = b'\x04'
      for i = 0; i < fs; i = i + 1 {
        out[1 + i] = x[i]
        out[1 + fs + i] = y[i]
      }
      Some(out)
    }
    _ => None
  }
}

///|
/// Parse an uncompressed point. Enforces the exact SEC1 length, rejects the
/// infinity marker, rejects out-of-range coordinates, and checks the curve
/// equation -- OpenSSH's get_ec() does the length/format check and lets
/// EC_POINT_oct2point do the rest, so a point off the curve never reaches
/// the verification step.
pub fn decode_point(c : Curve, b : FixedArray[Byte]) -> Point? {
  let fs = Curve::field_bytes(c)
  if b.length() != 1 + 2 * fs {
    return None
  }
  if b[0] != b'\x04' {
    return None
  }
  let xb : FixedArray[Byte] = FixedArray::make(fs, b'\x00')
  let yb : FixedArray[Byte] = FixedArray::make(fs, b'\x00')
  for i = 0; i < fs; i = i + 1 {
    xb[i] = b[1 + i]
    yb[i] = b[1 + fs + i]
  }
  let x = @bigint.BigNat::from_bytes_be(xb)
  let y = @bigint.BigNat::from_bytes_be(yb)
  if @bigint.BigNat::cmp(x, c.p) >= 0 {
    return None
  }
  if @bigint.BigNat::cmp(y, c.p) >= 0 {
    return None
  }
  let pt = Point::new(x, y)
  if !Curve::on_curve(c, pt) {
    return None
  }
  Some(pt)
}

// ============================================================================
// Key blob
// ============================================================================

///|
/// Full SSH public key blob, i.e. what a server sends as `string K_S` in
/// SSH_MSG_KEX_ECDH_REPLY.
pub fn encode_pubkey_blob(c : Curve, q : Point) -> FixedArray[Byte]? {
  match encode_point(c, q) {
    None => None
    Some(pt) =>
      Some(
        cat(
          cat(
            put_string(str_bytes(c.ssh_name())),
            put_string(str_bytes(c.curve_name())),
          ),
          put_string(pt),
        ),
      )
  }
}

///|
/// Parse an SSH ECDSA public key blob. The trailing-data check mirrors
/// sshkey_from_blob_internal: a blob with extra bytes is rejected outright.
pub fn decode_pubkey_blob(blob : FixedArray[Byte]) -> (Curve, Point)? {
  let s1 = read_string(blob, 0)
  match s1 {
    None => None
    Some((alg, o1)) => {
      let s2 = read_string(blob, o1)
      match s2 {
        None => None
        Some((cname, o2)) => {
          let s3 = read_string(blob, o2)
          match s3 {
            None => None
            Some((qb, o3)) => {
              if o3 != blob.length() {
                return None
              }
              let an = as_string(alg)
              if an != "ecdsa-sha2-nistp256" && an != "ecdsa-sha2-nistp384" {
                return None
              }
              match Curve::from_name(as_string(cname)) {
                None => None
                Some(c) =>
                  if c.ssh_name() != an {
                    None
                  } else {
                    match decode_point(c, qb) {
                      None => None
                      Some(q) => Some((c, q))
                    }
                  }
              }
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// Signature blob
// ============================================================================

///|
/// Full SSH ECDSA signature blob.
///
/// 外层是**两个** string,不是三个字段:
///
///     string  key_type            ("ecdsa-sha2-nistp256")
///     string  signature_blob      (mpint r ‖ mpint s)
///
/// 这层包装很容易写漏,因为 mpint 的 wire 形式本身就是"长度前缀 + 字节",
/// 少包一层之后前 4 个字节会被服务端当成 r 的长度读走——r 读出来是一坨巨大的
/// 数字,然后读 s 时缓冲已空,失败点被报成一个笼统的 "signature unverified",
/// 和「公钥不对」「数学错了」完全分不开。
///
/// 权威依据:
///   * ssh-ecdsa.c:431-432 `sshbuf_get_cstring(b,&ktype) || sshbuf_froms(b,&sigbuf)`,
///     随后从 sigbuf 里连读两个 `sshbuf_get_bignum2`。
///   * paramiko `ECDSAKey.sign_ssh_data`:`add_string(key_format_identifier)`
///     之后 `add_string(self._sigencode(r, s))`,而 `_sigencode` 是
///     `add_mpint(r) ‖ add_mpint(s)` —— 外面确实还有一层。
///   * 本仓 src/hostkey/sig_verify.mbt:71-88(验主机签名,Loop #31 已对真
///     sshd 验证过)走的就是 `get_cstring(alg) + get_string(inner)` 的顺序。
///     那个文件是对的;这里的编码器早于它且没跟上,本轮才暴露。
pub fn encode_sig_blob(c : Curve, sig : Signature) -> FixedArray[Byte] {
  cat(
    put_string(str_bytes(c.ssh_name())),
    put_string(
      cat(put_string(mpint_body(sig.r)), put_string(mpint_body(sig.s))),
    ),
  )
}

///|
/// Decode an unsigned integer from an SSH `string` body, per RFC 4251 mpint
/// exactly as OpenSSH's sshbuf_get_bignum2 does: minimal-length big-endian
/// with a 0x00 sign pad when the high bit is set.
///
///   A body of field_len+1 bytes must start with 0x00, and a body of
///   field_len bytes or fewer must have its high bit clear -- otherwise it is
///   a negative mpint and is rejected. That means a full-width 32-byte P-256 r
///   whose top bit is set is *not* accepted: RFC 5656 3.1.2 says `mpint`, and
///   the conformant encoding for such an r is 33 bytes with a leading zero.
///   Length alone is not the test, which is why a fixed-width encoder looks
///   right and interoperates only by luck.
pub fn decode_ecdsa_int(
  b : FixedArray[Byte],
  field_len : Int32,
) -> @bigint.BigNat? {
  if b.length() == 0 {
    return Some(@bigint.BigNat::from_uint64(0UL))
  }
  if b.length() == field_len + 1 {
    // Exactly the OpenSSH mpint shape; the leading byte must be the sign pad.
    if b[0] != b'\x00' {
      return None
    }
    return Some(@bigint.BigNat::from_bytes_be(b))
  }
  if b.length() > field_len {
    return None
  }
  if (b[0] & b'\x80') == b'\x80' {
    // High bit set with no sign pad: a negative mpint. Rejecting this is what
    // stops a fixed-width encoder from being silently misread.
    return None
  }
  Some(@bigint.BigNat::from_bytes_be(b))
}

///|
/// Parse an SSH ECDSA signature blob for the given curve.
///
/// 与 `encode_sig_blob` 互为镜像:外层两个 string,第二个 string 里装
/// `mpint r ‖ mpint s`。少一层包装时,第二个 string 会被整段当成 r,
/// 接着读 s 必然越界——所以这里对「内层必须恰好读完」和「外层不许有残余」
/// 都要显式判掉。
pub fn decode_sig_blob(c : Curve, blob : FixedArray[Byte]) -> Signature? {
  let fs = Curve::field_bytes(c)
  let s1 = read_string(blob, 0)
  match s1 {
    None => None
    Some((alg, o1)) => {
      if as_string(alg) != c.ssh_name() {
        return None
      }
      let inner = read_string(blob, o1)
      match inner {
        None => None
        Some((body, o2)) => {
          if o2 != blob.length() {
            return None
          }
          let rb = read_string(body, 0)
          match rb {
            None => None
            Some((rbytes, ro)) => {
              let sb = read_string(body, ro)
              match sb {
                None => None
                Some((sbytes, so)) => {
                  if so != body.length() {
                    return None
                  }
                  match
                    (decode_ecdsa_int(rbytes, fs), decode_ecdsa_int(sbytes, fs)) {
                    (Some(r), Some(s)) => Some(Signature::new(r, s))
                    _ => None
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

// ============================================================================
// Small helpers
// ============================================================================

///|
/// Read an SSH `string` at `off`; returns the bytes and the next offset.
pub fn read_string(
  b : FixedArray[Byte],
  off : Int32,
) -> (FixedArray[Byte], Int32)? {
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

///|
/// Lossy view of bytes as a String, for algorithm-name comparison.
fn as_string(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
/// String -> bytes, for the literal algorithm names.
pub fn str_bytes(s : String) -> FixedArray[Byte] {
  let n = s.length()
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = s.unsafe_get(i).to_byte()
  }
  out
}

///|
/// Uppercase hex of a byte array, for KAT diffing.
pub fn bytes_to_hex(b : FixedArray[Byte]) -> String {
  let hex = "0123456789ABCDEF"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_string(hex.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(hex.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}
