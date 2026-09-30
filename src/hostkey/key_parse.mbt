///| SSH hostkey blob 解析
///
/// 对应 OpenSSH sshkey.c sshkey_from_blob_internal(allow_cert=false 语义)
/// + sshbuf get_cstring/get_string/get_bignum2_bytes_direct 规则。
/// 行号引用见 docs/hostkey/navigator.md §1。

///|
/// 签名数据上限(sshkey.h L53:1<<20)
pub const MAX_SIGN_DATA_SIZE : Int = 1048576

///|
/// RSA 最小模长位数(sshkey.h L53)
pub const RSA_MIN_MODULUS_BITS : Int = 1024

///|
/// bignum 字节上限(sshbuf.h L36 SSHBUF_MAX_BIGNUM = 16384/8)
pub const MAX_BIGNUM_BYTES : Int = 2048

///|
/// 错误分类(navigator §2,ssherr 一一对应)
pub(all) enum KeyError {
  /// SSH_ERR_INVALID_FORMAT
  InvalidFormat
  /// SSH_ERR_KEY_TYPE_UNKNOWN(impl 表无此名)
  UnsupportedType
  /// SSH_ERR_KEY_CERT_INVALID_SIGN_KEY(!allow_cert 路径)
  CertNotAllowed
  /// SSH_ERR_KEY_TYPE_MISMATCH(sig alg ≠ key type)
  TypeMismatch
  /// SSH_ERR_UNEXPECTED_TRAILING_DATA
  TrailingData
  /// SSH_ERR_BIGNUM_IS_NEGATIVE
  BigNumNegative
  /// SSH_ERR_BIGNUM_TOO_LARGE
  BigNumTooLarge
  /// SSH_ERR_KEY_LENGTH(n < 1024 bits)
  RsaModulusTooShort
  /// SSH_ERR_SIGNATURE_INVALID
  SignatureInvalid
  /// SSH_ERR_INVALID_ARGUMENT(siglen==0 / msg 超限 / 空入参)
  InvalidArgument
  /// SSH_ERR_EC_CURVE_MISMATCH(blob 内 curve 名与 alg 不符)
  EcCurveMismatch
  /// SSH_ERR_KEY_INVALID_EC_VALUE(点不在曲线上/越界/无穷远)
  KeyInvalidEcValue
  /// RSA 密码学验证需 bignum modexp——本 loop 范围外,显式标注
  RsaVerifyUnavailable
}

///|
/// 解析结果
pub(all) enum ParseResult {
  Parsed(HostKey)
  Rejected(KeyError)
}

///|
/// 验证结果
pub(all) enum VerifyResult {
  Accepted
  Rejected(KeyError)
}

///|
/// 主机公钥
///
/// Ed25519Key:pk 恰 32 字节。
/// RsaKey:(e, n) 均为 trim 前导零后的大端字节(空数组表示数值 0)。
/// EcdsaKey:(曲线位数, 规范化未压缩点) —— 点为 0x04 || X || Y,
///   已在解析期通过曲线方程校验。
pub(all) enum HostKey {
  Ed25519Key(FixedArray[Byte])
  RsaKey(FixedArray[Byte], FixedArray[Byte])
  EcdsaKey(Int, FixedArray[Byte])
}

///|
/// offset 式解析游标(错误短路;调用方检查 failed)
priv struct HkCursor {
  bytes : FixedArray[Byte]
  mut off : Int
  mut err : KeyError?
}

///|
fn HkCursor::new(bytes : FixedArray[Byte]) -> HkCursor {
  { bytes, off: 0, err: None, }
}

///|
fn HkCursor::fail(self : HkCursor, e : KeyError) -> Unit {
  if self.err is None {
    self.err = Some(e)
  }
}

///|
fn HkCursor::remaining(self : HkCursor) -> Int {
  self.bytes.length() - self.off
}

///|
/// 取 u32 长度前缀的字节串(get_string 语义);不满足即 fail
fn HkCursor::get_string(self : HkCursor) -> FixedArray[Byte] {
  let empty : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  if self.err is Some(_) {
    return empty
  }
  if self.remaining() < 4 {
    self.fail(InvalidFormat)
    return empty
  }
  let len = read_u32hk(self.bytes, self.off).reinterpret_as_int()
  if len < 0 || len > self.remaining() - 4 {
    // C:get_string 对越界长度返回 SSH_ERR_MESSAGE_INCOMPLETE;
    // 本层统一归 InvalidFormat(连接终止语义一致)
    self.fail(InvalidFormat)
    return empty
  }
  let out : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = self.bytes[self.off + 4 + i]
  }
  self.off = self.off + 4 + len
  out
}

///|
/// 取 cstring(get_cstring 语义):\0 仅允许出现在末位
fn HkCursor::get_cstring(self : HkCursor) -> String {
  let raw = self.get_string()
  if self.err is Some(_) {
    return ""
  }
  for i = 0; i < raw.length() - 1; i = i + 1 {
    if raw[i] == b'\x00' {
      self.fail(InvalidFormat)
      return ""
    }
  }
  // 逐字节构造(String 索引返回 UInt16)
  let sb = StringBuilder()
  for i = 0; i < raw.length(); i = i + 1 {
    sb.write_char(Int::unsafe_to_char(raw[i].to_int()))
  }
  sb.to_string()
}

///|
/// 取 bignum2(get_bignum2_bytes_direct 完整规则):
/// MSB 负数拒绝 / >2049 或 ==2049 且首非 0 拒绝 / trim 前导零
fn HkCursor::get_bignum2(self : HkCursor) -> FixedArray[Byte] {
  let empty : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  if self.err is Some(_) {
    return empty
  }
  if self.remaining() < 4 {
    self.fail(InvalidFormat)
    return empty
  }
  let raw_len = read_u32hk(self.bytes, self.off).reinterpret_as_int()
  if raw_len < 0 || raw_len > self.remaining() - 4 {
    self.fail(InvalidFormat)
    return empty
  }
  let start = self.off + 4
  if raw_len != 0 && (self.bytes[start] & b'\x80') == b'\x80' {
    self.fail(BigNumNegative)
    return empty
  }
  if raw_len > MAX_BIGNUM_BYTES + 1 ||
    (raw_len == MAX_BIGNUM_BYTES + 1 && self.bytes[start] != b'\x00') {
    self.fail(BigNumTooLarge)
    return empty
  }
  // trim 前导零
  let mut first = start
  let end = start + raw_len
  while first < end && self.bytes[first] == b'\x00' {
    first = first + 1
  }
  let n = end - first
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = self.bytes[first + i]
  }
  self.off = end
  out
}

///|
/// 大端读 u32
fn read_u32hk(buf : FixedArray[Byte], off : Int) -> UInt {
  (buf[off].to_uint() << 24) |
  (buf[off + 1].to_uint() << 16) |
  (buf[off + 2].to_uint() << 8) |
  buf[off + 3].to_uint()
}

///|
/// 名字是否为证书类型(C 的 sshkey_type_is_cert 等价:
/// 全名以 -cert-v01@openssh.com 结尾)
fn is_cert_name(name : String) -> Bool {
  name.has_suffix("-cert-v01@openssh.com")
}

///|
/// trim 后大端字节的 bit length;空 → 0
fn bit_length_be(bytes : FixedArray[Byte]) -> Int {
  let n = bytes.length()
  if n == 0 {
    return 0
  }
  let top = bytes[0].to_int()
  let mut bits = 0
  let mut v = top
  while v > 0 {
    bits = bits + 1
    v = v >> 1
  }
  (n - 1) * 8 + bits
}

///|
/// 曲线名 → 位数
fn ecdsa_curve_bits(name : String) -> Int {
  if name == "nistp256" { 256 } else { 384 }
}

///|
/// 解析并校验 ECDSA 公钥点,返回规范化未压缩点字节(0x04 || X || Y)。
/// decode_point 已做长度/格式/曲线方程/坐标范围校验;再 encode_point
/// 得到与输入等价的规范形式,便于后续直接使用。
fn ecdsa_canonical_point(
  name : String,
  qb : FixedArray[Byte]
) -> FixedArray[Byte]? {
  match @ecdsa.Curve::from_name(name) {
    None => None
    Some(c) =>
      match @ecdsa.decode_point(c, qb) {
        None => None
        Some(pt) => @ecdsa.encode_point(c, pt)
      }
  }
}

///|
pub fn HostKey::from_blob(blob : FixedArray[Byte]) -> ParseResult {
  let cur = HkCursor::new(blob)
  let ktype = cur.get_cstring()
  if cur.err is Some(e) {
    return Rejected(e)
  }
  // type_from_name:精确匹配我们的实现表;证书名显式分类
  if is_cert_name(ktype) {
    return Rejected(CertNotAllowed)
  }
  let parsed : HostKey? = match ktype {
    "ssh-ed25519" => {
      let pk = cur.get_string()
      if cur.err is Some(_) {
        None
      } else if pk.length() != 32 {
        // ssh-ed25519.c:111 len != ED25519_PK_SZ → INVALID_FORMAT
        cur.fail(InvalidFormat)
        None
      } else {
        Some(Ed25519Key(pk))
      }
    }
    "ssh-rsa" => {
      let e = cur.get_bignum2()
      if cur.err is Some(_) {
        None
      } else {
        let n = cur.get_bignum2()
        if cur.err is Some(_) {
          None
        } else if bit_length_be(n) < RSA_MIN_MODULUS_BITS {
          // ssh-rsa.c deserialize 内的 check_rsa_length;
          // 先于 trailing 检查(C 同序)
          cur.fail(RsaModulusTooShort)
          None
        } else {
          Some(RsaKey(e, n))
        }
      }
    }
    "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" => {
      // ssh_ecdsa_deserialize_public(ssh-ecdsa.c):
      //   get_cstring(curve) → nid 与 ktype 不符 → SSH_ERR_EC_CURVE_MISMATCH
      //   get_eckey(Q)     → 长度/格式由 get_ec 拒
      //   validate_public  → 不在曲线上/越界 → SSH_ERR_KEY_INVALID_EC_VALUE
      let curve = cur.get_cstring()
      if cur.err is Some(_) {
        None
      } else {
        let want_name = if ktype == "ecdsa-sha2-nistp256" {
          "nistp256"
        } else {
          "nistp384"
        }
        if curve != want_name {
          cur.fail(EcCurveMismatch)
          None
        } else {
          let qb = cur.get_string()
          if cur.err is Some(_) {
            None
          } else {
            match ecdsa_canonical_point(want_name, qb) {
              None => {
                cur.fail(KeyInvalidEcValue)
                None
              }
              Some(canon) => Some(EcdsaKey(ecdsa_curve_bits(want_name), canon))
            }
          }
        }
      }
    }
    _ => {
      cur.fail(UnsupportedType)
      None
    }
  }
  match parsed {
    Some(key) =>
      if cur.remaining() != 0 {
        // sshkey.c:2053 尾部残余
        Rejected(TrailingData)
      } else {
        Parsed(key)
      }
    None =>
      Rejected(
        match cur.err {
          Some(e) => e
          None => InvalidFormat
        },
      )
  }
}
