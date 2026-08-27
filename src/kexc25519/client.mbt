///| 客户端 REPLY 包解析与 ssh-ed25519 签名 blob 解析

///|

///| REPLY(SSH2_MSG_KEX_ECDH_REPLY=31)载荷:

///|   string(K_S hostkey blob) ‖ string(Q_S=f) ‖ string(signature)

///| ssh-ed25519 签名 blob(RFC 4253 § 6.6 / RFC 8309):

///|   string("ssh-ed25519") ‖ string(64B = R ‖ S)

///|
/// 内部游标:严格解析用,任何越界/截断 → None
priv struct Cursor {
  bytes : FixedArray[Byte]
  mut pos : Int
}

///|
fn Cursor::make(bytes : FixedArray[Byte]) -> Cursor {
  { bytes, pos: 0 }
}

///|
fn Cursor::remaining(self : Cursor) -> Int {
  self.bytes.length() - self.pos
}

///|
fn Cursor::read_u32(self : Cursor) -> UInt? {
  if self.remaining() < 4 {
    return None
  }
  let v = self.bytes[self.pos].to_uint() << 24
  let v2 = v | (self.bytes[self.pos + 1].to_uint() << 16)
  let v3 = v2 | (self.bytes[self.pos + 2].to_uint() << 8)
  let v4 = v3 | self.bytes[self.pos + 3].to_uint()
  self.pos = self.pos + 4
  Some(v4)
}

///|
fn Cursor::read_bytes(self : Cursor, n : Int) -> FixedArray[Byte]? {
  if n < 0 || self.remaining() < n {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = self.bytes[self.pos + i]
  }
  self.pos = self.pos + n
  Some(out)
}

///|
fn Cursor::read_string(self : Cursor) -> FixedArray[Byte]? {
  match self.read_u32() {
    Some(len_u) => {
      // 防止 u32 → Int 溢出造成负长度绕过检查
      if len_u > 0x7FFFFFFFU {
        return None
      }
      self.read_bytes(len_u.reinterpret_as_int())
    }
    None => None
  }
}

///|
/// 解析后的 ECDH REPLY 三元组
pub struct KexReply {
  hostkey_blob : FixedArray[Byte] // K_S 原样(供 exchange hash 与验签)
  server_pub : FixedArray[Byte] // Q_S = f,32 字节
  sig_blob : FixedArray[Byte] // 未拆解的签名 string 内容
}

///|
/// 严格解析:三段 string 且必须恰好消费完(尾随数据视为协议违规)
pub fn parse_reply(wire : FixedArray[Byte]) -> KexReply? {
  let c = Cursor::make(wire)
  let hostkey_blob = match c.read_string() {
    Some(b) => b
    None => return None
  }
  let server_pub = match c.read_string() {
    Some(b) => b
    None => return None
  }
  let sig_blob = match c.read_string() {
    Some(b) => b
    None => return None
  }
  if c.remaining() != 0 {
    return None
  }
  // C 在 kex_c25519_dec 里校验 server_blob 长度恰为 CURVE25519_SIZE
  if server_pub.length() != 32 {
    return None
  }
  Some({ hostkey_blob, server_pub, sig_blob })
}

///|
/// 解析出的 ed25519 签名形态(alg 名 + 64B R‖S)
pub struct Ed25519Sig {
  alg_name : FixedArray[Byte]
  rs : FixedArray[Byte] // R(32B) ‖ S(32B)
}

///|
/// 判断是否 ssh-ed25519 算法标识
pub fn sig_is_ed25519(sig : Ed25519Sig) -> Bool {
  let name = "ssh-ed25519"
  if sig.alg_name.length() != name.length() {
    return false
  }
  for i = 0; i < name.length(); i = i + 1 {
    if sig.alg_name[i].to_int() != name[i].to_int() {
      return false
    }
  }
  true
}

///| 解析签名 blob:string(alg) ‖ string(rs);ed25519 要求 rs 恰 64B。

///| 本卷只做格式层;密码学验证由 src/ed25519 的 verify 承担(Loop #7 已三盲验证),

///|
/// 跨包 import 可用后在此直接接线。
pub fn parse_sig(blob : FixedArray[Byte]) -> Ed25519Sig? {
  let c = Cursor::make(blob)
  let alg_name = match c.read_string() {
    Some(b) => b
    None => return None
  }
  let rs = match c.read_string() {
    Some(b) => b
    None => return None
  }
  if c.remaining() != 0 {
    return None
  }
  if rs.length() != 64 {
    return None
  }
  Some({ alg_name, rs })
}
