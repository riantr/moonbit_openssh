///| SSH packet framing (RFC 4253 §6)
///|
/// 包结构:
///   uint32  packet_length     (不含 MAC)
///   byte    padding_length    (0-255)
///   byte    payload[N   - padding_length - 1]
///   byte    random_padding[padding_length]
///   byte    mac[mac_length]   (0 unencrypted / 16 chacha20-poly1305 / 20 hmac-sha1 / ...)
///|
/// 最小 packet_length = 1 (padding_length) + 4 (最小 padding) + 0 (payload) = 5
/// 最大 packet_length = 256 * 1024 = 262144 bytes

///|
/// 一个 SSH packet 解包后的内部表示
pub struct SshPacket {
  msg_type : Byte
  payload : FixedArray[Byte]
}

///|
/// 字节流累积器 (用于解析 SSH packet from WebSocket / TCP byte stream)
pub struct SshBuf {
  mut data : FixedArray[Byte]
  mut pos : Int
}

///|
pub fn SshBuf::new() -> SshBuf {
  let buf : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  { data: buf, pos: 0 }
}

///|
/// 把新字节 append 到 buffer
pub fn SshBuf::feed(self : SshBuf, new_data : FixedArray[Byte]) -> Unit {
  let old_len = self.data.length()
  let new_len = old_len + new_data.length()
  let buf : FixedArray[Byte] = FixedArray::make(new_len, b'\x00')
  for i = 0; i < old_len; i = i + 1 {
    buf[i] = self.data[i]
  }
  for i = 0; i < new_data.length(); i = i + 1 {
    buf[old_len + i] = new_data[i]
  }
  self.data = buf
}

///|
/// 跳过已解析的字节 (节省内存)
pub fn SshBuf::compact(self : SshBuf) -> Unit {
  let remaining = self.data.length() - self.pos
  if remaining == 0 {
    self.data = FixedArray::make(0, b'\x00')
    self.pos = 0
    return
  }
  let buf : FixedArray[Byte] = FixedArray::make(remaining, b'\x00')
  for i = 0; i < remaining; i = i + 1 {
    buf[i] = self.data[self.pos + i]
  }
  self.data = buf
  self.pos = 0
}

///|
/// 尝试解析一个完整 SSH packet。返回 Some(packet) 表示成功,None 表示字节不够
pub fn SshBuf::try_parse(self : SshBuf) -> SshPacket? {
  let avail = self.data.length() - self.pos
  // 至少 4 字节 length 头
  if avail < 4 {
    return None
  }
  // 读 packet_length (大端)
  let packet_length = (self.data[self.pos].to_uint() << 24) |
    ((self.data[self.pos + 1].to_uint() << 16) & 0xFF0000U) |
    ((self.data[self.pos + 2].to_uint() << 8) & 0xFF00U) |
    (self.data[self.pos + 3].to_uint() & 0xFFU)
  let packet_length_int = packet_length.reinterpret_as_int()
  if packet_length_int < 5 || packet_length_int > 262144 {
    // 非法长度,放弃 buffer (简化处理)
    return None
  }
  // 检查够不够(4 + packet_length)
  if avail < 4 + packet_length_int {
    return None
  }
  // padding_length
  let padding_length = self.data[self.pos + 4].to_uint()
  let padding_length_int = padding_length.reinterpret_as_int()
  if padding_length_int < 4 {
    return None
  }
  // payload 长度
  let payload_len = packet_length_int - padding_length_int - 1
  if payload_len < 0 {
    return None
  }
  // 读 msg_type + payload
  let msg_type = self.data[self.pos + 5]
  let payload : FixedArray[Byte] = FixedArray::make(payload_len - 1, b'\x00')
  for i = 0; i < payload_len - 1; i = i + 1 {
    payload[i] = self.data[self.pos + 6 + i]
  }
  // 前进 pos 跳过整个 packet (不含 MAC)
  self.pos = self.pos + 4 + packet_length_int
  Some({ msg_type, payload })
}

///|
/// 构造 SSH packet (RFC 4253 §6):
///   1. payload_full = msg_type || payload
///   2. block_size = 8
///   3. padding_length = block_size - (payload_full.length() + 5) % block_size
///      if padding_length < 4: padding_length += block_size
///   4. packet_length = payload_full.length() + padding_length + 1
///   5. padding = random bytes (4..block_size bytes, 至少 4)
///   6. return: u32(packet_length) || u8(padding_length) || payload_full || padding
pub fn make_packet(msg_type : Byte, payload : FixedArray[Byte]) -> FixedArray[Byte] {
  let block_size = 8
  let payload_full_len = 1 + payload.length()
  let total_minus_one = payload_full_len + 4  // 至少 padding_length = 4
  let mut padding_length = (block_size - (total_minus_one % block_size)) % block_size
  if padding_length < 4 {
    padding_length = padding_length + block_size
  }
  let packet_length = payload_full_len + padding_length + 1

  // 构造 packet bytes (without MAC)
  let total = 4 + 1 + payload_full_len + padding_length
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')

  // u32 packet_length (大端)
  let pl_u : UInt = packet_length.reinterpret_as_uint()
  out[0] = ((pl_u >> 24) & 0xFFU).to_byte()
  out[1] = ((pl_u >> 16) & 0xFFU).to_byte()
  out[2] = ((pl_u >> 8) & 0xFFU).to_byte()
  out[3] = (pl_u & 0xFFU).to_byte()

  // u8 padding_length
  out[4] = (padding_length.reinterpret_as_uint() & 0xFFU).to_byte()

  // payload_full = msg_type || payload
  out[5] = msg_type
  for i = 0; i < payload.length(); i = i + 1 {
    out[6 + i] = payload[i]
  }

  // padding (deterministic for Loop #18: zero bytes,length >= 4)
  // 真实 SSH 应是 random bytes,这里为了 byte-exact 验证用 0
  // (Loop #18 mock server 会忽略 padding 内容)
  for i = 0; i < padding_length; i = i + 1 {
    out[6 + payload.length() + i] = b'\x00'
  }
  out
}

///|
/// 读 SSH string (RFC 4251 §5): u32 length + bytes
pub fn read_ssh_string(buf : FixedArray[Byte], offset : Int) -> (FixedArray[Byte], Int) {
  let len = (buf[offset].to_uint() << 24) |
    ((buf[offset + 1].to_uint() << 16) & 0xFF0000U) |
    ((buf[offset + 2].to_uint() << 8) & 0xFF00U) |
    (buf[offset + 3].to_uint() & 0xFFU)
  let len_int = len.reinterpret_as_int()
  let out : FixedArray[Byte] = FixedArray::make(len_int, b'\x00')
  for i = 0; i < len_int; i = i + 1 {
    out[i] = buf[offset + 4 + i]
  }
  (out, offset + 4 + len_int)
}

///|
/// 构造 SSH string (RFC 4251 §5): u32 length + bytes
pub fn write_ssh_string(s : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4 + s.length(), b'\x00')
  let len_u : UInt = s.length().reinterpret_as_uint()
  out[0] = ((len_u >> 24) & 0xFFU).to_byte()
  out[1] = ((len_u >> 16) & 0xFFU).to_byte()
  out[2] = ((len_u >> 8) & 0xFFU).to_byte()
  out[3] = (len_u & 0xFFU).to_byte()
  for i = 0; i < s.length(); i = i + 1 {
    out[4 + i] = s[i]
  }
  out
}

///|
/// 读 SSH uint32 (大端)
pub fn read_u32(buf : FixedArray[Byte], offset : Int) -> UInt {
  (buf[offset].to_uint() << 24) |
    ((buf[offset + 1].to_uint() << 16) & 0xFF0000U) |
    ((buf[offset + 2].to_uint() << 8) & 0xFF00U) |
    (buf[offset + 3].to_uint() & 0xFFU)
}

///|
/// 构造 SSH uint32 (大端)
pub fn write_u32(v : UInt) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  out[0] = ((v >> 24) & 0xFFU).to_byte()
  out[1] = ((v >> 16) & 0xFFU).to_byte()
  out[2] = ((v >> 8) & 0xFFU).to_byte()
  out[3] = (v & 0xFFU).to_byte()
  out
}

///|
/// 读 SSH uint64 (大端)
pub fn read_u64(buf : FixedArray[Byte], offset : Int) -> UInt64 {
  let mut v : UInt64 = 0UL
  for i = 0; i < 8; i = i + 1 {
    v = (v << 8) | (buf[offset + i].to_uint().to_uint64() & 0xFFUL)
  }
  v
}

///|
/// 构造 SSH uint64 (大端)
pub fn write_u64(v : UInt64) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    out[i] = ((v >> ((7 - i) * 8)) & 0xFFUL).to_byte()
  }
  out
}