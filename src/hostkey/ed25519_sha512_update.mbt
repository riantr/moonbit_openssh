///| SHA-512 增量更新 + Merkle-Damgård padding

///| 对应 OpenBSD sha2.c SHA512Update + SHA512Pad

///| 把 message 增量加入 SHA-512 状态

///| state: 8 个 u64 hash state

///| buffer: 最多 128 字节缓存

///|
/// bit_count: 消息总 bit 数(UInt64,SHA-512 限制 < 2^128)
pub fn update(
  state : FixedArray[UInt64],
  buffer : FixedArray[Byte],
  buffer_len : Int32,
  bit_count : UInt64,
  message : FixedArray[Byte],
) -> (FixedArray[Byte], Int32, UInt64) {
  let mut buf_len = buffer_len
  let mut bc = bit_count
  let mut msg_offset = 0
  let mut msg_remaining = message.length()

  if msg_remaining == 0 {
    return (buffer, buf_len, bc)
  }

  bc = bc + (msg_remaining * 8).to_uint64()

  if buf_len > 0 {
    let free = block_len - buf_len
    if msg_remaining < free {
      for i = 0; i < msg_remaining; i = i + 1 {
        buffer[buf_len + i] = message[i]
      }
      return (buffer, buf_len + msg_remaining, bc)
    }
    for i = 0; i < free; i = i + 1 {
      buffer[buf_len + i] = message[i]
    }
    msg_offset = msg_offset + free
    msg_remaining = msg_remaining - free
    let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
    for i = 0; i < 16; i = i + 1 {
      block[i] = be8_to_64(buffer, i * 8)
    }
    transform(state, block)
    buf_len = 0
  }

  while msg_remaining >= block_len {
    let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
    for i = 0; i < 16; i = i + 1 {
      block[i] = be8_to_64(message, msg_offset + i * 8)
    }
    transform(state, block)
    msg_offset = msg_offset + block_len
    msg_remaining = msg_remaining - block_len
  }

  for i = 0; i < msg_remaining; i = i + 1 {
    buffer[buf_len + i] = message[msg_offset + i]
  }
  buf_len = buf_len + msg_remaining

  (buffer, buf_len, bc)
}

///|
/// SHA-512 Merkle-Damgård padding (128-bit 长度)
pub fn pad(
  state : FixedArray[UInt64],
  buffer : FixedArray[Byte],
  buffer_len : Int32,
  bit_count : UInt64,
) -> Unit {
  buffer[buffer_len] = b'\x80'
  let mut pos = buffer_len + 1

  // 如果 0x80 后剩余空间不够放 16 字节 length,先 pad 0 到 128 字节,做一次 transform
  if pos > 112 {
    while pos < 128 {
      buffer[pos] = b'\x00'
      pos = pos + 1
    }
    let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
    for i = 0; i < 16; i = i + 1 {
      block[i] = be8_to_64(buffer, i * 8)
    }
    transform(state, block)
    pos = 0
  }

  while pos < 112 {
    buffer[pos] = b'\x00'
    pos = pos + 1
  }

  // Append 128-bit big-endian bit length(高 64-bit 总是 0)
  for i = 0; i < 8; i = i + 1 {
    buffer[112 + i] = b'\x00'
  }
  buffer[120] = ((bit_count >> 56) & 0xFFUL).to_byte()
  buffer[121] = ((bit_count >> 48) & 0xFFUL).to_byte()
  buffer[122] = ((bit_count >> 40) & 0xFFUL).to_byte()
  buffer[123] = ((bit_count >> 32) & 0xFFUL).to_byte()
  buffer[124] = ((bit_count >> 24) & 0xFFUL).to_byte()
  buffer[125] = ((bit_count >> 16) & 0xFFUL).to_byte()
  buffer[126] = ((bit_count >> 8) & 0xFFUL).to_byte()
  buffer[127] = (bit_count & 0xFFUL).to_byte()

  let block : FixedArray[UInt64] = FixedArray::make(16, 0UL)
  for i = 0; i < 16; i = i + 1 {
    block[i] = be8_to_64(buffer, i * 8)
  }
  transform(state, block)
}
