///| SHA-256 增量更新 + Merkle-Damgård padding

///| 对应 OpenBSD sha2.c SHA256Update + SHA256Pad

///| 把 message 增量加入 SHA-256 状态

///| state: 8 个 u32 hash state

///| buffer: 最多 64 字节缓存(未满一个 block 的部分)

///| bit_count: 消息总 bit 数(用 UInt64 存,SHA-256 spec 是 64-bit length)

///|

///|
/// 调用方负责在 final 时再处理 padding
pub fn s256_update(
  state : FixedArray[UInt],
  buffer : FixedArray[Byte],
  buffer_len : Int, // 当前 buffer 已用字节数
  bit_count : UInt64,
  message : FixedArray[Byte],
) -> (FixedArray[Byte], Int, UInt64) {
  let mut buf_len = buffer_len
  let mut bc = bit_count
  let mut msg_offset = 0
  let mut msg_remaining = message.length()

  // 空消息直接返回
  if msg_remaining == 0 {
    return (buffer, buf_len, bc)
  }

  bc = bc + (msg_remaining * 8).to_uint64()

  // 如果 buffer 非空,先填满 buffer
  if buf_len > 0 {
    let free = s256_block_len - buf_len
    if msg_remaining < free {
      // 整个 msg 装进 buffer 即可
      for i = 0; i < msg_remaining; i = i + 1 {
        buffer[buf_len + i] = message[i]
      }
      return (buffer, buf_len + msg_remaining, bc)
    }
    // 填满 buffer
    for i = 0; i < free; i = i + 1 {
      buffer[buf_len + i] = message[i]
    }
    msg_offset = msg_offset + free
    msg_remaining = msg_remaining - free
    // 处理 buffer (s256_transform)
    let block : FixedArray[UInt] = FixedArray::make(16, 0U)
    for i = 0; i < 16; i = i + 1 {
      block[i] = be8_to_32(buffer, i * 4)
    }
    s256_transform(state, block)
    buf_len = 0
  }

  // 整块处理
  while msg_remaining >= s256_block_len {
    let block : FixedArray[UInt] = FixedArray::make(16, 0U)
    for i = 0; i < 16; i = i + 1 {
      block[i] = be8_to_32(message, msg_offset + i * 4)
    }
    s256_transform(state, block)
    msg_offset = msg_offset + s256_block_len
    msg_remaining = msg_remaining - s256_block_len
  }

  // 剩余部分装入 buffer
  for i = 0; i < msg_remaining; i = i + 1 {
    buffer[buf_len + i] = message[msg_offset + i]
  }
  buf_len = buf_len + msg_remaining

  (buffer, buf_len, bc)
}

///| SHA-256 Merkle-Damgård padding

///| 对应 OpenBSD sha2.c SHA256Pad

///|

///| 输入:state, buffer, buffer_len(0..63), bit_count

///|
/// 输出:已 s256_pad 完整 + s256_transform 后的最终 state
pub fn s256_pad(
  state : FixedArray[UInt],
  buffer : FixedArray[Byte],
  buffer_len : Int,
  bit_count : UInt64,
) -> Unit {
  // Pad with 0x80 byte at current position
  buffer[buffer_len] = b'\x80'
  let mut pos = buffer_len + 1

  // 如果 0x80 后剩余空间不够放 8 字节 length,先 s256_pad 0 到 64 字节,做一次 s256_transform
  if pos > 56 {
    while pos < 64 {
      buffer[pos] = b'\x00'
      pos = pos + 1
    }
    let block : FixedArray[UInt] = FixedArray::make(16, 0U)
    for i = 0; i < 16; i = i + 1 {
      block[i] = be8_to_32(buffer, i * 4)
    }
    s256_transform(state, block)
    pos = 0
  }

  // Pad 0x00 直到 pos == 56
  while pos < 56 {
    buffer[pos] = b'\x00'
    pos = pos + 1
  }

  // Append 64-bit big-endian bit length
  // SHA-256 spec: only 64-bit length (no 128-bit like SHA-512)
  buffer[56] = ((bit_count >> 56) & 0xFFUL).to_byte()
  buffer[57] = ((bit_count >> 48) & 0xFFUL).to_byte()
  buffer[58] = ((bit_count >> 40) & 0xFFUL).to_byte()
  buffer[59] = ((bit_count >> 32) & 0xFFUL).to_byte()
  buffer[60] = ((bit_count >> 24) & 0xFFUL).to_byte()
  buffer[61] = ((bit_count >> 16) & 0xFFUL).to_byte()
  buffer[62] = ((bit_count >> 8) & 0xFFUL).to_byte()
  buffer[63] = (bit_count & 0xFFUL).to_byte()

  let block : FixedArray[UInt] = FixedArray::make(16, 0U)
  for i = 0; i < 16; i = i + 1 {
    block[i] = be8_to_32(buffer, i * 4)
  }
  s256_transform(state, block)
}
