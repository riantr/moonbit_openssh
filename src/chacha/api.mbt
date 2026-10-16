///| ChaCha20 公开 API — 高层封装

///| 用户面向的接口:

///|   - `ChaChaState::new128(key)` / `ChaChaState::new256(key)` 构造

///|   - `set_iv(state, iv, counter?)` 装载 IV 与计数器

///|   - `process(state, input)` 加密/解密(同构操作)

///|
/// 从 16 字节 key 构造 ChaChaState(128-bit key,使用 tau 常量)
pub fn ChaChaState::new128(key : FixedArray[Byte]) -> ChaChaState {
  if key.length() != key_128_len {
    abort("ChaChaState::new128: key must be 16 bytes")
  }
  let state : FixedArray[UInt32] = FixedArray::make(16, 0U)
  // [0..4] = tau constants
  state[0] = tau0
  state[1] = tau1
  state[2] = tau2
  state[3] = tau3
  // [4..12] = key(128-bit 模式下 key 重复填入,共 32 字节 = 8 个 u32)
  state[4] = u8_to_32_le(key, 0)
  state[5] = u8_to_32_le(key, 4)
  state[6] = u8_to_32_le(key, 8)
  state[7] = u8_to_32_le(key, 12)
  // 128-bit 模式:key 重复填充
  state[8] = state[4]
  state[9] = state[5]
  state[10] = state[6]
  state[11] = state[7]
  // [12..16] = counter 0 + iv 0(稍后由 set_iv 设置)
  { input: state, }
}

///|
/// 从 32 字节 key 构造 ChaChaState(256-bit key,使用 sigma 常量,推荐)
pub fn ChaChaState::new256(key : FixedArray[Byte]) -> ChaChaState {
  if key.length() != key_256_len {
    abort("ChaChaState::new256: key must be 32 bytes")
  }
  let state : FixedArray[UInt32] = FixedArray::make(16, 0U)
  // [0..4] = sigma constants
  state[0] = sigma0
  state[1] = sigma1
  state[2] = sigma2
  state[3] = sigma3
  // [4..12] = key(32 字节 = 8 个 u32)
  state[4] = u8_to_32_le(key, 0)
  state[5] = u8_to_32_le(key, 4)
  state[6] = u8_to_32_le(key, 8)
  state[7] = u8_to_32_le(key, 12)
  state[8] = u8_to_32_le(key, 16)
  state[9] = u8_to_32_le(key, 20)
  state[10] = u8_to_32_le(key, 24)
  state[11] = u8_to_32_le(key, 28)
  // [12..16] = counter 0 + iv 0
  { input: state, }
}

///| 装载 IV 和 64-bit 计数器

///| iv 必须是 8 字节;counter 默认 0

///|
/// 注意:OpenSSH 变体下,counter 在 [12..14],iv 在 [14..16]
pub fn ChaChaState::set_iv(
  state : ChaChaState,
  iv : FixedArray[Byte],
  counter? : UInt64,
) -> ChaChaState {
  if iv.length() != nonce_len {
    abort("set_iv: iv must be 8 bytes")
  }
  let counter_val = match counter {
    Some(c) => c
    None => 0UL
  }
  // 复制 state 以保持不可变语义
  let new_input : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i = 0; i < 16; i = i + 1 {
    new_input[i] = state.input[i]
  }
  // counter low 32 bits @12, high 32 bits @13
  new_input[12] = (counter_val & 0xFFFFFFFFUL).to_uint()
  new_input[13] = ((counter_val >> 32) & 0xFFFFFFFFUL).to_uint()
  // iv @14, @15
  new_input[14] = u8_to_32_le(iv, 0)
  new_input[15] = u8_to_32_le(iv, 4)
  { input: new_input, }
}

///| ChaCha20 加/解密(同构操作)

///| 输入:任意长度的字节序列

///| 输出:等长的密文字节序列

///|

///| 关键性质(对合性):对任意 state、input:

///|
///   process(state, process(state, input)) == input
pub fn ChaChaState::process(
  self : ChaChaState,
  input : FixedArray[Byte],
) -> FixedArray[Byte] {
  let output : FixedArray[Byte] = FixedArray::make(input.length(), b'\x00')
  if input.length() == 0 {
    return output
  }
  // 计数器在 [12..14],从 state 中复制出来便于自增
  let mut mut_counter_low = self.input[12]
  let mut mut_counter_high = self.input[13]
  // 当前 state 的 [0..12] 是不变的(因为 set_iv 是 immutable 复制)
  // 但 [12..14] 会在循环中自增,所以我们拷贝一份 state 用于每个 block
  let base_state : FixedArray[UInt32] = FixedArray::make(16, 0U)
  for i = 0; i < 12; i = i + 1 {
    base_state[i] = self.input[i]
  }
  // 位置指针与剩余长度
  let mut pos = 0
  let mut remaining = input.length()
  while remaining > 0 {
    // 构造本轮的 state
    let round_state : FixedArray[UInt32] = FixedArray::make(16, 0U)
    for i = 0; i < 12; i = i + 1 {
      round_state[i] = base_state[i]
    }
    round_state[12] = mut_counter_low
    round_state[13] = mut_counter_high
    round_state[14] = self.input[14]
    round_state[15] = self.input[15]
    // 计算 keystream block
    let ks = chacha_block(round_state)
    // XOR 本 block(input 不足 64 字节时只取需要的部分)
    let take = if remaining < 64 { remaining } else { 64 }
    // 把 keystream 转成字节视图
    for j = 0; j < 16; j = j + 1 {
      let w = ks[j]
      let b0 = ((w >> 0) & 0xFFU).to_byte()
      let b1 = ((w >> 8) & 0xFFU).to_byte()
      let b2 = ((w >> 16) & 0xFFU).to_byte()
      let b3 = ((w >> 24) & 0xFFU).to_byte()
      let base = j * 4
      // XOR 4 字节
      if base + 0 < take {
        output[pos + base + 0] = b0 ^ input[pos + base + 0]
      }
      if base + 1 < take {
        output[pos + base + 1] = b1 ^ input[pos + base + 1]
      }
      if base + 2 < take {
        output[pos + base + 2] = b2 ^ input[pos + base + 2]
      }
      if base + 3 < take {
        output[pos + base + 3] = b3 ^ input[pos + base + 3]
      }
    }
    // 自增计数器
    mut_counter_low = mut_counter_low + 1U
    if mut_counter_low == 0U {
      mut_counter_high = mut_counter_high + 1U
    }
    pos = pos + take
    remaining = remaining - take
  }
  output
}
