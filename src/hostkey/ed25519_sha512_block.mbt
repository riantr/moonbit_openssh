///| SHA-512 单 block transform (80 轮 compression)

///| 对应 OpenBSD sha2.c 第 388-517 行 (SHA256Transform, 但用 64-bit)

///|

///| 输入:state[8] u64(初始 H 或累积值) + block[16] u64(BE 解析)

///| 输出:更新后的 state[8] u64

///|
/// 对 8 个 state word 做 80 轮 compression,就地更新
pub fn transform(
  state : FixedArray[UInt64],
  block : FixedArray[UInt64],
) -> Unit {
  // W[0..15] = block; W[16..79] = message schedule
  let w : FixedArray[UInt64] = FixedArray::make(80, 0UL)
  for i = 0; i < 16; i = i + 1 {
    w[i] = block[i]
  }
  for i = 16; i < 80; i = i + 1 {
    w[i] = small_sigma1(w[i - 2]) +
      w[i - 7] +
      small_sigma0(w[i - 15]) +
      w[i - 16]
  }

  // 寄存器
  let mut a = state[0]
  let mut b = state[1]
  let mut c = state[2]
  let mut d = state[3]
  let mut e = state[4]
  let mut f = state[5]
  let mut g = state[6]
  let mut h = state[7]

  // 80 轮
  for j = 0; j < 80; j = j + 1 {
    let t1 = h + big_sigma1(e) + ch(e, f, g) + k512[j] + w[j]
    let t2 = big_sigma0(a) + maj(a, b, c)
    h = g
    g = f
    f = e
    e = d + t1
    d = c
    c = b
    b = a
    a = t1 + t2
  }

  // 累加到 state
  state[0] = state[0] + a
  state[1] = state[1] + b
  state[2] = state[2] + c
  state[3] = state[3] + d
  state[4] = state[4] + e
  state[5] = state[5] + f
  state[6] = state[6] + g
  state[7] = state[7] + h
}
