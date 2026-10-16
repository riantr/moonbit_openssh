// inlined from E:\src\moon\openssh_moonbit\src\sha256\block.mbt (moon 0.1.20260608: no cross-package import)
// content unchanged; provenance tracked in docs/kex_c25519/

///| SHA-256 单 block transform (64 轮 compression)

///| 对应 OpenBSD sha2.c 第 388-517 行

///|

///| 输入:state[8] u32(初始 H 或累积值) + block[16] u32(BE 解析)

///| 输出:更新后的 state[8] u32

///| 对 8 个 state word 做 64 轮 compression,就地更新

///|
/// C: SHA256Transform(state, data) — 64 轮后 state[0..7] += {a..h}
pub fn transform(
  state : FixedArray[UInt32],
  block : FixedArray[UInt32],
) -> Unit {
  // W[0..15] = block; W[16..63] = message schedule
  let w : FixedArray[UInt32] = FixedArray::make(64, 0U)
  for i = 0; i < 16; i = i + 1 {
    w[i] = block[i]
  }
  for i = 16; i < 64; i = i + 1 {
    w[i] = sigma1_small(w[i - 2]) +
      w[i - 7] +
      sigma0_small(w[i - 15]) +
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

  // 64 轮
  for j = 0; j < 64; j = j + 1 {
    let t1 : UInt32 = h + sigma1_big(e) + ch(e, f, g) + k256[j] + w[j]
    let t2 : UInt32 = sigma0_big(a) + maj(a, b, c)
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
