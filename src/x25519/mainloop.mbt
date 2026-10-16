///| X25519 Montgomery ladder

///| 对应 OpenBSD smult_curve25519_ref.c 第 124-178 行

///|

///| 输入:

///|   work[64] = [P_x (32 bytes), P_z (32 bytes)]

///|   P_x 初始 = 输入 point

///|   P_z 初始 = 1

///|   scalar e[32] (已 clamp)

///| 输出:work[64] = (X_n, Z_n)

///|
///   最终 shared secret = X_n / Z_n = X_n * Z_n^(-1) mod p

// 辅助:fe_add 但带 offset(写入 dst[offset..offset+32])
fn fe_add_off(
  out : FixedArray[UInt32],
  out_off : Int32,
  a : FixedArray[UInt32],
  a_off : Int32,
  b : FixedArray[UInt32],
  b_off : Int32,
) -> Unit {
  let mut u : UInt32 = 0U
  for j = 0; j < 31; j = j + 1 {
    let sum : UInt32 = a[a_off + j] + b[b_off + j] + u
    out[out_off + j] = sum & 0xFFU
    u = sum >> 8
  }
  out[out_off + 31] = a[a_off + 31] + b[b_off + 31] + u
}

///|
fn fe_sub_off(
  out : FixedArray[UInt32],
  out_off : Int32,
  a : FixedArray[UInt32],
  a_off : Int32,
  b : FixedArray[UInt32],
  b_off : Int32,
) -> Unit {
  let mut u : UInt32 = 218U
  for j = 0; j < 31; j = j + 1 {
    let diff : UInt32 = a[a_off + j] + 65280U - b[b_off + j] + u
    out[out_off + j] = diff & 0xFFU
    u = diff >> 8
  }
  out[out_off + 31] = a[a_off + 31] - b[b_off + 31] + u
}

///|
fn fe_square_off(
  out : FixedArray[UInt32],
  out_off : Int32,
  a : FixedArray[UInt32],
  a_off : Int32,
) -> Unit {
  // square 到 out[out_off..out_off+32],输入 a[a_off..a_off+32]
  for i = 0; i < 32; i = i + 1 {
    let mut u : UInt32 = 0U
    let mut j = 0
    while j < i - j {
      u = u + a[a_off + j] * a[a_off + i - j]
      j = j + 1
    }
    j = i + 1
    while j < i + 32 - j {
      u = u + 38U * a[a_off + j] * a[a_off + i + 32 - j]
      j = j + 1
    }
    u = u * 2U
    if (i & 1) == 0 {
      let half : Int32 = i / 2
      u = u + a[a_off + half] * a[a_off + half]
      u = u + 38U * a[a_off + half + 16] * a[a_off + half + 16]
    }
    out[out_off + i] = u
  }
  fe_squeeze_off(out, out_off)
}

///|
fn fe_squeeze_off(a : FixedArray[UInt32], off : Int32) -> Unit {
  let mut u : UInt32 = 0U
  for j = 0; j < 31; j = j + 1 {
    let sum : UInt32 = a[off + j] + u
    a[off + j] = sum & 0xFFU
    u = sum >> 8
  }
  let sum : UInt32 = a[off + 31] + u
  a[off + 31] = sum & 0x7FU
  u = sum >> 7
  u = u * 19U
  for j = 0; j < 31; j = j + 1 {
    let sum2 : UInt32 = a[off + j] + u
    a[off + j] = sum2 & 0xFFU
    u = sum2 >> 8
  }
  a[off + 31] = a[off + 31] + u
}

///|
fn fe_mult_off(
  out : FixedArray[UInt32],
  out_off : Int32,
  a : FixedArray[UInt32],
  a_off : Int32,
  b : FixedArray[UInt32],
  b_off : Int32,
) -> Unit {
  for i = 0; i < 32; i = i + 1 {
    let mut u : UInt32 = 0U
    for j = 0; j <= i; j = j + 1 {
      u = u + a[a_off + j] * b[b_off + i - j]
    }
    for j = i + 1; j < 32; j = j + 1 {
      u = u + 38U * a[a_off + j] * b[b_off + i + 32 - j]
    }
    out[out_off + i] = u
  }
  fe_squeeze_off(out, out_off)
}

///|
fn fe_mult121665_off(
  out : FixedArray[UInt32],
  out_off : Int32,
  a : FixedArray[UInt32],
  a_off : Int32,
) -> Unit {
  let mut u : UInt32 = 0U
  for j = 0; j < 31; j = j + 1 {
    let sum : UInt32 = 121665U * a[a_off + j] + u
    out[out_off + j] = sum & 0xFFU
    u = sum >> 8
  }
  let sum : UInt32 = 121665U * a[a_off + 31] + u
  out[out_off + 31] = sum & 0x7FU
  u = sum >> 7
  u = u * 19U
  for j = 0; j < 31; j = j + 1 {
    let sum2 : UInt32 = out[out_off + j] + u
    out[out_off + j] = sum2 & 0xFFU
    u = sum2 >> 8
  }
  out[out_off + 31] = out[out_off + 31] + u
}

///|
/// 主循环:work[64] 包含 (P_x, P_z),e[32] 是 clamped scalar
pub fn mainloop(work : FixedArray[UInt32], e : FixedArray[UInt32]) -> Unit {
  // 局部变量(都是 64-limb = group element,或 32-limb = field element)
  let xzm1 : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let xzm : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let xzmb : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let xzm1b : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let xznb : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let xzn1b : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let a0 : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let a1 : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let b0 : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let b1 : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let c1 : FixedArray[UInt32] = FixedArray::make(64, 0U)
  let r : FixedArray[UInt32] = FixedArray::make(32, 0U)
  let s : FixedArray[UInt32] = FixedArray::make(32, 0U)
  let t : FixedArray[UInt32] = FixedArray::make(32, 0U)
  let u : FixedArray[UInt32] = FixedArray::make(32, 0U)

  // 初始化 xzm1 = (P_x, 1)
  for j = 0; j < 32; j = j + 1 {
    xzm1[j] = work[j]
  }
  xzm1[32] = 1U
  for j = 33; j < 64; j = j + 1 {
    xzm1[j] = 0U
  }

  // xzm = (1, 0)
  xzm[0] = 1U
  for j = 1; j < 64; j = j + 1 {
    xzm[j] = 0U
  }

  // 255 轮 Montgomery ladder
  let mut pos : Int32 = 254
  while pos >= 0 {
    let b : UInt32 = (e[pos / 8] >> (pos & 7)) & 1U
    let bm : UInt32 = bminus1(b)

    // select: xzmb, xzm1b ← xzm, xzm1
    let mut j = 0
    while j < 64 {
      let x : UInt32 = bm & (xzm[j] ^ xzm1[j])
      xzmb[j] = xzm1[j] ^ x
      xzm1b[j] = xzm[j] ^ x
      j = j + 1
    }

    // a0 = (X+Z, X-Z) for xzmb
    fe_add_off(a0, 0, xzmb, 0, xzmb, 32)
    fe_sub_off(a0, 32, xzmb, 0, xzmb, 32)

    // a1 = (X+Z, X-Z) for xzm1b
    fe_add_off(a1, 0, xzm1b, 0, xzm1b, 32)
    fe_sub_off(a1, 32, xzm1b, 0, xzm1b, 32)

    // b0 = (a0^2, (a0+32)^2)
    fe_square_off(b0, 0, a0, 0)
    fe_square_off(b0, 32, a0, 32)

    // b1 = (a1 * a0+32, a1+32 * a0)
    fe_mult_off(b1, 0, a1, 0, a0, 32)
    fe_mult_off(b1, 32, a1, 32, a0, 0)

    // c1 = (b1 + b1+32, b1 - b1+32)
    fe_add_off(c1, 0, b1, 0, b1, 32)
    fe_sub_off(c1, 32, b1, 0, b1, 32)

    // r = (c1+32)^2
    fe_square_off(r, 0, c1, 32)

    // s = b0 - b0+32
    fe_sub_off(s, 0, b0, 0, b0, 32)

    // t = 121665 * s
    fe_mult121665_off(t, 0, s, 0)

    // u = t + b0
    fe_add_off(u, 0, t, 0, b0, 0)

    // xznb = (b0 * b0+32, s * u)
    fe_mult_off(xznb, 0, b0, 0, b0, 32)
    fe_mult_off(xznb, 32, s, 0, u, 0)

    // xzn1b = (c1^2, r * work)
    fe_square_off(xzn1b, 0, c1, 0)
    fe_mult_off(xzn1b, 32, r, 0, work, 0)

    // select(xzm, xzm1, xznb, xzn1b, b)
    j = 0
    while j < 64 {
      let x : UInt32 = bm & (xznb[j] ^ xzn1b[j])
      xzm[j] = xzn1b[j] ^ x
      xzm1[j] = xznb[j] ^ x
      j = j + 1
    }

    pos = pos - 1
  }

  // 写回 work
  for j = 0; j < 64; j = j + 1 {
    work[j] = xzm[j]
  }
}
