///| Group operations on the twisted Edwards curve

///| 对应 OpenSSH ed25519.c (TweetNaCl ref10)

///|

///| Curve: -x^2 + y^2 = 1 + d*x^2*y^2

///| d = -121665/121666 mod p

///| Base point B: (15112221349535400772501151409588531511454012693041857206046113283949847762202,

///|                46316835694926478169428394003475163141307993866256225615783033603165251855960)

///|

///| 内部使用 4 种 projective 表示:

///| - Ge_p3:   (X, Y, Z, T)        T = XY/Z

///| - Ge_p2:   (X, Y, Z)

///| - Ge_p1p1: (X, Y, Z, T)        add/dbl 中间结果

///| - Ge_aff:  (X, Y)              仿射(用于 precomputed table)

///|
/// Twisted Edwards point (X, Y, Z, T) where T = XY/Z
type Ge_p3 = FixedArray[Fe]

///|
/// Twisted Edwards point (X, Y, Z)
type Ge_p2 = FixedArray[Fe]

///|
/// Add/Double intermediate (X, Y, Z, T)
type Ge_p1p1 = FixedArray[Fe]

///|
/// Affine point (X, Y)
type Ge_aff = FixedArray[Fe]

///|
/// 创建 Ge_p3 全零(内部存 4 个 Fe,每个 Fe 独立)
fn ge_p3_new() -> Ge_p3 {
  // 注意:不能直接用 FixedArray::make(4, fe_zero()),
  // 因为 FixedArray::make 会共享同一个内部数组,导致修改一个会影响所有
  let r : FixedArray[Fe] = FixedArray::make(4, fe_zero())
  for i = 0; i < 4; i = i + 1 {
    r[i] = fe_zero()
  }
  r
}

///|
/// 创建 Ge_p2 全零
fn ge_p2_new() -> Ge_p2 {
  let r : FixedArray[Fe] = FixedArray::make(3, fe_zero())
  for i = 0; i < 3; i = i + 1 {
    r[i] = fe_zero()
  }
  r
}

///|
/// 创建 Ge_p1p1 全零
fn ge_p1p1_new() -> Ge_p1p1 {
  let r : FixedArray[Fe] = FixedArray::make(4, fe_zero())
  for i = 0; i < 4; i = i + 1 {
    r[i] = fe_zero()
  }
  r
}

///|
/// 创建 Ge_aff 全零
fn ge_aff_new() -> Ge_aff {
  let r : FixedArray[Fe] = FixedArray::make(2, fe_zero())
  r[0] = fe_zero()
  r[1] = fe_zero()
  r
}

///| d = -121665/121666 mod p

///|
/// 对应 C: ge25519_ecd
let ge25519_ecd : Fe = [
  0xA3UL, 0x78UL, 0x59UL, 0x13UL, 0xCAUL, 0x4DUL, 0xEBUL, 0x75UL, 0xABUL, 0xD8UL,
  0x41UL, 0x41UL, 0x4DUL, 0x0AUL, 0x70UL, 0x00UL, 0x98UL, 0xE8UL, 0x79UL, 0x77UL,
  0x79UL, 0x40UL, 0xC7UL, 0x8CUL, 0x73UL, 0xFEUL, 0x6FUL, 0x2BUL, 0xEEUL, 0x6CUL,
  0x03UL, 0x52UL,
]

///| 2*d

///|
/// 对应 C: ge25519_ec2d
let ge25519_ec2d : Fe = [
  0x59UL, 0xF1UL, 0xB2UL, 0x26UL, 0x94UL, 0x9BUL, 0xD6UL, 0xEBUL, 0x56UL, 0xB1UL,
  0x83UL, 0x82UL, 0x9AUL, 0x14UL, 0xE0UL, 0x00UL, 0x30UL, 0xD1UL, 0xF3UL, 0xEEUL,
  0xF2UL, 0x80UL, 0x8EUL, 0x19UL, 0xE7UL, 0xFCUL, 0xDFUL, 0x56UL, 0xDCUL, 0xD9UL,
  0x06UL, 0x24UL,
]

///| sqrt(-1) mod p

///|
/// 对应 C: ge25519_sqrtm1
let ge25519_sqrtm1 : Fe = [
  0xB0UL, 0xA0UL, 0x0EUL, 0x4AUL, 0x27UL, 0x1BUL, 0xEEUL, 0xC4UL, 0x78UL, 0xE4UL,
  0x2FUL, 0xADUL, 0x06UL, 0x18UL, 0x43UL, 0x2FUL, 0xA7UL, 0xD7UL, 0xFBUL, 0x3DUL,
  0x99UL, 0x00UL, 0x4DUL, 0x2BUL, 0x0BUL, 0xDFUL, 0xC1UL, 0x4FUL, 0x80UL, 0x24UL,
  0x83UL, 0x2BUL,
]

///| 基础点 B (X, Y, Z, T) (projective 坐标)

///|
/// 对应 C: ge25519_base
let ge25519_base : Ge_p3 = [
  [
    0x1AUL, 0xD5UL, 0x25UL, 0x8FUL, 0x60UL, 0x2DUL, 0x56UL, 0xC9UL, 0xB2UL, 0xA7UL,
    0x25UL, 0x95UL, 0x60UL, 0xC7UL, 0x2CUL, 0x69UL, 0x5CUL, 0xDCUL, 0xD6UL, 0xFDUL,
    0x31UL, 0xE2UL, 0xA4UL, 0xC0UL, 0xFEUL, 0x53UL, 0x6EUL, 0xCDUL, 0xD3UL, 0x36UL,
    0x69UL, 0x21UL,
  ], // X
  [
    0x58UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL,
    0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL,
    0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL, 0x66UL,
    0x66UL, 0x66UL,
  ], // Y = 4/5
  [
    0x01UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL,
    0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL,
    0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL, 0x00UL,
    0x00UL, 0x00UL,
  ], // Z = 1
  [
    0xA3UL, 0xDDUL, 0xB7UL, 0xA5UL, 0xB3UL, 0x8AUL, 0xDEUL, 0x6DUL, 0xF5UL, 0x52UL,
    0x51UL, 0x77UL, 0x80UL, 0x9FUL, 0xF0UL, 0x20UL, 0x7DUL, 0xE3UL, 0xABUL, 0x64UL,
    0x8EUL, 0x4EUL, 0xEAUL, 0x66UL, 0x65UL, 0x76UL, 0x8BUL, 0xD7UL, 0x0FUL, 0x5FUL,
    0x87UL, 0x67UL,
  ], // T = X*Y
]

///| r = neutral element

///|
/// 对应 C: setneutral
pub fn ge_setneutral() -> Ge_p3 {
  let r = ge_p3_new()
  fe_setzero(r[0])
  fe_setone(r[1])
  fe_setone(r[2])
  fe_setzero(r[3])
  r
}

///| p1p1 → p2: r.x = p.x*p.t, r.y = p.y*p.z, r.z = p.z*p.t

///|
/// 对应 C: p1p1_to_p2
fn ge_p1p1_to_p2(p : Ge_p1p1) -> Ge_p2 {
  let r = ge_p2_new()
  r[0] = fe_mul(p[0], p[3])
  r[1] = fe_mul(p[1], p[2])
  r[2] = fe_mul(p[2], p[3])
  r
}

///| p1p1 → p3: 同 p1p1_to_p2,再 r.t = p.x*p.y

///|
/// 对应 C: p1p1_to_p3
fn ge_p1p1_to_p3(p : Ge_p1p1) -> Ge_p3 {
  let r = ge_p3_new()
  r[0] = fe_mul(p[0], p[3])
  r[1] = fe_mul(p[1], p[2])
  r[2] = fe_mul(p[2], p[3])
  r[3] = fe_mul(p[0], p[1])
  r
}

///|
/// p3 → p2(忽略 T):p2 = (p3.x, p3.y, p3.z)
fn ge_p3_to_p2(p : Ge_p3) -> Ge_p2 {
  let r = ge_p2_new()
  r[0] = fe_copy(p[0])
  r[1] = fe_copy(p[1])
  r[2] = fe_copy(p[2])
  r
}

///|
/// 复制 Fe
fn fe_copy(x : Fe) -> Fe {
  let r = fe_new()
  for i = 0; i < 32; i = i + 1 {
    r[i] = x[i]
  }
  r
}

///| p1p1 = p + q (twisted Edwards)

///|
/// 对应 C: add_p1p1
fn ge_add_p1p1(p : Ge_p3, q : Ge_p3) -> Ge_p1p1 {
  let r = ge_p1p1_new()
  let a = fe_sub(p[1], p[0])
  let t = fe_sub(q[1], q[0])
  let a = fe_mul(a, t)
  let b = fe_add(p[0], p[1])
  let t = fe_add(q[0], q[1])
  let b = fe_mul(b, t)
  let c = fe_mul(p[3], q[3])
  let c = fe_mul(c, ge25519_ec2d)
  let d = fe_mul(p[2], q[2])
  let d = fe_add(d, d)
  r[0] = fe_sub(b, a)
  r[3] = fe_sub(d, c)
  r[2] = fe_add(d, c)
  r[1] = fe_add(b, a)
  r
}

///| p1p1 = 2*p (twisted Edwards doubling)

///|
/// 对应 C: dbl_p1p1
fn ge_dbl_p1p1(p : Ge_p2) -> Ge_p1p1 {
  let r = ge_p1p1_new()
  let a = fe_square(p[0])
  let b = fe_square(p[1])
  let c = fe_square(p[2])
  let c = fe_add(c, c)
  let d = fe_neg(a)
  let rx = fe_add(p[0], p[1])
  let rx = fe_square(rx)
  let rx = fe_sub(rx, a)
  let rx = fe_sub(rx, b)
  let rz = fe_add(d, b)
  let rt = fe_sub(rz, c)
  let ry = fe_sub(d, b)
  r[0] = rx
  r[1] = ry
  r[2] = rz
  r[3] = rt
  r
}

///| r += q_aff (mixed addition, Z2 = 1)

///|
/// 对应 C: ge25519_mixadd2
fn ge_mixadd2(r : Ge_p3, q : Ge_aff) -> Ge_p3 {
  let qt = fe_mul(q[0], q[1])
  let a = fe_sub(r[1], r[0])
  let b = fe_add(r[1], r[0])
  let t1 = fe_sub(q[1], q[0])
  let t2 = fe_add(q[1], q[0])
  let a = fe_mul(a, t1)
  let b = fe_mul(b, t2)
  let e = fe_sub(b, a)
  let h = fe_add(b, a)
  let c = fe_mul(r[3], qt)
  let c = fe_mul(c, ge25519_ec2d)
  let d = fe_add(r[2], r[2])
  let f = fe_sub(d, c)
  let g = fe_add(d, c)
  let nx = fe_mul(e, f)
  let ny = fe_mul(h, g)
  let nz = fe_mul(g, f)
  let nt = fe_mul(e, h)
  r[0] = nx
  r[1] = ny
  r[2] = nz
  r[3] = nt
  r
}

///| 把 Ge_p3 编码为 32 字节

///|
/// 对应 C: ge25519_pack
pub fn ge_pack(p : Ge_p3) -> FixedArray[Byte] {
  let zi = fe_invert(p[2])
  let tx = fe_mul(p[0], zi)
  let ty = fe_mul(p[1], zi)
  let out = fe_pack(ty)
  // r[31] ^= (x_0's parity) << 7
  let parity = fe_getparity(tx)
  let p31 = out[31].to_uint64() ^ (parity << 7)
  out[31] = p31.to_byte()
  out
}

///| 把 32 字节解码为 Ge_p3(取 neg)

///| 返回 true 表示成功

///|
/// 对应 C: ge25519_unpackneg_vartime
pub fn ge_unpackneg_vartime(bytes : FixedArray[Byte]) -> (Ge_p3, Bool) {
  let r = ge_p3_new()
  fe_setone(r[2])
  let par = bytes[31].to_uint64() >> 7
  let py = fe_unpack(bytes)
  // 重新清一下 par(我们不需要把 sign bit 编到 y 里)
  py[31] = py[31] & 0x7FUL
  let num = fe_square(py) // num = y^2
  let den = fe_mul(num, ge25519_ecd) // den = d*y^2
  let num = fe_sub(num, r[2]) // num = y^2 - 1
  let den = fe_add(r[2], den) // den = d*y^2 + 1
  // 1. t = (num * den^7)^((p-5)/8)
  let den2 = fe_square(den)
  let den4 = fe_square(den2)
  let den6 = fe_mul(den4, den2)
  let t = fe_mul(den6, num)
  let t = fe_mul(t, den)
  let t = fe_pow2523(t)
  // 2. r.x = t * num * den^3
  let t = fe_mul(t, num)
  let t = fe_mul(t, den)
  let t = fe_mul(t, den)
  let rx = fe_mul(t, den)
  // 3. 若 chk != num 则 r.x *= sqrt(-1)
  let chk = fe_square(rx)
  let chk = fe_mul(chk, den)
  let rx2 = if fe_iseq_vartime(chk, num) {
    rx
  } else {
    fe_mul(rx, ge25519_sqrtm1)
  }
  // 4. 再次检查,若仍不等则解码失败
  let chk2 = fe_square(rx2)
  let chk2 = fe_mul(chk2, den)
  if !fe_iseq_vartime(chk2, num) {
    return (r, false)
  }
  // 5. 根据 parity 选择根
  let rxf = if fe_getparity(rx2) != 1UL - par { fe_neg(rx2) } else { rx2 }
  r[0] = rxf
  r[1] = py
  r[3] = fe_mul(rxf, py)
  (r, true)
}

///| constant-time affine select: r = b ? p : r

///|
/// 对应 C: cmov_aff
fn ge_cmov_aff(r : Ge_aff, p : Ge_aff, b : UInt64) -> Unit {
  fe_cmov(r[0], p[0], b)
  fe_cmov(r[1], p[1], b)
}

///| constant-time: b == c ? 1 : 0

///| 对应 C equal(): crypto_uint32 y = x; y -= 1; y >>= 31;

///|
/// 注意:C 是 32-bit shift(0xFFFFFFFF >> 31 = 1),MoonBit 用 UInt64 必须 >> 63 再 & 1
fn ge_equal_i8(b : Int32, c : Int32) -> UInt64 {
  let ub = b.to_uint64() & 0xFFUL
  let uc = c.to_uint64() & 0xFFUL
  let x = ub ^ uc
  let y = x - 1UL
  (y >> 63) & 1UL
}

///| b 是负数 ? 1 : 0

///|
/// b 是 Int,signed range [-4, 3]
fn ge_negative(b : Int32) -> UInt64 {
  if b < 0 {
    1UL
  } else {
    0UL
  }
}

///| 从 precomputed table 中选第 pos 位置,系数 b ∈ [-4, 4]

///|
/// 对应 C: choose_t
fn ge_choose_t(pos : Int32, b : Int32) -> Ge_aff {
  let t = ge_aff_new()
  // base = multiples[5*pos+0]
  let base = ge25519_base_multiples_affine[5 * pos + 0]
  t[0] = fe_copy(base[0])
  t[1] = fe_copy(base[1])
  // t = multiples[5*pos+0]
  let cond1 = ge_equal_i8(b, 1) | ge_equal_i8(b, -1)
  ge_cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 1], cond1)
  let cond2 = ge_equal_i8(b, 2) | ge_equal_i8(b, -2)
  ge_cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 2], cond2)
  let cond3 = ge_equal_i8(b, 3) | ge_equal_i8(b, -3)
  ge_cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 3], cond3)
  let cond4 = ge_equal_i8(b, -4)
  ge_cmov_aff(t, ge25519_base_multiples_affine[5 * pos + 4], cond4)
  // 负数则 x 取负
  let neg = ge_negative(b)
  let vx = fe_neg(t[0])
  fe_cmov(t[0], vx, neg)
  t
}

///| r = s * B (基础点 scalar multiplication,使用 425-entry precomputed table)

///|
/// 对应 C: ge25519_scalarmult_base
pub fn ge_scalarmult_base(s : Sc) -> Ge_p3 {
  let b = sc_window3(s)
  // r = multiples[5*0 + 0] with coefficient b[0]
  let r = ge_p3_new()
  let chosen = ge_choose_t(0, b[0])
  r[0] = fe_copy(chosen[0])
  r[1] = fe_copy(chosen[1])
  fe_setone(r[2])
  r[3] = fe_mul(r[0], r[1])
  for i = 1; i < 85; i = i + 1 {
    let t = ge_choose_t(i, b[i])
    let _r = ge_mixadd2(r, t)
    // ge_mixadd2 已经修改 r
    ignore(_r)
  }
  r
}

///| vartime: p 是否 == neutral element

///|
/// 对应 C: ge25519_isneutral_vartime
pub fn ge_isneutral_vartime(p : Ge_p3) -> Bool {
  let mut ret = true
  if !fe_iszero_vartime(p[0]) {
    ret = false
  }
  if !fe_iseq_vartime(p[1], p[2]) {
    ret = false
  }
  ret
}

///| 计算 s1*p1 + s2*p2 (变长时间,因为 p1, p2 是 public)

///|
/// 对应 C: ge25519_double_scalarmult_vartime
pub fn ge_double_scalarmult_vartime(
  p1 : Ge_p3,
  s1 : Sc,
  p2 : Ge_p3,
  s2 : Sc,
) -> Ge_p3 {
  // precompute 16-element table pre[s2 s1]
  // 注意:每个元素必须是独立的 Ge_p3,不能用 FixedArray::make(16, ge_setneutral())
  // (那会共享同一个对象)
  let pre : FixedArray[Ge_p3] = FixedArray::make(16, ge_setneutral())
  for i = 0; i < 16; i = i + 1 {
    pre[i] = ge_setneutral()
  }
  // pre[0] = neutral
  pre[1] = fe_p3_copy(p1)
  let tp1p1 = ge_dbl_p1p1(ge_p3_to_p2(p1))
  pre[2] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[1], pre[2])
  pre[3] = ge_p1p1_to_p3(tp1p1)
  pre[4] = fe_p3_copy(p2)
  let tp1p1 = ge_add_p1p1(pre[1], pre[4])
  pre[5] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[2], pre[4])
  pre[6] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[3], pre[4])
  pre[7] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_dbl_p1p1(ge_p3_to_p2(p2))
  pre[8] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[1], pre[8])
  pre[9] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_dbl_p1p1(ge_p3_to_p2(pre[5]))
  pre[10] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[3], pre[8])
  pre[11] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[4], pre[8])
  pre[12] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[1], pre[12])
  pre[13] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[2], pre[12])
  pre[14] = ge_p1p1_to_p3(tp1p1)
  let tp1p1 = ge_add_p1p1(pre[3], pre[12])
  pre[15] = ge_p1p1_to_p3(tp1p1)
  // interleave s1, s2
  let b_arr = sc_2interleave2(s1, s2)
  // r = pre[b[126]]
  let mut r : Ge_p3 = fe_p3_copy(pre[b_arr[126].to_int()])
  for i = 125; i >= 0; i = i - 1 {
    // dbl1
    let tp1p1 = ge_dbl_p1p1(ge_p3_to_p2(r))
    r = ge_p1p1_to_p2(tp1p1)
    // dbl2
    let tp1p1_2 = ge_dbl_p1p1(ge_p3_to_p2(r))
    let bi = b_arr[i].to_int()
    if bi != 0 {
      // p1p1_to_p3 then add
      let r_as_p3 = ge_p1p1_to_p3(tp1p1_2)
      let tp1p1_added = ge_add_p1p1(r_as_p3, pre[bi])
      if i != 0 {
        r = ge_p1p1_to_p2(tp1p1_added)
      } else {
        r = ge_p1p1_to_p3(tp1p1_added)
      }
    } else if i != 0 {
      r = ge_p1p1_to_p2(tp1p1_2)
    } else {
      r = ge_p1p1_to_p3(tp1p1_2)
    }
  }
  r
}

///|
/// 深度复制 Ge_p3
fn fe_p3_copy(p : Ge_p3) -> Ge_p3 {
  let r = ge_p3_new()
  for k = 0; k < 32; k = k + 1 {
    r[0][k] = p[0][k]
    r[1][k] = p[1][k]
    r[2][k] = p[2][k]
    r[3][k] = p[3][k]
  }
  r
}
