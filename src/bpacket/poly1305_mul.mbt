///| Poly1305 5x5 矩阵乘 + carry chain,完成 mod 2^130 - 5

///| 对应 OpenBSD poly1305.c 87-99 行

///|

///| 数学:输入 h(5 limb,共 130 bit)和 r(5 limb),输出 h * r mod 2^130 - 5

///| 实现:把 5x5 矩阵乘展开为 25 个 UInt32 mul,累加到 5 个 UInt64 槽,再做 carry chain

///| 把 5 个 limb(每个 26 bit)的累加器 h 乘以 r * (1 mod p),mod p

///| p = 2^130 - 5

///|

///| r_parts:(r0, r1, r2, r3, r4, s1, s2, s3, s4) — s_i = r_i * 5

///| h:(h0, h1, h2, h3, h4) — 5 个 26-bit limb

///|
/// 返回:新的 5 个 26-bit limb(归一化后)
pub fn mul_mod(
  h0 : UInt,
  h1 : UInt,
  h2 : UInt,
  h3 : UInt,
  h4 : UInt,
  r0 : UInt,
  r1 : UInt,
  r2 : UInt,
  r3 : UInt,
  r4 : UInt,
  s1 : UInt,
  s2 : UInt,
  s3 : UInt,
  s4 : UInt,
) -> (UInt, UInt, UInt, UInt, UInt) {
  // 5x5 矩阵:对每个 k, t[k] = sum h[i] * mul_factor[i][k]  (i=0..4)
  // 系数规律(对应 OpenBSD 代码):
  //   t[0] = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1
  //   t[1] = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2
  //   t[2] = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3
  //   t[3] = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4
  //   t[4] = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0
  let t0 : UInt64 = mul64(h0, r0) +
    mul64(h1, s4) +
    mul64(h2, s3) +
    mul64(h3, s2) +
    mul64(h4, s1)
  let t1 : UInt64 = mul64(h0, r1) +
    mul64(h1, r0) +
    mul64(h2, s4) +
    mul64(h3, s3) +
    mul64(h4, s2)
  let t2 : UInt64 = mul64(h0, r2) +
    mul64(h1, r1) +
    mul64(h2, r0) +
    mul64(h3, s4) +
    mul64(h4, s3)
  let t3 : UInt64 = mul64(h0, r3) +
    mul64(h1, r2) +
    mul64(h2, r1) +
    mul64(h3, r0) +
    mul64(h4, s4)
  let t4 : UInt64 = mul64(h0, r4) +
    mul64(h1, r3) +
    mul64(h2, r2) +
    mul64(h3, r1) +
    mul64(h4, r0)

  // Carry chain:把 5 个 64-bit 累加槽归一化到 5 个 26-bit limb
  // h[k] = t[k] & 0x3ffffff
  // t[k+1] += t[k] >> 26
  // h[0] += (t[4] >> 26) * 5  (因为 p = 2^130 - 5,所以 2^130 ≡ 5 mod p)
  let new_h0_0 : UInt = (t0 & 0x3ffffffUL).to_uint()
  let c0 : UInt64 = t0 >> 26
  let t1c : UInt64 = t1 + c0
  let new_h1 : UInt = (t1c & 0x3ffffffUL).to_uint()
  let b1 : UInt64 = t1c >> 26
  let t2c : UInt64 = t2 + b1
  let new_h2 : UInt = (t2c & 0x3ffffffUL).to_uint()
  let b2 : UInt64 = t2c >> 26
  let t3c : UInt64 = t3 + b2
  let new_h3 : UInt = (t3c & 0x3ffffffUL).to_uint()
  let b3 : UInt64 = t3c >> 26
  let t4c : UInt64 = t4 + b3
  let new_h4 : UInt = (t4c & 0x3ffffffUL).to_uint()
  let b4 : UInt64 = t4c >> 26
  let new_h0 : UInt = new_h0_0 + (b4 * 5UL).to_uint()

  (new_h0, new_h1, new_h2, new_h3, new_h4)
}

///|
/// 32-bit × 32-bit → 64-bit
fn mul64(a : UInt, b : UInt) -> UInt64 {
  a.to_uint64() * b.to_uint64()
}
