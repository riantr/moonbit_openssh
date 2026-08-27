// inlined from E:\src\moon\openssh_moonbit\src\x25519\arithmetic.mbt (moon 0.1.20260608: no cross-package import)
// content unchanged; provenance tracked in docs/kex_c25519/

///| X25519 field arithmetic (mod 2^255-19)

///| 对应 OpenBSD smult_curve25519_ref.c 第 11-88 行

///|

///| Field element 用 32 个 8-bit limb,小端。

///|
/// squeeze 后 limb[0..30] ∈ [0, 256), limb[31] ∈ [0, 2^15)。

// ===== add: out = a + b (无 mod,允许 limb 31 临时 ≥ 256) =====
pub fn fe_add(
  out : FixedArray[UInt],
  a : FixedArray[UInt],
  b : FixedArray[UInt],
) -> Unit {
  let mut u : UInt = 0U
  for j = 0; j < 31; j = j + 1 {
    let sum : UInt = a[j] + b[j] + u
    out[j] = sum & 0xFFU
    u = sum >> 8
  }
  // limb 31: 不 mask,允许临时 ≥ 256
  out[31] = a[31] + b[31] + u
}

// ===== sub: out = a - b + 2*p(保证 out ≥ 0,允许 limb 31 临时 ≥ 256) =====

///|
pub fn fe_sub(
  out : FixedArray[UInt],
  a : FixedArray[UInt],
  b : FixedArray[UInt],
) -> Unit {
  let mut u : UInt = 218U // 2*p 的低 8-bit 贡献 (= 2*19 mod 256)
  for j = 0; j < 31; j = j + 1 {
    let diff : UInt = a[j] + 65280U - b[j] + u
    out[j] = diff & 0xFFU
    u = diff >> 8
  }
  // limb 31: 不带 256 mod
  out[31] = a[31] - b[31] + u
}

// ===== squeeze: 把所有 limb 归约到 < 256(limb 31 < 2^15) =====

///|
pub fn fe_squeeze(a : FixedArray[UInt]) -> Unit {
  let mut u : UInt = 0U
  for j = 0; j < 31; j = j + 1 {
    let sum : UInt = a[j] + u
    a[j] = sum & 0xFFU
    u = sum >> 8
  }
  // limb 31: 清掉 bit 7(= 限制 < 128 = 2^7)
  let sum : UInt = a[31] + u
  a[31] = sum & 0x7FU
  u = sum >> 7
  // 进位 × 19(因为 2^255 ≡ 19 mod p)
  u = u * 19U
  for j = 0; j < 31; j = j + 1 {
    let sum2 : UInt = a[j] + u
    a[j] = sum2 & 0xFFU
    u = sum2 >> 8
  }
  // limb 31 最后一次:不再 mask,允许临时 ≥ 256(下次 squeeze 再归约)
  a[31] = a[31] + u
}

// ===== mult: out = a * b mod p =====
// 32 × 32 schoolbook mul,partial product 先存 16-bit,然后 squeeze

///|
pub fn fe_mult(
  out : FixedArray[UInt],
  a : FixedArray[UInt],
  b : FixedArray[UInt],
) -> Unit {
  // 第 1 步:计算 16-bit partial products 到 out[0..32]
  for i = 0; i < 32; i = i + 1 {
    let mut u : UInt = 0U
    // a[j] * b[i-j] for j in 0..=i  → 直接贡献到 out[i]
    for j = 0; j <= i; j = j + 1 {
      u = u + a[j] * b[i - j]
    }
    // 38 * a[j] * b[i+32-j] for j in i+1..32  → 对应 2*p 的折回
    // 实际是 a[j] * b[i-j+32] 的 2*p 倍修正
    for j = i + 1; j < 32; j = j + 1 {
      u = u + 38U * a[j] * b[i + 32 - j]
    }
    out[i] = u
  }
  fe_squeeze(out)
}

// ===== square: out = a^2 mod p,利用对称性 =====
// 对应 OpenBSD 第 90-108 行

///|
pub fn fe_square(out : FixedArray[UInt], a : FixedArray[UInt]) -> Unit {
  for i = 0; i < 32; i = i + 1 {
    let mut u : UInt = 0U
    // 对称化:对 j < i/2 取 a[j]*a[i-j]
    // 注:C 代码 `for (j = 0; j < i - j; ++j)` 等价于 j < i - j 即 j < i/2
    let mut j = 0
    while j < i - j {
      u = u + a[j] * a[i - j]
      j = j + 1
    }
    // 对 j > i 取 38 * a[j] * a[i+32-j]
    j = i + 1
    while j < i + 32 - j {
      u = u + 38U * a[j] * a[i + 32 - j]
      j = j + 1
    }
    // × 2 因为对称化只算了半边
    u = u * 2U
    // i 偶数时加对角项 a[i/2]^2 + 38 * a[i/2+16]^2
    if (i & 1) == 0 {
      let half : Int = i / 2
      u = u + a[half] * a[half]
      u = u + 38U * a[half + 16] * a[half + 16]
    }
    out[i] = u
  }
  fe_squeeze(out)
}

// ===== mult121665: out = 121665 * a mod p =====
// 121665 = (A - 2) / 4 where A = 486662 (RFC 7748 § 5)

///|
pub fn fe_mult121665(out : FixedArray[UInt], a : FixedArray[UInt]) -> Unit {
  let mut u : UInt = 0U
  for j = 0; j < 31; j = j + 1 {
    let sum : UInt = 121665U * a[j] + u
    out[j] = sum & 0xFFU
    u = sum >> 8
  }
  // limb 31: mask bit 7
  let sum : UInt = 121665U * a[31] + u
  out[31] = sum & 0x7FU
  u = sum >> 7
  // × 19 进位
  u = u * 19U
  for j = 0; j < 31; j = j + 1 {
    let sum2 : UInt = out[j] + u
    out[j] = sum2 & 0xFFU
    u = sum2 >> 8
  }
  out[31] = out[31] + u
}
