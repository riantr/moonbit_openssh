///| X25519 状态与常量

///| 对应 RFC 7748 + OpenBSD smult_curve25519_ref.c

///|
/// Field element 大小(byte 数)
pub let fe_len : Int = 32

///|
/// Group element 大小(byte 数,X25519 输出)
pub let ge_len : Int = 32

///|
/// Scalar 大小(byte 数)
pub let scalar_len : Int = 32

///| 2^255 - 19 拆为 32 byte 小端表示(minusp = 2*p,用于 sub 和 freeze)

///| minusp = 2 * (2^255 - 19) = 2^256 - 38

///| 2^256 - 38 mod 2^256 = -38 mod 2^256

///| 但我们要的是 2*p 的 byte 形式,使得 a - b + 2*p 永远 >= 0

///| OpenBSD 直接用 [19, 0, ..., 0, 128]:

///|   256-bit 值: 19 + 128 * 2^248 = 19 + 2^255 = 2^255 + 19 = 2*p + 1 + 19 = ...

///| 实际它是: limb[0] = 19, limb[31] = 128 → 19 + 128 * 2^(31*8) = 19 + 128*2^248

///|         = 19 + 2^255 = 2^255 + 19 = 2 * (2^254) + 19

///| 但 sub 用 u = 218 (= 2 * 19 mod 256),加到 limb 0 进位 + 后面 limb 全 65280 进位

///| 数学上: 2*p = 2*(2^255 - 19) = 2^256 - 38

///|        在 256-bit 表示下, = 2^256 - 38 = (2^256 - 1) - 37 = 0xFFFF...FF - 37

///| 实际上 minusp 只是 freeze 用的(用于 add(a, a, minusp))

///| OpenBSD freeze 逻辑: a += minusp; if bit 255 set: keep aorig; else keep new a

///| minusp = 19 + 2^255 → a + (2^255 + 19) → a + 2^255 + 19 → 触发 2^255 进位

///| 如果 a_orig < p: a_new = a + 2^255 + 19 ≡ a + 19 (mod p); bit 255 置位 → keep aorig

///| 如果 a_orig ≥ p: a_new = a + 2^255 + 19 ≡ a - p + 19; bit 255 清零 → keep new

///|
/// OK minusp = [19, 0,..., 0, 128] 是正确的
pub let minusp : FixedArray[UInt] = [
  19U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
  0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 128U,
]
