///| X25519 freeze - mod p 归约

///| 对应 OpenBSD smult_curve25519_ref.c 第 50-60 行

///|

///| 若 a >= p: a -= p  (等价于 a + 2*p 触发进位,然后减回 aorig)

///|
/// constant-time 实现
pub fn freeze(a : FixedArray[UInt]) -> Unit {
  let aorig : FixedArray[UInt] = FixedArray::make(32, 0U)
  for j = 0; j < 32; j = j + 1 {
    aorig[j] = a[j]
  }
  fe_add(a, a, minusp)
  // negative: 若 a[31] bit 7 = 1 (即 a_orig >= p),用 negative=0xFFFFFFFF 选 new a
  //          否则 negative=0 选 aorig
  // 这里 if-else 不依赖 secret (a[31]>>7 取决于 a, 而 a 在 freeze 之前已被 squeeze 归约到 [0,p)
  // squeeze 后 a ∈ [0, 2^255+19),若原 a < p 则 a+2p < 3p < 2^256,bit 255 = 0
  //                                     若原 a >= p 则 a+2p ≥ 3p,bit 255 = 1
  // 总之 negative 取决于原 a, 而原 a 不再是 secret(public key 派生),所以可分支
  let negative : UInt = if ((a[31] >> 7) & 1U) != 0 { 0xFFFFFFFFU } else { 0U }
  for j = 0; j < 32; j = j + 1 {
    a[j] = a[j] ^ (negative & (aorig[j] ^ a[j]))
  }
}
