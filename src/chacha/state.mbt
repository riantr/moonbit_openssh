///| ChaCha20 state — 4x4 状态矩阵的线性化表示

///| 对应 OpenSSH `chacha_ctx::input[16]`,每个元素是 32-bit 字

///|

///| 布局(OpenSSH / Bernstein 原始变体):

///|   [0..4]   = constants (sigma 或 tau,4 个 u32)

///|   [4..12]  = key       (8 个 u32,256-bit 模式;128-bit 模式时 key 重复填充)

///|   [12..14] = counter   (u64,小端:low=u32 @12, high=u32 @13)

///|
///   [14..16] = iv        (8 字节,小端)
pub struct ChaChaState {
  priv input : FixedArray[UInt] // length == 16
}

///|
/// 状态矩阵长度,公开以便调用者做断言
pub let state_len : Int = 16

///|
/// ChaCha20 块大小,单位:字节
pub let block_len : Int = 64

///|
/// Nonce 长度,单位:字节
pub let nonce_len : Int = 8

///|
/// 128-bit key 长度,单位:字节
pub let key_128_len : Int = 16

///|
/// 256-bit key 长度,单位:字节
pub let key_256_len : Int = 32

///| "expand 32-byte k" — Bernstein sigma 常量,4 个 u32

///| 字节布局(共 16 字节): 'e','x','p','a' / 'n','d',' ','3' / '2','-','b','y' / 't','e',' ','k'

///|
/// 按 little-endian u32 解读为下面这 4 个常量
let sigma0 : UInt = 0x61707865U // "expa"

///|
let sigma1 : UInt = 0x3320646eU // "nd 3"

///|
let sigma2 : UInt = 0x79622d32U // "2b-y"

///|
let sigma3 : UInt = 0x6b206574U // "te k"   ← 注意:是 "byte" 的 t/e/ /k,不是 "by" 的 e/ /k

///| "expand 16-byte k" — Bernstein tau 常量,4 个 u32

///|
/// 字节布局: 'e','x','p','a' / 'n','d',' ','1' / '6','-','b','y' / 't','e',' ','k'
let tau0 : UInt = 0x61707865U // "expa"

///|
let tau1 : UInt = 0x3120646eU // "nd 1"

///|
let tau2 : UInt = 0x79622d36U // "6b-y"

///|
let tau3 : UInt = 0x6b206574U // "te k"   ← 同 sigma3
