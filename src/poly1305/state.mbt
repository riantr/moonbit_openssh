///| Poly1305 状态与常量

///| 对应 RFC 8439 § 2.5,128-bit authenticator

///|
/// 单个 block 长度,字节
pub let block_len : Int32 = 16

///|
/// Key 长度,字节
pub let key_len : Int32 = 32

///|
/// Tag 长度,字节
pub let tag_len : Int32 = 16

///|
/// 5 个 limb 数(每个 26-bit,共 130 bit)
pub let limb_count : Int32 = 5
