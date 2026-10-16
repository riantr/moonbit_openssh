///| HMAC-SHA256 实现

///| 对应 RFC 2104 + OpenBSD hmac.c

///|

///| HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))

///| where K' = K if len(K) <= B else H(K)[:B]

///|       K' = K' || 0x00...0 to length B

///|       opad = 0x5c repeated B times

///|       ipad = 0x36 repeated B times

///|       B = SHA-256 block_size = 64 bytes

///|

///| 注:本文件直接 inline 了 SHA-256 实现(因为 moon 0.1.20260608 不支持跨包 import,

///|     hmac 包内含 sha256_* 同名模块)。这样不依赖外部包。

///|
/// HMAC-SHA256 块大小(等于 SHA-256 block_size)
pub let block_size : Int32 = 64

///|
/// HMAC-SHA256 输出长度(等于 SHA-256 hash_size = 32)
pub let output_size : Int32 = 32

///|
/// ipad 常量
let ipad_byte : Byte = b'\x36'

///|
/// opad 常量
let opad_byte : Byte = b'\x5c'

///|
/// 计算 HMAC-SHA256(key, message) -> 32 字节点阵
pub fn hmac_sha256(
  key : FixedArray[Byte],
  message : FixedArray[Byte],
) -> FixedArray[Byte] {
  // 1. 准备 K'(64 字节)
  let k_pad : FixedArray[Byte] = prep_key(key)
  // 2. 准备 ipad_key 和 opad_key
  let ipad_key : FixedArray[Byte] = FixedArray::make(block_size, ipad_byte)
  let opad_key : FixedArray[Byte] = FixedArray::make(block_size, opad_byte)
  for i = 0; i < block_size; i = i + 1 {
    ipad_key[i] = ipad_key[i] ^ k_pad[i]
    opad_key[i] = opad_key[i] ^ k_pad[i]
  }
  // 3. inner = SHA256(ipad_key || msg)
  let inner = inner_hash(ipad_key, message)
  // 4. tag = SHA256(opad_key || inner)
  outer_hash(opad_key, inner)
}

///| 准备 K'(64 字节):

///|   - 如果 len(K) > 64: K = SHA256(K)[:32]; 后续 pad 0 到 64

///|
///   - 如果 len(K) <= 64: K 直接复制,后续 pad 0 到 64
fn prep_key(key : FixedArray[Byte]) -> FixedArray[Byte] {
  let k_pad : FixedArray[Byte] = FixedArray::make(block_size, b'\x00')
  if key.length() > block_size {
    // key 太长,先 hash
    let hashed = sha256(key)
    for i = 0; i < output_size; i = i + 1 {
      k_pad[i] = hashed[i]
    }
    // 后 32 字节保持 0
  } else {
    // key 直接复制
    for i = 0; i < key.length(); i = i + 1 {
      k_pad[i] = key[i]
    }
    // 后部分保持 0
  }
  k_pad
}

///|
/// inner = SHA256(ipad_key || msg)
fn inner_hash(
  ipad_key : FixedArray[Byte],
  message : FixedArray[Byte],
) -> FixedArray[Byte] {
  // 拼接 ipad_key + msg,然后 SHA256
  let combined : FixedArray[Byte] = FixedArray::make(
    block_size + message.length(),
    b'\x00',
  )
  for i = 0; i < block_size; i = i + 1 {
    combined[i] = ipad_key[i]
  }
  for i = 0; i < message.length(); i = i + 1 {
    combined[block_size + i] = message[i]
  }
  sha256(combined)
}

///|
/// outer = SHA256(opad_key || inner)
fn outer_hash(
  opad_key : FixedArray[Byte],
  inner : FixedArray[Byte],
) -> FixedArray[Byte] {
  let combined : FixedArray[Byte] = FixedArray::make(
    block_size + inner.length(),
    b'\x00',
  )
  for i = 0; i < block_size; i = i + 1 {
    combined[i] = opad_key[i]
  }
  for i = 0; i < inner.length(); i = i + 1 {
    combined[block_size + i] = inner[i]
  }
  sha256(combined)
}
