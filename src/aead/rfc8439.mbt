///| RFC 8439 ChaCha20-Poly1305 AEAD 核心实现

///|

///| IETF 变体与 OpenSSH/Bernstein 变体的 state 布局不同:

///|   RFC 8439: [0..4]=sigma, [4..12]=key, [12]=32-bit counter, [13..16]=12-byte nonce

///|   Bernstein(本包 chacha_*): [12..14]=64-bit counter, [14..16]=8-byte IV

///|

///| 因此这里不能复用 ChaChaState::set_iv,必须直接构造 16-word state。

///| 块函数本身(chacha_block)是同一个,直接复用。

///| sigma 常量已在 chacha_state.mbt 中定义(sigma0..sigma3)

///|
/// 构造 RFC 8439 布局的初始 state
fn rfc8439_state(
  key : FixedArray[Byte],
  nonce12 : FixedArray[Byte],
  counter : UInt,
) -> FixedArray[UInt] {
  if key.length() != 32 {
    abort("rfc8439_state: key must be 32 bytes")
  }
  if nonce12.length() != 12 {
    abort("rfc8439_state: nonce must be 12 bytes")
  }
  let s : FixedArray[UInt] = FixedArray::make(16, 0U)
  s[0] = sigma0
  s[1] = sigma1
  s[2] = sigma2
  s[3] = sigma3
  s[4] = u8_to_32_le(key, 0)
  s[5] = u8_to_32_le(key, 4)
  s[6] = u8_to_32_le(key, 8)
  s[7] = u8_to_32_le(key, 12)
  s[8] = u8_to_32_le(key, 16)
  s[9] = u8_to_32_le(key, 20)
  s[10] = u8_to_32_le(key, 24)
  s[11] = u8_to_32_le(key, 28)
  s[12] = counter
  s[13] = u8_to_32_le(nonce12, 0)
  s[14] = u8_to_32_le(nonce12, 4)
  s[15] = u8_to_32_le(nonce12, 8)
  s
}

///| 用 RFC 8439 布局生成 keystream 并 XOR(加密=解密)

///|
/// counter 从 start_counter 开始自增(32-bit,溢出回绕由调用者保证不发生)
fn rfc8439_xor(
  state : FixedArray[UInt],
  input : FixedArray[Byte],
) -> FixedArray[Byte] {
  let output : FixedArray[Byte] = FixedArray::make(input.length(), b'\x00')
  let mut pos : Int = 0
  let mut ctr : UInt = state[12]
  while pos < input.length() {
    let round : FixedArray[UInt] = FixedArray::make(16, 0U)
    for i = 0; i < 16; i = i + 1 {
      round[i] = state[i]
    }
    round[12] = ctr
    let ks = chacha_block(round)
    let take = if input.length() - pos < 64 { input.length() - pos } else { 64 }
    for j = 0; j < take; j = j + 1 {
      let w = ks[j / 4]
      let shift = j % 4 * 8
      let kb = ((w >> shift) & 0xFFU).to_byte()
      output[pos + j] = kb ^ input[pos + j]
    }
    ctr = ctr + 1U
    pos = pos + take
  }
  output
}

///|
/// pad16:返回补零到 16 倍数需要的字节数(len % 16 == 0 时为 0)
fn pad16_len(n : Int) -> Int {
  let r = n % 16
  if r == 0 {
    0
  } else {
    16 - r
  }
}

///|
/// 把 UInt64 以 little-endian 写入 byte 数组
fn put_u64_le(bytes : FixedArray[Byte], offset : Int, v : UInt64) -> Unit {
  for i = 0; i < 8; i = i + 1 {
    bytes[offset + i] = ((v >> (i * 8)) & 0xFFUL).to_byte()
  }
}

///| 构造 RFC 8439 § 2.8 的 MAC 输入:

///|
///   aad ‖ pad16(aad) ‖ ct ‖ pad16(ct) ‖ LE64(|aad|) ‖ LE64(|ct|)
fn aead_mac_data(
  aad : FixedArray[Byte],
  ct : FixedArray[Byte],
) -> FixedArray[Byte] {
  let total = aad.length() +
    pad16_len(aad.length()) +
    ct.length() +
    pad16_len(ct.length()) +
    16
  let buf : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < aad.length(); i = i + 1 {
    buf[off + i] = aad[i]
  }
  off = off + aad.length() + pad16_len(aad.length())
  for i = 0; i < ct.length(); i = i + 1 {
    buf[off + i] = ct[i]
  }
  off = off + ct.length() + pad16_len(ct.length())
  put_u64_le(buf, off, aad.length().to_uint64())
  put_u64_le(buf, off + 8, ct.length().to_uint64())
  buf
}

///|
/// 派生 Poly1305 key:ChaCha20 block(counter=0)的前 32 字节
fn aead_poly_key(
  key : FixedArray[Byte],
  nonce : FixedArray[Byte],
) -> FixedArray[Byte] {
  let st = rfc8439_state(key, nonce, 0U)
  let ks = chacha_block(st)
  let pk : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for w = 0; w < 8; w = w + 1 {
    for b = 0; b < 4; b = b + 1 {
      pk[w * 4 + b] = ((ks[w] >> (b * 8)) & 0xFFU).to_byte()
    }
  }
  pk
}

///| RFC 8439 AEAD 加密

///|
/// 返回 ct ‖ tag(16),总长 |pt| + 16
pub fn aead_encrypt(
  key : FixedArray[Byte],
  nonce : FixedArray[Byte],
  aad : FixedArray[Byte],
  plaintext : FixedArray[Byte],
) -> FixedArray[Byte] {
  // 1. poly key = block counter 0
  let pk = aead_poly_key(key, nonce)
  // 2. payload keystream 从 counter 1 起
  let enc_state = rfc8439_state(key, nonce, 1U)
  let ct = rfc8439_xor(enc_state, plaintext)
  // 3. tag over mac_data
  let tag = poly1305_auth(pk, aead_mac_data(aad, ct))
  // 4. 输出 ct || tag
  let out : FixedArray[Byte] = FixedArray::make(ct.length() + 16, b'\x00')
  for i = 0; i < ct.length(); i = i + 1 {
    out[i] = ct[i]
  }
  for i = 0; i < 16; i = i + 1 {
    out[ct.length() + i] = tag[i]
  }
  out
}

///| RFC 8439 AEAD 解密

///|
/// 输入 = ct ‖ tag(16);tag 不匹配时返回 None
pub fn aead_decrypt(
  key : FixedArray[Byte],
  nonce : FixedArray[Byte],
  aad : FixedArray[Byte],
  ct_and_tag : FixedArray[Byte],
) -> FixedArray[Byte]? {
  if ct_and_tag.length() < 16 {
    return None
  }
  let ctlen = ct_and_tag.length() - 16
  let ct : FixedArray[Byte] = FixedArray::make(ctlen, b'\x00')
  for i = 0; i < ctlen; i = i + 1 {
    ct[i] = ct_and_tag[i]
  }
  // 重算期望 tag
  let pk = aead_poly_key(key, nonce)
  let expect = poly1305_auth(pk, aead_mac_data(aad, ct))
  // 比较(vartime 可接受:tag 是公开数据)
  for i = 0; i < 16; i = i + 1 {
    if expect[i] != ct_and_tag[ctlen + i] {
      return None
    }
  }
  // 解密
  let dec_state = rfc8439_state(key, nonce, 1U)
  Some(rfc8439_xor(dec_state, ct))
}
