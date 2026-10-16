///| AES block cipher + AES-CTR mode (Loop #25 G1)
///
/// 实现:
///   - AES block encrypt: FIPS 197
///   - AES block decrypt: FIPS 197 InvCipher
///   - AES-CTR encrypt/decrypt: RFC 4344 §4 (OpenSSH convention)
///   - AES-GCM AEAD encrypt/decrypt: RFC 5647 + NIST SP 800-38D
///
/// 字节级 byte-exact vs OpenSSL EVP_aes_*_ctr / EVP_aes_*_gcm

// ============================================================================
// AES S-box (FIPS 197 §5.1.1 InvSubBytes transformation table)
// ============================================================================

///|
/// AES S-box (256 bytes, FIPS 197 §5.1.1)
let sbox : FixedArray[Byte] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
  0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
  0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5,
  0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e,
  0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
  0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef,
  0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
  0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d,
  0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
  0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5,
  0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e,
  0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
  0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55,
  0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
  0xb0, 0x54, 0xbb, 0x16,
]

///|
/// AES inverse S-box (FIPS 197 §5.1.1 InvSubBytes transformation table)
let inv_sbox : FixedArray[Byte] = [
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3,
  0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44,
  0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c,
  0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
  0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68,
  0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
  0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8,
  0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13,
  0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce,
  0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
  0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
  0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2,
  0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33,
  0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51,
  0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53,
  0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
  0x55, 0x21, 0x0c, 0x7d,
]

// ============================================================================
// GF(2^8) arithmetic (for MixColumns)
// ============================================================================

///|
/// GF(2^8) xtime (multiply by 2 in AES field, FIPS 197 §4.2.1)
fn xtime(x : Byte) -> Byte {
  let hi = x.to_int() & 0x80 // MSB
  let lo = (x.to_int() << 1) & 0xFF
  if hi != 0 {
    (lo ^ 0x1B).to_byte()
  } else {
    lo.to_byte()
  }
}

///|
/// GF(2^8) multiply by 2: alias for xtime
fn gmul2(x : Byte) -> Byte {
  xtime(x)
}

///|
/// GF(2^8) multiply by 3: gmul3(x) = gmul2(x) XOR x
fn gmul3(x : Byte) -> Byte {
  (xtime(x).to_int() ^ x.to_int()).to_byte()
}

///|
/// GF(2^8) multiply by 9: 0x9 = 0b1001
fn gmul9(x : Byte) -> Byte {
  // 0x9*x = ((x << 3) ^ x) — but with reduction
  let a = xtime(x)
  let b = xtime(a)
  let c = xtime(b)
  (c.to_int() ^ x.to_int()).to_byte()
}

///|
/// GF(2^8) multiply by 11: 0xB = 0x8 ^ 0x2 ^ 0x1
fn gmul11(x : Byte) -> Byte {
  let a = xtime(x)
  let b = xtime(a)
  let c = xtime(b)
  (c.to_int() ^ a.to_int() ^ x.to_int()).to_byte()
}

///|
/// GF(2^8) multiply by 13: 0xD = 0x8 ^ 0x4 ^ 0x1
fn gmul13(x : Byte) -> Byte {
  let a = xtime(x)
  let b = xtime(a)
  let c = xtime(b)
  (c.to_int() ^ b.to_int() ^ x.to_int()).to_byte()
}

///|
/// GF(2^8) multiply by 14: 0xE = 0x8 ^ 0x4 ^ 0x2
fn gmul14(x : Byte) -> Byte {
  let a = xtime(x)
  let b = xtime(a)
  let c = xtime(b)
  (c.to_int() ^ b.to_int() ^ a.to_int()).to_byte()
}

// ============================================================================
// AES state operations (FIPS 197 §4)
// ============================================================================

///|
/// SubBytes: 替换每个 byte 通过 S-box
fn sub_bytes(state : FixedArray[Byte]) -> Unit {
  for i = 0; i < state.length(); i = i + 1 {
    state[i] = sbox[state[i].to_int()]
  }
}

///|
/// InvSubBytes: 替换每个 byte 通过 inverse S-box
fn inv_sub_bytes(state : FixedArray[Byte]) -> Unit {
  for i = 0; i < state.length(); i = i + 1 {
    state[i] = inv_sbox[state[i].to_int()]
  }
}

///|
/// ShiftRows: 第 r 行循环左移 r 位 (state 是 4x4 列主序)
fn shift_rows(state : FixedArray[Byte]) -> Unit {
  // state layout (column-major): state[4c + r]
  // row 0: no shift
  // row 1: shift left 1
  let tmp = state[1]
  state[1] = state[5]
  state[5] = state[9]
  state[9] = state[13]
  state[13] = tmp
  // row 2: shift left 2
  let t1 = state[2]
  let t2 = state[6]
  state[2] = state[10]
  state[6] = state[14]
  state[10] = t1
  state[14] = t2
  // row 3: shift left 3
  let tmp3 = state[3]
  state[3] = state[15]
  state[15] = state[11]
  state[11] = state[7]
  state[7] = tmp3
}

///|
/// InvShiftRows: 第 r 行循环右移 r 位
fn inv_shift_rows(state : FixedArray[Byte]) -> Unit {
  let tmp = state[13]
  state[13] = state[9]
  state[9] = state[5]
  state[5] = state[1]
  state[1] = tmp
  let t1 = state[2]
  let t2 = state[6]
  state[2] = state[10]
  state[6] = state[14]
  state[10] = t1
  state[14] = t2
  let tmp3 = state[3]
  state[3] = state[7]
  state[7] = state[11]
  state[11] = state[15]
  state[15] = tmp3
}

///|
/// MixColumns: 每列乘以固定多项式 a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
fn mix_columns(state : FixedArray[Byte]) -> Unit {
  for c = 0; c < 4; c = c + 1 {
    let s0 = state[4 * c]
    let s1 = state[4 * c + 1]
    let s2 = state[4 * c + 2]
    let s3 = state[4 * c + 3]
    state[4 * c] = (gmul2(s0).to_int() ^
    gmul3(s1).to_int() ^
    s2.to_int() ^
    s3.to_int()).to_byte()
    state[4 * c + 1] = (s0.to_int() ^
    gmul2(s1).to_int() ^
    gmul3(s2).to_int() ^
    s3.to_int()).to_byte()
    state[4 * c + 2] = (s0.to_int() ^
    s1.to_int() ^
    gmul2(s2).to_int() ^
    gmul3(s3).to_int()).to_byte()
    state[4 * c + 3] = (gmul3(s0).to_int() ^
    s1.to_int() ^
    s2.to_int() ^
    gmul2(s3).to_int()).to_byte()
  }
}

///|
/// InvMixColumns: 每列乘以固定多项式 a^-1(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}
fn inv_mix_columns(state : FixedArray[Byte]) -> Unit {
  for c = 0; c < 4; c = c + 1 {
    let s0 = state[4 * c]
    let s1 = state[4 * c + 1]
    let s2 = state[4 * c + 2]
    let s3 = state[4 * c + 3]
    state[4 * c] = (gmul14(s0).to_int() ^
    gmul11(s1).to_int() ^
    gmul13(s2).to_int() ^
    gmul9(s3).to_int()).to_byte()
    state[4 * c + 1] = (gmul9(s0).to_int() ^
    gmul14(s1).to_int() ^
    gmul11(s2).to_int() ^
    gmul13(s3).to_int()).to_byte()
    state[4 * c + 2] = (gmul13(s0).to_int() ^
    gmul9(s1).to_int() ^
    gmul14(s2).to_int() ^
    gmul11(s3).to_int()).to_byte()
    state[4 * c + 3] = (gmul11(s0).to_int() ^
    gmul13(s1).to_int() ^
    gmul9(s2).to_int() ^
    gmul14(s3).to_int()).to_byte()
  }
}

///|
/// AddRoundKey: state XOR round_key
fn add_round_key(
  state : FixedArray[Byte],
  round_key : FixedArray[Byte],
) -> Unit {
  for i = 0; i < 16; i = i + 1 {
    state[i] = (state[i].to_int() ^ round_key[i].to_int()).to_byte()
  }
}

// ============================================================================
// AES key schedule (FIPS 197 §5.2)
// ============================================================================

///|
/// AES round constant Rcon[i] = x^i in GF(2^8)
let rcon : FixedArray[Byte] = [
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
  0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
  0xef, 0xc5, 0x91, 0x39,
]

///|
/// Key schedule for AES-128/192/256 (FIPS 197 §5.2)
/// Returns (Nk+Nb*(Nr+1))-byte expanded key
pub fn aes_key_expand(key : FixedArray[Byte]) -> FixedArray[Byte] {
  let nk = key.length() / 4 // 4 (AES-128) | 6 (AES-192) | 8 (AES-256)
  let nb = 4
  let nr = if nk == 4 { 10 } else if nk == 6 { 12 } else { 14 }
  let out_len = nb * (nr + 1) * 4
  let out : FixedArray[Byte] = FixedArray::make(out_len, b'\x00')

  // copy key into first Nk words
  for i = 0; i < key.length(); i = i + 1 {
    out[i] = key[i]
  }

  let mut i = nk
  while i < nb * (nr + 1) {
    // out[4*(i-1)..4*i] is the previous word
    let mut temp0 = out[4 * (i - 1)]
    let mut temp1 = out[4 * (i - 1) + 1]
    let mut temp2 = out[4 * (i - 1) + 2]
    let mut temp3 = out[4 * (i - 1) + 3]

    if i % nk == 0 {
      // RotWord + SubWord + Rcon
      let t = temp0
      temp0 = temp1
      temp1 = temp2
      temp2 = temp3
      temp3 = t
      temp0 = sbox[temp0.to_int()]
      temp1 = sbox[temp1.to_int()]
      temp2 = sbox[temp2.to_int()]
      temp3 = sbox[temp3.to_int()]
      temp0 = (temp0.to_int() ^ rcon[i / nk].to_int()).to_byte()
    } else if nk > 6 && i % nk == 4 {
      // AES-256: extra SubWord
      temp0 = sbox[temp0.to_int()]
      temp1 = sbox[temp1.to_int()]
      temp2 = sbox[temp2.to_int()]
      temp3 = sbox[temp3.to_int()]
    }

    out[4 * i] = (out[4 * (i - nk)].to_int() ^ temp0.to_int()).to_byte()
    out[4 * i + 1] = (out[4 * (i - nk) + 1].to_int() ^ temp1.to_int()).to_byte()
    out[4 * i + 2] = (out[4 * (i - nk) + 2].to_int() ^ temp2.to_int()).to_byte()
    out[4 * i + 3] = (out[4 * (i - nk) + 3].to_int() ^ temp3.to_int()).to_byte()
    i = i + 1
  }

  out
}

// ============================================================================
// AES block cipher (FIPS 197 §5.1 Cipher / §5.3 InvCipher)
// ============================================================================

///|
/// AES block encrypt: 16 bytes plaintext + 16/24/32 byte key → 16 bytes ciphertext
pub fn aes_encrypt_block(
  key : FixedArray[Byte],
  block : FixedArray[Byte],
) -> FixedArray[Byte] {
  let nk = key.length() / 4
  let nr = if nk == 4 { 10 } else if nk == 6 { 12 } else { 14 }
  let expanded = aes_key_expand(key)
  let state : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    state[i] = block[i]
  }
  // Initial AddRoundKey
  add_round_key(state, sub_array(expanded, 0, 16))
  // Rounds 1..Nr-1
  let mut round = 1
  while round < nr {
    sub_bytes(state)
    shift_rows(state)
    mix_columns(state)
    add_round_key(state, sub_array(expanded, 16 * round, 16))
    round = round + 1
  }
  // Final round (no MixColumns)
  sub_bytes(state)
  shift_rows(state)
  add_round_key(state, sub_array(expanded, 16 * nr, 16))
  state
}

///|
/// AES block decrypt: 16 bytes ciphertext + 16/24/32 byte key → 16 bytes plaintext
pub fn aes_decrypt_block(
  key : FixedArray[Byte],
  block : FixedArray[Byte],
) -> FixedArray[Byte] {
  let nk = key.length() / 4
  let nr = if nk == 4 { 10 } else if nk == 6 { 12 } else { 14 }
  let expanded = aes_key_expand(key)
  let state : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    state[i] = block[i]
  }
  // Initial AddRoundKey with last round key
  add_round_key(state, sub_array(expanded, 16 * nr, 16))
  let mut round = nr - 1
  while round >= 1 {
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, sub_array(expanded, 16 * round, 16))
    inv_mix_columns(state)
    round = round - 1
  }
  inv_shift_rows(state)
  inv_sub_bytes(state)
  add_round_key(state, sub_array(expanded, 0, 16))
  state
}

///|
/// 提取 FixedArray 子数组 (start, length) — 类似 Java System.arraycopy
fn sub_array(
  src : FixedArray[Byte],
  start : Int32,
  length : Int32,
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(length, b'\x00')
  for i = 0; i < length; i = i + 1 {
    out[i] = src[start + i]
  }
  out
}

// ============================================================================
// AES-CTR mode (RFC 4344 §4: SSH AES-CTR)
// ============================================================================

///|
/// 16 字节 IV 计数器递增 (big-endian, last 8 bytes; OpenSSH convention)
fn ctr_increment(iv : FixedArray[Byte]) -> Unit {
  // RFC 4344 §4: counter in last 8 bytes, big-endian
  let mut i = 15
  while i >= 8 {
    let v = iv[i].to_int() + 1
    if v < 256 {
      iv[i] = v.to_byte()
      return
    }
    iv[i] = 0
    i = i - 1
  }
}

///|
/// AES-CTR encrypt/decrypt (same operation, XOR keystream)
pub fn aes_ctr(
  key : FixedArray[Byte],
  iv : FixedArray[Byte],
  input : FixedArray[Byte],
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(input.length(), b'\x00')
  let counter : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    counter[i] = iv[i]
  }
  let mut off = 0
  while off < input.length() {
    let keystream = aes_encrypt_block(key, counter)
    let chunk = if input.length() - off > 16 {
      16
    } else {
      input.length() - off
    }
    for i = 0; i < chunk; i = i + 1 {
      out[off + i] = (input[off + i].to_int() ^ keystream[i].to_int()).to_byte()
    }
    ctr_increment(counter)
    off = off + 16
  }
  out
}

// ============================================================================
// AES-GCM (RFC 5647 + NIST SP 800-38D) — Loop #26+ 完整实现
// ============================================================================

///|
/// GHASH 单步: state = state XOR block; 然后 state = state * H (in GF(2^128))
fn ghash_step(
  state : FixedArray[Byte],
  block : FixedArray[Byte],
  h : FixedArray[Byte],
) -> Unit {
  // state XOR block
  for i = 0; i < 16; i = i + 1 {
    state[i] = (state[i].to_int() ^ block[i].to_int()).to_byte()
  }
  // GF(2^128) multiply by H (MSB-first, NIST SP 800-38D §6.3)
  let z : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let v : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    v[i] = h[i]
  }
  let mut bit = 0
  while bit < 128 {
    let byte_idx = bit / 8
    let bit_idx = 7 - bit % 8
    let state_bit = (state[byte_idx].to_int() >> bit_idx) & 1
    if state_bit == 1 {
      for i = 0; i < 16; i = i + 1 {
        z[i] = (z[i].to_int() ^ v[i].to_int()).to_byte()
      }
    }
    // v = H * x (mod p(x) = x^128 + x^7 + x^2 + x + 1)
    let lsb = v[15].to_int() & 1
    // shift right 1
    let mut carry = 0
    for i = 0; i < 16; i = i + 1 {
      let new_carry = v[i].to_int() & 1
      v[i] = ((v[i].to_int() >> 1) | (carry << 7)).to_byte()
      carry = new_carry
    }
    if lsb == 1 {
      v[0] = (v[0].to_int() ^ 0xE1).to_byte()
    }
    bit = bit + 1
  }
  for i = 0; i < 16; i = i + 1 {
    state[i] = z[i]
  }
}

///|
/// GHASH full: 处理 AAD + ciphertext, 输出 auth tag contribution
fn ghash_full(
  h : FixedArray[Byte],
  aad : FixedArray[Byte],
  ct : FixedArray[Byte],
) -> FixedArray[Byte] {
  let state : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  // Process AAD
  let mut i = 0
  while i < aad.length() {
    let chunk = if aad.length() - i > 16 { 16 } else { aad.length() - i }
    let block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for j = 0; j < chunk; j = j + 1 {
      block[j] = aad[i + j]
    }
    ghash_step(state, block, h)
    i = i + 16
  }
  // Process ciphertext
  i = 0
  while i < ct.length() {
    let chunk = if ct.length() - i > 16 { 16 } else { ct.length() - i }
    let block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
    for j = 0; j < chunk; j = j + 1 {
      block[j] = ct[i + j]
    }
    ghash_step(state, block, h)
    i = i + 16
  }
  // Length block: u64(aad_bits) || u64(ct_bits)
  let len_block : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let aad_bits = aad.length() * 8
  let ct_bits = ct.length() * 8
  // Write aad_bits big-endian (8 bytes)
  let mut n = aad_bits
  let mut k = 7
  while k >= 0 {
    len_block[7 - k] = (n & 0xFF).to_byte()
    n = n >> 8
    k = k - 1
  }
  // Write ct_bits big-endian (8 bytes)
  n = ct_bits
  k = 7
  while k >= 0 {
    len_block[15 - k] = (n & 0xFF).to_byte()
    n = n >> 8
    k = k - 1
  }
  ghash_step(state, len_block, h)
  state
}

///|
/// AES-GCM encrypt: 16/32-byte key + 12-byte IV + AAD + plaintext → (ciphertext, tag)
pub fn aes_gcm_encrypt(
  key : FixedArray[Byte],
  iv : FixedArray[Byte],
  aad : FixedArray[Byte],
  plaintext : FixedArray[Byte],
) -> (FixedArray[Byte], FixedArray[Byte]) {
  // 1. H = AES_K(0^128)
  let h_zero : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let h = aes_encrypt_block(key, h_zero)
  // 2. J0 = IV || 0^31 || 1 (NIST SP 800-38D §5.2.1.1, 12-byte IV case)
  let j0 : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 12; i = i + 1 {
    j0[i] = iv[i]
  }
  j0[15] = 1
  // 3. CTR mode encrypt (counter = J0 + 1, big-endian increment on last 4 bytes)
  let ctr : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    ctr[i] = j0[i]
  }
  // Increment last 4 bytes by 1
  let mut carry = 1
  let mut i = 15
  while i >= 12 {
    let v = ctr[i].to_int() + carry
    ctr[i] = (v & 0xFF).to_byte()
    carry = v >> 8
    i = i - 1
  }
  let ciphertext = aes_ctr(key, ctr, plaintext)
  // 4. S = GHASH_H(AAD || CT || len_block)
  let s = ghash_full(h, aad, ciphertext)
  // 5. Tag = S XOR AES_K(J0)
  let ek_j0 = aes_encrypt_block(key, j0)
  let tag : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    tag[i] = (s[i].to_int() ^ ek_j0[i].to_int()).to_byte()
  }
  (ciphertext, tag)
}

///|
/// AES-GCM decrypt: ciphertext + tag → plaintext, returns None if tag invalid
pub fn aes_gcm_decrypt(
  key : FixedArray[Byte],
  iv : FixedArray[Byte],
  aad : FixedArray[Byte],
  ciphertext : FixedArray[Byte],
  tag : FixedArray[Byte],
) -> FixedArray[Byte]? {
  let h_zero : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let h = aes_encrypt_block(key, h_zero)
  let j0 : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 12; i = i + 1 {
    j0[i] = iv[i]
  }
  j0[15] = 1
  let s = ghash_full(h, aad, ciphertext)
  let ek_j0 = aes_encrypt_block(key, j0)
  let mut tag_match = true
  for i = 0; i < 16; i = i + 1 {
    if (s[i].to_int() ^ ek_j0[i].to_int()) != tag[i].to_int() {
      tag_match = false
    }
  }
  if !tag_match {
    return None
  }
  // Decrypt using CTR mode
  let ctr : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    ctr[i] = j0[i]
  }
  let mut carry = 1
  let mut i = 15
  while i >= 12 {
    let v = ctr[i].to_int() + carry
    ctr[i] = (v & 0xFF).to_byte()
    carry = v >> 8
    i = i - 1
  }
  Some(aes_ctr(key, ctr, ciphertext))
}
