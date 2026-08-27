///| Ed25519 公开 API

///| 对应 RFC 8032 + OpenSSH ed25519.c (TweetNaCl ref10)

///|

///| 三个核心函数:

///| - keypair_from_seed: 32-byte seed → (32-byte pk, 64-byte sk)

///| - sign: sk + msg → 64-byte sig

///| - verify: sig + msg + pk → bool

///| 从 32 字节 seed 派生 (pk, sk)

///| 符合 RFC 8032 § 5.1.2

///|
/// 返回:(pk[32], sk[64]),sk = seed || pk
pub fn keypair_from_seed(
  seed : FixedArray[Byte],
) -> (FixedArray[Byte], FixedArray[Byte]) {
  if seed.length() != 32 {
    abort("keypair_from_seed: seed must be 32 bytes")
  }
  // 1. h = SHA-512(seed)  → 64 字节
  let h : FixedArray[Byte] = sha512(seed)
  // 2. clamp:h[0..32] 用于 scalar a
  let az : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    az[i] = h[i]
  }
  az[0] = (az[0].to_uint64() & 0xF8UL).to_byte()
  az[31] = (az[31].to_uint64() & 0x7FUL).to_byte()
  az[31] = (az[31].to_uint64() | 0x40UL).to_byte()
  // 3. A = a * B
  let a : Sc = sc_from32bytes(slice_32(az, 0))
  let a_pt : Ge_p3 = ge_scalarmult_base(a)
  // 4. pk = pack(A)
  let pk : FixedArray[Byte] = ge_pack(a_pt)
  // 5. sk = seed || pk
  let sk : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    sk[i] = seed[i]
    sk[i + 32] = pk[i]
  }
  (pk, sk)
}

///| 签名 msg(任意长度)用 sk(64 字节 = seed || pk)

///| 符合 RFC 8032 § 5.1.6

///|
/// 返回 64 字节 sig
pub fn sign(msg : FixedArray[Byte], sk : FixedArray[Byte]) -> FixedArray[Byte] {
  if sk.length() != 64 {
    abort("sign: sk must be 64 bytes")
  }
  // 1. pk = sk[32..64]
  let pk : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    pk[i] = sk[i + 32]
  }
  // 2. h = SHA-512(sk[0..32])  → 64 字节 (az)
  let seed : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    seed[i] = sk[i]
  }
  let h : FixedArray[Byte] = sha512(seed)
  let az : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    az[i] = h[i]
  }
  // 3. clamp az[0..32] → a
  az[0] = (az[0].to_uint64() & 0xF8UL).to_byte()
  az[31] = (az[31].to_uint64() & 0x7FUL).to_byte()
  az[31] = (az[31].to_uint64() | 0x40UL).to_byte()
  let a : Sc = sc_from32bytes(slice_32(az, 0))
  // 4. prefix = az[32..64]
  let prefix : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    prefix[i] = az[i + 32]
  }
  // 5. nonce = SHA-512(prefix || msg)
  let nonce_in : FixedArray[Byte] = FixedArray::make(
    prefix.length() + msg.length(),
    b'\x00',
  )
  for i = 0; i < prefix.length(); i = i + 1 {
    nonce_in[i] = prefix[i]
  }
  for i = 0; i < msg.length(); i = i + 1 {
    nonce_in[prefix.length() + i] = msg[i]
  }
  let nonce : FixedArray[Byte] = sha512(nonce_in)
  // 6. r = nonce mod L → Scalar
  let r_sc : Sc = sc_from64bytes(nonce)
  // 7. R = r * B
  let r_pt : Ge_p3 = ge_scalarmult_base(r_sc)
  let r_bytes : FixedArray[Byte] = ge_pack(r_pt)
  // 8. hram_in = R_bytes || pk || msg
  let hram_in : FixedArray[Byte] = FixedArray::make(
    r_bytes.length() + pk.length() + msg.length(),
    b'\x00',
  )
  for i = 0; i < 32; i = i + 1 {
    hram_in[i] = r_bytes[i]
    hram_in[i + 32] = pk[i]
  }
  for i = 0; i < msg.length(); i = i + 1 {
    hram_in[64 + i] = msg[i]
  }
  // 9. hram = SHA-512(hram_in) → h
  let hram : FixedArray[Byte] = sha512(hram_in)
  let h_sc : Sc = sc_from64bytes(hram)
  // 10. s = (r + h * a) mod L
  let ha : Sc = sc_mul(h_sc, a)
  let s_sc : Sc = sc_add(r_sc, ha)
  let s_bytes : FixedArray[Byte] = sc_to32bytes(s_sc)
  // 11. sig = R_bytes || s_bytes
  let sig : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    sig[i] = r_bytes[i]
    sig[i + 32] = s_bytes[i]
  }
  sig
}

///| 验证 sig 是否对 msg 有效(用 pk)

///| 符合 RFC 8032 § 5.1.7

///|
/// 返回 true 表示有效
pub fn verify(
  sig : FixedArray[Byte],
  msg : FixedArray[Byte],
  pk : FixedArray[Byte],
) -> Bool {
  if sig.length() != 64 {
    return false
  }
  if pk.length() != 32 {
    return false
  }
  // 1. check sig[63] & 224 == 0 (R high bits cleared except sign)
  if (sig[63].to_uint64() & 0xE0UL) != 0UL {
    return false
  }
  // 2. s = sig[32..64], check raw s bytes < L BEFORE any reduction
  //    (对应 C: sc25519_inrange(sm+32) 在 barrett_reduce 之前调用)
  let s_bytes : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    s_bytes[i] = sig[i + 32]
  }
  if !sc_is_in_range_bytes(s_bytes) {
    return false
  }
  let s_sc : Sc = sc_from32bytes(s_bytes)
  // 3. unpackneg(pk) → -A
  let unpack_result : (Ge_p3, Bool) = ge_unpackneg_vartime(pk)
  let a_neg : Ge_p3 = unpack_result.0
  let ok : Bool = unpack_result.1
  if !ok {
    return false
  }
  if ge_isneutral_vartime(a_neg) {
    return false
  }
  // 4. compute h = SHA-512(R || pk || msg) mod L
  let r_bytes : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    r_bytes[i] = sig[i]
  }
  let hram_in : FixedArray[Byte] = FixedArray::make(
    32 + 32 + msg.length(),
    b'\x00',
  )
  for i = 0; i < 32; i = i + 1 {
    hram_in[i] = r_bytes[i]
    hram_in[i + 32] = pk[i]
  }
  for i = 0; i < msg.length(); i = i + 1 {
    hram_in[64 + i] = msg[i]
  }
  let hram : FixedArray[Byte] = sha512(hram_in)
  let h_sc : Sc = sc_from64bytes(hram)
  // 5. compute P = h*(-A) + s*B, check pack(P) == R
  let p_pt : Ge_p3 = ge_double_scalarmult_vartime(
    a_neg, h_sc, ge25519_base, s_sc,
  )
  let pcheck : FixedArray[Byte] = ge_pack(p_pt)
  equal_32(pcheck, r_bytes)
}

///|
/// 比较两个 32 字节 FixedArray 是否相等(变长时间)
fn equal_32(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut eq : Bool = true
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      eq = false
    }
  }
  eq
}

///|
/// 辅助:从 FixedArray 切片取 32 字节
fn slice_32(src : FixedArray[Byte], offset : Int) -> FixedArray[Byte] {
  let r : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    r[i] = src[offset + i]
  }
  r
}
