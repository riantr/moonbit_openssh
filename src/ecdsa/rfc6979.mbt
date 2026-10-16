///| RFC 6979 deterministic nonce generation (Loop #30 G2)
///
///   RFC 6979 §3.2: given a private key x and a message hash H(m), derive the
///   per-signature nonce k deterministically via HMAC-DRBG. This removes the
///   need for a CSPRNG during ECDSA signing, which matters for a browser
///   client that must not depend on `crypto.getRandomValues` for correctness
///   (and removes the classic "same k for two different messages" footgun).
///
///   V = 0x01 repeated hlen
///   K = 0x00 repeated hlen
///   K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(H(m)))
///   V = HMAC_K(V)
///   K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(H(m)))
///   V = HMAC_K(V)
///   loop:
///     T = empty
///     while len(T) < qlen: V = HMAC_K(V); T = T || V
///     k = bits2int(T)
///     if 1 <= k < order: return k
///     K = HMAC_K(V || 0x00); V = HMAC_K(V)

///|
/// Hash algorithm selector for RFC 6979.
pub enum HashAlg {
  Sha256
  Sha384
}

///|
/// HMAC for the selected algorithm.
fn hmac(
  alg : HashAlg,
  key : FixedArray[Byte],
  msg : FixedArray[Byte],
) -> FixedArray[Byte] {
  match alg {
    Sha256 => @hmac.hmac_sha256(key, msg)
    Sha384 => @hmac_sha384.hmac_sha384(key, msg)
  }
}

///|
/// Hash for the selected algorithm.
pub fn alg_hash(alg : HashAlg, msg : FixedArray[Byte]) -> FixedArray[Byte] {
  match alg {
    Sha256 => @sha256.sha256(msg)
    Sha384 => @sha512.sha384(msg)
  }
}

///|
/// Output length of the selected hash, in bytes.
pub fn alg_hash_len(alg : HashAlg) -> Int32 {
  match alg {
    Sha256 => 32
    Sha384 => 48
  }
}

///|
/// Big-endian bytes of a small non-negative integer.
fn int1(v : Int32) -> FixedArray[Byte] {
  FixedArray::from_array([v.to_byte()])
}

///|
/// bits2int (RFC 6979 §2.3.2): take the leftmost `bits` bits of the octet
///   string, treating it as a big-endian integer. When the hash is at least as
///   long as the group order this is just a big-endian decode.
pub fn bits2int(b : FixedArray[Byte], bits : Int32) -> @bigint.BigNat {
  let total = b.length() * 8
  let mut v = @bigint.BigNat::from_bytes_be(b)
  if total > bits {
    v = @bigint.BigNat::shift_right_bits(v, total - bits)
  }
  v
}

///|
/// int2octets (RFC 6979 §2.3.3): fixed-width big-endian encoding.
pub fn int2octets(v : @bigint.BigNat, rolen : Int32) -> FixedArray[Byte] {
  let raw = @bigint.BigNat::to_bytes_be(v)
  let out : FixedArray[Byte] = FixedArray::make(rolen, b'\x00')
  let take = if raw.length() > rolen { rolen } else { raw.length() }
  let off = rolen - take
  for i = 0; i < take; i = i + 1 {
    out[off + i] = raw[i]
  }
  out
}

///|
/// bits2octets (RFC 6979 §2.3.4): z1 = bits2int(H(m)); z2 = z1 - order;
///   if z2 < 0 use z1, else use z2; then int2octets.
pub fn bits2octets(
  h : FixedArray[Byte],
  order : @bigint.BigNat,
  bits : Int32,
  rolen : Int32,
) -> FixedArray[Byte] {
  let z1 = bits2int(h, bits)
  // z1 < order is the common case; avoid BigNat::sub, which aborts on a<b.
  let z = if @bigint.BigNat::cmp(z1, order) < 0 {
    z1
  } else {
    @bigint.BigNat::sub(z1, order)
  }
  int2octets(z, rolen)
}

///|
/// RFC 6979 §3.2 deterministic nonce for ECDSA.
///
///   `priv_key` must be in [1, order-1]; `h1` is the message hash.
///   Returns k in [1, order-1]. The loop is bounded so a pathological HMAC
///   stream cannot hang the client.
pub fn rfc6979_nonce(
  alg : HashAlg,
  order : @bigint.BigNat,
  bits : Int32,
  priv_key : @bigint.BigNat,
  h1 : FixedArray[Byte],
) -> @bigint.BigNat {
  let hlen = alg_hash_len(alg)
  let rolen = (bits + 7) / 8
  let v : FixedArray[Byte] = FixedArray::make(hlen, b'\x01')
  let k : FixedArray[Byte] = FixedArray::make(hlen, b'\x00')
  let bx = int2octets(priv_key, rolen)
  let bh = bits2octets(h1, order, bits, rolen)
  // K = HMAC_K(V || 0x00 || bx || bh)
  let k1 = hmac(alg, k, cat(cat(cat(v, int1(0)), bx), bh))
  let v1 = hmac(alg, k1, v)
  // K = HMAC_K(V || 0x01 || bx || bh)
  let k2 = hmac(alg, k1, cat(cat(cat(v1, int1(1)), bx), bh))
  let v2 = hmac(alg, k2, v1)
  let mut kcur = k2
  let mut vcur = v2
  // Bounded retry loop (RFC 6979 says "loop forever"; 64 attempts is far more
  // than any real distribution needs and guarantees termination).
  let mut attempt = 0
  while attempt < 64 {
    let mut t : FixedArray[Byte] = FixedArray::make(0, b'\x00')
    while t.length() * 8 < bits {
      vcur = hmac(alg, kcur, vcur)
      t = cat(t, vcur)
    }
    let cand = bits2int(t, bits)
    if @bigint.BigNat::cmp(cand, @bigint.BigNat::from_uint64(0UL)) > 0 &&
      @bigint.BigNat::cmp(cand, order) < 0 {
      return cand
    }
    kcur = hmac(alg, kcur, cat(vcur, int1(0)))
    vcur = hmac(alg, kcur, vcur)
    attempt = attempt + 1
  }
  // Unreachable for any well-formed curve; fall back to a value that will be
  // rejected by the caller rather than looping forever.
  @bigint.BigNat::from_uint64(0UL)
}
