///| HMAC-SHA-384 (RFC 2104 + FIPS 180-4 § 5.3.3)
///|
///| Used by RFC 6979 deterministic ECDSA over P-384, and by SSH's
///| `ecdsa-sha2-nistp384` host key algorithm.

///| HMAC-SHA-384 block size in bytes (SHA-384 uses 1024-bit blocks)
pub let block_size : Int = 128

///| HMAC-SHA-384 output length in bytes
pub let output_size : Int = 48

///| ipad constant
let ipad_byte : Byte = b'\x36'

///| opad constant
let opad_byte : Byte = b'\x5c'

///| Concatenate two byte arrays.
fn concat(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(a.length() + b.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  out
}

///| Build K' padded to `block_size` bytes (RFC 2104 §2).
fn prep_key(key : FixedArray[Byte]) -> FixedArray[Byte] {
  let k_pad : FixedArray[Byte] = FixedArray::make(block_size, b'\x00')
  if key.length() > block_size {
    // key longer than the block: K' = H(K), then zero-pad
    let hashed = @sha512.sha384(key)
    for i = 0; i < output_size; i = i + 1 {
      k_pad[i] = hashed[i]
    }
  } else {
    for i = 0; i < key.length(); i = i + 1 {
      k_pad[i] = key[i]
    }
  }
  k_pad
}

///| hmac_sha384(key, message) -> 48 byte tag
pub fn hmac_sha384(
  key : FixedArray[Byte],
  message : FixedArray[Byte],
) -> FixedArray[Byte] {
  let k_pad = prep_key(key)
  let ipad_key : FixedArray[Byte] = FixedArray::make(block_size, ipad_byte)
  let opad_key : FixedArray[Byte] = FixedArray::make(block_size, opad_byte)
  for i = 0; i < block_size; i = i + 1 {
    ipad_key[i] = ipad_key[i] ^ k_pad[i]
    opad_key[i] = opad_key[i] ^ k_pad[i]
  }
  let inner = @sha512.sha384(concat(ipad_key, message))
  @sha512.sha384(concat(opad_key, inner))
}
