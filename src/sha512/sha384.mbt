///| SHA-384 (FIPS 180-4 § 4)

///|

///| SHA-384 is SHA-512 with a different initial hash value and a 48-byte

///| (384-bit) truncated output. It shares the compression function and the

///| padding rules with SHA-512, so this only adds the SHA-384 IV and the

///| truncation.

///| SHA-384 initial hash value

///|   (fractional parts of the square roots of the 9th..16th primes)

///|
///   FIPS 180-4 § 5.3.3
pub let init_h384 : FixedArray[UInt64] = [
  0xcbbb9d5dc1059ed8UL, 0x629a292a367cd507UL, 0x9159015a3070dd17UL, 0x152fecd8f70e5939UL,
  0x67332667ffc00b31UL, 0x8eb44a8768581511UL, 0xdb0c2e0d64f98fa7UL, 0x47b5481dbefa4fa4UL,
]

///|
/// SHA-384 block size in bytes (same as SHA-512)
pub let block_len_384 : Int32 = 128

///|
/// SHA-384 output length in bytes
pub let hash_len_384 : Int32 = 48

///| sha384(message) -> 48 byte hash

///|

///|
/// 符合 FIPS 180-4 § 4
pub fn sha384(message : FixedArray[Byte]) -> FixedArray[Byte] {
  // 1. Initialize with the SHA-384 IV
  let state : FixedArray[UInt64] = FixedArray::make(8, 0UL)
  for i = 0; i < 8; i = i + 1 {
    state[i] = init_h384[i]
  }
  // 2. Incremental update (same routine as SHA-512)
  let buffer : FixedArray[Byte] = FixedArray::make(block_len, b'\x00')
  let (buf2, buf_len, bc) = update(state, buffer, 0, 0UL, message)
  // 3. Pad (same rules as SHA-512)
  pad(state, buf2, buf_len, bc)
  // 4. Serialize and truncate to the leftmost 384 bits
  let full = serialize_state(state)
  let out : FixedArray[Byte] = FixedArray::make(hash_len_384, b'\x00')
  for i = 0; i < hash_len_384; i = i + 1 {
    out[i] = full[i]
  }
  out
}
