///|
/// Loop #86: `bcrypt_pbkdf` -- the key derivation OpenSSH uses for an
/// encrypted private key.
///
/// When OpenSSH writes a private key with a passphrase, the passphrase
/// does not become the key.  It goes through `bcrypt_pbkdf`, which is a
/// PBKDF2-shaped construction built on two things this repository already
/// had by the time this loop started: SHA-512, and (as of this loop)
/// Blowfish.
///
/// **What the construction is.**  A password is collapsed with SHA-512
/// once, at the start.  Then, for each 32-byte block of key material:
///
///   1. the salt is hashed together with a big-endian counter;
///   2. the salt hash and the password hash are run through the *bcrypt
///      hash* -- 64 rounds of Blowfish key expansion, then 64 rounds of
///      encrypting a fixed 32-byte magic string;
///   3. the result is mixed with the previous round's result, `rounds`
///      times over;
///   4. the 32 bytes are scattered into the key, NOT written
///:      consecutively.
///
/// Step 4 is the part that is not PBKDF2.  OpenSSH's own comment on it
/// says why: a PBKDF2 that emits key material linearly lets an attacker
/// who wants two subkeys compute the whole thing once, while the
/// legitimate user has to run it twice.  Scattering the output forces
/// anyone who wants any part of the key to compute all of it.
///
/// **The magic string** is "OxychromaticBlowfishSwatDynamite" -- 32
/// bytes, which is exactly eight 32-bit words and exactly the size of
/// one bcrypt hash output.  It is the thing that gets enciphered, and
/// it is the reason the bcrypt hash is not a plain Blowfish encryption.
///
/// The magic string that the bcrypt hash enciphers.
///
/// Thirty-two bytes: "OxychromaticBlowfishSwatDynamite".  The array is
/// exactly 32 bytes long, so the string fills it with no NUL and no
/// padding, and `stream2word` reads it as eight whole words.
fn magic_string() -> FixedArray[Byte] {
  let s = "OxychromaticBlowfishSwatDynamite"
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = s[i].to_byte()
  }
  out
}

///|
/// The bcrypt hash: the inner function of `bcrypt_pbkdf`.
///
/// This is OpenSSH's `bcrypt_hash`.  It takes the SHA-512 of the
/// password and the SHA-512 of the salt, and returns 32 bytes.
///
/// The key schedule is the expensive part, and it is done like this:
///
///   * one *salted* expansion (`expand_state`) with the salt hash and the
///     password hash;
///   * then 64 rounds of an *unsalted* expansion (`expand0_state`), each
///     round with the salt hash and then with the password hash.
///
/// The magic string is then encrypted 64 times with the resulting
/// schedule, and the eight words are written out **little-endian**.
pub fn bcrypt_hash(
  sha2pass : FixedArray[Byte],
  sha2salt : FixedArray[Byte],
) -> FixedArray[Byte] {
  let state = @blowfish.init_state()
  @blowfish.expand_state(state, sha2salt, sha2pass)
  let mut round = 0
  while round < 64 {
    @blowfish.expand0_state(state, sha2salt)
    @blowfish.expand0_state(state, sha2pass)
    round = round + 1
  }
  // The magic string, as eight 32-bit words.
  let magic = magic_string()
  let cdata : FixedArray[UInt32] = FixedArray::make(8, 0U)
  let mut cursor = 0
  let mut i = 0
  while i < 8 {
    let (word, next) = @blowfish.stream2word(magic, cursor)
    cursor = next
    cdata[i] = word
    i = i + 1
  }
  // Sixty-four encryptions of the eight words.
  let mut round = 0
  while round < 64 {
    @blowfish.blf_enc(state, cdata)
    round = round + 1
  }
  // The words go out little-endian, four bytes each.
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  let mut i = 0
  while i < 8 {
    out[4 * i] = (cdata[i] & 0xFFU).to_byte()
    out[4 * i + 1] = ((cdata[i] >> 8) & 0xFFU).to_byte()
    out[4 * i + 2] = ((cdata[i] >> 16) & 0xFFU).to_byte()
    out[4 * i + 3] = ((cdata[i] >> 24) & 0xFFU).to_byte()
    i = i + 1
  }
  out
}

///|
/// The size of one bcrypt hash output, in bytes.
pub const HASH_SIZE : Int32 = 32

///|
/// The largest key this function will derive, in bytes.
///
/// OpenSSH's `bcrypt_pbkdf` refuses a key longer than 32 * 32 bytes,
/// because the output is scattered over a key of at most that length
/// with a stride of at least one.
pub const MAX_KEY_LEN : Int32 = 1024

///|
/// Derive key material from a passphrase and a salt.
///
/// This is OpenSSH's `bcrypt_pbkdf`, with the same argument order and
/// the same result.  The arguments are the raw bytes of the passphrase
/// and the raw bytes of the salt; OpenSSH passes
/// `strlen(passphrase)` and the salt as it is.
///
/// **An empty array means the arguments were refused.**  The refusals
/// are OpenSSH's: no rounds, no passphrase, no salt, a key length of
/// zero, a key longer than 1024 bytes, or a salt longer than a
/// megabyte.  OpenSSH fills the key with random bytes and returns -1 in
/// those cases; there is no key to give back here, so there is nothing
/// to return but an empty array, and the caller has to check.
///
/// The salt is not required to be 16 bytes.  OpenSSH uses 16, but the
/// construction takes any salt, and the tests use several sizes.
pub fn bcrypt_pbkdf(
  pass : FixedArray[Byte],
  salt : FixedArray[Byte],
  keylen : Int32,
  rounds : Int32,
) -> FixedArray[Byte] {
  if rounds < 1 ||
    pass.length() == 0 ||
    salt.length() == 0 ||
    keylen <= 0 ||
    keylen > MAX_KEY_LEN ||
    salt.length() > 1048576 {
    return FixedArray::make(0, b'\x00')
  }
  let saltlen = salt.length()
  let orig_keylen = keylen
  // The stride is how far apart two bytes of the same block land in the
  // key; the amount is how many bytes of the key one block fills.
  let stride = (keylen + HASH_SIZE - 1) / HASH_SIZE
  let mut amt = (keylen + stride - 1) / stride
  // The password is collapsed once, at the start.
  let sha2pass = @sha512.sha512(pass)
  let key : FixedArray[Byte] = FixedArray::make(keylen, b'\x00')
  // The salt and the counter, hashed together.
  let countsalt : FixedArray[Byte] = FixedArray::make(saltlen + 4, b'\x00')
  for i = 0; i < saltlen; i = i + 1 {
    countsalt[i] = salt[i]
  }
  let mut remaining = keylen
  let mut count = 1
  while remaining > 0 {
    countsalt[saltlen] = ((count >> 24) & 0xFF).to_byte()
    countsalt[saltlen + 1] = ((count >> 16) & 0xFF).to_byte()
    countsalt[saltlen + 2] = ((count >> 8) & 0xFF).to_byte()
    countsalt[saltlen + 3] = (count & 0xFF).to_byte()
    // First round: the salt is the salt.
    let sha2salt = @sha512.sha512(countsalt)
    let tmpout = bcrypt_hash(sha2pass, sha2salt)
    let out : FixedArray[Byte] = FixedArray::make(HASH_SIZE, b'\x00')
    for i = 0; i < HASH_SIZE; i = i + 1 {
      out[i] = tmpout[i]
    }
    // The other rounds: the salt is the previous output, and the
    // outputs are XORed together.
    let mut round = 1
    while round < rounds {
      let sha2salt2 = @sha512.sha512(tmpout)
      let next = bcrypt_hash(sha2pass, sha2salt2)
      for i = 0; i < HASH_SIZE; i = i + 1 {
        out[i] = out[i] ^ next[i]
        tmpout[i] = next[i]
      }
      round = round + 1
    }
    // The scatter.  Byte `i` of this block goes to `i * stride + count
    // - 1` of the key, which is what makes the output non-linear.
    if amt > remaining {
      amt = remaining
    }
    let mut i = 0
    while i < amt {
      let dest = i * stride + (count - 1)
      if dest >= orig_keylen {
        break
      }
      key[dest] = out[i]
      i = i + 1
    }
    remaining = remaining - i
    count = count + 1
  }
  key
}
