///|
/// Loop #86: Blowfish -- the cipher underneath OpenSSH's bcrypt_pbkdf.
///
/// OpenSSH protects an encrypted private key with `bcrypt_pbkdf`, and
/// `bcrypt_pbkdf` is built on Blowfish.  So this is the bottom of the
/// stack for that feature, and it is bottom in the strict sense: there is
/// nothing under it, and there is nothing above it here either.
/// `src/bcrypt_pbkdf` is the only thing that uses it.
///
/// **What is implemented.**  The whole of OpenBSD's `blowfish.c` that
/// `bcrypt_pbkdf.c` uses:
///
///   * `Blowfish_initstate`    -- the P-array and S-boxes, which are pi;
///   * `Blowfish_expandstate`  -- the salted key schedule;
///   * `Blowfish_expand0state` -- the unsalted key schedule;
///   * `Blowfish_encipher` / `Blowfish_decipher`;
///   * `Blowfish_stream2word`  -- the keystream reader;
///   * `blf_enc` / `blf_dec`   -- ECB over a word array.
///
/// **The one thing that is easy to get wrong** is the cursor in
/// `Blowfish_stream2word`.  It is a position in the *key* stream that is
/// then reused as a position in the *salt* stream, and the two streams
/// are read in different phases of the schedule.  In `expandstate` the
/// cursor is reset to zero between the key phase and the salt phase, but
/// NOT between the salt phase and the S-box phase -- so the S-boxes are
/// salted with the salt starting at offset 8, not at offset 0.  A port
/// that "cleans up" the cursor produces a key schedule that is subtly
/// wrong and never matches anything.
///
/// The cursor arithmetic is done here exactly as the C does it, and the
/// tests pin it down against the C.
///
/// The state of a Blowfish key schedule.
///
/// The four S-boxes are held in one flat array of 1024 words: `S[i][k]`
/// is at `s[i * 256 + k]`.  That is the same flattening the C macro `F`
/// does when it indexes `s[0x100 + ...]`, so the Feistel function reads
/// the same four words in the same order.
pub(all) struct BlowfishState {
  /// The four S-boxes, flattened.
  s : FixedArray[UInt32]
  /// The P-array: 18 words.
  p : FixedArray[UInt32]
}

///|
/// The number of rounds of the Feistel network.
pub const ROUNDS : Int32 = 16

///|
/// The number of words in the P-array.
pub const P_WORDS : Int32 = 18

///|
/// The number of S-boxes.
pub const S_BOXES : Int32 = 4

///|
/// The number of words in one S-box.
pub const S_BOX_WORDS : Int32 = 256

///|
/// A fresh key schedule: the P-array and the S-boxes, both from pi.
///
/// This is `Blowfish_initstate`.  The state it returns is the *initial*
/// state, before any key is mixed in; `expand_state` and `expand0_state`
/// are what turn it into a usable schedule.
pub fn init_state() -> BlowfishState {
  let words = pi_words()
  let p : FixedArray[UInt32] = FixedArray::make(P_WORDS, 0U)
  let s : FixedArray[UInt32] = FixedArray::make(S_BOXES * S_BOX_WORDS, 0U)
  for i = 0; i < P_WORDS; i = i + 1 {
    p[i] = words[i]
  }
  for i = 0; i < S_BOXES * S_BOX_WORDS; i = i + 1 {
    s[i] = words[P_WORDS + i]
  }
  { s, p, }
}

///|
/// The P-array of a key schedule.
///
/// The words are the subkeys.  This is a view of the schedule's own
/// array, not a copy, and it is here so that the schedule can be
/// inspected from outside the package -- the tests need to see it.
pub fn p_words(state : BlowfishState) -> FixedArray[UInt32] {
  state.p
}

///|
/// The four S-boxes of a key schedule, flattened.
///
/// `S[i][k]` is at index `i * 256 + k`, which is the same flattening the
///
/// Feistel function uses.
pub fn s_words(state : BlowfishState) -> FixedArray[UInt32] {
  state.s
}

///|
/// The Feistel function: `F(s, x)`.
///
/// It is the C macro, exactly:
///
/// ```
/// F(s, x) = ((s[(x>>24)&0xFF] + s[0x100+((x>>16)&0xFF)])
///            ^ s[0x200+((x>>8)&0xFF])
///          + s[0x300+(x&0xFF)])
/// ```
///
/// The addition and the XOR are in that order and they do not commute,
/// so the parentheses are not decoration.  The `+` is a 32-bit addition
/// that wraps, which is what C's `u_int32_t` does and what MoonBit's
///
/// `UInt32` does too.
fn f(state : BlowfishState, x : UInt32) -> UInt32 {
  let a = state.s[((x >> 24) & 0xFFU).reinterpret_as_int()]
  let b = state.s[S_BOX_WORDS + ((x >> 16) & 0xFFU).reinterpret_as_int()]
  let c = state.s[2 * S_BOX_WORDS + ((x >> 8) & 0xFFU).reinterpret_as_int()]
  let d = state.s[3 * S_BOX_WORDS + (x & 0xFFU).reinterpret_as_int()]
  ((a + b) ^ c) + d
}

///|
/// Encrypt one 64-bit block.
///
/// This is `Blowfish_encipher`.  The two words come in as the left and
/// right halves and go out as the cipher block, so the return is
/// `(l, r)` where `l` is the encrypted left half.
///
/// The round structure is the C's: after `Xl ^= p[0]`, round `n` XORs
/// into the *right* half when `n` is odd and into the *left* half when
/// `n` is even, and the halves are swapped and XORed with `p[17]` at the
/// end.
pub fn encipher(
  state : BlowfishState,
  xl : UInt32,
  xr : UInt32,
) -> (UInt32, UInt32) {
  let mut l = xl ^ state.p[0]
  let mut r = xr
  let mut n = 1
  while n <= ROUNDS {
    if n % 2 == 1 {
      r = r ^ f(state, l) ^ state.p[n]
    } else {
      l = l ^ f(state, r) ^ state.p[n]
    }
    n = n + 1
  }
  (r ^ state.p[17], l)
}

///|
/// Decrypt one 64-bit block.
///
/// This is `Blowfish_decipher`, and it is `encipher` run backwards: the
/// rounds go from 16 down to 1, and the parity flips -- round `n` XORs
/// into the *right* half when `n` is even and into the *left* half when
/// `n` is odd.  That flip is the whole difference between the two
/// directions, and getting it wrong gives a block that decrypts to
/// nothing in particular.
pub fn decipher(
  state : BlowfishState,
  xl : UInt32,
  xr : UInt32,
) -> (UInt32, UInt32) {
  let mut l = xl ^ state.p[17]
  let mut r = xr
  let mut n = ROUNDS
  while n >= 1 {
    if n % 2 == 0 {
      r = r ^ f(state, l) ^ state.p[n]
    } else {
      l = l ^ f(state, r) ^ state.p[n]
    }
    n = n - 1
  }
  (r ^ state.p[0], l)
}

///|
/// Read the next 32-bit word out of a keystream, and give back the
/// cursor.
///
/// This is `Blowfish_stream2word`.  The word is four bytes, **big-endian**
/// (which is worth noting: everything else in this KDF is little-endian),
/// and the cursor wraps back to the start of the buffer when it runs off
/// the end.
///
///
/// The cursor is a position, and the caller is responsible for what it
/// means.  In the key schedule the same cursor is used for the key
/// stream and for the salt stream, and where it is reset is the caller's
/// business -- see the note at the top of this file.
///
/// **The cursor that comes back can be equal to the length of the
/// buffer.**  The C does not normalise it: the wrap happens when a byte
/// is read, not when the word is finished, so a word that ends on the
/// last byte of the buffer hands back the buffer's length, and the next
/// call wraps it.  Normalising it here would read the same bytes, but it
/// would not be the same function, and the cursor is a visible output.
pub fn stream2word(data : FixedArray[Byte], cursor : Int32) -> (UInt32, Int32) {
  let n = data.length()
  if n == 0 {
    return (0U, 0)
  }
  let mut j = cursor
  let mut temp = 0U
  let mut i = 0
  while i < 4 {
    if j >= n {
      j = 0
    }
    temp = (temp << 8) | data[j].to_uint()
    j = j + 1
    i = i + 1
  }
  (temp, j)
}

///|
/// The salted key schedule: `Blowfish_expandstate`.
///
/// `data` is the salt and `key` is the key.  Three things happen, in this
/// order:
///
///   1. the key is XORed into the P-array, one 32-bit word at a time;
///   2. the salt is XORed into a running pair of words which are then
///      enciphered, and the results replace the P-array;
///   3. the same thing is done to all 1024 S-box words.
///
/// **The cursor is reset to zero between step 1 and step 2, and is NOT
/// reset between step 2 and step 3.**  That means the S-boxes are salted
/// with the salt starting at offset 8 (for a 64-byte salt), not at
/// offset 0.  This is the C's behaviour and the tests check it.
pub fn expand_state(
  state : BlowfishState,
  data : FixedArray[Byte],
  key : FixedArray[Byte],
) -> Unit {
  // Step 1: the key, into the P-array.
  let mut cursor = 0
  for i = 0; i < P_WORDS; i = i + 1 {
    let (word, next) = stream2word(key, cursor)
    cursor = next
    state.p[i] = state.p[i] ^ word
  }
  // Step 2: the salt, into the P-array.  The cursor starts over here.
  cursor = 0
  let mut datal = 0U
  let mut datar = 0U
  let mut i = 0
  while i < P_WORDS {
    let (wl, next1) = stream2word(data, cursor)
    cursor = next1
    let (wr, next2) = stream2word(data, cursor)
    cursor = next2
    datal = datal ^ wl
    datar = datar ^ wr
    let (el, er) = encipher(state, datal, datar)
    datal = el
    datar = er
    state.p[i] = datal
    state.p[i + 1] = datar
    i = i + 2
  }
  // Step 3: the salt, into the S-boxes.  The cursor carries on from
  // step 2 -- this is the part that is easy to get wrong.
  for box = 0; box < S_BOXES; box = box + 1 {
    let mut k = 0
    while k < S_BOX_WORDS {
      let (wl, next1) = stream2word(data, cursor)
      cursor = next1
      let (wr, next2) = stream2word(data, cursor)
      cursor = next2
      datal = datal ^ wl
      datar = datar ^ wr
      let (el, er) = encipher(state, datal, datar)
      datal = el
      datar = er
      state.s[box * S_BOX_WORDS + k] = datal
      state.s[box * S_BOX_WORDS + k + 1] = datar
      k = k + 2
    }
  }
}

///|
/// The unsalted key schedule: `Blowfish_expand0state`.
///
/// The same as `expand_state` without the salt: the key is XORed into
/// the P-array, and then the P-array and the S-boxes are replaced by
/// enciphering a running pair of words.  The pair is *not* reset
/// between the P-array phase and the S-box phase -- it carries on, which
/// is what the C does.
pub fn expand0_state(state : BlowfishState, key : FixedArray[Byte]) -> Unit {
  let mut cursor = 0
  for i = 0; i < P_WORDS; i = i + 1 {
    let (word, next) = stream2word(key, cursor)
    cursor = next
    state.p[i] = state.p[i] ^ word
  }
  let mut datal = 0U
  let mut datar = 0U
  let mut i = 0
  while i < P_WORDS {
    let (el, er) = encipher(state, datal, datar)
    datal = el
    datar = er
    state.p[i] = datal
    state.p[i + 1] = datar
    i = i + 2
  }
  for box = 0; box < S_BOXES; box = box + 1 {
    let mut k = 0
    while k < S_BOX_WORDS {
      let (el, er) = encipher(state, datal, datar)
      datal = el
      datar = er
      state.s[box * S_BOX_WORDS + k] = datal
      state.s[box * S_BOX_WORDS + k + 1] = datar
      k = k + 2
    }
  }
}

///|
/// Encrypt a word array in ECB mode, in place: `blf_enc`.
///
/// Two words make one 64-bit block, so the array's length must be even.
/// The C's `blocks` argument counts blocks, and `blf_enc(&state, cdata,
///
/// BCRYPT_WORDS / 2)` encrypts 8 words as 4 blocks.
pub fn blf_enc(state : BlowfishState, data : FixedArray[UInt32]) -> Unit {
  let mut i = 0
  while i + 1 < data.length() {
    let (l, r) = encipher(state, data[i], data[i + 1])
    data[i] = l
    data[i + 1] = r
    i = i + 2
  }
}

///|
/// Decrypt a word array in ECB mode, in place: `blf_dec`.
pub fn blf_dec(state : BlowfishState, data : FixedArray[UInt32]) -> Unit {
  let mut i = 0
  while i + 1 < data.length() {
    let (l, r) = decipher(state, data[i], data[i + 1])
    data[i] = l
    data[i + 1] = r
    i = i + 2
  }
}
