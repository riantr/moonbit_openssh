///|
/// Loop #86: Blowfish, checked against OpenSSH's own `blowfish.c`.
///
/// Every vector in this file was produced by OpenSSH's implementation,
/// compiled from `verify_c/blowfish_ref.c` -- which is OpenSSH's
/// `openbsd-compat/blowfish.c` with nothing but its include lines
/// changed.  The harness that produced them is
/// `verify_c/blowfish_harness.c`, and `host/blowfish_kat.py --check`
/// proves that the constants below still say what the C oracle says.
///
/// **No constant here was typed by hand.**  The script turns the
/// harness's output into the lines below and checks them back.  That
/// matters more than it sounds: a 144-character hex string is easy to
/// split in the wrong place, and a vector that is off by one word looks
/// exactly like a vector that is right.  Three such mistakes were made
/// in this file's first draft, and the script found all three.
///
/// The schedule is checked twice over: every word of the P-array, and
/// an FNV-1a checksum over all 1024 S-box words.  The P-array alone
/// would not catch a mistake in the S-box phase of the schedule, and
/// the checksum alone would not say *which* word went wrong.
///
/// The initial state is pi.
///
/// The P-array and the four S-boxes of Blowfish are the hexadecimal
/// expansion of the fractional part of pi.  That is a property of the
/// algorithm, and `host/blowfish_pi.py --check` proves it against pi
/// computed to 8336 hex digits rather than trusting the C file.
test "the_initial_state_is_pi" {
  let state = @blowfish.init_state()
  assert_eq(@blowfish.p_words(state).length(), 18)
  assert_eq(@blowfish.s_words(state).length(), 1024)
  let p = @blowfish.p_words(state)
  assert_eq(p[0], 0x243f6a88U)
  assert_eq(p[1], 0x85a308d3U)
  assert_eq(p[2], 0x13198a2eU)
  assert_eq(p[3], 0x03707344U)
  assert_eq(p[4], 0xa4093822U)
  assert_eq(p[5], 0x299f31d0U)
  assert_eq(p[6], 0x082efa98U)
  assert_eq(p[7], 0xec4e6c89U)
  assert_eq(p[8], 0x452821e6U)
  assert_eq(p[9], 0x38d01377U)
  assert_eq(p[10], 0xbe5466cfU)
  assert_eq(p[11], 0x34e90c6cU)
  assert_eq(p[12], 0xc0ac29b7U)
  assert_eq(p[13], 0xc97c50ddU)
  assert_eq(p[14], 0x3f84d5b5U)
  assert_eq(p[15], 0xb5470917U)
  assert_eq(p[16], 0x9216d5d9U)
  assert_eq(p[17], 0x8979fb1bU)
  let s = @blowfish.s_words(state)
  assert_eq(s[0], 0xd1310ba6U)
  assert_eq(s[1023], 0x3ac372e6U)
  assert_eq(fnv_of_words(s), 0x6c7a4136b5a7c636UL)
}

///|
/// The salted key schedule, word for word.
///
/// The salt is 64 bytes counting up and the key is 64 bytes counting
/// down.  Both are the C harness's inputs, so this checks the whole of
/// `Blowfish_expandstate`: the key phase, the salt phase, and the
/// S-box phase -- including the cursor that is reset between the key
/// and the salt and NOT reset before the S-boxes.
test "the_salted_key_schedule_is_openssh's" {
  let salt = counting_bytes(0, 64)
  let key = descending_bytes(255, 64)
  let state = @blowfish.init_state()
  @blowfish.expand_state(state, salt, key)
  let p = @blowfish.p_words(state)
  assert_eq(p[0], 0x217aef40U)
  assert_eq(p[1], 0xb94a2756U)
  assert_eq(p[2], 0x22a27fa3U)
  assert_eq(p[3], 0x4e48313dU)
  assert_eq(p[4], 0x331db66bU)
  assert_eq(p[5], 0x9adb5c2cU)
  assert_eq(p[6], 0x4f8dcd08U)
  assert_eq(p[7], 0x84325cc0U)
  assert_eq(p[8], 0xd2aadf8dU)
  assert_eq(p[9], 0xf0d42fcdU)
  assert_eq(p[10], 0x2a85daf5U)
  assert_eq(p[11], 0xde491effU)
  assert_eq(p[12], 0xfcdb0c56U)
  assert_eq(p[13], 0x7ffb9111U)
  assert_eq(p[14], 0xd2827b26U)
  assert_eq(p[15], 0x8a8865feU)
  assert_eq(p[16], 0x38f839dcU)
  assert_eq(p[17], 0x709160c7U)
  assert_eq(fnv_of_words(@blowfish.s_words(state)), 0xc8e912d13a59dd03UL)
}

///|
/// The unsalted key schedule, word for word.
///
/// `Blowfish_expand0state` is the same schedule without the salt.  It is
/// what `blf_key` does, and it is what the ECB vector below uses.
test "the_unsalted_key_schedule_is_openssh's" {
  let key = counting_bytes(0, 64)
  let state = @blowfish.init_state()
  @blowfish.expand0_state(state, key)
  let p = @blowfish.p_words(state)
  assert_eq(p[0], 0x5522c3deU)
  assert_eq(p[1], 0x69bc94c7U)
  assert_eq(p[2], 0x54e200fbU)
  assert_eq(p[3], 0xd02371ceU)
  assert_eq(p[4], 0x54e74c7aU)
  assert_eq(p[5], 0xda754f81U)
  assert_eq(p[6], 0xb062230aU)
  assert_eq(p[7], 0xd4afe236U)
  assert_eq(p[8], 0xae76eb21U)
  assert_eq(p[9], 0xdc253fe5U)
  assert_eq(p[10], 0x102f1fbbU)
  assert_eq(p[11], 0x1ce4be0aU)
  assert_eq(p[12], 0xd8d4eff6U)
  assert_eq(p[13], 0x3269cd6bU)
  assert_eq(p[14], 0x67f29ef8U)
  assert_eq(p[15], 0x8fcf9a38U)
  assert_eq(p[16], 0x52facbc8U)
  assert_eq(p[17], 0x102cae94U)
  assert_eq(fnv_of_words(@blowfish.s_words(state)), 0x9d7224ebc5165369UL)
}

///|
/// The published Blowfish ECB vector.
///
/// The key is the alphabet, the plaintext is the word BLOWFISH, and the
/// ciphertext is `324ed0fe f413a203`.  This is the vector from the
/// original Blowfish test program, and OpenSSH's own copy of that
/// program prints the same answer -- which is why the answer is in this
/// file and not only in the C harness.
test "the_published_ecb_vector" {
  let state = @blowfish.init_state()
  @blowfish.expand0_state(state, ascii("abcdefghijklmnopqrstuvwxyz"))
  let data : FixedArray[UInt32] = [0x424c4f57U, 0x46495348U]
  @blowfish.blf_enc(state, data)
  assert_eq(data[0], 0x324ed0feU)
  assert_eq(data[1], 0xf413a203U)
  // And back again.
  @blowfish.blf_dec(state, data)
  assert_eq(data[0], 0x424c4f57U)
  assert_eq(data[1], 0x46495348U)
}

///|
/// Decryption is the inverse of encryption.
///
/// Not the published vector this time: a schedule that has been through
/// the salted expansion, and a block that has been enciphered and
/// deciphered.  If the two halves of the Feistel network were not
/// mirrors of each other, this would not come back.
test "decipher_inverts_encipher" {
  let state = @blowfish.init_state()
  @blowfish.expand_state(state, counting_bytes(3, 32), counting_bytes(200, 32))
  let plain : FixedArray[UInt32] = [0xdeadbeefU, 0xcafebabeU, 1U, 2U]
  let cipher : FixedArray[UInt32] = [0U, 0U, 0U, 0U]
  for i = 0; i < 4; i = i + 1 {
    cipher[i] = plain[i]
  }
  @blowfish.blf_enc(state, cipher)
  assert_true(cipher[0] != plain[0] || cipher[1] != plain[1])
  @blowfish.blf_dec(state, cipher)
  for i = 0; i < 4; i = i + 1 {
    assert_eq(cipher[i], plain[i])
  }
}

///|
/// The keystream reader, and its wrap-around.
///
/// `Blowfish_stream2word` takes four bytes at a time, **big-endian**,
/// and wraps back to the start of the buffer when it runs off the end.
/// The cursor it hands back is the position for the NEXT word, and the
/// third word here starts at the beginning again because the buffer is
/// eight bytes and two words were read from it.
///
/// The last case starts the cursor at 7, one byte before the end, so
/// the word is `h` followed by `abc`.
///
/// **The cursor that comes back can be the length of the buffer.**  The
/// C does not normalise it -- the wrap happens when a byte is read, not
/// when the word is finished -- so the second call hands back 8, and
/// the third call reads from the beginning again.
test "the_keystream_reader_wraps" {
  let data = ascii("abcdefgh")
  let (w0, c0) = @blowfish.stream2word(data, 0)
  assert_eq(w0, 0x61626364U)
  assert_eq(c0, 4)
  let (w1, c1) = @blowfish.stream2word(data, c0)
  assert_eq(w1, 0x65666768U)
  assert_eq(c1, 8)
  let (w2, c2) = @blowfish.stream2word(data, c1)
  assert_eq(w2, 0x61626364U)
  assert_eq(c2, 4)
  let (w3, c3) = @blowfish.stream2word(data, 7)
  assert_eq(w3, 0x68616263U)
  assert_eq(c3, 3)
}

///|
/// The FNV-1a checksum of a word array.
///
/// The same computation as the C harness: the words are taken as four
/// bytes each, little-endian, so the answer does not depend on the
/// host's byte order.  The multiplication is a 64-bit multiplication
/// that wraps, which is what FNV-1a is defined in terms of.
fn fnv_of_words(words : FixedArray[UInt32]) -> UInt64 {
  let mut h : UInt64 = 0xcbf29ce484222325UL
  for i = 0; i < words.length(); i = i + 1 {
    let w = words[i]
    let mut k = 0
    while k < 4 {
      let byte = ((w >> (8 * k)) & 0xFFU).to_byte()
      h = h ^ byte.to_uint64()
      h = h * 0x100000001b3UL
      k = k + 1
    }
  }
  h
}

///|
/// `n` bytes, counting from `start` and wrapping at 256.
fn counting_bytes(start : Int32, n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ((start + i) & 0xFF).to_byte()
  }
  out
}

///|
/// `n` bytes, counting DOWN from `start` and wrapping at 256.
///
/// The C harness's key for the salted schedule counts down from 255, and
/// a key that counts up is a different key.
fn descending_bytes(start : Int32, n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ((start - i) & 0xFF).to_byte()
  }
  out
}

///|
/// The bytes of an ASCII string.
fn ascii(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = s[i].to_byte()
  }
  out
}
