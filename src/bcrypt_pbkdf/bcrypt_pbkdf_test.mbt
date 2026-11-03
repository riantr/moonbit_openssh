///|
/// Loop #86: `bcrypt_pbkdf`, against OpenSSH's own `bcrypt_pbkdf.c`.
///
/// The vectors here come from OpenSSH's implementation, compiled from
/// `verify_c/bcrypt_pbkdf_ref.c` -- which is OpenSSH's
/// `openbsd-compat/bcrypt_pbkdf.c` with nothing but its include lines
/// and one `#define` changed.  The harness that produced them is
/// `verify_c/blowfish_harness.c`.
///
/// **None of these hex strings was typed by hand.**  `host/blowfish_kat.py`
/// turns the harness's output into the lines below, and `--check` proves
/// that the committed tests still hold what the C oracle says.  That
/// matters more than it sounds: a 96-character hex string is easy to
/// split in the wrong place, and a vector that is off by one byte looks
/// exactly like a vector that is right.
///
/// **The rounds are what make this slow.**  One bcrypt hash is 128 key
/// expansions, and each expansion is 521 Blowfish encryptions, so one
/// hash is about 67,000 block encryptions and a 16-round derivation is
/// about a million.  On a JavaScript backend that is seconds, not
/// milliseconds, and the four targets this repository builds for are
/// four times the work.
///
/// The first vector: OpenSSH's own parameters.
///
/// The passphrase is "password", the salt is sixteen bytes counting up
/// from zero, the key is 48 bytes long and there are 16 rounds -- which
/// is the shape OpenSSH uses for an AES-256 private key (32 bytes of
/// key and 16 bytes of IV).
test "bcrypt_pbkdf_matches_openssh" {
  let pass = ascii("password")
  let salt = counting_bytes(0, 16)
  let key = @bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 48, 16)
  assert_eq(key.length(), 48)
  assert_eq(
    hex_of(key),
    "3bf00d79f63fbfe0da0fb0fdf469a1a" +
    "144b39eb1c527e3e7e7acc2639b77a27" +
    "2851b705e76d964c0277a199a494ca980",
  )
}

///|
/// A different passphrase, a different salt, and fewer rounds.
test "bcrypt_pbkdf_matches_openssh_again" {
  let pass = ascii("correct horse battery staple")
  let salt = counting_bytes(0xF0, 16)
  let key = @bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 48, 4)
  assert_eq(key.length(), 48)
  assert_eq(
    hex_of(key),
    "d328404a622286ff957d76bd954a5459f" +
    "9412330963b53a49d95d9986adfff9bf" +
    "715db7d8a6d62dbacd1a325918243fd",
  )
}

///|
/// One round, and a 32-byte key.
///
/// One round is the cheapest derivation there is, and it is here because
/// it is also the one that most clearly shows the scatter: with 32 bytes
/// of key the stride is 1 and the two rounds fill the key in order, and
/// with 100 bytes the stride is 4 and the bytes are spread out.
test "bcrypt_pbkdf_matches_openssh_with_one_round" {
  let pass = ascii("x")
  let salt = fixed_bytes(0x5A, 16)
  let key = @bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 32, 1)
  assert_eq(key.length(), 32)
  assert_eq(
    hex_of(key),
    "089257aadf93a27caf1e6b50d35c00d0" + "f761c4e3b80ac0692aed89462c04d99d",
  )
}

///|
/// A key that is longer than one hash's output.
///
/// 100 bytes needs four rounds of the outer loop with a stride of four,
/// so the bytes of the key are not in the order they were produced in.
/// This is the vector that catches a scatter which writes the key
/// linearly.
test "bcrypt_pbkdf_scatters_a_long_key" {
  let pass = ascii("password")
  let salt = fixed_bytes(0x5A, 16)
  let key = @bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 100, 2)
  assert_eq(key.length(), 100)
  assert_eq(
    hex_of(key),
    "20170e0d037e68689e21a2f12db393d12" +
    "71858f6a8eb2bc3812a055d5d42ef41b" +
    "66640b83e9f65b3f4fd2cd46af68f1b6d" +
    "83cec21e8a41a7a6100a16bacf512953" +
    "25346d1496354ce8ee85a9955f37bce" +
    "dfae6d233ca73c2fbeb2f4f69aa61baf" +
    "9f35642",
  )
}

///|
/// The arguments OpenSSH refuses are refused here too.
///
/// OpenSSH's `bcrypt_pbkdf` returns -1 for these and fills the key with
/// random bytes, so there is no key to give back; an empty array is
/// what this returns instead.  A caller that forgets to check would
/// otherwise carry on with an all-zero key, which is exactly the kind
/// of quiet failure this repository does not want.
test "bcrypt_pbkdf_refuses_what_openssh_refuses" {
  let pass = ascii("password")
  let salt = fixed_bytes(0x5A, 16)
  assert_eq(@bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 0, 16).length(), 0)
  assert_eq(@bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 48, 0).length(), 0)
  assert_eq(@bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 48, -1).length(), 0)
  assert_eq(
    @bcrypt_pbkdf.bcrypt_pbkdf(FixedArray::make(0, b'\x00'), salt, 48, 16).length(),
    0,
  )
  assert_eq(
    @bcrypt_pbkdf.bcrypt_pbkdf(pass, FixedArray::make(0, b'\x00'), 48, 16).length(),
    0,
  )
  assert_eq(@bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, 1025, 16).length(), 0)
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
/// `n` bytes, all the same.
fn fixed_bytes(value : Int32, n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = value.to_byte()
  }
  out
}

///|
/// The bytes as a hex string.
///
/// A test vector written as hex is one that cannot be misread: every
/// byte is two characters and there is nothing to misalign.
fn hex_of(b : FixedArray[Byte]) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_string(digits.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(digits.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}
