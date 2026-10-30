///|
/// Loop #85: the private key file, byte for byte.
///
/// The vector in this file is not a hand-made one.  It is what OpenSSH
/// itself produced: a real `ssh-keygen -t ed25519` run, and the bytes
/// of its file.  The whole point of the test is that the file this
/// repository writes is the file OpenSSH writes, and the only way to
/// know that is to compare against OpenSSH's own output.
///
/// The seed is fixed, so the key is fixed, so the file is fixed -- and
/// the file is 242 bytes, which is what the arithmetic in `keyfile.mbt`
/// says it should be.
///
/// The test does not need an entropy source: the seed is a constant
/// here, and the drawing lives in `generate_ed25519`, which the gate
/// exercises separately.
test "the_private_key_file_is_the_file_openssh_writes" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let blob = @keyfile.ed25519_private_blob(
    pair.pk,
    pair.sk,
    "e2e@loop85",
    0x6983577DU,
  )
  assert_eq(blob.length(), 242)
  assert_eq(
    hex_of(blob),
    "6f70656e7373682d6b65792d763100" +
    "000000046e6f6e65" +
    "000000046e6f6e65" +
    "00000000" +
    "00000001" +
    "000000330000000b7373682d65643235353139" +
    "000000200ab2b6f21b28c388806bec29b768aacfae2130cd6fdfdaa6e5b95888c57b308d" +
    "00000090" +
    "6983577d6983577d" +
    "0000000b7373682d65643235353139" +
    "000000200ab2b6f21b28c388806bec29b768aacfae2130cd6fdfdaa6e5b95888c57b308d" +
    "00000040" +
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9" +
    "0ab2b6f21b28c388806bec29b768aacfae2130cd6fdfdaa6e5b95888c57b308d" +
    "0000000a653265406c6f6f703835" +
    "010203",
  )
}

///|
/// The text of the file, byte for byte.
///
/// The base64 is wrapped at 70 columns, the way OpenSSH's
/// `sshbuf_dtob64` wraps it, and the padding `=` is present.  Both of
/// those are things a reader tolerates and a byte comparison does not.
test "the_private_key_file_text_is_wrapped_at_seventy_columns" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let text = @keyfile.private_file_text(pair, "e2e@loop85", 0x6983577DU)
  // The lines are at known offsets, because the file's shape is fixed:
  // the marker, four lines of 70, one short line, the end marker.  The
  // lines are taken by offset rather than by split() because split()
  // returns an iterator, and an iterator cannot be indexed.
  let body = @keyfile.body_after_marker(text)
  assert_eq(body.length(), 5)
  assert_eq(body[0].length(), 70)
  assert_eq(body[1].length(), 70)
  assert_eq(body[2].length(), 70)
  assert_eq(body[3].length(), 70)
  // The last base64 line is short, and the file ends with the marker.
  assert_eq(body[4].length(), 44)
  assert_true(text.has_prefix("-----BEGIN OPENSSH PRIVATE KEY-----\n"))
  assert_true(text.has_suffix("-----END OPENSSH PRIVATE KEY-----\n"))
  // The body is the base64 of the blob, with the padding kept.
  assert_true(text.contains("="))
}

///|
/// The `.pub` line, byte for byte.
///
/// The base64 of an `authorized_keys` line is UNPADDED, unlike the
/// private key file's.  That difference is not a typo in either place,
/// and this test is where it is pinned down.
test "the_public_key_line_is_unpadded_base64" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let text = @keyfile.public_file_text(pair, "e2e@loop85")
  assert_eq(
    text,
    "ssh-ed25519 " +
    "AAAAC3NzaC1lZDI1NTE5AAAAIAqytvIbKMOIgGvsKbdoqs+uITDNb9/apuW5WIjFezCN" +
    " e2e@loop85\n",
  )
}

///|
/// A file with no comment has no trailing space either.
///
/// OpenSSH writes `ssh-ed25519 <base64>` and nothing more when the
/// comment is empty, and a trailing space would be a difference a
/// byte-for-byte comparison with OpenSSH's own `.pub` would catch.
test "the_public_key_line_without_a_comment_has_no_trailing_space" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let text = @keyfile.public_file_text(pair, "")
  assert_eq(
    text,
    "ssh-ed25519 " +
    "AAAAC3NzaC1lZDI1NTE5AAAAIAqytvIbKMOIgGvsKbdoqs+uITDNb9/apuW5WIjFezCN" +
    "\n",
  )
}

///|
/// The file this repository writes is the file this repository reads.
///
/// The reader is not a separate implementation of the format -- it is
/// the same format, read back.  A writer with no reader is a writer
/// nobody can check, and this is the check that does not need OpenSSH.
test "a_private_key_file_round_trips_through_the_reader" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let text = @keyfile.private_file_text(pair, "e2e@loop85", 0x6983577DU)
  match @keyfile.parse_private_file(text) {
    Ed25519(back, comment) => {
      assert_eq(comment, "e2e@loop85")
      assert_eq(hex_of(back.pk), hex_of(pair.pk))
      assert_eq(hex_of(back.sk), hex_of(pair.sk))
      // And the seed comes back out of the secret key, which is what
      // makes the key usable rather than merely readable.
      assert_eq(hex_of(back.seed), hex_of(seed))
    }
    Malformed(why) => abort("the file did not parse: " + why)
    Unsupported(why) => abort("the file was not supported: " + why)
  }
}

///|
/// The secret key is the seed followed by the public key.
///
/// This is what OpenSSH stores (`ED25519_SK_SZ` is 64), and it is what
/// makes the reader's job possible: the seed is the first half of the
/// secret key, so a file can be turned back into a usable key without
/// re-deriving anything.
test "the_secret_key_is_the_seed_followed_by_the_public_key" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  assert_eq(pair.sk.length(), 64)
  for i = 0; i < 32; i = i + 1 {
    assert_eq(pair.sk[i], pair.seed[i])
    assert_eq(pair.sk[32 + i], pair.pk[i])
  }
}

///|
/// A file that is not a key file says so.
///
/// The reader has to be able to say "no" as well as "yes", and it has to
/// say it about the file OpenSSH would also refuse.
test "a_file_that_is_not_a_key_file_is_reported_as_malformed" {
  match @keyfile.parse_private_file("hello") {
    Malformed(_) => ()
    Ed25519(_, _) => abort("a file that is not a key file was accepted")
    Unsupported(why) =>
      abort("a file that is not a key file was reported as unsupported: " + why)
  }
}

///|
/// A file whose two check words differ is refused.
///
/// The check words are the same word twice, and they are there so that
/// a wrong passphrase decrypts to something that is almost never equal
/// to itself.  A file whose two words differ is a file that was
/// encrypted with a different key, and reading it would be reading
/// nonsense.
test "a_file_whose_check_words_differ_is_refused" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  // Build the file with one check word, then patch the second one.
  let text = @keyfile.private_file_text(pair, "e2e@loop85", 0x6983577DU)
  let patched = @keyfile.zero_second_check_word(text)
  match @keyfile.parse_private_file(patched) {
    Malformed(_) => ()
    Ed25519(_, _) => abort("a file with two different check words was accepted")
    Unsupported(why) => abort("it was reported as unsupported instead: " + why)
  }
}

///|
/// The bytes of a hex string.
///
/// A test vector written as hex is a test vector that cannot be
/// misread: every byte is two characters and there is nothing to
/// misalign.
fn hex_bytes(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length() / 2, b'\x00')
  for i = 0; i < s.length() / 2; i = i + 1 {
    let hi = hex_nibble(s[i * 2])
    let lo = hex_nibble(s[i * 2 + 1])
    out[i] = ((hi << 4) | lo).to_byte()
  }
  out
}

///|
/// The value of one hex digit.
///
/// The digit arrives as a `UInt16`, because that is what indexing a
/// `String` gives -- the character, not the code point.
fn hex_nibble(c : UInt16) -> Int32 {
  if c >= '0' && c <= '9' {
    c.to_int() - '0'.to_int()
  } else if c >= 'a' && c <= 'f' {
    c.to_int() - 'a'.to_int() + 10
  } else {
    c.to_int() - 'A'.to_int() + 10
  }
}

///|
/// The bytes as a hex string.
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
