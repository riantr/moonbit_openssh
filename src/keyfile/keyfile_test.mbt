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
    WrongPassphrase(why) => abort("the passphrase was reported wrong: " + why)
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
    WrongPassphrase(why) =>
      abort(
        "a file that is not a key file was reported as a wrong passphrase: " +
        why,
      )
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
    WrongPassphrase(why) =>
      abort("it was reported as a wrong passphrase instead: " + why)
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

///|
/// An encrypted private key file round trips through the reader.
///
/// The salt is fixed here so that the file is the same file every time,
/// and the round count is small so that the test is quick.  What is
/// being checked is that the reader can get the key back out of a file
/// that was enciphered -- which means the KDF, the cipher and the
/// check words all have to agree with each other.
test "an_encrypted_private_key_file_round_trips_through_the_reader" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  let text = @keyfile.private_file_text_encrypted(
    pair, "e2e@loop86", 0x6983577DU, "correct horse", salt, 4,
  )
  assert_true(text.length() > 0)
  match @keyfile.parse_private_file_with_passphrase(text, "correct horse") {
    Ed25519(back, comment) => {
      assert_eq(comment, "e2e@loop86")
      assert_eq(hex_of(back.pk), hex_of(pair.pk))
      assert_eq(hex_of(back.sk), hex_of(pair.sk))
      assert_eq(hex_of(back.seed), hex_of(seed))
    }
    Malformed(why) => abort("the encrypted file did not parse: " + why)
    Unsupported(why) => abort("the encrypted file was not supported: " + why)
    WrongPassphrase(why) =>
      abort("the encrypted file reported a wrong passphrase: " + why)
  }
}

///|
/// An encrypted file read without a passphrase says it is encrypted.
///
/// And it says it with `Unsupported`, not `Malformed`: the file is
/// perfectly good, the reader simply was not given the key it needs.
test "an_encrypted_file_read_without_a_passphrase_is_unsupported" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  let text = @keyfile.private_file_text_encrypted(
    pair, "e2e@loop86", 0x6983577DU, "correct horse", salt, 4,
  )
  match @keyfile.parse_private_file(text) {
    Unsupported(why) => assert_true(why.contains("encrypted"))
    Malformed(why) => abort("it was reported as malformed instead: " + why)
    Ed25519(_, _) => abort("an encrypted file was read without a passphrase")
    WrongPassphrase(why) =>
      abort("it was reported as a wrong passphrase instead: " + why)
  }
}

///|
/// The wrong passphrase says the passphrase is wrong.
///
/// That is a fourth answer, and it is not the same as "the file is
/// broken": the file is fine, and the reader was given the wrong key.
/// The check words are what say so -- they are the same word twice,
/// and a wrong passphrase makes them differ.
test "the_wrong_passphrase_says_the_passphrase_is_wrong" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  let text = @keyfile.private_file_text_encrypted(
    pair, "e2e@loop86", 0x6983577DU, "correct horse", salt, 4,
  )
  match @keyfile.parse_private_file_with_passphrase(text, "wrong horse") {
    WrongPassphrase(_) => ()
    Malformed(why) => abort("it was reported as malformed instead: " + why)
    Unsupported(why) => abort("it was reported as unsupported instead: " + why)
    Ed25519(_, _) => abort("a wrong passphrase still opened the file")
  }
}

///|
/// The encrypted file names the cipher and the KDF OpenSSH names.
///
/// "aes256-ctr" and "bcrypt", in that order, and then the KDF options:
/// the salt, as a length-prefixed string, and the round count, as a
/// plain four-byte word.  **The salt comes first.**  OpenSSH's writer
/// (`sshkey.c:2879`) and its reader (`sshkey.c:3109`) agree on that,
/// and it is easy to assume the other order.
test "the_encrypted_file_names_the_cipher_and_the_kdf" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  let blob = @keyfile.ed25519_private_blob_encrypted(
    pair.pk,
    pair.sk,
    "e2e@loop86",
    0x6983577DU,
    "correct horse",
    salt,
    24,
  )
  assert_true(blob.length() > 0)
  // 15 bytes of magic, then the cipher name.
  assert_eq(slice(blob, 15, 4), [0x00, 0x00, 0x00, 0x0a])
  assert_eq(bytes_of(slice(blob, 19, 10)), "aes256-ctr")
  // Then the KDF name.
  assert_eq(slice(blob, 29, 4), [0x00, 0x00, 0x00, 0x06])
  assert_eq(bytes_of(slice(blob, 33, 6)), "bcrypt")
  // Then the KDF options: the salt as a string, then the rounds.
  assert_eq(slice(blob, 39, 4), [0x00, 0x00, 0x00, 0x18])
  assert_eq(slice(blob, 43, 4), [0x00, 0x00, 0x00, 0x10])
  assert_eq(hex_of(slice(blob, 47, 16)), "000102030405060708090a0b0c0d0e0f")
  // Then the rounds, as a big-endian word.
  assert_eq(slice(blob, 63, 4), [0x00, 0x00, 0x00, 0x18])
  // The encrypted section is a whole number of AES blocks.
  let enc_len = u32_at(blob, 74)
  assert_eq(enc_len.reinterpret_as_int() % 16, 0)
}

///|
/// `n` bytes of `b`, starting at `at`.
fn slice(b : FixedArray[Byte], at : Int32, n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = b[at + i]
  }
  out
}

///|
/// The bytes at `at`, as a big-endian word.
fn u32_at(b : FixedArray[Byte], at : Int32) -> UInt32 {
  ((b[at].to_uint() << 24) & 0xFF000000U) |
  ((b[at + 1].to_uint() << 16) & 0x00FF0000U) |
  ((b[at + 2].to_uint() << 8) & 0x0000FF00U) |
  (b[at + 3].to_uint() & 0x000000FFU)
}

///|
/// The bytes as an ASCII string.
fn bytes_of(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
/// The file OpenSSH itself wrote, with a passphrase on it.
///
/// This is not a file this repository made.  It is a real
/// `ssh-keygen -t ed25519 -N "s3cr3t-pass"` output, taken whole, and
/// `host/openssh_key_vector.py` is what read it and printed these
/// fields:
///
/// ```
/// cipher:    aes256-ctr
/// kdf:       bcrypt
/// salt:      3d2bdcff443360298e423f41552e936d
/// rounds:    24
/// encrypted: 144 bytes
/// ```
///
/// **Twenty-four rounds** is OpenSSH's own default (`DEFAULT_ROUNDS`,
/// `sshkey.c:75`), and the salt is sixteen bytes of `arc4random`.
/// Both are what this repository writes too.
///
/// So the test is: this file, written by the program everybody has to
/// read, opens with the passphrase and gives back the key that is in
/// it.  That is the half of the round trip that a unit test can make,
/// because the other half -- OpenSSH reading OUR file -- needs the
/// real program and lives in the gate.
test "the_file_openssh_wrote_opens_with_its_passphrase" {
  let text = openssh_encrypted_key()
  match @keyfile.parse_private_file_with_passphrase(text, "s3cr3t-pass") {
    Ed25519(pair, comment) => {
      assert_eq(comment, "e2e@loop86")
      assert_eq(
        hex_of(pair.pk),
        "6fb449409fe85edc4b215f2a4fe7ac52a148864ddbf130cd4ef16014e7af2b70",
      )
    }
    Malformed(why) => abort("OpenSSH's own file did not parse: " + why)
    Unsupported(why) => abort("OpenSSH's own file was not supported: " + why)
    WrongPassphrase(why) =>
      abort("OpenSSH's own file reported a wrong passphrase: " + why)
  }
}

///|
/// The wrong passphrase on OpenSSH's own file says the passphrase is
/// wrong.
///
/// The check words are the same word twice, and a wrong passphrase
/// makes the two of them differ.  That is the whole mechanism by which
/// a passphrase is checked: there is no MAC, and the check words are
///: the tag.
test "the_wrong_passphrase_on_openssh's_own_file_says_so" {
  let text = openssh_encrypted_key()
  match
    @keyfile.parse_private_file_with_passphrase(text, "not the passphrase") {
    WrongPassphrase(_) => ()
    Malformed(why) => abort("it was reported as malformed instead: " + why)
    Unsupported(why) => abort("it was reported as unsupported instead: " + why)
    Ed25519(_, _) => abort("a wrong passphrase still opened OpenSSH's file")
  }
}

///|
/// The file the real `ssh-keygen` wrote, with a passphrase on it.
fn openssh_encrypted_key() -> String {
  let body = "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABA9" +
    "K9z/RDNgKY5CP0FVLpNtAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIG+0" +
    "SUCf6F7cSyFfKk/nrFKhSIZN2/EwzU7xYBTnrytwAAAAkFPDOqiqhWGqiu1wrCp/" +
    "ATijLTjKjPxszYjuAFmDCygiTIo86ayfnhWOduBuzN4s0A4Q2t8zQ9kMBe+3l07P" +
    "4l+DQTYSJmPcpYfcdkmumvxesq2MawLZjQ0VhCrk+nelJVMv4CAL2w42uDLPDcDJ" +
    "w/R+gtsV1xmD+lW9w0+ZhF3tTXE8L9N1nVOWQp9Mc6/+Qg=="
  "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
  body +
  "\n-----END OPENSSH PRIVATE KEY-----\n"
}

///|
/// A file that asks for far too many KDF rounds is refused.
///
/// The round count is four bytes in the file, and it is untrusted
/// input.  OpenSSH obeys it whatever it is, which means a file of a
/// few hundred bytes can make a reader spend hours; this repository
/// caps the count instead and says so in the answer.
///
/// The rounds word is at a fixed offset -- 63 -- because everything
/// before it has a fixed size: the magic, the cipher name, the KDF
/// name, the length of the KDF options, the salt, and then the rounds.
///
///
/// **The count is just past the cap, not two billion.**  The cap is one
/// comparison, so a count of `MAX_ROUNDS + 1` proves it as well as a
/// count of two billion does -- and if the cap were ever removed this
/// test would take a few seconds and FAIL, where a count of two
/// billion would make it hang, and a test that hangs is worse than a
///
///
/// test that fails.
test "a_file_that_asks_for_too_many_rounds_is_refused" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  let blob = @keyfile.ed25519_private_blob_encrypted(
    pair.pk,
    pair.sk,
    "e2e@loop86",
    0x6983577DU,
    "correct horse",
    salt,
    4,
  )
  let patched = slice(blob, 0, blob.length())
  // One more round than the cap allows: 257 is 0x00000101.
  patched[63] = 0x00
  patched[64] = 0x00
  patched[65] = 0x01
  patched[66] = 0x01
  let text = @keyfile.encode_pem(patched)
  match @keyfile.parse_private_file_with_passphrase(text, "correct horse") {
    Malformed(why) => assert_true(why.contains("rounds"))
    Unsupported(why) => abort("it was reported as unsupported instead: " + why)
    Ed25519(_, _) => abort("a file asking for two billion rounds was opened")
    WrongPassphrase(why) =>
      abort("it was reported as a wrong passphrase instead: " + why)
  }
}

///|
/// The key material is not derived from an impossible round count.
///
/// The refusal has to be a refusal and not a very slow derivation: a
/// round count of zero is not a key that is hard to get, it is a key
/// that is never produced, and a round count of two billion is a key
///
///
/// that is never produced either.
test "the_key_material_is_not_derived_from_an_impossible_round_count" {
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  assert_eq(@keyfile.derive_key_material("correct horse", salt, 0).length(), 0)
  // One past the cap is refused too, and refused immediately.
  assert_eq(
    @keyfile.derive_key_material("correct horse", salt, @keyfile.MAX_ROUNDS + 1).length(),
    0,
  )
  // And the ordinary count still gives the 48 bytes: 32 of key and 16 of
  // IV.
  assert_eq(
    @keyfile.derive_key_material("correct horse", salt, 24).length(),
    48,
  )
}

///|
/// A comment that is not ASCII survives the round trip.
///
/// The comment is text, and it is written into the file as UTF-8 and
/// read back as UTF-8.  The shortcut that writes one byte per
/// character would put a different character in the file, and the file
/// would then hold a comment that nobody typed.
///
/// The comment here is two characters outside ASCII -- one Latin-1
/// letter and one Greek one -- written with escapes so that this file
///
///
/// stays plain ASCII.
test "a_comment_that_is_not_ascii_survives_the_round_trip" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let comment = "\u{00E9}\u{03A9}"
  let text = @keyfile.private_file_text(pair, comment, 0x6983577DU)
  match @keyfile.parse_private_file(text) {
    Ed25519(back, back_comment) => {
      assert_eq(back_comment, comment)
      assert_eq(hex_of(back.pk), hex_of(pair.pk))
    }
    Malformed(why) => abort("the file did not parse: " + why)
    Unsupported(why) => abort("the file was not supported: " + why)
    WrongPassphrase(why) => abort("the passphrase was reported wrong: " + why)
  }
}

///|
/// And the same comment survives the ENCRYPTED round trip.
///
/// The comment lives inside the private block, so on the encrypted
/// path it goes through the cipher as well -- which means a writer
///
///
/// that mangled it would mangle it twice.
test "a_comment_that_is_not_ascii_survives_the_encrypted_round_trip" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  let comment = "\u{00E9}\u{03A9}"
  let text = @keyfile.private_file_text_encrypted(
    pair, comment, 0x6983577DU, "correct horse", salt, 4,
  )
  match @keyfile.parse_private_file_with_passphrase(text, "correct horse") {
    Ed25519(back, back_comment) => {
      assert_eq(back_comment, comment)
      assert_eq(hex_of(back.pk), hex_of(pair.pk))
    }
    Malformed(why) => abort("the encrypted file did not parse: " + why)
    Unsupported(why) => abort("the encrypted file was not supported: " + why)
    WrongPassphrase(why) =>
      abort("the encrypted file reported a wrong passphrase: " + why)
  }
}
