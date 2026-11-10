///|
/// Loop #88: the part of a rewrite that needs an entropy source.
///
/// A rewrite draws two things fresh -- the salt and the check word --
/// and drawing them needs a random source.  The `wasm` and `wasm-gc`
/// targets have no entropy source at all (`src/rng` says so), so these
/// tests are compiled only where there is one, which is the same split
/// `src/rng` makes for its own tests.
///
/// Without the split, `moon test src/keyfile` on wasm would be a red
/// run -- and a red run that means "there is no entropy here", not
/// "the code is wrong".  A gate that has to be read for its meaning is
/// a gate that gets ignored.

///|
/// A rewrite without a passphrase writes an UNENCRYPTED file.
///
/// That is OpenSSH's rule and not this repository's: an empty
/// passphrase means the cipher "none" and the KDF "none"
/// (`sshkey_private_to_blob2`, sshkey.c:2850), and the private block
/// is then stored in the clear.
///
/// It is the rule that makes `ssh-keygen -p -N ""` a way to take the
/// passphrase OFF a key -- measured with the real tool, which then
/// opens the key with no passphrase at all.
test "a_rewrite_without_a_passphrase_writes_an_unencrypted_file" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let text = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "", 0,
  )
  assert_true(text.length() > 0)
  assert_false(@keyfile.private_file_is_encrypted(text))
  match @keyfile.parse_private_file(text) {
    Ed25519(p, comment) => {
      assert_eq(hex_of(p.pk), hex_of(pair.pk))
      assert_eq(comment, "e2e@loop88")
    }
    Malformed(why) => abort("the rewritten file did not parse: " + why)
    Unsupported(why) => abort("the rewritten file was not supported: " + why)
    WrongPassphrase(why) =>
      abort("the rewritten file reported a wrong passphrase: " + why)
  }
}

///|
/// A rewrite with a passphrase writes an ENCIPHERED file, and the file
/// opens with that passphrase and with no other.
test "a_rewrite_with_a_passphrase_writes_an_encrypted_file" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let text = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "s3cr3t", 0,
  )
  assert_true(text.length() > 0)
  assert_true(@keyfile.private_file_is_encrypted(text))
  match @keyfile.parse_private_file_with_passphrase(text, "s3cr3t") {
    Ed25519(p, comment) => {
      assert_eq(hex_of(p.pk), hex_of(pair.pk))
      assert_eq(comment, "e2e@loop88")
    }
    Malformed(why) => abort("the rewritten file did not parse: " + why)
    Unsupported(why) => abort("the rewritten file was not supported: " + why)
    WrongPassphrase(why) =>
      abort("the rewritten file reported a wrong passphrase: " + why)
  }
  // And with the wrong one it does not open.
  match @keyfile.parse_private_file_with_passphrase(text, "not it") {
    WrongPassphrase(_) => ()
    Ed25519(_, _) => abort("the wrong passphrase opened the rewritten file")
    Malformed(why) => abort("it was reported as malformed instead: " + why)
    Unsupported(why) => abort("it was reported as unsupported instead: " + why)
  }
}

///|
/// The salt of a rewrite is drawn afresh.
///
/// Two rewrites of the same key with the same passphrase must not have
/// the same salt: the same salt and the same passphrase derive the
/// same key, and a file that reuses its salt is a file whose old
/// passphrase is still worth something.
test "the_salt_of_a_rewrite_is_drawn_afresh" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let first = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "s3cr3t", 0,
  )
  let second = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "s3cr3t", 0,
  )
  let a = hex_of(slice(blob_of(first), 47, 16))
  let b = hex_of(slice(blob_of(second), 47, 16))
  assert_true(a != b)
}

///|
/// The check word of a rewrite is drawn afresh.
///
/// The check word is the tag that says "this file was deciphered with
/// the passphrase it thinks it was".  OpenSSH draws it afresh every
/// time it writes a file, and a rewrite that kept the old one would be
/// a file that could be told apart from a fresh one.
test "the_check_word_of_a_rewrite_is_drawn_afresh" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let first = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "", 0,
  )
  let second = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "", 0,
  )
  // The private block of an unencrypted file starts at 98, and the
  // check word is its first four bytes.
  let a = hex_of(slice(blob_of(first), 98, 4))
  let b = hex_of(slice(blob_of(second), 98, 4))
  assert_true(a != b)
}

///|
/// The two check words of a rewritten file are the SAME word.
///
/// They are written twice so that a wrong passphrase decrypts to
/// something that is almost never equal to itself, and a file whose
/// two words differ is a file no reader accepts.
test "the_two_check_words_of_a_rewrite_are_the_same_word" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let text = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "", 0,
  )
  let blob = blob_of(text)
  assert_eq(slice(blob, 98, 4), slice(blob, 102, 4))
}

///|
/// The round count of a rewrite is the DEFAULT.
///
/// OpenSSH's `ssh-keygen` has one global `rounds`, which is 0 unless
/// `-a` was given, and `sshkey_private_to_blob2` turns a 0 into
/// `DEFAULT_ROUNDS` (24).  So a rewrite does NOT keep the round count
/// the old file had: it uses the default.  Measured with the real tool,
/// whose own default is 24.
test "the_round_count_of_a_rewrite_is_the_default" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let text = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "s3cr3t", 0,
  )
  assert_eq(u32_at(blob_of(text), 63), 24U)
}

///|
/// The round count of a rewrite can be asked for.
test "the_round_count_of_a_rewrite_can_be_asked_for" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let text = @keyfile.private_file_text_with_passphrase(
    pair, "e2e@loop88", "s3cr3t", 32,
  )
  assert_eq(u32_at(blob_of(text), 63), 32U)
}

///|
/// A rewrite with a round count the KDF refuses writes NOTHING.
///
/// An empty string is returned rather than a file, so that a caller
/// cannot write a file that claims to be enciphered and is not.
test "a_rewrite_with_too_many_rounds_writes_nothing" {
  let pair = @keyfile.derive_ed25519(test_seed())
  let text = @keyfile.private_file_text_with_passphrase(
    pair,
    "e2e@loop88",
    "s3cr3t",
    @keyfile.MAX_ROUNDS + 1,
  )
  assert_eq(text, "")
}
