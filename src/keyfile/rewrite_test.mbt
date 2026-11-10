///|
/// Loop #88: rewriting a private key file.
///
/// The tests here are about the FILE, not about the driver: they check
/// what a rewritten file holds -- is it enciphered, does it open, does
/// it still hold the same key, does it still hold the same comment --
/// and they check the two things a rewrite has to draw afresh, the
/// salt and the check word.
///
/// **A rewrite that kept the salt would keep the old passphrase's key
/// material alive.**  The same salt and the same passphrase derive the
/// same key, so a file that reuses its salt is a file whose old
/// passphrase is still worth something.  OpenSSH draws the salt afresh
/// every time it writes a file (`arc4random_buf(salt, SALT_LEN)` in
/// `sshkey_private_to_blob2`), and so does this.
///
/// **A rewrite that kept the check word would be a file that could be
/// told apart from a fresh one.**  The check word is the tag that says
/// "this file was deciphered with the passphrase it thinks it was",
/// and OpenSSH draws it afresh too (`check = arc4random()`).
///
/// The offsets in the tests are FIXED, and they are fixed because
/// every field before the one being looked at has a fixed size.  The
/// layout is written out in `src/keyfile/moon.pkg`; the short version
/// is:
///
/// ```
/// 0   15  "openssh-key-v1\0"
/// 15   4  the length of the cipher name
/// 19   n  the cipher name       ("none" or "aes256-ctr")
/// ..   4  the length of the KDF name
/// ..   n  the KDF name          ("none" or "bcrypt")
/// ..   4  the length of the KDF options
/// ..  24  the KDF options: the salt (a string) and the rounds (a word)
/// ..   4  the number of keys
/// ..   4  the length of the public blob
/// ..  51  the public blob
/// ..   4  the length of the private block
/// ..   n  the private block: the check word twice, then the key
/// ```
///
/// so the salt is at 47, the rounds at 63, and the private block at 98
/// for an unencrypted file and at 130 for an enciphered one.

///|
/// The seed of the test key, so that the key is the same on every run
/// and on every target.
fn test_seed() -> FixedArray[Byte] {
  hex_bytes("19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9")
}

///|
/// The bytes of a private key file, with the markers taken off.
fn blob_of(text : String) -> FixedArray[Byte] {
  let begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
  let end = "-----END OPENSSH PRIVATE KEY-----"
  let b = index_of(text, begin)
  let e = index_of(text, end)
  if b < 0 || e < 0 {
    abort("the file has no markers in it")
  }
  let view : StringView = text[b + begin.length():e]
  let raw = @base64.decode(view, ignore_whitespace=true) catch {
    _ => abort("the body of the file does not decode")
  }
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}

///|
/// The index of the first occurrence of `needle` in `hay`, or -1.
fn index_of(hay : String, needle : String) -> Int32 {
  let n = hay.length()
  let m = needle.length()
  if m == 0 || m > n {
    return -1
  }
  let mut at = 0
  while at + m <= n {
    let mut same = true
    let mut j = 0
    while j < m {
      if hay[at + j] != needle[j] {
        same = false
        break
      }
      j = j + 1
    }
    if same {
      return at
    }
    at = at + 1
  }
  -1
}

///|
/// A comment change is a change only when the comment differs.
///
/// OpenSSH compares the comment it read with the comment it was asked
/// for, and when they are the same it says `No change to comment` and
/// writes NOTHING (ssh-keygen.c:1545).
///
/// **The comment of a key with no comment is an EMPTY comment, not an
/// absent one.**  So `-c -C ""` on a key that has no comment is NOT a
/// change: the two are equal.  Measured with the real tool:
///
/// ```
/// Old comment:
/// No change to comment
/// ```
test "a_comment_change_is_a_change_only_when_the_comment_differs" {
  assert_true(@keyfile.comment_is_unchanged("old@loop88", "old@loop88"))
  assert_false(@keyfile.comment_is_unchanged("old@loop88", "new@loop88"))
  assert_false(@keyfile.comment_is_unchanged("old@loop88", ""))
  // And the empty comment against the empty comment.
  assert_true(@keyfile.comment_is_unchanged("", ""))
}
