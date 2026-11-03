///|
/// Loop #85: reading a private key file back.
///
/// The reader matters for two reasons.  The first is that a writer with
/// no reader is a writer nobody can check: a file that can only be
/// produced cannot be verified by reading it, and the only other way to
/// verify it is to hand it to OpenSSH, which is a good gate but a slow
/// one.  The second is that the reader is what turns a private key file
/// into something a client can actually use.
///
/// **Loop #86 added the encrypted form.**  A file with a passphrase has
/// `ciphername != "none"` and a real KDF, and this package now does
/// that part too: it derives the key with `bcrypt_pbkdf` and deciphers
/// the block with AES-256-CTR.  Reading such a file needs the
/// passphrase, so there are two entry points -- `parse_private_file`
/// for a file with no passphrase, and
/// `parse_private_file_with_passphrase` for one with.
///
/// **The four answers are four different things.**  A file that is not
/// a key file at all is `Malformed`.  A file that is a key file this
/// reader cannot open -- another key type, another cipher -- is
/// `Unsupported`, and so is an encrypted file read without a
/// passphrase.  A file that WAS opened and whose passphrase turned out
/// to be wrong is `WrongPassphrase`, which is not the same as
/// malformed: the file is perfectly good, the reader simply was not
/// given the key it needs.  And a file that was opened and is a key is
/// `Ed25519`.

///|
///
/// What came of reading a private key file.
pub(all) enum Parsed {
  /// The file was read and it is an unencrypted ed25519 key.
  Ed25519(Ed25519KeyPair, String)
  /// The file is not an `openssh-key-v1` file at all.
  Malformed(String)
  /// The file is an `openssh-key-v1` file this reader cannot open --
  /// because it is encrypted and no passphrase was given, or because it
  /// holds another key type.
  Unsupported(String)
  /// The file was deciphered and the check words did not match, which
  /// means the passphrase was wrong.
  WrongPassphrase(String)
}

///|
/// Read a private key file with no passphrase.
///
/// An encrypted file is reported as `Unsupported`, not as `Malformed`:
/// the file is fine, this reader simply was not given the passphrase it
/// needs, and the two are different answers.
pub fn parse_private_file(text : String) -> Parsed {
  parse_text(text, None)
}

///|
/// Read a private key file, with a passphrase.
///
/// The passphrase is the one the file was written with.  A file with no
/// passphrase is read the same way whether or not one is given.
pub fn parse_private_file_with_passphrase(
  text : String,
  passphrase : String,
) -> Parsed {
  parse_text(text, Some(passphrase))
}

///|
/// Read a private key file.
fn parse_text(text : String, passphrase : String?) -> Parsed {
  let body = strip_markers(text)
  match body {
    None => Parsed::Malformed("the file has no OPENSSH PRIVATE KEY markers")
    Some(b64) => {
      let view : StringView = b64
      let decoded = @base64.decode(view, ignore_whitespace=true) catch {
        _ => return Parsed::Malformed("the base64 body does not decode")
      }
      parse_blob(decoded, passphrase)
    }
  }
}

///|
/// The base64 body of a private key file, with the second check word
/// zeroed.
///
/// This exists for one test, and it is a public function because that
/// test is a black-box test: a test file is compiled into its own
/// package and cannot see private items.
///
/// The check words are the first four bytes of the private block, and
/// the private block is the last field of the file, so the second word
/// is at a fixed offset from the end of the header.  The offset is
/// computed rather than guessed: 94 is where the private block's length
/// prefix starts, 98 is where the block itself starts, and the second
/// word is the four bytes after the first.
pub fn zero_second_check_word(text : String) -> String {
  let body = strip_markers(text)
  match body {
    None => text
    Some(b64) => {
      let view : StringView = b64
      let raw = @base64.decode(view, ignore_whitespace=true) catch {
        _ => return text
      }
      let bytes : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
      for i = 0; i < raw.length(); i = i + 1 {
        bytes[i] = raw[i]
      }
      if bytes.length() < 102 {
        return text
      }
      bytes[98 + 4] = 0x00
      bytes[98 + 5] = 0x00
      bytes[98 + 6] = 0x00
      bytes[98 + 7] = 0x00
      encode_pem(bytes)
    }
  }
}

///|
/// The base64 body of a private key file, without the markers.
///
/// The markers are lines of their own.  Anything before the first one or
/// after the second one is not part of the key and is dropped -- a file
/// with a comment above it is still a key file.
fn strip_markers(text : String) -> String? {
  let begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
  let end = "-----END OPENSSH PRIVATE KEY-----"
  let b = find_sub(text, begin)
  let e = find_sub(text, end)
  match (b, e) {
    (Some(bi), Some(ei)) => {
      if ei <= bi {
        return None
      }
      Some(text.unsafe_substring(start=bi + begin.length(), end=ei))
    }
    _ => None
  }
}

///|
/// The index of the first occurrence of `needle` in `hay`, if any.
///
/// `String::find` is not in the core package this repository builds
/// against, so this is the plain scan.  The haystack here is a key file:
///
/// a few hundred bytes.
fn find_sub(hay : String, needle : String) -> Int32? {
  let n = hay.length()
  let m = needle.length()
  if m == 0 || m > n {
    return None
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
      return Some(at)
    }
    at = at + 1
  }
  None
}

///|
/// The parsed form of the binary blob.
///
/// This is where the format is actually checked: the magic, the cipher
/// and KDF names, the number of keys, and then the private block.
fn parse_blob(bytes : Bytes, passphrase : String?) -> Parsed {
  let b : FixedArray[Byte] = FixedArray::make(bytes.length(), b'\x00')
  for i = 0; i < bytes.length(); i = i + 1 {
    b[i] = bytes[i]
  }
  let n = b.length()
  if n < magic().length() {
    return Parsed::Malformed("the file is too short to be a key file")
  }
  let mg = magic()
  for i = 0; i < mg.length(); i = i + 1 {
    if b[i] != mg[i] {
      return Parsed::Malformed("the file does not start with openssh-key-v1")
    }
  }
  let mut at = mg.length()
  match read_string(b, at) {
    None => return Parsed::Malformed("the cipher name is missing")
    Some((cipher, a1)) => {
      at = a1
      match read_string(b, at) {
        None => return Parsed::Malformed("the KDF name is missing")
        Some((kdf, a2)) => {
          at = a2
          if cipher == CIPHER_NONE && kdf == CIPHER_NONE {
            return parse_unencrypted(b, at)
          }
          if cipher != CIPHER_AES256_CTR || kdf != KDF_BCRYPT {
            return Parsed::Unsupported(
              "the key uses a cipher this reader does not have (cipher " +
              cipher +
              ", KDF " +
              kdf +
              ")",
            )
          }
          match passphrase {
            None =>
              return Parsed::Unsupported(
                "the key is encrypted (cipher " + cipher + ", KDF " + kdf + ")",
              )
            Some(pw) => return parse_encrypted(b, at, pw)
          }
        }
      }
    }
  }
}

///|
/// The rest of an unencrypted file: the KDF options, the key count, the
/// public blob and the private block.
fn parse_unencrypted(b : FixedArray[Byte], at : Int32) -> Parsed {
  match read_string(b, at) {
    None => return Parsed::Malformed("the KDF options are missing")
    Some((_opts, a3)) => {
      let at = a3
      match read_key_count(b, at) {
        None => return Parsed::Malformed("the key count is missing")
        Some((count, a4)) => {
          if count != 1U {
            return Parsed::Unsupported(
              "the file holds " + count.to_string() + " keys, not one",
            )
          }
          let at = a4
          match read_bytes(b, at) {
            None => return Parsed::Malformed("the public key is missing")
            Some((pubblob, a5)) => {
              let at = a5
              match read_bytes(b, at) {
                None => return Parsed::Malformed("the private key is missing")
                Some((block, _a6)) =>
                  match parse_block(block, false) {
                    Parsed::Ed25519(pair, comment) =>
                      match check_envelope(pubblob, pair) {
                        None => Parsed::Ed25519(pair, comment)
                        Some(why) => Parsed::Malformed(why)
                      }
                    other => other
                  }
              }
            }
          }
        }
      }
    }
  }
}

///|
/// The rest of an encrypted file.
///
/// The KDF options are the salt and the round count, in that order,
/// and the private block is a multiple of the cipher's block size --
/// OpenSSH checks that too (`sshkey.c:3095`), and a file that fails
/// it is not a file OpenSSH wrote.
fn parse_encrypted(
  b : FixedArray[Byte],
  at : Int32,
  passphrase : String,
) -> Parsed {
  match read_bytes(b, at) {
    None => return Parsed::Malformed("the KDF options are missing")
    Some((opts, a3)) => {
      let at = a3
      match read_key_count(b, at) {
        None => return Parsed::Malformed("the key count is missing")
        Some((count, a4)) => {
          if count != 1U {
            return Parsed::Unsupported(
              "the file holds " + count.to_string() + " keys, not one",
            )
          }
          let at = a4
          match read_bytes(b, at) {
            None => return Parsed::Malformed("the public key is missing")
            Some((pubblob, a5)) => {
              let at = a5
              match read_bytes(b, at) {
                None => return Parsed::Malformed("the private key is missing")
                Some((block, _a6)) => {
                  if block.length() % AES_BLOCK_SIZE != 0 ||
                    block.length() < AES_BLOCK_SIZE {
                    return Parsed::Malformed(
                      "the encrypted block is not a whole number of blocks",
                    )
                  }
                  match read_kdf_options(opts) {
                    None =>
                      return Parsed::Malformed("the KDF options are not right")
                    Some((salt, rounds)) => {
                      // The salt and the round count come out of the
                      // file, and the file is untrusted input.  A file
                      // that names two billion rounds must not be
                      // obeyed -- see MAX_ROUNDS for why.
                      if salt.length() == 0 {
                        return Parsed::Malformed("the file has no salt")
                      }
                      if rounds == 0U {
                        return Parsed::Malformed(
                          "the file asks for no KDF rounds at all",
                        )
                      }
                      if rounds > MAX_ROUNDS.reinterpret_as_uint() {
                        return Parsed::Malformed(
                          "the file asks for " +
                          rounds.to_string() +
                          " KDF rounds, and this reader will not do more than " +
                          MAX_ROUNDS.to_string(),
                        )
                      }
                      let plain = decrypt_private_block(
                        block,
                        passphrase,
                        salt,
                        rounds.reinterpret_as_int(),
                      )
                      if plain.length() != block.length() {
                        return Parsed::Malformed(
                          "the key could not be deciphered",
                        )
                      }
                      match parse_block(plain, true) {
                        Parsed::Ed25519(pair, comment) =>
                          match check_envelope(pubblob, pair) {
                            None => Parsed::Ed25519(pair, comment)
                            Some(why) => Parsed::Malformed(why)
                          }
                        other => other
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

///|
/// The number of keys in the file, and the offset just past it.
fn read_key_count(b : FixedArray[Byte], at : Int32) -> (UInt32, Int32)? {
  if at + 4 > b.length() {
    return None
  }
  let count = @sshwire.read_u32(b, at)
  Some((count, at + 4))
}

///|
/// The KDF options: the salt, then the round count.
///
/// The salt is a length-prefixed string and the rounds are a plain
/// four-byte word.  The order is the salt FIRST -- both OpenSSH's
/// writer (`sshkey.c:2879`) and its reader (`sshkey.c:3109`) have it
/// that way.
///
/// **The options are read as bytes, not as text.**  They are a binary
/// blob -- a string inside a string -- and the salt inside them is
/// sixteen bytes of `arc4random`, which is not text at all.  Routing
/// them through `String` and back would mangle any salt byte above
///
/// 0x7f, and a mangled salt derives a different key: the file would
///
///
/// open with no passphrase at all.
fn read_kdf_options(opts : FixedArray[Byte]) -> (FixedArray[Byte], UInt32)? {
  match read_bytes(opts, 0) {
    None => None
    Some((salt, at)) => {
      if at + 4 > opts.length() {
        return None
      }
      let rounds = @sshwire.read_u32(opts, at)
      Some((salt, rounds))
    }
  }
}

///|
/// The public key in the envelope has to be the public key of the
/// secret key in the file.
///
/// OpenSSH checks this too (`sshkey.c:3214`), and it is worth checking
/// here: a file whose envelope says one key and whose body holds
/// another is a file that means two things at once, and a reader that
/// believed the envelope would be wrong.
///
/// The envelope holds the public blob, which is the key type followed
/// by the key.
///
///
/// The blob is read as BYTES.  It holds the 32 bytes of an ed25519
/// public key, and those bytes are not text; a reader that turned them
/// into a `String` and back would change every byte above 0x7f and
/// then report that the envelope does not match the key it just
///
///
/// decrypted -- which is a true sentence about a file that is fine.
fn check_envelope(pubblob : FixedArray[Byte], pair : Ed25519KeyPair) -> String? {
  match read_string(pubblob, 0) {
    None => Some("the public key blob is not readable")
    Some((ktype, at)) => {
      if ktype != KEY_TYPE {
        return Some("the public key blob is of type " + ktype)
      }
      match read_bytes(pubblob, at) {
        None => Some("the public key blob has no key in it")
        Some((pk, _a)) => {
          if pk.length() != pair.pk.length() {
            return Some(
              "the public key in the envelope is not the public key of " +
              "the secret key in the file",
            )
          }
          for i = 0; i < pk.length(); i = i + 1 {
            if pk[i] != pair.pk[i] {
              return Some(
                "the public key in the envelope is not the public key of " +
                "the secret key in the file",
              )
            }
          }
          None
        }
      }
    }
  }
}

///|
/// The parsed form of the private block.
///
/// `encrypted` says whether the block was enciphered.  It matters for
/// one thing only: when the check words disagree, a file that was
/// enciphered was enciphered with the wrong passphrase, which is a
/// different answer from a file that is simply broken.
fn parse_block(block : FixedArray[Byte], encrypted : Bool) -> Parsed {
  let n = block.length()
  if n < 8 {
    return Parsed::Malformed("the private block is too short")
  }
  let c1 = @sshwire.read_u32(block, 0)
  let c2 = @sshwire.read_u32(block, 4)
  if c1 != c2 {
    if encrypted {
      return Parsed::WrongPassphrase("the passphrase is wrong")
    }
    return Parsed::Malformed("the two check words are not the same")
  }
  let mut at = 8
  match read_string(block, at) {
    None => Parsed::Malformed("the key type is missing")
    Some((ktype, a1)) => {
      at = a1
      if ktype != KEY_TYPE {
        return Parsed::Unsupported("the key type is " + ktype + ", not ed25519")
      }
      match read_bytes(block, at) {
        None => Parsed::Malformed("the public key is missing")
        Some((pk, a2)) => {
          at = a2
          match read_bytes(block, at) {
            None => Parsed::Malformed("the secret key is missing")
            Some((sk, a3)) => {
              at = a3
              match read_string(block, at) {
                None => Parsed::Malformed("the comment is missing")
                Some((comment, _a4)) => {
                  if pk.length() != ED25519_PK_LEN ||
                    sk.length() != ED25519_SK_LEN {
                    return Parsed::Malformed("the key lengths are wrong")
                  }
                  // The secret key is the seed followed by the public key,
                  // so the seed is the first half of it.
                  let seed : FixedArray[Byte] = FixedArray::make(
                    ED25519_SEED_LEN,
                    b'\x00',
                  )
                  for i = 0; i < ED25519_SEED_LEN; i = i + 1 {
                    seed[i] = sk[i]
                  }
                  let pair = derive_ed25519(seed)
                  Parsed::Ed25519(pair, comment)
                }
              }
            }
          }
        }
      }
    }
  }
}

///|
/// A length-prefixed string at `at`, and the offset just past it.
fn read_string(b : FixedArray[Byte], at : Int32) -> (String, Int32)? {
  match read_bytes(b, at) {
    None => None
    Some((raw, next)) => Some((bytes_to_string(raw), next))
  }
}

///|
/// The bytes as a String.
///
/// The fields read this way are the key type, the cipher name and the
/// comment.  The first two are ASCII; the comment is whatever the
/// writer put there, and this repository writes it as UTF-8 -- so it
/// is decoded as UTF-8 here and the two agree.
/// The bytes that are NOT text (the
/// public key and the secret key) are read with `read_bytes` and never
/// come through here.
///
/// **Decoding is lossy on purpose.**  A comment that is not valid UTF-8
///
/// -- and OpenSSH does not insist on UTF-8, it stores the bytes it was
/// given -- comes back with replacement characters rather than as an
/// error.  A key file whose comment is in some other encoding still
///
///
/// opens; it just has a comment that is not quite the one it had.
fn bytes_to_string(raw : FixedArray[Byte]) -> String {
  @utf8.decode_lossy(Bytes::from_array(raw))
}

///|
/// A length-prefixed byte string at `at`, and the offset just past it.
///
/// The binary fields -- the public key and the secret key -- are bytes
/// and not text, so they cannot go through `String`.  This is the reader
/// they use.
fn read_bytes(b : FixedArray[Byte], at : Int32) -> (FixedArray[Byte], Int32)? {
  let n = b.length()
  if at + 4 > n {
    return None
  }
  let len = @sshwire.read_u32(b, at)
  let start = at + 4
  if len > (n - start).reinterpret_as_uint() {
    return None
  }
  let l = len.reinterpret_as_int()
  let out : FixedArray[Byte] = FixedArray::make(l, b'\x00')
  for i = 0; i < l; i = i + 1 {
    out[i] = b[start + i]
  }
  Some((out, start + l))
}
