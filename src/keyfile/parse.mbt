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
/// **Only the unencrypted form is read.**  A file with a passphrase has
/// `ciphername != "none"` and a real KDF, and this package does not
/// implement bcrypt_pbkdf.  Such a file is reported as
/// `Unsupported`, not as `Malformed`: the file is fine, this reader
/// simply does not do that part of it, and the two are different
/// answers.

///|
/// What came of reading a private key file.
pub(all) enum Parsed {
  /// The file was read and it is an unencrypted ed25519 key.
  Ed25519(Ed25519KeyPair, String)
  /// The file is not an `openssh-key-v1` file at all.
  Malformed(String)
  /// The file is an `openssh-key-v1` file this reader cannot open --
  /// because it is encrypted, or because it holds another key type.
  Unsupported(String)
}

///|
/// Read a private key file.
///
/// The file is the PEM text: the two markers, and base64 in between.
/// The base64 may be wrapped over several lines (OpenSSH wraps it at 70
/// columns) and may have whitespace anywhere; the core package's decoder
/// is told to ignore whitespace for that reason.
///
/// The check words are read and compared.  They are the same word twice
/// in a file nobody encrypted, and a file whose two words differ is a
/// file that was encrypted with the wrong key -- which cannot happen here,
/// and which is worth catching rather than ignoring.
pub fn parse_private_file(text : String) -> Parsed {
  let body = strip_markers(text)
  match body {
    None => Parsed::Malformed("the file has no OPENSSH PRIVATE KEY markers")
    Some(b64) => {
      let view : StringView = b64
      let decoded = @base64.decode(view, ignore_whitespace=true) catch {
        _ => return Parsed::Malformed("the base64 body does not decode")
      }
      parse_blob(decoded)
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
fn parse_blob(bytes : Bytes) -> Parsed {
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
          if cipher != CIPHER_NONE || kdf != CIPHER_NONE {
            return Parsed::Unsupported(
              "the key is encrypted (cipher " + cipher + ", KDF " + kdf + ")",
            )
          }
          match read_string(b, at) {
            None => return Parsed::Malformed("the KDF options are missing")
            Some((_opts, a3)) => {
              at = a3
              if at + 4 > n {
                return Parsed::Malformed("the key count is missing")
              }
              let count = @sshwire.read_u32(b, at)
              at = at + 4
              if count != 1U {
                return Parsed::Unsupported(
                  "the file holds " + count.to_string() + " keys, not one",
                )
              }
              match read_string(b, at) {
                None => return Parsed::Malformed("the public key is missing")
                Some((_blob, a4)) => {
                  at = a4
                  match read_bytes(b, at) {
                    None =>
                      return Parsed::Malformed("the private key is missing")
                    Some((block, _a5)) => parse_block(block)
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
/// The parsed form of the private block.
fn parse_block(block : FixedArray[Byte]) -> Parsed {
  let n = block.length()
  if n < 8 {
    return Parsed::Malformed("the private block is too short")
  }
  let c1 = @sshwire.read_u32(block, 0)
  let c2 = @sshwire.read_u32(block, 4)
  if c1 != c2 {
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
/// comment -- all of them ASCII.  The bytes that are NOT text (the
/// public key and the secret key) are read with `read_bytes` and never
/// come through here.
fn bytes_to_string(raw : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < raw.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(raw[i].to_int()))
  }
  sb.to_string()
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
