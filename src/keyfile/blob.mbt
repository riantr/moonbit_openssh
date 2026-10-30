///|
/// Loop #85: the binary half of a private key file.
///
/// Everything here is pure: it takes bytes in and gives bytes out, and it
/// never draws anything.  The randomness -- the seed and the check word --
/// is a parameter, so the whole encoding can be tested byte for byte
/// against a fixed input on every target.
///
/// The layout is OpenSSH's `openssh-key-v1`, and it is written out in full
/// in `keyfile.mbt` because the two string encodings in it are different
/// and the difference is easy to lose:
///
///   * a `cstring` is a **uint32 length followed by the bytes** -- it is
///     the same wire form as a `string`, and the name only means "no NUL
///     inside";
///   * a `string` is a uint32 length followed by the bytes.
///
/// (Both are length-prefixed.  The name "cstring" in OpenSSH means "a
/// string that contains no NUL", not "a NUL-terminated string" -- which
/// is the reading that gets the file wrong by one byte per field.)

///|
/// The magic that opens every `openssh-key-v1` file.
///
/// OpenSSH's `AUTH_MAGIC` (sshkey.c:72) is `"openssh-key-v1"` and it is
/// written with `sizeof(AUTH_MAGIC)`, so the NUL terminator is part of
/// the bytes on the wire.  Fifteen bytes, not fourteen.
///
/// It is a function rather than a constant because MoonBit's constants
/// must be immutable primitives, and a byte array is not one.
pub fn magic() -> FixedArray[Byte] {
  [
    0x6f, 0x70, 0x65, 0x6e, 0x73, 0x73, 0x68, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x76,
    0x31, 0x00,
  ]
}

///|
/// The cipher name written when there is no passphrase.
///
/// OpenSSH's `sshkey_private_to_blob2` sets `ciphername = "none"` and
/// `kdfname = "none"` when the passphrase is empty (sshkey.c:2849), and
/// then the "encrypted" block is not encrypted at all -- it is stored in
/// the clear.  This package refuses a passphrase outright, so it always
/// writes "none" for both.
pub const CIPHER_NONE : String = "none"

///|
/// Concatenate byte strings, in order.
///
/// `src/sshwire` has no concatenator and `src/sshclient` has one, but
/// `src/sshclient` is above this package in the dependency graph and
/// pulling it in here would drag the whole client along with a file
/// format.  Twelve bytes is not worth that.
fn cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut at = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let p = parts[i]
    for j = 0; j < p.length(); j = j + 1 {
      out[at] = p[j]
      at = at + 1
    }
  }
  out
}

///|
/// The public key blob, in the wire form OpenSSH puts in a `.pub` file.
///
/// It is the key type as a string, then the key as a string:
///
/// ```
/// string "ssh-ed25519"
/// string <32 bytes of public key>
/// ```
///
/// This is the same blob the fingerprint is computed over, and the same
/// one that goes into the `publickey` field of a USERAUTH request.
pub fn ed25519_public_blob(pk : FixedArray[Byte]) -> FixedArray[Byte] {
  cat([
    @sshwire.write_ssh_string(ascii(KEY_TYPE)),
    @sshwire.write_ssh_string(pk),
  ])
}

///|
/// The bytes of a String, as UTF-8.
///
/// The key type and the cipher names are ASCII, so this is the identity on
/// them; but going through `String` rather than hard-coding a byte array
/// keeps the field and the name in one place.
fn ascii(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = s[i].to_byte()
  }
  out
}

///|
/// The private key block: the "encrypted" part of the file.
///
/// With no passphrase this is stored in the clear, and it is:
///
/// ```
/// uint32  check      the same word twice
/// uint32  check
/// string  "ssh-ed25519"
/// string  <32 bytes of public key>
/// string  <64 bytes of secret key>
/// string  <the comment>
/// padding 1, 2, 3, ... up to the cipher's block size
/// ```
///
/// The padding is OpenSSH's `sshbuf.c` convention: bytes 1, 2, 3, ... in
/// order, so that a reader can tell how much padding there was by
/// looking at the last byte.  With the "none" cipher the block size is 8.
///
/// `check` is the same word twice because it is there to make a wrong
/// passphrase decrypt to something that is almost never equal to itself.
/// There is no passphrase here, so the words are only ever equal to
/// themselves -- but writing them the way OpenSSH writes them means a
/// reader cannot tell which file was made by which tool.
pub fn ed25519_private_block(
  pk : FixedArray[Byte],
  sk : FixedArray[Byte],
  comment : String,
  check : UInt32,
) -> FixedArray[Byte] {
  let body = cat([
    @sshwire.write_u32(check),
    @sshwire.write_u32(check),
    @sshwire.write_ssh_string(ascii(KEY_TYPE)),
    @sshwire.write_ssh_string(pk),
    @sshwire.write_ssh_string(sk),
    @sshwire.write_ssh_string(ascii(comment)),
  ])
  let mut len = body.length()
  let mut pad = 0
  while len % NONE_BLOCK_SIZE != 0 {
    pad = pad + 1
    len = len + 1
  }
  let out : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < body.length(); i = i + 1 {
    out[i] = body[i]
  }
  // The padding bytes are 1, 2, 3, ... -- OpenSSH's `sshkey.c:2916` does
  // `sshbuf_put_u8(encrypted, ++i & 0xff)`.
  for i = 0; i < pad; i = i + 1 {
    out[body.length() + i] = (i + 1).to_byte()
  }
  out
}

///|
/// The whole binary blob of a private key file, before base64.
///
/// ```
/// "openssh-key-v1\0"
/// string  "none"          the cipher name
/// string  "none"          the KDF name
/// string  ""              the KDF options
/// uint32  1               the number of keys
/// string  <the public blob>
/// string  <the private block>
/// ```
///
/// The magic is 15 bytes including its NUL, and both names are length-
/// prefixed strings, so the two "none"s cost 8 bytes each and the empty
/// options cost 4.  For a 32-byte ed25519 key with an empty comment the
/// whole blob is 242 bytes, which is what OpenSSH's own writer produces.
pub fn ed25519_private_blob(
  pk : FixedArray[Byte],
  sk : FixedArray[Byte],
  comment : String,
  check : UInt32,
) -> FixedArray[Byte] {
  let blob = ed25519_public_blob(pk)
  let block = ed25519_private_block(pk, sk, comment, check)
  cat([
    magic(),
    @sshwire.write_ssh_string(ascii(CIPHER_NONE)),
    @sshwire.write_ssh_string(ascii(CIPHER_NONE)),
    @sshwire.write_ssh_string(FixedArray::make(0, b'\x00')),
    @sshwire.write_u32(1U),
    @sshwire.write_ssh_string(blob),
    @sshwire.write_ssh_string(block),
  ])
}
