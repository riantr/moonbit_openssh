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
///
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
    @sshwire.write_ssh_string(utf8_bytes(KEY_TYPE)),
    @sshwire.write_ssh_string(pk),
  ])
}

///|
/// 从公钥 blob 里取出那 32 字节的 ed25519 公钥。
///
/// 公钥 blob 的形状是 `string "ssh-ed25519"` + `string 32 字节`,所以
/// 这一步是**反** `ed25519_public_blob`。
///
/// 别的密钥类型不在本仓库的范围里,这里对它们返回 None。**「不认」
/// 是可以说清楚的,「认了但算错了」不行。**
///
/// 这条规则住在 `src/keyfile`,因为它讲的是**密钥文件的格式**;agent
/// 那边要拆 blob 时也用它,而不是自己再拆一遍。
pub fn ed25519_public_of_blob(blob : FixedArray[Byte]) -> FixedArray[Byte]? {
  let (name, next) = match read_bytes(blob, 0) {
    None => return None
    Some(v) => v
  }
  if bytes_to_string(name) != KEY_TYPE {
    return None
  }
  let (pk, _) = match read_bytes(blob, next) {
    None => return None
    Some(v) => v
  }
  if pk.length() != 32 {
    return None
  }
  Some(pk)
}

///|
/// 公钥 blob 变成 authorized_keys 那一行,**不带行尾换行**。
///
/// 这一行是 `<类型> <base64>` + (注释非空时)` <注释>`。
///
/// **和 `.pub` 文件那一行不是同一件事**:文件那一行在注释为空时没有
/// 尾随空格,而 OpenSSH 的 `ssh-add -L` 是先打印公钥行、再打印
/// `" " + 注释`,所以它的注释为空时**有一个尾随空格**。这里给的是
/// `ssh-add -L` 那种,所以空格是无条件的。
pub fn public_line_of_blob(blob : FixedArray[Byte], comment : String) -> String {
  if ed25519_public_of_blob(blob) is None {
    return ""
  }
  let padded = @base64.encode(Bytes::from_array(blob))
  let b64 = strip_padding(padded)
  KEY_TYPE + " " + b64 + " " + comment
}

///|
/// The bytes of a String, as UTF-8.
///
/// The key type and the cipher names are ASCII, so UTF-8 is the identity
/// on them; but going through `String` rather than hard-coding a byte
/// array keeps the field and the name in one place.
///
/// **The comment is not ASCII, and that is the whole point of this
/// function.**  The tempting shortcut -- taking the low byte of each
/// character -- is right for ASCII and silently wrong for everything
/// else: it turns one character into one byte and throws the rest of the
/// encoding away.  A comment of one accented letter would go into the
/// file as one byte and come back as some other character, and the file
/// would hold a comment that is not the comment anybody typed.
///
/// UTF-8 is what the reader decodes with, so the two agree by
/// construction.  See `bytes_to_string` on the reading side.
fn utf8_bytes(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
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
  private_block(pk, sk, comment, check, NONE_BLOCK_SIZE)
}

///|
/// The private key block, padded to a given block size.
///
/// This is the same block as `ed25519_private_block`, but the padding
/// boundary is a parameter.  With the "none" cipher the boundary is 8;
/// with AES it is 16.  The padding bytes themselves are the same either
/// way -- 1, 2, 3, ... in order -- because that is what OpenSSH's
/// reader checks for (`private2_check_padding`, `sshkey.c:1755`).
fn private_block(
  pk : FixedArray[Byte],
  sk : FixedArray[Byte],
  comment : String,
  check : UInt32,
  block_size : Int32,
) -> FixedArray[Byte] {
  let body = cat([
    @sshwire.write_u32(check),
    @sshwire.write_u32(check),
    @sshwire.write_ssh_string(utf8_bytes(KEY_TYPE)),
    @sshwire.write_ssh_string(pk),
    @sshwire.write_ssh_string(sk),
    @sshwire.write_ssh_string(utf8_bytes(comment)),
  ])
  let mut len = body.length()
  let mut pad = 0
  while len % block_size != 0 {
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
    @sshwire.write_ssh_string(utf8_bytes(CIPHER_NONE)),
    @sshwire.write_ssh_string(utf8_bytes(CIPHER_NONE)),
    @sshwire.write_ssh_string(FixedArray::make(0, b'\x00')),
    @sshwire.write_u32(1U),
    @sshwire.write_ssh_string(blob),
    @sshwire.write_ssh_string(block),
  ])
}

///|
/// The whole binary blob of an ENCRYPTED private key file.
///
/// This is the same file as `ed25519_private_blob`, with three fields
/// changed and the private block enciphered:
///
/// ```
/// "openssh-key-v1\0"
/// string  "aes256-ctr"     the cipher name
/// string  "bcrypt"          the KDF name
/// string  <the KDF options>  the salt and the round count
/// uint32  1                 the number of keys
/// string  <the public blob>
/// string  <the enciphered private block>
/// ```
///
/// The private block is padded to 16 bytes -- the AES block size --
/// rather than to the 8 bytes the "none" cipher uses, and it is then
/// enciphered with AES-256-CTR under a key derived from the passphrase
/// and the salt.
///
/// **An empty array means the derivation failed.**  An empty passphrase
/// is refused by the KDF, and there is then no key to encipher with,
/// so there is no file to write.  Returning an empty array rather than
/// a file with an empty private section means the caller cannot
///: accidentally write a file that looks encrypted and is not.
pub fn ed25519_private_blob_encrypted(
  pk : FixedArray[Byte],
  sk : FixedArray[Byte],
  comment : String,
  check : UInt32,
  passphrase : String,
  salt : FixedArray[Byte],
  rounds : Int32,
) -> FixedArray[Byte] {
  let block = private_block(pk, sk, comment, check, AES_BLOCK_SIZE)
  let encrypted = encrypt_private_block(block, passphrase, salt, rounds)
  if encrypted.length() == 0 {
    return FixedArray::make(0, b'\x00')
  }
  let blob = ed25519_public_blob(pk)
  cat([
    magic(),
    @sshwire.write_ssh_string(utf8_bytes(CIPHER_AES256_CTR)),
    @sshwire.write_ssh_string(utf8_bytes(KDF_BCRYPT)),
    @sshwire.write_ssh_string(kdf_options(salt, rounds)),
    @sshwire.write_u32(1U),
    @sshwire.write_ssh_string(blob),
    @sshwire.write_ssh_string(encrypted),
  ])
}
