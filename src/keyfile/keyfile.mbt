///|
/// Loop #85: the OpenSSH private key file -- openssh-key-v1.
///
/// Before this loop the client could USE a key but could not MAKE one:
/// there was no `ssh-keygen` here, and no way to write a private key file
/// at all.  `src/rng` (Loop #84) had just made the missing piece possible --
/// a key is a secret, and a secret needs an entropy source.
///
/// The format is the one OpenSSH writes since 7.8, and it is written down
/// here in full because it is easy to get subtly wrong:
///
/// ```
/// "openssh-key-v1\0"        the magic
/// cstring  ciphername      "none" when there is no passphrase
/// cstring  kdfname         "none" when there is no passphrase
/// string   kdfoptions      empty when the KDF is "none"
/// uint32   number of keys  always 1 here
/// string   publickey blob  the wire form of the public key
/// string   encrypted       the block below, ciphered (here: not)
/// ```
///
/// and inside the encrypted block:
///
/// ```
/// uint32   check           the same random value, twice
/// uint32   check
/// string   key type        "ssh-ed25519"
/// string   public key      32 bytes
/// string   private key     64 bytes: the 32-byte seed, then the public key
/// string   comment
/// padding  1, 2, 3, ...    up to the cipher's block size
/// ```
///
/// **A `cstring` and a `string` are the SAME wire form.**  Both are a
/// uint32 length followed by the bytes.  The name "cstring" in OpenSSH
/// means "a string whose contents contain no NUL" -- it does NOT mean
/// "NUL-terminated".
///
/// That is worth writing down because the other reading is the natural
/// one and it is wrong by one byte per field: it puts a NUL after
/// "none" and after "none", and the file comes out 242 + 2 bytes long
/// and no reader accepts it.  The file this repository writes is 242
/// bytes, and the byte vector in `keyfile_test.mbt` is OpenSSH's own
/// file, read back byte for byte.
///
/// The whole thing is base64, wrapped at 70 columns, between the two
/// `-----BEGIN/END OPENSSH PRIVATE KEY-----` markers.
///
/// **The two check words are the same value.**  They are there so that a
/// wrong passphrase decrypts to something that is almost never equal to
/// itself -- and this implementation refuses a passphrase outright, so it
/// writes the cipher name "none" and the KDF name "none" and there is
/// nothing to get wrong.
///
/// The whole file is base64 of a structure whose only randomness is the
/// seed and the check words, both of which come from `src/rng`.

///|
/// The key type this package writes: OpenSSH's `ssh-ed25519`.
pub const KEY_TYPE : String = "ssh-ed25519"

///|
/// The size of an ed25519 seed, in bytes.
///
/// RFC 8032 § 5.1.5: the secret seed is 32 bytes.
pub const ED25519_SEED_LEN : Int32 = 32

///|
/// The size of an ed25519 public key, in bytes.
pub const ED25519_PK_LEN : Int32 = 32

///|
/// The size of an ed25519 "secret key" as OpenSSH stores it.
///
/// OpenSSH's `ssh-ed25519.c` `ssh_ed25519_serialize_private` writes the
/// public key and then `ED25519_SK_SZ` bytes of secret key, and
/// `ED25519_SK_SZ` is 64: the 32-byte seed followed by the 32-byte public
/// key.  That is the same `seed || pk` layout RFC 8032 uses for the
/// expanded secret key, so the file holds what the algorithm already has
/// and nothing has to be re-derived.
pub const ED25519_SK_LEN : Int32 = 64

///|
/// The size of the private key block, in bytes, when the cipher is "none".
///
/// The block is the check words, the key type, the public key, the secret
/// key and the comment, padded up to the cipher's block size.  With no
/// passphrase the cipher is "none", whose block size is 8.
pub const NONE_BLOCK_SIZE : Int32 = 8
