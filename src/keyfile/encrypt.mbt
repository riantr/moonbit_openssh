///|
/// Loop #86: the encrypted form of a private key file.
///
/// Loop #85 wrote a private key file and refused a passphrase, because
/// refusing was the honest answer to a question this repository could
/// not yet answer: there was no `bcrypt_pbkdf` here, and a key file
/// that says "encrypted" and is not is worse than no key file at all.
///
/// Now there is.  This file holds the three things that make an
/// OpenSSH private key file encrypted:
///
///   * the **KDF**, which turns a passphrase into key material;
///   * the **cipher**, which is AES-256-CTR over the private block;
///   * the **salt and the round count**, which go into the file so that
///     the reader can do the same derivation.
///
/// **What OpenSSH writes.**  From `sshkey.c`'s
/// `sshkey_private_to_blob2`:
///
/// ```
/// "openssh-key-v1\0"
/// cstring  ciphername      "aes256-ctr"
/// cstring  kdfname         "bcrypt"
/// string   kdfoptions      string salt; uint32 rounds
/// uint32   number of keys  1
/// string   publickey blob
/// string   encrypted       the block below, enciphered
/// ```
/// and the block, once deciphered, is the same block the unencrypted
/// file holds -- the check words, the key type, the public key, the
/// secret key, the comment -- padded with 1, 2, 3, ... up to the
/// cipher's block size, which is 16 for AES and 8 for the "none" cipher.
///
/// **The order inside `kdfoptions` is `salt` then `rounds`.**  Both
/// the writer (`sshkey.c:2879`) and the reader (`sshkey.c:3109`) put
/// the salt first, and the two are `sshbuf_put_string` and
/// `sshbuf_get_string` -- a length-prefixed string, then a plain
/// four-byte word.  It is easy to assume the other order, and the
/// assumption produces a file that no reader accepts.
///
/// **The key material is 48 bytes: 32 of key and 16 of IV.**  That is
/// `cipher_keylen + cipher_ivlen`, and it is what `bcrypt_pbkdf` is
/// asked for.  The IV is not a separate random value -- it comes out
/// of the same derivation, which is why the file does not carry one.
///
/// The cipher OpenSSH uses for a passphrase-protected key.
pub const CIPHER_AES256_CTR : String = "aes256-ctr"

///|
/// The KDF OpenSSH uses for a passphrase-protected key.
pub const KDF_BCRYPT : String = "bcrypt"

///|
/// The length of the KDF salt, in bytes.
///
/// OpenSSH's `SALT_LEN` (`sshkey.c:73`) is 16, and it is filled with
///
/// `arc4random_buf`.
pub const SALT_LEN : Int32 = 16

///|
/// The number of KDF rounds OpenSSH writes when none is asked for.
///
/// OpenSSH's `DEFAULT_ROUNDS` (`sshkey.c:75`) is 24.  `ssh-keygen`'s
/// own `-a` option overrides it, and `ssh-keygen` passes 0 when the
/// option was not given, which is what makes the default apply.
pub const DEFAULT_ROUNDS : Int32 = 24

///|
/// The largest number of KDF rounds this repository will use, in a file it
/// writes and in a file it reads.
///
/// **OpenSSH has no such limit, and that is a problem worth copying
///: less of.**  Its `ssh-keygen -a` takes anything from 1 to `INT_MAX`
///
/// (`ssh-keygen.c:3503`), and its reader takes whatever round count
/// the file names (`sshkey.c:3110`) and hands it straight to the KDF.
/// A file that says two billion rounds is therefore a file that makes
/// OpenSSH spend the rest of the afternoon deriving a key -- and the
/// file is four bytes to write.
///
/// A private key file is untrusted input: it arrives over the network
///
/// (`~/.ssh/id_ed25519` from a server, a key from a tarball, a file
/// somebody sent you).  A reader that obeys the round count in the
/// file is a reader that can be made to stop.  So this repository
///
/// **caps the rounds instead of obeying them**, and a file that asks
/// for more than the cap is refused with a sentence that says why.
///
/// The cap itself is well past any sane use.  The default is 24, and
/// a round costs about forty milliseconds here, so the cap is a little
/// over ten seconds of work -- and a file asking for more than that is
/// not a file somebody made by hand.
///
/// (The cost is worth saying out loud: the same derivation in
///
/// OpenSSH's C is a hundred times faster, so a number that is absurd
/// here is merely slow there.  The cap is set for THIS implementation,
/// which is the one that has to finish.)
///
/// **This is a policy of the file layer, not of the KDF.**  The
///
/// `bcrypt_pbkdf` in `src/bcrypt_pbkdf` is a faithful port and keeps
///
/// OpenSSH's own rule (one round or more); the cap lives here, where
///
///
/// the number comes from a file or from a person.
pub const MAX_ROUNDS : Int32 = 256

///|
/// The block size of AES, in bytes.
///
/// This is the padding boundary of the private block when the file is
/// encrypted.  The "none" cipher's block size is 8.
pub const AES_BLOCK_SIZE : Int32 = 16

///|
/// The length of the AES-256 key, in bytes.
pub const AES_KEY_LEN : Int32 = 32

///|
/// The length of the AES-CTR initialisation vector, in bytes.
pub const AES_IV_LEN : Int32 = 16

///|
/// The length of the key material the KDF has to produce.
///
/// The key and the IV come out of the same derivation, so this is
///
/// `cipher_keylen + cipher_ivlen` = 32 + 16.
pub const KEY_MATERIAL_LEN : Int32 = AES_KEY_LEN + AES_IV_LEN

///|
/// The bytes of a passphrase.
///
/// OpenSSH hashes the passphrase as a C string: `strlen(passphrase)`
/// bytes of it, and no terminator.  So what matters is the BYTES, not
/// the characters, and a passphrase that is not ASCII has to be
/// encoded the same way both sides encode it.
///
/// UTF-8 is that encoding here.  It is what a command line carries on
/// the platform OpenSSH was written for, and it is what
/// `@encoding/utf8.encode` produces.  The tempting shortcut --
/// taking the low byte of each character -- is right for ASCII and
/// silently wrong for everything else, and a passphrase that
/// derives a different key on the two sides is a passphrase the user
/// cannot get past.
pub fn passphrase_bytes(passphrase : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(passphrase)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}

///|
/// The key material for a passphrase and a salt.
///
/// 48 bytes: 32 bytes of AES key and 16 bytes of IV.  An empty array
/// means the derivation was refused -- an empty passphrase, no salt,
/// or no rounds -- and there is no key material to return in that case.
///
///
/// **A round count outside 1 .. `MAX_ROUNDS` is refused too.**  The
/// number comes either from a file or from a person, and both of them
/// can be wrong; a derivation that takes hours is not a key that is
/// hard to get, it is a key that never arrives.  See `MAX_ROUNDS` for
///
///
/// why the cap exists at all.
pub fn derive_key_material(
  passphrase : String,
  salt : FixedArray[Byte],
  rounds : Int32,
) -> FixedArray[Byte] {
  if rounds < 1 || rounds > MAX_ROUNDS {
    return FixedArray::make(0, b'\x00')
  }
  let pass = passphrase_bytes(passphrase)
  @bcrypt_pbkdf.bcrypt_pbkdf(pass, salt, KEY_MATERIAL_LEN, rounds)
}

///|
/// The first 32 bytes of the key material: the AES key.
fn aes_key(material : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(AES_KEY_LEN, b'\x00')
  for i = 0; i < AES_KEY_LEN; i = i + 1 {
    out[i] = material[i]
  }
  out
}

///|
/// The last 16 bytes of the key material: the IV.
fn aes_iv(material : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(AES_IV_LEN, b'\x00')
  for i = 0; i < AES_IV_LEN; i = i + 1 {
    out[i] = material[AES_KEY_LEN + i]
  }
  out
}

///|
/// Encrypt a private block with a passphrase.
///
/// AES-256-CTR, which is its own inverse: the same call deciphers.
/// The key and the IV both come out of the KDF, so nothing else is
/// needed and nothing else is stored.
///
/// An empty array means the KDF refused the arguments, and the block
/// was not encrypted.
pub fn encrypt_private_block(
  block : FixedArray[Byte],
  passphrase : String,
  salt : FixedArray[Byte],
  rounds : Int32,
) -> FixedArray[Byte] {
  let material = derive_key_material(passphrase, salt, rounds)
  if material.length() != KEY_MATERIAL_LEN {
    return FixedArray::make(0, b'\x00')
  }
  @aes.aes_ctr(aes_key(material), aes_iv(material), block)
}

///|
/// Decrypt a private block with a passphrase.
///
/// An empty array means the KDF refused the arguments.  A block that
/// decrypts to nonsense is NOT an empty array -- the check words are
/// what say whether the passphrase was right, and that is the reader's
/// job, not this one's.
pub fn decrypt_private_block(
  block : FixedArray[Byte],
  passphrase : String,
  salt : FixedArray[Byte],
  rounds : Int32,
) -> FixedArray[Byte] {
  encrypt_private_block(block, passphrase, salt, rounds)
}

///|
/// The KDF options of an encrypted file: the salt and the round count.
///
///
/// The salt is a length-prefixed string and the rounds are a plain
///: four-byte word, and the salt comes FIRST.
pub fn kdf_options(salt : FixedArray[Byte], rounds : Int32) -> FixedArray[Byte] {
  cat([
    @sshwire.write_ssh_string(salt),
    @sshwire.write_u32(rounds.reinterpret_as_uint()),
  ])
}

///|
/// A fresh salt, from the platform CSPRNG.
///
/// Sixteen bytes, from `src/rng` -- the same source the seed and the
/// check words come from.  A salt that repeats is not a security
///: problem on its own, but it is a sign that something is wrong, and
///: two key files with the same salt and the same passphrase would
///: derive the same key, which is not what anybody wants.
pub fn random_salt() -> FixedArray[Byte] {
  @rng.bytes(SALT_LEN)
}
