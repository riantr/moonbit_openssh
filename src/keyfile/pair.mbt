///|
/// Loop #85: making a key pair.
///
/// Two things live here, and they are kept apart on purpose:
///
///   * `generate_ed25519` draws the seed and derives the pair.  This is
///     the part that needs an entropy source, so it is the part that is
///     not testable without one.
///
///   * `encode_ed25519_private` turns a pair into the bytes of a private
///     key file.  That is pure, and it is therefore the part the tests
///     can pin down byte for byte on every target.
///
/// The split is the same one Loop #84 made in `src/kexdh`: a test that
/// needs an entropy source is a test that cannot be instrumented at the
/// default target, and a package that cannot be instrumented is a package
/// the coverage report stops talking about.
///
/// **The secret key is `seed || pk`, and that is not an accident.**  OpenSSH
/// stores `ED25519_SK_SZ` = 64 bytes, which is the 32-byte seed followed
/// by the 32-byte public key -- the same layout RFC 8032 uses for the
/// expanded secret key.  `src/ed25519`'s `keypair_from_seed` returns
/// exactly that, so the file holds what the algorithm already had and
/// nothing has to be re-derived.

///|
/// A key pair, and the two halves of it that go into different files.
///
/// The seed is the secret.  The public key is the public half.  The
/// 64-byte secret key is `seed || pk`, which is what OpenSSH stores.
pub(all) struct Ed25519KeyPair {
  seed : FixedArray[Byte]
  pk : FixedArray[Byte]
  sk : FixedArray[Byte]
}

///|
/// A fresh ed25519 key pair, from the platform CSPRNG.
///
/// The seed is 32 bytes from `src/rng` -- the same package Loop #84 put
/// in, and the same one the DH private exponent comes from.  Two key
/// pairs drawn in a row are different, and that is the only property of
/// randomness that can be checked without looking at the randomness.
///
/// **The seed is the secret and it is never printed.**  Nothing in this
/// repository writes a seed down.  What goes into the file is the seed
/// inside the secret key, which the file has to have.
pub fn generate_ed25519() -> Ed25519KeyPair {
  let seed = @rng.bytes(ED25519_SEED_LEN)
  derive_ed25519(seed)
}

///|
/// The key pair for a given seed.
///
/// This is the part that is pure, and it is what the tests use: give it
/// a fixed seed and it gives the same key every time, on every target.
///
/// `src/ed25519`'s `keypair_from_seed` aborts if the seed is not 32
/// bytes, so this does not have to check again -- but it does check the
/// lengths of what comes back, because a key file whose public key is
/// the wrong size is a file that no reader will accept, and it is much
/// cheaper to catch it here than in a diff against a reference file.
pub fn derive_ed25519(seed : FixedArray[Byte]) -> Ed25519KeyPair {
  if seed.length() != ED25519_SEED_LEN {
    abort("derive_ed25519: the seed must be 32 bytes")
  }
  let pair = @ed25519.keypair_from_seed(seed)
  let pk = pair.0
  let sk = pair.1
  if pk.length() != ED25519_PK_LEN {
    abort("derive_ed25519: the public key must be 32 bytes")
  }
  if sk.length() != ED25519_SK_LEN {
    abort("derive_ed25519: the secret key must be 64 bytes")
  }
  { seed, pk, sk, }
}

///|
/// The text of the private key file for this key pair.
///
/// `check` is the word OpenSSH writes twice at the head of the private
/// block.  It is a random word in OpenSSH's writer, and it is here a
/// parameter so that the encoding can be tested against a fixed input.
pub fn private_file_text(
  pair : Ed25519KeyPair,
  comment : String,
  check : UInt32,
) -> String {
  let blob = ed25519_private_blob(pair.pk, pair.sk, comment, check)
  encode_pem(blob)
}

///|
/// The text of the `.pub` file for this key pair.
pub fn public_file_text(pair : Ed25519KeyPair, comment : String) -> String {
  encode_public_line(pair.pk, comment)
}

///|
/// Four random bytes for the check word.
///
/// The check word is a random word written twice into the private block,
/// so that a reader can tell whether a file was decrypted with the
/// passphrase it thinks it was.  There is no passphrase here, so the word
/// only has to be random enough that two key files do not look alike.
///
/// It comes from `src/rng`, the same source as the seed, and for the same
/// reason: it is a value that must not repeat.
pub fn random_check_bytes() -> FixedArray[Byte] {
  @rng.bytes(4)
}

///|
/// The fingerprint of this key, in the form `ssh-keygen -l` prints it.
///
/// That is `SHA256:` followed by the base64 of the SHA-256 of the public
/// key blob, with the padding stripped.  `src/hostkey` already computes
/// fingerprints over host key blobs, and this is the same computation
/// over the same blob -- but `src/hostkey` is above this package in the
/// dependency graph, so it is repeated here rather than inverted.
pub fn fingerprint_text(pair : Ed25519KeyPair) -> String {
  let blob = ed25519_public_blob(pair.pk)
  let digest = @sha256.sha256(blob)
  let padded = @base64.encode(Bytes::from_array(digest))
  "SHA256:" + strip_padding(padded)
}
