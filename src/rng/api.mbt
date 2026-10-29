///|
/// src/rng -- the platform's cryptographically secure random source.
///
/// Loop #84.  Before this package the client had no entropy at all.  The
/// KEXINIT cookie was a fixed 16-byte array (`sshclient.fixed_cookie`) and
/// the Diffie-Hellman private exponent was a fixed 32-byte constant
/// (`cmd/ssh_live.fixed_x`), so **every session this client opened used the
/// same two values**.  A DH exchange with a known private exponent has no
/// forward secrecy at all: the shared secret is `f^x` for an `x` that is in
/// the source code, and so is the KEXINIT cookie that every transcript
/// starts with.
///
/// What OpenSSH does, from its source:
///
///   kex.c:598        arc4random_buf(cookie, KEX_COOKIE_LEN)
///   kexc25519.c:54   arc4random_buf(key, CURVE25519_SIZE)
///   dh.c:303         DH_generate_key(dh) -- OpenSSL, whose randomness comes
///                    from the platform
///
/// So OpenSSH draws both from the platform CSPRNG and never reuses either.
///
/// This package is the same idea and nothing more.  It is a thin wrapper
/// over the platform's CSPRNG: it holds **no state and no seed**, it makes
/// one platform call per request, and it either produces bytes or it fails.
/// A seeded generator whose seed lives in the binary is not a CSPRNG, and a
/// package whose whole job is to be one is not the place where that mistake
/// should hide.
///
/// The contract, in full:
///
///   * `bytes(n)` returns `n` bytes from the platform CSPRNG;
///   * two calls never return the same bytes;
///   * a failure is reported and never papered over with zeros.  OpenSSH's
///     `arc4random_buf` aborts when the platform call fails, and so does
///     this: a caller handed zeros would use them as a secret, and a zero
///     key is not a key.
///
/// The entropy itself is not this package's business.  The protocol side --
/// "how long is a DH private exponent, and what has to be true of it" --
/// lives in `src/kexdh`, which is where the group lives.
///
/// `n` bytes from the platform CSPRNG.
///
///
/// Aborts if the length is negative or if the platform source fails.
pub fn bytes(n : Int32) -> FixedArray[Byte] {
  if n < 0 {
    abort("rng.bytes: the length cannot be negative")
  }
  // The buffer is filled IN PLACE by the platform call, so the bytes have to
  // be read back from the `Bytes` and not from the `FixedArray` it was copied
  // from -- `Bytes::from_array` copies, and the copy is the one the platform
  // never sees.  This is the same trap `src/tcp` documents for the port the
  // listener reports: read the wrong buffer and you get zeros.
  let buf = Bytes::from_array(FixedArray::make(n, b'\x00'))
  if mb_rng_fill(buf, n) != 0 {
    abort("rng.bytes: the platform entropy source failed")
  }
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = buf[i]
  }
  out
}
