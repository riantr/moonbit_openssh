///|
/// Loop #84: the secrets a key exchange needs.
///
/// Before this loop the client had neither of them: the KEXINIT cookie was
/// a fixed 16-byte array and the Diffie-Hellman private exponent was a fixed
/// 32-byte constant, and every session this client opened used the same
/// two.  A DH exchange with a known private exponent has no forward secrecy
/// at all -- the shared secret is `f^x` for an `x` that is in the source
/// code -- and a fixed cookie means every transcript this client produces
/// starts with the same sixteen bytes.
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
/// The two are not treated the same way here, and the difference is
/// deliberate:
///
///   * The COOKIE is always random.  Nothing needs it to be reproducible:
///     the transcript oracle reads it off the wire.  So the library draws
///     it and no caller can get it wrong.
///
///   * The EXPONENT has one documented exception, because
///     `host/transcript_check.py` recomputes the exchange hash in Python
///     from the bytes on the wire, and to do that it needs the shared
///     secret, and to get the shared secret it needs the client's private
///     exponent -- which it cannot learn from the wire, because recovering
///     it from `e = g^x mod p` is the discrete logarithm.  The oracle
///     therefore runs the client with a known exponent, and the driver has
///     to ask for that by name.  It is a testing premise, not a production
///     one: a client that used the fixed exponent in anger would have no
///     forward secrecy, which is the very thing this loop exists to remove.
///
/// A fresh 16-byte KEXINIT cookie (RFC 4253 §7.1), from the platform CSPRNG.
///
/// The cookie is meant to make every KEXINIT distinct.  A fixed one does
/// not: it says "this is the same client that was here yesterday", to
///
/// anyone reading the transcript.
pub fn random_cookie() -> FixedArray[Byte] {
  @rng.bytes(@kexflow.KEX_COOKIE_LEN)
}

///|
/// A fresh DH private exponent for the group this client negotiates.
///
/// The exponent is a SECRET.  It is never printed and never written down;
///
/// what is published is `e = g^x mod p`, which is on the wire anyway.
pub fn random_dh_priv() -> @bigint.BigNat {
  @kexdh.dh_private_exponent(@kexdh.group14_prime_bit_length())
}

///|
/// The fixed DH private exponent, the one the transcript oracle knows.
///
/// It is the value that `cmd/ssh_live`, `cmd/ssh_keyscan` and `cmd/wt_ssh`
/// each carried a copy of before Loop #84, and the value
///
/// `host/transcript_check.py` has in its `FIXED_X`.
pub fn fixed_dh_priv() -> @bigint.BigNat {
  @bigint.BigNat::from_bytes_be(
    FixedArray::from_array([
      0x5A, 0x17, 0xC3, 0x9E, 0x44, 0xB2, 0x6D, 0xF1, 0x08, 0xA7, 0x35, 0xCC, 0x91,
      0x2E, 0x60, 0xD3, 0x74, 0x18, 0x9F, 0xE2, 0x50, 0xB7, 0xC6, 0x3D, 0x81, 0x0A,
      0xF5, 0x29, 0x64, 0xC8, 0x7B, 0x1E,
    ]),
  )
}

///|
/// The fixed 16-byte KEXINIT cookie.
///
/// Kept for the same reason as `fixed_dh_priv`: a transcript that has to
///
/// be reproducible.  Nothing else should use it.
pub fn fixed_cookie() -> FixedArray[Byte] {
  let c : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  let mut i = 0
  while i < 16 {
    c[i] = (0xA0 + i).to_byte()
    i = i + 1
  }
  c
}
