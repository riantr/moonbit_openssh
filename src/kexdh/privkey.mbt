///|
/// Loop #84: the Diffie-Hellman private exponent.
///
/// OpenSSH does not draw this itself -- it asks OpenSSL:
///
///   dh.c:283  dh_gen_key(dh, need)
///     dh.c:300    DH_set_length(dh, MINIMUM(need * 2, pbits - 1))
///     dh.c:303    DH_generate_key(dh)
///
/// and OpenSSL's `DH_generate_key` draws the key with
/// `BN_priv_rand(..., BN_RAND_TOP_ONE, BN_RAND_TOP_ONE, ...)`: the top TWO
/// bits are set, so the key really has the length that was asked for, and the
/// bottom bit is set, so the key is odd.  The doubling in `dh.c:300` is
/// there because Pollard rho and the big-step/little-step attacks are
/// O(sqrt(n)).
///
/// This draws `pbits - 1` bits, which is the largest length the group
/// allows and is the length OpenSSH ends up with for the largest `need`.
/// It is never weaker than OpenSSH's rule; the difference is a few hundred
/// extra squarings in a modexp that costs milliseconds.
///
/// Why `pbits - 1` rather than `pbits`: the exponent has to be smaller than
/// the prime, and the prime has `pbits` bits, so a value with `pbits - 1`
/// bits is below 2^(pbits-1) and therefore below the prime.  That is a
/// GUARANTEE and not a rejection loop -- there is no "draw again until it
/// fits" here, so the distribution of the exponent is not skewed by the
/// filtering.  (A rejection loop would be fine here too, since the prime is
/// within 2^-64 of 2^2048, but a guarantee needs no argument about the
/// acceptance rate.)
///
/// The exponent is a SECRET and this file keeps it that way: it is returned,
/// never printed, and nothing in the repository writes it down.  What is
/// published is `e = g^x mod p`, which is on the wire anyway.
///
/// The SHAPING is separated from the DRAW on purpose.  `exponent_from_bytes`
/// is pure -- it takes bytes and returns an exponent with the right size and
/// the right bits -- so the whole contract can be tested WITHOUT an entropy
/// source, and therefore on every target, including the wasm ones that have
/// none.  A test file that is compiled only where an entropy source exists
/// is a test file the coverage tool cannot instrument at the default target,
/// and a package that cannot be instrumented is a package the coverage
/// report stops talking about.
///
/// How many bytes a group of `pbits` bits draws from.
///
/// `pbits` must be a whole number of bytes and at least 16.
pub fn private_exponent_bytes(pbits : Int32) -> Int32 {
  if pbits < 16 || pbits % 8 != 0 {
    abort(
      "private_exponent_bytes: the group size must be a whole number of bytes",
    )
  }
  let nbytes = pbits / 8
  nbytes
}

///|
/// Turn `bytes` into a private exponent with the right size and the right
/// bits.
///
/// The bytes are the RANDOM part; this function is the part that decides what
/// an exponent for this group has to look like:
///
///   * the top byte's high bit is CLEARED, so the exponent is below
///     2^(8n-1) and therefore below the prime;
///   * the top two bits below that are SET -- OpenSSL's "top two bits", so
///     the exponent really has the length that was asked for and the Pollard
///     rho attack has to work for all of it;
///   * the bottom byte's low bit is SET -- OpenSSL's "odd", because an even
///     exponent is `2y`, which makes `g^x = (g^y)^2` and halves the work of
///     the same attack.
///
/// `bytes` must be a whole number of bytes and at least two.
pub fn exponent_from_bytes(bytes : FixedArray[Byte]) -> @bigint.BigNat {
  let nbytes = bytes.length()
  if nbytes < 2 || nbytes % 8 != 0 {
    abort(
      "exponent_from_bytes: the exponent must be a whole number of bytes, at least two",
    )
  }
  let top = bytes[0].to_uint64()
  bytes[0] = ((top & 0x7FUL) | 0x60UL).to_byte()
  let last = bytes[nbytes - 1].to_uint64()
  bytes[nbytes - 1] = (last | 0x01UL).to_byte()
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
/// A private exponent for a Diffie-Hellman group whose prime is `pbits` bits.
///
/// `pbits` must be a whole number of bytes and at least 16.
pub fn dh_private_exponent(pbits : Int32) -> @bigint.BigNat {
  let bytes = @rng.bytes(private_exponent_bytes(pbits))
  exponent_from_bytes(bytes)
}
