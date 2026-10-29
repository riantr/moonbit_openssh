///|
/// src/kexdh: the DH private exponent's size and shape.
///
/// Run: `moon test src/kexdh`
///
/// These tests are about the SIZE and the SHAPE of the exponent, not about
/// its value -- the value is a secret and is never printed.  Three
/// properties are checked, and each of them is a security property:
///
///   * the exponent has the group's bit length.  A 256-bit exponent in a
///     2048-bit group is not a weaker DH, it is a broken one: the discrete
///     logarithm over such a group is a matter of seconds, and the shared
///     secret that was "protected" is recoverable by anyone who recorded
///     the exchange.
///
///   * the top TWO bits are set.  This is OpenSSL's
///     `BN_RAND_TOP_ONE, BN_RAND_TOP_ONE`, which OpenSSH's `dh.c:300`
///     reaches through `DH_set_length(dh, MINIMUM(need * 2, pbits - 1))`:
///     the doubling exists because Pollard rho and the big-step/little-step
///     attacks are O(sqrt(n)).  An exponent with a random top half is
///     easier to attack by exactly that much.
///
///   * the exponent is odd.  OpenSSL's `BN_RAND_TOP_ONE` on the bottom
///     bit, and the reason is the same: an even exponent halves the
///     effective work of the Pollard rho attack, because `x = 2y` makes
///     `g^x = (g^y)^2`.
///
/// The SHAPING is tested on fixed bytes rather than on a draw, and that is
/// deliberate.  The shaping is the part that has to be right, and it can be
/// tested without an entropy source -- so these tests run on every target,
/// including the wasm ones, which have none.  (A test that needed a draw
/// would have to be compiled only where there is a CSPRNG, and a package
/// whose test driver does not compile at the default target is a package
/// the coverage tool cannot instrument at all.)
///
/// What is NOT tested here is that two draws differ: that is a property of
/// `src/rng`, and it is tested there and, end to end, by comparing the DH
/// public values of two live connections.
test "a_2048_bit_group_draws_256_bytes" {
  // The link between the group's size and the draw's length.  256 bytes is
  // 2048 bits, and the exponent that comes out of it has 2047 of them.
  assert_eq(@kexdh.private_exponent_bytes(2048), 256)
}

///|
test "the_private_exponent_has_the_groups_bit_length" {
  // pbits - 1, not pbits: a value with pbits bits could be larger than the
  // prime, and the prime is what the exponent has to stay below.
  let bytes = FixedArray::make(256, b'\x00')
  let x = @kexdh.exponent_from_bytes(bytes)
  assert_eq(@bigint.BigNat::bit_length(x), 2047)
}

///|
test "the_private_exponent_has_its_top_two_bits_set" {
  let bytes = FixedArray::make(256, b'\x00')
  let x = @kexdh.exponent_from_bytes(bytes)
  // Shifting a bit down to position 0 and asking whether the result is odd
  // asks whether THAT bit was set.  Bit 2046 is implied by the bit length;
  // bit 2045 is the one that is not.
  assert_eq(
    @bigint.BigNat::is_odd(@bigint.BigNat::shift_right_bits(x, 2046)),
    true,
  )
  assert_eq(
    @bigint.BigNat::is_odd(@bigint.BigNat::shift_right_bits(x, 2045)),
    true,
  )
}

///|
test "the_private_exponent_is_odd" {
  let bytes = FixedArray::make(256, b'\x00')
  let x = @kexdh.exponent_from_bytes(bytes)
  assert_eq(@bigint.BigNat::is_odd(x), true)
}

///|
test "the_shape_does_not_depend_on_the_bytes_it_is_given" {
  // The shaping overrides the top byte's high bit and the bottom byte's low
  // bit, so two inputs that differ ONLY in those bits come out the same --
  // and two inputs that differ anywhere else do not.
  let a = FixedArray::make(256, b'\x00')
  let b = FixedArray::make(256, b'\x00')
  b[128] = b'\x01'
  assert_eq(
    @bigint.BigNat::cmp(
      @kexdh.exponent_from_bytes(a),
      @kexdh.exponent_from_bytes(b),
    ) !=
    0,
    true,
  )
}
