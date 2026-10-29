///|
/// cmd/rng_probe -- Loop #84: the CSPRNG, on the command line.
///
///   The gate cannot check randomness by looking at it -- that is the whole
///   point of randomness -- so it checks the things a CSPRNG wrapper can be
///   wrong about, and it needs bytes to do that with.  This driver produces
///   them and prints them; the comparing happens in the gate, not here, so
///   that a mistake in this file cannot hide a mistake in `src/rng`.
///
///   The lines are:
///
///     rng_first:   <64 hex>     32 bytes
///     rng_second:  <64 hex>     32 bytes, a second draw
///     rng_4096:    <8192 hex>   4096 bytes
///     rng_len1:    <2 hex>      one byte
///     rng_zero_len: ok          a request for zero bytes
///
///   The 4096-byte line is the one that proves the WHOLE buffer was
///   written: an implementation that filled only the first half would leave
///   two identical 2048-byte halves, which the gate compares.  A statistical
///   argument would not do -- two halves of a real CSPRNG output are equal
///   with probability 2^-16384, but "the byte distribution looks random" is
///   a claim about a sample, and a structural claim about a buffer is not.
///
/// Uppercase hex, local to this driver: `src/rng` has no dependencies and
///
/// this probe should not add one just to print bytes.
fn hex(b : FixedArray[Byte]) -> String {
  let digits = "0123456789ABCDEF"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_string(digits.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(digits.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}

///|
fn main {
  println("rng_first: " + hex(@rng.bytes(32)))
  println("rng_second: " + hex(@rng.bytes(32)))
  println("rng_4096: " + hex(@rng.bytes(4096)))
  println("rng_len1: " + hex(@rng.bytes(1)))
  let zero = @rng.bytes(0)
  println("rng_zero_len: " + zero.length().to_string())
}
