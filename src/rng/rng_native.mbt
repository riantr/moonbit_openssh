///|
/// Loop #84: native backend for the CSPRNG.
///
///   `Bytes` and `String` are both pointer types in this ABI, so the buffer
///   needs the #borrow annotation: the MoonBit side keeps ownership and C
///
///   fills the bytes in place.
#borrow(buf)
extern "c" fn mb_rng_fill(buf : Bytes, len : Int32) -> Int32 = "mb_rng_fill"
