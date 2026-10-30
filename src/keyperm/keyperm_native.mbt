///|
/// Loop #85: the native half of making a private key file private.
///
/// The C side is `keyperm.c`, and it is a thin call into the Windows
/// security API.  What it does and why is written out there.
///
/// **The path is passed with a length, not as a NUL-terminated string.**
/// A MoonBit `Bytes` is not NUL-terminated, and every Windows API that
/// takes a path wants one.  The C side copies the bytes into a buffer
/// it terminates itself.
#borrow(path)
extern "c" fn mb_keyperm_protect(path : Bytes, path_len : Int32) -> Int32 = "mb_keyperm_protect"

///|
/// The wide character at `index` of the path, as an integer.
///
/// This exists so that a failure in the C side can be told apart from a
/// failure in the MoonBit side: the C side reports a stage code, and
/// this reports what it saw.  It is not part of the public contract of
/// the package.
pub fn path_code_unit(path : String, index : Int32) -> Int32 {
  if index < 0 || index >= path.length() {
    return -1
  }
  path[index].to_int()
}

///|
/// Restrict the file at `path` to its owner.
///
/// Returns 0 on success and a negative stage code on failure.  The
/// stage codes are documented in `keyperm.c`.
pub fn protect(path : String) -> Int32 {
  let bytes : FixedArray[Byte] = FixedArray::make(path.length(), b'\x00')
  for i = 0; i < path.length(); i = i + 1 {
    bytes[i] = path[i].to_byte()
  }
  let b = Bytes::from_array(bytes)
  mb_keyperm_protect(b, path.length())
}
