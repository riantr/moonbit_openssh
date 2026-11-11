///| A path as the bytes the platform layer takes.
///
/// ## Why this is not inside the native file
///
/// It started there, and `moon check --deny-warn` refused the package on
/// wasm-gc with `unused_package: 'moonbitlang/core/encoding/utf8'` --
/// because the only user was a `targets: ["native"]` file, and on any
/// other target nothing referenced the encoder at all.
///
/// Rather than delete the import (which would break the native build) or
/// silence the warning, the helper moved here.  Encoding a path to UTF-8
/// is **not** platform-specific: it is the one step both halves of the
/// contract agree on, and it is testable on every backend, which is what
/// the test below does.  The C side then widens these bytes to UTF-16
/// with `MultiByteToWideChar(CP_UTF8, ...)` -- `localfs.c` says why wide.
///
/// ## Why bytes and not a `String`
///
/// A MoonBit `String` is not NUL-terminated and is not a byte array: it
/// is a sequence of UTF-16 code units.  Every C entry point in this loop
/// takes `(pointer, length)` for exactly that reason, and a path
/// containing a non-ASCII name has to survive the crossing -- which is
/// the second test.

///|
/// A MoonBit string as UTF-8 bytes.
pub fn path_bytes(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}

///|
/// The same array as a `Bytes`, which is what the `extern "c"` calls take.
pub fn path_borrow(s : String) -> Bytes {
  Bytes::from_array(path_bytes(s))
}
