///|
/// Loop #84: the wasm stand-in for the CSPRNG.
///
///   A bare wasm module has no entropy source: there is no operating system
///   underneath it, no Web Crypto API, and no host to ask.  The browser path
///   this project cares about runs on the js target, where
///   `crypto.getRandomValues` is there; the wasm targets are compile-only
///   here.
///
///   So this reports failure rather than pretending.  The caller aborts with
///   a message that says the target has no entropy, instead of handing back
///   zeros that would be used as a key -- a zero key is not a key, and a
///   client that quietly used one would be a client whose traffic could be
///   read.
///
///   The wasm backends reject `extern "js"` outright, so this is plain
///
///   MoonBit rather than an FFI stub.
fn mb_rng_fill(buf : Bytes, len : Int32) -> Int32 {
  ignore(buf)
  ignore(len)
  -1
}
