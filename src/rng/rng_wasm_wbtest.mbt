///|
/// src/rng: the wasm backends' own test.
///
///   The contract in `rng_test.mbt` -- "the length asked for is the length
///   delivered, two calls differ, the output is not zeros, the whole buffer
///   was written" -- is a contract about a source of entropy.  The wasm
///   backends have none: a bare wasm module has no operating system
///   underneath it, no Web Crypto API and no host to ask.  So the contract
///   file is compiled only where the contract can hold (native and js), and
///   this file is compiled only where it cannot.
///
///   What this file asserts is the one thing that has to be true on a target
///   with no entropy source: the backend REPORTS the failure.  It does not
///   return zeros, and it does not return some other bytes it made up.  A
///   caller handed zeros would use them as a key, and a zero key is not a
///   key -- a client that quietly used one would be a client whose traffic
///   could be read.
///
///   The abort that follows the failure is in `api.mbt`, and it is observed
///   from the outside by `host/verify_loop84.mjs`, which runs a wasm build
///   of `cmd/wasm_rng_probe` under `host/node_host.mjs` and requires it to
///   PANIC rather than print zeros.  A unit test cannot watch an abort from
///   the inside, which is why the end-to-end half of the claim lives in the
///
///   gate and this file covers the half a unit test can see.
test "the_wasm_backend_reports_failure_instead_of_inventing_bytes" {
  let buf = Bytes::from_array(FixedArray::make(16, b'\x00'))
  assert_eq(mb_rng_fill(buf, 16), -1)
  // And it did not touch the buffer on its way to failing.  A backend that
  // filled it and then reported failure would be a backend that has an
  // entropy source after all, and the caller would be right to ignore the
  // error -- which is exactly the mistake this package is here to prevent.
  let mut touched = 0
  for i = 0; i < 16; i = i + 1 {
    if buf[i] != b'\x00' {
      touched = touched + 1
    }
  }
  assert_eq(touched, 0)
}
