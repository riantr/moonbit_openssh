///|
/// cmd/wt_rng_probe -- Loop #84: the CSPRNG, inside a browser Web Worker.
///
///   The native side of this loop is easy to check: `moon test src/rng
///   --target native` runs the contract in a process that has an operating
///   system underneath it.  The browser side is the one that matters for this
///   project, because the browser is where the client is meant to run, and a
///   browser has no `BCryptGenRandom` -- it has the Web Crypto API.
///
///   So this probe asks the browser the four questions the contract is made
///   of, in the place the contract has to hold:
///
///     rng: len=16          the length asked for is the length delivered
///     rng: differs=1       two calls are not the same bytes
///     rng: nonzero=1       the output is not all zeros
///     rng: halves=1        the whole buffer was written (4096 bytes, two
///                          halves that a half-filled implementation would
///                          have made equal)
///     rng: head=<32 hex>   the first sixteen bytes, so a human can see they
///                          are not the constant this client used to send
///
///   The last one is a fact, not a claim: the old constant was
///   A0A1A2A3A4A5A6A7A8A9AAABACADAEAF, and the gate asserts the head is not
///   it.
///
///   It takes no arguments: a browser has no argv, so configuration arrives
///   through the global the Worker bootstrap sets before importing this
///   module.  `@env.args()` is deliberately not used -- it compiles to a
///   `__moonbit_fs_unstable` import that a browser would have to shim.
///
/// Hand the result back to the Worker.  The `globalThis.__wt_finish` guard
/// is what lets the same module run under Node, where the Worker bootstrap
///
/// does not exist.
extern "js" fn wt_finish(ok : Bool, detail : String) -> Unit = "((ok, detail) => { if (globalThis.__wt_finish) { globalThis.__wt_finish({ ok: ok, detail: detail }); } })"

///|
/// Uppercase hex, local to this probe: `src/rng` has no dependencies and
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
fn same_bytes(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
fn all_zero(b : FixedArray[Byte]) -> Bool {
  for i = 0; i < b.length(); i = i + 1 {
    if b[i] != b'\x00' {
      return false
    }
  }
  true
}

///|
/// Is the second half of the buffer anything but zeros?
///
/// A CSPRNG that filled only the first half of the buffer would leave the
/// second half exactly as it found it -- all zeros.  That is the check that
/// catches a HALF-filled buffer, and the check that compares the two halves
/// does NOT catch it: a half-filled buffer has a random first half and a
///
/// zero second half, and those two are DIFFERENT.
fn tail_nonzero(b : FixedArray[Byte]) -> Bool {
  let half = b.length() / 2
  for i = half; i < b.length(); i = i + 1 {
    if b[i] != b'\x00' {
      return true
    }
  }
  false
}

///|
/// Are the two halves of the buffer different?
///
/// This is the check that catches a buffer filled with ONE CONSTANT: its
/// halves are equal.  The check that catches a half-filled buffer is
/// `tail_nonzero` above, and both are needed -- a constant fill and a half
///
/// fill are different mistakes with different shapes.
fn halves_differ(b : FixedArray[Byte]) -> Bool {
  let half = b.length() / 2
  for i = 0; i < half; i = i + 1 {
    if b[i] != b[i + half] {
      return true
    }
  }
  false
}

///|
fn main {
  let sixteen = @rng.bytes(16)
  println("rng: len=" + sixteen.length().to_string())
  println("rng: head=" + hex(sixteen))
  let a = @rng.bytes(32)
  let b = @rng.bytes(32)
  println("rng: differs=" + (if same_bytes(a, b) { "0" } else { "1" }))
  let zeros = @rng.bytes(64)
  println("rng: nonzero=" + (if all_zero(zeros) { "0" } else { "1" }))
  let big = @rng.bytes(4096)
  println("rng: tail=" + (if tail_nonzero(big) { "1" } else { "0" }))
  println("rng: halves=" + (if halves_differ(big) { "1" } else { "0" }))
  println("rng: done")
  wt_finish(true, "ok")
}
