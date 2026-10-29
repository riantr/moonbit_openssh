///|
/// cmd/wasm_rng_probe -- Loop #84: the wasm backend has no entropy source,
/// and says so.
///
///   The lines are:
///
///     wasm_rng_probe: start     before the draw
///     wasm_rng_probe: got <n>   after the draw
///
///   On the wasm backends only the first line is ever printed: the draw
///   aborts, and the abort is the answer.  The gate runs this binary under
///   `host/node_host.mjs`, which reports a MoonBit panic as exit code 3,
///   and requires exit 3 with no second line.  A build that printed the
///   second line would be handing back bytes it made up, and a key made up
///
///   out of nothing is not a key.
fn main {
  println("wasm_rng_probe: start")
  let a = @rng.bytes(32)
  println("wasm_rng_probe: got " + a.length().to_string())
}
