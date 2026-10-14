///| Loop #63 probe: can wasm-gc export a callable function, or only `_start`?
///
/// `cmd/ssh_full_ws`'s wasm exports exactly one symbol, `_start`, which calls
/// `main` once. `moonbit_socket.ws_recv_into` is therefore reached from a
/// synchronous call inside a wasm frame, with no way for the host to hand
/// control back to Node's event loop -- and a WebSocket delivers data from
/// `onmessage`, which needs the event loop. That is the deadlock
/// `host/verify_loop23.mjs` names in its own header and works around by writing
/// a Node.js client instead.
///
/// The only way out is to re-enter the wasm between reads, which needs an
/// exported symbol. This file exists to find out whether MoonBit can produce
/// one. If it cannot, the answer is not "try harder": the browser path needs a
/// different shape, and saying so precisely is the deliverable.

///| A plain function. If wasm-gc can export it, it appears in the module's
/// export table alongside `_start`.
pub fn probe_step(n : Int) -> Int {
  n + 1
}

fn main {
  println("probe_step(41) = \{probe_step(41)}")
}