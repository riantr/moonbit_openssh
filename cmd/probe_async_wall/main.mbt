///| Loop #64 probe: can a *synchronous* MoonBit fn observe bytes that a
/// deferred JavaScript callback has not delivered yet?
///
/// This decides whether `@transport.Transport` can be implemented over a real
/// browser WebSocket without converting the whole SSH layer to `async fn`.
///
/// The setup mirrors the real thing exactly: a JavaScript callback scheduled
/// with `setTimeout(..., 0)` is the stand-in for `WebSocket.onmessage`, and a
/// shared array is the stand-in for the receive buffer. A byte that exists only
/// inside that callback is exactly a byte a real socket has not delivered yet.
///
///   sync  -- spin until the slot is non-empty
///   async -- await the promise the same callback resolves
///
/// If MoonBit's synchronous code yields to the JS event loop, `sync` finds the
/// byte. If it does not -- which is the claim under test -- `sync` spins its
/// whole budget with the callback never able to run, and reports STARVED,
/// while `async` receives the byte.

extern "js" fn slot_reset() -> Unit =
  "() => { globalThis.__probe_slot = []; }"

extern "js" fn slot_empty() -> Bool =
  "() => globalThis.__probe_slot.length === 0"

extern "js" fn slot_take() -> Int =
  "() => globalThis.__probe_slot.shift()"

// The stand-in for `WebSocket.onmessage`: one byte, delivered by the event loop.
extern "js" fn arm_deferred_byte() -> Unit =
  "() => { setTimeout(() => { globalThis.__probe_slot.push(0x5a); }, 0); }"

extern "js" fn arm_deferred_promise() -> @js_async.Promise[Int] =
  "() => new Promise((res) => { setTimeout(() => res(0x5a), 0); })"

///|
/// The synchronous attempt. Bounded so the probe terminates instead of hanging
/// the process; the bound is also the measurement.
fn sync_take(spin_budget : Int) -> Int {
  let mut spins = 0
  while slot_empty() && spins < spin_budget {
    spins = spins + 1
  }
  if slot_empty() {
    -1
  } else {
    slot_take()
  }
}

///|
/// The asynchronous attempt: the callback this waits on is scheduled exactly
/// like the one above.
async fn async_take() -> Int {
  @js_async.Promise::wait(arm_deferred_promise())
}

///|
async fn main {
  let budget = 5000000

  slot_reset()
  arm_deferred_byte()
  let s = sync_take(budget)
  if s == 0x5a {
    println("sync : GOT 0x5a -- synchronous code does yield")
  } else {
    println("sync : STARVED after \{budget} spins -- synchronous code never yields")
  }

  let a = async_take()
  if a == 0x5a {
    println("async: GOT 0x5a")
  } else {
    println("async: UNEXPECTED \{a}")
  }
}