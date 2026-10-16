///| cmd/wt_probe -- Loop #32 G1: can MoonBit run inside a browser Web Worker?

///|

///|   This is the load-bearing assumption for everything in Loop #32. Two

///|   things have to be true at once, and neither is obvious:

///|

///|     1. MoonBit's `--target js` output is a self-contained IIFE with no

///|        `process` / `require` / `module.exports` reference, so a Worker can

///|        `importScripts()` it with no Node shim at all.

///|     2. `extern "js"` FFI *and* the moonbitlang/async Promise bridge work

///|        inside a Worker. The bridge is the whole reason the browser story

///|        is viable: WebTransport is Promise-based, so the SSH transport has

///|        to be able to await.

///|

///|   The probe checks both and prints one line per fact. It takes no

///|   arguments: a browser has no argv, so configuration arrives through a

///|   global the Worker bootstrap sets before importing this module.

///|

///|   Deliberately not used: `@env.args()`. It compiles to a

///|   `__moonbit_fs_unstable` import that a browser would have to shim, and

///|   nothing in the browser path needs a command line.

///|

///|
/// Read one value out of the bootstrap-supplied config global.
extern "js" fn cfg(name : String) -> String = "((n) => (globalThis.__wt_cfg && globalThis.__wt_cfg[n] != null) ? String(globalThis.__wt_cfg[n]) : '')"

///|

///|
/// Call into plain JavaScript, to prove the FFI boundary is live in a Worker.
extern "js" fn js_probe() -> Int32 = "(() => (typeof globalThis) === 'object' && typeof globalThis.WorkerGlobalScope !== 'undefined' ? 1 : 0)"

///|

///| Return a real JS Promise, so the MoonBit side can await something that is

///|
/// genuinely asynchronous rather than an already-resolved value.
extern "js" fn js_async_probe(tag : String) -> @js_async.Promise[String] = "((t) => new Promise((resolve) => setTimeout(() => resolve('async:' + t), 5)))"

///|

///| Hand the result back to the Worker. MoonBit's entry is an `async fn`, so

///| the Worker cannot treat "importScripts returned" as completion; MoonBit

///|
/// has to say when it is actually done.
extern "js" fn wt_finish(ok : Bool, detail : String) -> Unit = "((ok, detail) => { globalThis.__wt_finish({ ok: ok, detail: detail }) })"

///|

///| `async fn main` because awaiting a Promise is itself an async operation:

///| MoonBit's compiler tracks asyncness statically, so a sync `fn main` may

///|
/// not call `.wait()` at all.
async fn main {
  println("probe: js_iife=true")
  println("probe: js_ffi=" + js_probe().to_string())
  println("probe: cfg_tag=" + cfg("tag"))
  let v = @js_async.Promise::wait(js_async_probe(cfg("tag")))
  println("probe: promise_wait=" + v)
  println("probe: done")
  wt_finish(true, v)
}
