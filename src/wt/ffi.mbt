///| Loop #32: FFI surface to `host/wt/moonbit_wt.js`.

///|

///|   Each declaration is a thin arrow function over the shim's promise-based

///|   API. The bodies use the double-quoted IIFE form

///|   (`= "((args) => ...)"`) rather than `#| ... |#`: the compiler evaluates

///|   the right-hand side as a module constant, and in this toolchain the

///|   quoted form is the one that reliably lands a bare function value in the

///|   output. The `|#` inline form leaked its own terminator into the emitted

///|   JavaScript and produced a SyntaxError at load time in the browser.

///|

///|   Errors are returned rather than raised on the JS side: MoonBit maps a

///|   rejected Promise onto its own error type, and doing the conversion here

///|   keeps the shim free of any MoonBit knowledge. The MoonBit wrappers

///|
///   re-raise as `WtError` with a code that means something.
#borrow(bytes)
extern "js" fn ffi_wt_send(
  handle : Int,
  bytes : FixedArray[Byte],
) -> @js_async.Promise[Unit] = "((h, b) => globalThis.__moonbit_wt.send(h, new Uint8Array(b)))"

///|
extern "js" fn ffi_wt_open(url : String) -> @js_async.Promise[Int] = "((u) => globalThis.__moonbit_wt.open(u).then((h) => h))"

///|
extern "js" fn ffi_wt_read_exact(
  handle : Int,
  n : Int,
) -> @js_async.Promise[FixedArray[Byte]] = "((h, n) => globalThis.__moonbit_wt.read_exact(h, n).then((u8) => u8))"

///|
extern "js" fn ffi_wt_close(handle : Int) -> @js_async.Promise[Unit] = "((h) => globalThis.__moonbit_wt.close(h))"
