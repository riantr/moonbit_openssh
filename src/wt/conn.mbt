///| Loop #32: WebTransport byte-stream transport for the js backend.

///|

///|   This is the browser counterpart to Loop #31's `src/tcp`. The shapes are

///|   deliberately identical -- open / send / read_exact / close -- so the SSH

///|   layer above does not have to know which one it is sitting on. What

///|   differs is the *timing*: `src/tcp` is blocking because a socket can be,

///|   whereas WebTransport is Promise-based, so every operation here awaits.

///|

///|   All of the WebTransport machinery (the CONNECT, the bidirectional

///|   stream, the read buffer, backpressure) lives in

///|   `host/wt/moonbit_wt.js`. Keeping it there is not laziness: those are

///|   chunked, event-driven JS primitives, and the only way MoonBit can await

///|   them is across the async bridge. What is left here is the contract.

///|

///|   Scope: js target only. MoonBit's async support is native + js; the wasm

///|   backends have none, and a browser Worker running wasm could not await a

///|   socket in any case.

///|

///| Errors the transport can report. A `suberror` rather than a plain enum

///| because these cross an `async fn` boundary as raised values, and a

///| distinct code lets a caller tell "the server is unreachable" from "the

///|
/// stream died mid-handshake" without matching on message text.
suberror WtError {
  /// The session never became ready: DNS, certificate pinning, or the server
  /// not speaking WebTransport at all.
  ConnectFailed(String)
  /// The stream ended before the requested number of bytes arrived.
  Eof(String)
  /// The session failed after it had been established.
  TransportFailed(String)
}

///|

///|
/// An open WebTransport bidirectional stream, as a byte source.
pub(all) struct WtConn {
  handle : Int
}

///|

///| Open a WebTransport session and take a bidirectional stream from it.
///

///|
/// `url` is a full https origin, e.g. `https://127.0.0.1:8443/ssh`.
pub async fn WtConn::connect(url : String) -> WtConn raise WtError {
  let h = @js_async.Promise::wait(ffi_wt_open(url)) catch {
    err => raise WtError::ConnectFailed(err.to_string())
  }
  { handle: h, }
}

///|

///| Write every byte. Awaiting this matters: two concurrent writers on one

///| WritableStream throw, and the SSH layer has writes in flight while a read

///|
/// is outstanding.
pub async fn WtConn::send(
  self : WtConn,
  bytes : FixedArray[Byte],
) -> Unit raise WtError {
  let _ = @js_async.Promise::wait(ffi_wt_send(self.handle, bytes)) catch {
    err => raise WtError::TransportFailed(err.to_string())
  }
}

///|

///| Read exactly `n` bytes.
///

///| WebTransport delivers chunks, not lengths, so the shim buffers and hands

///| back an exact-size result. A short stream is an error rather than a short

///| buffer: a partial SSH packet is never useful, and silently returning one

///|
/// would push the failure somewhere much harder to read.
pub async fn WtConn::read_exact(
  self : WtConn,
  n : Int,
) -> FixedArray[Byte] raise WtError {
  let got = @js_async.Promise::wait(ffi_wt_read_exact(self.handle, n)) catch {
    err => raise WtError::Eof(err.to_string())
  }
  // The shim guarantees the length; re-derive it rather than trusting the
  // crossing, because a mismatch here would corrupt the packet framing and
  // the resulting failure would look like a crypto bug.
  let out : FixedArray[Byte] = FixedArray::make(got.length(), b'\x00')
  for i = 0; i < got.length(); i = i + 1 {
    out[i] = got[i]
  }
  out
}

///|

///| Release the stream and close the session. A handle the shim has already

///| dropped is not an error: the peer may have hung up first, and that is a

///|
/// normal way for a connection to end.
pub async fn WtConn::close(self : WtConn) -> Unit {
  let _ = @js_async.Promise::wait(ffi_wt_close(self.handle)) catch { _ => () }
}
