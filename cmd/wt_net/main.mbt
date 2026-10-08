///| cmd/wt_net -- Loop #32 G2: MoonBit byte-stream transport against an echo.

///|

///|   Proves the MoonBit side of the transport in isolation. Everything the

///|   SSH layer needs from a transport -- open, write, read an exact length,

///|   close -- is exercised here against a known-answer payload, so a failure

///|   names the transport rather than "handshake failed".

///|

///|   The payload is echoed byte-for-byte and compared, not just hashed: an

///|   off-by-one in the shim's read buffer would still hash consistently enough

///|   to look fine, and would corrupt SSH packet framing at a point far from

///|   the cause.
///

///|   Configuration arrives through a global the Worker bootstrap sets, since a

///|   browser has no argv.

///|

///|
/// Read one value out of the bootstrap-supplied config global.
extern "js" fn cfg(name : String) -> String = "((n) => (globalThis.__wt_cfg && globalThis.__wt_cfg[n] != null) ? String(globalThis.__wt_cfg[n]) : '')"

///|

///| Hand the result back to the Worker. MoonBit's entry is an `async fn`, so

///|
/// the Worker cannot treat "importScripts returned" as completion.
extern "js" fn wt_finish(ok : Bool, detail : String) -> Unit = "((ok, detail) => { globalThis.__wt_finish({ ok: ok, detail: detail }) })"

///|
fn hex_of(b : FixedArray[Byte]) -> String {
  let hex = "0123456789ABCDEF"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_string(hex.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(hex.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}

///|
fn ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///|

///| Compare two byte arrays exactly. Length first, then contents, so a

///|
/// truncated read is reported as what it is.
fn bytes_equal(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
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

///| `async fn main` because awaiting a Promise is itself async, and MoonBit

///|
/// tracks asyncness statically: a sync `fn main` may not call the transport.
async fn main {
  let url = cfg("url")
  let nonce = cfg("nonce")
  let payload = ascii("moonbit-loop32-echo-" + nonce)
  println("wt: url=" + url)
  println("wt: payload_len=" + payload.length().to_string())
  // Report a transport failure through the normal completion path instead of
  // letting it escape: a driver asserting "this transport is expected to be
  // refused here" needs to see *why*, and a bare "did not complete" would make
  // it guess. `async fn main` may propagate an error, but then __wt_finish
  // never runs and the page learns nothing.
  try {
    let conn = @wt.WtConn::connect(url)
    println("wt: connected")
    conn.send(payload)
    println("wt: sent")
    let back = conn.read_exact(payload.length())
    println("wt: read " + back.length().to_string())
    let same = bytes_equal(back, payload)
    println("wt: echo_hex=" + hex_of(back))
    println("wt: echo_match=" + same.to_string())
    conn.close()
    wt_finish(same, "echo complete")
  } catch {
    e => {
      println("wt: transport_error=" + e.to_string())
      wt_finish(false, "transport error")
    }
  }
}
