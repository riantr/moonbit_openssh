///|
/// Loop #84: js backend for the CSPRNG.
///
///   The Web Crypto API is the browser's own CSPRNG, and it is the same
///   generator a page would use for anything else.  Node has it too, as
///   `globalThis.crypto` since Node 19, so the same code runs under the js
///   target in a page and in Node.
///
///   Measured, not assumed: a MoonBit `Bytes` reaches JS as a `Uint8Array`,
///   and `crypto.getRandomValues` fills it in place -- the MoonBit side sees
///   the new bytes.  (Probe: a 16-byte buffer pre-filled with 0xAA came back
///   with all 16 bytes changed.)
///
///   Two details the Web Crypto API insists on:
///
///   * `getRandomValues` refuses a view longer than 65536 bytes, so a long
///     request is filled in chunks.  `subarray` gives a view on the SAME
///     buffer, so the chunks land where the first chunk would have.
///
///   * It needs an integer TypedArray.  A MoonBit `Bytes` is one, so it can
///
///     be handed over as it is.
#borrow(buf)
extern "js" fn mb_rng_fill(buf : Bytes, len : Int32) -> Int32 = "((_b, _l) => { const c = globalThis.crypto; if (!c || typeof c.getRandomValues !== 'function') { return -1; } const CHUNK = 65536; for (let off = 0; off < _l; off += CHUNK) { const n = Math.min(CHUNK, _l - off); c.getRandomValues(_b.subarray(off, off + n)); } return 0; })"
