# Project Agents.md Guide

This is a [MoonBit](https://docs.moonbitlang.com) project.

You can browse and install extra skills here:
<https://github.com/moonbitlang/skills>

## Project Structure

- MoonBit packages are organized per directory; each directory contains a
  `moon.pkg` file listing its dependencies. Each package has its files and
  blackbox test files (ending in `_test.mbt`) and whitebox test files (ending in
  `_wbtest.mbt`).

- In the toplevel directory, there is a `moon.mod` file listing module
  metadata.

## Coding convention

- MoonBit code is organized in block style, each block is separated by `///|`,
  the order of each block is irrelevant. In some refactorings, you can process
  block by block independently.

- Try to keep deprecated blocks in file called `deprecated.mbt` in each
  directory.

## Tooling

- `moon fmt` is used to format your code properly.

- `moon ide` provides project navigation helpers like `peek-def`, `outline`, and
  `find-references`. See $moonbit-agent-guide for details.

- `moon info` is used to update the generated interface of the package, each
  package has a generated interface file `.mbti`, it is a brief formal
  description of the package. If nothing in `.mbti` changes, this means your
  change does not bring the visible changes to the external package users, it is
  typically a safe refactoring.

- In the last step, run `moon info && moon fmt` to update the interface and
  format the code. Check the diffs of `.mbti` file to see if the changes are
  expected.

- Run `moon test` to check tests pass. MoonBit supports snapshot testing; when
  changes affect outputs, run `moon test --update` to refresh snapshots.

- Prefer `assert_eq` or `assert_true(pattern is Pattern(...))` for results that
  are stable or very unlikely to change. For snapshot tests that record
  structured debugging output, derive `Debug` and use `debug_inspect`, rather
  than deriving `Show` for debugging. For solid, well-defined results (e.g.
  scientific computations), prefer assertion tests. You can use
  `moon coverage analyze > uncovered.log` to see which parts of your code are
  not covered by tests.

## Project-Specific: Triple-Blind Crypto Verification

This is a cryptographic port of OpenSSH. Every crypto module must be
**byte-exact** cross-checked against two independent references before being
trusted: (1) the OpenBSD C reference, (2) a Python stdlib/library
implementation. The MoonBit implementation is the third leg.

### Layout

```
verify_c/             ← earlier, broader C-side harness suite (9 modules:
                        aead / bpacket / ed25519 / hmac_sha512 / hostkey /
                        kex / kex_c25519 / poly1305 / sha256 / sha512 /
                        x25519). Uses OpenBSD sha2.c for SHA.  Keep as-is.
triple_check/         ← newer, unified 3-way harness with one driver per
                        module + a top-level compare.py. Uses hand-written
                        SHA-512 (gen_tables.py derives H0/K from Newton
                        integer roots; no hand transcription).
                        c/main.c + python/verify.py + compare.py
```

Both directories coexist. Use `verify_c/` for the broader per-module harness
(especially when you need sha2.c-style incremental SHA-512 over a large
stream), and use `triple_check/<module>/` when you want a single, self-
contained, three-language byte-exact comparison.

### Adding triple-blind for a new module

For module `<m>`:

1. Pick the reference C source (preferably a stripped copy of the OpenSSH
   `<m>.c` placed in `triple_check/c/`) plus the same shim headers used
   for ed25519 (`config.h`, `includes.h`, `crypto_api.h`).
2. Write `triple_check/c/main_<m>.c` driver: minimal driver that calls
   the C functions on RFC/Rosenpass/OpenSSH KAT vectors, prints hex.
3. Write `triple_check/python/verify_<m>.py` using the corresponding
   Python library (`cryptography`, `hashlib`, `hmac`, etc.).
4. Update `triple_check/compare.py` to run all three: MoonBit test +
   C driver + Python ref, and assert byte-exact equality on the printed
   hex strings plus the published RFC KAT values.
5. Document the result in `<module>/REPORT.md` with the protocol/RFC
   number, KAT source, and the unified pass/fail per target.

### Acceptance criterion

For each crypto module:
- All three impls (MoonBit / C / Python) produce **byte-exact** outputs
  on the published KAT vectors.
- `moon test` passes 100% on native / wasm-gc / js.
- `moon check` shows 0 errors (warnings allowed only if pre-existing
  and unrelated to the module under test).

### Build commands

```bash
# Loop #32: the full browser gate -- G1 Worker, G2 byte stream, G3 SSH
# handshake against a real sshd, plus the Loop #30 crypto suites 4x2.
node host/verify_loop32.mjs
node host/verify_loop32.mjs --skip-regression   # browser stages only

# Loop #31: live-sshd gate (real OpenSSH on 127.0.0.1:22230, the MoonBit
# client, the exchange hash cross-checked twice, Loop #30 regressions)
node host/verify_loop31.mjs
node host/verify_loop31.mjs --keep-sshd     # leave the server up for poking

# Run all MoonBit tests
moon test                                   # defaults to native

# Rebuild C driver (hand-written SHA-512, no OpenSSH sha2.c)
cd triple_check/c
python gen_tables.py                        # regenerate tables.h
gcc -I. -c ed25519.c -o ed25519.o           # vendored OpenSSH ed25519.c
gcc -I. -c main.c -o main.o                 # driver
gcc main.o ed25519.o -o test_c.exe          # link

# Cross-check Python reference
cd triple_check/python
python verify.py

# One-shot triple-blind comparison (all 3 impls)
cd triple_check
python compare.py
```

### Pitfalls observed and fixed

- **`for ... else` in gen_tables.py**: the original prime sieve had
  `break` inside the `for` body, so the `else` clause never fired and
  the loop never produced primes. Fixed with an explicit `is_prime`
  flag.
- **`>> 31` on UInt64**: MoonBit UInt64 shift returns a 64-bit value, so
  `(x >> 31) & 1` gives a wrong bit position. Use `(x >> 63) & 1UL`
  instead. Affected: `fe_equal16`, `fe_ge16`, `sc_lt16`, `ge_equal_i8`.
- **`FixedArray::make(n, shared_val)` aliasing**: the inner value is
  shared by reference; struct constructors must initialize each element
  independently. The `src/test_nested/nested_test.mbt` directory is
  kept on disk (gitignored) as a diagnostic for this bug.
- **`#include "includes.h"` search path**: quoted includes always
  search the source file's directory first, so copying `ed25519.c` into
  `triple_check/c/` (next to the shim `includes.h`) is required to use
  the shim instead of the OpenSSH `includes.h` (which pulls in
  `<sys/socket.h>` and friends).
- **Empty-string SHA-512 self-test**: hashing `""` and comparing
  against `cf83e135...` transitively validates ALL 8 H0 and 80 K
  constants. Any single wrong constant changes the digest.
- **SSH transport exchange hash (Loop #31)**: RFC 4253 §8 lists the
  inputs informally and the natural reading is wrong. All eight fields
  are length-prefixed, K included, and I_C / I_S are the *complete*
  KEXINIT payload with the `0x14` type byte sitting **immediately after
  the length prefix**, not at the end. See `kex_gen_hash()` in
  `kexgen.c:47-96` and `kex_dh_compute_key()` in `kexdh.c:105` for the
  authoritative shape. Do not re-derive this from the RFC: run
  `python host/paramiko_oracle.py --port <p>`, which sweeps all 16
  prefix combinations against a live paramiko `session_id`.
- **`mpint_encode` already emits the u32 length prefix.** Wrapping its
  output in `write_ssh_string` again produces a string whose value
  starts with four zero bytes; a real server reads that as a far larger
  number and rejects the DH value as `>= p-1`.
- **SSH packet framing**: `packet_length` must be `4 (mod 8)` (the
  length field counts itself), the payload begins at offset 5 *within*
  the packet but at index 6 of the assembled buffer once the type byte
  is in place, and the payload length is
  `packet_length - padding_length - 2`.
- **`moon fmt` scope and CJK damage**: run it only over the packages the
  loop actually touched, then `git checkout --` the rest — it reformats
  unrelated legacy files and can alter CJK comments (it turned
  `真实加密` into `真加密` in `src/sshclient/moon.pkg`).
- **`moon check` summary goes to stderr** and exits 0 even with
  warnings, so a stdout-only capture sees an empty string. Read the
  error count out of the `N warnings, M errors` line across both
  streams, as `moonCheck()` in `host/verify_loop31.mjs` does.
- **Absolute artifact paths in `execSync`**: a bare `_build/...` is
  resolved by `cmd.exe` as a command name, not a path. Quote an
  absolute path instead.
- **`extern "js"` inline bodies: use the quoted IIFE form.** Write
  `= "((x) => ...)"`, not `#| (x) => ... |#`. In the `moon` version
  in use here the `#| ... |#` terminator is left in the emitted
  JavaScript, so every such FFI becomes a `SyntaxError` at load time
  in the browser. The quoted form is what `src/tcp/socket_js.mbt`
  already uses.
- **MoonBit has no `FixedArray` slice syntax.** `b[off..len]` is a
  parse error. Use a helper (`slice_bytes` in `src/sshclient/framing.mbt`).
- **A `suberror` cannot be pattern-matched.** Its constructors are not
  enum constructors. If a type must both be raised and matched for
  reporting, keep it a plain `pub(all) enum` and have the inner helpers
  return `Bool`/`Option` instead of raising -- which is also how
  Loop #31's blocking driver is structured.
- **`moonbitlang/async` does not support the wasm backends.** It covers
  native and js only. Anything awaiting a browser API is therefore
  `--target js` plus a Web Worker; the wasm artifacts cannot be the
  browser path. A `targets:` gate on a js-only module is what stops it
  leaking (the build simply fails for wasm, producing no artifact).
- **An `async fn main` that raises never reaches the Worker's completion
  hook.** Wrap the body and report through `wt_finish`, or the page
  only ever learns "timed out".
- **Chromium does not accept a locally-added certificate over QUIC.**
  It reports `QUIC_TLS_CERTIFICATE_UNKNOWN` for every override flag
  (`--ignore-certificate-errors`, `--ignore-certificate-errors-spki-list`
  with either the CA or leaf SPKI, dropping `--enable-automation`, and
  headed mode), while accepting the *same* certificate over plain HTTPS.
  WebTransport cannot be tested locally against a self-signed endpoint;
  use `ws://` (see `host/wt/ws_relay.py`) for the local end-to-end proof
  and keep WebTransport for endpoints with a publicly trusted
  certificate.
- **`page.evaluate` passes exactly one argument.** A Node-side variable
  referenced inside the browser function is simply undefined there, and
  the failure surfaces as a generic timeout. Put everything the browser
  needs inside the single config object.
- **aioquic 1.x: start a server with `serve()`, never a hand-rolled
  `create_datagram_endpoint`.** `QuicServer` is a `DatagramProtocol`
  that multiplexes connections off one socket; reusing a single instance
  leaves the packet loop with nothing to dispatch to, and the symptom is
  a silent server whose port still appears in `netstat`.
- **aioquic client: `wait_connected=False` sends nothing.** `connect()`
  calls `protocol.connect(addr, transmit=wait_connected)`, so the
  probe never puts an Initial on the wire and can only time out.
- **Generate the WebTransport test certificate idempotently.** The
  browser only trusts it because it was added to the Windows store, so
  regenerating the key each run invalidates that trust instantly.
  `host/wt/make_cert.py` reuses an existing pair unless `--rotate`.
- **Serve `chain.pem` (leaf + CA), not a bare self-signed leaf.**

### Loop #33: aes128-ctr + hmac-sha2-256 (encrypt-and-MAC)

Reaching the encrypted session turned up four protocol facts that are all
easy to get wrong and all fail silently. Each was read out of the OpenSSH C
source rather than inferred from the RFC.

- **The block size for `aes128-ctr` is 16, not 8.** `cipher.c:93` lists
  `{ "aes128-ctr", 16, 16, 0, 0, 0, EVP_aes_128_ctr }` and the second column
  is `block_size`. So padding must make `4 + packet_length` a multiple of
  **16** — i.e. `packet_length ≡ 12 (mod 16)` — while the plaintext phase
  used `≡ 4 (mod 8)`. A hard-coded 8 leaves every post-NEWKEYS packet
  misaligned and the server answers `padding error: need N block 16 mod M`.
  This is why `block_size_of` is a function of the mode and not a constant.
- **`hmac-sha2-256` is a full 32-byte MAC.** `mac.c:62` sets
  `truncatebits = 0`. Plenty of implementations truncate to 16 by mistake
  (conflating it with `hmac-sha1-96`); that simply will not interoperate.
  paramiko agrees — `transport.py` `_mac_info` gives it `size: 32`.
- **The CTR counter is per-connection, not per-packet.** `cipher.c:280-281`
  calls `aesctr_ivsetup` once at NEWKEYS and then `aesctr_encrypt_bytes`
  advances it for the life of the connection. Re-seeding from the IV for
  every packet still produces a byte-correct *first* packet, so the bug only
  shows on packet 2 — which is exactly why the KAT cases emit several packets
  back to back.
- **Non-EtM MACs cover the *decrypted* packet.** `packet.c:1749-1754` passes
  `incoming_packet`, which by then holds the full `4 + packet_length` bytes
  (first block from `packet.c:1687`, remainder appended at `packet.c:1738`).
  The MAC is appended *after* the ciphertext. Verifying before decrypting, or
  over the ciphertext, both produce a stream that decrypts to garbage with no
  error anywhere near the cause.
- **`kex->we_need` is one length for all six keys.** `kex.c:1141-1152`
  computes `max(enc.key_len, enc.block_size, enc.iv_len, mac.key_len)` and
  `kex.c:1155` derives A..F all at that length. For aes128-ctr +
  hmac-sha2-256 that is **32**, not the cipher's 16. The cipher is then
  handed only the prefix it wants (`head_bytes(.., 16)`); passing the full
  32-byte key aborts in `AesCtrMacCtx::new`. This is *not* a bug in the
  pre-existing `derive_keys`, which was already faithful.
- **Strict KEX is off unless the peer advertises it** (`kex.c:963-970`), and
  our proposal does not advertise `kex-strict-c-v00@openssh.com`. So the
  sequence number runs straight through NEWKEYS instead of resetting to 0
  (`packet.c:1376-1379`). Advertising it would change the Loop #31/#32
  transcript and invalidate the 509/753 assertions, so it is a
  transcript-stability choice; `SendCtx`/`RecvCtx` handle either outcome.
- **Sequence numbers must be tracked even in the plaintext phase.** Loop #31's
  hand-rolled packet helpers had no seqnr accounting, which was invisible while
  everything was plaintext — but seqnr feeds the MAC. Driving the whole
  handshake through `SendCtx`/`RecvCtx` fixes it and leaves the wire bytes
  identical (509/753), verified.
- **Packet reads must be exact, never chunked.** Once a packet is consumed the
  next read is for the following message, so a chunked reader blocks waiting for
  bytes nobody asked for. Past NEWKEYS the length is itself ciphertext, so ask
  for it first: `RecvCtx::wire_len_from_header` decrypts the 4-byte header from
  a counter snapshot without mutating state, and the caller then pulls exactly
  `packlen + authlen + maclen` more.
- **`await` is not MoonBit syntax.** Async calls are plain calls; writing
  `await f(x)` gives "The value identifier await is unbound" plus a parse
  error, which reads like a missing import rather than a bad keyword.
- **MoonBit's `String` indexer yields `UInt16`, not `Char`.** A hex parser
  declared as `fn hex_nibble(c : Char)` fails to type-check against `s[i]`.
- **paramiko 5.x has no `Cipher` class** — the framing moved into
  `Packetizer`. `write_all` (packet.py:348-386) calls `socket.send` and its
  bare `except Exception: n = -1` turns a typo in a mock socket into an
  `EOFError` three frames away. `Packetizer._build_packet` uses
  `3 + bsize - ((len(payload) + 8) % bsize)`, which is algebraically identical
  to `SendCtx::emit`'s rule — useful to know, since it is the cross-check.
- **The handshake is not reproducible across connections.** The client pins its
  DH exponent and KEXINIT cookie, but the *server* draws a fresh one per
  connection, so K, the exchange hash and `session_id` differ between any two
  runs. Only framing-level facts (byte counts, block alignment, field shapes)
  are comparable between the native and browser paths — do not assert hash
  equality there.

Run the gate with `node host/verify_loop33.mjs` (`--skip-regression` to skip
the crypto suites). It checks the packet layer against
`host/ssh_ctrhmac_oracle.py` — which refuses to emit vectors until its own
from-spec construction matches paramiko byte for byte, so MoonBit is the third
opinion rather than the first — then drives the native client and the browser
Worker against a real OpenSSH 8.0p1 sshd and requires `SERVICE_ACCEPTED` from
both, with identical byte counts (509/753 for the handshake, 573/817 with the
encrypted exchange).

