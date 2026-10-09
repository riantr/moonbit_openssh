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

Above those sit the per-loop gates, which are what "done" means for a loop:

```
cmd/<name>_test/          ← KAT driver, runs on 4 target x 2 mode unless the
                            dependency graph forces otherwise (say so in the
                            package comment when it does)
host/gen_*_vectors.py     ← KAT generator. Vectors come from Python, never from
                            transcribing our own encoder, or the suite proves
                            nothing.
host/*_oracle.py          ← reference implementation; refuses to emit anything
                            until it agrees with a second one (paramiko /
                            cryptography / a published RFC vector)
host/verify_loopNN.mjs    ← the gate: oracle agreement, KAT, real sshd, browser
                            Worker, and the earlier loops re-run
```

A gate is worth more than its check count. The checks that keep earning their
keep are the ones that can fail for a reason nobody had already ruled out.

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

And one rule that the rest of this file keeps rediscovering the hard way:

> **A check that cannot fail is worse than no check.** Before believing any
> green line, ask what change would have turned it red. If nothing can, either
> delete it or fix the thing it was supposed to cover.

Three ways this repo got it wrong, all found by review rather than by a test:

- `moon test -p src/bpacket` — `-p` is not `moon test`'s package flag in this
  moon version (it takes a PATH), so it reported **0 tests**; and the assertion
  was written `passed === total && failed === '0'`, which `0/0` satisfies.
  The whole `src/bpacket` regression was therefore never running. Correct call:
  `moon test src/bpacket`, which immediately surfaced 13 real tests in
  `src/sha256`. A `total > 0` clause belongs in every such assertion.
- `check('counter continuity ...', text.includes('emit: PASS') && text.includes('wire:'))`
  — both conjuncts were already implied by the two checks above it. Rewritten
  to assert the *fixture* actually has multi-packet cases with pairwise-distinct
  packets, which is the precondition that makes the byte comparison a claim
  about counter continuity at all.
- A negative wire test whose *builder* used a different blob layout than the
  decoder under test: it kept passing, for the wrong reason.

### Build commands

```bash
# Loop #38: host key algorithms (ssh-ed25519 + RFC 8332 rsa-sha2-*).
# Starts its own sshd with NO HostKeyAlgorithms pin, plus one pinned instance
# per algorithm so each dispatch is proved separately.
node host/verify_loop38.mjs
node host/verify_loop38.mjs --skip-regression

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

### Loop #34: RFC 4252 section 7 publickey authentication

The client now proves who it is. A real OpenSSH 8.0p1 server looks the public
key up in `authorized_keys`, verifies the RFC 6979 ECDSA signature over the
RFC 4252 section 7 bytes, and answers `USERAUTH_SUCCESS` — first natively, then
from inside a browser Web Worker with zero native code and zero dependencies.

- **The ECDSA signature blob is two strings, not three fields:**

      string  key_type          "ecdsa-sha2-nistp256"
      string  signature_blob    (mpint r ‖ mpint s)

  This is the bug this loop spent most of its time on, and it is worth
  remembering because *every* local check passed while it was broken:
  `cryptography` verified the `(r, s)` over the exact bytes we sent, our own
  decoder round-tripped it, the KAT was generated from our own encoder and
  matched it, and the RFC 6979 values matched the published ones. Only a real
  server rejected it, with the least informative message in the protocol.

  The reason it hides so well is that an mpint's wire form *is* "length prefix
  + bytes". Drop the outer `string` and you still have `len ‖ r ‖ len ‖ s`, which
  a permissive reader will happily consume — just with the first 4 bytes
  swallowed as the length of `r`, and then no bytes left for `s`.

  Authority, in order of usefulness:
  - `ssh-ecdsa.c:431-432` — `sshbuf_get_cstring(b,&ktype) || sshbuf_froms(b,&sigbuf)`,
    then two `sshbuf_get_bignum2` reads out of `sigbuf`.
  - paramiko `ECDSAKey.sign_ssh_data` — `add_string(key_type)` then
    `add_string(self._sigencode(r, s))`, and `_sigencode` is the two mpints.
  - `src/hostkey/sig_verify.mbt:71-88`, which had it right all along because it
    verifies real host keys against a real server (Loop #31).

  **Lesson: when a blob layout is disputed, ask the implementation that has
  already been proven against a live server in this same repo, before adding
  another oracle.** `hostkey` was the answer and it was sitting one directory
  away.
- **`host/paramiko_blob_capture.py` is the tool that found it.** Patching
  paramiko's `AuthHandler._get_session_blob` dumps the bytes it *actually*
  signs. The first attempt patched `AuthHandler._finalize_pubkey_algorithm` and
  rebuilt the blob by hand — that produced a `pkblob` of 19 bytes (the key type
  only) and looked like a second, unrelated layout bug. A probe that reconstructs
  the blob instead of intercepting it will mislead you exactly when you can least
  afford it.
- **`ECDHSA_ERROR` never says which part was wrong.** OpenSSH's monitor path
  reports one line for both "that key is not in authorized_keys" and "that
  signature does not verify". `AuthError::AuthRejected` therefore carries the
  reason *plus* the signed bytes *plus* the signature, so a second implementation
  can replay the exact failure. Every hypothesis in the investigation below was
  ruled out by re-reading OpenSSH's C against our bytes — the only thing left was
  to compare against a working client.
- **The service name in `USERAUTH_REQUEST` is `ssh-connection`,** not
  `ssh-userauth` (the latter belongs to the preceding `SERVICE_REQUEST`).
  `auth2.c:302` takes it from the request itself, so the two are not
  interchangeable in any way that a live server will point at.
- **The public point Q is one SEC1 `string` (`0x04 ‖ X ‖ Y`),** not two
  coordinate strings and not an mpint. Getting this wrong produces a valid-looking
  key blob that no server will ever accept.
- **`cmd/userauth_test` depends on `src/userauth`, not `src/sshclient`.**
  `src/sshclient` reaches `src/tcp`, which is native-only, so a KAT built on it
  could only ever run on one backend. The section 7 assembly is pure byte work
  over `src/sshwire` and now runs on 4 target × 2 mode like everything else in
  this repo. The two five-line helpers it duplicates (`ascii`, `concat`) are the
  price of not dragging `@tcp` in — moving them into `src/sshwire` would touch
  every byte-exact baseline from Loops #31–#33 to save eight lines.
- **A negative wire test must build the blob in the layout you fixed.** When
  `decode_sig_blob` gained the wrapper, `build_sig` in `cmd/ecdsa_test` still
  produced three flat fields — so every "must be rejected" case kept passing, for
  the wrong reason: it failed at the parse layer, not on the defect it names.
  Silent, green, and worthless. `ecdsa_test`'s output hash moved with this fix
  (`0e3ec3f7e954bd98` → `d78cd820e9ea2317`); the harness re-baselined both
  `cmd/userauth_test`'s `mpint_pair_padded` parser and this one in the same commit.
- **P-256 r and s need a `0x00` sign pad about half the time.** The vector set
  covers 4 of 6 cases, and both sides must agree on the count — a suite that
  never exercises the pad tests only the easy half. Judge minimality by the
  rule, not by the first byte: a padded mpint *must* be followed by a byte with
  the high bit set.
- **A KAT generated from your own encoder cannot catch your own layout bug.**
  `verify_loop34.mjs` therefore re-derives the signed blob from the request
  actually put on the wire, exactly as `auth2-pubkey.c:207-213` rebuilds it, and
  compares byte for byte. That check is local, needs no server, and fails with a
  specific message — which is what turns the next occurrence of this bug class
  from a two-day investigation into a red line.

Run the gate with `node host/verify_loop34.mjs` (`--skip-regression` to skip the
Loop #32/#33 harnesses and the crypto baselines). It re-derives
`cmd/userauth_test/vectors.mbt` from `host/ecdsa_auth_oracle.py` and fails if the
committed copy has drifted, so the KAT cannot be satisfied by hand-editing it.

### Loop #33 review fixes

A review of Loop #33 turned up six items. Three were real defects, and the
other three were the same failure mode wearing different hats: a green check
that could not go red.

- **`recv_packet` collapsed every `PacketError` into `None`.** A MAC mismatch
  therefore looked identical to "the peer closed", so the only symptom on an
  encrypted channel was *waiting for SERVICE_ACCEPT and timing out* — a
  timeout that points at the wrong layer entirely. `recv_packet` and
  `wt_recv_plain_packet` now return `RecvOutcome { Packet, Closed, BadPacket }`
  and carry the `PacketError` label up through `LiveError::BadPacket(String)` /
  `SessionError::BadPacket` / `AuthError::BadPacket`. Both transports share the
  one enum and the one `packet_error_label`, so the browser path cannot invent a
  second name for the same fault.
- **`initial_kex` was never cleared.** `kex.c:567` does
  `kex->flags &= ~KEX_INITIAL` once the first key exchange is done; without it
  the flag stays true forever and every packet keeps evaluating a
  "is this wrap fatal?" branch whose answer stopped being right after NEWKEYS.
  Added `SendCtx/RecvCtx::end_initial_kex` + `in_initial_kex`, called right
  after `set_mode` in both paths, and `src/bpacket/packet_ctx_wbtest.mbt` pins
  the difference: same frame, `Failed(SeqnrWrapInitial)` before the call and a
  cleanly decoded packet after. Verified by mutation — making
  `end_initial_kex` a no-op turns 4 of the 25 tests red.
- **`key_head` printed key material.** It was the first 8 raw bytes of
  `enc_key_ctos` and the first 8 raw bytes of `mac_key_ctos`, hex-encoded —
  32 bytes of live session key into stdout and CI logs on every handshake,
  under a comment reading "does not print raw keys". Replaced with `key_tag`:
  `sha256(key)` truncated to 12 hex chars, `<enc>/<mac>`. Same diagnostic
  value (are the two directions different? did both paths derive the same
  keys?) with nothing recoverable. The harnesses now assert 12-hex halves and
  additionally check the two directions are *not* equal.
- **`head_bytes` / `hex_bytes_head` were duplicated** in `src/sshclient` and
  `src/wtlive`. They are now `pub` in `src/sshclient` and called from wtlive;
  a divergence in "how many leading bytes" would otherwise only bite the
  browser path, with the symptom "the server can't decrypt us".
- **`SentPacket.wire` documented only the AEAD shape** (`ct‖tag(16)`) and
  `emit`'s `pad_src` doc did not mention `MacEncrypt` at all. For the encrypt-
  and-MAC mode both are wrong in ways that read as plausible: the tag is 32
  bytes (`mac.c:62`, `truncatebits = 0` — and 16 is what chacha20-poly1305
  uses, so the wrong number looks right), and padding does come from `pad_src`
  even though the mode is not AEAD.
- **The counter-continuity check was tautological.** See the "cannot fail"
  rule above; it is now three checks, including that the vector set really
  contains multi-packet cases whose packets are pairwise distinct — without
  that, re-seeding the CTR counter per packet is byte-identical to correct
  behaviour on packet 1 and the whole property is untested.

Recomputed baselines: `src/bpacket/pkg.generated.mbti` catches up with Loop
#33's `AesCtrMacCtx` (it was stale because `moon info` aborts on three js-only
`cmd/wt_*` packages that report `Missing main function` under a native check —
generate it per package instead of project-wide).

### Loop #35: RFC 4254 connection layer (channels)

Loops #31-#34 proved we could open an encrypted session and say who we are.
Neither of them touched the connection layer, which is where SSH actually lives:
`ssh host cmd` opens a `session` channel, sends `exec`, and reads `CHANNEL_DATA`
until the peer sends `exit-status`. This loop does that against a real OpenSSH
8.0p1 server, natively and then inside a browser Web Worker.

**Where the protocol lives.** `src/channel` is a separate package with no
dependency on `src/sshwire` beyond the wire primitives and none at all on
`src/tcp`, for the same reason `src/userauth` was split out in Loop #34: a KAT
that can only run where a TCP stack exists is a quarter of the coverage this
repo insists on. Its core is `chan_step(state, msg_type, payload) ->
(new_state, actions, error?)` -- a pure state machine. The transport layers
(`src/sshclient/live.mbt` over TCP, `src/wtlive/live.mbt` over a WebSocket)
only move bytes. That is why "native and browser agree" does not rest on both
being written correctly: the protocol has exactly one implementation.

**Three bugs, all of the same shape.** Every one of them is locally
self-consistent, passes every check that does not require a big transfer or a
non-zero channel number, and is only visible to a real counterpart.

- `maybe_adjust` returned the **incoming** state on the no-adjust path, throwing
  away the window it had just decremented. `local_consumed` therefore never
  accumulated and not a single `WINDOW_ADJUST` was ever sent. Any output that
  fits in the 2 MiB window completes normally, which is every output anyone
  tries first. Found by replaying a 1.5 MiB transcript through the KAT.
- `maybe_adjust` read the amount off the window **after** `take_adjust` had zeroed
  `consumed`, so every `WINDOW_ADJUST` carried 0 bytes. The transfer still runs;
  the window simply never comes back.
- Inbound packets were matched against `remote_id`. RFC 4254 section 5.2 says the
  recipient field of an inbound packet names **our** channel. Both ids are 0 on a
  first channel, so this cannot be observed until a vector uses local=3 /
  remote=7. OpenSSH itself just resolves the id through `channel_by_id`
  (`channels.c:3474 channel_from_packet_id`) rather than committing to one side.

**Two deliberate divergences from OpenSSH**, both documented in place:

- `channel_input_extended_data` (`channels.c:3606`) does a bare
  `c->local_window -= data_len` and nothing else, while `channel_input_data`
  (`:3518-3523`) also does `c->local_consumed += win_len`. So in OpenSSH a peer
  that fills our window with nothing but stderr never gets a `WINDOW_ADJUST` and
  the transfer stalls. `chan_step` runs the same `consume()` on both streams: one
  extra `WINDOW_ADJUST` is always legal, a stall is not.
- A non-stderr extended-data code is dropped without touching window state,
  matching `channels.c:3585-3590`, which discards it before the string is even
  parsed.

**Oracle.** `host/channel_oracle.py` re-derives every value from the C
(`channels.h:231-232`, `channels.c:2440-2465`, `channels.c:3505-3523`,
`channels.c:3126-3135`, `session.c:2344-2347`) and cross-checks its
`CHANNEL_OPEN` / `exec` / `EOF` bytes against a **live paramiko session** before
emitting anything. That cross-check earned its place immediately: its
`CHANNEL_REQUEST` branch had been copy-pasted from the `CHANNEL_OPEN` branch and
parsed the recipient channel number as a string length, so every exec request
parsed to a zero-length request type and was silently skipped. "No disagreement
found" and "we never looked at the right packet" look identical from the outside.

`CHANNEL_EOF` is verified when paramiko emits it but not required -- paramiko
only sends it on the close path, and whether it appeared says nothing about our
layout. A check that goes red for unrelated timing reasons trains people to
ignore it.

**Mutation check.** `host/channel_mutations.py` puts each of the three bugs back
and requires `cmd/channel_test` to notice, then restores the file. A KAT that
stays green under the defects it was written for is not evidence of anything.

Run the gate with `node host/verify_loop35.mjs`. It re-derives
`cmd/channel_test/vectors.mbt` from the oracle and fails on drift, so the KAT
cannot be satisfied by hand-editing vectors; it runs the mutation check; it
compares six remote commands byte for byte against a local run of the same
programs; and it repeats all six inside a browser Web Worker.

One trap worth naming: the remote side is a Windows shell, so `echo` terminates
lines with CRLF. A hand-written `"hello\n"` reference is the wrong expectation and
sends you hunting a bug that is correct behaviour -- it did, once. The harness
reproduces every command locally instead of hard-coding expected bytes.

### Loop #36: interactive session (pty-req / shell / window-change)

Loop #35 ran commands over `exec`, the one-shot form of the connection layer.
An interactive shell is where the rest of RFC 4254 lives, and each piece has a
field that is wrong in a way the server tolerates:

- **`pty-req` puts columns before rows on the wire.** The client writes
  `sshpkt_put_u32(ws.ws_col)` first (`clientloop.c:2739`) and the server reads
  `sshpkt_get_u32(&s->col)` first (`session.c:1872`). Write them the other way
  round and you still get a perfectly valid pty with the dimensions transposed.
- **The terminal modes are wrapped in a `string`.** `ssh_tty_make_modes` does
  `sshbuf_put_u8(buf, TTY_OP_END)` then `sshpkt_put_stringb(ssh, buf)`
  (`ttymodes.c:331-332`), and `ssh_tty_parse_modes` opens with
  `sshpkt_get_string_direct` (`:352`). Leave the wrapper off and the server reads
  the four length bytes as an opcode -- and the pty still opens.
- **`TTY_OP_END` is 0** (`ttymodes.c:60`); `TTY_OP_ISPEED`/`TTY_OP_OSPEED` are
  128/129. paramiko sends an empty modes string, which is also legal
  (`ttymodes.c:354` returns early on `len == 0`) -- which is why the paramiko
  cross-check compares pty-req field by field rather than blob for blob.
- **`window-change` has `want_reply = FALSE` and no modes string.** The server
  reads four u32s and then `sshpkt_get_end` (`session.c:1847-1851`). Wait for a
  CHANNEL_SUCCESS there and you wait forever.
- **`exit-signal` is not `exit-status`.** When the process is killed the server
  sends `string name || boolean core || string language || string message`
  (RFC 4254 section 6.10). A client that only knows `exit-status` reports 255 with
  no explanation.

**A refused pty is not fatal.** OpenSSH clears `client_tty` and carries on
(`clientloop.c:2750`). `chan_step` therefore carries an `interactive` flag: in
that mode CHANNEL_FAILURE only increments a counter, while the `exec` path still
reports `ExecRejected`. The state machine does not track which request a reply
answers, so it cannot decide this -- and guessing wrong makes `ssh -T host`
unusable.

**Two bugs this loop's own tooling had, both from the same cause -- writing a
parser by copying a structurally different one:**

- The oracle's `exit-signal` transcript had a stray 8-byte blob between the
  language tag and the message. It had never been parsed by anything, because
  until now the client ignored `exit-signal` outright.
- The oracle read the signal name as a `u32`; it is a string, and reading the
  length prefix that way reported the signal as `"4"` for a request that said
  `"TERM"`. It also missed the `want_reply` byte, putting the length one byte
  late.

**One driver bug worth naming.** The first wait for CHANNEL_OPEN_CONFIRMATION
was written by reusing the helper that waits for CHANNEL_SUCCESS. The symptom is
not an error -- the server has already sent its confirmation and has nothing
more to say, and the read is blocking, so the client waits forever. Wrong wait
conditions in blocking code look like hangs, not like mistakes.

**Not claimed.** A pty banner from a Windows server carries the OS build number,
ANSI state and a prompt, so it is not reproducible byte for byte. G2/G3 check the
deterministic part -- the echoed command, the exit status, the byte counts, and
native-vs-browser equality -- while the bytes we *send* stay byte-exact against
the oracle and a live paramiko pty session. `host/channel_mutations.py` now
covers ten defects across both loops; every one of them turns the KAT red.

Run the gate with `node host/verify_loop36.mjs`.

### Loop #37: stdin flow control and the `env` request

Two RFC 4254 features every real `ssh` client uses and neither of the last two
loops touched. Both fail **silently**, which is the whole reason they need their
own loop:

- **Sending past the peer's window disconnects the connection** (RFC 4254
  section 5.2), but *under*-sending looks like success. The remote command still
  exits 0, the client still prints `EXEC_DONE`, and only the byte count
  disagrees.
- **`env` is never answered.** RFC 4254 section 6.4 says "No response is
  returned by the server", OpenSSH's client sends `channel_request_start(...,
  "env", 0)` (`clientloop.c:2706`), and paramiko's docstring calls the refusal
  "silent ... common client practice". Three sources agreeing means there is
  nothing on the wire to check -- the only oracle is the remote command looking
  at its own environment.

**The send-side clamp** (`channels.c:3085-3100`), transcribed exactly in shape:

```c
if (len > c->remote_window)     len = c->remote_window;
if (len > c->remote_maxpacket)  len = c->remote_maxpacket;
if (len == 0)                    return 0;
... send len bytes ...
sshbuf_consume(c->input, len);
c->remote_window -= len;
```

Clamp, not error. **A zero-length clamp is not a failure** -- it means the peer
has not made room yet, and the bytes stay in the buffer until a
CHANNEL_WINDOW_ADJUST arrives. `ChanState::stdin_take` returns the unsent tail
for exactly that reason. `stdin_action` is gone: one clamp, one place, and the
interactive shell path now goes through the same function instead of a second
encoding of the same rules.

**CHANNEL_EOF only after the buffer is empty.** `chan_ibuf_empty` returns
without sending when `sshbuf_len(c->input) != 0` (`nchan.c:130-134`). Sending it
early tells the peer the input is finished, and the remote command reads a
truncated stream *without complaining* -- harder to diagnose than a disconnect.
The `exec` path now sends EOF even with no stdin, which is what `ssh -n` does;
without it any command that reads stdin blocks forever, so the bug shows up as a
hang rather than as a wrong answer.

**`env` must go out before `exec`.** `session_input_channel_req` only dispatches
`"env"` while `c->type == SSH_CHANNEL_LARVAL` (`session.c:2175`); after `exec`
the request is dropped without a word, and want_reply is FALSE, so there is no
error either. Exactly two strings, then `sshpkt_get_end` (`session.c:2042-2044`)
-- a trailing field there is `sshpkt_fatal`, not something ignored.

**How the test proves it.** `sshd_setup.mjs` now names `LOOP37_TEST` and
`LOOP37_SECOND` in `AcceptEnv`, so one run covers both branches: the accepted
name arrives, the unlisted one is dropped, and the session completes either way.
For the bulk transfer the remote fixture reports the byte count *and* a SHA-256
of what landed, and `host/stdin_expect.py` computes that digest beforehand from
the same pattern the client uses -- so the comparison is between the far side and
an independent expectation, not between the client and itself. 3 MiB through the
2 MiB default window takes 96 packets and no disconnect.

**Two bugs found by the tooling, both worth naming:**

- `--exec` swallowed the rest of argv, so `--exec ... --env FOO=bar` handed the
  flags to the remote command. The remote ran fine and produced output; only the
  fact that the flags were also in the command string gave it away. Same class
  as the `--shell` bug in Loop #36.
- The KAT's stdin replay **rebuilt** the packets from the clamp, which was the
  point -- but it never checked the buffer that came back on the stall path, so
  the mutation "a stalled stdin went out in full" passed. The assertion that a
  `None` action returns the buffer untouched is now part of both replays.

**Mutation count:** sixteen across three loops, all caught.

Run the gate with `node host/verify_loop37.mjs`.

### Loop #38: real host key algorithms (`ssh-ed25519` + RFC 8332 RSA)

Thirty-seven loops of green, and the client could not talk to a stock
OpenSSH server. Not a subtle failure -- the handshake died outright:

```
client: NoAgreement
server: kex: host key algorithm: (no match)
        Unable to negotiate ... no matching host key type found.
        Their offer: ecdsa-sha2-nistp256,ecdsa-sha2-nistp384
```

The cause was a test fixture, not a protocol gap. `host/sshd_setup.mjs` pinned
`HostKeyAlgorithms` to ECDSA, and `live_proposal()` reported only ECDSA, so the
two always agreed. A server holding the ed25519 and RSA keys that a default
install actually has offered nothing we would accept. The pin made an
incomplete client look complete, and it took a *probe server with the pin
removed* to see it.

**The three names, which is the whole content of RFC 8332.** For RSA:

| what | value |
|---|---|
| the key blob's type string | `ssh-rsa` |
| the negotiated algorithm name | `rsa-sha2-512` |
| the algorithm name inside the signature blob | `rsa-sha2-512` |

All three are in play and the first two legitimately differ. Writing the check
by analogy with `ssh-ed25519` -- "the signature name must equal the key type" --
rejects every RFC 8332 signature, and rejects it as `TypeMismatch`, pointing at
a name that looks perfectly fine. The real test is what
`ssh-rsa.c:526-535` says: the two names must each resolve to a digest, and
**the digests must be equal**. So `src/hostkey` grew
`rsa_digest_of_sigtype` (`:328-338`) and `rsa_digest_of_keyname`
(`:345-359`) as two separate functions rather than one -- collapsing "signature
type" and "key type" into a single table is precisely the mistake RFC 8332
exists to correct.

`ssh-rsa` is deliberately **absent** from the proposal. It maps to SHA-1
(`ssh-rsa.c:331`), which this project does not implement, and OpenSSH 8.8+
disables it by default. Advertising a name we cannot verify would move the
failure from negotiation time to verify time and blame an algorithm that was
never selected. Loop #38's G4 asserts the good version of that: a SHA-1-only
server is refused with `NoAgreement`, not accepted and then failed at the
signature check.

**What else changed.** `src/rsa` takes a digest parameter instead of being
SHA-256-only, and `rsa_verify_pkcs1_prefix` now enforces `RSA_PKCS1_MIN_FF = 8`
(`RFC 8017` §9.2) -- it had been more permissive than OpenSSL. The rule for
left-padding a signature shorter than the modulus (`ssh-rsa.c:549-560`, because
`sshbuf_put_bignum2` strips leading zeros) is transcribed explicitly rather
than left to `RSA_verify`. `agrees_with_alg` and `describe` live in
`src/hostkey`, not in the two drivers: RSA's answer differs structurally from
ed25519's and ECDSA's, and two copies of that rule drift. `live_proposal()`
now reports `ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384`
-- and the client's order is the preference outright (`kex.c:887-890`
`match_list(client, server)`, the rule RFC 4253 §7.1 states).

**A framing detail that a spec reading would have gotten wrong.** The algorithm
name in a signature blob is a length-prefixed `string`, not a NUL-terminated
`cstring` -- OpenSSH's `sshbuf_get_cstring` reads a length-prefixed string and
strips a trailing NUL, and both spellings accept the same bytes. This was not
believed but measured: `host/hostkey_capture.py` interposes on a real
handshake and takes the bytes at the point paramiko is about to verify them.

```
0000000b "ssh-ed25519"  00000040 <64 bytes>
0000000c "rsa-sha2-512" 00000100 <256 bytes>
```

Three of the KAT's vectors are those captures -- bytes an actual sshd put on
the wire over an exchange hash it actually computed. The rest are paramiko
blobs, and every case expected to be `Accepted` is verified raw by
`cryptography` 50.0 before being written out, so the KAT cannot agree that
garbage is valid. Negative expectations are declared per *layer*
(`agree` / `rsa` / `crypto`), because pinning the wrong layer's answer is
worse than pinning none: it keeps passing while the layer that matters is
broken.

**Two bugs the tooling found, one of them a real implementation defect:**

- `rsa_parse_pkcs1_prefix` counted the `0x00` separator as a padding byte, so a
  signature with seven `0xFF` instead of eight was accepted. It was *more*
  permissive than OpenSSL, in the direction that only shows up against a
  deliberately malformed signature. The mutation "count the 0x00 separator as a
  padding byte, which the fix removed" is in the harness and reproduces it.
- The test harness's `waitForLog` read `proc.stdout.data` from a poll loop
  without attaching a `data` handler. Without one the stream stays paused and
  the buffer is never filled, so it timed out on a child that was printing
  exactly the marker it was waiting for. Worth naming because it presented as
  "the sshd did not start" and sent the investigation at the server.

`hostkey_test`'s `t5[5]` was also red before this loop and for an unrelated
reason: `ecdsa-sha2-nistp256` with a name and no fields expects
`UnsupportedType`, but `sshkey.c:2031-2046` looks the name up in the impl table
*before* it tries to parse, so `InvalidFormat` is correct. The test was wrong,
not the code.

**Removing the pin moved four earlier harnesses, and that is the point.**
`verify_loop31/32/33/34` had inherited the ECDSA default silently: loop31
asserts `hostkey_alg: ecdsa-sha2-nistp256` and hand-verifies the server's
ECDSA signature over the exchange hash, and loops 32/33/34 carry transcript
byte counts (`509/753`, `573/817`) that are the sizes of *that* handshake. With
the pin gone they negotiated ed25519 and every constant moved. Each of them now
passes `--hostkey-algs ecdsa-sha2-nistp256` explicitly, which restores exactly
what they were written to test. Relaxing them to accept any algorithm would
have been the tempting move and the wrong one: the constants would have had to
be deleted rather than corrected, and loop31's hand-verified ECDSA signature is
the whole subject of that loop.

`verify_loop31`'s `ecdsa_test` baseline had been stale since Loop #34 (`6f8271b`
changed both `cmd/ecdsa_test` and `src/ecdsa` to add the RFC 6979 user-key
vectors, after the hash was frozen in Loop #31). It was re-baselined, with the
cause named in a comment -- worth recording because it presented as an ECDSA
regression and no ECDSA code had moved.

**Harness:** `cmd/hostkey_test`, 39 vectors (8 key blobs, 16 signatures, 12
PKCS#1 shapes, 3 real captures), green on all four backends in both modes with
byte-identical output. `host/hostkey_mutations.py` carries fourteen
mutations, all caught -- one of them can only be caught as a crash, since
removing the longer-than-modulus check makes the left-pad offset negative and
panics before any verdict is compared. `host/sshd_setup.mjs` grew
`--hostkey-algs` and `--name` so several pinned instances can run at once; the
pin is a test lever again, not a default.

Run the gate with `node host/verify_loop38.mjs`.

