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

