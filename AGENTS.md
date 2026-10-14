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

### Loop #39: SFTP over a subsystem channel

`exec`, `pty-req`/`shell` and `window-change` all worked. `subsystem` -- the
third channel request type, and the one most deployments actually use -- did
not exist. The client could run a command, open a shell, and could not
transfer a file.

**The architectural decision, which is the reason this loop restructured
itself once.** The first draft put ~400 lines of SFTP in
`src/sshclient/sftp.mbt`. Adding the browser transport then meant writing the
same 400 lines again in `src/wtlive`, and a second copy of "when does a
READDIR end" is a second answer waiting to drift. So the protocol moved into
`src/sftp` as a transport-free state machine (`SftpSession`) and both drivers
became thin: ~120 lines each, and the only thing they are allowed to disagree
about is which function moves bytes.

The contract is four lines:

```moonbit
let s = SftpSession::new(ops)   // queues INIT
//   out = s.take_out()          // framed requests, for the channel
//   s.pump()                    // drain + advance
//   s.feed(channel_data_payload)// each inbound CHANNEL_DATA
// until s.done() or s.failed()
```

`pump` is called outside `feed` as well, on purpose: a reply may already be
sitting in the reassembly buffer while the socket has nothing left, and a
client that only pumps after a read ends up waiting forever for a packet it
already has.

**`subsystem` is want_reply=TRUE, and that is the whole point.**
`clientloop.c:2799-2811` sends it and then `client_expect_confirm(CONFIRM_CLOSE)`.
`env` is want_reply=FALSE and nothing ever answers it (RFC 4254 §6.4); the two
cannot share a rule. Waiting is what makes `ChanError::SubsystemRejected` /
`ExecError::SubsystemRejected` possible at all -- and it is deliberately *not*
folded into `ExecRejected`, because "there is no such subsystem" (usually a
typo: `sftp` vs `sftp-server`) and "the server refused this command" are
different diagnoses. `session.c:1945-1948` is the C that tells them apart.
Without the wait, a typo in `sshd_config` presents as "SFTP hangs after
connecting", which is the single most common SFTP deployment mistake.

**Two facts that only exist on the wire, and one of them nearly bit us.**

1. The reply numbers are `101 STATUS / 102 HANDLE / 103 DATA / 104 NAME /
   105 ATTRS`. The draft lists the *same five numbers sorted by name* --
   `101 DATA / 102 HANDLE / 103 NAME / 104 ATTRS / 105 STATUS` -- which reads
   naturally enough to be what an implementer writes from memory. A parser
   built on that ordering accepts every reply it is fed: a NAME reply parses
   as ATTRS, an ATTRS reply parses as NAME with a count of its first flag
   word. `host/sftp_capture.py` is what put the right order in the source, and
   `host/sftp_mutations.py` keeps it there by swapping the constants and
   requiring the KAT to go red.
2. `STATUS` carries a language tag after the message, so `expect_end` before
   reading it turns *every* STATUS into a parse failure -- including the
   `FX_EOF` that ends a read and the `SSH2_FX_NO_SUCH_FILE` a negative test
   expects. Same shape as VERSION's extension pairs: a parser that wants
   end-of-packet after the version number dies on the first byte a real
   server sends (six pairs on OpenSSH 8.0p1, more on newer ones -- so the
   count is *reported*, never asserted as a constant).

**End-of-read has two spellings.** A real server sends `STATUS(FX_EOF)`;
some send a zero-length `DATA`. Both are handled, and neither is confused with
a short chunk: a short chunk is NOT EOF, because treating one as EOF
truncates every file larger than a single read. The 200 KB fixture in the
gate exists for exactly this -- it takes many READs, many CHANNEL_DATA
packets, and at least one WINDOW_ADJUST back from the server.

**READDIR ends on `STATUS(FX_EOF)`, not on a short name list**, and the READ
offset accumulates over the whole file. Resetting it each round re-reads the
head of the file every time while the total length still looks plausible --
the worst kind of bug to find.

**The negative case is a status, not a transport error.**
`SSH2_FX_NO_SUCH_FILE` is a *successful* SFTP exchange: the request went out,
the server answered, the answer was code 2. `SftpOpResult::Failed(code, msg)`
carries it, so a routine negative test does not look like a broken client.

**Sizes are bounded before anything is sized from them.**
`SFTP_MAX_MSG_LENGTH` (256 KiB, `sftp-common.h:29`) is checked on the length
prefix itself, in the same order `sftp-client.c:195` does. A framing refusal
ends the session rather than only stopping packets from being handed out --
otherwise the driver waits for a reply that is never coming, and the symptom
is a hang rather than a refusal.

**The KAT has 14 session cases and 7 buffer cases.** All inbound bytes are a
real `internal-sftp` capture, with exactly one rewrite: the 4-byte request
id, because ids are client-chosen and pinning our numbering to paramiko's
would test the wrong thing. Two cases (`two_packets_one_feed`,
`second_packet_only_after_another_feed`) live at the `SftpInbuf` level rather
than the session level, because with one outstanding request there is no
causally possible session in which two replies arrive together -- writing it
as a session case would have demanded that the client ignore a reply it never
asked for.

19 mutations, all caught. `host/verify_loop39.mjs`: KAT on 4 backends x 2
modes byte-identical, the capture replayed, the mutations, a real
`internal-sftp` (realpath / listdir / read 11 B / read 200 KB / missing file),
the refused subsystem, and the browser Worker.

Run the gate with `node host/verify_loop39.mjs`.

Note: the Worker section skips with a message if Playwright's Chromium was
never downloaded (`npx playwright install chromium`). It is a *skip*, printed
in the summary -- silently reporting the browser path as verified is the one
outcome worse than a failure.

### Loop #40: the SFTP write side

Loop #39 could read. It could not write, which for an SFTP client is roughly
half the protocol -- a tool that only downloads is a different tool from one
that syncs.

**No new architecture.** Everything went into the existing `src/sftp` state
machine, because the split Loop #39 paid for is exactly the split this side
needs: `WRITE` / `SETSTAT` / `FSETSTAT` / `MKDIR` / `REMOVE` / `RMDIR` /
`RENAME` / `EXTENDED` are protocol, not transport, and `src/sshclient` and
`src/wtlive` stayed thin. `Rename` checks
`SftpSession::has_extension("posix-rename@openssh.com")` rather than counting
extensions, because the count is a property of the server and has no mapping to
"which capabilities".

**The offset is the whole loop.** `process_write` does
`lseek(fd, off, SEEK_SET)` before every write (`sftp-server.c:865-866`), so a
wrong offset is *not* a rejected request -- the server writes the bytes
somewhere else and answers `STATUS(OK)`. The file ends up with a plausible
length and the wrong contents, and every status code on the wire says it
worked. `written` is therefore a file offset advanced as each WRITE is
**queued**, not when it is acknowledged; waiting for the STATUS looks more
cautious and is not, because it re-sends the same chunk at the same offset
forever. The capture shows paramiko's offsets walking `0, 8192, 16384, ...`
and then **returning to 0** for the second file -- offsets are per file, so a
session-global counter is also wrong.

**Three things the C does not say, and the capture did.**

1. `FXP_RENAME` and `posix-rename@openssh.com` are different requests. The
   draft's RENAME is specified to fail when the target exists; the extension is
   `rename(2)` and replaces it. Confirmed against a target that was known to
   exist.
2. An unknown extension name is a clean `STATUS(SSH2_FX_OP_UNSUPPORTED=8)`,
   not a dropped channel. A client that treats it as fatal hangs against any
   server lacking the extension.
3. `SSH2_FXP_REMOVE` is 13 and `SSH2_FXP_RMDIR` is 15. Adjacent, and swapping
   them still produces a well-formed packet the server simply refuses.

**An empty payload sends zero WRITE requests**, not one empty WRITE. `TRUNC`
has already destroyed the old contents, and an empty WRITE comes back
`STATUS(OK)` -- so "create an empty file" and "write a file" would be
indistinguishable on the wire. A WRITE that *fails* still sends CLOSE: the OPEN
succeeded, so the server is holding a descriptor.

**Three bugs the KAT caught, all of them in code that looked finished.**

- `SftpVersionReply` gained `ext_names`, the field was added to the session --
  and nothing ever assigned it. Every `Rename` therefore took the v3 path and
  could not overwrite. It compiled, and it was wrong in the one way that only
  shows up against a real file.
- `send_write` never advanced `written`, so every chunk re-wrote offset 0.
- The driver grouped operations by flag rather than by command-line order, so
  `--sftp-mkdir d --sftp-write d/f` sent the write first. The comment above
  that code said "in command-line order" -- a comment/behavior split is worse
  than either one alone, because it makes the wrong order look intentional.
  `--sftp` now builds the op list while scanning argv.

**`--sftp-write` takes `<path>@<size>`, not two argv slots.** The port in this
driver is a *bare numeric* argument and `find_port` scans for the first thing
that parses as one, so a size in its own slot became the port and the run
reported `CONNECT_FAILED` -- which reads as a broken client. `@` rather than
`:` because Windows paths already contain colons.

**Two harness defects that made Loop #39's browser section vacuous.** It never
ran: the gate hung first (see below), and when forced through, G5 pointed the
Worker at a WebSocket port with **no relay behind it**. The Worker started,
never connected, and the symptom was a browser-shaped failure. `verify_loop39.mjs`
now starts `host/wt/ws_relay.py` like loop38 does; with that fixed, the browser
read path works too, and Loop #40's Worker writes 40000 bytes and reads the
same digest back as the native path.

**`startSshd` must not use `spawnSync`.** `sshd_setup.mjs` runs `sshd -D` in the
foreground and ends with `await new Promise(() => {})`, so it never returns.
`spawnSync` waits for that forever: the gate sat with no output and zero CPU
for 27 minutes, which looks like a slow run rather than a dead one. Async
`spawn` plus a port probe is the fix, and the probe is not optional either --
a fixed sleep is what made the sshd miss its window after the mutation pass
warmed `_build` back up cold.

**Windows has no POSIX permissions**, so `chmod` is recorded but never asserted
there: the capture shows mode `0o607` after a `chmod 0640`. Asserting it would
be theatre. Times *do* round-trip (`1700000000` / `1700000123`) and are.

**Verification.** 24 session cases + 7 buffer cases, 4 backends x 2 modes,
byte-identical. 30 mutations, all caught (11 new). The live run creates a
directory, writes 40000 bytes across several WRITEs, reads them back and
compares the SHA-256 against the same bytes computed independently in the gate,
renames, then **overwrites the renamed file through the extension and reads
that back** -- 11 bytes where 40000 used to be, which is what makes "accepted"
mean something. The Worker's 40000-byte digest matches the native one, which is
what the duplicated three-line payload rule is for: a Worker has no filesystem,
so the rule is repeated and the digest is the thing that would catch a drift.

### Build commands

```bash
# Loop #40: the SFTP write side (WRITE / SETSTAT / MKDIR / REMOVE / RMDIR /
# RENAME + posix-rename@openssh.com).  Starts its own sshd (18783), recaptures
# the write session, replays both KATs on 4 backends x 2 modes, runs the 30
# mutations, then drives the write script natively and in a Worker against the
# real server -- including the overwrite, which is proved by reading the
# replaced file back.
node host/verify_loop40.mjs
node host/verify_loop40.mjs --skip-regression

# Loop #39: SFTP over a subsystem channel. Starts its own sshd (18781),
# replays a captured internal-sftp through cmd/sftp_test on 4 backends x 2
# modes, runs the 19 mutations, then the same script natively and in a Worker
# against the real server
node host/verify_loop39.mjs

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

**Two lessons from Loop #39, both of which cost a red regression run.**

Adding a constructor to `ChanError` (`SubsystemRejected`) turned loop35, loop36
and loop37 red at once, with no change to any of their code. MoonBit treats a
non-exhaustive `match` on an enum as an error, which is the *right* default,
but the blast radius is every `describe(e : ChanError)`-style helper across
`cmd/` and `src/` -- five files, not one. When a loop adds a variant to a
shared error enum, grep for the enum name and fix every match in the same
commit; the regression suite is what found it, and it found it all three times
in a row, which is exactly as noisy as it is useful.

The second is quieter. `host/channel_mutations.py` anchors each mutation on a
literal source snippet, and this loop's edit to the 0x64 branch turned
`      if st.interactive {` into `  } else if st.interactive {` -- so one
mutation became a silent `SKIP` and loop35/36/37 all reported
`all mutations turn the KAT red` as failed while the KAT itself was perfectly
green. A mutation harness treats "the anchor is not where I left it" as a
failure, not a warning, and that is the right default: an anchor that moved
means either the code changed (so the mutation no longer describes anything)
or the harness went stale (so it is not testing what it claims). Either way
there is no reading of it under which it should be quietly skipped.

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

### Loop #41: Proton desktop shell (debug console, milestone 1)

`proton@0.3.4` is the GUI framework for a **manual fault-injection console**:
commands that drive `src/sftp`'s `SftpSession` directly -- malformed WRITEs,
wrong request ids, EXTENDED names no server has -- the branches a KAT against
a real well-behaved server never reaches. Not an SFTP file browser: the
browser-Worker gate already proves that path, and a second front end would
prove it again with more code.

**The boundary that keeps it safe: `src/` never imports `@proton`.** Only
`cmd/proton_gui` does. Proton is native-only (`supported-targets: "+native"`,
six packages in lockstep at 0.3.4), and a 0.x GUI framework must not become a
dependency of the 4-target KAT gates. The compiler enforces half of this
itself -- it warns when a package depends on Proton without declaring
`supported_targets` explicitly, which `cmd/proton_gui/moon.pkg` now does.

**The three prerequisites were already on the machine** (installed by the
`moonbit_static_analysis` project): `proton_cli 0.3.4` on PATH, the CEF
runtime in `~/.proton/store/win32-x64/cef-<sha256>-layout-1/`, and the
version-locked `cef_process.exe` helper in `~/.proton/helpers/win32-x64/0.3.4/`.
What was missing was only `moon add moonbit-community/proton@0.3.4` and the
runtime layout beside the built executable.

**What the executable wants at run time, relative to itself** -- derived from
the runtime's own error messages, which name each missing path in turn; this
is the complete list it asks for:

- the CEF **Release** set (`libcef.dll`, `chrome_elf.dll`, `libEGL.dll`,
  `libGLESv2.dll`, `d3dcompiler_47.dll`, `dxcompiler.dll`, `dxil.dll`,
  `vk_swiftshader.dll`, `vulkan-1.dll`, `icudtl.dat`, `resources.pak`,
  `chrome_100_percent.pak`, `chrome_200_percent.pak`,
  `v8_context_snapshot.bin`, `vk_swiftshader_icd.json`) in the exe's own
  directory. **Not `bin\`**: the first run put them in `bin\` because the
  runtime's earlier error text names `bin\libcef.dll`, and the result was
  `0xC0000135` (STATUS_DLL_NOT_FOUND) before `main()` -- the Windows loader
  resolves the import table before any MoonBit code runs, the exe's own
  directory is on the default search path and a `bin\` subdirectory is not,
  and the runtime's `bin\` convention is only its *later* check. The loader's
  rule wins.
- `cef_process.exe` (the subprocess helper, version-locked to the proton
  release) beside the exe.
- `Resources/` (the CEF pak/icu tree) beside the exe.

`host/proton_stage.mjs` does all three from the store, reading the CEF
archive's sha256 from
`.mooncakes/moonbit-community/proton/cef_requirements.generated.mjs` rather
than hard-coding it, so a proton bump takes the script along. Run it after
every `moon build` that removed `_build`:

```
node host/proton_stage.mjs
$env:PROTON_HEADLESS = "1"; _build\native\debug\build\cmd\proton_gui\proton_gui.exe   # smoke, no window
_build\native\debug\build\cmd\proton_gui\proton_gui.exe                               # the window
```

**Verified:** milestone 1 -- window opens (headless run stays alive consuming
CPU through the event loop; visible run opens the window). The 5-step
third-party check ran clean: `.mooncakes` populated, `moon tree` shows all six
packages at 0.3.4, and `src/sftp` checks green on all four targets with the KAT
still passing -- the native-only dependency pollutes nothing.

**Milestone 2 (done):** the command bridge. See below.

### Loop #41-M2: the fault-injection console

Milestone 1 proved a window opens. Milestone 2 gives it something to do: three
application commands bound through `.commands(...)` / `CommandRegistrar::bind`,
each driving `src/sftp`'s `SftpSession` over replies a well-behaved
`internal-sftp` never sends.

**Why a GUI and not another `cmd/sftp_test` case.** The Loop #39 KAT and the
Loop #40 live round trip both prove the happy path against real OpenSSH bytes.
Neither can reach "STATUS before VERSION", "a reply carrying someone else's
request id", "a length prefix over `SFTP_MAX_MSG_LENGTH`", or "an extension
advertised and then refused" -- OpenSSH does not emit those, so no capture
contains them. A fault injector is the only way to hold those branches, and
holding a branch by hand is a console's job. The console is a third *driver*
of the one `src/sftp` implementation, not a second implementation: no byte
assembly of its own, no parse rules of its own.

**The three commands** (`cmd/proton_gui/main.mbt`), each named by
`@proton_contract.command(...)`, each reachable as
`window.__MoonBit__.app.<name>(payload)`:

- `sftp_fault_list` -- the catalogue the page renders its buttons from
- `sftp_fault_run`  -- one scenario, full transcript
- `sftp_fault_all`  -- the whole suite verdict

**The signatures came from `pkg.generated.mbti`, never the README**, same rule
as every other third-party surface here:

```
pub fn[Request, Response] command(String) -> Command[Request, Response]
pub fn[Request : @json.FromJson, Response : ToJson]
    CommandRegistrar::bind(Self, Command[Request, Response],
        async (CommandContext, Request) -> Response) -> Unit raise
```

So a request type derives `FromJson`, a response type derives `ToJson`, and the
handler is `async` and takes the request context first. `moon check` reports
`unused_async` on all three handlers (none awaits; MoonBit would promote a
plain `fn` implicitly) -- the annotation is kept so the declared type still
says what the registrar asks for, with the reasoning in a comment at the
definitions.

**The transport name is derived, never written down.** An application route is
`app:<name>` (`ContractRoute::operation_name`), and the injected bridge
(`bridge_bootstrap.js`) exposes one property per granted op as
`__MoonBit__.app.<name>` -- so neither side assembles the string by hand.

**Ten scenarios, each aimed at a named branch of `src/sftp/session.mbt`:**
STATUS-before-VERSION ignored; wrong request id dropped, session still usable;
DATA where a WRITE expects STATUS (unexpected, handle still closed); EOF as a
WRITE answer (failure, never success); EXTENDED-vs-RENAME chosen by extension
*name* with six extensions advertised and the rename one absent; EXTENDED sent
when it *is* advertised; advertised-then-refused = `OP_UNSUPPORTED` result not a
dead session; over-max length prefix refused before anything is sized from it;
truncated ATTRS fatal; STATUS trailing byte fatal.

**The expectations come from a second implementation.**
`host/sftp_fault_oracle.py` is an independent SFTP client written from the draft
and OpenSSH's error branches with no reference to `src/sftp`. It refuses to
emit the vectors unless its own run of each scenario agrees with a hand-written
expectation. `host/gen_fault_vectors.py` transcribes that JSON into
`cmd/proton_gui/fault_vectors.mbt` (a generated file). This is the repo's
multiple-blind rule applied to fault injection: without it a scenario passes
the moment it agrees with itself.

**The blind check immediately paid for itself:** the oracle's first draft
called an over-max length prefix `framing: BadLength`; `src/sftp` reports
`framing: Unexpected`. The oracle was wrong -- in `src/sftp` `BadLength` is the
*cursor's* "a length field pointed past the end of the buffer" (`proto.mbt`),
a different failure with a different cause, while the framing check rejects a
length that is out of range before any buffer is sized from it. The oracle was
corrected and the distinction documented at both sites.

**The gate drives the real bridge, not the functions.**
`node host/verify_loop41.mjs` runs the oracle, builds, stages CEF, then opens a
**real window** with a CDP endpoint and evaluates
`window.__MoonBit__.app.sftp_fault_all({})` and
`...sftp_fault_run({name: ...})` *in the page*. Calling the MoonBit handler
directly would prove the scenarios and prove nothing about the bridge. The
two environment variables are the ones the source actually reads
(`facade_manifest.mbt`): `PROTON_MODE=dev` (which is what turns debug on) and
`PROTON_REMOTE_DEBUGGING_PORT` -- the port alone is not enough, because
`resolve_remote_debugging` returns Disabled unless debug > 0.

**Verified:** `ALL PASS (22 checks)` -- oracle self-consistency, build+stage,
CDP attach to the real document, `core.invokeOp` present, three granted ops,
both command shapes round-tripping JSON, and all ten scenarios byte-identical
to the oracle (requests, results, done/failed/reason). The extension *names*
are asserted, not just the count, since the names are what decide EXTENDED vs
RENAME.

**Three harness lessons from building it, all "impossible" verdicts:**

1. **`{}` not `null` for a fieldless request.** The registry decodes the
   payload with `@json.from_json(payload_json)` straight into the Request type
   (`core/op_registry.mbt`), and `EmptyRequest` is a fieldless *struct* -- it
   wants an object. `null` is valid JSON and still fails the struct decode, so
   the bridge reported "invalid payload for op app:sftp_fault_all". The page
   and the gate now send `{}`.

2. **Do not filter the CDP target by a guessed URL.** Two versions of the
   readiness check failed as a *timeout*, not as a wrong answer: one attached
   to CEF's `about:blank` placeholder (the bootstrap only runs on the real
   document, so there is no bridge on it), the next matched
   `url.startsWith("proton")` -- and the real URL is `https://proton.localhost/`.
   The wait condition is now the actual precondition: "a page where
   `__MoonBit__` exists and all three ops are functions".

3. **Compare rendered-to-rendered.** The JSON holds a result as a raw tuple
   (`["realpath", "/C:/Users/hp"]`); the bridge returns the rendered form
   `cmd/sftp_test` prints. Comparing them directly produced seven failures
   that looked like protocol disagreements -- `["changed"]` versus `["changed"]`
   is the same answer in two shapes. The gate now renders the JSON with the
   same rules, and -- because that makes a second port of one rule set, which
   is how ports drift -- cross-checks the port against the *generated*
   `fault_vectors.mbt`, so the duplication is an assertion rather than a fork.

5-step third-party check after adding `moonbit-community/proton_contract`:
`.mooncakes` populated; `moon tree` shows it at 0.3.4 in lockstep with the
other five; **`moon.mod` needed the direct edge** -- "the module is in the
global environment" is not "this module may import it", and moon says so
explicitly; `src/sftp` checks green on all four targets; the KAT still prints
`ALL PASS (24 session cases, 7 inbuf cases)`.

### Loop #59: the client dials what the config says, and pins under the name the user typed

Loop #58 made `cmd/ssh_live` *print* its resolved connection parameters and
checked those against `ssh -G`. Printing the right thing and connecting to the
right thing are different claims, and only the first one had been proven. A
`HostName` that resolves correctly in the dump while the socket still goes to
`127.0.0.1` would have passed every check in Loop #58.

So this loop runs the client against a real SSH peer -- `host/sftp_mitm.py`, the
one Loop #54 uses -- with **no port argument at all**. If it authenticates, the
host and the port came out of the config file, because there is nowhere else for
them to have come from.

#### `HostName` decides where to connect. It does not decide what to pin under.

This was the one thing worth getting right, and it is worth stating because the
wrong answer is invisible. `add_host_to_hostfile(filename, host, key, store_hash)`
takes exactly **one** host, and `write_host_entry(f, host, NULL, ...)` passes
`ip = NULL` (hostfile.c:542 / :476) -- `HostName` never enters the key. Pinning
under the resolved name means the next connection *by alias* looks up a name that
is not in the file, so every connection looks like a first connection and TOFU
fires forever. That failure never errors; it just never remembers.

`--kh-host` therefore now defaults to `--target`, not to a hardcoded `127.0.0.1`.
The gate asserts the *absence* of a `127.0.0.1` line, not just the presence of
the alias line, because a client that wrote both would pass the first check.

#### The `find_user` re-parse that Loop #54 had already declared dead

`run_exec` and `run_shell` each called `find_user(@env.args())` themselves. That
is precisely the "both sides ask the question separately" drift Loop #54 removed
from the known_hosts path -- and it had a consequence Loop #58 could not see:
the user resolved from the config never reached either function. `main` now
computes the user once, alongside host and port, and passes it down; both
functions lost their private `argv` re-parse.

Six `TcpConn::connect("127.0.0.1", port)` call sites became
`connect(host, port)`. Loop #54's own precedent is "they just take one more
parameter", so this is threading rather than a refactor into a session struct.

#### What step 1 does **not** prove

The fixture's `HostName` is `127.0.0.1` and the client's fallback is also
`127.0.0.1`, so step 1 cannot distinguish "dialed the configured host" from
"dialed the default". The **port** is what proves the config drove the dial: it
is absent from argv entirely. The host half is covered by `--config-effective`
against `ssh -G` (Loop #58), and the alias-keying rule is covered by mutation A.
A hostname that resolves differently from `127.0.0.1` would have made the check
*look* stronger than it is; it is written down instead.

#### A gate defect worth the two runs it cost

The known_hosts checks first spelled the key type as `ssh-`. The peer presents
`ecdsa-sha2-nistp256`, so:

- "pin is keyed by the alias" **failed against a correct file**, and
- "pin is NOT keyed by the resolved HostName" **passed vacuously**.

A regex that never matches anything is indistinguishable from a regex proving an
absence, so the second check was decoration that read as evidence. Both now match
`\S+`. The gate also dumps the file's contents on failure -- Loop #40's rule that
the failure and its evidence land together -- because "no line keyed by
loop59-pin" costs a re-run with a debug print to diagnose, and there were three
plausible explanations.

#### Mutations: 3 CAUGHT, 1 EQUIVALENT

| | mutation | caught by |
|---|---|---|
| A | pin keyed by the resolved `HostName` | both keying checks, with the file dumped |
| B | the port from the config is ignored | step 1 cannot connect |
| C | the user from the config is ignored | step 1's reported user |
| D | gate stops checking `--proposal` | EQUIVALENT |

#### Process discipline

Loop #53's rule, kept because it is the reason a failure stays a failure: the
peers are killed and `.loop59` removed in a `finally`, so a failure part-way
through cannot leave a peer listening that the *next* gate connects to.

### Loop #58: ssh_config on the client's path, and the rule that decides whether it is usable

Loop #57 ended with `src/sshconfig` proven correct against `ssh -G` and still
called by nothing. That is not a resting state. It is the exact condition the
first-block-only bug survived in for thirty loops: correct-looking code with no
caller rots the way wrong code does, because nothing ever exercises it.

So this loop wires it into `cmd/ssh_live` and checks the thing that decides
whether the feature is worth having at all -- **precedence**.

#### The rule

OpenSSH takes the first value obtained for each keyword, and the command line is
read before any file:

```
--user / -o Key=Value   >   the config file   >   the client's built-in default
```

Checked, not assumed: `ssh -G -F fallback.conf -o User=cliu -o Port=2200 web1`
answers `user cliu`, `port 2200` -- the command line wins over a file that sets
both, and also over a file that sets neither.

If the file were consulted only when the caller said nothing, then anyone with a
config file could never override it from the command line, which is the everyday
case. That is why `-o` is here rather than deferred.

**The whole chain is computed once, in `cfg_resolve`.** `--proposal` already
existed for the same reason (Loop #38): "the connection succeeded" does not show
*which* configuration was used, so there has to be an offline path that prints the
answer. `--config-effective` is that path, and it returns before anything dials.

The `--user` step is asserted **against the client's own rule, not against
`ssh -G`**, because `ssh -G` has no `--user`. It is labelled as such in the gate
output so nobody later reads it as a cross-check. That gap was in the first draft
of this loop: `--config-effective` originally showed only `-o` and the file, so
the top of the chain was claimed but unobservable.

#### Two rules again, and the second is still the one that matters

1. **VALUE** -- every keyword the client resolved must equal `ssh -G`'s answer.
2. **COMPLETENESS** -- every keyword the config or the overrides *moved* must be
   resolved. The moved set comes from diffing `ssh -G` with and without the
   fixture, so OpenSSH decides what counts as changed.

Rule 1 alone passes a client that resolves nothing. Mutation B (ignore `--config`
entirely) is caught **only** by rule 2:

```
FAIL  case cascade.conf db1.prod.example.com answers everything the config changes
      not resolved: hostname, user, port, identityfile
```

`ssh -G` also prints every compiled-in default, so comparing all four keywords
unconditionally would be asking the client to invent `port 22` and seven default
`IdentityFile` paths. The first draft of the gate did exactly that and produced
six confident, wrong failures.

#### `IdentityFile` ordering

`-o IdentityFile=` is the first value obtained, and `IdentityFile` accumulates, so
the override **precedes** the file's entries rather than replacing the list. The
gate compares the ordered `|`-joined list for this reason: mutation C produces
the same *set* in the wrong order, and a membership check would have called that
correct.

#### `find_port` learned about arguments that take a value

`find_port` scans argv for the first all-digits token. `--target 2222` and
`-o Port=2220` put a digits-only string in argv for a reason unrelated to the
port, and the scan would happily dial the wrong one. It now skips the token after
`--target`, `-o` and `-F`. This was not a bug before this loop -- there were no
such arguments -- and it would have become one the moment the feature landed.

**Nothing moves without `--config`.** Every `ConnConfig` field is empty unless a
file was given, and `main` substitutes only non-empty ones. Every existing gate
passes no `--config` and dials `127.0.0.1:22222`, so none of them can have moved;
`--proposal` is asserted byte-identical in the gate as the concrete form of that
claim.

#### Mutations: 4 CAUGHT, 1 EQUIVALENT

| | mutation | caught by |
|---|---|---|
| A | `-o` loses to the file | value rule (4 cases) |
| B | `--config` ignored entirely | **completeness rule only** |
| C | `-o IdentityFile` appended last | value rule, by ordering |
| D | `--user` loses to `-o` | the `--user` assertion |
| F | gate stops checking the no-config run | EQUIVALENT |

C was first written as "replace the list" and was caught by a **compile error**,
not by an assertion -- `Array::remove_at` does not exist in this MoonBit version.
A mutation caught by a broken compiler is not evidence, so it was rewritten as an
append-last mutation that compiles, and the CAUGHT it produces is the ordered
comparison doing its job.

#### Still not done

`cmd/ssh_live` dials `127.0.0.1:22222` by construction; it is a test client
against a local sshd, not a general SSH CLI. `HostName`/`User`/`Port`/`IdentityFile`
are now resolved and printable, but the resolved `hostname` is **not** yet the
dial target -- wiring that means this client stops being a fixed-target harness,
which is a larger change than a config flag and is left for its own loop.
`Match`, `Include` and quoting remain unimplemented, as in Loop #57.

### Loop #57: ssh_config resolution, diffed against OpenSSH's own `ssh -G`

This loop did not start by auditing `ssh_config`. It started by measuring which
`src/` packages have **no production importer** -- after Loop #56 left a survey
script behind. Four qualify: `kex_names`, `sshconfig`, `test_nested`, `wt_socket`.

**The survey's first answer was wrong, and that mattered.** The first run counted
another `src/` package as a *test* reference rather than a library reference, and
reported seven "dead" packages including `aes`, `bpacket`, `sha512` and
`kexc25519`. All four are live -- `src/kexflow/moon.pkg` imports `kexc25519`.
Building a loop on that number would have been building on a miscount. The lesson
is the one Loop #40 already wrote down about nested gates: a classifier that is
silently wrong is worse than no classifier, because it produces a confident
number.

#### What was actually wrong

`src/sshconfig` is not merely unused. `match_host_option` **searched only the
first matching `Host` block**:

```
Host web1
  User deploy
Host *
  Port 2222
```

`ssh -G web1` answers `user deploy` **and** `port 2222`. The old code answered
`deploy` and, for `Port`, "no such option". `Host *` at the end of a file is the
single most common thing in every `~/.ssh/config` on earth. It was never noticed
because nothing called it -- and because its only test checked a config where the
keyword happened to be in the first matching block.

Three more parser bugs fell out of checking against the authority rather than the
spec: options **before** the first `Host` were accumulated into a pattern-less
section and then **dropped**; `Keyword=Value` became a keyword literally named
`Port=2202`; and a trailing `# comment` stayed in the value.

#### The rules, each confirmed before it was written down

Nothing here was written from memory. Every line was settled by running
`ssh -G` on OpenSSH_for_Windows_9.5p2:

1. **All** matching `Host` blocks participate, in file order -- not just the first.
2. Single-valued keywords keep the **first** value obtained.
3. Multi-valued keywords **accumulate**. `IdentityFile` is one: two matching
   `Host x` blocks both survive. This is why arity is per-keyword. A resolver that
   treats everything as first-wins silently drops a key; one that treats
   everything as accumulate turns `User` into a list. Both fail quietly.
4. Options before the first `Host` apply unconditionally, and win over the rest.
5. One match on a `!` pattern discards **the whole block**, positive patterns
   included. It is not "that one pattern is skipped".
6. Keywords are case-insensitive (`readconf.c` uses `strcasecmp`).
7. `Host` patterns are matched case-**sensitively**. `ssh_config(5)` is ambiguous
   here, so it was checked rather than assumed: `Host Web1` does not match `web1`.

The last two are the kind of pair that is easy to get backwards and impossible to
guess from the prose, which is the argument for having an executable authority.

#### The gate: two rules, and the second is the one that matters

`host/verify_loop57.mjs`, 21 checks, two-sided on purpose. Loop #55 needed three
sides because its authority was a published constant two implementations could
both misread. Here the authority **executes**, so a third leg could only agree
with one of the two.

1. **VALUE** -- every keyword MoonBit resolves must equal `ssh -G`'s answer.
2. **COMPLETENESS** -- every keyword where the fixture *changed* OpenSSH's answer
   relative to an empty config must be resolved by MoonBit too.

Rule 1 alone passes a resolver that silently drops half the file, because a
resolver that answers nothing has no wrong answers. Rule 2 is what turns "I found
User" into "I found Port too, two blocks down". Mutation A restores the original
bug and is caught **only** by rule 2:

```
FAIL  case fallback.conf web1 answers every keyword the fixture changes
      not resolved: port, serveraliveinterval
```

The changed-keyword set comes from diffing `ssh -G -F <fixture>` against
`ssh -G -F empty.conf`, so OpenSSH decides what counts as changed rather than this
gate. That is what lets completeness be checked without hardcoding a list of
keywords the fixtures happen to set.

#### The fnmatch test that was wrong twice, and hid itself

`cmd/sshconfig_test` counted passing `if` conditions and printed them against a
**hardcoded** `fnmatch_total = 23`, then exited 0 either way. The block holds 25
conditions, so it printed `23/23` -- green-looking arithmetic that could not be.

Two of its expectations were wrong, both verified with `ssh -G`:

- `fnmatch("a*b*c", "abdc")` -- it asserted **no** match. OpenSSH matches: `a` +
  `""` + `b` + `"d"` + `c` is exactly the pattern.
- `fnmatch("*.ngs.fi", "ngs.fi")` -- it asserted a match. OpenSSH does not match:
  `*` can match the empty string, but `.ngs.fi` still has to match `ngs.fi`
  afterwards, and the lengths differ.

Both errors claimed *more* matching than glob gives. **The implementation was
right and the test was wrong, twice** -- so the fix was to delete the block rather
than repair it: the same 25 expectations now live once, as a table, in
`src/sshconfig/sshconfig_test.mbt` t10, where a mismatch is counted and asserted
and a failure names the case. A second copy is what let the two drift in the first
place; the copy that drifted was the one a human read.

This also fixes `moon test src/sshconfig`, which reported **`Total tests: 0`** --
Loop #24 wrote its checks as a printing command, so the package looked exercised
and was not. It now has 10.

#### Mutations: 5 CAUGHT, 1 EQUIVALENT

| | mutation | caught by |
|---|---|---|
| A | first matching block only (the original bug) | completeness rule |
| B | `!` pattern ignored instead of vetoing its block | value rule |
| C | keyword lookup case-sensitive | value rule (`user=deploy\|fallback`) |
| D | pre-`Host` options dropped again | completeness rule |
| E | `IdentityFile` stops accumulating | **`moon test`, not the gate** |
| F | gate stops checking case coverage | EQUIVALENT |

E is reported the way it happened. The fixtures give one `IdentityFile` each, so
the gate cannot see its accumulation; only `t7_multivalued_keywords_accumulate`
does. Saying otherwise would have meant inventing a fixture the loop did not
build.

F is a finding: no emitter skips a case on this tree, so the coverage assertion is
not observable. The claim is bounded to these inputs.

#### Not done

`Match`, `Include`, quoting and escapes are not implemented, and `#` unconditionally
starts a comment, so an `IdentityFile` containing `#` is truncated. Written down
rather than papered over. The package is still **not wired into any client** --
`cmd/ssh_live` does not read a config file. That is the next step, and the reason
this loop fixed the resolver before wiring it: the bug was worth finding either
way, but wiring a wrong resolver into a client would have made the user's
connections fail in a way that is very hard to read back to this.

### Loop #56: known_hosts, three sides -- and the two references that had fallen behind

The known_hosts chain in `verify_c/` is the oldest in the repository and, until this
loop, nothing ran any of it automatically:

```
knownhosts_python_ref.py   42 self-checks against hashlib / hmac
      |                    -> writes _knownhosts_ref_out.txt   (the vector file)
      v
gen_knownhosts_test.py     sanity-checks against FIPS 180-4 and RFC 2202
                           -> emits src/knownhosts/knownhosts_test.mbt
                           -> emits verify_c/_knownhosts_kat.h
      |
      v
knownhosts_harness.c       28 assertions, built by build_knownhosts.bat
```

`knownhosts_test.mbt` asserting against vectors that the generator wrote from a file
that Python wrote is a closed loop: a mistake anywhere inside it is invisible to it.
**Two things are done here that nothing did before.**

**One: the sides emit verdicts, not just bytes.** The new `cmd/knownhosts_kat` and
the Python reference both print the *decision* each reaches for every vector --
`0=Ok 1=Mismatch 2=Unknown 3=Invalid 4=CertAuthority` -- in the vector file's own
`key = value` shape, so `host/verify_loop56.mjs` can line them up by name. The point
is that a disagreement about what a pinning rule **means** shows up here; a
disagreement about SHA-1 arithmetic is not the interesting one, and that has
published constants.

**Two: drift is an assertion.** The two generated files are compared byte for byte
against what the generator produces right now. They were regenerated once by hand
and then left alone, and a generator change nobody re-ran would otherwise sit there
looking fine.

#### The finding: two references still had the Loop #51/#53 fail-open

Only `src/knownhosts` had the fix. `knownhosts_harness.c` and
`knownhosts_python_ref.py` were both still on the Loop #14 rule, where a
`@cert-authority` entry takes part in last-match-wins. Comparing a CA entry's blob
against the presented host key is meaningless -- it holds the **CA's** public key,
not this host's -- and **equal is fail-open**: a peer presenting the CA's own key
as its host key used to be accepted. The vector set predated the fix, so **neither
reference side had a single CA vector to notice**. Loop #51 fixed the bug and
Loop #53 wrote down why; nobody noticed that fixing it in one place out of three is
not a fix. Both sides are corrected here, `HOST_CERT_AUTHORITY = 4` is added to both,
and C1-C3 pin it:

| case | what it is | expected |
|---|---|---|
| C1 | CA entry covers the host, no direct entry | `4` CertAuthority |
| C2 | direct entry **and** CA entry for the same host | `0` Ok -- the direct one speaks |
| C3 | presenting the CA entry's **own** key | `4`, never `0` |

C3 is the load-bearing one: it is the case that returned `Ok` before the fix.

`CertAuthority` is not `Unknown` and the difference is operational, not cosmetic:
"nobody has pinned this host" means *add a line*, "pinned via a CA and we do not
verify certificates" means *get a new CA or re-sign*. Both refuse; they must not
report the same thing. `check_host_key_strict` deliberately does **not** upgrade
`CertAuthority` to `InvalidEntry` -- that would merge it with "the entry is broken".

#### The case table is not uniform, and that is the trap

The vectors do not spell themselves out by id. V2 is a wildcard match *of V1's line*
and has no line of its own; V3/V6/V7 present `V1_blob_hex`, not their own
`V*_blob_hex`; V7 is the strict path; V10 is two cases sharing one expected value;
V8 is marker parsing and has no verdict at all. The first version of the emitter
derived every key name as `<id>_knownhosts_line` / `<id>_presented_blob_hex`, which
fed an **empty entry list** into four cases -- and `parse_file` on nothing returns
no entries, which is a real verdict, `Unknown`, so those cases *passed*. That is the
whole failure mode this loop is about, and it is now a hard abort:
`assert_full_coverage` fails if the vector file carries an `_expected_status` that no
row claims.

That guard earned its keep immediately, on the author: the suffix length was written
as 15 instead of 16, so `V1_expected_status` sliced down to `V1_`, and the guard
reported "V1 has no row in the case table" -- an error that looks correct and is
not. The suffix is a named constant now.

**C2 is two known_hosts lines.** They were first written as one `key = value` whose
value contained a newline, which quietly breaks the vector file itself: it is
line-oriented, and both `pairs()` in the MoonBit emitter and `parse_kv` in Python
read a second key out of a value that does not exist. It is two keys now
(`C2_knownhosts_line`, `C2_knownhosts_line_ca`) and the generator splits them into
`C2_KH_LINE` / `C2_KH_LINE_CA` for the C harness, whose `parse_kh_line` takes one
line at a time.

#### The gate, and four things it caught in its own first run

`host/verify_loop56.mjs`, 41 checks. It refuses to overwrite a key it has already
parsed, and it checks the **key sets** match before comparing values -- a case that
exists on one side only does not error, it just stops being checked.

- `V10_expected_status` was printed once per sub-case. A duplicate key, correctly
  refused. The emitters now print it once, and the gate compares each sub-case to it.
- The `*_strict_got_status` row was a duplicate wearing a different prefix: V7 *is*
  the strict case. Both sides dropped it.
- `^\s*fail\b` was case-sensitive and the harness prints `FAIL` in caps, so the
  counter was always zero -- dead code shaped like a working second opinion. The
  `Total:` line was doing the real work.
- `build_knownhosts.bat` had CJK in `REM` comments. cmd reads a `.bat` in the OEM
  code page, so the multibyte comment was split into byte sequences cmd then tried
  to **execute**: the build still succeeded, but three `'...' is not recognized as
  an internal or external command` lines landed in the middle of the output. That
  noise is what made a real 24/28 regression read as a build break. The comments are
  ASCII now, with a note saying why, and the script deletes the previous `.exe`
  before compiling (the `build_ed25519.bat` rule from Loop #55).

#### Coverage the emitters cannot supply between them

Both emitters have `assert_full_coverage`, but two implementations that are wrong in
the same way check each other perfectly. Delete the C3 row from **both** tables and
their key sets stay identical while one case quietly stops being decided at all.
The gate therefore reads `_knownhosts_ref_out.txt` itself -- the one artifact neither
emitter gets to curate -- and fails if any `*_expected_status` in it has no verdict.
`host/loop56_mutations.py` mutation E deletes the row from both tables *and* switches
the emitter's guard off, and the gate's own check is what catches it.

**Representation, not semantics.** Python's `marker` is the raw token (`@revoked`)
and its two internal callers compare against `'@revoked'`; C's `kh_entry_t.marker`
and MoonBit's `Marker` enum both carry the bare name. Three sides first met here and
disagreed -- on representation, not on what a marker means -- so it is normalized at
the emitter boundary rather than by rewriting the Python reference's internals.

#### What the C side can and cannot contribute

`knownhosts_harness.c` asserts `s == V*_STATUS`, so it yields a boolean, not a
verdict. MoonBit and Python are compared **by value**; C is compared on whether it
agreed with the pinned number. That asymmetry is the harness's, not the gate's, and
it is written down rather than papered over.

#### Mutations: 5 CAUGHT, 1 EQUIVALENT

| | mutation | verdict |
|---|---|---|
| A | MoonBit lets CA entries back into last-match-wins | CAUGHT (C1/C2/C3 + 12 unit failures) |
| B | the C harness stops treating a CA entry as "not a pin" | CAUGHT (24/28, four named assertions) |
| C | the Python reference does the same | CAUGHT (three case disagreements) |
| D | a generated file is hand-edited | CAUGHT by the drift check |
| E | the C3 row is deleted from both tables, guard off | CAUGHT by the vector-file coverage check |
| F | the gate's `parseKeyed` drops its `=` line guard | **EQUIVALENT** |

F is a finding, not a failure: no line either emitter prints begins with `=`, so the
guard cannot be observed here. The claim is bounded -- *on these outputs* -- and the
distinction from `MISSED` is a verdict rather than a comment, because `MISSED` is an
accusation and conflating the two makes both useless.

**The mutation harness had a bug, and it is worth recording because it produced a
confident wrong answer.** Its first version wrote each edit from the pristine text,
so for a mutation with two edits to the *same* file the later one silently undid the
earlier. Mutation E therefore never deleted the C3 row from `main.mbt` at all -- it
only disabled the coverage guard, and it reported a crisp `CAUGHT` about a key-set
mismatch that had nothing to do with what it claimed to test. Reading the current
file content per edit fixes it. `python host/loop56_mutations.py E` now runs one
mutation by label prefix, which is what made the discrepancy findable at all: the
same mutation in isolation behaved differently from the same mutation in sequence.

**Workspace note, not a project fact:** the `edit` tool in this workspace could not
round-trip CJK inside `old_string` and reported "could not find the exact text" on
lines that were present and unchanged. One attempt to fix a stray `")` that way
wrote that line back as **invalid UTF-8**, which Python then refused to parse and
which `edit` could still not match -- the one repair had to go through a script.
Use **ASCII-only anchors** in `edit`, and in the mutation script too: an anchor that
fails to match on an encoding round-trip reports `NOBUILD`, which reads as "nothing
proven" rather than "the script is broken".

### Loop #55: a second pair of eyes, runnable

`verify_c/` has held nine C harnesses and seven Python references since the
early loops. Every one was run by hand and the result went into a document.
**Nothing ran them again.** `scripts/compare_kat.mjs` exists and works; nothing
invokes it. The nine `build_*.bat` scripts are named in `docs/` and nowhere
else. A `git grep` for `build_ed25519` outside `verify_c/` hits only
documentation.

That is worth stating plainly because it is the same shape Loop #53 was written
against: a fixture and a verifier sharing one mistake. Ed25519, AEAD and the
binary packet layer are the three places where a wrong answer is **silent** -- a
verifier that accepts a forged signature, an AEAD that accepts tampered
ciphertext, a length prefix off by four -- and all three were being checked only
against constants this repository also wrote.

**What runs now.** `host/verify_loop55.mjs`, three seconds, and it compares
*values* rather than counting lines:

| side | what it is |
|---|---|
| MoonBit | `src/ed25519` via the new `cmd/ed25519_kat` |
| C | OpenSSH's original `ed25519.c` (`verify_c/ed25519_harness.c`) |
| Python | `cryptography`, libsodium/OpenSSL-backed (`verify_c/ed25519_python_ref.py`) |

Each side prints the vectors in a different shape, so the gate parses each into
a map keyed by vector name and compares `pk` and `sig` across all three. A
shared text format would have been cosmetic and would have broken the first time
one side's banner changed.

**A published authority is not a second opinion, so all three are checked
against each other as well as against RFC 8032.** Two implementations agreeing
with a standard is evidence. Two implementations agreeing with each other
because both were written from the same misreading is not, and nothing here can
rule that out -- which is exactly why the malleability check is asserted
separately instead of being folded into the byte comparison.

**The negative cases are the load-bearing part, and getting them right took a
mutation.** `s == L` (malleability), a tampered message and a wrong key change
no positive vector at all. A verifier that accepts a malleable signature agrees
with all three sides on every RFC 8032 vector and is still exploitable, so a
gate that only compared the vectors would report ALL PASS.

**The first mutation run proved the opposite of what was assumed here, and the
harness was at fault.** `MISSED -- the gate still reported ALL PASS` for "disable
the range check". The malleability vector was built with `s = L`, and L's top
byte is `0xed`, so `sig[63] & 0xE0 != 0` rejected it at the **first** check --
the range check was never reached. The test had been passing for a reason that
had nothing to do with malleability.

The real attack is `s + L`, not `L`: a second valid signature over the same
message. `s + L < 2L < 2^253`, so its top byte is under `0x20` -- both the
high-bits check and the S-range bit check pass, and the *only* thing that can
reject it is the range check. That is the vector that tests the thing. It also
carries its own self-check: if `s + L` overflowed 32 bytes it would have wrapped
back into range and stopped being malleable, so the emitter prints the carry and
the gate requires it to be clear. A test that quietly stops testing itself is
worse than no test.

The original signature is re-verified in the same block as the control. Without
it, "the malleable one was rejected" could just mean `verify` rejects everything.

**One mutation here turned out to be an equivalent mutant, and that is recorded
as its own verdict rather than as `MISSED`.** Disabling `sc_is_in_range_bytes`
does not change what this client accepts: `s + L` is still rejected. Asking
Python settled why -- `cryptography`, which is OpenSSL/libsodium-backed and
shares no code with this repository, **also rejects `s + L`** (`InvalidSignature`).
So the rejection is a property of the format, not of one line here, and the range
check is defence in depth rather than the sole guard.

`MISSED` is an accusation and `EQUIVALENT` is a finding; conflating them makes
both useless, which is why `loop55_mutations.py` grew a fifth verdict. The
concrete claim is bounded and stated that way: **equivalent with respect to the
vectors this gate tests.** A vector that separated them does not exist yet, and
inventing one would mean hand-rolling a signature no other implementation
accepts -- the thing Loop #53 twice declined to do.

The mutation that *does* prove the negative cases are load-bearing is dropping
the final `pack(P) == R` comparison instead. No positive vector changes; a
forged signature becomes accepted, and the tampered-message, wrong-key and
malleability checks are the only things that see it.

**The C harness's own verdict is asked before anything is compared with it.**
If the reference says FAIL, "MoonBit matched it" is not good news, and a gate
that only compared values would print a cheerful match.

**`build_ed25519.bat` had `%%` in a `REM` line**, so cmd expanded it and every
run printed `'%' is not recognized` before the build. Harmless -- and it trained
everyone to ignore noise in the output of the one script a gate shells out to.
The script now also **deletes the previous `.exe` before building**: a stale
binary that still passes is the Loop #47 failure exactly, one level down.

**AEAD and bpacket are regressions only, and the gate says so.** Their C and
Python sides use *independently generated* case sets -- `C1a` versus `S1a` --
so there is nothing to line up and no shared vector file to compare against. The
gate checks that both harnesses still build and pass, which catches a harness
that stopped compiling, and says in its own header that this is not a substitute
for a three-way comparison. Claiming more than that would be the kind of
overclaim this loop exists to remove.

**The gate's first run caught a bug in the gate.** The Python reference prints
its RFC vectors and *then* a "Tampered Message Rejection" section that also has a
`sig =` line; the parser kept `current = "Test 3"` and silently overwrote the
signature, so the gate reported "Python disagrees with C and MoonBit" and pointed
at the reference. It is now wrong twice over on purpose: a `=====` banner ends the
section, and a key that already exists raises instead of overwriting. A parser
that can silently replace a value it already has will, given any reference with
more than one section, report a confident wrong answer -- which is the same shape
as the bug the loop exists to catch, one level up.

**`hx()` is written out again rather than shared with `src/aead`.** The two never
parse the same input -- RFC 8032 constants here, RFC 8439 constants there -- so
sharing a parser would make "both sides mis-read the same character" happen once
instead of twice, which is the failure being hunted.

**Verified:** `verify_loop55` `ALL PASS (17 checks)`, 3 seconds.
`host/loop55_mutations.py` 3 CAUGHT / 0 MISSED / 0 NOBUILD / 0 CRASH, where the
three mutations are "a signature bit is wrong" (caught by the comparison and by
`moon test`), "s == L is accepted" (caught only by the negative case, which is
the point), and "the MoonBit side prints nothing" (caught because a comparison
with a missing side must fail rather than pass vacuously).
`moon test src/ed25519` 23/23 unchanged.

**What it does not retire.** Six of the nine harnesses -- hostkey, kexflow,
knownhosts, kex, kex_c25519, and the SHA-2 / HMAC / poly1305 / x25519 ones --
still run only by hand. Each needs a MoonBit-side emitter in its reference's
format before it can be compared the way ed25519 now is, and that is one loop
each.

### Loop #54: the pin that outlives the process

Loop #52 made TOFU remember, in a browser. The native client kept **printing**
the line: `--kh-tofu` produced text, a human copied it into `known_hosts`, and
the pin lived exactly as long as the terminal they had open. That is the same
defect Loop #52's own title names, on the other transport -- and after Loop #53
it got worse, because the hint on a rejected certificate tells the user to add
a `@cert-authority` line by hand while the tool that could write the file does
not exist natively.

**"This moon version has no file IO" was out of date.** Loop #48 wrote that and
it was true then. `moonbitlang/async/fs` is in `.mooncakes` with a native stub
(`stub.c`, `dir.c`, `watch_windows.c`) and the whole surface this needs: `exists`,
`read_file`, `write_file`, `rename`, `remove`.

**`write_file(append=true)` truncates unless you also change `create_mode`.**
This is the footgun worth knowing about, and it is silent:

```
create_mode defaults to CreateOrTruncate
append     defaults to false
```

Those two defaults are safe *together*. Pass `append=true` alone and the file is
truncated and then one line is appended to nothing -- no error, no log, and the
next connection reports the host as unpinned, which reads as "TOFU forgot
again" wearing a completely different cause. `OpenOrCreate` is the mode that
makes append mean append, and `store_test.mbt` asserts the *property* (existing
entries survive) rather than the mechanism, so the test still holds if the
implementation is rewritten.

**Append, not read-modify-write.** Both preserve existing content, so the gate
asserts the property and not the choice. Append is narrower: a read-modify-write
can lose a concurrent writer's entry outright, while an append can only fail to
add its own. There is no lock, and that is a decision rather than an omission --
concurrent writers can still race, and it is written down instead of implied.

**A torn append costs the line being added and nothing else, and that was
checked rather than assumed.** `parse_file` skips a line it cannot parse, so a
fragment is ignored rather than read as a wrong key -- the failure that would
actually matter, because a half-written entry that *did* parse would report a
mismatch against a host nobody changed.

**The gate's isolation is a separate process, which is stronger than Loop
#52's fresh page.** Nothing carries over between the two runs except the file on
disk -- no module variable, no Worker, no open connection. "The client
remembered" and "the client is still holding the first connection's state" are
indistinguishable from inside one process; a new process makes them different
facts.

**What step 1 asserts past "a line appeared" is the part that is easy to get
wrong.** The file already holds a comment, an unrelated direct entry and an
`@revoked` line. A write-back that rewrites instead of appending destroys all
three, and the *next* connection still authenticates on the new host -- so the
damage stays invisible until the day somebody relies on a pin they already had.
"Exactly one line added" does not catch it either: truncate-then-append also adds
exactly one line. Only the three preservation assertions do.

**Reading the file is a decision input, not just a write target**, so step 4
pins a key that is *not* the presented one and requires `HostkeyMismatch` with
zero authentication attempts. A `--kh-file` that was only ever written would pass
every other step of this gate.

**The write-failure case is its own step because the failure this shape invites
is the exact one Loop #52 had to fix on the browser side**: print `accepted`,
quietly drop the pin. And the notice has to separate two different failures --
the credentials already went out, so the connection succeeded; what failed is
the *remembering*. Reporting it as a connection failure tells the user something
was refused, and reporting it as success tells them they are pinned.

**`main` became async; nothing else did.** Reading a file is async, and
`kh_policy` had six call sites each re-parsing `argv`. The fix is to resolve once
in `main` and pass a `KhConfig` down, so the `run_*` functions stayed **sync**
and each gained one parameter. The alternative -- making each caller async --
would have put the read six times and reintroduced the read/write drift that
`KhConfig` exists to remove. It also puts `--kh-file` resolution *after* the
`--proposal` early return, so that path stays a pure offline dump.

**`has_line` was extracted rather than written twice.** `append_line` already
contained the "is this line already here" loop, and the file path needs the same
predicate against different storage. `append_line` now goes through
`to_line` + `has_line`, which also removes the inline field-order duplication
its own comment complained about.

**A read that fails forces strict on, and that is the only safe reading.**
A user who cannot read their own trust anchors must never be accepted *because*
they could not read them -- that translates "storage is broken" into "trust
whatever is offered". `Missing` and `Unreadable` are separated in the transcript
so the user learns their file has a problem, while the *trust decision* treats
both as "no pin here" and refuses.

**`src/khfile` does not depend on `src/knownhosts`, deliberately.** Row format
belongs to the format layer and the dependency runs *that* way: the format
package is used by the platform package, not the reverse. The first draft had
`khfile` call `has_line` and it was removed -- one fewer edge that can drift.

**Deleted `src/knownhosts_store`**, 19 lines of Loop #19 `extern "wasm"`
scaffolding with zero importers. The repo-root `moon check --target native` is
*still* red afterwards, but for a different and correct reason: `src/ws_socket`,
`src/wt_socket` and the `cmd/wt_*` executables are js/wasm-only live packages.
Per-package checking is the right granularity in a repository with per-target
packages; a root-wide native check cannot be green here and chasing it would
mean deleting working code.

**Verified:** `verify_loop54` `ALL PASS (16 checks)` -- five steps, every one a
separate `cmd/ssh_live` process against its own man in the middle.
`host/loop54_mutations.py` 3 CAUGHT / 0 MISSED / 0 NOBUILD / 0 CRASH.
`moon test src/khfile --target native` 8/8. No regression: `moon test
src/knownhosts`, `verify_loop41` 29, `verify_loop47` 19, `verify_loop52` 9,
`verify_loop53` 26.

### Loop #53: `@cert-authority` becomes a real trust anchor

Loop #51 turned the fail-*open* off and stopped there: a `@cert-authority` line
was parsed, noticed, and refused, but nothing was ever verified against it. That
is the right answer for a client that cannot verify certificates -- and it makes
the standard deployment impossible. Puppet, Chef and Ansible all ship SSH host
certificates signed by a CA; a client that refuses every certificate is a client
that cannot be pointed at a fleet those tools manage.

So this loop makes the CA entry the thing it is named after: a **trust anchor**.
The certificate is accepted when the pinned CA signed it, it is inside its
validity window, and it names this host.

**The hard part was not the cryptography -- it was four facts about the blob that
I had wrong, and all four fail silently.**

| what I would have written from memory | what the bytes say |
|---|---|
| `cert type`: 1 = host, 2 = user | **`USER = 1`, `HOST = 2`** |
| inner key field carries its type name | **bare public key material**, no type name (32 bytes for ed25519) |
| `principals` is a comma-separated ASCII list | **one string**, holding length-prefixed substrings back to back (`00 00 00 10 host.example.com`) |
| `signed_data` = `nonce..reserved` (192 bytes) | **`blob[0 : len - 4 - len(sig)]`** (247 bytes), including the type name *and* the signature-key field |

Getting the type constants backwards does not "support one more certificate" --
it treats a certificate issued **to alice** as proof of a **host's** identity. The
two have different principal semantics and a different meaning entirely. The
values here came from signing one certificate with and without `ssh-keygen -h`,
reading the type field out of the blob, and cross-checking against what
`ssh-keygen -L` prints.

**The `signed_data` one is the reason this loop needed an independent oracle.**
The 192-byte reading is off by 55 bytes, and an ed25519 verifier given the wrong
message does not raise -- it returns "invalid signature". Every self-made vector
would therefore have been checked by a *broken* verifier and come out red for the
right-looking reason, or, once the fixture was signed by the same broken
implementation, come out green. The fixtures cannot catch it, because the
fixtures and the verifier would share the same mistake.

So `host/cert_signed_data_oracle.mjs` does not trust the layout: it takes the
blob's **every contiguous slice** and asks OpenSSL whether any of them verifies.
Exactly one does, and it is the 247-byte one. The oracle self-checks against a
self-signed vector before it will say anything (`host/cert_oracle_selfcheck.mjs`)
-- an oracle that is itself unverified is how a wrong answer gets promoted to a
spec.

**The signature check runs before every semantic check.** Every field in the
certificate is attacker-supplied until the CA signature verifies, so reading
`cert_type` first is feeding peer bytes into a branch. Written as a
non-negotiable rule with the reason next to it, because reordering it "for a
better error message" breaks nothing that any test would catch: each individual
check stays green.

**Six conditions, and `--kh-tofu` is not an exception to any of them.** There is
no case where a certificate is accepted without a pinned CA. A certificate with
no local anchor is indistinguishable from one a man in the middle invented, and
TOFU cannot help: there is no single key to remember, there is a CA to trust.

**Direct pins still beat CA entries, certificates included.** A known_hosts with
both a direct pin and a CA anchor, presented with a valid certificate, is a
`Mismatch` -- not "certificates are unsupported". Loop #51's priority rule
exists so a genuine key change is not laundered into an unimplemented-feature
error.

**`CertAuthority` and `CertUntrusted` are different failures with opposite
remedies.** The first means "an anchor is configured and this certificate does
not match it" (re-sign, or the CA changed). The second means "no anchor exists
at all" (add one line). Both refuse; telling the user to go hunting for a man in
the middle when the fix is one config line is the wrong answer either way. This
is also why `PinVerdict::CertAuthority` was renamed to `CertRejected(String)` --
its meaning changed under Loop #51, and a same-named constructor in two enums
does not compile.

**The clock is injected, and the default is fail-closed.** `KnownHostsPolicy::now`
defaults to `0`, which is "not yet valid" -- i.e. reject. The failure mode for
forgetting to pass a clock is a refusal, never an acceptance. And it must be
injected rather than read: the gate re-runs "an expired certificate must be
refused" forever, and a wall clock would make that assertion permanently true
after the day it was written. The drivers pass `@env.now() / 1000`; the unit was
measured against Python's `time.time()`, not assumed. An extern `Date.now()`
version was written first and deleted -- one less FFI boundary, and Loop #52 had
already paid for the bugs on that boundary.

**The certificate algorithm is advertised only when an anchor exists.** OpenSSH
offers `ssh-ed25519-cert-v01@openssh.com` unconditionally. Offering it
unconditionally is not a security gain here, and it would move the KEXINIT
baseline in `verify_loop41` / `verify_loop45` byte for byte. This is a
deliberate deviation, marked as one in the source, so the next person to
"complete" it reads the argument first.

**The gate refuses for the right reason, and that is the assertion.** Two
outcomes that look like failures are the *strong* outcomes: with no anchor
configured, the client never offers the certificate algorithm, so the peer has
nothing to negotiate and the handshake dies at **agreement** -- the client never
reaches a pinning decision at all, let alone sends credentials. Asserting
`HostkeyUnknown` there would demand the weaker behaviour and read a correct run
as a failure. Each refusal additionally asserts the leaf name, that the hint
names the actual remedy, that `auth_attempts == 0`, and that the peer really had
a host key configured -- absent must never be read as zero.

**Two of the awkward decisions are not guesses -- they are `hostfile.c`.**

- **The CA is found by issuer, and the first match wins.** `hostfile.c:377`
  handles `want_cert` by comparing `k->cert->signature_key` against each entry's
  key and `break`ing on the first hit with the comment "A matching CA exists".
  That is byte equality against the **issuer**, not last-match-wins, and it is
  what `find_ca_entry` does. Last-match-wins is the rule for the *direct* key
  path precisely because a bare key line is a claim about a host; a certificate
  names exactly one issuer, so there is nothing to order.
- **Revoking a CA kills every certificate it cut, host-scoped or not.**
  `hostfile.c:321-330` sweeps every `MRK_REVOKE` entry globally and, for a
  certificate, compares against `k->cert->signature_key` as well as the key
  itself. The `revoked-ca` case in the gate exists because that second
  comparison is easy to leave out, and leaving it out means a revoked CA keeps
  working forever.

**An untested half, recorded rather than glossed.** `ssh-keygen` refuses to sign
a certificate with no principals ("Empty principal name"), so the other half of
"an empty principal list is valid for every principal" -- the accepting side --
has no fixture. Only the parsing side of `parse_principals` is covered. A
fixture minted by hand-rolling the signing would need a second implementation of
certificate issuance, which is exactly the thing this loop avoided.

**Four harness lessons, all of them failures that pointed somewhere else:**

1. **A MITM serves exactly one connection** (`listen(1)`, a single `accept`). The
   first version of the browser half reused the peer's the native client had just
   consumed, so the browser run reported `NoServerIdent` -- a transport symptom
   for a harness bug. Every transport now gets its own man in the middle.

2. **Check that the man in the middle is alive.** `freePort()` closes a listener
   and hands the number back, and the OS may give it to something else, or
   paramiko may exit on it. Against a dead peer the transcript says nothing and
   the client says `NoServerIdent`. Loop #52 already wrote this check; loop53
   wrote a new `startMitm` and left it out, and then spent three hypotheses
   ruling out the certificate code.

3. **Browser gates must never run concurrently.** Each spawns Chromium, a static
   server and a WS bridge. One gate's `moon clean` deleted another gate's
   freshly built `_build` mid-run, and the result was a failure that read like a
   protocol bug.

4. **A gate that does not exit is a gate whose results cannot be attributed.**
   `serve()` leaves an HTTP server listening and `chromium.launch()` leaves a
   browser open; `openPage(..., { freshStorage: true })` opens a context per case
   that outlives its page. The gate printed its verdict and then sat there
   forever, so the shell never returned and an **orphaned gate from the previous
   run stayed on the machine**, holding ports and racing the next one. That is
   how two `verify_loop53.mjs` processes ended up writing the same
   `.loop53/*.json` at once -- and one mutation verdict was read from a
   transcript the other gate had overwritten. Closing the server, the browser
   and each context dropped the runtime from over four minutes to 111 seconds as
   well.

The fourth lesson has a corollary worth stating on its own: **`task_stop` is not
a substitute for a restore.** Killing the mutation runner mid-flight skipped its
`finally`, leaving the tree mutated, and the next gate run faithfully reported
the mutation as a failure. Nothing about that output was wrong -- it was a
correct verdict about the wrong tree.

**Verified:** `verify_loop53` `ALL PASS (26 checks)` -- 11 cases, each driven by
both `cmd/ssh_live --auth` over TCP and `cmd/wt_ssh` in a browser Worker.
`host/loop53_mutations.py` 3 CAUGHT / 0 MISSED / 0 NOBUILD / 0 CRASH.
`moon test src/hostkey` 25/25, `moon test src/knownhosts` 49/49. No regression:
`verify_loop41` 29 (the KEXINIT byte baseline, unmoved -- the conditional
advertisement does its job), `verify_loop45` 51, `verify_loop46` 53,
`verify_loop47` 19, `verify_loop52` 9.

### Loop #52: a pin that survives the page going away

Loops #49/#50 made the *decision* right and the *rendering* right, and then
printed the line. Printing is not remembering: the gate caught stdout and fed
the line back by hand, while a browser user has nobody to do that. So `--kh-tofu`
on Tuesday means unpinned again on Wednesday -- the exact state TOFU exists to
remove and `accept-new` is not allowed to leave. The pin lived exactly as long as
the test that produced it.

New `src/khstore` (js-only) plus `host/wt/moonbit_khs.js`, following the shape
`src/wt` already established: "what a line looks like" stays in `src/knownhosts`
and is shared by both transports; "where it goes" is the platform's. The stored
value is the **line**, not a structured object, so a browser user who exports it
gets text they can paste into `~/.ssh/known_hosts` -- a richer structure would
need a conversion step, and conversion is where format bugs live (Loop #49's
marker-loss bug was exactly that).

**Four real obstacles, all found by running it rather than reasoning about it.**

1. **A Web Worker has no `localStorage`.** The first version wrote to it. Not a
   policy or a permission -- simply absent: `globalThis.localStorage` is
   `undefined` inside a Worker, so the property access throws and no `try` around
   the call rescues it. IndexedDB is the only origin-scoped storage a Worker has,
   and the only one that makes sense here. What made this findable rather than a
   silent no-op is that the failure was **reported**: every connection printed
   `tofu: NOT stored`, and the driver says it in words rather than letting a user
   believe they are pinned.
2. **No string literals inside an `extern "js"` body.** MoonBit has no
   single-quoted string (`'` is a lexing error, U+0027), so `""` inside a
   double-quoted body must be written `\"` -- and the compiler emits that
   right-hand side as a literal, backslash and all. The generated JavaScript
   contains `?? \"\"`, a SyntaxError, and the module dies at `importScripts` with
   an **empty transcript**, so the failure looks like a harness problem rather
   than a code problem. `src/wt/ffi.mbt` escaped this by accident: none of its
   bodies needs a string. Same family, opposite end -- it recorded inline
   `#| ... |#` leaking its own terminator.
3. **No `Option` across the FFI boundary.** `getItem`'s `null` looks like it
   should arrive as `None` and does not: the generated code tests
   `=== undefined` and treats `null` as `Some(null)`, so the `Some` arm
   dereferences null and the error surfaces far from the cause. The extern now
   answers "was there anything" and the value travels in a second call.
4. **Awaiting is `@js_async.Promise::wait(...)`, not an `await` keyword.**
   `await f(x)` parses `await` as an unbound identifier. Only a parse error, so
   the only kind of confusion that costs nothing.

**A fifth one, and it is the harness contract rather than the language.** Every
mode in `cmd/wt_ssh` ends with its own `wt_finish(...)`, because the Worker
harness takes "finished" from MoonBit through `__wt_finish` rather than guessing
when `importScripts` returned. `kh_forget` shipped once without it: the mode
printed `forget: 127.0.0.1` correctly and then hung, so the gate saw a bare
timeout with a *complete and correct* transcript. That failure reads as a slow
machine, not as a missing signal. **A new mode that returns early must signal.**
The gate now reports that case by name rather than as a timeout.

**`moon check src/khstore` said "no work to do" right after a failed run**,
because the failed attempt had already populated the cache. Force a rebuild
(`moon build`) when a check seems to have skipped your change.

**The gate's isolation is the design, not a detail.** The obvious version passes
for the wrong reason: if step 2 runs in the same page, it cannot distinguish "the
store worked" from "nothing changed and the browser is still holding the first
connection's state". So every step runs in a fresh Page inside a **shared
BrowserContext** -- a new page, new globals, new Worker, no leftovers, and the
same origin-scoped storage. That required changing `host/wt_browser.mjs`'s
`openPage`, which had used `browser.newPage()` and therefore opened a fresh
*context* every call: right for Loop #48/49/51, which wanted total isolation, and
wrong here, where the whole claim is that the pin outlives the page. Getting that
backwards reports a working store as a broken one.

Five cases, and three of them exist to stop the store from being merely a cache:

| case | flags | expected |
|---|---|---|
| 0 | nothing stored, nothing pinned | refuse, `HostkeyUnknown` |
| 1 | `kh_tofu` | authenticate, and the browser really holds the pin |
| 2 | **none at all**, new page | authenticate, from the stored pin |
| 3 | the stored host presents a different key | refuse, `HostkeyMismatch` |
| 4 | `kh_forget`, then connect | forget does not connect; then refuse as `Unknown` |

Case 4 is two steps on purpose, and that is what is under test. `kh_forget`
forgets and **stops** -- it does not go on to accept whatever the peer presents.
One step that does both is how a "remove this pin" button becomes a silent
accept, which is the fail-open Loop #51 closed. And a forgotten host must come
back as `Unknown`, not `Mismatch`: a store that cannot tell "not pinned" from
"the key changed" cries wolf about a legitimate rotation, and its users learn to
click through.

**Step 4a asserts the absence of a file, not the contents of one.** "Forgetting
must not also connect" is checked as `existsSync(transcript) === false`, because
the man in the middle writes its transcript when a connection happens and writes
nothing otherwise. The first version read the transcript and asserted
`auth_attempts == 0` -- and `.loop52/` is not cleaned between runs, so it read a
file left by a *previous* run and reported an authentication attempt that never
happened. A failure with no cause behind it is the worst kind to chase, and it
took an isolated run of `kh_forget` (which showed no connection, and no file at
all) to see that the client was right and the gate was not. The scratch directory
is now wiped at startup for the same reason, so the property holds on the first
run and not just the hundredth. **Step 4a passes `kh_tofu` as well, and that combination took four attempts to
find.** Removing `kh_forget`'s `return` -- the obvious mutation -- turns out to
be *safe*: the pin has just been forgotten, so the connection that follows reads
an empty store and is refused anyway. The mutation also has to remove the
`wt_finish` **call**, because the harness takes "finished" from that call: with
the signal still there the mode announced completion before performing the
authentication it was supposed to perform, and the gate correctly read a clean
forget. A mutation that produces the right answer for a reason that has nothing
to do with the mutation is indistinguishable, from the outside, from a gate with
a hole. So 4a asks for both `kh_forget` and `kh_tofu` and asserts that neither
credential leaves nor any authentication is attempted.

**Sharing the context cost a real regression, and that is the interesting part.**
Making storage survive meant `openPage` had to stop using `browser.newPage()`,
which opens a fresh *context* every call. The first regression run then failed
**Loop #48**, whose `unpinned` case had been relying on "a new context means a
clean slate" -- and it failed by *authenticating*, because a pin left behind by an
earlier case in the same run was still there. That is the worst way for this gate
to fail: the case named "nothing is pinned" passed by being pinned.

So `openPage` takes `{ freshStorage: true }`, and every gate that is not about
storage persistence now asks for it explicitly. Only `verify_loop52` shares. The
default stays shared so that a future gate testing persistence inherits the right
behaviour rather than having to discover it, and the opt-out is one visible word
at the call site. `verify_loop46` needed it for a second reason: it passes
`kh_tofu`, and a leftover pin from an earlier case can change whether a fault
vector is even reached -- which is the part that gate measures.

**The gate asks the browser, not the client.** The first version of step 1
asserted the `tofu: stored` line -- and mutation A *is* `let stored = true`. The
self-report agreed with itself and passed, so a client that stored nothing would
have been reported as having stored. The gate now reads the same IndexedDB from
its own side, twice: that a pin exists, and that it carries the key the peer was
shown. A pin filed under the right host with the wrong key would authenticate on
the next connection only by luck, and "only by luck" is exactly what TOFU is.

Writing that check immediately failed for the wrong reason: the first version
looked up the bare host name, while `src/khstore` files pins under
`moonbit.ssh.known_hosts/<host>`. Step 2 was *passing* throughout, which is what
said the pin was really there and the lookup was wrong -- two checks that
disagree is a signal worth reading before believing either. The key is now
duplicated into the gate **on purpose**: if `storage_key` ever changes, the
lookup returns null and step 1 fails loudly instead of quietly agreeing with a
store that moved.

**Four failed mutations, and the fourth one is the lesson.** Getting C to mean
"kh_forget forgets and then carries on" took four attempts, each failing in a way
that looked like a different problem:

1. the anchor spelled out a Chinese comment, which drifts when someone edits it;
2. the anchor shrank to `wt_finish(true, "done")\n    return` -- which appears
   **five times** in `main.mbt`, because every mode ends the same way. So
   `str.replace` rewrote all five and the mutation silently became "every mode
   carries on". At the one path the gate measures, behaviour was unchanged, so it
   reported **MISSED** -- pointing at the gate;
3. a one-line anchor plus an inserted statement, which changes no control flow at
   all, so the `return` was still there;
4. removing the `return` but keeping `wt_finish(true, "done")` -- the subtle one.
   The harness takes "finished" from that call, so the mode announced completion
   **before** the authentication it was supposed to perform, and the gate
   correctly read a clean forget.

The fourth is worth keeping. **A mutation that produces the right answer for a
reason that has nothing to do with the mutation is indistinguishable, from the
outside, from a gate with a hole** -- nothing in `MISSED` says which it was.

Every one of these produces a confident verdict about a mutation that was not the
one described. All four mutation drivers now assert `src.count(frm) == 1` and
report **NOBUILD** otherwise -- nothing was proven, and MISSED would be a lie.

**Adding a status line is a protocol change, and it broke two gates downstream.**
Loop #52 inserts `tofu: stored` / `tofu: NOT stored` between the existing
`tofu: accepted-unpinned` and the entry itself. `verify_loop49` and
`verify_loop50` both parse that output to recover the written line, and both had
their own filter listing only the one marker they knew about -- so each silently
picked up `stored` as if it were a known_hosts line. Same failure both times: a
byte-for-byte comparison between transports reporting a mismatch, and a
reconnect refused because the "line" was the word `stored`.

Two gates, one cause, found twice, which is what it costs for a parsed protocol to
have a marker list living in two places. It now lives in **one**
(`host/tofu_transcript.mjs`), used by all three gates, and it recognises the entry
**structurally** as well -- a `known_hosts` line has at least two
whitespace-separated fields, and no status line does. So a future status line
breaks the parse only if somebody forgets a file that already has a fallback.

The general rule: a driver and a gate are two independent implementations of "what
this output means", and neither is documentation for the other.

**Browser gates do not run concurrently with anything.** Every one of them
launches Chromium, a static server, and a WebSocket bridge, and they pick ports
with `freePort()`. Two at once produce failures that read like protocol bugs --
`no outcome from the Worker`, `http=404` for the MoonBit module, `did not
authenticate: ""` -- none of which says "two gates shared the machine". Discovered
by running a mutation driver and a regression sweep at the same time during this
loop and having to throw both sets of results away. Run them one at a time.

**Verified:** `ALL PASS (9 checks)` on `verify_loop52`, and `loop52_mutations`
reports `3 CAUGHT, 0 MISSED`. No regression on `verify_loop46` 53 / `47` 19 /
`48` 15 / `49` 11 / `50` 13 / `51` 17.
`verify_loop47` 19 / `48` 15 / `49` 11 / `50` 13 / `51` 17.

### Loop #51: `@cert-authority` is not a host key pin

Loop #50 made refusing the default. This closes a hole that default made
reachable, and it was found by reading what a marker *means* rather than what it
parses as -- Loop #49 had just taught `render` to preserve `@cert-authority`, and
nobody had asked what the matcher did with it.

**It did nothing.** `Marker::Revoked` is consulted in `check.mbt`; `Marker::CertAuthority`
was never read anywhere in the decision path. `entry_matches_spec` ignores the
marker, so a `@cert-authority` line was an ordinary trust entry. Measured with a
throwaway probe before fixing anything:

```
direct pin (the control)       AUTHENTICATED    auth_attempts=1
@cert-authority, same blob     AUTHENTICATED    auth_attempts=1   <-- fail-open
@revoked, same blob            refused  HostkeyMismatch  auth_attempts=0
```

`@cert-authority host K` says *trust this host only when it presents a certificate
signed by K*. This client does not validate host certificates. So the entry is a
question we cannot answer, and **both** obvious ways to answer it are wrong, in
opposite directions:

- treat it as a direct pin -> fail open when the blobs coincide (the hole above);
- treat it as a mismatch -> fail closed, but accuse a man in the middle who does
  not exist. `HOST_CHANGED`'s documented remedy is "add the key" or "type yes",
  which here means reaching for `--kh-tofu`.

That second one is why this is more than a missing check. **A client that cries
wolf about an ordinary CA deployment trains its user to disable the protection**,
and Loop #50's entire argument was that turning protection off should cost a
deliberate keystroke. The bug was finding a way around the keystroke.

`@cert-authority` is common in real `~/.ssh/known_hosts` -- it is how a Puppet /
Chef / Ansible CA gets pinned -- so both halves of this are reachable in
ordinary use.

**The fix is a separate match path, not a special case.** `find_last_match_v2`
became `find_last_direct_match_v2`, which excludes `@cert-authority` outright,
plus `has_cert_authority_match` to tell "nobody pinned this" apart from "pinned
via a CA, which we cannot answer". `HostStatus` / `PinVerdict` / `PinFailure` each
gain `CertAuthority`, and both adapters plus `src/kexflow` translate it into their
own error (`HostkeyCertAuthority` / `HostKeyCertAuthority`). Three states that
must not be confused, each with a different remedy:

| verdict | says | the user's next move |
|---|---|---|
| `Mismatch` | someone is lying | rotate the key, investigate |
| `Unknown` | nobody pinned this host | add a pin |
| `CertAuthority` | this client cannot answer | use a different tool, or pin the host key directly |

Two precedence rules, both asserted because both directions are wrong:

- **A direct entry wins over a CA entry**, so a *real* key change on a host that
  has both still screams. If the CA entry won, a genuine compromise would be
  laundered into "this client doesn't do certificates" -- strictly worse than
  the reverse.
- **`@revoked` still bites first**, because its scan is global and by design
  ignores host matching. A key that is both revoked and CA-referenced reported as
  `CertAuthority` would turn an unambiguous revocation into a feature gap.

**`--kh-tofu` does not open this one.** It is easy to read "accept what you haven't
seen" as permission to accept this, and it would restore exactly the downgrade
being removed -- through a switch that looks entirely reasonable.

**Gate: `ALL PASS (15 checks)` over five cases on both transports**, plus 38
known_hosts unit tests. `ca-other-blob` is the case that looks like a pass and is
not: refusing is correct there, but refusing *for the wrong reason* is the whole
damage, so the leaf name is compared and not just the outcome. A gate that checked
only yes/no would have shipped the accusation.

**The name is not the whole fix, so the gate checks the sentence too.** Loop
#51's argument is that the name decides what the user does next, and an
unfamiliar label in a log changes nothing -- the user still walks the path they
walked last time. Both drivers therefore print a `hint:` line *after* the
machine-readable `error:` line, and every refused case in the gate asserts both
that the hint exists and that it mentions what that case is about: `revoked` must
say "man in the middle", `ca-*` must say "certificate", `unpinned` must say "no
key pinned". Without that, deleting `print_pin_hint` turns every gate green again
while quietly putting the autopilot back, and the three hints could converge into
one paragraph with every leaf name still correct.

```
error: transport:handshake:HostkeyCertAuthority
hint: 127.0.0.1 is pinned via a @cert-authority entry, and this client does not
      validate host certificates. This is not a man in the middle: pin the host
      key directly (ssh-keyscan -t ecdsa 127.0.0.1), or use --kh-tofu and know
      that the pin will break when the host renews its certificate.
```

**Verified:** `ALL PASS (17 checks)` on `verify_loop51` over six cases on both
transports, plus 38 known_hosts unit tests. `ca-other-blob` is the case that looks
like a pass and is not: refusing is correct there, but refusing *for the wrong
reason* is the whole damage, so the leaf name is compared and not just the
outcome. A gate that checked only yes/no would have shipped the accusation.

**Two traps in the tree that are not regressions.** Both cost time during this
loop; neither was introduced by it.

1. **`moon check --target native` at the repo root fails**, and did before this
   loop. `src/knownhosts_store` is a Loop #19-era host-shim scaffold using
   `extern "wasm"`, last touched in `3a23d8c`, **imported by nobody**, with no
   `targets:` gate in its `moon.pkg` to keep it off the native backend (the
   pattern exists elsewhere -- see Loop #37). Check the packages you touched, or
   the known-hosts dependents specifically (`src/knownhosts`, `src/kexflow`,
   `src/sshclient`, `src/wtlive`, `cmd/ssh_live`, `cmd/wt_ssh`, `cmd/sftp_mitm`);
   do not read a red root-level check as a regression. It is also, incidentally,
   where a real store would go if the write-back ever stops being a printed line.

2. **The committed `pkg.generated.mbti` files are stale.** `src/knownhosts`'s was
   last written in `3a23d8c` (Loop #17-#21) and does not contain
   `KnownHostsPolicy`, `decide`, `PinFailure` or `append_line` -- everything from
   Loop #48 on. Moon does not regenerate them in place here, and there are no
   fresh copies under `_build`. Most of them date to the initial commit. So **do
   not read a `pkg.generated.mbti` in this repo as the package's API surface**;
   read the `.mbt` files. This bit during this loop: the stale `knownhosts` mbti
   already contained a `CertAuthority`, which is `Marker::CertAuthority` from
   Loop #14, and it briefly looked like evidence that Loop #51's new status was
   already there. The "read the real `pkg.generated.mbti`" rule in the
   third-party-package checklist is about `.mooncakes`, where moon *does*
   generate a current one; it does not apply here.

**Mutation check: `host/loop51_mutations.py`** -- A drops the exclusion (the
fail-open returns), B downgrades the answer to `Unknown` (the accusation
returns), C makes `src/wtlive` discard the verdict. All three caught.

A is the informative one, because it reproduces **both halves of the original
bug at once**: `ca-same-blob` and `tofu-ca` go back to `AUTHENTICATED`, and
`ca-other-blob` goes back to `HostkeyMismatch`. That is the pre-fix behaviour,
side by side, in one run.

B turned up something the gate's cases had not made explicit: **the TOFU hole
does not need the marker filter removed.** Downgrading the CA answer to `Unknown`
is enough, because `Unknown` under `--kh-tofu` is "accept". So
"accept-new must not re-open this" is a property of the *verdict being distinct*,
not of the exclusion in `find_last_direct_match_v2` -- two independent mechanisms,
and asserting only one of them would have left the other untested.

### Loop #50: the default is the refusal

Loop #48 made pinning real. Loop #49 made it write back. Neither changed the
**default**, which stayed where #48 left it: pin nothing, connect anyway. That is
the shape OpenSSH has spent twenty years defaulting away from, and it is where
every forgotten configuration file lands silently. This loop puts the default on
the safe side: **nothing configured means refuse**, and accepting a new key
becomes something you have to type (`--kh-tofu` / `kh_tofu`, the equivalent of
`StrictHostKeyChecking=accept-new`).

The shape is half the argument. In the safe default the unsafe thing costs one
flag; in the old one, the safe thing cost a file **and** a flag. One fewer
configuration item is one fewer thing to get wrong. For the same reason
`--kh-strict` was **deleted** rather than flipped: once refusing is the default,
a switch named "strict" points the opposite way from every other switch, and of
two oppositely-named switches one will never be read.

**What actually went wrong, three times over.** The first three attempts at this
were correct code. `moon check` passed. And a client with nothing configured kept
authenticating. The cause was one line in `KnownHostsPolicy::verify`:

```moonbit
if self.entries.length() == 0 { return Skip }
```

`Skip` was a verdict meaning "nothing was configured, so nothing was compared",
and `decide` read it as *no objection*. So under `strict`, "you configured
nothing" was reported as "everything checked out". `check_host_key` already
returns `Unknown` for an empty entry list -- that early return was swallowing it.
Fixing it was to **delete the state**: `Skip` is gone from `PinVerdict`, because
"forgot to configure" and "configured, nothing matched" are the same behaviour
with opposite answers under strict, and a field that conflates them is a field a
default can fall into. The only way to not pin is now `skip()` (`strict = false`),
which reaches the same verdict through the **same code** rather than a bypass.

**A fail-open default is structurally invisible to end-to-end tests.** The peer
does not care what our default is; it will happily accept userauth from a client
that should never have sent it. Nothing in a gate that only checks "did the right
thing happen" can see the difference. So `host/verify_loop50.mjs` is built around
*differences*, not absolute outcomes:

| case | flags | expected |
|---|---|---|
| a | none at all | refuse `HostkeyUnknown`, 0 auth attempts |
| b | a + exactly one switch | authenticate, report a line to write back |
| c | b's written-back line, **no** switch | authenticate |
| d | `--kh-strict` (deleted in #50) | still refuse |

`c` is the payoff: once the key is written back, the unsafe switch is not needed
again. If it were, `accept-new` would be a permanent downgrade rather than a
one-time decision and "remember it" would be a lie. `d` is there because a deleted
flag is not automatically an inert one, and "we removed it" is a claim rather than
a measurement.

**The refusal is asserted three ways, and only the third is new.** The error name
could be anything, and `auth_attempts == 0` could hold for an unrelated reason
(peer hung, wrong port, dead bridge). What makes it *this* layer's doing is that
the man in the middle still recorded a host key blob: the exchange completed
signature verification and we refused a peer whose key we had just proven it
holds. A peer that never presented a key also shows zero auth attempts -- and
would be refusing for a reason that has nothing to do with pinning.

**Both the rule and the call sites collapsed to one copy.** `allows` (the Bool
version) had no callers at all while both adapters hand-rolled the same decision;
that is three copies of one rule, and a default changed in one of them. Loop #50
deletes `allows` and leaves `decide` as the only entry point -- adapters now only
translate the failure into their own error type. The stale anchor in
`host/loop48_mutations.py` had to move with it, which is itself the lesson: an
anchor that no longer matches reports `SKIP`, and a `SKIP` is indistinguishable
from a gate with nothing left to catch.

**Harness lessons:**

* **`moon build` reported "no work to do" while the source had changed.** It cost
  real time, because the resulting binary behaves exactly like a correct build of
  an older default. `moon clean` fixed it. The mutation driver now cleans before
  every run: a mutation that fails to show up because nothing was rebuilt reads as
  `MISSED`, which points at the gate rather than at the tree.
* `kh_host` now defaults to `127.0.0.1` in both drivers, via one helper each
  (`kh_host_name` / `cfg_kh_host`). Two call sites asking "which host do we look
  up" independently is how the write-back ends up writing a name the next
  connection will not query -- and `HostkeyUnknown("")` is a refusal that says
  nothing actionable.
* A unit test, not just a gate, is the right regression net for a default. The
  assertion `from_text("", host, 0, true).decide(blob) == Some(Unknown(...))` runs
  in milliseconds and covers precisely the branch that never executes.

**Mutation check: `3 CAUGHT, 0 MISSED`.** `host/loop50_mutations.py` mutates the
default three ways, all the same bug in different clothes -- the default quietly
stops refusing:

| | mutated | caught by |
|---|---|---|
| A | `cmd/ssh_live`: `strict` no longer derived from `--kh-tofu` | native only |
| B | `decide` ignores `self.strict` on `Unknown` | both transports **and** the unit test |
| C | `cmd/wt_ssh`: default policy built non-strict | browser only |

B is the one that matters. A and C are a wrong constant at a call site and read
as such in a diff; B is the rule itself losing the property while every caller
still passes the right arguments -- exactly the shape of Loop #50's original bug.
That the unit test catches it too is the point of having added one: the rule is
shared, so a rule-level regression has to show up in both transports, and a gate
that only ran end to end would have paid two browser launches to learn the same
thing.

**Two real defects in the mutation driver itself, both found by running it.**
Restoring the tree only in `finally` meant each mutation started from the
*previous* one's leftovers, so C -- which touches `cmd/wt_ssh` alone -- reported
the **native** client failing too. Every mutation was still CAUGHT, so the
tally looked perfect while the attribution was fiction; and a mutation reported
against a client it never touched invents a dependency edge that sends the next
person looking for it in `moon.pkg`. The same bug was in
`host/loop48_mutations.py`. Second, the per-transport breakdown matched
`"native "` against labels that begin `"FAIL native "`, so it had never printed
once -- dead reporting that looked like "nothing was caught by either client".

**Gates adjusted rather than re-tuned:** `verify_loop47` now passes `--kh-tofu`,
which makes it *stronger* -- willing to accept any self-consistent key, the only
thing left stopping a forgery is signature verification. `verify_loop48`'s
`no-policy` case became `unpinned` and now expects a refusal: the case used to be
written down as a **passing** case precisely so the gap stayed visible, and
flipping it is how the gap's closure gets re-checked every run instead of claimed
once. `verify_loop45` (`cmd/sftp_mitm` passes `skip()` explicitly at a call site)
and `verify_loop46`/`verify_loop49` were unaffected.

**Verified:** `ALL PASS (13 checks)` on `verify_loop50` plus 32 known_hosts unit
tests, `verify_loop48` 15, `verify_loop47` 19, `verify_loop45` 51, `verify_loop46`
53, `verify_loop41` 29, no regression.

### Loop #49: TOFU has to actually remember

Loop #48 added the comparison. This closes the half that makes the policy TOFU
rather than just "trust anything": **trust on first *use***. Accepting an
unpinned host is half a policy. If nothing is written back, "use" never happened
-- the next connection is again a fresh credential-free acceptance, and so is
the one after that. The client never becomes harder to fool, only slower.

**The write-back is rendered in `src/knownhosts` and printed by the driver.**
`render.mbt` holds the rendering (`render`, `append_line`, `to_line`) and nothing
else; no filesystem is touched, because this moon version's core has no
file-reading API and `src/wt` is js-only where a browser has no filesystem at
all. So "what a line looks like" has one implementation that both transports
share, and "where it goes" is the driver's business -- a known_hosts file natively,
localStorage in a browser. The gate captures the printed line and feeds it back
in.

**The sequence is the point, and step 3 is what makes step 2 mean something:**

1. no known_hosts at all, an honest peer -> authenticate, and the client reports
   the key it just accepted
2. that text fed back in, **the same** peer -> authenticate, and it is now a match
3. that text fed back in, a peer with a **different real key** -> refuse

Step 3 is what catches a write-back that produced text matching nothing: TOFU
would be indistinguishable from never having pinned at all, and step 2 alone
passes in that case. The mismatching peer is a *self-consistent* one with the
wrong key -- a forged one would fail earlier for an unrelated reason.

**Two real bugs the round-trip property caught, both invisible end to end:**

* **`render` dropped the `@revoked` / `@cert-authority` marker.** A revocation
  record written back becomes an ordinary **trust** record -- the opposite
  direction -- and it still parses, so nothing anywhere reports an error. This is
  the worst class of write-back damage and the end-to-end sequence cannot see it,
  because nothing in the sequence writes a marker. Hence a dedicated assertion.
* **`render` did not emit a trailing newline**, so "read back out byte for byte"
  did not close: every line differed by one `\n`.

Both came from writing the property down first and testing it against real data.
**The test constants are real SSH wire blobs, not placeholders** -- a made-up
base64 string parses to zero entries, and a `0 != 1` failure reads like "the
rendering is broken" when only the fixture was never a key. Same shape as Loop
#43's `hex_to_bytes` lesson: a bad fixture produces a failure that points at the
rule.

**Two harness lessons, and one of them is a good assumption I got wrong:**

* `println` can wrap the base64 across lines, so a single-line regex truncates
  the key and the gate then reports "the written line does not carry the key the
  peer presented" -- pointing at the driver, which was right. The line is also
  printed *after* `tofu: accepted-unpinned`, so a first-match read returns the
  status marker as content, and a last-match read swallows the rest of the
  transcript.
* **A repeated TOFU on reconnect is correct, not a failure.** Writing back again
  on every accepted connection is what keeps the file current when a host
  legitimately rotates its key. The first draft of this gate treated it as "the
  first write-back was not remembered" and failed on correct behaviour; the
  distinction that actually matters is in step 3.
* The man in the middle writes its transcript when its session thread returns, so
  a read placed before the client has connected gets an empty file. Both step 1
  and step 3 had this; step 1 happened to pass, which is not a reason to leave it.

**Verified:** `ALL PASS (11 checks)` plus 24 known_hosts unit tests. Both
transports write a byte-identical line, so a browser user and a native user end
up with the same known_hosts for the same server. `verify_loop48` 15,
`verify_loop47` 19, `verify_loop41` 29, no regression.

### Loop #48: host key pinning, in the live client

Loop #47 proved the client refuses a peer's key exchange when the exchange does
not hold up. Both of its forgeries are **inconsistent**: the blob does not
prove the signature. What they cannot reach is the attack that matters in
practice -- a man in the middle with its own key and its own perfectly valid
signature. That exchange is entirely self-consistent, so every signature check
passes. Only comparing the presented key against the expected one stops it.

**And the live client was not doing that at all.** `src/kexflow` carries the
rule (`check_host_key_strict`), and both live adapters implement their own
handshake without going through kexflow -- so on the client that actually
connects, host key pinning had never executed. The rule existed, was
unit-tested, and was unreachable. Reading "the rule is written" as "the rule
runs" is the specific mistake this loop closes.

**The rule stayed in one place.** `KnownHostsPolicy` / `PinVerdict` live in
`src/knownhosts`, next to `agrees_with_alg`'s reasoning and for the same reason:
a rule copied into two transport adapters is a rule that eventually exists in
one of them only. The adapters each translate the verdict into their own error
variant and nothing else -- `HostkeyMismatch(String)` and `HostkeyUnknown(String)`
in both, which Loop #44's anchors then hold together.

**`Skip` and `Accept` are different verdicts on purpose.** "Checked and
consistent" and "never checked" collapse to the same value in a Bool, and a log
that says everything was verified would be lying. Keeping them apart is what
lets a caller -- and a gate -- tell them apart.

**Five cases per client, and the set is the point.** One man in the middle,
presenting one self-consistent key, told different things about what to expect:

| case | what the client is told | expected |
|---|---|---|
| match | pin the key actually sent | authenticate |
| mismatch | pin a different key | refuse, send nothing |
| unknown-strict | pin another host, strict | refuse, send nothing |
| unknown-tofu | pin another host, non-strict | authenticate |
| no-policy | nothing at all | authenticate |

The last two look like failures and are not. They are here to pin down the
policy actually in force -- **pinning is opt-in, and an unpinned host is
accepted**. OpenSSH's default is the opposite. Writing that down as *passing*
cases is what keeps the gap visible instead of quietly closed by somebody
assuming it had been handled.

**The matching case's known_hosts line is built from the transcript, not from a
file in the repo.** The man in the middle reports the blob it presented
(`hostkey_blob_b64`), so the line that should match is derived from what the
peer actually sent. A pinned file would go stale the moment the key was
regenerated, and the stale file reads as a mismatch -- which looks like a
protocol bug and is a fixture problem.

**known_hosts arrives as text, not as a path, and that was forced.** This moon
version's core has no file-reading API (`@env` is argv / env / time), nothing in
the repo reads files, and `src/wt` is js-only where a browser has no filesystem
at all. A "read the known_hosts file" option that only works natively would
split the two adapters into different behaviours -- the exact drift this repo
keeps paying for. Text works in both, and it is what a browser application
actually has. Both drivers call one `KnownHostsPolicy::from_text`.

**A policy that parses to nothing is refused, not skipped.** `--known-hosts-text`
with zero parsed entries would otherwise become a silent `Skip`, which is the
worst possible outcome: a check that looks like it ran and did not.

**Two mutations, both caught.** Reporting a mismatch as a match, and discarding
the verdict in `src/sshclient`, both turn the gate red. Only the browser half of
the second is left standing on purpose -- the point of a shared rule is that one
adapter can be mutated without the other covering for it.

**The mutation driver undoes itself, and that is not optional.** It snapshots
every file it touches and restores from the snapshot. The first version was
debugged by hand with `git checkout -- src/sshclient/live.mbt`, which -- because
the loop's own uncommitted work sat in that same file -- silently undid the work
too. The loss was invisible: the file still compiled. The same mistake then
recurred on a second file, and for a while the driver reported the browser half
failing under a mutation that only touches the native adapter. That result was
impossible, and the cause was not a hidden dependency between the adapters but a
tree that was not what it was believed to be. **A mutation is never undone with
git unless it was committed first**, and when a result is impossible, suspect the
tree before suspecting the code.

**Verified:** `ALL PASS (15 checks)`. `verify_loop47` 19, `verify_loop46` 53,
`verify_loop45` 51, `verify_loop41` 29, no regression.

### Loop #47: a peer that lies about its host key

Every handshake test in this repo had talked to a peer that told the truth.
Loop #38 pinned the host key algorithms against a real sshd; Loops #34-#40 and
#43-#46 all completed handshakes against a man in the middle whose host key was
correct. So `HostkeyInvalid` and `SignatureInvalid` were **defined in both
transport adapters and driven by nothing** -- reachable only by a peer whose key
exchange does not hold up. That is the most security-relevant gap left in the
client, and it took a wrapper object to close.

**One wrapper, no cryptography of our own.** paramiko builds both halves of
`KEXDH_REPLY` from a single object -- `kex_ecdh_nist.py` reads
`get_server_key().asbytes()` for the blob and `get_server_key().sign_ssh_data()`
for the signature -- so `LyingHostKey` splits them: `asbytes()` returns key A,
`sign_ssh_data()` signs with key B. Both keys are real paramiko keys and both
signatures are made by paramiko; the only thing invented is *which* of them
answers which half.

**Two forgeries, because they are different rules on different branches:**

| MITM flag | the lie | the branch it must reach |
|---|---|---|
| `--lie-hostkey` | blob A, signed by B | `SignatureInvalid` |
| `--lie-hostkey-type NAME` | a real blob announced as another type | `HostkeyInvalid` |

Driving only one leaves the other untested, and they are not interchangeable:
the client checks the type *before* the signature, so `--lie-hostkey-type` never
reaches the signature check at all.

**The assertion is not "the client reports an error" -- it is that no
credentials left.** An implementation that logs an error and authenticates
anyway has leaked the thing the error was about. So the man in the middle counts
the authentication attempts it is asked to approve, and the gate asserts that
count is zero, along with zero channel requests. It approves everything by
design (Loop #45's decision), so it cannot notice a client that should not have
arrived -- it has to be told. The counts are written into the transcript before
anything can fail, so "zero" is a measured `0` and never a missing key.

**`--auth` is the mode to drive on purpose**: its success condition *is* reaching
authentication, so a verification hole shows up as the run succeeding where it
must fail.

**A control run is not optional.** Three clients that refused everything would
satisfy every check above, so each client also runs against an honest man in
the middle and must authenticate. The refusals and the control are one
measurement from two ends.

**Three clients answer the same question, and the third is not ours:** paramiko
(`host/hostkey_witness.py`, a real client that was written by somebody else, so
the expectation is not "whatever MoonBit does"), `cmd/ssh_live --auth` over TCP,
and `cmd/wt_ssh` (`auth: 1`) in a browser Worker over WebSocket. The error name
is compared by its **leaf** -- `cmd/ssh_live` renders
`transport:handshake:SignatureInvalid` and `cmd/wt_ssh` renders
`handshake:SignatureInvalid`; the prefixes are two renderings of where it
surfaced, and the leaf is the part the rule produced. Both transports must agree
on the leaf.

**Two mutations, and the second one found a defect in the gate itself.**
Never rejecting a bad ECDSA signature, and always agreeing with the negotiated
algorithm name, both fail the gate -- and the second fails as a *branch
fall-through* (`HostkeyInvalid` becomes `SignatureInvalid`) while the security
property still holds, which is the argument for asserting both.

The first mutation also exposed the reason this loop needed its own gate rather
than an extension of `verify_loop45.mjs`: `verify_loop47.mjs` originally built
only `cmd/ssh_live --target native`, so the browser half ran a `wt_ssh.js` left
over from whenever it was last built and **kept passing** against mutated
source. A gate that can report PASS for a tree it did not compile converts a
caught regression into a silent one -- and the browser half is the half this loop
exists to cover. Both halves are now rebuilt on every run.

**The browser plumbing is shared, not copied.** `host/wt_browser.mjs` holds the
HTTP server, the page, the Worker driver and the Worker's `Event` rendering that
`verify_loop46.mjs` and `verify_loop47.mjs` both need. Two copies of a *rule*
is the duplication this repo keeps paying for (see Loops #41/#45); there is no
reason to start paying for it in the plumbing too.

**Verified:** `ALL PASS (19 checks)`. `verify_loop46` 53, `verify_loop41` 29,
`verify_loop45` 51, no regression.

### Loop #46: the same vectors, in a browser Worker

Loop #45 left exactly one adapter undriven. `src/sshclient` had a man in the
middle in front of it; `src/wtlive` did not, and the stated reason was that
`src/wt` speaks **WebTransport**, which needs a publicly trusted certificate --
Chromium rejects a locally-added one on the QUIC path with
`QUIC_TLS_CERTIFICATE_UNKNOWN` no matter which override flag is set.

**The reason was half right, and the useful half was in `src/wt`.** It picks its
transport from the URL: `ws://` opens a `WebSocketStream`, anything else opens
WebTransport (`host/wt/moonbit_wt.js`). A `ws://` URL carries exactly the same
bytes, so everything above the transport is exercised identically -- no change
to `src/`, no new cryptography, and the WebTransport limitation stops being a
limit on what can be *tested* rather than on what can be *shipped*.

```
browser Worker (MoonBit js, src/wtlive) --WebSocket--> wt_mitm_bridge --TCP--> sftp_mitm.py
```

`host/wt_mitm_bridge.mjs` is `host/wt/ws_relay.py` with a different upstream,
which is deliberate: the relay is already proven against a real sshd, so the
browser half is not a new thing being trusted for the first time. It forwards
bytes and **parses nothing** -- no SSH, no reassembly, no counting. Any of those
would be a second implementation of something that already has one, and a place
for a transcript to be quietly wrong in a way the gate could not see.

**The rendering is `cmd/wt_ssh`'s own, and the gate undoes it instead of
forcing it to match.** `wt_print_sftp_op` prints `op0: REALPATH` plus
`op0_hex: ...` rather than `cmd/ssh_live`'s single rendered line, because its
alignment with `ssh_live` line for line *is* Loop #39 G5's assertion. Changing it
to make this gate simpler would have deleted the thing the earlier gate
measures, so the third gate parses the multi-line form back into the shape the
other two compare. That is a different trade from `verify_loop41` and
`verify_loop45`, which each ported the renderer: those compare rendered strings
to rendered strings, this one compares parsed fields, so the duplication is
smaller and there is nothing to cross-check against a generated table.

**Hex case is a rendering choice, not a protocol fact, and the two drivers make
opposite ones.** `cmd/wt_ssh` prints through `@ecdsa.bytes_to_hex` (uppercase);
`cmd/sftp_mitm` has its own `to_hex` (lowercase). `wt_ssh` is the one that is
right -- `wt_dump_prefix` is deliberately aligned with `cmd/ssh_live` -- so the
gate folds case on the **hex fields only**. Folding the whole rendered string
would also hide a case change in `realpath=` itself.

**Requests are compared by count, not by bytes.** In the TCP run the framing is
the client's, so the concatenated stream is comparable; a browser's WebSocket
chunks it however it likes. Counting still catches the failure that matters --
a client that never sends its requests, or sends the wrong number.

**Four harness lessons, every one of them a failure that pointed somewhere
else:**

1. **`worker error: [object Event]` was a 404, twice over.** `serve()` called
   `readFile`, which was never imported, so *every* static request raised a
   `ReferenceError` and answered 404 -- the page, the Worker script, everything.
   A Worker's `onerror` for a script that never loaded receives a DOM `Event`
   with no `.message`, no `.filename`, and `String(ev)` is the literal
   `"[object Event]"`, so the cause was nowhere in the output. Two changes make
   that class of failure impossible to hide again: the Event's fields are copied
   into a plain object and rendered by name, and the page records every
   `response >= 400` and every `requestfailed`, so a missing asset is a visible
   `404 <url>` instead of an opaque Event.

2. **`page.evaluate` carries no Node scope.** The formatting helper was defined
   beside the gate and referenced inside the evaluated function, so the page
   raised `ReferenceError: describeEvent is not defined` -- while the gate went
   on to report a *worker* failure, one layer away from the actual cause. The
   browser side now copies fields out and Node formats them; no `eval` of a
   stringified function.

3. **The gate hung up on the MITM before it finished writing.** `sftp_mitm.py`
   records its transcript when the session thread returns, and three scenarios
   were reported as `the man in the middle recorded nothing` -- which reads as
   a protocol failure. It was a race: the child was killed the instant the
   Worker's result arrived. The order is the dependency's order -- close the
   bridge, the MITM sees the socket end, the thread returns, the transcript is
   written -- and only then is a kill still needed.

4. **A wrong field name reads as a protocol divergence.** The parser asked for
   `op0_path_hex`; `wt_print_sftp_op` prints `op<i>_hex` for the bytes and
   `op<i>_path` for the length. The failure was
   `got ["realpath=undefined"] want ["realpath=2f"]`, which is indistinguishable
   from `src/wtlive` returning something else.

**Verified:** `ALL PASS (53 checks)` -- the same 10 scenarios x 5 cut points
`verify_loop45` runs, every one of them a real SSH handshake, but driven from a
browser Worker over WebSocket. The bytes above the transport are now proven
identical across both adapters: a window rule changed in one file, or a pump
forgotten in the other, shows up here as a transcript that differs from
expectations `verify_loop45` already proved.

**What it does not retire.** The WebTransport path itself is still untested
locally -- that needs a publicly trusted certificate, not a flag -- so what is
proven is everything above the transport, on the WebSocket carrier.

### Loop #45: the fault vectors over a real socket (the MITM)

Loop #44 stated the limit plainly: `run_sftp_session` is private in both
adapters and starts from a post-authentication session state, so **no
malformed byte could reach a transport adapter**. This removes that limit.

**`host/sftp_mitm.py` is paramiko in _server_ mode.** Key exchange, cipher
setup, NEWKEYS and userauth are a real SSH implementation doing real crypto --
none of it re-derived, none of it trusted. What it does *not* do is speak
SFTP: once the client asks for the `sftp` subsystem, it acknowledges the
request and writes a scenario's bytes straight onto the channel. There is no
`SFTPServer` anywhere in the file, and no code path that could grow one by
accident -- the peer is wrong on purpose.

It accepts **any** public key. That is a decision, not an oversight: the thing
under test is what the client does with SFTP bytes *after* authentication, and
a key check would be testing `src/userauth`, which Loop #34 and the live sshd
gate already cover.

`cmd/sftp_mitm` is the other end: a real TCP connection, a real handshake, the
real `live_sftp`. Native by necessity -- `live_sftp` takes a `@tcp.TcpConn`.

**The expectation does not change**, and that is the whole claim: the SFTP
layer cannot tell whether the bytes came from a real `internal-sftp`, a fake
peer in-process, or a man in the middle over a socket. Same vector table, same
oracle, same cut points.

**Two transcripts are compared, against different things on purpose.** The
client's own report (version / results / done-or-failed, plus the
`Protocol(<reason>)` string a failed session reports) against the expectations;
and *the bytes the MITM saw the client send* against the expected request
frames. The second is the one that would catch a transport that mangled what
it sent -- a window clamp that over-sends, a subsystem request that leaves
before the confirmation -- and the client's own report cannot see that, because
a client has no idea what went out before the channel closed.

**Three harness lessons, all of them wrong-looking failures:**

1. **CRLF silently turns a match into no match.** The gate reported
   `results: got []` for scenarios that were demonstrably producing the right
   answer when run by hand. In a JavaScript regular expression `.` does not
   match `\r` -- it is a line terminator, alongside `\n` -- so
   `^op\d+: (.*)$` without the `m` flag can never match a CRLF line, and the
   failure is **no match**, not a wrong value. An empty list reads as "this
   scenario produced nothing", which points at the SFTP layer. `verify_loop39`
   has normalized CRLF since Loop #38; the rule travels with the repo, not with
   whichever file happened to remember it.

2. **Comparing a raw tuple to a rendered string, a second time.** The oracle
   stores a result as `["realpath", "/C:/Users/hp"]`; the client prints
   `realpath=2f433a2f55736572732f6870`. `verify_loop41` made this exact
   mistake and fixed it; `verify_loop45` made it again, because it is a new
   file with a new author and the shape looks obviously compatible until it
   does not. The fix is the same, and the cross-check against the *generated*
   `cmd/sftp_mitm/vectors.mbt` is what keeps the second port honest.

3. **The MITM must re-frame correctly or every transcript differs for the
   wrong reason.** Re-assembling the client's requests re-attaches the length
   prefix, and the length does **not** count itself
   (`put_u32(mlen, sshbuf_len(m))`, sftp-client.c:160-161). Writing
   `len(body) + 4` produced transcripts that differed from the expectations by
   exactly four -- a difference with nothing to do with the fault being
   injected, and one that would have been reported as a transport bug.

**Verified:** `ALL PASS (51 checks)` -- 10 scenarios x 5 cut points, every one
of them a real TCP connection, a real key exchange and a real userauth against
the man in the middle. Three of the ten end in `Failed`, and their
`Protocol(<reason>)` strings are compared rather than merely logged, so the
path from a malformed reply to a reportable outcome is checked end to end.

**It is a separate gate** (`node host/verify_loop45.mjs`), not a step inside
`verify_loop41.mjs`, because it is by far the slowest thing in the repo: 50
sessions, each a full handshake. Folding it into the fast gate would make
every iteration pay for it.

**What it retires.** `host/verify_transport_parity.py` (Loop #44) exists
because nothing could reach an adapter. Now `src/sshclient` can be driven
directly. `src/wtlive` could not -- it needs WebTransport, not TCP -- so at this
point the parity gate still carried the browser half alone. Loop #46 put the
same vectors in front of `src/wtlive` over a WebSocket carrier, which closes
that; the parity anchors are now checked against real coverage on both sides.

### Loop #44: keeping the two transport adapters in step

**What could not be tested then, and no longer cannot.**
`run_sftp_session` is private in
both `src/sshclient/sftp.mbt` and `src/wtlive/sftp.mbt`, and both take a
*post-authentication* session state as their entry point. So the only way to
hand either adapter's loop a malformed reply is to speak enough of the SSH
handshake to get there -- a MITM server implementing the server side of kex and
userauth. Until Loop #45 built that, **no malformed byte could reach a
transport adapter**, and any claim that the fault vectors covered the
transports would have been false. They cover `SftpSession` and `ChanState`,
which is where Loop #43 drew the line.

**So the anchors below are a stopgap, not a permanent answer.** Once the MITM
drives both adapters, this gate can retire; until it does, it is what stands
between a one-sided edit and a divergence nobody would notice.

That leaves the actual risk: two files, two edit sites, and a rule that exists
in both. Loop #39's G5 proves the browser side works against a real
`internal-sftp`; Loop #43 proves the state machine and the channel layer hold
under ten malformed replies. **Neither can catch "someone changed the window
rule in one file and not the other"** -- the happy path never fills the
window, and the fault vectors never reach either adapter's loop.

**Why anchors and not a diff.** A normalized diff of the two files is ~145
lines of *legitimate* difference: the auth entry points genuinely differ
(native takes a `subsystem` parameter and gets its state from
`live_auth_with_state`; wtlive hardcodes `"sftp"` and gets it from
`wt_auth_into`), one is sync and one is async, and the send/receive calls have
different names. Such a check fires on every correct edit and gets muted on
the next one.

`host/verify_transport_parity.py` instead pins the smaller claim: **each of
fifteen load-bearing statements must still be present in both files.** It only
goes red when a rule is actually removed, each anchor names the decision rather
than a line number, and the anchors are *statements* -- deleting the comment
that explains a rule does not satisfy it. Verified by deleting
`if stuck && rest.length() > 0 {` from the wtlive copy: the gate reported
exactly that one rule and named the file.

The fifteen: wait for OPEN_CONFIRMATION; wait for CHANNEL_SUCCESS on the
subsystem; the subsystem request itself; requests through the peer's window; a
full window pumps before giving up; a bound on rounds; a bound on the clamp
spin; an unparsable CHANNEL_DATA is an error; the parsed payload reaches the
session; the session is pumped every round; only 0x5e carries data; the
session's failure reason is surfaced; EOF on the clean path; both byte
counters.

**The last one is annotated, not just listed.** `st.counters.recv` counts the
*encrypted stream from the server* and carries WINDOW_ADJUST timing, which is
load-sensitive -- Loop #42 defect 4 exists because `verify_loop36` compared it
cross-transport. The anchor requires the counter to be *reported* in both
files while the exclusion stays a cross-transport rule; the reason sits next
to the anchor so the next person to "fix" loop36 finds the argument.

### Loop #43: the same fault vectors through the channel layer

Loop #41-M2 fed malformed bytes straight into `SftpSession::feed`. That proves
the state machine. It says nothing about the layer below it, and the layer
below is where the risk actually lives:

- `ChanState::stdin_take` clamps each outbound packet to
  `min(remote_window, remote_max_packet)` (RFC 4254 §5.2), so a request is
  routinely split across several CHANNEL_DATA.
- the CHANNEL_DATA boundary is **not** an SFTP packet boundary -- that is the
  entire reason `src/sftp/stream.mbt` exists.
- `src/sshclient/sftp.mbt` and `src/wtlive/sftp.mbt` are two near-identical
  files. Deliberately (they hold no protocol), but still two files.

**`cmd/sftp_fault` is a fake peer.** It answers CHANNEL_OPEN_CONFIRMATION and
CHANNEL_SUCCESS, delivers each vector's payload as CHANNEL_DATA **re-sliced at
four cut points** (1, 3, 7, 64 bytes), and reads our requests back out of the
CHANNEL_DATA the client framed them into -- reassembled through `SftpInbuf` and
re-framed with `sftp_frame`, because `drain` hands back bodies while the
vectors record whole frames.

**The invariant under test is the one `stream.mbt` exists to hold:**

> the CHANNEL_DATA cut point must not change the answer

Each chopped run is asserted against the whole-payload answer *and* the
expectation, not just the expectation -- comparing a chopped run to the
chopped expectation would let a shared error pass twice. The oracle
(`host/sftp_fault_oracle.py`) proves the same invariant independently before
it will emit the vectors at all.

**Verified:** `ALL PASS (50/50 runs, 10 scenarios x 5 cut points)` on all four
backends with the same verdict, and byte-identical between js debug and
release. 5 mutations all caught (`host/sftp_fault_mutations.py`).

**Two driver bugs this found, both of which pass the un-sliced case:**

1. **Never feeding the session.** `chan_step` advances the *channel*; handing
   the payload to the state machine is the driver's job (`pump_once` does it
   right after the step). A driver that only steps the channel leaves the
   session waiting for a reply that arrived. Symptom: every scenario hangs at
   VERSION with exactly one request emitted -- INIT.
2. **Comparing bodies to frames.** `SftpInbuf::drain` consumes the length
   prefix and never returns it, so the peer reported `0100000003` where the
   expectation said `000000050100000003`. The fix is to re-frame with
   `sftp_frame`, which is the one function that owns framing.

Both are now mutation cases, so they cannot come back quietly.

**One mutation was deliberately dropped rather than left failing.** "Consume
the bytes of a refused packet anyway" changes `take()` on a path that returns
`None` immediately afterwards (`self.failed` latches), so nothing this gate
observes can move -- dropping four bytes no one reads is not a difference. It
is not a hole in the gate: `cmd/sftp_test` already asserts it, as
`length_over_max_refused` with `expect_pending: 13`. Listing it here would
have produced a MISSED that said nothing about `cmd/sftp_fault`.

**The mutation script distinguishes four verdicts,** because conflating them
is how a mutation list quietly stops meaning anything: `NOBUILD` (the mutated
source did not compile -- nothing was proven either way, and calling it
MISSED would point at the gate), `CRASH` (it compiled and blew up -- caught,
because a gate that cannot survive the mutation still noticed it), `CAUGHT`
(a named check went FAIL), and `MISSED` (it ran and everything still passed).
The first draft had only two, and the "forget `want` after a short feed"
mutation arrived as `PanicError` -- which under a two-valued scheme is
indistinguishable from "no output at all", and would have been reported as a
gate hole.

### Loop #42: three harness defects behind one impossible verdict

`verify_loop40`'s regression reported `FAIL loop39 still passes` with the
detail line `ALL PASS (44 checks)` -- a gate that passed everything and
failed anyway. Three defects were stacked under that one line, and none of
them was in the code any loop tests.

**1. A shadowed variable that only exploded on success.**
`verify_loop39.mjs`'s G2 declared `const skipped = <SKIP-line count>` inside
`main()`, shadowing the global `skipped` **array** (line 61) with a Number
for the whole function. The ending's `for (const s of skipped)` then threw
`TypeError: skipped is not iterable` -- but only on the ALL-PASS path,
because the failure path returns 1 without ever touching it. So loop39
printed ALL PASS and exited 1; every run with a real failure had shown a
clean FAILURES summary, which is what made the verdict look impossible.
Renaming the counter `skippedCount` is the whole fix.

**2. A mutation batch that died mid-run with no traceback.** The nested runs
also showed loop37 at `46/47` with `5 caught, 0 missed` -- five CAUGHT lines
and then silence, no MISSED, no SKIP, nothing. `channel_mutations.py`'s
`run_kat()` used `text=True` with no explicit encoding, so moon's output was
decoded with the locale codec (cp936 here); one box-drawing character the
compiler prints on a cold-build diagnostic path raised
`UnicodeDecodeError` inside the batch loop, the `finally` restored the
sources, and the child died with its stdout buffer unflushed -- leaving
exactly the five lines that had made it out. Single runs on a warm `_build`
printed pure ASCII and could not reproduce it, which is why it looked like a
timing flake. The fix is three independent belts: `encoding="utf-8",
errors="replace"` (the decode can never raise), `flush=True` on every batch
line (what is printed is delivered), and an explicit 64 MiB `maxBuffer` on
the spawnSync side (the 1 MiB default is one cold build away from killing
the child for a different reason).

**3. Nested failures that discarded their own evidence.** loop38 captured
each child gate's full output and kept only a 200-char summary; loop39 kept
400 chars; the gate file kept one line. Diagnosing defect 2 required three
level-deep re-runs on a warm machine and a hope. Both `verify_loop38.mjs`
and `verify_loop40.mjs` now write each failed child's complete output to
`.loop38/last_<label>.log` / `.loop40/last_loopN.log` (gitignored,
overwritten each run) at the moment the failure is detected -- the failure
and its evidence land together, and one run is enough.

**4. An assertion on the wrong half of the stream.** With 1-3 fixed, the
next full nested run exposed a fourth defect that had been hiding behind
them: `verify_loop36.mjs` asserted `total_recv_bytes` cross-transport --
the **encrypted stream from the server**, which carries WINDOW_ADJUST
timing. Under nested load the server answers a window-consuming shell with
one extra 80-byte adjust (correct behavior), and the gate read it as a
transport bug. The Loop #40 gate excludes `total_*_bytes` from
cross-transport comparison for exactly this reason; loop36 predates that
rule. It now keeps `total_sent_bytes` -- the half that is ours and is
byte-exact -- and drops the recv side, with the rationale in a comment.

**Method note, because it is what found defect 1.** The impossibility
("ALL PASS and failed anyway") was chased by treating the two halves as two
different bugs -- which they were: defect 3 made the evidence invisible,
defect 2 supplied the flaky red, and defect 1 turned the green path red too.
Defect 4 only surfaced once 1-3 stopped flaking. Each fix was verified
against the next full nested run, not against a warm single run -- a warm
single run is what made defect 2 invisible for weeks.

