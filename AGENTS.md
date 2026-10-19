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
  unrelated legacy files.
  **The CJK half of this note did not reproduce and Loop #67 removed it.**
  It read: "`moon fmt` in write mode alters CJK comments (it turned
  `真实加密` into `真加密` in `src/sshclient/moon.pkg`)". On
  `moon 0.1.20261012` the damage is not there. Measured three ways, all
  before running write mode over anything: (1) the formatter's own output
  already sits in `_build/<target>/release/format/`, and all 366 CJK runs in
  `cmd/channel_test/main.mbt` are byte-identical between source and that
  output; (2) after formatting 12 files that needed it, all 373 CJK runs
  across them were unchanged; (3) after formatting the whole tree — 267
  files — `host/cjk_snapshot.py` compared all **12,840** CJK runs across 226
  files against a snapshot taken beforehand and found zero difference.
  The scope rule above stays, because the reformats are real; the CJK
  warning did not. `host/cjk_snapshot.py` is the standing guard: snapshot
  before any whole-tree format, `check` after, and it exits 1 if a single
  CJK run is lost or gained. What the old incident actually was is not
  recorded, and guessing is how a wrong rule survives for a dozen loops —
  the file it named no longer contains the string.
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

### Loop #69: a gate that dies at exit is not a pass, and a red step whose evidence was thrown away is not a bug report

GitHub run `39194939821` was the first run on the Windows runner to get past the
engine's own accounting, and it failed 18 of 47 steps. The interesting part is
not the 18. It is that **the log could not explain them.**

#### Defect 1: the engine keeps 12 lines, so a 928-second failure arrives as a fragment

`ci/ci.py` stored `lines[-12:]` per step and that was the whole record. Measured
on that run: `verify_loop45` burned **928.7s** and the surviving text ended at
`import paramiko`. Every follow-up question -- which fixture, did it build, was
the port taken -- needed a fact that had already been discarded, and the only
way to get it back was another 25-minute run.

This is **Loop #42's defect 3, one level up**. That loop fixed nested gates that
kept a 200-char summary and lost the rest; the fix was to write the failing
child's whole output to disk *at the moment of failure*. The CI engine has been
doing the same discarding ever since, and nobody noticed because a summary is
the right size for reading a green-ish run and the wrong size for reading a red
one.

A failing step now writes its complete stdout to `ci/artifacts/steps/<name>.log`
and `ci.json` carries a `full_log` key pointing at it. Passing steps write
nothing: an artifact full of green noise is an artifact nobody opens. The
workflow uploads the whole directory, not just `ci.json`.

The new self-check case is the one the defect is about -- a step that fails
*after* printing more than 12 lines, asserting the dropped **first** line is on
disk. Checking that a file exists would pass against a 12-line tail that happens
to be written. Engine self-check **24/24**.

#### Defect 2: two environment facts, both of which the workflow asserted were unnecessary

`ModuleNotFoundError: No module named 'paramiko'` and `'cryptography'` account
for ~11 of the 18. The Python MITM peers (`host/*.py`, `host/sftp_mitm.py`) are
not vendored and the runner's Python has neither.

The workflow carried a comment explaining why Playwright browsers were *not*
installed: "the gates that drive a real browser are peer-gates and do not run in
this tier". That reasoning is wrong in the same shape as the comment above it in
the same file -- it assumed a fact about the tier assignment instead of
measuring it. `verify_loop47` is in the **default** tier, reaches Playwright
unconditionally at startup, and takes a different code path when the binary is
absent:

```
Executable doesn't exist at ...\ms-playwright\chromium-1124\chrome-win\chrome.exe
SKIP  the Worker run
FAIL  harness  ReferenceError: Cannot access 'only' before initialization
```

Two lessons worth keeping. First, a comment justifying an omission is a claim
that can rot, and it rotted silently for two runs. Second, **the reason a
comment gave for skipping a step is not evidence that skipping was right** --
that is the whole reason this repository stopped curating lists and started
re-deriving them at runtime.

#### Defect 3: `host/sshd_setup.mjs` knew one developer's install prefix

```js
const SSHD_BIN = 'C:\\Program Files\\OpenSSH-Win64\\sshd.exe';
```

That is the portable Win32-OpenSSH build, installed on the machine these gates
were developed on. A GitHub `windows-latest` runner has the *inbox* Windows
feature instead, at `C:\Windows\System32\OpenSSH`. So every gate that needs a
server (loop31, 40, 47, 48, 50, 51, 54, 55, 62, 65, 66) died on a runner that
had sshd perfectly well.

It now probes three known locations and takes the first that exists, and when
none does it says so once, by name, before spawning anything -- instead of an
ENOENT from inside `spawn`, which reads as a bug in this file rather than as
"this machine has no sshd server".

**A hardcoded absolute path in a gate helper is a claim about the machine, and
the machine is not the repository.**

#### Defect 4: `verify_loop41` printed ALL PASS and then crashed

```
ALL PASS (29 checks)
node : Assertion failed: !(handle->flags & UV_HANDLE_CLOSING), file src\win\async.c, line 76
EXIT=-1073740791
```

Reproduced locally at roughly **1 run in 4**; on run `39194939821` it is why
`verify_loop41.mjs` failed in 2.6s. The cause is a genuine race:
`cleanup()` called `child.kill()`, `cdp.close()` and `process.exit()` with
nothing awaited between them. `kill()` only *requests* termination and
`WebSocket.close()` only starts the closing handshake, so `process.exit()` tore
the loop down while libuv was mid-close on both handles.

`cleanup()` is now async and waits for the socket and the child to actually
close; the tail sets `process.exitCode` and lets the loop drain, with an
unref'd 10s timer as the escape hatch for a handle nobody remembered. Verified
**5/5 clean runs**, but the honest statement is that a race proved by 5 passes
is not proved -- what makes this more than a lucky streak is that the
`process.exit()` that was racing has been *removed*, not merely retried.

**No mutation was added for it, deliberately.** A mutation that reproduces a
1-in-4 race cannot be relied on to fail, and a mutation that cannot be relied on
to fail is worse than no mutation -- it sits in the count looking like coverage.
Same reasoning as Loop #68's deleted `MOON_COVE_REPORT_ENABLED` variant.

#### Still open

`verify_loop57/58/59` (ssh_config) failed on the runner with keywords reported
"not resolved" and one fixture's `IdentityFile` resolving to `/cli/key|/tmp/a`
instead of `/cli/key`. All three pass locally against
`OpenSSH_for_Windows_9.5p2`. `/tmp/a` is a value that exists in
`verify_c/sshconfig/syntax.conf` and in no other fixture, so the runner is
resolving a *different config* than the gate wrote. Not yet understood; the full
per-step output from defect 1 is what will settle it on the next run.

### Loop #70: the rule that was never in the repository, and the guard that was narrower than the failure

Run `39200128854` failed 10 of 47. Six of the ten had one cause, and the cause
was a rule this repository believed it had.

#### The finding: `core.autocrlf` lived in one developer's home directory

`verify_loop67` has guarded line endings since it was written. Its verdict on
the runner was:

```
FAIL  no source file is CRLF where the formatter emits LF
      CRLF files remain: cmd/aes_test/main.mbt, cmd/aes_test/moon.pkg,
      cmd/bench_cached/main.mbt, ... (essentially the whole tree)
```

The rule that should have prevented it was never in the repository. It was:

```
git config --global core.autocrlf false
git config --global core.eol lf
```

**A global git config does not travel with a clone.** Git for Windows defaults
to `autocrlf=true`, so `actions/checkout` on `windows-latest` wrote CRLF over
the entire tree while the developer got LF from the same commit. The gate that
exists to prevent this watched the whole time.

This is Loop #69's `SSHD_BIN` lesson one layer over, and the general form is
worth stating once: **a claim about the machine that is not written down in
the repository is not a rule -- it is a coincidence that happens to hold on
yours.**

#### Six gates, one line ending

| gate | what the run showed | why |
|---|---|---|
| loop67 | whole tree CRLF | the guard, reporting |
| loop57 | `values match ssh -G 0 keyword(s)`, all 8 cases | `src/sshconfig/parser.mbt` has **no `\r` handling anywhere**, so `Host *.example.com\r` matches nothing and the MoonBit side resolved **zero** keywords |
| loop58 | same, 8 of 13 cases | same resolver |
| loop56 | `SHA-1(b'')` failed, `b'abc'` passed | the empty input vector was the one carrying a stray `\r` |
| loop62 | `[7713 vs 7621 bytes]` | 92 bytes = 92 lines' worth of `\r` |
| loop66 | `only 0 entries carry a reason string` | the accept table broke on its reason field |

The loop57/58 shape is the one worth remembering: **the MoonBit side resolved
nothing while `ssh -G` -- C, and therefore tolerant -- answered everything.**
One side all-correct and one side all-empty is a shape only a line ending
produces, and it is worth naming that shape before spending an hour on config
precedence.

loop62 had a second-order effect worth recording: the generator writes in Python
text mode, so on Windows it **rewrote the committed file while asserting the
file was byte-for-byte reproducible**. The gate was modifying the thing it was
measuring.

#### What the fix is, and why it is not `text=auto`

`.gitattributes` pins `eol=lf` rather than relying on `text=auto`. `text=auto`
alone leaves the *checkout* conversion to `core.autocrlf` -- which is exactly
the setting that was wrong. Pinning `eol=lf` makes the working tree LF whatever
the machine's git believes.

`*.bat` is the deliberate exception, and not for looks:
`verify_c/build_poly1305.bat` contains `goto :check`, and cmd.exe label
resolution is not reliable in an LF-only batch file. Normalising those to LF
would have traded a class of CI failures for a class of local ones.

Renormalising then rewrote **9 blobs that were stored as CRLF** -- which is how
they got that way: they were never covered by loop67's guard, because that guard
only looked at `*.mbt, *.pkg, *.moon`. The diff is 4349 insertions and 4349
deletions and is **empty under `--ignore-cr-at-eol`**: the catastrophic-looking
whole-file rewrite that contains no change, which is precisely what loop67's own
comment describes.

#### A guard has to be at least as wide as the thing it guards

loop67's CRLF check was 342 files wide and the failure it exists to prevent
involved 765. It stayed green through all six gates it should have caught,
because every file that actually broke was a file it did not look at.

It now walks `git ls-files` with no extension filter, and **derives its
exceptions from `.gitattributes` rather than restating them**, so the two
cannot drift: add `*.foo text eol=crlf` and the guard learns by reading rather
than by being edited. 765 tracked files, 1 CRLF exception, 3 binary.

The first version of that matcher was wrong in an instructive way: it treated
the `*` in `*.wasm` as a **trailing** wildcard (`p.endsWith("*")`), which matches
nothing, so the check reported a `.wasm` file it had just been told to ignore.
Git attribute globs match by a **leading** star.

**Verified:** `loop70_mutations.py`, 2 CAUGHT / 0 MISSED.

- **M1** -- CRLF in `verify_c/ed25519_ref.c`. Must go red and name the file.
  This is the mutation that *justifies the widening*: the old guard was blind
  to it by construction.
- **M2** -- LF in `verify_c/build_poly1305.bat`. Must stay **green**. Without
  it, an exception list that matches everything would pass a test that only
  proves the guard is on.

#### The evidence chain has a hole at every layer that summarises a child

Loop #69 fixed the engine, which keeps 12 lines. Then run `39200128854` showed
the same disease one level down, in three places at once:

```
verify_loop41          FAIL moon build  Error: failed to run build for target Native
                       -- and not one line of the compiler's complaint
verify_loop55          BUILD FAILED / The system cannot find the path specified.
                       -- the kept line is the batch's own echo, not cl's error
probe_sshd_leak        the sshd never came up -- sshd's own stderr was discarded
                       by `inner.stderr.on('data', () => {})`
```

`host/keep_output.mjs` makes the fix a one-call change: the summary still
prints, the full transcript goes to `.loop70/<label>.log`. Wired into those
three call sites.

Note what loop41's failure actually was: the build died in **3.0 seconds**, so
it could not have been a compile error. Loop #69's libuv race was real and is
reproduced locally at ~1 in 4, but **it is not what CI hit** -- CI hit a build
that fails immediately. Two different defects; reporting only the local one
would have been reporting the one that could not explain the run.

#### Still open, and deliberately not fixed here

- **loop55** -- `The system cannot find the path specified.` Root cause found
  and it is not CRLF: all **9** `verify_c/build_*.bat` scripts begin with
  `set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe`. A second
  instance of the hardcoded-machine-path defect, in nine files at once. Loop
  #69 fixed one such path and proved nothing about the other eight.
- **loop41** -- the native build of `cmd/proton_gui`, unexplained until the
  transcript survives.
- **loop65** -- sshd still will not start on the runner; now the starter's own
  stderr survives to say why.
- **loop53** -- `missing .loop53/ca`, a generated fixture that is not there.
- **11 of 44 gates never run on CI at all** (`PEER_GATES`). A quarter of the
  suite is skipped by design, and "skipped by design" is exactly the shape that
  nobody looks at again.

#### Run `39204915519`: 10 failures became 5, and the fix had a hole in it

The CRLF half is **verified on CI, not just locally**. Of the ten failures,
`verify_loop57`, `58`, `62`, `66` and `67` are green. Those were five of the six
CRLF casualties; the sixth, `verify_loop56`, turned out not to be CRLF at all
(its file was already LF; it was taking the first eight lines of a failing
script instead of the last -- see below).

What is left is `41`, `53`, `55`, `56`, `65`.

**The evidence fix did not work, because of where it wrote.** `keep_output.mjs`
put the transcripts in `.loop70/`, and the workflow uploaded `ci/artifacts/`
only. So on the runner the transcripts were produced and then destroyed with
the VM -- which is the exact failure Loop #69 was written to end, reintroduced
one layer down by the layer that was supposed to fix it. The upload path now
names `.loop70/` too.

**`verify_loop56` took the HEAD of a failing subprocess's output.**

```js
bad("python reference", py.text.trim().split("\n").slice(0, 8)...)
```

On the runner that printed eight `pass S1 ... == hashlib` lines out of a script
that then failed. The traceback is always at the end. This is Loop #69's
12-line tail inverted -- there the error was pushed out by volume, here it is
pushed out by choosing the wrong end -- and it now goes through `keep()`.

No mutation was added for either of these two, for the reason Loop #70 already
set out: there is no injection point that makes `knownhosts_python_ref.py` fail
on demand, and a mutation that cannot be relied on to fail is worse than none.

### Loop #71: nine copies of one path, and a rule I wrote down without measuring it

Loop #69 fixed `SSHD_BIN`, one hardcoded machine path. It could not claim that
fixed the class, because the class is "a path that exists on one machine and
is asserted as if it existed on all of them". This loop finds the rest, and
then tries to make the question stop needing to be asked.

#### Nine `build_*.bat`, all with one developer's gcc

```bat
set GCC=D:\llvm-mingw\llvm-mingw-20260602-ucrt-x86_64\bin\gcc.exe
```

On the runner that expands to a path that is not there, and the only line the
gate could show was the batch's own echo:

```
BUILD FAILED
The system cannot find the path specified.
```

All nine now resolve the way `build_poly1305.bat` **already did** -- `where
gcc`, then `where clang`, then fail by name. Which is the point: this was not a
new convention being invented, it was a convention that had been in the
repository the whole time in one file out of nine, and the other eight had not
heard of it.

Measured: `cmd /c build_aead.bat` prints `using gcc`, builds, runs, exits 0.

#### The rule I wrote down without measuring it

Loop #70 added this to `.gitattributes`:

```
*.bat text eol=crlf
```

justified by "cmd.exe label resolution is not reliable in an LF-only batch
file". That claim was assumed. The repository contradicted it immediately:
all nine `.bat` files were already stored as LF, `build_poly1305.bat` already
contained `goto :check`, and it worked.

Loop #71 put a `goto :cc_ready` block into eight more of them, which forced
the question to be asked, and the answer was: **it works**. So the exception
was removed.

Leaving it would have been worse than having been wrong in the first place.
**An exception list is a place the CRLF guard stops looking.** A `.bat` entry
with a false reason is nine files with a permanent blind spot, justified by a
sentence nobody re-reads. That is the same habit this loop exists to end:
writing an assumption down and then treating the writing-down as the proof.

#### `verify_loop71.mjs`: is there another one?

The question Loop #69 could not answer. It does not keep a list of what has
been fixed -- a list goes stale, and a stale list is worse than none. It
**derives** the set of tracked files still containing a machine-specific
absolute path and refuses to pass while that set is non-empty.

Result when it first ran: **45 hits in 16 files.** Loop #71 fixed all sixteen.

| what | files | how |
|---|---|---|
| hardcoded repo root `E:\src\moon\openssh_moonbit` | 9 | derived from `__file__` |
| `verify_e2e.mjs` chromium: user **and** browser revision | 1 | read `LOCALAPPDATA`, list `chromium-*`, newest first |
| `verify_loop60.mjs` OpenSSH-C: already a probe | 1 | declared, not changed |
| `verify_loop39.mjs` realpath `/C:/Users/hp` | 1 | compared against this machine's `USERPROFILE` |
| `sftp_fault_oracle.py` synthesised `/C:/Users/hp` | 1 | declared: synthesised payload, chosen for its shape |
| `cmd/sftp_test/vectors.mbt`, 26 captured paths | 1 | declared: captured wire bytes, byte-compared against an oracle |
| `setup-moonbit/action.yml` `C:\Users\runneradmin\.moon\bin` | 1 | `$env:USERPROFILE\.moon\bin` |

The last one deserves a line of its own. It worked because GitHub's Windows
runner account happens to be named `runneradmin` -- the single most
implementation-detail thing about a runner, and exactly the kind of fact that
changes without warning.

**`verify_loop39` got stronger, not just portable.** The old assertion was
"the realpath equals this developer's home". paramiko's `normalize('.')`
resolves the *process's own* home, so the honest expectation is not a literal
at all. It is now "whatever this machine's home is, in the shape sftp converts
it to" -- and an unset `USERPROFILE` shows up as a mismatch with both sides
printed, rather than as a silent pass on someone else's computer.

**The two exemptions are not laziness.** `vectors.mbt` holds request bytes
captured from a live OpenSSH 8.0p1 `internal-sftp` session, compared
byte-for-byte against an independently written oracle. Rewriting those paths
would not make the vectors portable; it would make the comparison
meaningless. And `sftp_fault_oracle.py`'s value is *synthesised* -- the client
receives it and echoes it back, both sides in one file, so it cannot drift. It
is a placeholder exactly like `does-not-exist.bin` next to it.

Exemptions are declared in the file that needs them, with a reason, and a bare
marker with no reason **fails**.

#### The gate's own bugs, all found by its own tests

Four, and every one of them would have made the gate worse than useless:

1. `https://example.com` contains `s:/`, which matched `[A-Za-z]:[\\/]`
   exactly -- so the gate flagged a machine path in front of **every URL in the
   repository**. Fixed with a lookbehind.
2. `'/C:/' + home` is a *prefix*, not a path, and matched because zero
   characters after the separator were acceptable. Fixed by requiring one.
3. `stripComments` deleted multi-line block comments, so line indices drifted
   and the "refusing to guess" guard fired on **622 of 765 files**. Fixed by
   blanking comment characters and keeping their newlines.
4. The first exemption heuristic tried to *infer* "probe list" from the text
   ("is this an array element?", "does the file mention `where`?") and its own
   exclusion test failed on the very case it was written to allow. Replaced
   with a marker that has to state its reason.

A gate that cries wolf on its own header is a gate that gets switched off, and
a heuristic that misclassifies a file that is already correct makes its
silence untrustworthy. The exclusion tests exist for that, and they are the
only reason these were caught before CI.

The exemption window is not a taste decision either. It was 4, then 8, and
each time the gate complained about a file Loop #69 had already fixed. It is
now **measured against the tree** and asserted: "the widest legitimate
exemption needs 10 lines, the window is 12."

**Verified:** `9/9`, 768 files scanned, 0 hits. `loop71_mutations.py`,
**3 CAUGHT / 0 MISSED**:

- **M1** a hardcoded gcc path returns to `build_aead.bat` -- must go red and
  name the file. This is the exact shape that made loop55 fail on CI, put back
  where it was found.
- **M2** a bare `machine-path-exempt` with no reason -- must go red. The
  escape hatch used as a mute button.
- **M3** a justified probe list -- must stay **green**. Without it, "passes
  everything" is equally consistent with "flags everything", and M1 and M2
  would prove nothing about the steady state.

M2 reported MISSED the first time, and the reason was in the harness rather
than the rule: the scratch file was never `git add --intent-to-add`ed, so
`git ls-files` did not list it and the gate was never asked. **A mutation that
fails to set up its own preconditions is not evidence about the thing under
test.**

#### Two findings this loop did not fix

- **`gen_hostkey_test.py` and `gen_kexflow_test.py` no longer reproduce their
  committed outputs.** Running them and then `moon fmt` -- exactly what
  loop56's drift check does -- produces a diff that *deletes a hand-written
  comment* explaining that a peer may offer MAC names the client cannot run,
  which is Loop #60's invariant in prose. The generated output also drops the
  `@kexflow.` qualification. The files were restored rather than committed.
  `gen_knownhosts_test.py` is honest: byte-identical after formatting.
  So the drift check exists for one of three generators. **This is worth its
  own loop**: the fix is to teach the generators to emit what the hand-edits
  added, or to move those comments somewhere a generator cannot eat.
- **loop41, 53, 56, 65 are still unfixed on CI.** `.loop70/` reached the
  runner this time (`include-hidden-files: true`; before that,
  `upload-artifact@v4` skips dot-prefixed paths by default and
  `if-no-files-found: warn` stayed quiet because `ci/artifacts/` matched), so
  the next run should finally carry the transcripts.

### Loop #68: the last red row was two untrue declarations, and a third failure that was this repository's own build cache

`test-coverage` had been red for about a dozen loops. Loop #67 pinned the
mechanism -- `moon coverage analyze` has no `--target`, so it builds the whole
workspace for the DEFAULT target, and a js-gated `main.mbt` is not there -- and
recorded it as structural. The structural part was true and is still true. What
was on top of it was not.

There were three things stacked here, and the third was the expensive one,
because for most of this loop it looked like a property of the toolchain:

1. **Seven `cmd/` executables under-declared their target**, and
   `cmd/ssh_live` declared nothing at all while building on native only. Both
   are untrue statements about the repository, and both are fixed below.
2. **`moon coverage analyze` has no `--target`.** Real, structural, and
   unchanged. It is why a workspace-wide walk at the default target is the thing
   that surfaces the other two.
3. **A stale instrumented `_build`.** This one produced
   `conflicting trace metadata` for three packages and an OCaml assertion
   failure, neither of which had anything to do with the code. It is also what
   made steps 4 and 5 of the recipe below look mandatory when they are not, and
   it survived three refuted hypotheses and a lot of confident writing before
   the mutations caught it.

#### Two declarations were untrue, and `moon coverage analyze` was the instrument that caught them

The combine step walks every package in the module. Seven executables gated
their only source file with

```moonbit
options(
  targets: { "main.mbt": [ "js" ] },
)
```

which is a **file** filter, not a package declaration: on every other target the
package still exists, it just has no `main.mbt` left, and the compiler answers
`[4067] Missing main function in the main package`.

And `cmd/ssh_live` declared **nothing at all**, while building on native only.
That one was never a gate artefact -- seven real errors, every one of them true:

| target | `moon check -p cmd/ssh_live` |
|---|---|
| native | 0 errors |
| js | 8 |
| wasm | 7 |
| wasm-gc | 9 |

`cmd/ssh_live` consumes `src/khfile` and `src/tcp`, both native-only, so
`@khfile.append_terminated` and `@khfile.AppendResult` do not exist anywhere else.
Every gate had missed it because the gates only ever asked whether a package
builds on the target it was built for.

The fix is the form `cmd/proton_gui` and `cmd/sftp_mitm` already used:

```moonbit
options(
  supported_targets: "+js",
)
```

Measured, not assumed: a package that declares `supported_targets` and is asked
for a target it does not support **refuses**, exiting non-zero with **zero
diagnostics** -- a declared impossibility rather than a surprise. Neither
`proton_gui` nor `sftp_mitm` ever appeared in the combine run's output. The
controlled proof was converting `cmd/wt_ssh` alone: its `[4067]` disappeared
while the other six stayed.

**The per-file `targets:` form is still correct under `src/`, and this loop did
not touch it.** `src/khstore/moon.pkg` and `src/khfile/moon.pkg` say why: a
package-level declaration would block downstream consumers, so a wasm-wanting
consumer fails loudly at its own compile instead of silently inside the library.
`cmd/` packages are leaves -- nothing imports them -- so the reason does not
apply and only the honesty does. `verify_loop68.mjs` asserts both halves, so the
library rule cannot be quietly relaxed later.

`host/patch_target_decl.py` applies the conversion and then **checks every
package against all four targets** instead of trusting its own edit. Ten
packages declare a target; all ten build on exactly that one.

#### The recipe is one command, and both obvious additions turn out to be unnecessary

**`moon clean` first. That is the whole recipe.** It is worth saying why,
because each of the two steps people reach for next looks load-bearing and is
not, and each of them cost this loop real time before the mutations caught on.

1. **`moon clean`.** The dirty state it removes produces *two* errors that read
   like toolchain limitations: `conflicting trace metadata` for three packages'
   worth of "this can never be reported", and an OCaml assertion failure. Both
   are the same cause. Wiping `_build` fixes both -- see the next section.
   `moon coverage clean` does **not** substitute for it: that removes the dump
   files (28 of which had accumulated here) and leaves the conflict in place.
2. **`MOON_COVE_REPORT_ENABLED=1`.** **Not needed.** `moon coverage --help`
   advertises it, and the default OCaml `moon_cove_report` does die on an
   assertion inside `output_no_intermediate` (`moon_cove_report.ml:220291`) --
   against a dirty `_build`. Against a clean one it exits 0 and prints the same
   report: `src/kexflow`, 73 `<-- UNCOVERED` markers against `Total: 73`, in 15
   seconds, which is the same report the wasm reporter produced for that
   package. (No speed claim is made here: the two were timed in different build
   states, and comparing them would be exactly the kind of measurement this
   section is about not inventing.) The env var was a workaround for a symptom
   of the thing above.
3. **~~`moon coverage clean` between packages.~~ Not needed.** `moon clean` has
   already done everything it does. Deleting it changes nothing measurable.

`moon clean` is the reason `host/cov_report.py` exists at all: `ci/qa.py` cannot
set an environment variable (`_run_argv` inlines the environment) and a bare
command line cannot run one thing and then another, so the qa row is a script.
`host/cov_probe.py` and section C of the gate do the same clean for the same
reason.

#### What it measures -- and the one measurement in this loop that was wrong

15 of the 17 `src` directories holding a test driver produce a real,
source-annotated report: **463 uncovered lines** measured in total, every report
cross-checked so that the number of `<-- UNCOVERED` markers on the annotated
source equals the `Total:` the reporter claims. A number on its own would not
notice a dropped or duplicated line.

The two that do not are both explained, and neither is a toolchain limit:

- `src/khfile` -- `no coverage source data`. Its only test file is gated to
  native (`targets: { "store.mbt": ["native"], "store_test.mbt": ["native"] }`,
  for the library reason above), and `moon coverage analyze` runs at the
  DEFAULT target with no `--target` flag to change that. So its tests are never
  compiled by the command that wants to report on them. This is the honest
  residue of the missing flag, and it is the only package in the tree it costs.
- `src/test_nested` -- the same message, for a boring reason: it has no
  `moon.pkg` at all. It is a fixture directory holding one `nested_test.mbt`,
  not a package.

**A third entry in the earlier, longer list was this loop's own build cache.**
For most of this loop the answer was 13 of 17: `src/bpacket` and `src/hmac`
failed with

```
error: conflicting trace metadata for file id '.../src/bpacket$chacha_api'
```

which reads exactly like a toolchain limitation, and two plausible mechanisms
were tested and refuted on the way -- "a package with two test drivers" (nine of
the reportable packages have both a blackbox and a whitebox driver) and "a file
id present in more than one dump" (`src/aead` and `src/sha256` have every key
in more than one dump and report cleanly). The thing that finally broke it was
not an experiment at all. In the harness's **first draft**, three mutations --
one deleting a `moon coverage clean`, one dropping an environment variable, one
changing a package list -- reported **the same single FAIL line**:
`newly reportable: src/bpacket,src/hmac`. Three unrelated mutations cannot
produce one identical unrelated failure. The gate was not catching them; it was
failing for an environmental reason on every run and the mutations were riding
on it. (The first-draft M3/M4/M5 are not the M3/M4/M5 in the shipped file --
that is the point, and the reason is in the harness docstring.)

Confirmed three ways, in this order:

1. A sandbox, which has no `_build` at all, reports both packages fine.
2. `moon clean` in the working tree, then the same command: `src/bpacket`
   exits 0 with `Total: 66 uncovered line(s) in 11 file(s)`, in 31 seconds.
3. Reproducing the suspected cause *fails* to reproduce it: a standalone
   `moon test --enable-coverage -p src/bpacket --target native` followed by
   `moon coverage clean` and a re-analyse still reports cleanly, so the stale
   thing is not the dumps and not the extra test run.

`moon coverage clean` removes the dump files and leaves the conflict exactly
where it was. Only `moon clean` clears it. So `host/cov_report.py`,
`host/cov_probe.py` and section C of the gate all begin with `moon clean`, and
that line is what makes the committed `host/cov_reportable.json` a statement
about the repository instead of a statement about whoever ran it last.

`host/cov_conflict.py` exists so the next person does not have to re-derive this
from scratch: it reports, for every file id carried by more than one dump, which
dumps hold it and how their counters differ.

#### The gate derives the answer instead of listing it

`host/verify_loop68.mjs` keeps **no** list of which packages should be
reportable. It re-runs the toolchain over every `src` package with a test driver
and compares the result against the committed `host/cov_reportable.json` **in
both directions**. A package that silently becomes unreportable fails, and so
does one that silently becomes reportable -- the second is Loop #66's accept
table lesson: a gate that only notices new problems is a gate whose evidence has
stopped being checked.

Section A2 is the check that closes the hole the rest of section A leaves. The
declared-package matrix only inspects packages that already declare something, so
deleting `cmd/ssh_live`'s declaration would just drop it off the list. A2 asks
the workspace-wide question instead -- `moon check` at the default target must
report **zero `Error: [NNNN]` lines** -- and that is the very observation that
found the bug. It is asserted on the error count and *not* on the exit code: a
package that correctly refuses an unsupported target exits non-zero with no
diagnostics at all, so an exit-code assertion would be demanding the workspace
build on the target it was told it cannot support. This is Loop #67's
`evidence_targets` lesson wearing a different hat -- silence is the healthy state
here, and a package that failed to compile must never be read as a clean one.

`host/loop68_mutations.py` runs 7 mutations, each one a **reversal of a fix this
loop shipped** rather than a synthetic defect: the per-file gate restored, the
`ssh_live` declaration deleted, a declaration pointed at the wrong target, the
library-side gate that this loop deliberately left alone removed, the qa command
aimed at the one package whose tests can never be covered, and the committed
evidence edited in each of the two directions. The question a mutation answers
is never "can this gate see an arbitrary bug" but "would it have seen the thing
that was actually wrong here".

**Result: `mutations=7 CAUGHT=7 MISSED=0 BUILD-BROKEN=0`.**

**The mutations earned their keep twice, and both times by failing.**

The first time, in the harness's first draft, M3, M4 and M5 -- a clean call, an
environment variable and a package list, nothing to do with one another --
reported **the same single FAIL line**:
`newly reportable: src/bpacket,src/hmac`. Three unrelated mutations cannot
produce one identical unrelated failure, so the gate was not catching them; it
was failing for an environmental reason on every run and the mutations were
riding on it. Without looking at *which* check fired, M3 through M7 would have
been recorded as five comfortable CAUGHTs and a stale `_build` would have
shipped as a permanent claim about the toolchain.

The second time, two mutations came back **MISSED** and both were right to.
Deleting the per-package `moon coverage clean`, and separately dropping
`MOON_COVE_REPORT_ENABLED=1`, each changed nothing -- because `moon clean` has
already done the work of both. Those two were written, run, judged and then
**deleted from the set**, and the reason is recorded in the harness rather than
quietly dropped. A mutation that provably cannot fail is worse than no
mutation: it sits in the count looking like coverage of the recipe and it trains
the reader to trust a number that means nothing.

#### Two gates of older loops needed updating, and neither update was optional

Making the row green was the easy half. Two older gates then went red, and both
had been written to assert something that is no longer true. The interesting
question is not that they went red -- it is which direction they were wrong in.

**`verify_loop67.mjs` asserted that the evidence must name
`combine_coverages`** -- the OCaml function inside the reporter whose source line
had been read in Loop #67 to find the failure. Loop #68 fixed the blocker, the
evidence stopped quoting that function, and the gate went red on a row that is
now GREEN. That is a stale assertion, not a regression, and the right fix was to
assert the part of the story that has not changed (the row must still say the
combine walks the whole workspace at the default target) rather than to quote the
old prose back. Asserting the name of a function inside someone else's
implementation would have meant the fix had to keep naming it forever.

Then the same check failed a second time, on a claim that was present and
correct. `ci/qa.py` builds each evidence block by concatenating adjacent string
literals, so the **source** reads

```python
"...has no "
"--target, and src/test_nested..."
```

and a literal search for `no --target` in the source text misses, because the two
halves are separated by `" "`. The check was reading the spelling of the
evidence rather than the value, and it had only been passing by luck of where the
prose happened to wrap. It now joins the literals the way Python does before
looking for anything. Same rule as everywhere else in this file: assert the
property, never the formatting of the source that happens to spell it.

**`verify_loop65.mjs` failed for real, and not because of anything this loop
changed.** Its sshd-leak probe waited a flat `setTimeout(1500)` after the owner
process exited, then asked once whether the port was still bound. Under a full
CI run that guess was wrong:

```
FAIL  the probe cleans up after itself  [self-cleanup by this probe: FAILED, port still bound]
```

Standalone, minutes later, the same gate passed 25/25 with no sshd process left
behind. A check that fails under load and passes when idle is a flaky check, and
`moon clean` -- which Loop #68 puts at the head of the coverage recipe, making
every run start cold -- is exactly the kind of load that exposes one. The probe
now asks the question that matters: has the port been free *continuously* for a
settling window, rather than was it free at one instant after a guessed delay.
Three consecutive standalone runs: 25/25.

Two lessons, both about what a green gate is made of. A gate can be red for a
reason that has nothing to do with the code it inspects, and the way to tell is
to run it alone -- a failure that disappears when you stop running everything
else is a timing bug until proven otherwise. And a gate whose failure text names
no file is a gate that will cost an hour next time; `host/cov_report.py` now also
writes its reason to **stderr**, because the CI engine keeps only the last 12
lines of output and a coverage table is longer than that, which is exactly how an
earlier run of this loop showed a table of successes and the bare words
"exit 1" with no indication of what had gone wrong.

### Loop #67: a twelve-loop-old warning was wrong, and the tool that measured it was wrong in a worse way

Loop #66 closed the static-analysis row. This one closes format-check and
benchmark, disproves a standing instruction, and finds a real regression that
Loop #66 shipped. The regression is the reason to read this section twice.

#### The CJK warning was false, and it was costing us the fix

AGENTS.md carried this rule for a dozen loops:

> `moon fmt` in write mode corrupts CJK comments (`真实加密` -> `真加密`)

It was the stated reason `format-check` could never be made green -- "run with
`--check` ONLY". It does not reproduce on `moon 0.1.20261012`. Measured three
ways, and the first one needed no write mode at all:

1. **The formatter's own output is already on disk.** `moon fmt --check` writes
   what it *would* write to `_build/<target>/release/format/`. All 366 CJK runs
   in `cmd/channel_test/main.mbt` are byte-identical between source and that
   output. This is the decisive test and it is free.
2. After formatting the 10 files `--check` named, all 373 CJK runs across them
   were unchanged.
3. After formatting the whole tree -- 267 files -- `host/cjk_snapshot.py`
   compared **12,840** CJK runs across 226 files against a snapshot taken
   beforehand. Zero difference.

The rule is deleted, and the guard that replaces it is stronger than the rule
was: `host/cjk_snapshot.py save|check` snapshots CJK *content* and fails if a
run is lost or changed inside a file that still exists. It fired once during
this loop -- on `src/wtlive/live.mbt`, because a dead function and its Chinese
doc comment were deleted on purpose -- which is the proof that it is measuring
something real. `verify_loop67.mjs` runs it.

The incident itself is not recorded, and guessing is how a wrong rule outlives
a dozen loops. The file it named no longer contains the string.

#### `moon fmt --check` reports a partial set, like `moon check`

Before formatting, `--check` named 10 files. Formatting them made it name **20
more, with no overlap**. Same command, same tree, and the second batch was
always there. This is the Loop #66 finding wearing a different hat: a single
measurement pass is a floor, not a total. Both tools report what they reached,
not what exists.

Of the 10 it named first, **2 were line-ending-only** -- a CRLF source against
an LF formatter, byte-identical after normalising. The diff renders as a
whole-file delete-and-readd, which reads like a catastrophe and contains no
change at all. `verify_loop67.mjs` now asserts that every tracked `.mbt`,
`.pkg` and `.moon` file is LF.

#### Loop #66 shipped a compile error, and only a js build found it

Loop #66 renamed `AuthReport.method` -> `auth_method` because `method` is a
reserved keyword, and updated `cmd/wt_ssh/main.mbt` to read `r.auth_method`.
But `cmd/wt_ssh`'s `r` is a `src/wtlive.WtAuthReport` -- the WebTransport twin
of the type, not the type itself. Loop #66 renamed one twin and edited the
consumer of the other.

`moon check cmd/wt_ssh` on the default target does not see it: the file is
gated to js. `moon check --target js` does, and so does `moon build`. It
surfaced in this loop as `verify_loop46.mjs` failing with "failed when building
project" -- the first time the whole-workspace CI had run since.

Two lessons, and the second is the expensive one:

1. Parallel types must be renamed together. `WtAuthReport` got the same
   treatment, and its `reserved_keyword` warning had been invisible for the same
   reason the error was.
2. **The collector reported that broken package as CLEAN.** Its
   `_is_hard_error` tested `msg.startswith("Error")`, and the message is
   `The type ... has no field auth_method.` -- no prefix. Loop #66's fixpoint
   of "3 remaining warnings" was therefore a statement about packages that
   happened to build. Fixed to key on the diagnostic's shape
   (`Warning (<kind>):` or not), which is the only thing that actually
   discriminates -- `level` cannot, because `--deny-warn` reports warnings as
   `"level": "error"` too.

#### The same mistake one level up: judging a package from one target

With the error detector fixed, the collector immediately reported **five
packages that "failed to build"** -- and every one of them was fine. They are
js-only executables with `options(targets: { "main.mbt": ["js"] })`; checked on
the default target they have no main and fail [4067]. `cmd/probe_async_wall`
was the real defect hiding in that list: its `main.mbt` is `extern "js"` end to
end and **its `moon.pkg` never declared the gate at all**, so it was a js-only
package pretending to be universal.

So the collector now reads `moon.pkg` and checks a package on all four targets
when it declares gating, on the default target when it does not, and only
gathers diagnostics from targets that built -- a target that failed produces
cascade noise, which is exactly how `cmd/wt_ssh` once produced a wall of
`test_unqualified_package`. Fixing all of that turned "3 warnings" into 4 real
sites across 3 files, all of them justified:

- `cmd/proton_gui` x3 `unused_async` -- `CommandRegistrar::bind` declares its
  handler type as `async fn`, so a handler is async whether or not its body
  awaits. `main.mbt:69` says so in the source. The warning is about the body;
  the requirement is about the type.
- `src/khfile` x1 `unused_package` -- Loop #66's entry, kept.

And a controlled experiment settled a disagreement between the two loops.
`src/wtlive` also imported `moonbitlang/async`, unused by the same test.
Loop #66's evidence says such an import must stay; Loop #67 deleted it and
measured: `moon check --target js` and `moon build cmd/wt_ssh --target js` are
both green without it. **Same warning, same package shape, opposite answers** --
because `src/khfile` has `async test` (whose expansion consumes the import) and
`src/wtlive` has only `async fn` (which does not). Both entries now carry that
distinction in their evidence.

#### benchmark: the row had never measured anything

`moon bench --target native` with no `-p` benchmarks the *current* package, so
the row inherited the whole workspace and died on the js-only Worker mains.
Scoped to `-p src/bigint`, the real reason surfaced: the repository contained
**zero** benchmark blocks, and `moon bench` on a package with none exits **0**
while printing `Total tests: 0, passed: 0, failed: 0` and `Warning: no test
entry found`. An exit-code-only check would have reported a PASS having measured
nothing. `verify_loop67.mjs` asserts on that text.

`src/bigint/bigint_bench.mbt` now carries five. A MoonBit benchmark is a
**test block taking a `@bench.T`**, not a `bench "..." { }` block -- `bench` is
not a keyword in that position, and `ignore(x)` and `let _ = x` both fail to
parse inside one. `b.keep()` is what stops the optimiser deleting the
computation. Measured here:

| benchmark | time (mean ± σ) |
|---|---|
| `mod_pow` 2048-bit e=65537, schoolbook | 4.86 ms ± 52 µs |
| `mod_pow_auto`, cached Montgomery ctx | **173.96 µs ± 2.23 µs** |
| `mod_mul` 2048-bit | 237.80 ns ± 2.34 ns |
| `mpint_encode` 2048-bit | 329.05 ns ± 2.40 ns |
| bytes round trip | 486.26 ns ± 2.21 ns |

The 28x gap is Loop #29's optimisation finally quantified instead of asserted.
The modulus is RFC 3526 group 14, written as a derivation (`2^2048 - 1` is 255
bytes of `0xFF` and `0xFF`, and `189 = 0xBC`, so subtracting puts `0x43` last)
rather than 256 pasted bytes that nothing here could check.

#### The first full CI run found three more, and two of them were self-inflicted

Closing format-check meant formatting 267 files, and formatting is exactly the
kind of change that breaks gates which were asserting on things nobody thought
to re-derive. Three failures, all from that one action:

1. **`src/bigint/bigint_bench.mbt` shipped five warnings.** `@bench.T` is a
   core package, and core packages are no longer implicitly in scope. It reports
   as `core_package_not_imported`, a **deprecation rather than an error** --
   which is why the benchmarks still ran and the number still came out. A gate
   that only ran the benchmarks would never have noticed.
2. **`verify_loop56.mjs` failed on a 276-byte "drift".** Its two generated files
   are compared byte for byte, so formatting one turned a content check into a
   wrapping check. Worse, the gate *writes* the generator's output back in
   place, so the unformatted file it left behind turned `moon fmt --check` red
   **two steps later in the same run** -- one byte-for-byte assertion turned one
   green row into two red ones. The fix is to run `moon fmt` on the generated
   files before comparing, so the check measures what it exists to measure
   (did the content change) and formatting stays format-check's business. The
   failure message now says "after formatting, so this is a content change and
   not a wrapping one", which is the difference between an action and a shrug.
3. **`verify_loop66` and `verify_loop67` went red on the new file** -- the same
   five warnings, caught by the accept-table equality, which is what it is for.

The generalisable part: **turning on a gate you had been carrying as "known
defect" is its own change**, and it will find things that were always there and
that no gate was looking at. The benchmark file is the clean example -- it was
written to be correct, ran correctly, printed real numbers, and was still wrong
in a way only the accept table could name.


#### Mutations, and one that was filed in the wrong place

`host/loop67_mutations.py`, six mutations. The first run came back
**4 CAUGHT / 2 MISSED / 1 BUILD-BROKEN**, and all three of the wrong-looking
ones were worth more than a pass would have been:

- **M1 was BUILD-BROKEN, and it should not have been.** It prepended a junk
  line to a source file to create a CRLF defect, which also made the package
  fail to compile -- so it tested the compiler, not the CRLF check, even though
  the gate did catch it. It now converts the file's line endings instead, which
  is the defect without the breakage. *A mutation that cannot build has not
  tested the gate*, and reporting it as a pass would have been the lie.
- **M7 errored on a stale anchor** because I had edited `cjk_snapshot.py`
  under it. A harness whose anchors silently rot stops testing anything, so it
  fails loudly and the anchor is fixed rather than the mutation dropped.
- **M5 MISSED, and the gate deserved it.** It re-added `src/wtlive`'s dead
  `moonbitlang/async` import -- and the only check in the repository that
  notices a stray unused import is the accept-table equality inside
  `verify_loop66.mjs`, which `verify_loop67.mjs` invokes with `--skip-live` so
  that a mutation run stays affordable. So the mutation sat exactly where the
  check it attacks was switched off.

  It moved to `host/loop66_mutations.py` as **M9**, beside the check, and runs
  there with `live=True`. **A mutation belongs beside the check that catches
  it, not beside the loop that introduced the defect** -- which is a different
  statement from "put it in the same file as the code it breaks".


#### The mutation that was right about the gate, twice

M9 re-adds `src/wtlive`'s dead `moonbitlang/async` import and expects the
accept-table equality to reject it. It did not -- and it was right twice, which
is rarer and more useful than being right once.

The first MISSED was cheap to explain and was a placement error: M9 sat in
`loop67_mutations.py`, whose gate calls Loop #66's with `--skip-live` to keep a
mutation run affordable, and that flag skips exactly the accept-table check it
attacks. Moved to `loop66_mutations.py` beside the check.

The second MISSED was a **real hole in the collector**, found only because the
mutation was not deleted and the gate was not explained away:

- The site *was* reported. `collect_one("src/wtlive", target="js")` returns
  `('src\\wtlive\\moon.pkg', '2')` as an `unused_package`.
- But `unused_package_all_targets` returned the **empty set**, and empty means
  "classified as a false positive and filtered out".

The intersection runs over all four targets. `src/wtlive` gates both of its
files to js, so on native it builds with **zero active files** and reports
nothing at all -- and an empty set intersected with anything is empty.
**A target where a package has no files is silence, not evidence.**

That fix then exposed two more, both of the same family:

- **Bare `moon check` does not default to native.** `cmd/proton_gui` is
  `supported_targets: "+native"`, so checking it with no `--target` produced no
  diagnostics, and the collector would have called a package with three real
  warnings clean. The collector had been consulting "whatever the default is" --
  now it consults `targets:`, then `supported_targets:`, and otherwise **all
  four targets**.
- **The `targets:` parser only captured the first element of each list.** With
  `[ "wasm", "wasm-gc" ]` it returned `{wasm}`, so `src/tcp` was being
  intersected over three targets instead of four -- and an intersection over
  fewer targets is one that can hide a real dead import. Caught by printing
  what each package resolved to rather than by reasoning about it.

With the hole closed, one more genuinely dead import appeared that three rounds
of "is this a false positive?" had been waving through: **`cmd/wt_ssh`'s
`moonbitlang/async/js_async`**. Deleted after `moon check --target js` and
`moon build cmd/wt_ssh --target js` both came back clean without it. Nothing in
this repository noticed it for a dozen loops, because every layer above the
compiler was answering the question it had been asked rather than the question
that was true.

The mutation harness earned its keep here in a way a passing run could not:
**a mutation that cannot fail is more dangerous than no mutation at all**, and
three of this loop's four were failures that had to be read before they could
be fixed.


#### Still red

`test-coverage`. `moon coverage analyze` has **no `--target` flag**, only
`--target-dir`, and `-p` does not limit the scan -- `combine_coverages` builds
every package for the default target, so the two js-only Worker mains fail
[4067]. An attempt to declare them differently (`options(is_main: [...])`) was
reverted after the key turned out to take a boolean, and `git diff` confirmed
the revert before moving on. This is recorded, not worked around.

The release gate stays shut and no tag was cut. `ci/release.py` refusing while a
tier is red is the correct outcome, and it is not a formality: it was exercised
in exactly that mode both this loop and the last.

Where the matrix ended up, for the record. `python ci/ci.py --tiers
env,build,gates,qa`: **57/58 steps in 762.9 s**, and of the twelve runnable QA
categories **11 pass**. That is 8/12 at the start of Loop #66, 9/12 after it,
and 11/12 now:

| row | Loop #66 | Loop #67 |
|---|---|---|
| static-analysis | red (one package) | **pass**, 22.4 s |
| format-check | red | **pass**, 0.1 s |
| benchmark | red | **pass**, 5.0 s |
| test-coverage | red | red, structural |

#### A note on editing, because it cost more time than any of this

The `edit` tool failed to match multi-line blocks in this repository -- AGENTS.md,
ci/qa.py, cmd/flow_kat/main.mbt, collect_warnings.py, src/khfile/moon.pkg --
on invisible byte differences alone, repeatedly. `host/patch_span.py` locates a
span by two unique ASCII lines and rewrites between them, with a uniqueness check
so a drifted file fails loudly. The one trap worth naming: `}` is not a unique
end marker in MoonBit, `cmd/flow_kat/main.mbt` has 74 of them, hence the
`until:` form.


### Loop #66: the warnings were hiding each other, and the collector was hiding the warnings

Loop #66 set out to turn the four red qa rows green. It closed one of them and
found, on the way, that the tool used to measure the others had been lying in a
way that made every earlier count wrong.

#### The headline: `moon check --deny-warn` is not a set of warnings, it is a snapshot

The first measurement said the tree had 15 warning sites. It actually had 318.
Then 62. Then 12. Then 3. Nothing was added to the tree between those numbers --
the *same* command was reporting fewer things each time, because fixing one kind
of diagnostic made another kind visible.

`src/hostkey` is the clean example. While `cert.mbt` still contained one
`deprecated` call, `moon check src/hostkey --deny-warn` reported exactly that
call and nothing else. Fixing it -- changing `.substring(start=0, end=n)` to
`n[:len].to_owned()` -- made **105** `test_unqualified_package` warnings appear
in the same package, in the same command, with no file touched except the one
that had just been fixed. Three consecutive runs on the repaired tree returned
105, 105 and 105, so the result is stable; it is just *not* stable against the
act of fixing something else.

The operational consequence is the part worth keeping: **a static-analysis gate
built on one measurement pass cannot work here, and a number read off a single
pass is a floor rather than a total.** The loop measured, fixed, re-measured and
repeated until one full pass produced no new sites. That fixpoint is 3.

#### Two independent reasons an import can look unused, and only one of them is fixable

`unused_package` fired on 19 sites. They split cleanly, and the split is the
useful part:

| Cause | Example | Verdict |
|---|---|---|
| Files gated per target | `src/wt`, `src/khstore`, `src/khfile`, `cmd/wt_probe`, `cmd/knownhosts_kat` | false positive |
| Consumed by a compiler expansion | `src/khfile`'s `moonbitlang/async` | false positive |
| Genuinely dead | `src/tcp`'s `moonbitlang/core/bytes` | removed |

The first is handled **derived, not by allowlist**. `options(targets: {...})`
leaves an import with no textual reference whenever the files that use it are
gated away, so `host/collect_warnings.py` intersects `unused_package` across all
four targets and keeps only what fires everywhere. That alone removed 15 sites,
and it has teeth: the real `src/tcp` case fires on all four and was caught by it.

The second is the one the intersection **cannot** reach, and finding that is the
loop's sharpest result. `moonbitlang/async` is consumed by the compiler's
`async test` expansion, which emits a call to `@moonbitlang/async.run_async_main`
-- generated code, so no source line references the package. It looks unused on
*every* target, and the gate would otherwise tell the next reader to delete a
line whose deletion produces eight hard errors, one per `async test` block,
reproducing verbatim the message the package comment had predicted. The gate
therefore asserts the import is **present**, and the comment now says "do not
clean it up". The lesson generalises: *an intersection over configurations cannot
detect a consumer that is not in the source text at all.*

#### What was removed

- `src/tcp`: `moonbitlang/core/bytes`. `Bytes` is prelude, so four files using
  the type never needed the import.
- `src/sshclient`: `src/tcp`. This is Loop #64's payoff, finally visible as a
  deleted line -- the Transport impl moved to the transport side and took the last
  `@tcp.` reference with it, so the dependency arrow the loop argued about is
  gone rather than merely pointing the other way.
- `cmd/main`, `cmd/ssh_full`: three dead imports.
- Dead code: `eq_at`, `bytes_to_ascii_string`, `ascii_bytes`, `byte_to_hex`,
  the whole `PfCursor` reader, the write-only `in_section`, a `key_kat256_dbg`
  that was byte-identical to the `key_kat256` below it, and `HASH_LEN` /
  `HASH_MAGIC`.
- 19 deprecated `.substring(start=A, end=B)` calls rewritten to `[A:B].to_owned()`.
  Two of the intermediate forms compile-fail rather than misbehave, which is
  what made it safe to try: a bare `s[:n]` is a `StringView` where a `String` is
  wanted, and `.to_string()` *on a StringView* is itself deprecated. Only
  `.to_owned()` satisfies both.
- `AuthReport.method` → `auth_method`, because the word is reserved. The printed
  label stays `method:` -- that is RFC 4252's term, and `verify_loop34` asserts
  on it. Renaming the field but not the label is the whole point: the toolchain
  objected to an identifier, not to the protocol vocabulary.

#### Two instruments that were themselves wrong

`host/collect_warnings.py` keyed results as `path -> {line: kind}`, so two
warnings on one line silently collapsed into one, and a package that **failed to
build** reported as clean because its cascade noise was filtered out. Both are
fixed, and a broken package now exits 2 with its name on stderr, because "cannot
tell" and "clean" are different answers.

Separately, the first reading of the collector's own output was wrong before the
collector was: `python host/collect_warnings.py 2>&1 | Out-String` on
PowerShell 5.1 interleaves stderr into stdout and destroyed a whole file's entry
mid-JSON. The `files=9 sites=15` in this loop's notes is that artefact, not a
measurement. Native redirection writes UTF-16 (0xFF BOM), so the working forms
are `cmd /c "python ... > out.json"` or reading with `encoding="utf-16"`.
**When a tool reports a count, verify the collector before believing the number**
-- the third time this repository has been bitten by it.

#### Gate and mutations

`host/verify_loop66.mjs`, 14 checks, exit 0. Two are negative assertions
(`src/khfile` must still import `moonbitlang/async`; `in_section` must still be
*read* by the second function in `parser.mbt`, even though the dead copy is
gone), one re-runs the collector live and asserts the reported set **equals** the
accept table -- so a new warning fails and a fixed one fails too. The gate caught
two of its own bugs while being written: it asserted `in_section` was absent
file-wide when a second function legitimately reads it, and it used `require` in
an ESM module. A gate that fails on correct code is still doing its job.

`host/loop66_mutations.py`: **7 CAUGHT, 0 MISSED, 1 BUILD-BROKEN** over 8
mutations. M3 is the deliberate shape from Loop #65 -- deleting
`src/khfile`'s `moonbitlang/async` **is** the fix a future reader will attempt,
and the gate must reject it. M5 is recorded as BUILD-BROKEN because the mutation
does not compile: a mutation caught by the compiler has not tested the gate.

#### Still red, and why

`ci/qa.py`'s `static-analysis-sast-code` row now runs the gate instead of
`moon check --deny-warn`. The other three rows are untouched and still red:

- **test-coverage** -- `moon coverage analyze` has **no `--target` flag**, only
  `--target-dir`, and `-p` does not limit the scan: `combine_coverages` builds
  every package for the default target, so the two js-only Worker entry points
  (`cmd/wt_probe`, `cmd/wt_ssh`) fail [4067] "Missing main function". An attempt
  to declare them differently (`options(is_main: [...])`) was reverted -- the key
  takes a boolean, and `git diff` confirmed the revert before moving on.
- **benchmark** -- needs real `*_bench.mbt` files; the repo has none, and the
  zero-work guard is what stops the row reporting a green that measured nothing.
- **format-check** -- `moon fmt --check` wanted to re-wrap KAT byte arrays.
  **Solved in Loop #67**, which also disproved the CJK warning this line used to
  carry: `moon fmt` over the whole tree leaves all 12,840 CJK runs across 226
  files byte-identical. `moon fmt --check` now exits 0.

The release gate therefore stays shut and no tag was cut, which is the correct
outcome and not a formality: `ci/release.py` refuses when a tier is red, and it
was exercised in exactly that mode.


### Loop #65: verify_loop40 leaks the server it starts, and a fixed port makes that bite

`verify_loop40.mjs` starts a real OpenSSH server and **cannot stop it**.
`startSshd()` (line 147) spawns `node host/sshd_setup.mjs`, calls
`child.unref()`, polls until the port answers, and returns a boolean — the
handle is discarded and never stored. `sshd_setup.mjs:210` parks on
`await new Promise(() => {})`: `sshd -D` runs in the foreground forever and no
SIGTERM/SIGINT handler is installed. The only `kill()` in the whole gate is
`relay.kill()` (line 556), a different process. So on every run, successful or
not, an sshd is orphaned on `SSHD_PORT = 18783` — a **hard-coded literal**, so
the second run collides with the first.

That is the shape behind `verify_loop49` passing standalone and failing inside
a suite run. It is the kind of order-dependent failure that gets relabelled
"flaky" and then lived with forever.

Reading the code shows there is no owner; it does **not** show that the process
survives. `host/probe_sshd_leak.mjs` measures it, in two processes on purpose:
the inner one reproduces loop40's `spawn` + `unref` + dropped handle verbatim
and exits normally, exactly as a gate that finished — or was killed — would;
the outer one then polls the port. If it still answers, the server outlived its
only owner. In a single process that measurement would be void, because the
inner process would still be alive. The outer probe cleans up after itself,
which is precisely what loop40 lacks.

```
LEAK CONFIRMED: the port still answers after the owner exited.
self-cleanup by this probe: ok, port released
```

`verify_loop65.mjs` 25/25. Mutations **6 CAUGHT / 0 MISSED**. M1 is worth
reading twice: giving loop40 an sshd kill *is* the fix being argued for, and
the gate goes red when it appears — the gate asserts the leak exists, so a real
fix must be accompanied by a decision about what the gate should then say.

#### The classification mistake, corrected

Loop #64 wrote `PEER_GATES` as `verify_loop31..39` and left loop40 in the
default tier, where it costs ~44 minutes and turns the run red for reasons
unrelated to the code under test. That was Loop #64's error, not a judgement
call. The set is now `31..40, 49`, each entry carrying the measurement that put
it there. Default tier: **44 steps**; the eleven excluded gates are named on
every run.

#### A note on restoring bytes

Two separate incidents this loop, both mine:

- `git show … | Out-String` turned a 2-line change into a 717-line diff.
  PowerShell rewrites line endings and appends a newline. Use `git show` piped
  to a binary write.
- A restore-from-HEAD script then reverted the loop's own uncommitted work along
  with the temporary mutation, and the gate noticed before I did.
  **Restore-by-HEAD is only safe on files with no legitimate uncommitted
  changes.** Restore by re-applying the exact change instead.

#### A gate that took four attempts to specify

The provenance check on `PEER_GATES` — "the set must carry the measurement that
justifies it" — was too weak three times in a row, and each time a mutation that
should have failed it passed:

1. A mutation that appended a misleading comment and deleted nothing. The gate
   was right to pass; **the mutation was broken**, which is worse than no
   mutation because it looks like a hole.
2. Deleting one line of the block — "measured" also appears on Loop #64's
   paragraph about 31–39.
3. Deleting the block's header — the detail lines still name `loop40`.

Deleting the whole nine-line block fails it (23/25). The spec that works names
the two gates specifically. Three broken mutations are recorded in
`host/loop65_mutations.py` rather than deleted: **a mutation that cannot fail is
more dangerous than no mutation at all.**

### Loop #64: a transport seam, a measured wall, and a CI that can say no

`src/sshclient/live.mbt` and `src/sftp.mbt` named `@tcp.TcpConn` in 25
signatures. `@tcp` is **our own** package (`src/tcp`, a plain Winsock binding) —
not `moonbitlang/core/tcp` — so the protocol layer and one transport were the
same thing at the type level. There was no way to say "run the same handshake
over a WebSocket", and no way to *prove* two transports equivalent because only
one existed.

`src/transport` supplies the seam. Three methods, because that is all
`sshclient` calls: SSH is strict request/response, so `read_exact` is the only
read primitive that matters and no partial-read notion leaks upward.

```
pub(open) trait Transport {
  fn wire_send(Self, FixedArray[Byte]) -> Bool
  fn wire_read_exact(Self, Int) -> FixedArray[Byte]?
  fn wire_close(Self) -> Unit
}
```

The `Transport for @tcp.TcpConn` impl lives in `src/transport`, not in
`src/tcp`. The dependency arrow points one way and `src/tcp` is unmodified: if
the socket binding learned about the trait, the "seam" would be a cycle wearing
a trait's clothes. `verify_loop64.mjs` asserts both directions.

**The wall, measured rather than argued.** `cmd/probe_async_wall` puts a byte
into a JS-visible slot from a `setTimeout` callback — the stand-in for
`WebSocket.onmessage` — and asks whether a *synchronous* `fn` can ever see it:

```
sync : STARVED after 5000000 spins -- synchronous code never yields
async: GOT 0x5a
```

Both arms are driven by the same `setTimeout` scheduling, because if they
differed the comparison would prove nothing; `verify_loop64.mjs` asserts that.
**Consequence, and it is the real finding of this loop:** `src/sshclient` is
synchronous, a browser WebSocket can only be read by awaiting, and in MoonBit
only an `async fn` can await. So running the verified handshake in a browser is
not "write a WebSocket bridge" — it requires converting the whole SSH layer to
`async fn`. Loop #63's conclusion is narrowed, not overturned: the wasm target
cannot do it; the js target can, but only asynchronously.

Verification: `verify_loop64.mjs` 31/31. Mutations: **4 CAUGHT / 0 MISSED /
2 BUILD-BROKEN** (the two broken ones are compile errors, so the gate never
judged them and they are not evidence).

`verify_loop63.mjs` asserted `live.mbt` contains `@tcp.TcpConn` — a literal that
this loop supersedes. It was replaced by the stronger statement it was standing
in for: scan every `impl Transport for` in the repo and assert the set is
exactly `["@tcp.TcpConn"]`. A second implementation is exactly what would let a
browser transport in, and nothing else in that gate would notice. Loop #64's own
mutation M6 found the first attempt was too weak — it only guarded one end of
the arrow — and that is now asserted too.

#### Local CI, and three gates that were red for reasons nobody had noticed

`ci/ci.py` is the engine; `.github/workflows/ci.yml` is a thin shell that calls
it. The step list lives in **one** place on purpose: a YAML copy of 40 gates
drifts within a couple of loops, and the failure mode is silent — CI goes green
because it stopped running the new gate.

The engine exists because a hand-written loop got it wrong inside one session:
PowerShell 5.1 evaluates `.Count` on a *scalar* as `$null`, so a run with one
failing gate printed `11 - $null = 11`, i.e. **"11/11 PASS" while the process
exited 1**. A summary that can disagree with the exit status is not a summary.
`--self-check` therefore tests the engine's own accounting, including that one.

Three red gates surfaced immediately, all pre-existing (reproduced on a clean
`git worktree` of `59145fb`):

1. **`verify_loop24.mjs`, red since Loop #57.** It asserted
   `cmd/sshconfig_test` prints `fnmatch_pass: 23/23`. Loop #57 *deleted* that
   block — the count was hardcoded, so the binary printed 23/23 whether or not
   the arithmetic held — and moved the cases into `src/sshconfig/sshconfig_test.mbt`
   as a table that asserts instead of printing. The gate was never updated. It
   now asserts the *absence* of the hardcoded line and the *presence* of the
   table.
2. **`verify_loop30.mjs`, KAT mismatch vs Python — and the MoonBit side was
   right.** An independent RFC 4251/5656 parser decided it:
   MoonBit's blob parses and consumes all 101 bytes; the expected file does not
   parse at all. `gen_ecdsa_driver.py`'s `sig_blob` omitted the outer
   `string signature_blob` length, and `render`'s `format(v, "X")` dropped
   leading zeros, producing a 95-character hex string where a 48-byte value needs
   96. Both fixed; the generator is now idempotent (`cmd/ecdsa_test/main.mbt`
   regenerates byte-identical to HEAD).
3. **The generator was a landmine.** Loop #34 had fixed `build_sig` *by hand*
   in `cmd/ecdsa_test/main.mbt`, left a comment predicting exactly this bug, and
   never fixed the generator. Regenerating silently reverted it. The generator
   now emits the correct layout with the original Chinese comment preserved
   byte-for-byte.

All three are the same disease: **one fact stored twice, one copy edited.**
Keep the generator authoritative and make regeneration idempotent, or a future
loop will repeat this.

#### Mutations run in a sandbox, because `finally` is not a safety net

Mutation harnesses restore the tree in a `finally`, which does not run when the
process is killed — and `subprocess.run(timeout=...)` kills. This already
happened: `verify_loop40` was interrupted at 44 minutes and left
`src/channel/channel.mbt` with the `env` name/value pair swapped. The tree was
restored byte-exactly (via `git show` + a binary write; `git show | Out-String`
turns a 2-line change into a 717-line diff, and `git checkout --` is forbidden).

`ci/sandbox.py` runs the mutations tier against a throwaway `git worktree` with
the current uncommitted state applied on top, so the tree that matters is never
written to.

#### QA matrix: 20 categories, each with evidence

`ci/qa.py` classifies 20 QA categories as `implemented` / `not_available` /
`needs_external`. Every `not_available` carries the probe that proves it, and
the matrix is printed in full — omitting a category is the failure mode to
avoid. Notable: **Gherkin does exist** (`moonrockz/gherkin@0.5.1`); it is
unavailable *here* only because `moon.mod` declares neither it nor `cucumber`,
and adding dependencies is out of scope. Also merged rather than shipped twice:
`static-code-check` into static-analysis, `contract-test` into
api-interface-contract — this project has been bitten three times by two copies
of one fact. Two commands that exit 0 while testing nothing were caught and are
guarded: `moon bench cmd/bench_cached` and `moon test -p src/channel` both
report "Total tests: 0".

`python ci/ci.py --tiers qa` currently reports **8/12 pass, 4 fail**
(`format-check`, `moon check --deny-warn` with 114 `test_unqualified_package`,
`moon coverage analyze` with no data, `moon bench` hitting `extern "wasm"` on
native). Not hidden. ~~`moon fmt --check` failing is expected and must not be
"fixed" by running `moon fmt`: that corrupts CJK comments
(`真实加密` → `真加密`).~~ **Superseded by Loop #67**, which measured the CJK
claim three ways and found no damage on `moon 0.1.20261012` — 12,840 runs
across 226 files, byte-identical after a whole-tree format. The format-check
row is now green. The other three rows moved as follows: the static-analysis row
went green in Loop #66 (8/12 → 9/12); `moon coverage analyze` and `moon bench`
are still red, for the reasons recorded under Loop #66 and Loop #67.

#### Release gate

`ci/release.py`. **No tag while the local CI is not fully green — including when
the owner asks directly.** The gate does not know who is asking; the tag is
produced by `git tag` from `next_tag()`, never hand-typed. `next_tag` moves only
the trailing number (`v0.1.0` -> `v0.1.1`), preserving zero padding, and refuses
rather than guessing when there is nothing to move. Gitee may be pushed at any
time; GitHub only after a green run and a tag. Tiers excluded from the tag
decision (`peer-gates`, `mutations`) are printed at the moment the decision is
made, not hidden.

**Both halves of that rule now have a remote, as of 2026-10-19.** This file
previously said the GitHub half was "policy with nothing to act on yet"; that is
no longer true and the note was removed rather than left to mislead:

| remote | URL | role |
|---|---|---|
| `origin` | `git@gitee.com:ren-yongxiang/moonbit_openssh.git` | day-to-day storage |
| `github` | `git@github.com:riantr/moonbit_openssh.git` | version/release updates |

The Gitee repository was renamed from `moonbit-openssh` to `moonbit_openssh` and
re-created empty, so this is a move rather than a second origin -- one remote per
host, and `origin` still means "the one you push to normally". The rename is why
the old path 404s now: `git ls-remote` on it fails with `404 not found`, which is
worth knowing before anyone concludes the SSH key broke.

The GitHub rule is unchanged and still has teeth: a green run is necessary but
not sufficient. `v0.1.1` was computable the moment qa reached 12/12, and pushing
it to GitHub still required the tag to exist first.

A self-check case caught a contradiction here: this file originally promised to
refuse a date-shaped tag like `release-2026-10`, while the implementation
incremented it. The implementation matched the owner's rule ("only the last
digit moves"), so the *promise* was corrected, not the code.

#### Left open: verify_loop41 fails in the suite and passes alone

The default tier is **43/44**, with one red: `verify_loop41.mjs` exits
`3221226505` (`0xC0000409`, a native abort) inside a suite run, while running
it standalone passes — three times in a row, 29 checks each. It is not flaky
on its own, so something else in the suite affects it.

**Whether this predates Loop #65 is NOT established.** The evidence leans that
way — this loop changed only `ci/ci.py` (the peer-gate set and the mutations
sandbox) plus new files under `host/`, touched nothing in `src/` or `cmd/`,
and loop41 shares no state with loop40 — but leaning is not proving, and the
attempt to prove it failed three times: a `git worktree` is a plain checkout,
so it has no `node_modules`, and `verify_loop41.mjs` imports the npm `ws`
package. Every control run therefore died with `ERR_MODULE_NOT_FOUND` before
reaching any assertion. The experiment needs `npm install ws` in the worktree
first; until then this is an open question, not a result.

#### Also learned this loop

- MoonBit type parameters go **before** the name: `fn[T] f`, not `fn f[T]`.
  This was got wrong three times during the migration.
- `src/tcp` has a `moon.pkg` warning about `moonbitlang/core/bytes` being unused
  — pre-existing, harmless.
- `[System.IO.File]` with a relative path resolves against the *process* CWD,
  not `Set-Location`, so an encoding check reported `INVALID-UTF8` for files it
  had never read. Always use absolute paths there.

### Loop #63: the browser path has never run, and on this toolchain it cannot

Loops #60, #61 and #62 each found a thing that looked tested and was not — a
proposal naming an algorithm it cannot run, a function with a swapped argument
order, a gate that trusted its own emitter. This is the same defect at the
largest scale in the tree, and it concerns the reason this project exists.

**The claim.** `docs/socket/loop23-summary.md` records Loop #23 as "PASS (with
caveat)", `host/verify_loop23.mjs` is titled as a verification of
`cmd/ssh_full_ws`, and across Loops #23–#33 the browser path is described as
byte-exact verified. The goal — SSH from a browser — rests on it.

**What is true, in four pieces.**

- **`src/sshclient/live.mbt` is the only code that performs a real, verified
  handshake, and it is bound to `@tcp.TcpConn`.** It does not import
  `src/ws_socket`. That is native TCP, and it *is* genuinely verified: Loops
  #54–#59 run it against a real peer.
- **`cmd/ssh_full_ws` compiles and does not do a handshake.** It reads the
  server's KEXINIT and KEXDH_REPLY into `let _ =` — discarded — never
  negotiates, never parses a host key, never verifies a signature, never derives
  a session key, and continues in plaintext after NEWKEYS. Its `read_n` calls
  take lengths computed by `make_server_*_reply().length()`: the peer is a
  hardcoded byte blob, and the client knows in advance how long each answer is.
  That is the shape of a scripted replay, not of a protocol.
- **`verify_loop23.mjs` runs no MoonBit code.** Both sides are JavaScript — a
  Node WebSocket client against a Node mock server, with hand-written algorithm
  lists standing in for the client's. Its own header says the MoonBit side was
  checked by compilation only and points at `verify_loop22.mjs`, a `MockSocket`
  path that is not a socket.
- **`host/node_host_wasm.mjs`, the host that would run the wasm, has never
  run.** Zero callers. And it had an `await` inside a non-async function, so
  the file could not even be parsed — `moon build` never loads it and nothing
  ever noticed. Its `ws_recv_into` throws on a short buffer, with a comment
  conceding that blocking is unsupported and MoonBit has no retry.

**Why it cannot be fixed by restructuring the client.** wasm-gc exports exactly
one symbol, `_start`. There is no way for a host to re-enter the module between
reads, so a synchronous `Socket::read_n` inside a wasm frame can never yield to
the event loop that a WebSocket's `onmessage` needs. `cmd/probe_export` exists
to make that falsifiable rather than a claim in a comment: a plain `pub fn`,
built and inspected, **does not appear in the export table**. If MoonBit ever
grows an export mechanism, section A of the gate fails and this reasoning has
to be revisited — which is exactly why it is a gate and not a paragraph.

The escape that does work is `--target js`, which shares `src/` and supports
async I/O. That is the next piece of work; this loop establishes what is true
today so it starts from facts.

**What was fixed here.** The `await` bug, so the file parses. Not the blocking
limitation — `ws_wait_for_bytes` is now `async` and correctly documented, but
`ws_recv_into` still refuses to block, and the gate asserts both that refusal
and the absence of callers, so nobody reads the file as a working path.

**Three gate defects, all mine, and one of them nearly inverted the finding.**

- The syntax check ran `node --check node_host_wasm.mjs` with `cwd` at the repo
  root. The file is in `host/`, so Node reported a missing-module error that
  reads exactly like a syntax error. **Asking Node to parse a file that is not
  there is not a parse.**
- The "discarded reads" regex used `[^)]*`, so it truncated at the inner `)` of
  `make_server_kexinit_reply().length()` and concluded the reads were *not*
  scripted — the opposite of the finding. **A regex that cannot count its own
  parentheses will confidently agree with anything.**
- The caller scan matched this gate's own header comment and reported
  `verify_loop63.mjs` as a caller. It now excludes itself and strips comments
  before matching, because a comment runs nothing.

**Mutation D was my error, not the gate's.** The first version wired a "caller"
in by appending a comment naming the host — and the gate reported MISSED,
correctly, since it strips comments. A mutation that does not change behaviour
cannot test a behaviour check. Rewritten as a real `execSync` spawn, it is
caught.

**Results.** `verify_loop63.mjs` 23/23, `loop63_mutations.py` 5 CAUGHT /
1 EQUIVALENT / 0 MISSED. Loops #53–#62 unchanged.

**What this loop does not do.** It does not build a browser client. It states,
with evidence, that the browser client does not exist yet — that MoonBit does
real SSH over native TCP, and compiles to wasm, and that the two have never been
joined. The next honest step is the transport abstraction that would join them,
or the `--target js` route that sidesteps the blocking read entirely.

### Loop #62: `flow_on_reply` completes a real handshake, and the three bugs were in my vectors

Loop #61 ended by naming what it had *not* proved. Quoting itself:

> `flow_on_reply` has no caller and no end-to-end test. Argument order and the
> derived length are pinned, but "this function can complete a handshake" is not
> yet a claim anything here can support.

This is that claim, with a vector set behind it.

**Result: 7/7, and the client code changed not at all.** That is the headline,
and it needs stating plainly because the opposite would have been easier to
write. `flow_on_reply` was correct once Loop #61 fixed it. What was missing was
the ability to *know* that — and the three defects I spent most of this loop
chasing were all in my own vector generator. `from_blob` reporting
`InvalidFormat` was **right**; the blob I handed it was malformed.

**The vectors are two-blind.** `host/gen_flow62_vectors.py` implements the server
half independently: X25519 and Ed25519 from Python's `cryptography`, and the
exchange-hash layout transcribed from kexgen.c:67-82 rather than copied from
`src/kexc25519/exchange_hash.mbt`. H and the signature are each computed twice by
code sharing nothing with the tree. The generator's own RFC 7748 implementation
is cross-checked against `cryptography` — they agree on every seed, and if they
did not, the generator would not be independent at all.

**The three generator bugs, and how each was found.** None by re-reading RFC
4253; all three by a probe, because a gate that cannot say *why* a case failed
is a gate you end up debugging by hand:

1. **K_S was `type ‖ pubkey`** — missing the key's own length prefix.
   `from_blob` said `InvalidFormat` and it was correct.
   Probe: `FLOW_PROBE <id> from_blob=<...> ks_len=<n>`, gated on the length being
   51 so a truncated blob cannot pass as "parsed".
2. **I_C was a copy of I_S.** The exchange hash covers both, so the signature
   could never verify. Probe: `FLOW_H <id> h=<hex>`, diffed against the `h =`
   line the generator wrote. A hash mismatch is unambiguous — exactly one side
   has the layout wrong, and this says which. Both now agree byte for byte.
3. **The signature blob had an extra length prefix** around the algorithm name.

I also spent two attempts "fixing" the signature framing by reasoning from memory
before re-reading `HkCursor::get_cstring`, which settles it: the algorithm name
*is* a length-prefixed string, because `get_cstring` is built on `get_string`.
The project's own rule — constants and formats come from sources, never from
recall — has a cost, and this is what the cost looks like.

**V7 is the case that matters.** The server signs an exchange hash computed over
a *different* Q_S than the one it transmits: a substituted server public key, the
classic active attack on curve25519 ECDH. The client recomputes H from its own
view and rejects it. The vector file records both `h` and `h_signed`, so the gap
between them is visible in the file rather than only in a failure message.

**What the mutations actually proved: 3 CAUGHT / 2 MISSED / 1 EQUIVALENT.** The
two MISSED are the most useful output, and they are limits of the gate, not
defects in it:

- **Hardcoding the derivation length to 64 again is invisible here.** Correct
  for chacha20-poly1305, which is the only cipher every vector negotiates. A
  chachapoly-only vector set structurally cannot see it. Loop #61's gate catches
  it by reading the source, which is the honest division of labour: **a vector
  set tests behaviour; a source check tests an invariant about code shape.**
  Closing this properly means an `aes128-ctr` vector, the day the browser path
  can carry a non-AEAD cipher.
- **Removing the `session_id == H` assertion is invisible by construction.** The
  emitter reports a variant name, and both a correct and a wrong session id
  produce `Established`. Making it observable is a change to the harness.

The caught one worth naming is **C: skip host key verification entirely.** A
client that never checks the signature reports `Established` for V1/V2 and
`SignatureInvalid` for V5/V7 — the *same* verdicts as a correct client, because a
broken signature and an unchecked one look identical from outside. V5 and V7
catch it. **That is what makes the negative cases worth having.**

Getting C to compile took three attempts, and the first two were caught by the
**compiler**, which proves nothing about the gate; the script now says so in
those words. MoonBit rejects a multi-line argument list in a `let` binding that
it accepts inside `match`, so the working mutation keeps the original statement
shape and changes one arm.

**Two harness defects, both mine.**

- The drift check used `git status --porcelain`, which reports `??` for a new
  uncommitted file — so it failed every run for a reason that had nothing to do
  with reproducibility. **A drift check that cannot tell "changed" from
  "untracked" is not a drift check.** It compares bytes before and after.
- The generated vector file was not in the mutation snapshot. The gate
  regenerates it as its first step, so a generator mutation rewrote it on disk
  and the *next* mutation started dirty. Not theoretical: mutation F was
  reported CAUGHT purely because E had left a wrong expectation behind, when F
  should be EQUIVALENT.

**Tooling, self-inflicted.** Twice more this loop, PowerShell `python -c` with
multi-line `\n` inside single-quoted strings mangled the replacement text, so
the anchor matched already-corrupted content and reported a syntax error from a
line I had never written. Restored with `git checkout --` on a file I was
mutating on purpose. The rule stands: script files go through the file tools.

**Results.** `verify_loop62.mjs` 35/35, `flow_kat` 7/7, three distinct verdicts
across the set. `loop53`–`loop61` unchanged. `moon test src/kexflow` 15/15,
`src/hostkey` 25/25, `src/bpacket` 25/25.

**What this loop does not cover.** `cmd/ssh_full_ws` still calls `flow_start` and
stops; nothing runs the browser path end to end over a socket. What is now
proven is that `flow_on_reply` turns a real, independently signed REPLY into the
right verdict — the framing around it is still untested.

### Loop #61: the kex and host key axes, and the function that had never been run

Loop #60 left kex and hostkey out of scope and said so. This closes that, and
the reason it was left out is where the real defect turned out to be.

**`flow_on_reply` could never succeed.** It called
`derive_keys(shared_mpint, h, we_need)`. The signature is
`derive_keys(hash, shared_secret_mpint, we_need)`, and `derive_single`
concatenates `K ‖ H ‖ letter ‖ session_id` (RFC 4253 §7.2), so the call site had
the two operands swapped: K1 was computed as HASH(H ‖ K ‖ letter ‖ H), and
`session_id` came back as the shared secret. The `session_id == h` assertion two
lines below therefore failed every single time, and reported
`Failed(ProtocolError)` — "the peer's bytes are malformed" — for a bug that is
entirely ours. `cmd/sshclient/live.mbt` calls the same function the other way
round, and that path is validated against a real sshd, which is what makes the
disagreement decidable.

Nothing caught it because **the function has no caller**. `cmd/ssh_full_ws`
calls `flow_start` and stops. A function that has never run cannot have been
tested, and the other two defects were sitting in the same unlit room:

- **`FLOW_WE_NEED = 64` hardcoded.** Right for chacha20-poly1305, silently the
  wrong length for anything else — which is how an unrunnable cipher could still
  produce a *successful* `Established`. Now derived from
  `@bpacket.transport_params`.
- **"We cannot answer this algorithm" was reported as `ProtocolError`.** Two
  new variants, `AlgorithmNotRunnable` and `CipherNotRunnable`, kept separate
  because the owner differs: the first is fixed by changing a proposal, the
  second by adding to `src/bpacket`. The tree had already made this split once,
  for `@cert-authority`, precisely because reporting it as `HostKeyMismatch`
  walks the user into `--kh-tofu`.

**The argument swap is now pinned by a test, not by reading code.** Both
parameters are `FixedArray[Byte]`, so MoonBit cannot see a swap — a compile
error would have been the cheapest possible defence and does not exist. `t12`
asserts that `session_id` is the hash argument and that `K‖H` and `H‖K` derive
different keys.

**What I suspected and found clean, before writing anything.** I expected the
host key list to be the real problem — a client advertising RSA and ECDSA host
keys it cannot verify would be a genuine security defect. It is not:
`HostKey::verify` does ed25519 and ECDSA, and `verify_with_alg` adds the RSA
path (Loop #38) precisely because RFC 8332 means the negotiated name is not the
blob's type string. All five names are backed. Recorded because "I checked and
it was fine" is a result, and because the next person should not redo it.

I also expected `cmd/ssh_full_ws` to carry a hand-copied proposal literal
still naming the EtM MAC Loop #60 removed. It does not — it calls
`Proposal::default_client(false)`, and its `make_server_kexinit_reply` is a mock
*server*, exempt by design. Two of my three suspicions this loop were wrong,
and both were caught by reading the source instead of the grep hit.

**Two false positives, and what they were really telling me.** The first honest
run reported `default_client/strict=true` and `live_proposal_with_certs=true` as
over-promising. Both wrong, and the reasons matter:

- `kex-strict-c-v00@openssh.com` **is not a key exchange**. OpenSSH appends it
  in `kex_proposal_populate_entries` to signal strict-KEX, and `ssh -Q kex`
  lists twelve algorithms that do not include it. Treating it as unimplemented
  makes the gate demand the marker's removal — and the fix anyone reaches for
  under that pressure is to drop it and turn off strict KEX. **A gate that
  demands a security property be deleted is a security regression wearing the
  costume of a failing test.**
- `ssh-ed25519-cert-v01@openssh.com` is gated by **policy**, not by
  implementation: Loop #53 parses and validates certificate structure but
  deliberately refuses certificates as host keys. `ssh -Q key-plain` and
  `ssh -Q key-cert` are two disjoint lists, which is the authority saying
  exactly this.

So a name list is not a uniform list of algorithms. The emitter now has four
verdicts — `ok`, `NO-PATH`, `MARKER`, `POLICY-GATED` — and the gate asserts the
classification rather than the binary, so a checker that answered `ok` for both
would fail.

**Gate defects found, all of them mine.** Four, and one of them a repeat:

- The check used `ssh -Q key-plain` for all five host key names and failed on
  `rsa-sha2-256` / `rsa-sha2-512`. It was right to fail: those are *signature*
  algorithm names (RFC 8332), not key types, and `key-plain` lists `ssh-rsa`.
  I made the RFC 8332 conflation in the very checker that exists to prevent it.
  The category is `ssh -Q key-sig`.
- `verdictFull === undefined` against a `null` initialiser — **the exact same
  bug Loop #60 made with `verdict_stoc`**, five confident wrong failures. Same
  gate-author, consecutive loops, same defect class: the process needs a rule,
  not just the fix. In these emitters every optional field starts `null`, so the
  test is `!field`, never `=== undefined`.
- The source-text checks read my own explanatory comments. The comment
  documenting the swap contains `derive_keys(hash, shared_secret_mpint, ...)`,
  and the one documenting `FLOW_WE_NEED` says "`FLOW_WE_NEED` was 64" — three
  confident failures caused by the gate reading its own documentation. **A
  comment explaining a bug will always contain the bug's text**, so every
  textual gate now runs on comment-stripped source.
- Mutation B **slipped through**: `expect(...flowBody.includes("@bpacket.transport_params"))`
  was satisfied by a leftover mention while the length was hardcoded. That is the
  hollow-check shape again, and the mutation is now `let we_need : Int = 64`
  with the mention removed, caught by asserting the *assignment* — seeded from
  `we_key`, raised by `we_mac`, never bound to a numeric literal.

**Results.** `verify_loop61.mjs` 62/62, `loop61_mutations.py` 5 CAUGHT /
1 EQUIVALENT / 0 MISSED. `verify_loop60.mjs` unchanged at 73/73 and `loop53`–
`loop59` still ALL PASS. `moon test src/kexflow` 15/15, `src/hostkey` 25/25,
`src/sshconfig` 10/10, `src/knownhosts` 49/49, `src/bpacket` 25/25.
`src/kexflow` and `src/hostkey` check clean on all four targets.

The equivalent mutant is `flow_on_reply`'s new cipher guard short-circuited to
`&& false`: unobservable today because every client proposal offers only
chacha20-poly1305, so an unrunnable cipher is never negotiated. Dead defence
now; live the moment a second cipher enters a proposal.

**Still open, and named so it is not mistaken for done.** `flow_on_reply` has
no caller and no end-to-end test — a real handshake vector through the browser
path would be the next thing worth building. Argument order and the derived
length are pinned, but "this function can complete a handshake" is not yet a
claim anything here can support.

### Loop #60: a client proposal may only name algorithms the packet transport can run

The invariant is one line. Writing it down is most of the work.

**What `src/bpacket` can actually run.** `Mode` has three constructors
(`packet_ctx.mbt:34-38`), so there are exactly two encrypted transports behind
them:

| cipher | `Mode` | files |
|---|---|---|
| `chacha20-poly1305@openssh.com` | `Aead` | `chacha_*.mbt` + `poly1305_*.mbt` |
| `aes128-ctr` | `MacEncrypt` | `aes_ctr_mac.mbt` |

and exactly one MAC the `MacEncrypt` branch can compute: `hmac-sha2-256`.
`packet_ctx.mbt:32` already said EtM is unimplemented; this loop makes that
statement enforceable instead of documentary.

**Defect 1 — `kexflow::default_client` advertised an algorithm it cannot run.**
Its MAC list led with `hmac-sha2-256-etm@openssh.com`. Nothing had ever failed,
because that proposal's cipher is an AEAD and an AEAD never computes the MAC:
the over-promise was harmless *by coincidence*, and the coincidence is invisible
to every test that exists. It is not a near-miss of a name either — `mac.c:62`
and `mac.c:72` are two different rows with `etm=0` and `etm=1`, so EtM is a
different algorithm, not a spelling variant of the one we implement. The list is
now `hmac-sha2-256`.

The reason a coincidence is not a property is worth spelling out: change one
line of `enc_ctos` to `aes128-ctr` and `negotiate` hands back the EtM name,
because `pf_match_list` scans *our* list first. The client would then have
agreed to an algorithm it cannot run, in a handshake it just completed.

**Defect 2 — `we_need_for` was a second, looser parameter table.**
`sshclient/live.mbt` accepted four ciphers and five MACs, and the caller then
truncated the derived key to 16 bytes and built an `AesCtrMacCtx` regardless of
what came back. A proposal naming `aes256-ctr` would have run **aes128-ctr with
the first 16 bytes of a 256-bit key**, and reported nothing. Latent — no live
proposal offered it — but it failed *open*, and it was one line from live.
`we_need_for` now delegates to `@bpacket.transport_params`, which aborts on
anything without a `Mode` branch, and the `16`s are gone from `live.mbt`:
they come from the table now.

`live.mbt` also gained a routing guard. That path builds a `MacEncrypt` context
and nothing else, so an AEAD agreement would need the `ChachaPolyCtx` branch and
has to fail loudly instead of being fed into the wrong constructor.

**Scope is deliberately asymmetric.** A *client* proposal is checked. A *server*
proposal is not: negotiation takes the intersection, so a peer may name anything
and the handshake still lands on something we can run. `host/verify_loop23.mjs`'s
six-cipher list is a **server** proposal and is exempt — that was worth stating
because it looks exactly like the thing this loop forbids.

The gate proves the exemption still holds, rather than merely not contradicting
it: `cmd/proposal_kat` emits a deliberately-broken peer fixture (two names with
no packet layer) and the gate asserts it is still `scope=server` and still
unjudged. A gate that had quietly widened into "reject every name we do not
implement" would pass a much simpler test and break connectivity against real
sshd for no safety gain.

**The third truth source is deleted, not trimmed.** `src/kex_names` had four
unused `*_default()` functions naming 6 ciphers and 6 MACs — a third place to
learn algorithm names from, and the part that would most invite the same bug
back. They are gone; the name↔enum mapping stays, because that is a spelling
table and makes no claim about what executes. The GCM ciphers are the sharp
case: `src/aes` really does implement AES-GCM, so "the name resolves" and "the
transport runs it" look identical from the outside.

**Numbers come from outside this tree.** Every parameter is cross-checked
against OpenSSH's own tables in the C reference tree, not transcribed:
`cipher.c:93` / `:105` for `block_size`/`key_len`/`iv_len`/`auth_len`, and
`mac.c:62` for the MAC. `cipher_ivlen` (cipher.c:170-178) is why chacha20's
`iv_len` is 0 and aes128-ctr's is 16 — the same column, two different answers.
Names are cross-checked against `ssh -Q cipher` / `ssh -Q mac`.

That last cross-check earns its keep by including the name we *removed*. If
`hmac-sha2-256-etm@openssh.com` were not a genuine OpenSSH MAC, deleting it
would be a typo fix rather than a policy fix, and the two deserve different
confidence.

**Seven gate failures on first run, all of them real.** Worth recording because
four were self-inflicted and two were the *correct* kind of catch:

- `verdict_stoc` was initialised to `null` and compared against `undefined`:
  five confident wrong failures out of a parser that was working.
- The gate compared OpenSSH's `auth_len` against our `mac_key_len` slot. Two
  different quantities; the accessor for the right one simply did not exist.
- That gap then let `authlen_for` ship a wrong answer: it returned 32 for
  aes128-ctr, where OpenSSH's `auth_len` is **0** and the 32-byte MAC lives in
  `mac_len`. The C cross-check caught it on the next run. "Looks right" and
  "is right" are separate properties, and only the outside authority had the
  second one.
- One check asserted a test *name* appeared in `moon test` output. moon prints
  names only for failures, so it could never pass — and looked exactly like a
  real assertion. This is the same shape as Loop #59's regex that matched
  nothing.

**The gate does not trust the emitter.** `proposal_kat` tags each name
`ok` / `NO-PATH`, but the gate keeps its own copy of the runnable set and
recomputes. Trusting the label would mean the same package evaluating the same
predicate twice — both sides agree, both are wrong, mutation B would pass. That
check exists because mutation B is the one most likely to be written by someone
who "just wanted it to work".

**Results.** `verify_loop60.mjs` 73/73, `loop60_mutations.py` 5 CAUGHT /
1 EQUIVALENT / 0 MISSED. Gate `loop53`–`loop59` all still ALL PASS;
`moon test src/kexflow` 14/14, `src/sshconfig` 10/10, `src/knownhosts` 49/49,
`src/bpacket` 25/25. `src/bpacket` and `src/kexflow` check clean on all four
targets (native / js / wasm / wasm-gc).

`cmd/ssh_live` does **not** build for js / wasm / wasm-gc, and did not before
this loop either: Loop #54 gave `--kh-file` real disk writes through
`moonbitlang/async/fs`, which is native-only. Noted so nobody reads the failure
as a Loop #60 regression.

**The equivalent mutant is the interesting one.** Short-circuiting the new
cipher routing guard to `&& false` changes nothing observable, because
`live_proposal` offers only `aes128-ctr` and the guard never fires. That is a
correct classification, not a gap in the gate: the guard is dead defence on
today's inputs and starts mattering the moment a second cipher becomes
negotiable. Reported as a finding rather than quietly excluded.

**What this loop does not cover.** The invariant is enforced over cipher and
MAC only. `kex_algs` and `hostkey_algs` have the same shape of problem — a
client naming an unimplemented kex would fail the same way — and are tagged
`kind=info` in the emitter so `NO-PATH` always means "over-promising on the
transport". Widening the gate to kex and hostkey is a separate decision with a
real connectivity cost, and it is not silently bundled in here.

**Tooling note, self-inflicted.** A PowerShell one-liner intended to add return
type annotations resolved its path against the *PowerShell* working directory
rather than the process one, and `WriteAllText` truncated
`cmd/proposal_kat/main.mbt` to 0 bytes. The project rule against PowerShell file
editing already covers this; the new datum is that the failure is **silent and
destructive** rather than an error, and `git status` is the only thing that
showed the scope was limited to one new file. Recovered by rewriting the file.

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

