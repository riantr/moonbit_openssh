# Loop #12 Summary — KEX flow (kexflow)

**Status**: CLOSED — PASS_OVERALL
**Date**: 2026-08-26

## Result

| Layer | Pass rate |
|-------|-----------|
| MoonBit test suite | 216/216 |
| C harness | 14/14 |
| Python self-check | 6/6 (including ed25519 sig roundtrip) |
| Vector cross-check (Python ↔ C ↔ MoonBit, byte-exact) | ✓ |

The MoonBit `kexflow` package ports OpenSSH's `kexgen.c` + `kex.c` client-side
flow (CURVE25519 KEX + ssh-ed25519 host key + chacha20-poly1305 AEAD) from C
to MoonBit, using the three积木 from Loops #9–11 (hostkey, kexc25519,
bpacket) imported as packages.

## What was built

### Source (`src/kexflow/`)

- `moon.pkg` — DSL-syntax import: `hostkey`, `kexc25519`, `bpacket`
- `proposal.mbt` (9.1 KB) — `Proposal` struct, `default_client`,
  `kexinit_payload` (kex_prop2buf layout), `parse_kexinit` (direct-index
  variant, see §Bugfix), `Negotiate`, `PeerKexInit`, `Negotiated`,
  `NegotiationError` enum
- `flow.mbt` (7.5 KB) — `FlowConfig`, `flow_start` (kex_gen_client),
  `flow_on_reply` (input_kex_gen_reply), `Established`, `ReplyOutcome`,
  `FlowError` flat 5-variant enum
- `kexflow_test.mbt` (generated, 10 tests T1–T10) — 216/216 PASS

### Verify (`verify_c/`)

- `kexflow_python_ref.py` (12 KB) — deterministic server + V1–V5 vectors
- `gen_kexflow_test.py` (5.5 KB) — dual output: `kexflow_test.mbt` + `_kexflow_kat.h`
- `_kexflow_kat.h` (generated) — 22 byte arrays, 22 length constants
- `kexflow_harness.c` (10.7 KB) — links OpenSSH sshbuf + smult_curve25519 +
  sha2 + chacha + poly1305, ~150 lines of dispatch
- `build_kexflow.bat` — `gcc -O2 -Wall kexflow_harness.c -lm`
- `_kexflow_ref_out.txt` (no BOM, ASCII only)
- `_kexflow_kat_out.log` — `PASSED: 14, FAILED: 0`, exit 0

### Docs (`docs/kexflow/`)

- `navigator.md` — kexgen.c/kex.c source map, 8 reusable assets
- `architect.md` — package design + 6 decisions + 10 test cases
- `reviewer.md` — pass/fail evidence
- `reality-checker.md` — independent re-run
- `loop12-summary.md` — this file

## Bugfixes

1. **parse_kexinit PfCursor struct bug** — first implementation used
   `PfCursor { bytes, mut off, mut bad }` with methods that modified `self.off`
   in place. MoonBit's pass-by-value semantics for struct receivers in this
   build caused the modifications to be lost across method calls, so
   `c.off` never advanced past 0 and the parse always returned None with
   "trailing residual". **Fix**: rewrote `parse_kexinit` with direct index
   manipulation on a local `off: Int`. The unused `PfCursor` definitions
   are left in place pending a cleanup pass.

2. **MoonBit test template `@@` placeholder collision** — initial generator
   used `tpl.format(**vec)` with `{V1_xxx}` placeholders, but MoonBit's
   `{ }` syntax in `abort("...")` string literals collided with Python's
   format spec. **Fix**: switched to `@@KEY@@` placeholders with manual
   `str.replace`.

3. **MoonBit 0x1Fu8 syntax** — `assert_eq(reply[0], 0x1Fu8)` is a parse error
   in this MoonBit version. **Fix**: use `b'\x1f'` (Byte literal).

4. **MoonBit `assert!` is reserved keyword**. **Fix**: use `abort("...")`.

5. **MoonBit `pass` doesn't exist in test bodies**. **Fix**: use `()` (unit).

6. **C harness chacha counter byte order** — `chacha_ivsetup` takes
   counter as 8-byte LE u32; the payload encryption counter is 1, so
   `ctr_one = {1,0,0,0,0,0,0,0}` (NOT `{0,0,0,0,0,0,0,1}` which would
   put the 1 in the high half of the 64-bit counter).

7. **C harness `chacha_encrypt_bytes(ctx, m, c, len)` arg order** — first
   attempt swapped plaintext/ciphertext, causing the poly_key to contain
   uninitialized data. **Fix**: correct to `(ctx, plaintext, ciphertext, len)`.

8. **C harness V_C length** — `"SSH-2.0-OpenSSH_8.9"` is 19 bytes, not 20.
   Passing 20 caused a trailing garbage byte in the SHA-256 input. **Fix**:
   use `19` explicitly.

## Decisions ratified

- **D0**: kexflow imports hostkey + kexc25519 + bpacket via跨包 import
  (no inline re-implementation). This is a major space savings over
  Loops #9–11 which inlined.
- **D1**: kexflow is a pure message layer; frame encapsulation / encryption
  switching is the caller's responsibility (bpacket).
- **D2**: `FlowError` is a flat 5-variant enum (ProtocolError /
  NoAgreement(NegotiationError) / HostkeyInvalid / SignatureInvalid /
  SharedSecretInvalid), not a nested error hierarchy.
- **D3**: MAC proposal sends "hmac-sha2-256-etm@openssh.com,hmac-sha2-256"
  (OpenSSH default table first two entries; AEAD 下 the negotiated MAC is
  unused).
- **D4**: `strict_kex` flag appends `kex-strict-c-v00@openssh.com` to the
  kex list; does not auto-set `first_kex_packet_follows`.
- **D5**: cookie is caller-injected (16B test deterministic); production
  random belongs to the integration layer.
- **D6**: `c25519_shared_key_mpint(seed, f)` takes raw seed (API auto-clamps
  per RFC 7748 §5); no separate `sk` export needed.
- **D7**: loop priority is #12 KEX flow → #13 known_hosts → #14 RSA modexp verify.
- **D8**: KAT literals generated by `gen_kexflow_test.py` synchronously
  from `_kexflow_ref_out.txt`; no hand-copied expected values anywhere.

## Next loop

**Loop #13: known_hosts parsing + host_key_check**

The `cfg_snapshot_strict` plumbing is in place but no test exercises
`kex-strict-c-v00@openssh.com`. Loop #13 should:
1. Parse OpenSSH `known_hosts` format (one host per line, optional
   `hostnames,ip` comma list, key type tag, key blob, comment).
2. Match the negotiated host key against the relevant line.
3. Hook into `flow_on_reply` to add a `HostKeyMismatch` error variant
   if the server's host key is not in the trusted set (or if it is but
   with a different key, triggering the "host key changed" warning).
4. Wire the strict-kex path so that if both sides advertise
   `kex-strict-s-v00@openssh.com` and the negotiated algorithm is
   curve25519-sha256, the host key check is mandatory.

The `hostkey` package already provides `HostKey::from_blob` for both
ssh-ed25519 and ssh-rsa, so the KAT work for the key parsing half is
already done.

— Mavis
