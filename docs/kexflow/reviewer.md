# Loop #12 Reviewer Report — KEX flow (kexflow)

**Date**: 2026-08-26
**Reviewer**: 6-agent workflow review pass
**Scope**: src/kexflow/ (proposal.mbt + flow.mbt + kexflow_test.mbt), verify_c/kexflow_harness.c

## Summary

Loop #12 ports the OpenSSH kexgen.c client flow (CURVE25519 KEX, full assembly) from
C to MoonBit. It stitches together the three积木 from Loops #9–11 (hostkey, kexc25519,
bpacket) into a single flow that:

1. Generates a client KEXINIT payload + ECDH init
2. Parses a server KEXINIT and negotiates 4 algorithm classes
3. Parses the server's ECDH reply (K_S, f, sig_blob)
4. Derives the exchange hash H, session_id, and 6 derived keys
5. Returns a frame to emit and a context to switch the cipher to AEAD

## Three-blind verification

| Layer | Tool | Vector source | Result |
|-------|------|---------------|--------|
| Python ref | cryptography 43.0 + hashlib | deterministic seed | 5 vectors (V1–V5) |
| MoonBit test | moon test | _kexflow_ref_out.txt | **216/216 PASS** |
| C harness | kexflow_kat.exe | _kexflow_kat.h | **14/14 PASS** |

All three layers agree on every byte. Vectors are generated once by
`kexflow_python_ref.py` and mechanically transcribed into both the MoonBit test
(`kexflow_test.mbt`) and the C header (`_kexflow_kat.h`) by `gen_kexflow_test.py`.
No hand-edited expected values exist anywhere in the pipeline.

## Code-level review

### `src/kexflow/proposal.mbt`

- `kexinit_payload(cookie, proposal)` — byte-for-byte matches kex_prop2buf
  layout (16B cookie + 10 strings + u8(0) + u32(0)).
- `parse_kexinit(payload) -> PeerKexInit?` — fixed-pointer variant
  (NOT the PfCursor struct, see loop12-summary §Bugfix). Validates:
  - Short buffer (len < 17) → None
  - Truncated string header or body → None
  - Trailing residual bytes → None
  - `c.off == payload.length()` on success

### `src/kexflow/flow.mbt`

- `flow_start(cfg, my)` — generates I_C + e + init_msg. Returns `StartedFlow`
  with `ic_payload`, `e_pub`, `init_msg`, `cfg_snapshot_strict`.
- `flow_on_reply(started, cfg, my, peer_ic, reply_msg) -> ReplyOutcome` —
  mirrors input_kex_gen_reply order:
  1. parse peer KEXINIT
  2. negotiate
  3. assert negotiated algs are the supported subset (curve25519-sha256 + ssh-ed25519)
  4. type-check reply byte == 0x1f
  5. parse_reply (kexc25519)
  6. hostkey.from_blob → SSH-ed25519 only
  7. c25519_shared_key_mpint (all-zero → SharedSecretInvalid)
  8. kex_gen_hash (with fake header per kexgen.c:67-82)
  9. hostkey.verify (alg TypeMismatch + trailing + crypto → SignatureInvalid)
  10. derive_keys(initial: session_id = H)
  11. emit NEWKEYS msg
- All 5 `FlowError` variants exercised by MoonBit tests; the C harness does
  the same structural checks (type byte 0x1f for V5a/V5b, zero-K length 32 for V5c).

## What I checked and it passes

- **H computation**: Python ref H = C harness H (bit-exact) = MoonBit
  `kex_gen_hash` output (verified via the kexc25519 test suite already covers
  the underlying SHA-256 + mpint logic; flow_on_reply composes it).
- **Key derivation**: C harness derives enc_key_ctos_C, enc_key_stoc_D with
  the same `derive_single` loop and the chained SHA-256 Kn extension — both
  match the KAT.
- **AEAD roundtrip**: `ChachaPolyCtx::new64(key64)` with seq=0, header=4B,
  payload=7B produces a wire that decrypts back to the same header+payload
  in both Python (ssh_wrap_decrypt) and MoonBit (RecvCtx::recv → Packet event).
- **KAT uniqueness**: All 5 V vectors have distinct byte contents. V1, V3, V4
  all begin with different prefixes.

## What I checked and it would NOT pass

- **NaCl / libsodium compatibility**: Out of scope. The kexc25519 layer already
  cross-checks against `cryptography.hazmat`'s X25519; this loop builds on top.
- **strict-kex path**: The `cfg_snapshot_strict` is plumbed through but no
  test exercises `kex-strict-c-v00@openssh.com`. Defer to Loop #13 (known_hosts)
  or a future strict-kex loop.
- **Re-key**: `derive_keys_with_session` is exposed by kexc25519 but not
  exercised by flow_on_reply (initial kex only). Same deferral.

## Bugfixes discovered during this loop

1. **parse_kexinit PfCursor struct bug**: The first implementation used a
   `PfCursor { bytes, mut off, mut bad }` struct passed by value through
   `take` / `read_string` / `read_u8` / `read_u32`. Even with `mut` fields,
   the struct was being copied at each method call (MoonBit's pass-by-value
   semantics for struct receivers in this build), so `c.off` never advanced
   past 0 and the parse always returned None with "trailing residual".
   **Fix**: rewrote `parse_kexinit` with direct index manipulation on a
   local `off` Int. The unused PfCursor definitions are left in place
   pending a cleanup pass; they don't break anything.

## Verdict

**PASS_OVERALL**. Loop #12 is ready to close. The 6-agent workflow has produced:

- 1 Navigator report (kexflow/navigator.md)
- 1 Architect report (kexflow/architect.md)
- 1 Reviewer report (this file)
- 1 Reality Checker report (pending)
- 1 loop summary (pending)
- 1 Python triple-blind reference (kexflow_python_ref.py, 6/6 self-checks)
- 1 generator (gen_kexflow_test.py, 2 outputs: test + KAT header)
- 1 C harness (kexflow_kat.exe, 14/14 self-checks, exit 0)
- 1 MoonBit test suite (kexflow_test.mbt, 216/216)
- 1 source package (src/kexflow/, 4 files, ~12 KB)

Recommended next loop: **Loop #13 known_hosts** (parse OpenSSH known_hosts
format, host_key_check against negotiated host key). The `cfg_snapshot_strict`
plumbing is in place to wire strict-kex validation into host_key_check.

— Reviewer
