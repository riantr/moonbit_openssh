# Loop #7 Ed25519 — Code Reviewer Report

**Date:** 2026-08-25
**Role:** 🧪 Code Reviewer
**Scope:** Audit Ed25519 implementation against RFC 8032, OpenSSH ed25519.c (TweetNaCl ref10), and Python cryptography

---

## 1. Files Audited

| File | Size | Role |
|------|------|------|
| `fe.mbt` | 10.7 KB | Field arithmetic mod p = 2^255-19 (32 × 8-bit limbs, UInt64 storage) |
| `sc.mbt` | 8.4 KB | Scalar arithmetic mod L (32 × 8-bit limbs + Barrett reduction) |
| `ge.mbt` | 15 KB | Twisted Edwards group ops (p3/p2/p1p1/aff) |
| `ge_table.mbt` | 215 KB | 425-entry precomputed base multiples (from OpenSSH C, parsed via Python) |
| `api.mbt` | 6.3 KB | keypair_from_seed / sign / verify |
| `sha512_*.mbt` × 6 | 10.6 KB | SHA-512 inlined (3rd copy — known DRY debt) |
| `ed25519_test.mbt` | ~200 lines | 9 blackbox tests |
| `ed25519_wbtest.mbt` | 207 lines | 3 RFC 8032 KAT + 8 internal unit tests |

---

## 2. Critical Bugs Found & Fixed

### 2.1 🔴 `ge_equal_i8`: UInt64 shift-width bug (root cause of 9 test failures)

**Location:** `ge.mbt` — constant-time byte equality used by `choose_t`

**Bug:**
```moonbit
let y = x - 1UL
y >> 31   // ❌ UInt64: 0xFFFFFFFFFFFFFFFF >> 31 = 0x1FFFFFFFF (33 bits!), not 1
```

The C original (`crypto_uint32 y; y >>= 31`) is a **32-bit** shift giving exactly 0 or 1. The worker translated it to UInt64 but kept the 31-bit shift distance. Result: cmov received garbage masks like `0xFFFFFFFE00000001`, corrupting every table lookup in `choose_t`. This single bug broke `ge_scalarmult_base` → keypair/sign/verify all produced wrong output.

**Fix:** `(y >> 63) & 1UL`

**Lesson:** This is the same class of bug the Loop #4 X25519 hit ("UInt vs UInt64 shift semantics"). The worker had already fixed the identical pattern in `fe.mbt`'s `fe_equal16` but missed its twin in `ge.mbt`. **When fixing a shift-semantics bug, grep for ALL shifts of the same width class in the same loop.**

### 2.2 🟡 Signature malleability: s < L check applied after Barrett reduction

**Location:** `api.mbt` verify step 2

**Bug:** Original code did:
```moonbit
let s_sc = sc_from32bytes(s_bytes)   // ← barrett_reduce: ANY input → [0, L)
if !sc_is_in_range(s_sc) { return false }   // ← always true! No-op!
```

OpenSSH's C (`crypto_sign_ed25519_open`) checks `sc25519_inrange(sm+32)` on the **raw bytes before any reduction**. A signature with s ∈ [L, 2^256) must be rejected; checking after reduction accepts it (s mod L < L trivially). Our `s_at_l_rejected` test passed only **by accident**: R was set to identity so a later check happened to fail.

**Fix:**
- Added `sc_is_in_range_bytes(bytes)` comparing raw LE bytes against `sc_l`
- verify now checks raw bytes BEFORE `sc_from32bytes`
- Strengthened test: uses a real signed R with s replaced by L exactly, added `s_above_l_rejected` (L+1)

### 2.3 🟡 Test bugs that masked implementation correctness

| Test | Bug | Fix |
|------|-----|-----|
| `ge_pack_unpack_roundtrip` | Expected pack(unpackneg(p)) == p. Wrong: unpackneg returns −P by design, so the x-sign bit MUST flip. | Assert: bytes 0..30 identical, byte 31 low-7-bits identical, sign bit flipped |
| `tampered_msg_rejected` | Used `hex_to_bytes("hello World")` — non-hex chars map to 0 via `hex_digit`, so `'w'` and `'W'` both → 0x00. "Tampered" message was byte-identical to original! | Use real hex: `68656c6c6f20776f726c64` vs `68656c6c6f20576f726c64` (differs in one byte: 0x77→0x57) |
| `s_at_l_rejected` | R = all-zeros (invalid point); failure came from later stages, not the range check | Real R from actual signing; s := L |

**Meta-lesson (3rd occurrence):** test inputs built through lossy parsers (hex_digit silently zeroing invalid chars) can make tests vacuous. Always feed tests canonical hex literals and verify the input transformation is identity on your test data.

### 2.4 🟢 Hygiene fixes

- Removed leftover debug `println("after_init r0=...")` block (~20 lines) from `ge_scalarmult_base`
- Removed debug `println` from `fe_cmov_test` and strengthened it (b=0 no-op case)
- Removed stray `println` from Loop #4's `x25519_wbtest.mbt` (collateral cleanup)

---

## 3. C Harness Bug (harness-side, not algorithmic)

The first harness run showed `got sig` first-half zeros while memcmp reported PASS — contradictory. Root cause: my own harness allocated `unsigned char mout[16]` as the output buffer for `crypto_sign_ed25519_open`, which writes `smlen` (= mlen+64 ≥ 64) bytes into it and memsets the tail → **stack buffer overflow trampling adjacent locals**, including `sig`. The memcmp ran before corruption (legit PASS), hexdump ran after (showing trampled data).

Fix: size `mout` ≥ mlen + 64. After fix, hexdump shows byte-exact match on all 3 vectors.

Also noted: PowerShell merges native stderr into ErrorRecords making exit codes unreliable under `2>&1`; switched harness to stdout-only + explicit `$LASTEXITCODE` / `Start-Process -PassThru`.

---

## 4. Line-by-Line Conformance Check vs OpenSSH ed25519.c

| C function | MoonBit | Verdict |
|------------|---------|---------|
| `crypto_hash_sha512` | `sha512_*` inlined (Loop #5 verified) | ✅ |
| `crypto_verify_32` | `equal_32` (early-exit bool variant; vartime OK, public data) | ✅ equivalent |
| fe25519 unpack/pack/add/sub/mul/square/neg/cmov/equal/ge/freeze/pow2523/invert/getparity | fe.mbt | ✅ (fe_roundtrip + KAT confirm) |
| sc25519 from32/from64/to32/add/mul/reduce_add_sub/barrett/window3/2interleave2 | sc.mbt | ✅ (sc_zero/sc_one/sc_roundtrip/reduce_add_sub_l1 confirm) |
| ge25519 p1p1_to_p2/p3, add_p1p1, dbl_p1p1, mixadd2, setneutral, choose_t, scalarmult_base, double_scalarmult_vartime, pack, unpackneg_vartime, isneutral | ge.mbt | ✅ formulas match C line-by-line (verified against source lines 700–1300) |
| `crypto_sign_ed25519_keypair_from_seed` | `keypair_from_seed` | ✅ same clamp (&248/&127/\|64), same sk=seed‖pk layout |
| `crypto_sign_ed25519` | `sign` | ✅ same nonce/hram/s composition order |
| `crypto_sign_ed25519_open` | `verify` | ✅ sig[63]&224 check + raw-byte inrange + unpackneg + neutral-reject + dbl_scalarmult + pack-compare |
| `sc25519_inrange` (OpenSSH addition) | `sc_is_in_range_bytes` | ✅ after fix § 2.2 |

One intentional deviation: `crypto_verify_32` is branch-free; ours short-circuits on first diff. Acceptable — signatures/public keys are public data; no secret-dependent timing.

---

## 5. Verification Matrix

| Layer | Command | Result |
|-------|---------|--------|
| MoonBit full suite | `moon test` | ✅ **120/120**, 0 failures, 0 stdout noise |
| MoonBit compile | `moon check` | ✅ 0 errors 0 warnings |
| OpenSSH C ref (same .c file OpenSSH ships) | `verify_c\ed25519_kat.exe` | ✅ 4/4 (3× pk+sig+verify + tamper + malleability), exit 0 |
| Python cryptography 44.0.1 | `verify_c\ed25519_python_ref.py` | ✅ 3 KAT byte-exact vs wbtest constants + tamper/wrong-key rejection + 1024-byte msg |
| Cross-blind | MoonBit KAT constants ≡ Python output ≡ C output | ✅ byte-exact |

---

## 6. Sign-off

**Status:** ✅ APPROVED

Implementation is byte-exact against both independent references across all RFC 8032 vectors, rejects tampered messages/wrong keys/out-of-range s, and compiles clean. Remaining debt (non-blocking):

1. **SHA-512 3rd inline copy** — refactor when moon gains cross-package imports (tracked since Loop #6)
2. `sc_is_in_range(Sc)` now dead code path in verify (kept for potential internal use) — consider removal in DRY pass
3. `ge_double_scalarmult_vartime` pre[16] table rebuilt per call — fine for correctness-focused port; note as future optimization target

**签字:** 🧪 Code Reviewer — 2026-08-25
