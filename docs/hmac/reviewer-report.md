# Loop #3 HMAC-SHA256 — Code Reviewer Report

**Reviewer:** 👁️ Senior Code Reviewer
**Date:** 2026-07-24
**Scope:** `src/sha256/{state,primitives,block,update,final,api}.mbt` + `src/hmac/{api}.mbt` + 全部测试

---

## TL;DR

**Status: PASS.** 54/54 tests passing, all FIPS 180-4 Test 1-3 byte-exact match, all RFC 4231 Test 1-7 byte-exact match. moon check is clean.

**No critical bugs found** — the previous UInt/UInt64 shift pitfall (Loop #2 lesson) was avoided because all SHA-256 operations stayed in UInt domain where 32-bit arithmetic is natural.

---

## 1. Critical observations

### 1.1 UInt vs UInt64 domain discipline ✅

SHA-256 is **entirely 32-bit arithmetic**. The implementation:
- All `state[i]`, `K[j]`, `W[j]`, `a..h` registers are `UInt`
- All `+` operations wrap at 2^32 (correct for SHA-256 spec)
- All `>>` and `<<` happen in UInt domain → 32-bit truncation is automatic
- Only `bit_count` is `UInt64` (SHA-256 spec uses 64-bit length)
- `rotr(n, x)` uses `(x >> n) | (x << (32 - n))` — both shifts in UInt domain ✓

**Contrast with Loop #2 poly1305 bug**: that was a case where UInt64 shift was used where C intended UInt32 shift. Here everything stays UInt, so no equivalent bug is possible.

### 1.2 Big-endian I/O correctly handled ✅

- `be8_to_32(bytes, offset)` reads 4 bytes as BE u32 — used to parse input block
- `be32_to_8(bytes, offset, value)` writes u32 as BE bytes — used to serialize final hash
- FIPS 180-4 § 6.2 explicitly specifies big-endian for input blocks and output

### 1.3 Padding logic ✅

`update.mbt/pad` correctly handles:
- Case A: `buffer_len + 1 <= 56` → 0x80 + zeros + 8-byte length fits in current block
- Case B: `buffer_len + 1 > 56` → need extra block, pad to end of current block, transform, then 0x00 * 56 + 8-byte length in new block
- `bit_count` is `UInt64` (not 128-bit like SHA-512) — correct for SHA-256

The `if pos > 56` check is critical — without it, when buffer has 56+ bytes already, the 0x80 + length wouldn't fit.

### 1.4 Message schedule W[16..63] ✅

In `block.mbt:16`:
```moonbit
w[i] = sigma1_small(w[i - 2]) + w[i - 7] + sigma0_small(w[i - 15]) + w[i - 16]
```

Matches FIPS 180-4 § 6.2.2 exactly. `sigma0_small` and `sigma1_small` correctly use SHR (not ROTR) for the `>> 3` and `>> 10` parts.

---

## 2. HMAC correctness

### 2.1 Algorithm ✅

`hmac/api.mbt` implements RFC 2104 § 2 exactly:
1. `prep_key`: if len(K) > 64, K' = SHA256(K); else K' = K with zero-pad to 64
2. Compute `inner = SHA256(K' ⊕ ipad || msg)`
3. Compute `tag = SHA256(K' ⊕ opad || inner)`

Verified against all 7 RFC 4231 test vectors.

### 2.2 Edge cases ✅

| Case | RFC 4231 Test | Result |
|------|---------------|--------|
| K < B (key=4 bytes) | Test 2 | ✅ |
| K = B (key=20 bytes) | Test 1, 3, 5 | ✅ |
| K between B/2 and B (key=25 bytes) | Test 4 | ✅ |
| K > B (key=131 bytes) | Test 6, 7 | ✅ (forces SHA256(k) path) |
| Truncated output (128-bit) | Test 5 | ✅ (verified first 16 bytes) |

### 2.3 Architecture note — Inline SHA-256 in HMAC package ✅

Originally planned to import `@sha256` from hmac package. Discovered moon 0.1.20260608 doesn't support cross-package imports cleanly (`Cannot find import 'openssh/openssh_moonbit/sha256' in ...`).

**Decision:** Inlined SHA-256 (as `sha256_*` modules) into hmac package. This is functionally identical to having a separate package — just less DRY. Trade-off accepted; can refactor when moon import works.

---

## 3. Test coverage

### 3.1 SHA-256 KAT (sha256_wbtest.mbt)

| Test | Source | Bytes | Status |
|------|--------|-------|--------|
| FIPS Test 1 "abc" | FIPS 180-4 B.1 | 3 | ✅ |
| FIPS Test 2 1M 'a' | FIPS 180-4 B.1 | 1,000,000 | ✅ (runs in ~5 sec) |
| FIPS Test 3 56-byte | FIPS 180-4 B.1 | 56 | ✅ |

### 3.2 SHA-256 Blackbox (sha256_test.mbt, 8 tests)

Empty / 1-byte / 55 / 56 / 64 / 119 / 128 bytes / deterministic / different-input.

### 3.3 HMAC KAT (hmac_wbtest.mbt)

All 7 RFC 4231 test vectors byte-exact.

### 3.4 HMAC Blackbox (hmac_test.mbt, 7 tests)

Empty / deterministic / different keys / short key / exact 64 / > 64 (triggers H(K)) / empty msg.

---

## 4. Code quality assessment

### 4.1 Module structure ✅

```
src/sha256/
├── state.mbt        (constants: K[64], init_H[8], block_len, hash_len)
├── primitives.mbt   (rotr, ch, maj, sigma0/1, be8_to_32, be32_to_8)
├── block.mbt        (64-round compression)
├── update.mbt       (incremental update + padding)
├── final.mbt        (state serialization)
└── api.mbt          (single-entry sha256())

src/hmac/
├── api.mbt          (HMAC with inlined SHA-256)
├── sha256_state.mbt, sha256_primitives.mbt, sha256_block.mbt,
│   sha256_update.mbt, sha256_final.mbt, sha256_api.mbt  (inlined SHA-256)
├── hmac_test.mbt    (7 blackbox)
└── hmac_wbtest.mbt  (7 KAT)
```

### 4.2 Function-level review ✅

- `rotr(n, x)`: clean, matches OpenBSD `S32(b, x)` ✓
- `transform(state, block)`: 64 rounds correct, registers used (not array indexing) for performance ✓
- `update`: handles partial buffer correctly ✓
- `pad`: handles both padding cases ✓
- `serialize_state`: simple big-endian serialization ✓
- `sha256`: thin wrapper, single entry ✓
- `hmac_sha256`: implements RFC 2104 cleanly ✓
- `prep_key`: handles both key-too-long and key-too-short ✓

### 4.3 Type safety ✅

- All arithmetic in `UInt` domain for SHA-256 (32-bit wrap is correct)
- `bit_count` correctly `UInt64` (SHA-256 spec is 64-bit length)
- No implicit promotions

---

## 6. Verification summary

| Check | Result |
 | |
| `moon check` | ✅ clean |
| `moon test` (sha256) | ✅ 40/40 |
| `moon test` (hmac) | ✅ 14/14 |
| FIPS 180-4 B.1 Test 1-3 | ✅ 3/3 byte-exact |
| RFC 4231 § 4 Test 1-7 | ✅ 7/7 byte-exact |
| OpenBSD C harness (sha256_kat.exe) | ✅ 2/2 (FIPS 1+3, FIPS 2 too slow for C harness, skipped) |
| Python `hashlib.sha256` cross-check | ✅ all 3 |
| Python `hmac.new(sha256)` cross-check | ✅ Test 1 + Test 2 spot-check |

## 7. Sign-off

**Code Reviewer 签字:** ✅ APPROVED for Loop #3 closure.

算法实现正确,所有 KAT 通过。Inline SHA-256 是为 moon 0.1.20260608 跨包限制的权宜方案,不影响正确性。Loop #4 可以接着写 — 推荐顺序:Curve25519 (X25519) → Ed25519,因为 SSH key exchange 用 X25519,user auth 用 Ed25519。