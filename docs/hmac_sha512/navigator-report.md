# Loop #6 HMAC-SHA512 — Navigator Report

**Date:** 2026-07-28
**Role:** 🧭 Codebase Navigator
**Scope:** Find HMAC-SHA512 reference in OpenSSH C, identify KAT sources (RFC 4231), plan extraction of MoonBit implementation

---

## 1. OpenSSH C Reference Inventory

### 1.1 HMAC-SHA512 Algorithm

OpenSSH does **not** have a standalone `hmac_sha512.c`. HMAC is implemented as a generic wrapper (`hmac.c`) over the digest infrastructure (`digest.c` + `openbsd-compat/sha2.c`).

**Key APIs in `hmac.c`:**

| Function | Purpose |
|----------|---------|
| `ssh_hmac_start(alg)` | Allocates `ssh_hmac_ctx`, sets alg, creates 3 digest ctx (i, o, digest), allocates buf = blocksize |
| `ssh_hmac_init(ctx, key, klen)` | Truncates/hashes key to blocksize, XORs with 0x36, feeds ictx, then XORs 0x36^0x5c, feeds octx |
| `ssh_hmac_update(ctx, m, mlen)` | Updates the **inner** digest ctx |
| `ssh_hmac_final(ctx, d, dlen)` | Finalizes inner (digest → buf), then octx + buf → d |
| `ssh_hmac_free(ctx)` | Frees all 3 ctx + buf |

The state structure carries **two** pre-initialized digest contexts (one with ipad-key, one with opad-key) and a third "live" digest for the actual message.

### 1.2 SHA-512 in `openbsd-compat/sha2.c`

Already used in Loop #5. Provides:
- `SHA512Init(SHA2_CTX *)`
- `SHA512Update(SHA2_CTX *, const void *, size_t)`
- `SHA512Final(u_int8_t [SHA512_DIGEST_LENGTH], SHA2_CTX *)`
- `SHA512Transform(u_int64_t state[8], const u_int8_t block[128])` (internal)

Block size: 128 bytes. Hash size: 64 bytes.

### 1.3 HMAC-SHA512 in OpenSSH protocol

Used in:
- **KEX**: `hmac-sha2-512` for `diffie-hellman-group-exchange-sha256` / `curve25519-sha256` (RFC 8731)
- **Packet MAC**: `hmac-sha2-512` (rare, more common: `hmac-sha2-256`)
- **Hostkey signing**: `ssh-rsa` and `ssh-ed25519` don't use HMAC-SHA512 directly, but `rsa-sha2-512` does internally

---

## 2. KAT Resources (RFC 4231)

**RFC 4231 § 4** defines 7 test cases for HMAC-SHA-1/256/384/512. The § 4.5 "truncation" test is **only** for SHA-1/256; SHA-512 has no truncation test.

| # | Key | Data | Notes |
|---|-----|------|-------|
| 1 | `0x0b * 20` | `"Hi There"` | Standard short key test |
| 2 | `"Jefe"` | `"what do ya want for nothing?"` | RFC 2104 Test Case 2 |
| 3 | `0xAA * 20` | `0xDD * 50` | Repeated byte pattern |
| 4 | `0x01..0x19` (25 bytes) | `0xCD * 50` | Sequential byte key |
| 5 | `0x0c * 20` | `"Test With Truncation"` | **NO expected for SHA-512** (truncation only for SHA-1/256) |
| 6 | `0xAA * 131` | `"Test Using Larger Than Block-Size Key - Hash Key First"` | key > block_size (128), triggers H(key) path |
| 7 | `0xAA * 131` | `"This is a test using a larger than block-size key..."` (152 bytes) | msg > block_size too |

**Available hex expected for tests 1, 2, 3, 4, 6, 7** (RFC 4231 § 4.2-4.5, 4.7, 4.8). Test 5 only verifies output length = 64 bytes.

### 2.1 Python `hmac` reference

```python
import hmac, hashlib
hmac.new(bytes([0x0b]*20), b"Hi There", hashlib.sha512).hexdigest()
# -> 87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde
#    daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854
```

This is the **golden reference** for all 6 KAT vectors.

---

## 3. Implementation Strategy (reuse Loop #3 + Loop #5)

### 3.1 Algorithm structure

`HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))`

Where:
- `B = 128` (SHA-512 block_size)
- `L = 64` (SHA-512 hash_size)
- `K' = K` if `len(K) ≤ B`, else `K' = H(K)[:B]` (truncate to B = 128)
- `K' = K' || 0x00...0` to length B
- `ipad = 0x36 * B`, `opad = 0x5c * B`

### 3.2 Files to create

```
src/hmac_sha512/
├── moon.pkg
├── api.mbt           (block_size, output_size, hmac_sha512 entry, prep_key, inner_hash, outer_hash)
├── sha512_state.mbt  (k512, init_h, inlined from src/sha512/)
├── sha512_primitives.mbt  (rotr, ch, maj, big_sigma0/1, small_sigma0/1, be8_to_64, be64_to_8)
├── sha512_block.mbt  (80-round compression)
├── sha512_update.mbt (incremental + 128-bit Merkle-Damgård padding)
├── sha512_final.mbt  (serialize 8 × UInt64 → 64 bytes BE)
├── sha512_api.mbt    (public sha512(msg) entry — used internally)
├── hmac_sha512_test.mbt    (8 blackbox tests)
├── hmac_sha512_wbtest.mbt  (6 RFC 4231 KAT)
└── hmac_sha512_trace.mbt   (3 roundtrip + API tests)
```

### 3.3 Critical cross-package import issue (carried from Loop #3)

`moon 0.1.20260608` does **not** support cross-package imports:
```
Error: [4042] Cannot find import 'openssh/openssh_moonbit/sha512'
```

**Workaround (same as Loop #3):** Inline SHA-512 implementation directly into `hmac_sha512` package. This violates DRY but works around the compiler bug. The Loop #7+ clean-up may refactor this if/when cross-package imports work.

### 3.4 Reuse from Loop #3 + #5

| Component | Source | Notes |
|-----------|--------|-------|
| `prep_key` | Loop #3 (`src/hmac/`) | Truncate/hash key to block_size |
| `inner_hash` / `outer_hash` | Loop #3 | SHA(block || msg) composition |
| `sha512_*.mbt` | Loop #5 (`src/sha512/`) | Inlined (copy) |
| `block_size=128` / `output_size=64` | RFC 6234 | Same as Loop #5 |
| RFC 4231 KAT expected | Python `hmac` | Generated each loop (NOT hand-transcribed from RFC text — Loop #5 lesson) |

---

## 4. Verification matrix

| Verification | Tool | Expected |
|--------------|------|----------|
| MoonBit algorithm correct | `moon test` (wbtest) | 6/6 RFC 4231 KAT |
| MoonBit blackbox | `moon test` (test) | 8/8 |
| MoonBit hex roundtrip | `moon test` (trace) | 3/3 |
| MoonBit vs OpenBSD C | `verify_c/hmac_sha512_kat.exe` | 6/6 |
| MoonBit vs Python | Python `hmac` script | 6/6 |
| Compile clean | `moon check` | 0 warnings |

**Triple-blind verification**: MoonBit ⊕ OpenBSD C ⊕ Python agree on 6 KAT vectors.

---

## 5. Risk Assessment

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Hand-transcribed KAT expected wrong (Loop #5 lesson) | High | Always use Python `hmac` for expected hex |
| MoonBit `^=` operator quirk | Low | Use `x = x ^ y` form |
| `String::make(1, byte)` type error (Char vs Byte) | Medium | Use `StringBuilder` + `write_string` for hex |
| `unsafe_substring(0, 20)` crash on empty buffer | Medium | Don't use substring on debug dumps of empty keys |
| Cross-package import workaround is fragile | Low | Same workaround as Loop #3 — verified |

---

**签字:** 🧭 Navigator — 2026-07-28
