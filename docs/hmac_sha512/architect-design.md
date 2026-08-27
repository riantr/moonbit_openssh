# Loop #6 HMAC-SHA512 — Architect Design

**Date:** 2026-07-28
**Role:** 🏗️ Architect
**Scope:** Design the inlined HMAC-SHA512 module mirroring Loop #3 HMAC-SHA256 with SHA-512

---

## 1. Architecture Overview

HMAC-SHA512 is structurally identical to HMAC-SHA256 with three changes:

| Component | HMAC-SHA256 | HMAC-SHA512 |
|-----------|-------------|-------------|
| Inner hash | SHA-256 | SHA-512 |
| Block size `B` | 64 | 128 |
| Output size `L` | 32 | 64 |
| ipad/opad const | 0x36/0x5c | 0x36/0x5c (same) |
| Key-truncate | `H(K)[:32]` | `H(K)[:64]` |

Since the SHA-512 primitives and round function are already in `src/sha512/`, we **inline** them into `src/hmac_sha512/` to bypass the `moon 0.1.20260608` cross-package import limitation.

---

## 2. Module Decomposition

### 2.1 `api.mbt` — Public HMAC entry point

```moonbit
pub let block_size : Int = 128
pub let output_size : Int = 64

pub fn hmac_sha512(key : FixedArray[Byte], message : FixedArray[Byte]) -> FixedArray[Byte] {
  // 1. K' = prep_key(key)  -- 128 bytes
  // 2. ipad_key = K' ^ 0x36 * 128
  // 3. opad_key = K' ^ 0x5c * 128
  // 4. inner = sha512(ipad_key || msg)
  // 5. tag   = sha512(opad_key || inner)
}

fn prep_key(key : FixedArray[Byte]) -> FixedArray[Byte] {
  // if len(key) > 128: hashed = sha512(key); k_pad[0..64] = hashed; k_pad[64..128] = 0
  // else:              k_pad[0..len(key)] = key;   k_pad[len(key)..128] = 0
}

fn inner_hash(ipad_key : FixedArray[Byte], message : FixedArray[Byte]) -> FixedArray[Byte] {
  // combined = ipad_key || message
  // sha512(combined)
}

fn outer_hash(opad_key : FixedArray[Byte], inner : FixedArray[Byte]) -> FixedArray[Byte] {
  // combined = opad_key || inner
  // sha512(combined)
}
```

**Return type:** `FixedArray[Byte]` of length 64.

### 2.2 `sha512_*.mbt` — Inlined SHA-512 (copy of `src/sha512/`)

Five files copied verbatim from Loop #5's `src/sha512/`:

- `sha512_state.mbt` — `k512 : FixedArray[UInt64]`, `init_h : FixedArray[UInt64]`, `block_len=128`, `hash_len=64`
- `sha512_primitives.mbt` — `rotr64`, `ch`, `maj`, `big_sigma0/1`, `small_sigma0/1`, `be8_to_64`, `be64_to_8`
- `sha512_block.mbt` — 80-round compression (UInt64 domain)
- `sha512_update.mbt` — incremental API + 128-bit Merkle-Damgård padding
- `sha512_final.mbt` — serialize 8 × UInt64 → 64 bytes BE
- `sha512_api.mbt` — `pub fn sha512(message : FixedArray[Byte]) -> FixedArray[Byte]`

**Total:** ~430 lines MoonBit (same as `src/sha512/`)

### 2.3 Test modules

- `hmac_sha512_test.mbt` — 8 blackbox tests (mirrors `src/hmac/hmac_test.mbt` structure)
- `hmac_sha512_wbtest.mbt` — 6 RFC 4231 KAT (1, 2, 3, 4, 6, 7) + Test 5 length-only check
- `hmac_sha512_trace.mbt` — 3 hex-roundtrip + 2 blackbox smoke tests

---

## 3. Data Flow

```
key, message (FixedArray[Byte])
  │
  ▼
prep_key (returns 128-byte K')
  │
  ├─ if len(key) > 128:  k_pad[0..64] = sha512(key);  k_pad[64..128] = 0
  └─ else:               k_pad[0..len(key)] = key;   k_pad[len(key)..128] = 0
  │
  ▼
ipad_key[128] = 0x36*128 ^ k_pad[128]
opad_key[128] = 0x5c*128 ^ k_pad[128]
  │
  ├─ inner[64] = sha512(ipad_key || message)  (length = 128 + len(message))
  │
  └─ tag[64]   = sha512(opad_key || inner)    (length = 128 + 64 = 192)
  │
  ▼
return tag[64]
```

---

## 4. Edge Cases

| Case | Behavior |
|------|----------|
| Empty key | `prep_key` returns 128 zero bytes; `inner = sha512(0x36*128 || msg)` |
| Empty msg | `inner = sha512(ipad_key)` (just the 128-byte ipad_key) |
| `len(key) == 128` | Direct copy to `k_pad` (no hash) |
| `len(key) > 128` | `k_pad[0..64] = sha512(key)[:64]`, `k_pad[64..128] = 0` (RFC 2104 § 2) |
| `len(msg) > 128` | `sha512` handles 128-byte blocks + 128-bit length internally |

---

## 5. KAT Test Vectors (RFC 4231, Python-generated)

| Test | Key | Msg | Expected (first 16 bytes) |
|------|-----|-----|---------------------------|
| 1 | `0x0b * 20` | `"Hi There"` | `87aa7cdea5ef619d 4ff0b4241a1d6cb0` |
| 2 | `"Jefe"` | `"what do ya want for nothing?"` | `164b7a7bfcf819e2 e395fbe73b56e0a3` |
| 3 | `0xAA * 20` | `0xDD * 50` | `fa73b0089d56a284 efb0f0756c890be9` |
| 4 | `0x01..0x19` | `0xCD * 50` | `b0ba465637458c69 90e5a8c5f61d4af7` |
| 5 | `0x0c * 20` | `"Test With Truncation"` | (length-only) |
| 6 | `0xAA * 131` | `"Test Using Larger Than Block-Size Key - Hash Key First"` | `80b24263c7c1a3eb b71493c1dd7be8b4` |
| 7 | `0xAA * 131` | `"This is a test using a larger than block-size key..."` | `e37b6a775dc87dba a4dfa9f96e5e3ffd` |

**Source:** `hmac.new(key, msg, hashlib.sha512).hexdigest()` in Python 3.12.

---

## 6. C Verification Harness

`verify_c/hmac_sha512_harness.c` implements HMAC-SHA512 directly using `sha2.c` (OpenBSD original, BSD-licensed):

```c
static void hmac_sha512(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t out[HMAC_DIGEST_SIZE]) {
  uint8_t k_pad[HMAC_BLOCK_SIZE];
  uint8_t ipad_key[HMAC_BLOCK_SIZE];
  uint8_t opad_key[HMAC_BLOCK_SIZE];
  uint8_t inner[HMAC_DIGEST_SIZE];
  SHA2_CTX ctx;

  // 1. K' = prep_key(key)
  memset(k_pad, 0, HMAC_BLOCK_SIZE);
  if (klen > HMAC_BLOCK_SIZE) {
    SHA512Init(&ctx); SHA512Update(&ctx, key, klen); SHA512Final(k_pad, &ctx);
  } else {
    memcpy(k_pad, key, klen);
  }
  // 2. ipad/opad
  for (size_t i = 0; i < HMAC_BLOCK_SIZE; i++) {
    ipad_key[i] = k_pad[i] ^ 0x36;
    opad_key[i] = k_pad[i] ^ 0x5c;
  }
  // 3. inner
  SHA512Init(&ctx);
  SHA512Update(&ctx, ipad_key, HMAC_BLOCK_SIZE);
  SHA512Update(&ctx, msg, mlen);
  SHA512Final(inner, &ctx);
  // 4. tag
  SHA512Init(&ctx);
  SHA512Update(&ctx, opad_key, HMAC_BLOCK_SIZE);
  SHA512Update(&ctx, inner, HMAC_DIGEST_SIZE);
  SHA512Final(out, &ctx);
}
```

**Build:** `gcc -o hmac_sha512_kat.exe hmac_sha512_harness.c` (uses OpenBSD `sha2.c` via `#include`)

**Coverage:** Tests 1, 2, 3, 4, 6, 7 (Test 5 skipped — no expected for SHA-512 in RFC).

---

## 7. Test Plan

```powershell
# MoonBit tests
cd E:\src\moon\openssh_moonbit
moon test

# C harness
cd verify_c
.\build_hmac_sha512.bat
```

**Expected results:**
- MoonBit: 100/100 (8 blackbox + 6 wbtest + 3 trace + others from other modules)
- C harness: 6/6 PASS

---

## 8. Open Issues / Future Work

1. **DRY violation** — SHA-512 is inlined in `src/sha512/` AND `src/hmac_sha512/`. When `moon` adds cross-package imports, refactor to a single shared `src/sha512/`.
2. **Test 5 SHA-512 truncation** — RFC 4231 § 4.6 explicitly says no truncation test for SHA-512. Only verify output length = 64 bytes.
3. **Loop #7 candidate** — **Ed25519** (depends on X25519 + SHA-512). Will inline SHA-512 again (same workaround). When/if cross-package imports work, refactor all 3 inlinings into one.

---

**签字:** 🏗️ Architect — 2026-07-28
