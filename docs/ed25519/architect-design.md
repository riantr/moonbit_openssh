# Loop #7 Ed25519 — Architect Design

**Date:** 2026-07-28
**Role:** 🏗️ Architect
**Scope:** Design the Ed25519 module from scratch mirroring TweetNaCl ref10

---

## 1. Architecture Overview

Ed25519 is a digital signature scheme based on **Curve25519** (twisted Edwards form, -x²+y²=1+dx²y² with d=-121665/121666 mod p). It is structurally a stack of three independent layers:

```
┌─────────────────────────────────────────────────────────┐
│ Public API: keypair, sign, verify                       │  api.mbt
└─────────────────────────────────────────────────────────┘
  │
  ├─► Group operations (ge25519)         ─► twisted Edwards points
  │     │
  │     ├─► Scalar arithmetic (sc25519)  ─► mod L
  │     │     └─► SHA-512 (inlined)      ─► keygen prefix, sign nonce
  │     │
  │     └─► Field arithmetic (fe25519)   ─► mod p
  │
  └─► SHA-512 (inlined)                  ─► keygen h, sign prefix, verify h
```

---

## 2. Module Decomposition

### 2.1 `fe.mbt` — Field arithmetic mod p

```moonbit
// Field element: 10 × 26-bit limbs
// Reduction: lazy carry propagation, full reduce via "freeze"
fn fe25519_unpack(r : Fe, x : FixedArray[Byte])   // 32 LE bytes → 10 limbs
fn fe25519_pack(r : FixedArray[Byte], x : Fe)     // 10 limbs → 32 LE bytes
fn fe25519_setzero(r : Fe)
fn fe25519_setone(r : Fe)
fn fe25519_neg(r : Fe, x : Fe)
fn fe25519_add(r : Fe, x : Fe, y : Fe)
fn fe25519_sub(r : Fe, x : Fe, y : Fe)
fn fe25519_mul(r : Fe, x : Fe, y : Fe)            // 20 × 26-bit → 10 × 26-bit
fn fe25519_square(r : Fe, x : Fe)                  // reuse mul(r, x, x)
fn fe25519_invert(r : Fe, x : Fe)                  // Fermat: x^(p-2)
fn fe25519_pow2523(r : Fe, x : Fe)                 // x^((p-5)/8)
fn fe25519_freeze(r : Fe)                          // full reduce mod p
fn fe25519_iszero(x : Fe) -> Bool
fn fe25519_iseq_vartime(x : Fe, y : Fe) -> Bool
fn fe25519_cmov(r : Fe, x : Fe, b : Byte)          // constant-time select
```

**Internal storage:** 10 × UInt32, but each limb holds ≤ 26 bits of "value". After mul, limbs can be 51 bits — full reduce uses `fe25519_reduce_add_sub` + `reduce_mul`.

### 2.2 `sc.mbt` — Scalar arithmetic mod L

```moonbit
// Scalar: 8 × 32-bit limbs, but each holds signed 32-bit (window-3 table)
fn sc25519_from32bytes(r : Sc, x : FixedArray[Byte])  // 32 LE bytes → 8 limbs
fn sc25519_from64bytes(r : Sc, x : FixedArray[Byte])  // 32 LE bytes (top of 64) → 8 limbs
fn sc25519_to32bytes(r : FixedArray[Byte], x : Sc)    // 8 limbs → 32 LE bytes
fn sc25519_add(r : Sc, x : Sc, y : Sc)
fn sc25519_mul(r : Sc, x : Sc, y : Sc)                // 16 × 32-bit → 8 × 32-bit, Barrett reduce
fn sc25519_window3(r : FixedArray[Int], s : Sc)       // signed bytes for comb
fn sc25519_2interleave2(r : FixedArray[Byte], s1 : Sc, s2 : Sc)  // for dbl scalarmult
```

**Internal storage:** 8 × Int (signed, since values can be in [-L/2, L/2] during window-3). After mul, limbs can be 64 bits — Barrett reduction brings back to 8 × 32-bit.

**Group order L** (8 × 32-bit LE):
```
L = 0xEDD3F55C1A631258D69CF7A2DE9F130D5DB00280485A829B121A62D9F4D6D815
  (256 bits, prime)
```

### 2.3 `ge.mbt` — Group operations

```moonbit
// Twisted Edwards point: 4 forms depending on operation
struct Ge_p3 { x : Fe, y : Fe, z : Fe, t : Fe }            // (X:Y:Z:T) with T = XY/Z
struct Ge_p2 { x : Fe, y : Fe, z : Fe }                    // (X:Y:Z)
struct Ge_p1p1 { x : Fe, y : Fe, z : Fe, t : Fe }          // (X:Y:Z:T) after add/dbl
struct Ge_aff { x : Fe, y : Fe }                            // (X:Y), for precomputed

fn ge25519_setneutral(r : Ge_p3)
fn ge25519_unpackneg_vartime(r : Ge_p3, p : FixedArray[Byte])  // 32 → p3 (negate)
fn ge25519_pack(r : FixedArray[Byte], p : Ge_p3)            // 32 ← p3
fn ge25519_isneutral_vartime(p : Ge_p3) -> Bool
fn ge25519_scalarmult_base(r : Ge_p3, s : Sc)              // sB
fn ge25519_double_scalarmult_vartime(r : Ge_p3,
                                       p1 : Ge_p3, s1 : Sc,
                                       p2 : Ge_p3, s2 : Sc)  // s1*p1 + s2*p2
```

**Precomputed base multiples:** 425 affine points (4 tables × 85 windows × 8 multiples, 5-bit windows in comb). Inlined as a 425-element array of `Ge_aff`.

**Curve parameters** (inlined as `Fe` constants):
- `ecd` = -121665/121666 mod p
- `ec2d` = 2d (used in doublings)
- `sqrtm1` = sqrt(-1) mod p
- `d` (computed at init: `ec2d * inv(2) * inv(ecd + 1)`)

### 2.4 `api.mbt` — Public API

```moonbit
// RFC 8032 § 5.1.2
pub fn keypair_from_seed(seed : FixedArray[Byte]) -> (FixedArray[Byte], FixedArray[Byte]) {
  // h = SHA-512(seed)
  // a = clamp(h[0..32])
  // A = a * B
  // pk = pack(A)
  // sk = seed || pk   // 64 bytes (OpenSSH format)
  // returns (pk, sk)
}

// RFC 8032 § 5.1.6
pub fn sign(msg : FixedArray[Byte], sk : FixedArray[Byte]) -> FixedArray[Byte] {
  // sk is 64 bytes: seed[32] || pk[32]
  // h = SHA-512(seed)
  // a = clamp(h[0..32])
  // prefix = h[32..64]      // 32 bytes
  // r = SHA-512(prefix || M) mod L
  // R = r * B
  // h2 = SHA-512(R || A || M) mod L
  // s = (r + h2 * a) mod L
  // sig = pack(R) || to32(s)    // 64 bytes
  // returns sig
}

// RFC 8032 § 5.1.7
pub fn verify(sig : FixedArray[Byte], msg : FixedArray[Byte], pk : FixedArray[Byte]) -> Bool {
  // sig is 64 bytes: R[32] || s[32]
  // if s >= L: return false
  // A = unpack(pk)
  // h = SHA-512(R || A || M) mod L
  // check: sB == R + hA
  // returns true if equal
}
```

### 2.5 SHA-512 inlined (3rd copy, 5 files)

| File | Lines | Inlined from |
|------|-------|--------------|
| `sha512_state.mbt` | 100 | `src/sha512/` |
| `sha512_primitives.mbt` | 80 | `src/sha512/` |
| `sha512_block.mbt` | 60 | `src/sha512/` |
| `sha512_update.mbt` | 130 | `src/sha512/` |
| `sha512_final.mbt` | 20 | `src/sha512/` |
| `sha512_api.mbt` | 20 | `src/sha512/` |

**DRY violation:** This is the **3rd inline** of SHA-512. After Loop #7 lands, refactor all 3 inlinings into one `src/sha512/` if/when moon cross-package imports work.

---

## 3. Data Flow

### 3.1 Signing flow

```
seed (32 bytes)
  │
  ▼
SHA-512 → h (64 bytes)
  │
  ├─► clamp(h[0..32]) → a (32 bytes, mod L)
  │     │
  │     ▼
  │   sc25519_from32bytes(a) → Sc
  │     │
  │     ▼
  │   ge25519_scalarmult_base(A, a) → Ge_p3
  │     │
  │     ▼
  │   ge25519_pack(pk, A) (32 bytes)
  │
  └─► h[32..64] → prefix (32 bytes)
        │
        ▼
      SHA-512(prefix || msg) → nonce_h (64 bytes)
        │
        ▼
      sc25519_from64bytes(nonce_h) → r (Sc)
        │
        ▼
      ge25519_scalarmult_base(R, r) → Ge_p3
        │
        ▼
      ge25519_pack(R_bytes, R) (32 bytes)
        │
        ▼
      SHA-512(R_bytes || pk || msg) → h2 (64 bytes)
        │
        ▼
      sc25519_from64bytes(h2) → h2_sc
        │
        ▼
      sc25519_mul(ha, h2_sc, a)  // ha = h2*a
      sc25519_add(s, r, ha)      // s = r + h2*a  (mod L)
        │
        ▼
      sc25519_to32bytes(s_bytes, s)
        │
        ▼
      sig = R_bytes || s_bytes  (64 bytes)
```

### 3.2 Verification flow

```
sig (64 bytes) → R_bytes[32] || s_bytes[32]
  │
  ├─► sc25519_from32bytes(s) → s_sc
  │     if s_sc >= L: reject
  │
  ├─► ge25519_unpackneg_vartime(R_neg, R_bytes) → Ge_p3  // R_neg = -R
  │     if invalid encoding: reject
  │
  ├─► ge25519_unpackneg_vartime(A_neg, pk) → Ge_p3
  │     if invalid: reject
  │
  ├─► SHA-512(R_bytes || pk || msg) → h2
  │     sc25519_from64bytes(h2) → h2_sc
  │
  ├─► ge25519_double_scalarmult_vartime(P, R_neg, s_sc, A_neg, h2_sc)
  │     // P = s*(-R) + h2*(-A) = -(sB - h2A)  if check passes
  │
  └─► check ge25519_isneutral_vartime(P)  // == identity?
        │
        ▼
      return (P is identity)
```

---

## 4. Edge Cases & Constant-Time

| Case | Handling |
|------|----------|
| Empty msg | `sign("", sk)` works (prefix only, no msg) |
| All-zero seed | works (clamp + scalar mult) |
| sig with s ≥ L | reject (small-subgroup) |
| pk with high bit set | still works (sign bit encoded) |
| pk = identity | reject (no public key should be identity) |
| `fe25519_invert(0)` | never called (we invert non-zero elements only) |
| Constant-time | TweetNaCl uses vartime for unpack/pack; **NOT** CT in unpack. Ed25519 verify is allowed to be vartime per RFC. |

---

## 5. KAT Test Vectors (RFC 8032 § 7.1)

We will use the 3 vectors from OpenSSH `test_ed25519.c` (which are RFC 8032 Tests 1, 2, 3) plus Tests 4 (1023-byte) and Test 5 (prehashed "abc") from RFC 8032 text. Python `cryptography` is the golden reference for verification.

| # | seed (32 bytes) | pk (32 bytes) | msg | sig (64 bytes) |
|---|-----------------|---------------|-----|----------------|
| 1 | `9d61b19d...f60` | `d75a9801...511a` | `""` | `e5564300...100b` |
| 2 | `4ccd089b...a6fb` | `3d4017c3...660c` | `"72"` (1 byte) | `92a009a9...0c00` |
| 3 | `c5aa8df4...58f7` | `fc51cd8e...8025` | `"af82"` (2 bytes) | `6291d657...c40a` |

Tests 4 and 5 from RFC 8032 will be added by Python regeneration (don't hand-transcribe — Loop #5/6 lesson).

---

## 6. C Verification Harness

`verify_c/ed25519_harness.c` will:
1. Reuse OpenSSH's `ed25519.c` (vendored TweetNaCl) via `#include "ed25519.c"`
2. Stub the OpenSSH-specific includes (`#include "includes.h"` → minimal types)
3. Run 3 KAT sign+verify cycles
4. Output `got` vs `expected` for `pk` and `sig`

**Build:** `gcc -o ed25519_kat.exe ed25519_harness.c` — should compile in <1s.

**Coverage:** 3 sign+verify KAT, ~3 blackbox (determinism, keypair-from-seed, verify rejects bad sig).

---

## 7. Test Plan

```powershell
# MoonBit tests
cd E:\src\moon\openssh_moonbit
moon test

# C harness
cd verify_c
.\build_ed25519.bat
```

**Expected results:**
- MoonBit: 3 KAT sign+verify + 8 blackbox = 11 tests minimum
- C harness: 3/3 PASS

---

## 8. Open Issues

1. **3rd SHA-512 inline** — DRY violation, will refactor after Loop #7
2. **Vartime scalar mult in verify** — RFC permits (verify is allowed to leak), but document it
3. **Test 4 (1023-byte msg)** — need to generate expected sig from Python (no hand-transcription)
4. **Test 5 (prehashed "abc")** — same, need Python generation

---

**签字:** 🏗️ Architect — 2026-07-28
