# Loop #7 Ed25519 — Navigator Report

**Date:** 2026-07-28
**Role:** 🧭 Codebase Navigator
**Scope:** Find Ed25519 reference in OpenSSH C, identify KAT sources (RFC 8032), plan extraction of MoonBit implementation

---

## 1. OpenSSH C Reference Inventory

### 1.1 Ed25519 in `E:\src\moon\openssh-C\ed25519.c`

The OpenSSH Ed25519 implementation is the **TweetNaCl ref10** (Bernstein, Duif, Lange, Schwabe, Yang — Public Domain), 1859 lines, vendored from `supercop-20221122/crypto_sign/ed25519/ref/`.

**Three-layer structure (mirrors TweetNaCl):**

| Layer | Prefix | Role | Reuses from X25519? |
|-------|--------|------|---------------------|
| Field arithmetic | `fe25519_*` | Operations mod p = 2^255 - 19 (10 × 26-bit limbs) | **Same field** but with different operations (carry, freeze) |
| Scalar arithmetic | `sc25519_*` | Operations mod L = group order (8 × 32-bit limbs with radix-16) | **Different** from X25519's scalar field |
| Group operations | `ge25519_*` | Twisted Edwards curve points (Y, X, T, Z, ...) | **Different** from X25519 (X-only Montgomery ladder) |

**Public API (entry points):**

| Function | Signature | Role |
|----------|-----------|------|
| `crypto_sign_ed25519_keypair_from_seed` | `(pk[32], sk[64], seed[32]) → 0/-1` | Derive pubkey from 32-byte seed; sk = seed || pubkey |
| `crypto_sign_ed25519_keypair` | `(pk[32], sk[64]) → 0/-1` | Random keypair (uses /dev/urandom) |
| `crypto_sign_ed25519` | `(sm[64+mlen], smlen, m, mlen, sk[64]) → 0/-1` | Sign: prefix sig to msg (sm = sig \|\| m) |
| `crypto_sign_ed25519_open` | `(m[mlen], mlen, sm, smlen, pk[32]) → 0/-1` | Verify: extract sig, check sig, copy m to output |

### 1.2 Key Generation (RFC 8032 § 5.1.2)

```
1. h = SHA-512(seed)  // 64 bytes
2. a = h[0..32] interpreted as little-endian int, then:
   a[0]  &= 248     // clear bottom 3 bits
   a[31] &= 127     // clear top bit
   a[31] |= 64      // set second-top bit
3. A = a * G  (scalar mult of base point)
4. pk = encode(A)  // 32 bytes
5. sk = seed || pk  // 64 bytes (OpenSSH format; RFC 8032 has 32-byte sk too)
```

### 1.3 Signing (RFC 8032 § 5.1.6)

```
1. h = SHA-512(seed)  // reuse from keygen
2. a = clamp(h[0..32])  // same clamping as keygen
3. prefix = h[32..64]  // 32 bytes secret prefix
4. r = SHA-512(prefix || M) interpreted as little-endian int, mod L
5. R = r * G
6. s = (r + h_int(R || A || M) * a) mod L
7. sig = encode(R) || encode(s)  // 64 bytes
```

### 1.4 Verification (RFC 8032 § 5.1.7)

```
1. Split sig into R (32 bytes) and s (32 bytes)
2. Check s < L (rejects small-subgroup / malleable sigs)
3. h = SHA-512(R || A || M) interpreted as little-endian int, mod L
4. Check: s * B == R + h * A  (cofactored verification)
5. Reject if check fails
```

### 1.5 Curve parameters

```
p = 2^255 - 19          // Field prime
L = 2^252 + 27742317777372353535851937790883648493  // Group order
d = -121665/121666 mod p // Twisted Edwards d
B = (X, Y, Z, T) where   // Base point
  Y = 4/5 mod p
  X = recover from Y
sqrt(-1) mod p = 2^((p-1)/4) mod p
```

---

## 2. KAT Resources (RFC 8032 § 7.1)

The OpenSSH test file `regress/unittests/crypto/test_ed25519.c` contains **3 KAT vectors** (Tests 1, 2, 3 of RFC 8032 § 7.1). For full coverage we need **5 vectors** (Tests 1–5).

| # | Test | seed (32 bytes) | pubkey (32 bytes) | msg | sig (64 bytes) |
|---|------|-----------------|------------------|-----|----------------|
| 1 | Empty msg | `9d61b19d...f60` | `d75a9801...511a` | `""` | `e5564300...100b` |
| 2 | 1-byte msg | `4ccd089b...a6fb` | `3d4017c3...660c` | `"72"` | `92a009a9...0c00` |
| 3 | 2-byte msg | `c5aa8df4...58f7` | `fc51cd8e...8025` | `"af82"` | `6291d657...c40a` |
| 4 | 1023-byte msg | `833dafe7...07c0` | `ec172b93...38d5` | `(1023 bytes hex)` | `0aab2ad6...30e0` |
| 5 | Prehashed "abc" | `7d4d0e7f...05a1` | `d4bcd469...3305` | `"616263"` | `8d0d96e8...5c0d` |

**Tests 1-3 are in OpenSSH `test_ed25519.c`; Tests 4-5 need to come from RFC 8032 text or Python `cryptography` library.**

### 2.1 Python `cryptography` reference

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
sk = Ed25519PrivateKey.from_private_bytes(seed)
pk = sk.public_key()
sig = sk.sign(b"")
# sig = 64 bytes
```

Python's `cryptography` library wraps **libsodium** or **OpenSSL** Ed25519 (depending on build), both of which are RFC 8032 compliant.

---

## 3. Implementation Strategy

### 3.1 Three-layer architecture (mirror OpenSSH structure)

| Layer | File | Role |
|-------|------|------|
| Field | `fe.mbt` | `fe25519_*` — p=2^255-19 operations, 10×26-bit limbs |
| Scalar | `sc.mbt` | `sc25519_*` — L=group order operations, 8×32-bit limbs |
| Group | `ge.mbt` | `ge25519_*` — twisted Edwards point add/double/scalarmult |
| API | `api.mbt` | `keypair`, `sign`, `verify` — public entry points |
| SHA-512 | `sha512_*.mbt` (5 files) | Inlined from `src/sha512/` (Loop #5) — **3rd inline, NEED refactor** |

### 3.2 Critical inline dependency

Per Loop #6 lesson, `moon 0.1.20260608` doesn't support cross-package imports. Ed25519 needs SHA-512, so we'll inline again (3rd time):
- `src/sha512/` (Loop #5)
- `src/hmac_sha512/sha512_*.mbt` (Loop #6)
- `src/ed25519/sha512_*.mbt` (Loop #7, this one)

**This is the **3rd inline** — at this point DRY cleanup is becoming a real concern.** After Loop #7 lands, we should investigate moon 0.1.20260713 changelog for cross-package import support, and refactor all 3 inlinings into a single `src/sha512/`.

### 3.3 Field arithmetic (fe25519)

10 limbs × 26 bits = 260 bits > 255, so need carry propagation after mul/add.

```
fe representation: 10 × UInt32, but each holds 26-bit value (radix-2^26)
mul: 20 × 26-bit = 520-bit intermediate, reduce mod p
add/sub: carry propagate across limbs
freeze: full reduction mod p with p = 2^255 - 19
```

**Key operations:**
- `fe25519_unpack(r, x[32])` — load 32 LE bytes → 10 × 26-bit limbs
- `fe25519_pack(r[32], x)` — 10 × 26-bit limbs → 32 LE bytes
- `fe25519_add/sub/mul/square` — basic field ops
- `fe25519_invert` — Fermat's little theorem: a^(p-2) mod p, requires `pow2523`
- `fe25519_pow2523(r, x)` — x^((p-5)/8) mod p, used in `sqrt`

### 3.4 Scalar arithmetic (sc25519)

8 limbs × 32 bits = 256 bits, but **signed** representation for window-3 table (range [-8, 8]).

```
sc representation: 8 × UInt32, but each holds signed 32-bit value (radix-2^31 or 2^32)
mul: 16 × 32-bit = 512-bit intermediate, reduce mod L
window3: serialize as signed bytes for comb table
```

**Key operations:**
- `sc25519_from32bytes(r, x[32])` — load 32 LE bytes → 8 × 32-bit limbs
- `sc25519_from64bytes(r, x[64])` — same but uses top 32 bytes of 64-byte hash
- `sc25519_to32bytes(r[32], x)` — 8 × 32-bit limbs → 32 LE bytes
- `sc25519_mul(r, a, b)` — 64-bit limbs, Barrett reduction mod L
- `sc25519_add(r, a, b)` — 256-bit add with reduce mod L

### 3.5 Group operations (ge25519)

Twisted Edwards point representation. TweetNaCl uses 4 different projective coordinate systems:

```
ge25519_p1p1 — complete (4-tuple after add/double)
ge25519_p2    — (X, Y, Z)        — for doubling
ge25519_p3    — (X, Y, Z, T)     — for adding
ge25519_aff   — (X, Y)           — for precomputed base multiples
ge25519_cached — (Y+X, Y-X, T, Z) — precomputed multiples of base
```

**Key operations:**
- `ge25519_scalarmult_base(r, s)` — sB using precomputed table of 425 base multiples (5-bit windows)
- `ge25519_double_scalarmult_vartime(r, p1, s1, p2, s2)` — s1*p1 + s2*p2 (used in verify)
- `ge25519_pack(r[32], p)` — encode point to 32 bytes (Y + sign of X)
- `ge25519_unpackneg_vartime(r, p[32])` — decode + negate

### 3.6 Public API

```moonbit
pub fn keypair_from_seed(seed : FixedArray[Byte]) -> (FixedArray[Byte], FixedArray[Byte])
  // returns (pk[32], sk[64]) — OpenSSH format

pub fn sign(msg : FixedArray[Byte], sk : FixedArray[Byte]) -> FixedArray[Byte]
  // sk must be 64 bytes (seed || pk); returns sig[64]

pub fn verify(sig : FixedArray[Byte], msg : FixedArray[Byte], pk : FixedArray[Byte]) -> Bool
  // returns true if valid
```

---

## 4. Verification Matrix

| Verification | Tool | Expected |
|--------------|------|----------|
| MoonBit keypair from seed | `moon test` | RFC 8032 § 7.1 Tests 1, 2, 3 (5 vectors) |
| MoonBit sign byte-exact | `moon test` (wbtest) | RFC 8032 § 7.1 Tests 1-3 (OpenSSH has 3) + add Test 4 (1023-byte) |
| MoonBit verify | `moon test` | Verify each test's own sig, reject wrong sigs |
| MoonBit vs OpenBSD C | `verify_c/ed25519_kat.exe` | Same 3 KAT + verify accepts/rejects |
| MoonBit vs Python `cryptography` | Python script | Same 3 KAT (Python uses libsodium/OpenSSL internally) |
| Determinism | `moon test` (blackbox) | Same seed → same sig |
| Bad sig rejection | `moon test` (blackbox) | Tampered sig → false |

**Triple-blind verification**: MoonBit ⊕ OpenBSD C (TweetNaCl) ⊕ Python `cryptography` (libsodium/OpenSSL) on same seed+msg.

---

## 5. Risk Assessment

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Field mul carry overflow | High | Use 64-bit intermediate limbs; verify with X25519's fe layer (not reusable, but pattern is) |
| Scalar mod L wrong | High | Barrett reduction is non-trivial; copy C code line-by-line |
| Edwards coord mixup (p1p1/p2/p3/aff) | High | Use only as transformation helper, all internal |
| SHA-512 inlined bugs | Low | Already validated in Loop #5/6 |
| DRY violation (3rd SHA-512 inline) | Medium | Refactor after Loop #7 lands; not a blocker |
| Slow comb table in `scalarmult_base` | Low | 425 precomputed points × 64 doublings = ~1700 ops; ~5ms in C, similar in MoonBit |
| `String::make(1, byte)` type errors | Low | Use `StringBuilder::write_string` (Loop #6 lesson) |

---

## 6. Module Count

| Module | Lines (est) | Purpose |
|--------|-------------|---------|
| `fe.mbt` | 250 | Field arithmetic |
| `sc.mbt` | 200 | Scalar arithmetic |
| `ge.mbt` | 350 | Group operations |
| `api.mbt` | 100 | Public entry points |
| `sha512_*.mbt` (5 files) | 430 | SHA-512 inlined (3rd copy) |
| `ed25519_test.mbt` | 80 | 8 blackbox |
| `ed25519_wbtest.mbt` | 200 | 3-5 RFC 8032 KAT |
| `ed25519_trace.mbt` | 60 | roundtrip + smoke |
| **Total** | **~1670** | |

---

**签字:** 🧭 Navigator — 2026-07-28
