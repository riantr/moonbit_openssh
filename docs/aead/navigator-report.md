# Loop #8 ChaCha20-Poly1305 AEAD — Navigator Report

**Date:** 2026-08-25
**Role:** 🧭 Codebase Navigator
**Scope:** Map OpenSSH's chacha20-poly1305@openssh.com composition, inventory existing MoonBit primitives, identify verification strategy

---

## 1. OpenSSH C Reference

### 1.1 `cipher-chachapoly.c` (v1.10, 4244 bytes) — THE composition layer

Two independent ChaCha20 contexts, **two different 32-byte keys**:

```c
struct chachapoly_ctx {
	struct chacha_ctx main_ctx, header_ctx;
};

chachapoly_new(key /* 64 bytes */):
	chacha_keysetup(&ctx->main_ctx,   key,       256);  // K_main   = key[0..32)
	chacha_keysetup(&ctx->header_ctx, key + 32,  256);  // K_header = key[32..64)
```

**Critical discovery:** OpenSSH uses **TWO separate keys**, not one shared key! (My initial recollection of "one key, two counters" was wrong — the C code is unambiguous.)

### 1.2 Per-packet flow (`chachapoly_crypt`, seqnr = packet sequence number)

```
seqbuf = POKE_U64(seqnr)                       // 8-byte big-endian sequence

// Step 1: derive per-packet Poly1305 key from K_main
chacha_ivsetup(main_ctx, iv=seqbuf, counter=NULL)     // counter starts at 0
poly_key[32] = chacha_encrypt_bytes(main_ctx, zeros, 32)

// Step 2: decrypting → verify tag FIRST (encrypt-then-MAC overall)
tag = src[aadlen+len .. +16]
expected = poly1305_auth(poly_key, src[0 .. aadlen+len])   // AAD || ciphertext as MAC input
if !timingsafe_bcmp: reject

// Step 3: decrypt the length header with K_header
chacha_ivsetup(header_ctx, iv=seqbuf, counter=NULL)    // fresh ctx, counter 0
dest[0..aadlen) = chacha(src[0..aadlen))

// Step 4: decrypt payload with K_main at counter 1
chacha_ivsetup(main_ctx, iv=seqbuf, counter=one[LE u64=1])
dest[aadlen..+len) = chacha(src[aadlen..+len))

// Step 5: encrypting → append tag over dest[0..aadlen+len)
```

Key subtleties:
- **IV = 8-byte big-endian seqnr**, counter is the *second* arg to `chacha_ivsetup`
- Poly-key derivation uses **counter 0**; payload encryption uses **counter 1**
- MAC input = `aad || ciphertext` (the **encrypted** length header, not plaintext)
- Decrypt path verifies tag **before any decryption** (no malleability window)
- `chachapoly_get_length`: header_ctx-only decryption of first 4 bytes (used pre-buffering)

### 1.3 Underlying chacha.c semantics (matches Loop #1 MoonBit port)

```c
chacha_ivsetup(x, iv /*8B*/, counter /*8B or NULL*/):
	input[12] = counter ? U8TO32_LITTLE(counter+0) : 0
	input[13] = counter ? U8TO32_LITTLE(counter+4) : 0
	input[14] = U8TO32_LITTLE(iv+0)
	input[15] = U8TO32_LITTLE(iv+4)
```

✅ Exactly matches our `ChaChaState::set_iv(iv, counter?)` from Loop #1 (`src/chacha/api.mbt:59`). The one[8]={1,0,...} LE constant maps to `counter: Some(1UL)`.

---

## 2. Existing MoonBit Primitives (Loop #1 + #2, both triple-blind verified)

| Primitive | Package | Public API we can reuse | Status |
|-----------|---------|------------------------|--------|
| ChaCha20 block | `src/chacha/block.mbt` | `chacha_block(state) -> FixedArray[UInt]` | ✅ 10/10 |
| ChaCha20 state/keystream | `src/chacha/api.mbt` | `ChaChaState::new256(key)`, `::set_iv(iv, counter?)`, `::process(input)` | ✅ 10/10 |
| Poly1305 MAC | `src/poly1305/api.mbt` | `poly1305_auth(key32, msg) -> tag16` | ✅ 28/28 |

**Constraint:** moon 0.1.20260608 has no cross-package imports → both must be **inlined** into new package (4th and 2nd inline copies respectively).

---

## 3. Verification Strategy

### 3.1 Two-layer design, two verification regimes

| Layer | API | Reference available? | Blind count |
|-------|-----|---------------------|-------------|
| **RFC 8439 core AEAD** | `aead_encrypt(key24, nonce12, aad, pt)`, `aead_decrypt(...)` | RFC 8439 § 2.8.2 KAT + **Python `cryptography.ChaCha20Poly1305`** | Triple ✅ |
| **OpenSSH wire wrapper** | `chachapoly_new64`, `crypt(seq, buf, aadlen, datalen, encrypt)`, `get_length(seq, hdr)` | OpenSSH C harness only (Python has no @openssh.com variant) | Double (C + self-consistency) |

Rationale: RFC 8439 core gives us the strong triple-blind anchor (12-byte nonce, poly-key = block 0 counter 1, AAD‖ct MAC). The OpenSSH wrapper is thin glue over already-verified primitives; its correctness is pinned by a C harness running the actual `chachapoly_crypt` on identical inputs.

### 3.2 RFC 8439 § 2.8.2 vector (for the core layer)

```
key    = 808182...9f (32 bytes sequential)
nonce  = 07000000404142...07 (12 bytes)
aad    = 50515253c0c1c2c3c4c5c6c7 (16 bytes)
pt     = "Ladies and Gentlemen of the class of '99 ..."
tag    = 1ae10b594f09e26a7e902ecbd0600691
```

Python cross-check via:
```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
ChaCha20Poly1305(key).encrypt(nonce, pt, aad)   # ct||tag
```

### 3.3 OpenSSH wrapper harness

Copy `chacha.c`, `poly1305.c`, `cipher-chachapoly.c` into verify_c/, stub includes, drive `chachapoly_crypt` with fixed key/seq/packet, dump outputs; mirror the same calls in MoonBit wrapper tests.

---

## 4. Module Plan

```
src/aead/
├── moon.pkg
├── chacha_*.mbt × 5      # inlined from src/chacha (state/primitives/block/api minus tests)
├── poly1305_*.mbt × 6    # inlined from src/poly1305
├── rfc8439.mbt           # core AEAD: rfc8439_aead_encrypt / _decrypt
│                         #   - poly_key = ChaCha20(K, nonce12, counter=1) block
│                         #   - ct = ChaCha20(K, nonce12, counter≥2) ⊕ pt
│                         #   - tag = Poly1305(pk, aad ‖ pad16 ‖ ct ‖ pad16 ‖ LE64(|aad|) ‖ LE64(|ct|))
├── ssh_wire.mbt          # OpenSSH variant: chachapoly_new64 / chachapoly_crypt / get_length
├── aead_test.mbt         # blackbox: roundtrip, tamper-reject, wrong-aad, wrong-nonce, wrong-key
└── aead_wbtest.mbt       # RFC 8439 § 2.8.2 KAT + internal unit checks
```

Note the RFC 8439 vs OpenSSH differences the architect must encode carefully:

| Aspect | RFC 8439 AEAD | OpenSSH @openssh.com |
|--------|---------------|----------------------|
| Nonce | 12 bytes | 8-byte BE seqnr |
| Poly key | Chacha block **counter=1** | Chacha(K_main, seq IV) **counter=0** |
| Key count | 1 (32B) | 2 (64B: K_main + K_header) |
| Header encryption | none (AAD plaintext) | 4B length encrypted w/ K_header |
| MAC input | aad‖pad‖ct‖pad‖lengths | raw aad‖ct concatenation, no padding/lengths |

These are genuinely different algorithms sharing components — both layers must be tested separately.

---

## 5. Risk Assessment

| Risk | Mitigation |
|------|------------|
| RFC 8439 padding/length-format wrong (pad16, LE64 lengths) | § 2.8.2 official KAT catches instantly |
| Counter off-by-one between poly-key derivation and payload | KAT + Python cross-check catch instantly |
| Inline name collisions (u8_to_32_le exists in both chacha & poly1305 clamp.mbt!) | Rename on inline: chacha_u8_to_32_le / poly_u8_to_32_le — **must check for duplicates at inline time** |
| OpenSSH wrapper seqbuf endianness (POKE_U64 big-endian!) | C harness byte-compare |
| 5th SHA-style DRY debt growing | Accepted; tracked for future refactor |

---

**签字:** 🧭 Navigator — 2026-08-25
