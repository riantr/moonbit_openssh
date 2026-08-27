# Loop #8 ChaCha20-Poly1305 AEAD — Architect Design

**Date:** 2026-08-25
**Role:** 🏗️ Architect
**Scope:** Two-layer AEAD design — RFC 8439 core (triple-blind verifiable) + OpenSSH wire wrapper (C-harness verifiable)

---

## 1. Architecture Overview

```
┌────────────────────────────────────────────────────────────┐
│ ssh_wire.mbt                                               │
│   chachapoly_new64(key64) / chachapoly_crypt(...)          │  OpenSSH @openssh.com
│   chachapoly_get_length(seq, hdr4)                         │  (2 keys, seq-IV)
└────────────────────────────────────────────────────────────┘
          │ reuses                    │ reuses
┌─────────▼──────────┐    ┌───────────▼──────────────────────┐
│ rfc8439.mbt        │    │ inlined chacha_* + poly1305_*    │
│   aead_encrypt     │    │ ChaChaState::new256/set_iv/process│
│   aead_decrypt     │    │ poly1305_auth                     │
│   (12B nonce, 1 key)│   │                                   │
└────────────────────┘    └───────────────────────────────────┘
```

Two distinct algorithms, deliberately separated:

| | RFC 8439 AEAD | OpenSSH @openssh.com |
|---|---|---|
| Keys | one 32-byte | two 32-byte (K_main, K_header) |
| Nonce/IV | 12 bytes (counter=1 for poly-key, ≥2 payload) | 8-byte BE seqnr |
| Poly-key derivation | ChaCha20(K, nonce, counter=**1**) block 0 | ChaCha20(K_main, seqIV, counter=**0**) 32 bytes |
| Payload keystream | counter starts at **2** | K_main counter starts at **1**; header via separate K_header ctx counter 0 |
| MAC input | aad ‖ pad16 ‖ ct ‖ pad16 ‖ LE64(\|aad\|) ‖ LE64(\|ct\|) | raw `aad‖ct` concatenation only |
| Header encryption | none | 4-byte length encrypted with K_header |

---

## 2. Module Decomposition

### 2.1 Inlined primitives (rename-collision audit required)

From `src/chacha/`: `state.mbt`, `primitives.mbt`, `block.mbt`, api part of `api.mbt` → prefix stays (`ChaChaState`, `chacha_block`, etc. are unique).

From `src/poly1305/`: `clamp.mbt`, `mul.mbt`, `process.mbt`, `final.mbt`, api of `api.mbt`.

⚠️ **Collision found by Navigator:** `u8_to_32_le` exists in BOTH `chacha/primitives.mbt` and `poly1305/clamp.mbt`. Resolution: keep the chacha one as-is; rename the poly1305 copy to `poly_u8_to_32_le` and update its single caller inside inlined `clamp.mbt`.

### 2.2 `rfc8439.mbt` — Core AEAD

```moonbit
pub fn aead_encrypt(key : FixedArray[Byte],      // 32
                    nonce : FixedArray[Byte],    // 12
                    aad : FixedArray[Byte],
                    plaintext : FixedArray[Byte]) -> FixedArray[Byte]
// returns ct || tag(16)

pub fn aead_decrypt(key, nonce, aad, ciphertext_and_tag) -> FixedArray[Byte]?
// Option: Some(pt) on valid tag, None on tag mismatch
```

Algorithm (RFC 8439 § 2.8):
1. `poly_key[32] = chacha20_block(key, nonce, counter=1)` — first 32 bytes of keystream block 1
2. `ct = ChaCha20 encrypt(plaintext)` with same state continuing from counter=2
3. `mac_data = aad ‖ Z(padtolen(aad)) ‖ ct ‖ Z(padtolen(ct)) ‖ LE64(len(aad)) ‖ LE64(len(ct))`
4. `tag = poly1305_auth(poly_key, mac_data)`
5. decrypt: recompute tag over received ct, constant-time-ish compare (vartime acceptable — tag is public), then decrypt

### 2.3 `ssh_wire.mbt` — OpenSSH wrapper

```moonbit
pub struct ChachaPolyCtx {
  priv main_key : FixedArray[Byte]     // 32
  priv header_key : FixedArray[Byte]   // 32
}

pub fn chachapoly_new64(key : FixedArray[Byte]) -> ChachaPolyCtx   // abort if len != 64

// Mirrors chachapoly_crypt(): operates on a full packet buffer layout
//   src[0..aadlen)        encrypted length header (aadlen is always 4 in practice)
//   src[aadlen..aadlen+len) payload
//   src[aadlen+len .. +16)  tag
pub fn chachapoly_crypt(ctx : ChachaPolyCtx, seqnr : UInt,
                        src : FixedArray[Byte],
                        aadlen : Int, datalen : Int,
                        do_encrypt : Bool) -> FixedArray[Byte]?
// None = MAC invalid (decrypt path)

pub fn chachapoly_get_length(ctx : ChachaPolyCtx, seqnr : UInt,
                             hdr : FixedArray[Byte]) -> UInt  // 4-byte hdr
```

Flow per Navigator's C reading:
1. seqbuf = BE64(seqnr); poly_key = ChaCha(K_main, iv=seqbuf, ctr=0) process 32 zero bytes
2. decrypt: verify Poly1305(poly_key, src[0..aadlen+datalen)) vs src tail FIRST → fail = None
3. header: ChaCha(K_header, iv=seqbuf, ctr=0) crypt aadlen bytes
4. payload: ChaCha(K_main, iv=seqbuf, ctr=1UL) crypt datalen bytes
5. encrypt: tag = Poly1305(poly_key, dest[0..aadlen+datalen)) appended

### 2.4 Tests

- `aead_wbtest.mbt`:
  - `rfc8439_2_8_2_kat` — official vector byte-exact
  - `rfc8439_poly_key_derivation` — check block-counter-1 derivation against Python dump
  - internal pad16/LE64 unit checks
- `aead_test.mbt`:
  - roundtrip encrypt→decrypt (empty pt, pt < 64B, pt across blocks, exact multiple of 16)
  - tampered ct bit-flip → None
  - tampered tag → None
  - wrong AAD → None (tag covers it)
  - wrong nonce → None
  - wrong key → None
  - OpenSSH wrapper: roundtrip with aadlen=4, get_length consistency, tamper → None, seq sensitivity (seq 0 vs 1 differ)

---

## 3. Data Flow (RFC 8439 encrypt)

```
key(32) ──┐
nonce(12)─┤
          ▼
  ChaChaState::new256 ──set_iv(nonce[0..8]+nonce[8..12]? , counter=1)
```

⚠️ **Design note — nonce packing:** our Loop #1 `set_iv` takes an **8-byte IV** into words [14..15] and a UInt64 counter into [12..13]. RFC 8439's 12-byte nonce maps to words [13..15]? NO — RFC 8439 layout is:

```
state[12] = counter (32-bit)
state[13] = nonce[0..4)
state[14] = nonce[4..8)
state[15] = nonce[8..12)
```

That is the **IETF variant** (32-bit counter), which DIFFERS from our Bernstein layout (64-bit counter at [12..13], 8-byte IV at [14..15]). We must NOT shoehorn the 12-byte nonce into set_iv.

**Solution:** build the 16-word state directly for RFC 8439:
```moonbit
fn rfc8439_state(key : FixedArray[Byte], nonce12 : FixedArray[Byte], counter : UInt) -> FixedArray[UInt]
// [0..4]=sigma, [4..12]=key, [12]=counter, [13..16]=nonce12 as 3 LE u32s
```
and run `chacha_block` manually for poly-key (single block), then reuse a small XOR loop for payload starting from counter+1 (reusing `ChaChaState::process` semantics would fight the different layout — instead write a tiny local `rfc8439_xor(state_words, input, start_counter)` mirroring Loop #1's process loop but with the IETF layout). This keeps both variants unambiguous.

For the **OpenSSH wrapper**, the existing Bernstein-layout `ChaChaState::new256 + set_iv(iv8=seqbuf_LE?...)` applies — BUT careful: OpenSSH loads iv via U8TO32_LITTLE(iv+0/+4) i.e. **the 8 seqbuf bytes go into words [14..15] little-endian**, and POKE_U64 wrote seqnr big-endian into seqbuf. So net effect: word14 = swap32(lo32(seqnr)), word15 = swap32(hi32(seqnr)). Our MoonBit wrapper must reproduce exactly: build seqbuf as BE64 bytes, then feed to set_iv unchanged. Simplest faithful approach: replicate literally — construct seqbuf BE64 array and call set_iv(seqbuf).

---

## 4. Edge Cases

| Case | Handling |
|------|----------|
| empty plaintext | allowed; tag still computed over aad‖lengths |
| empty aad | allowed; skipped in mac_data |
| pt length % 16 ≠ 0 | pad16 zero-padding in MAC only, not stored |
| aadlen ≠ 4 (wrapper) | supported generically (OpenSSH only ever uses 4) |
| tag mismatch | return None BEFORE any decryption (wrapper) / None (core) |
| seqnr wrap | out of scope (transport layer concern) |

---

## 5. Verification Plan

| Check | Tool | Expected |
|-------|------|----------|
| Compile clean | `moon check` | 0 err/warn |
| Full suite | `moon test` | existing 120 + new ~18 all pass |
| RFC 8439 § 2.8.2 | wbtest KAT | byte-exact |
| Python cross | `aead_python_ref.py` using `cryptography.ChaCha20Poly1305` | ct‖tag byte-exact on 3 scenarios (kat + random-ish + aad-only) |
| OpenSSH C harness | `verify_c/chachapoly_harness.c` including real `cipher-chachapoly.c`+`chacha.c`+`poly1305.c` | identical outputs for fixed (key, seq, packet) matrix, encrypt+decrypt+tamper |

---

## 6. Open Issues

1. `timingsafe_bcmp` ported as vartime compare (documented deviation; tags are public).
2. Wrapper returns fresh arrays (functional style) rather than in-place C buffers.
3. DRY debt now: SHA-512 ×3, chacha ×2, poly1305 ×2 — refactor when moon gains imports.

---

**签字:** 🏗️ Architect — 2026-08-25
