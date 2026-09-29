# Loop #26 Architect — BigInt + DH group 14 KEX

**Date**: 2026-09-29
**Status**: Architect 设计 → **Verdict**: G1 = src/bigint/ — 64-bit limbs BigInt + Montgomery mod exp (基础 for DH/RSA/ECDSA); G2 = src/kexdh/exchange.mbt — DH group 14 KEX (RFC 3526 + RFC 4253 §8); G3 = cmd/bigint_test/ + cmd/kexdh_test/ + verify_loop26.mjs — 4 target × 2 mode + Python int reference

## TL;DR

| 子目标 | 模块 | LOC | 关键产物 |
|---|---|---|---|
| **G1** BigInt | src/bigint/{moon.pkg, basic.mbt, montgomery.mbt} | 500 | UInt64 limb array + add/sub/mul + Montgomery mod mul/exp |
| **G2** DH group 14 | src/kexdh/{moon.pkg, group14.mbt, exchange.mbt} | 300 | RFC 3526 prime + RFC 4253 §8 SSH-DH-SHA256 |
| **G3** verify | cmd/bigint_test + cmd/kexdh_test + verify_loop26.mjs | 250 | 4 target × 2 mode + Python int reference KAT |

## A. G1 — src/bigint/

### A.1 src/bigint/basic.mbt (250 行)

#### A.1.1 64-bit limbs BigInt
```moonbit
pub struct BigInt {
  limbs : FixedArray[UInt64]  // little-endian (limbs[0] is least significant)
  mut len : Int               // 实际使用长度
  mut sign : Int              // 0 = positive, 1 = negative (Loop #26 only positive)
}
```

#### A.1.2 基础函数
```moonbit
pub fn BigInt::from_uint64(v : UInt64) -> BigInt
pub fn BigInt::from_bytes_le(bytes : FixedArray[Byte]) -> BigInt  // little-endian byte stream
pub fn BigInt::to_bytes_be() -> FixedArray[Byte]                  // big-endian SSH wire format

pub fn BigInt::add(a : BigInt, b : BigInt) -> BigInt
pub fn BigInt::sub(a : BigInt, b : BigInt) -> BigInt
pub fn BigInt::mul(a : BigInt, b : BigInt) -> BigInt               // O(n^2) schoolbook
pub fn BigInt::cmp(a : BigInt, b : BigInt) -> Int                  // -1 / 0 / 1

pub fn BigInt::is_zero() -> Bool
pub fn BigInt::bit_length() -> Int
```

#### A.1.3 SSH wire mpint encoding
```moonbit
pub fn BigInt::mpint_encode(n : BigInt) -> FixedArray[Byte] {
  // RFC 4251 §5: mpint = u32 length + bytes (big-endian)
  // Leading zero byte if MSB of magnitude is set
  let bytes = n.to_bytes_be()
  let needs_leading_zero = bytes.length() > 0 && (bytes[0] & 0x80) != 0
  // ... prepend u32 length + bytes (with optional 0x00 prefix)
}
```

### A.2 src/bigint/montgomery.mbt (250 行)

#### A.2.1 Montgomery modular multiplication
```moonbit
// Algorithm: Henry S. Warren Jr., "Hacker's Delight" §13.6 MRED
// R = 2^(64*n_bits), n is odd, r = R mod n
// MonPro(xs, X) = (xs + (-X * n mod R) * n) / R

pub struct MontCtx {
  n : BigInt              // modulus (must be odd)
  r : BigInt              // 2^(64*n_limbs)
  n_inv_r64 : UInt64      // -n^(-1) mod 2^64
  n_prime : BigInt         // 1 / n (precomputed for Barrett)
}

pub fn MontCtx::new(n : BigInt) -> MontCtx {
  // n_inv_r64 = -n^(-1) mod 2^64 (Newton's iteration)
  // r = 2^(64 * n.len())
  // Compute using low limbs only
}

pub fn mont_mul(ctx : MontCtx, a : BigInt, b : BigInt) -> BigInt {
  // MRED loop: for i = 0..n_limbs:
  //   m = a.limbs[0] * b.limbs[0] mod 2^64 (64-bit mul)
  //   ... accumulate
  // return result / R mod n
}
```

#### A.2.2 Montgomery modular exponentiation
```moonbit
pub fn mont_pow(ctx : MontCtx, base : BigInt, exp : BigInt) -> BigInt {
  // Binary exponentiation with Montgomery multiplication
  // result = MontMul(ctx, 1, R) // MontMul(R^2, base, n) — actually MontMul(R, 1) gives R mod n
  // for bit in exp (LSB to MSB):
  //   result = MontMul(ctx, result, result)
  //   if bit: result = MontMul(ctx, result, base)
}
```

## B. G2 — src/kexdh/

### B.1 src/kexdh/group14.mbt (100 行)

#### B.1.1 RFC 3526 group 14 (2048-bit MODP)
```moonbit
pub fn group14_prime() -> BigInt {
  // p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
  // 256-byte big-endian bytes (RFC 3526 §C2):
  // FFFFFFFF FFFFFFFF C90FDAA2 2168C234
  // C4C6628B 80DC1CD1 29024E08 8A67CC74
  // 020BBEA6 3B139B22 514A0879 8E3404DD
  // EF9519B3 CD3A431B 302B0A6D F25F1437
  // 4FE1356D 6D51C245 E485B576 625E7EC6
  // F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
  // EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
  // 49286651 ECE65381 FFFFFFFF FFFFFFFF
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    ...
  ])
  BigInt::from_bytes_be(bytes)
}

pub fn group14_generator() -> BigInt {
  // g = 2
  BigInt::from_uint64(2UL)
}
```

### B.2 src/kexdh/exchange.mbt (200 行)

#### B.2.1 Client-side KEX flow
```moonbit
pub struct DhClientKey {
  x : BigInt       // private key (random)
  e : BigInt       // public key e = g^x mod p
}

pub fn dh_generate_client_key() -> DhClientKey {
  // x = random < p (2048 bits), e = g^x mod p
}

pub fn dh_compute_shared_secret(
  x : BigInt,
  f_bytes : FixedArray[Byte],  // server's public key (mpint)
  prime : BigInt,
) -> FixedArray[Byte> {
  // K = f^x mod p
  // Encode K as mpint (RFC 4253 §8: prepend 0x00 if MSB set)
}
```

#### B.2.2 Exchange hash H (RFC 4253 §8)
```moonbit
pub fn kex_dh_sha256(
  v_c : String, v_s : String,
  i_c : FixedArray[Byte], i_s : FixedArray[Byte],
  k_s : FixedArray[Byte],  // server host key blob
  e : FixedArray[Byte], f : FixedArray[Byte],  // mpint encoded
  k : FixedArray[Byte],   // mpint encoded shared secret
) -> FixedArray[Byte] {
  // H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
  // V_C/V_S: version strings (without \r\n)
  // I_C/I_S: KEXINIT full payloads (msg_type 0x14 included)
}
```

## C. G3 — cmd/bigint_test/ + cmd/kexdh_test/ + verify_loop26.mjs

### C.1 cmd/bigint_test/main.mbt 输出

```
=== SSH-WASM-SSH Loop #26 BigInt ===
basic_add: PASS
basic_sub: PASS
basic_mul: PASS
basic_cmp: PASS
mont_mul_kat: PASS          # vs Python pow(a*b*R^-1 mod p)
mont_pow_kat: PASS       # vs Python pow(a, e, p)
dh_e_compute: PASS        # vs Python pow(g, x, p)
dh_k_compute: PASS        # vs Python pow(f, x, p)
dh_k_check: PASS          # K == pow(e, y, p) consistency
exchange_hash_kat: PASS   # H = SHA-256(...) vs Python hashlib
```

### C.2 cmd/kexdh_test/main.mbt 输出
```
=== SSH-WASM-SSH Loop #26 DH group 14 KEX ===
group14_prime_len: 256      # bytes
group14_g: 2                # generator
e_size: 256                 # e length
f_size: 256                 # f length
k_size: 256                 # K length (mpint encoded)
k_consistency: PASS        # pow(f, x, p) == pow(e, y, p)
h_size: 32                  # SHA-256 output
h_kat: PASS                 # vs Python hashlib
```

### C.3 verify_loop26.mjs (4 target × 2 mode byte-exact)

## D. 验证

### D.1 4 target byte-exact
```
$ node host/verify_loop26.mjs
✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: <new>)
```

### D.2 Triple-blind (MoonBit vs Python vs OpenSSL)
- BigInt mul: MoonBit = Python int * int
- BigInt mont_pow: MoonBit = Python pow(a, e, p)
- DH shared secret: MoonBit = OpenSSL EVP_PKEY_derive

### D.3 Verify.mjs/loop22/loop24/loop25 维持
- verify.mjs hash 230bfd5b0c02d682 维持
- verify_loop22.mjs hash 4ac5544049c297cf 维持
- verify_loop24.mjs hash 7f69fdbe8860a78a 维持
- verify_loop25.mjs hash b3cfa84c014758cb 维持

## E. 4 target byte-exact 维持

| 验证 | 维持 hash |
|---|---|
| verify.mjs | 230bfd5b0c02d682 |
| verify_loop22.mjs | 4ac5544049c297cf |
| verify_loop24.mjs | 7f69fdbe8860a78a |
| verify_loop25.mjs | b3cfa84c014758cb |
| verify_loop26.mjs | 新 hash (cmd/bigint_test + cmd/kexdh_test) |

Loop #26 不破现有 cmd/main 输出（new exes）。

## F. 时间预算

| 任务 | 预估 |
|---|---|
| G1 BigInt library | 4-5 hours |
| G2 DH group 14 KEX | 2-3 hours |
| G3 verify + KAT | 1-2 hours |
| Loop #26 5 件套文档 | 30 min |
| 总计 | 7-10 hours |