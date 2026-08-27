# Loop #5 SHA-512 — Architect Design

**Date:** 2026-07-24
**Role:** 🏛️ Software Architect

---

## 1. 模块划分

```
src/sha512/
├── moon.pkg
├── state.mbt                    # 128-byte block, 64-byte hash, K[80], init_H[8]
├── primitives.mbt               # Ch, Maj, Sigma0/1, sigma0/1, ROTR (64-bit)
├── block.mbt                    # 80 轮 compression
├── update.mbt                   # 增量更新 + 128-bit Merkle-Damgård padding
├── final.mmt                    # 序列化 64 字节大端
├── api.mbt                      # 公开 API: sha512(msg) -> 64 字节
├── sha512_test.mbt              # blackbox (空 / 1B / 边界)
└── sha512_wbtest.mbt            # FIPS 180-4 KAT
```

## 2. 关键算法差异 (vs SHA-256)

| 维度 | SHA-256 | SHA-512 |
|------|---------|---------|
| `block_len` | 64 | **128** |
| `hash_len` | 32 | **64** |
| `W` array length | 64 | **80** |
| rounds | 64 | **80** |
| state type | `UInt` (32-bit) | **`UInt64`** (64-bit) |
| state 长度 | 8 × UInt | 8 × UInt64 |
| 长度编码 | 64-bit BE | **128-bit BE** (高 64 bit 总为 0) |

## 3. 64-bit 操作

MoonBit `UInt64` 是原生 64-bit unsigned,`>>`/`<<`/`&`/`|`/`^` 都是 64-bit,wrap-around 在 2^64。

- `rotr(n, x) = (x >> n) | (x << (64 - n))` (UInt64 域)
- `Ch(x, y, z) = (x & y) ^ ((x ^ 0xFFFFFFFFFFFFFFFF) & z)` (UInt64)
- `Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)` (UInt64)
- `Sigma0(x) = ROTR(28, x) ^ ROTR(34, x) ^ ROTR(39, x)`
- `Sigma1(x) = ROTR(14, x) ^ ROTR(18, x) ^ ROTR(41, x)`
- `sigma0(x) = ROTR(1, x) ^ ROTR(8, x) ^ (x >> 7)` (注意:不是 ROTR(7)!)
- `sigma1(x) = ROTR(19, x) ^ ROTR(61, x) ^ (x >> 6)` (注意:不是 ROTR(6)!)

(FIPS 180-4 § 4.1.3)

## 4. Padding (128-bit 长度)

跟 SHA-256 一样是 Merkle-Damgård,但长度是 128-bit BE:
- append `0x80` byte
- pad 0x00 until `len + 1 + length_bytes (16) ≡ 0 (mod 128)`
- append 16-byte (128-bit) big-endian bit length
- 至少 1 byte padding,16 bytes length,total padding = 17-144 bytes

我们用 `UInt64 bit_count`,高 64 bit 总是 0(因为 SHA-512 限制 input < 2^128 bits)。padding 写 16 字节:高 8 字节 0 + 低 8 字节 bit_count BE。

## 5. Public API

```moonbit
pub fn sha512(message : FixedArray[Byte]) -> FixedArray[Byte]  // 64 字节
```

跟 Loop #3 sha256() 平行:
```moonbit
let state : FixedArray[UInt64] = FixedArray::make(8, 0UL)
for i = 0; i < 8; i = i + 1 { state[i] = init_H[i] }
let buffer : FixedArray[Byte] = FixedArray::make(block_len, b'\x00')
let (buf2, buf_len, bc) = update(state, buffer, 0, 0UL, message)
pad(state, buf2, buf_len, bc)
serialize_state(state)
```

## 6. 测试策略

### 6.1 KAT (sha512_wbtest.mbt)

- FIPS 180-4 § A.1 Test 1: "abc" → `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9fc94d54f6b6a6b1f1d26f5fc69f3044a8d68b6c19c19e`
- FIPS 180-4 § A.1 Test 2: 56-byte → `8e40b84480b1f47f11d6c8b389f2369a3288b2b0451d0f1feee5a4d97c1f8b3e4...`
- FIPS 180-4 § A.2 Test 3: 112-byte → `8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aebb6c1a3e9ec4cd2c78dd3c2d2e70e94e64c2c79e2c...`
- FIPS 180-4 § A.2 Test 4: 1,000,000 × "a" (~5-10 sec, skip if too slow)

### 6.2 Blackbox (sha512_test.mbt)

- 空 message
- 1 byte
- 边界 (127 / 128 / 129 / 191 / 256 / 384 / 512 bytes)
- deterministic
- 不同 input 不同 output

### 6.3 C Verification

`verify_c/sha512_kat.exe` 跑 OpenBSD sha2.c 原版 (Test 1 + Test 3,skip Test 4 1M 'a' 慢)

### 6.4 Python Triple-Blind

```python
import hashlib
hashlib.sha512(b"abc").hexdigest()
```

---

**签字:** 🏛️ Architect — 2026-07-24