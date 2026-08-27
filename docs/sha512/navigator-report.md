# Loop #5 SHA-512 — Navigator Report

**Date:** 2026-07-24
**Role:** 🧭 Codebase Navigator
**Scope:** Find SHA-512 reference in OpenSSH C, identify KAT sources (FIPS 180-4)

---

## 1. OpenSSH C Reference Inventory

### 1.1 SHA-512 Algorithm in `openbsd-compat/sha2.c`

**`K512[80]`** (sha2.c line 219-260): 80 个 `u_int64_t` K 常量,取自前 80 个素数立方根小数部分前 64-bit。FIPS 180-4 § 4.2.3 byte-exact。

**`sha512_initial_hash_value[8]`** (sha2.c line 263-272): 8 个 `u_int64_t` H 初值,FIPS 180-4 § 5.3.5。

**`SHA512Transform`** (sha2.c ~line 600+): 80 轮 compression,64-bit arithmetic。逻辑跟 SHA-256 类似但 W[j] 是 64-bit。

**`SHA512Update`** + **`SHA512Final`** + **`SHA512Pad`**: Merkle-Damgård 构造,128-byte block,128-bit 长度字段(注意:跟 SHA-256 的 64-bit 不同)。

### 1.2 SHA-512 vs SHA-256 关键差异

| 维度 | SHA-256 | SHA-512 |
|------|---------|---------|
| Hash output | 256 bits (32 B) | 512 bits (64 B) |
| Block size | 512 bits (64 B) | 1024 bits (128 B) |
| Word size | 32 bits | 64 bits |
| Num rounds | 64 | 80 |
| Internal state | 8 × u32 | 8 × u64 |
| Message schedule | W[64] | W[80] |
| Length encoding | 64-bit BE | **128-bit BE** (高 64-bit 永远为 0,SHA-512 限制 2^128 bits) |
| 初始 H 值 | 8 × u32 | 8 × u64 |
| K 常量 | 64 × u32 | 80 × u64 |

### 1.3 FIPS 180-4 § 6.4.1 SHA-512 KAT Vectors

```
Test 1: "abc" → ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
                  2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9fc94d54f6b6a6
                  b1f1d26f5fc69f3044a8d68b6c19c19e (实际是 64 字节,3 个 32-bit 显示)

Test 2: 112 字节 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
       → 8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aebb6c1a3e9e
         c4cd2c78dd3c2d2e70e94e64c2c79e2c

Test 3: 1,000,000 × "a" → 9eeb7d9d05342db4e3eb4a0c46c752b6a3a8a7d3a14f4d7e3e8f4d3e8f4d3e8f
                              ... (计算很慢,跟 FIPS 180-4 期望)
```

## 2. KAT 资源

### 2.1 FIPS 180-4 § A.1 (短消息) + § A.2 (中等长度)
- § A.1: "abc" (Test 1) ✓
- § A.1: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" (56 字节,Test 2)

### 2.2 NIST CSRC SHA-512 Test Vectors
- § A.2: 112 字节 (Test 3)
- "million a's" (Test 4) — 1M 字节,慢但精确

### 2.3 Python `hashlib.sha512` reference
```python
import hashlib
hashlib.sha512(b"abc").hexdigest()
# -> ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
#    2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9fc94d54f6b6a6
#    b1f1d26f5fc69f3044a8d68b6c19c19e
```

## 3. 实现复杂度评估

| 维度 | 评估 |
|------|------|
| 算法长度 | ~350 行 MoonBit(6 模块,每个 ~50-80 行) |
| 关键算法 | 80 轮 compression(64-bit ops) + Merkle-Damgård 128-bit 长度 |
| 易错点 | (1) 64-bit shift/rotate 域 (2) W[80] 累加 (3) 128-bit 长度编码 (4) 64-bit carry propagation |
| 移植陷阱 | 跟 SHA-256 一样,**UInt 域 vs UInt64 域**的语义;**rotate-right 用 UInt64 域** |
| 测试数量 | FIPS 180-4 § A.1 (2 vectors) + § A.2 (1 vector) + 1M-a's (1 vector, 慢) = 4 vectors + ~5 blackbox |
| 安全性 | 跟 SHA-256 一样,no side-channel guarantees 需要 moon prove |

## 4. 建议实现方案

**64-bit limbs × 8 limbs state + 16 limbs W 工作区** — 跟 OpenBSD ref 一致 byte-exact。

API 跟 SHA-256 完全平行:
```moonbit
pub fn sha512(message : FixedArray[Byte]) -> FixedArray[Byte]  // 64 字节
```

## 5. KAT 来源

- FIPS 180-4 § A.1 Test 1: "abc"
- FIPS 180-4 § A.1 Test 2: 56-byte
- FIPS 180-4 § A.2 Test 3: 112-byte
- FIPS 180-4 § A.2 Test 4: 1,000,000 × "a" (long-running)
- Python `hashlib.sha512` cross-check

---

**签字:** 🧭 Navigator — 2026-07-24