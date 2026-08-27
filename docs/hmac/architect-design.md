# Loop #3 HMAC-SHA256 — Architect Design

**Date:** 2026-07-24
**Role:** 🏛️ Software Architect

---

## 1. 模块划分

### 1.1 顶层结构

```
src/
├── sha256/                          # SHA-256 单向哈希
│   ├── moon.pkg
│   ├── state.mbt                    # 常量 (block_len, hash_len, init H[8], K[64])
│   ├── primitives.mbt               # Ch, Maj, Sigma0, Sigma1, sigma0, sigma1, ROTR
│   ├── block.mbt                    # 1 block transform (64 轮 compression)
│   ├── update.mbt                   # 增量更新 + Merkle-Damgård padding
│   ├── final.mbt                    # 输出 32 字节大端 hash
│   ├── api.mbt                      # 公开 API: sha256(msg) -> 32 字节
│   ├── sha256_test.mbt              # blackbox (空 / 1B / 边界)
│   └── sha256_wbtest.mbt            # FIPS 180-4 KAT (3 vectors)
│
├── hmac/                            # HMAC 包装 (基于 SHA-256)
│   ├── moon.pkg
│   ├── api.mbt                      # hmac_sha256(key, msg) -> 32 字节
│   ├── hmac_test.mbt                # blackbox (不同 key 长度 / 多次调用)
│   └── hmac_wbtest.mbt              # RFC 4231 KAT (7 vectors)
```

### 1.2 模块依赖

```
sha256/  ─────────► (无外部依赖,仅 stdlib UInt/UInt64)
   ▲
   │
hmac/   ─────────► sha256/ (内部 import)
```

### 1.3 数据流

**SHA-256:**
```
input (任意长度)
  ↓ update
  ├─ fill buffer (64 B) → 满 → transform → 状态更新
  ↓ final
  ├─ pad 0x80 + 0x00* + 64-bit big-endian length
  ├─ transform (last 1 or 2 blocks)
  └─ 序列化 state[8] → 32 字节大端输出
```

**HMAC-SHA256:**
```
key (任意长度) + msg (任意长度)
  ↓
  ┌─ if len(key) > 64: key = SHA256(key)[:64]
  ├─ else: key = key[:64] 补 0
  ├─ ipad_key = key XOR 0x36 (64 字节)
  ├─ opad_key = key XOR 0x5c (64 字节)
  ├─ inner = SHA256(ipad_key || msg)
  └─ HMAC = SHA256(opad_key || inner)  → 32 字节
```

---

## 2. 关键算法细节

### 2.1 SHA-256 Compression Function (block.mbt)

输入:`state[8]` + `block[16] u32 BE`
输出:更新的 `state[8]`

```
W[0..15]  = block  (大端解析)
W[16..63] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]

a,b,c,d,e,f,g,h = state[0..7]
for j = 0..63:
  T1 = h + Sigma1(e) + Ch(e,f,g) + K[j] + W[j]
  T2 = Sigma0(a) + Maj(a,b,c)
  h = g; g = f; f = e; e = d + T1
  d = c; c = b; b = a; a = T1 + T2

state[0..7] += a,b,c,d,e,f,g,h
```

### 2.2 辅助函数 (primitives.mbt)

```
ROTR(n, x) = (x >> n) | (x << (32 - n))      // UInt 域,32-bit 循环右移
Ch(x,y,z)  = (x & y) ^ (~x & z)
Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)
Sigma0(x)  = ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x)
Sigma1(x)  = ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x)
sigma0(x)  = ROTR(7, x) ^ ROTR(18, x) ^ (x >> 3)
sigma1(x)  = ROTR(17, x) ^ ROTR(19, x) ^ (x >> 10)
```

**关键移植陷阱(Loop #2 教训):**
- `ROTR` 必须在 UInt 域做,否则 32-bit 循环会变成 UInt64 的长循环
- `>> n` 在 UInt 域会自动按 32-bit 截断

### 2.3 Padding (update.mbt + final.mbt)

Merkle-Damgård 构造:
- append `0x80` byte
- append `0x00` bytes until message length ≡ 56 (mod 64)
- append 64-bit big-endian bit length (length_in_bits)
- 至少 1 byte padding,至少 8 bytes length 字段,total padding = 1-64+8 bytes

如果原长度已经 ≡ 56 (mod 64) after appending 0x80,需要额外 64 bytes。

### 2.4 Big-endian I/O (state.mbt + primitives.mbt)

- **读 BE u32:** `(b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]`
- **写 BE u32:** `out[0] = (v >> 24) & 0xFF; out[1] = (v >> 16) & 0xFF; out[2] = (v >> 8) & 0xFF; out[3] = v & 0xFF`

**注意 SHA-256 内部状态用 BE 解析,但 W[j] 累加时是 UInt 算术(模块 2^32,等同 u32 wrap-around)。**

---

## 3. HMAC 关键点

### 3.1 完整算法 (RFC 2104)

```
HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
where:
  K' = K if len(K) ≤ B else H(K)[:B]  (B = block_size = 64)
  K' = K' || 0x00...0  to length B
  opad = 0x5c repeated B times
  ipad = 0x36 repeated B times
```

### 3.2 边界 cases

- key 比 block_size 长(> 64): 先 SHA256(key),再 pad 到 64
- key 比 block_size 短(< 64): pad 0x00 到 64
- key 正好 64: 直接用
- msg 任意长度

### 3.3 RFC 4231 Test Case 5: 输出截断

Test 5 期望 `a3b6167473100ee06e0c796c2955552b` (16 字节 = 128 bit)。标准 HMAC-SHA256 输出 32 字节,这是显式截断到 16 字节。

**架构决策:** 我们的 `hmac_sha256` 默认输出 32 字节。Test 5 截断到 16 字节由测试代码负责(取前 16 字节对比)。

---

## 4. API 设计

### 4.1 SHA-256 公开 API

```moonbit
// src/sha256/api.mbt
pub fn sha256(message : FixedArray[Byte]) -> FixedArray[Byte]  // 32 字节
```

### 4.2 HMAC-SHA256 公开 API

```moonbit
// src/hmac/api.mbt
pub fn hmac_sha256(key : FixedArray[Byte], message : FixedArray[Byte]) -> FixedArray[Byte]  // 32 字节
```

**简化决策:** 一次性 API(类似 Loop #1 chacha20_block、Loop #2 poly1305_auth),不暴露 streaming init/update/final。后续 SSH 集成如需 streaming 可加 `hmac_sha256_init/update/final` 三段式。

---

## 5. 测试策略

### 5.1 SHA-256 KAT (sha256_wbtest.mbt)

- FIPS 180-4 Appendix B.1 Test 1: "abc"
- FIPS 180-4 Appendix B.1 Test 2: 1,000,000 × "a"
- FIPS 180-4 Appendix B.1 Test 3: 56 字节 "abcdbcde..."

### 5.2 SHA-256 Blackbox (sha256_test.mbt)

- 空消息
- 1 字节
- 63 字节(刚好 block_size - 1)
- 64 字节(刚好 block_size)
- 65 字节(block_size + 1,触发 2 块 + padding)
- 119 字节(block_size * 2 - 1,需要 2 块 + padding)
- 128 字节(刚好 2 块)

### 5.3 HMAC KAT (hmac_wbtest.mbt)

- RFC 4231 § 4 Test 1-7(7 vectors,涵盖 key<blocksize, key>blocksize, truncation, long msg)

### 5.4 HMAC Blackbox (hmac_test.mbt)

- 同一 key + msg 多次调用 → 同一 tag(deterministic)
- 不同 key → 不同 tag
- 空 msg
- key 为空字节(全部 0x00)
- key 0x5c 字节

---

## 6. C Verification Harness

`verify_c/sha256_harness.c` 跑 OpenBSD `sha2.c`:
- 编译 OpenBSD `openbsd-compat/sha2.c`
- 跑 FIPS 180-4 Test 1, 2 (skip 1M-'a' 太慢), 3
- 输出 hex,Python 独立参考对比

`verify_c/hmac_harness.c` 跑 OpenBSD `hmac.c` + `sha2.c`:
- 跑 RFC 4231 Test 1-7
- Python 独立对比

**编译命令:** 同 verify_c/chacha 和 verify_c/poly1305 模式。

---

**签字:** 🏛️ Architect — 2026-07-24
