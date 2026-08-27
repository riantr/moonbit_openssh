# Loop #3 HMAC-SHA256 — Navigator Report

**Date:** 2026-07-24
**Role:** 🧭 Codebase Navigator
**Scope:** Find SHA-256 + HMAC reference implementations in OpenSSH C, identify KAT sources

---

## 1. OpenSSH C Reference Inventory

### 1.1 Files located

| File | Size | Purpose |
|------|------|---------|
| `E:\src\moon\openssh-C\hmac.c` | 5179 B | HMAC 包装 (init/update/final) |
| `E:\src\moon\openssh-C\hmac.h` | 1662 B | HMAC public API + ctx struct |
| `E:\src\moon\openssh-C\openbsd-compat\sha2.c` | 28393 B | SHA-224/256/384/512 完整实现 |
| `E:\src\moon\openssh-C\openbsd-compat\bsd-sha2.h` | 7833 B | SHA-2 ctx struct + API |

### 1.2 SHA-256 (从 sha2.c 第 207-216 行)

Initial hash value (8 × 32-bit, big-endian 序列化):
```
0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
```
(取自 sqrt(2), sqrt(3), sqrt(5), sqrt(7), sqrt(11), sqrt(13), sqrt(17), sqrt(19) 的小数部分前 32 bit)

K[64] 常量 (取自 cube root of first 64 primes, sha2.c 第 187-204 行): 64 个 u32,本文不复述。

### 1.3 SHA-256 Transform (sha2.c 第 388-517 行)

64 轮 compression:
- 前 16 轮:从 input block (BE 16-byte → 16 × u32 W[j]) 直接取
- 后 48 轮:`W[j] = sigma1(W[j-2]) + W[j-7] + sigma0(W[j-15]) + W[j-16]`
- 每轮:`T1 = h + Sigma1(e) + Ch(e,f,g) + K[j] + W[j]; T2 = Sigma0(a) + Maj(a,b,c); h=g, g=f, f=e, e=d+T1, d=c, c=b, b=a, a=T1+T2`
- 64 轮后:`state[i] += {a,b,c,d,e,f,g,h}`

辅助函数:
- `Ch(x,y,z) = (x & y) ^ (~x & z)`
- `Maj(x,y,z) = (x & y) ^ (x & z) ^ (y & z)`
- `Sigma0(x) = ROTR(2,x) ^ ROTR(13,x) ^ ROTR(22,x)`
- `Sigma1(x) = ROTR(6,x) ^ ROTR(11,x) ^ ROTR(25,x)`
- `sigma0(x) = ROTR(7,x) ^ ROTR(18,x) ^ SHR(3,x)`
- `sigma1(x) = ROTR(17,x) ^ ROTR(19,x) ^ SHR(10,x)`

### 1.4 SHA-256 Update/Final

- **Update:** 把 input 凑到 64-byte 边界,满一块就 SHA256Transform,不满就缓存到 context->buffer
- **Final:** pad 0x80 + 0x00... + 64-bit big-endian bit length,正好补满 1 或 2 个 block
- **bitcount:** SHA-256 是 64-bit 长度计数器(但 OpenBSD 把它放在 u_int64_t[2] 里做 128-bit,虽然 SHA-256 实际只用 64-bit 长度)

### 1.5 HMAC (从 hmac.c)

```c
ssh_hmac_init(ctx, key, klen):
  if klen > blocksize: key = H(key)[:blocksize]  // 长 key 先 hash
  for i in blocksize: buf[i] = key[i] ^ 0x36     // ipad
  ictx = SHA256_Init(); SHA256_Update(ictx, buf, blocksize)
  for i in blocksize: buf[i] = key[i] ^ 0x36 ^ 0x5c  // opad
  octx = SHA256_Init(); SHA256_Update(octx, buf, blocksize)
  digest = copy(ictx)

ssh_hmac_update(ctx, m, mlen):
  SHA256_Update(digest, m, mlen)

ssh_hmac_final(ctx, out, outlen):
  inner = SHA256_Final(digest, ...)
  copy_state(octx, digest)
  SHA256_Update(digest, inner, hashlen)
  SHA256_Final(digest, out, ...)
```

简化后:**HMAC-SHA256(K, M) = SHA256((K ^ opad) || SHA256((K ^ ipad) || M))**

---

## 2. KAT 资源

### 2.1 SHA-256 KAT (FIPS 180-4 Appendix B.1)

```
Test 1: "abc" → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
Test 2: 1,000,000 × "a" → cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0
Test 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" → 248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
```

### 2.2 HMAC-SHA256 KAT (RFC 4231 § 4)

| Test | Key | Data | Expected |
|------|-----|------|----------|
| 1 | `0b*20` | "Hi There" (8 B) | `b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7` |
| 2 | "Jefe" (4 B) | "what do ya want for nothing?" (28 B) | `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843` |
| 3 | `aa*20` | `dd*50` | `773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe` |
| 4 | `01..19` (25 B) | `cd*50` | `82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b` |
| 5 | `0c*20` | "Test With Truncation" (20 B) | `a3b6167473100ee06e0c796c2955552b` (128-bit trunc) |
| 6 | `aa*131` | "Test Using Larger Than Block-Size Key - Hash Key First" (54 B) | `60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54` |
| 7 | `aa*131` | "This is a test..." (152 B) | `9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2` |

### 2.3 Python `hashlib` 作为独立 reference

```python
import hashlib, hmac
hashlib.sha256(b"abc").hexdigest()
hmac.new(key, msg, hashlib.sha256).hexdigest()
```

---

## 3. Implementation 复杂度评估

| 维度 | 评估 |
|------|------|
| 算法长度 | ~400 行 MoonBit(6 modules,每个 ~50-80 行) |
| 关键算法 | 64 轮 compression + Merkle-Damgård 构造 + HMAC 包装 |
| 易错点 | (1) W[j] 循环依赖 W[j-15]/W[j-7] (2) Big-endian input parsing (3) bit length encoding (4) HMAC 长 key 先 hash |
| 移植陷阱 | UInt vs UInt64 shift(Loop #2 教训):在 SHA-256 里所有 32-bit op,**UInt 移位要保持 UInt 域截断** |
| Test 数量 | 3 SHA-256 (FIPS 180-4) + 7 HMAC (RFC 4231) + ~5 blackbox = ~15 tests |

---

## 4. 调研结论 & 建议

1. **SHA-256 移植**:从 OpenBSD `sha2.c` 第 207-216 (init) + 187-204 (K) + 388-517 (transform) 移植,严格保持 32-bit 域操作。
2. **HMAC 包装**:从 OpenBSD `hmac.c` 第 64-91 (init) + 105-120 (final) 移植,**长 key (> block_size = 64) 必须先 H(key)**。
3. **KAT 来源**:
   - SHA-256: FIPS 180-4 Appendix B.1 (3 vectors,含 1 个 1M-'a' 长测试)
   - HMAC-SHA256: RFC 4231 § 4 (7 vectors,覆盖 key < blocksize, key > blocksize, truncation, long msg)
4. **C verification harness**: 复用 `verify_c/` 模式,跑 OpenBSD 原版 sha2.c + hmac.c,对比 MoonBit 输出。

---

**签字:** 🧭 Navigator — 2026-07-24
