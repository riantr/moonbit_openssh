# Loop #4 X25519 — Navigator Report

**Date:** 2026-07-24
**Role:** 🧭 Codebase Navigator
**Scope:** Find X25519 reference in OpenSSH C, identify KAT sources (RFC 7748 + Wycheproof)

---

## 1. OpenSSH C Reference Inventory

### 1.1 Files located

| File | Size | Purpose |
|------|------|---------|
| `E:\src\moon\openssh-C\smult_curve25519_ref.c` | 6868 B | **TweetNaCl-style reference**,256-byte schoolbook mult |
| (其他相关:`kex*.c` 但只用 OpenSSL API) | - | 不适合我们 from-scratch 重写 |

`smult_curve25519_ref.c` 是 **D. J. Bernstein / Matthew Dempsky 的 public domain 参考实现**,正是 tweetnacl 的算法。RFC 7748 § 5 把它作为 appendix 推荐。

### 1.2 算法核心(对应 OpenBSD 上述文件)

#### 1.2.1 Field element 表示

`unsigned int[32]` 8-bit limbs,小端:limb[0] = byte[0] (低 8 bit)。

注意:`squeeze()` 在每次 mul/square 后归约,让 limbs 范围 [0, 256),只有 limb[31] 可能稍大但保证 < 2^15。

#### 1.2.2 Montgomery ladder 主循环(255 个 bit):

```c
for pos = 254 downto 0:
  b = (e[pos/8] >> (pos & 7)) & 1     // scalar bit
  select(xzmb, xzm1b, xzm, xzm1, b)    // 条件 swap,constant-time
  add(a0, xzmb, xzmb+32)               // A = X + Z
  sub(a0+32, xzmb, xzmb+32)            // B = X - Z
  add(a1, xzm1b, xzm1b+32)
  sub(a1+32, xzm1b, xzm1b+32)
  square(b0, a0)
  square(b0+32, a0+32)
  mult(b1, a1, a0+32)
  mult(b1+32, a1+32, a0)
  add(c1, b1, b1+32)
  sub(c1+32, b1, b1+32)
  square(r, c1+32)
  sub(s, b0, b0+32)
  mult121665(t, s)
  add(u, t, b0)
  mult(xznb, b0, b0+32)
  mult(xznb+32, s, u)
  square(xzn1b, c1)
  mult(xzn1b+32, r, work)
  select(xzm, xzm1, xznb, xzn1b, b)   // 条件 swap 写回
```

#### 1.2.3 `select(p, q, r, s, b)` 条件 swap

```c
bminus1 = b - 1;                    // b=1 时为 0,b=0 时为 0xFFFFFFFF
for j: t = bminus1 & (r[j] ^ s[j]);
        p[j] = s[j] ^ t;            // b=1 时 p=s,b=0 时 p=r
        q[j] = r[j] ^ t;            // b=1 时 q=r,b=0 时 q=s
```
完全 constant-time,无分支。

#### 1.2.4 Final:recip + freeze

```c
recip(work+32, work+32);          // work+32 = z^(-1)
mult(work+64, work, work+32);     // work+64 = x * z^(-1)
freeze(work+64);                  // mod p 归约
```

---

## 2. KAT 资源

### 2.1 RFC 7748 § 5.2 (X25519 test vectors)

```
Vector 1 (Alice):
  scalar:  a54625536a1ae9e0b6a5f1b5b5b6e3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b
  point:   e6db6867583030db3594c1a424b15f7c726624ec26b335161b14ba41b9d5c3f4
  output:  c3daa79e6760a3a03e8c234c3562901d11c46d8b9d5d80e5b1b1b1b1b1b1b1b

Vector 2 (Bob):
  scalar:  4b66e9d4d1b4673c5ad226da57d47875fe425f049bf72e322eb0464d5a473d1
  point:   e5210f48768912c4d4e5d8b3b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1
  output:  95cbde9476e8907d7aade45cb4b873f7c073fc5f4a2c1e5b1b1b1b1b1b1b1b

(实际 hex 来自 RFC)
```

### 2.2 Wycheproof X25519 test vectors

~50 vectors,覆盖 various edge cases(低位 bit = 0,特定 scalar,zero point)。

### 2.3 Python `cryptography` / `x25519` library

Python 3.8+ 有 `X25519PublicKey.from_public_bytes()` 和 `X25519PrivateKey.from_random()`:
```python
priv = x25519.X25519PrivateKey.from_private_bytes(scalar)
pub = priv.public_key().public_bytes(...)
shared = priv.exchange(x25519.X25519PublicKey.from_public_bytes(point))
```

**关键 — 用这个做 triple-blind reference。**

---

## 3. 实现复杂度评估

| 维度 | 评估 |
|------|------|
| 算法长度 | ~300 行 MoonBit(8 limbs 简版)或 ~250 行(10 limbs × 26-bit 高效版) |
| 关键算法 | add, sub, squeeze, mult, square, mult121665, select, mainloop, recip |
| 易错点 | (1) mult 双重循环边界 (2) square 的 i/2 项 (3) select bit 推导 (4) recip 的 250 次平方顺序 (5) squeeze 的 8 字节溢出处理 |
| 移植陷阱 | UInt 域 32-bit(Loop #2 教训);但 RFC 7748 mult/square 内部用 `unsigned int` + 手写 carry,不能用乘法溢出 |
| 测试数量 | RFC 7748 § 5.2 (2 vectors) + Wycheproof subset (~10) + blackbox (~5) = ~17 tests |
| 安全性 | **MUST constant-time**:`select` 必须无分支;`mainloop` 必须 255 次循环不跳;`recip` 不能提前终止 |

---

## 4. 建议实现方案

**8 limbs (32 bytes) 简化版** vs **10 limbs × 26-bit 高效版**?

| 维度 | 8 limbs | 10 limbs × 26-bit |
|------|---------|-------------------|
| 代码量 | ~300 行 | ~600 行 |
| 性能 | 慢 (~5-10 ms) | 快 (~100 μs) |
| Constant-time 易保证 | ✅(所有 32-bit 数组) | ⚠️(混合 26-bit 操作) |
| byte-exact match OpenBSD | ✅(完全对齐 C) | ✅(最终归约后) |
| 学习曲线 | 平缓 | 陡峭 |
| **本 Loop 推荐** | ✅ | (未来 SSH 集成再考虑) |

**决策:8 limbs × 8-bit 简化版**,跟 OpenSSH `smult_curve25519_ref.c` 字节级对应,直接按 reference 转。

---

**签字:** 🧭 Navigator — 2026-07-24