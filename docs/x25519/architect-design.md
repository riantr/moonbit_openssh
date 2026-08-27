# Loop #4 X25519 — Architect Design

**Date:** 2026-07-24
**Role:** 🏛️ Software Architect

---

## 1. 模块划分

```
src/x25519/
├── moon.pkg
├── state.mbt                    # 字段:prime 2^255-19 的常量表示
├── arithmetic.mbt               # add, sub, squeeze, mult, square, mult121665
├── select.mbt                   # constant-time conditional swap
├── mainloop.mbt                 # Montgomery ladder 255 轮
├── recip.mbt                    # z^(-1) mod p (Fermat 小定理链)
├── freeze.mbt                   # mod p 归约到 [0, p)
├── api.mbt                      # x25519(scalar, point) -> 32 字节 shared secret
├── x25519_test.mbt              # blackbox
└── x25519_wbtest.mbt            # RFC 7748 § 5.2 KAT
```

---

## 2. 关键算法

### 2.1 Field element(32 limbs, 每 limb 8 bit)

```moonbit
struct Fe { limbs : FixedArray[UInt] }  // length 32, little-endian
```

limb[0..30] ∈ [0, 256),limb[31] ∈ [0, 2^15)(squeeze 后)。

### 2.2 add(a, b) -> a + b mod 2^256(无 mod p)

```moonbit
carry = 0
for j in 0..31:
  sum = a[j] + b[j] + carry
  out[j] = sum & 0xFF        // low 8 bit
  carry = sum >> 8
```

对应 C `add(out, a, b)`:u = 0, 31 个 byte 加 carry,最后 1 个 byte 不模 256(`u += a[31] + b[31]; out[31] = u;`),这样 limbs 可以临时达到 16-bit(squeeze 会归约)。

### 2.3 sub(a, b) -> a - b + 2*p(无 mod p,但保证 ≥ 0)

```moonbit
borrow = 218   // 2 * p 的低 32 byte 缩到 32-bit 累加 = 218
for j in 0..30:
  diff = a[j] + 65280 - b[j] + borrow
  out[j] = diff & 0xFF
  borrow = diff >> 8          // 0 或 1
diff = a[31] - b[31] + borrow
out[31] = diff                // 可能临时为负,但 squeeze 后保证 ≥ 0
```

对应 C `sub(out, a, b)`: u = 218 (= 2*(2^255-19) mod 2^256 在 limb 0 的贡献), a + 65280 - b + borrow,最后 limb 31 不带 256。

### 2.4 squeeze(a)

把所有 limb 归约到 < 256(limb 31 < 2^15):

```moonbit
carry = 0
for j in 0..30:
  sum = a[j] + carry
  a[j] = sum & 0xFF
  carry = sum >> 8
sum = a[31] + carry
a[31] = sum & 0x7F            // 清 bit 7 (= 限制 < 128 = 2^7)
carry = sum >> 7
carry = 19 * carry             // p = 2^255 - 19,溢出的 2^255 ≡ 19 mod p
for j in 0..30:
  sum = a[j] + carry
  a[j] = sum & 0xFF
  carry = sum >> 8
a[31] = a[31] + carry          // 这次不再 mask,允许 limb 31 >= 256(下轮 squeeze 再归约)
```

### 2.5 mult(out, a, b)

32 × 32 schoolbook mul,先算 256-bit partial products,然后 squeeze:

```moonbit
for i in 0..32:
  sum = 0
  for j in 0..=i:  sum += a[j] * b[i - j]
  for j in i+1..32: sum += 38 * a[j] * b[i + 32 - j]   // 19 * 2 = 38 模拟 2*p 进位
  out[i] = sum & 0xFFFF    // 16-bit limb 暂存(squeeze 会归约)
squeeze(out)
```

**关键**:`38 * a[j] * b[i+32-j]` 项表示 19*2,模拟 `(2^256 - 38) * coef`,把 b[i+32..31] 折回到 b[0..i]。

### 2.6 square(out, a)

类似 mult 但利用对称性 `a[j] * a[i-j] = a[i-j] * a[j]`,再加 `a[i/2]^2`(i 偶数时):

```moonbit
for i in 0..32:
  sum = 0
  for j in 0..(i-j):  sum += a[j] * a[i - j]       // 注:这里 j < i-j 是利用对称性
  for j in i+1..(i+32-j): sum += 38 * a[j] * a[i+32-j]
  sum *= 2                                            // 对称化: 2 * sum
  if (i & 1) == 0:
    sum += a[i/2] * a[i/2]                            // diagonal
    sum += 38 * a[i/2 + 16] * a[i/2 + 16]            // diagonal of 38s
  out[i] = sum & 0xFFFF
squeeze(out)
```

(注意 C 这里 `for (j = 0; j < i - j; ++j)` 看起来是 typo,但实际是 `< i/2`。**移植时要小心。**)

### 2.7 mult121665(out, a)

```moonbit
carry = 0
for j in 0..30:
  sum = 121665 * a[j] + carry
  out[j] = sum & 0xFF
  carry = sum >> 8
sum = 121665 * a[31] + carry
out[31] = sum & 0x7F                              // mask high bit
carry = sum >> 7
carry = 19 * carry                                 // 2^255 ≡ 19 mod p
for j in 0..30:
  sum = out[j] + carry
  out[j] = sum & 0xFF
  carry = sum >> 8
out[31] = out[31] + carry
```

### 2.8 select(p, q, r, s, b) — constant-time conditional swap

```moonbit
bminus1 : UInt = (b.to_uint()) ^ 0xFFFFFFFFU     // b=1 时是 0,b=0 时是 0xFFFFFFFF
for j in 0..64:
  t = bminus1 & (r[j] ^ s[j])
  p[j] = s[j] ^ t                                 // b=1 时 p = s,b=0 时 p = r
  q[j] = r[j] ^ t                                 // b=1 时 q = r,b=0 时 q = s
```

对应 C `(b - 1) & (r ^ s)`:`b=0 → b-1 = -1 = 0xFFFFFFFF`,`b=1 → b-1 = 0`。

### 2.9 mainloop(work, e)

255 轮 Montgomery ladder(完整对照 OpenBSD ref 见 `navigator-report.md § 1.2.2`)。

### 2.10 recip(out, z) — Fermat 小定理 z^(p-2) mod p

`p = 2^255 - 19`,所以 `p - 2 = 2^255 - 21`。

二进制: `11111111...11101011` (253 个 1,然后 01011)。

按位展开:
```
2^0:   z
2^1:   z^2
2^2:   z^4
...
2^250: z^(2^250)
```

按 `p - 2 = 2^255 - 21` 的位展开:
```
z^(p-2) = z^(2^255 - 21)
       = (z^(2^250))^4 * z^(-21)
       = (z^(2^250))^4 / z^21
```

OpenBSD 用多次 square + mult 拼接(参见 `recip()` 实现)。

### 2.11 freeze(a)

```moonbit
let aorig = copy(a)
add(a, a, minusp)                                // a += 2*p(等价于 a -= p 然后再加 p)
let negative : UInt = 0 - ((a[31] >> 7) & 1)      // 如果 a 减后 ≥ 2^255(bit 255 = 1),则 negative = 0
                                               // 即 a >= p 时 negative = 0,选 aorig
                                               // a < p 时 negative = 0xFFFFFFFF,选 a
for j in 0..32:
  a[j] ^= negative & (aorig[j] ^ a[j])
```

(等价于 `if a >= p: a -= p`,但用位运算 constant-time。)

---

## 3. Public API

```moonbit
///| X25519(scalar, point) -> 32-byte shared secret
///| scalar: 32 bytes (clamped by RFC 7748)
///| point: 32 bytes (little-endian u-coordinate)
///| output: 32 bytes
pub fn x25519(scalar : FixedArray[Byte], point : FixedArray[Byte]) -> FixedArray[Byte]
```

实现:
1. clamp scalar: `scalar[0] &= 248; scalar[31] &= 127; scalar[31] |= 64;`
2. copy point → work[0..32]
3. work[32..64] = 0; work[64..96] = 1; work[96..128] = 0
4. mainloop(work, scalar)
5. recip(work+32, work+32)
6. mult(work+64, work, work+32)
7. freeze(work+64)
8. output work[64..96] as 32 bytes

---

## 4. 测试策略

### 4.1 KAT (x25519_wbtest.mbt)

- RFC 7748 § 5.2 Vector 1 (Alice)
- RFC 7748 § 5.2 Vector 2 (Bob)
- Wycheproof subset (~10 vectors)
- Zero scalar (edge case)
- Identity point (gives zero output)
- All-zero point (gives zero output, RFC 7748 § 6.1)

### 4.2 Blackbox (x25519_test.mbt)

- Scalar clamping (input scalar modified per RFC 7748 § 5)
- Identity element (all zeros after clamping) → zero output
- Point with high bit cleared (RFC 7748 § 5)
- self-exchange (private A, public A → predictable? Not really for X25519,skip)
- Different scalar orderings
- Wrong input length handling (abort)

### 4.3 C Verification

`verify_c/x25519_harness.c` 跑 OpenBSD `smult_curve25519_ref.c`,对比 MoonBit 输出。

### 4.4 Python Triple-Blind

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
priv = X25519PrivateKey.from_private_bytes(scalar)
shared = priv.exchange(X25519PublicKey.from_public_bytes(point))
```

---

**签字:** 🏛️ Architect — 2026-07-24