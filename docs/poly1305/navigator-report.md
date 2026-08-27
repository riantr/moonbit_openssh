# 🧭 Codebase Navigator Report — poly1305.c

> 任务:为 `poly1305.c` 转换到 MoonBit 提供代码库探索报告
> 来源:`E:\src\moon\openssh-C\poly1305.c` (157 行) + `poly1305.h`
> 规范参照:RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols § 2.5

---

## 1. 模块定位

OpenSSH 的 `poly1305.c` 是 Andrew Moon 的 `poly1305-donna-unrolled.c`
(从 https://github.com/floodyberry/poly1305-donna 移植),DJB 公共域贡献,
非 IETF 变体 — 但本版本与 RFC 8439 兼容(后者统一了 Poly1305 的规范)。

在 SSH 协议栈中由 `cipher.c` 调度,作为 `chacha20-poly1305@openssh.com` AEAD 套件
的 MAC 部分。ChaCha20 加密数据,Poly1305 计算 tag。

---

## 2. 公开 API 清单

```c
void poly1305_auth(u_char out[16], const u_char *m, size_t inlen,
                   const u_char key[32]);
```

**输入**:
- `m`:任意长度的 message
- `inlen`:message 字节数(可以为 0)
- `key`:32 字节 key(前 16 字节 → clamped r,后 16 字节 → 加性 s)

**输出**:
- `out`:16 字节 authentication tag

**内部状态**:
```c
uint32_t h0..h4;  // 累加器,5 个 26-bit limb,共 130 bit
uint32_t r0..r4;  // r 拆分到 5 个 limb(经过 clamp)
uint32_t s1..s4;  // r*5,用于乘法优化
```

## 3. 核心算法(参考 RFC 8439 § 2.5)

### 3.1 整体流程

```
输入:K(32 字节), M(任意长度)
输出:T(16 字节)

1. 解析 K:
   r = clamp_le(K[0..16])     // 26-bit limb × 5
   s = K[16..32]              // 128-bit 加性 key

2. 处理 M:
   把 M 切为 16 字节 block(最后一块不足则 pad 0x01 后接 0x00)
   for each block:
     a = block as 130-bit int (高位填 0x01)
     h = (h + a) * r mod (2^130 - 5)

3. 输出:
   T = h + s  mod 2^128
```

### 3.2 Clamp (RFC 8439 § 2.5)

```c
r0 = t0 & 0x3ffffff;
r1 = t0 & 0x3ffff03;  (其中 0x3ffff03 = 0x3ffffff & ~(0x3 << 30) 即清掉 5 个特定 bit)
r2 = t1 & 0x3ffc0ff;
r3 = t2 & 0x3f03fff;
r4 = t3 & 0x00fffff;
```

> 注:此处的 AND mask 把 r 的特定位清零,保证 `r` 在 2^130 - 5 上可逆。
> 这是 Poly1305 安全性的关键:clamp 后的 r 满足某些 bit 为 0,使 r 模 2^130 - 5 不为 0。

## 4. 关键不变量(给 Architect 写规约用)

### I1 — 算术域
- 所有 limb 操作在 26-bit / 32-bit / 64-bit 之间转换
- 模 (2^130 - 5) 用 5 个 26-bit limb 表示
- 5 × 26 = 130 ✓

### I2 — Mul-Mod 展开
对于 h = (h + a) × r mod p(p = 2^130 - 5),展开为 5x5 矩阵乘 + carry 链:
```
t[k] = Σ h[i] * mul_factor[i][k]   (i, k = 0..4)
t[k] = t[k] mod 2^64 (自然溢出)
carry 链: h[k] = t[k] & 0x3ffffff; t[k+1] += t[k] >> 26
最后: h[0] += (t[4] >> 26) * 5
```

### I3 — Block 输入构造
- 完整 16 字节 block:h4 加入 `1 << 24`(在第 25 位,即第 129 位)
- 末块不足 16 字节:补 `0x01` 然后 `0x00...`,不加 `1 << 24`

### I4 — Final
- 全累加完后再做一次 mod p 归一化(确保 h < 2^130)
- 计算 h + 5(进位法处理 "g = h + 5 - 2^130" 比较)
- `b = (g4 >> 31) - 1`:如果 h >= -5 mod p = p - 5 = 2^130 - 10,选 h;否则选 g
- 这个分支逻辑用 `(h & nb) | (g & b)` 实现,**无显式 if** (constant-time)

### I5 — 输出
- `(h0 + s[0..4])` + `(h1 << 26) + s[4..8])` + ... 共 4 个 u32,LE 编码

## 5. 可形式化验证的子集分析

| 子集 | moon prove 可行性 | 难度 | 备注 |
|---|---|---|---|
| Clamp 函数 | ⭐⭐⭐⭐⭐ | 低 | 纯位运算,Why3 SMT 秒解 |
| 单 block 加法 | ⭐⭐⭐⭐ | 中 | 26-bit 算术归一化 |
| 5x5 模乘矩阵 | ⭐⭐⭐ | 中高 | 64-bit 中间结果,Why3 求解稍慢但可行 |
| Final 归一化 | ⭐⭐⭐ | 中 | constant-time 选择逻辑 |
| 端到端 MAC 验证 | 不太适合 | - | 属于黑盒测试范畴,不走 prove |

**建议**:clamp、单 block、5x5 矩阵乘三个函数加规约。整流程用 KAT 字节级对比(已有 RFC 测试向量)。

## 6. 与 OpenSSH 内部的耦合

- 独立的纯函数,无文件 IO、无全局状态
- `cipher.c` 调用 `poly1305_auth(out, data, len, poly_key)` 完成 MAC
- 没有任何平台依赖

## 7. 转换风险点

1. **5x5 矩阵展开**:C 用 5 行 `mul32x32_64` 表达式,容易看花;MoonBit 端需要清楚地表达 5 行 × 5 列 = 25 个乘法的加和
2. **u64 中间结果**:C 显式 `uint64_t`,MoonBit `UInt64` 自然支持
3. **carry chain**:C 用 `t[k+1] += t[k] >> 26;` 这种"读-改-写",MoonBit 需要 `let mut` 或 `Ref` 包装
4. **constant-time final**:OpenSSH 的 `(h & nb) | (g & b)` 是关键 — MoonBit 端必须保留,不能改成 if-else
5. **空 message**:inlen = 0 时直接走 `poly1305_donna_finish`,输出 = K[16..32]

## 8. 优势:有 RFC 标准测试向量!

**这是 Poly1305 比 ChaCha20 好的地方**:RFC 8439 § 2.5.2 直接给了 4 个测试向量,
不需要依赖 OpenSSH C 实现做交叉验证(虽然 C 实现也是参考点之一)。

主要测试向量:
- Vector #1:34 字节 message,expected tag = `d5 b3 0f 4d 11 c8 59 f1 ...`
- Vector #2:空 message,expected tag = `ae 66 0f 88 c0 9b 43 c5 ...`
- Vector #3:16 字节 message (1 block),expected tag = `49 97 07 e4 19 ...
- Vector #4:375 字节 message,expected tag = `1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91`

## 9. 一句话总结

`poly1305.c` 是一个**自包含的小型 MAC 算法**,57 行 + 100 行 mul 矩阵 + final
归一化。纯函数、无副作用。RFC 8439 标准测试向量齐全,可以直接字节级对比验证。
Clamp + 5x5 矩阵乘 + constant-time final 是三个关键点。
比 ChaCha20 简单(没有循环),但 constant-time final 容易写错。

---

**Navigator 交付**:本报告
**下一步**:交 🏛️ Architect 设计 MoonBit 模块结构 + 规约契约
