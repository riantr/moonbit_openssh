# 🧭 Codebase Navigator Report — chacha.c

> 任务:为 `chacha.c` 转换到 MoonBit 提供代码库探索报告
> 来源:`E:\src\moon\openssh-C\chacha.c` (195 行) + `chacha.h`
> 规范参照:RFC 7539 — ChaCha20 and Poly1305 for IETF Protocols

---

## 1. 模块定位

OpenSSH 的 `chacha.c` 实现的是 **Bernstein 原始 ChaCha20 流密码**(D.J.Bernstein, 2008 合并版本,
"chacha-merged.c version 20080118")。在 SSH 协议栈中由 `cipher.c` 调度,用于
`chacha20-poly1305@openssh.com` AEAD 套件,这是 OpenSSH 6.5+ 流量加密的主力。

**关键事实**:OpenSSH 这份代码是 IETF 之前的"原始版",不是 IETF 后续的 RFC 7539
"通用计数器位布局"(counter 在 state[12] 而非 state[16])。我们在 MoonBit 端**应同时支持两个变体**,
但本轮先实现 OpenSSH 变体(`chacha_keysetup` 行为),后续可在 `chacha_ietf` 命名空间下补 RFC 7539。

---

## 2. 公开 API 清单

源文件只导出 3 个函数(无内部 helper 暴露):

| # | C 函数 | 作用 | 输入 | 输出 / 副作用 |
|---|---|---|---|---|
| F1 | `chacha_keysetup(ctx, k, kbits)` | 初始化 key,选 constants | `k`: 16/32 字节,`kbits`: 128 / 256 | 写 `ctx->input[0..11]` |
| F2 | `chacha_ivsetup(ctx, iv, counter)` | 装载 IV 和计数器 | `iv`: 8 字节,`counter`: 可选 8 字节 | 写 `ctx->input[12..15]` |
| F3 | `chacha_encrypt_bytes(ctx, m, c, bytes)` | 流密码加/解密(same op) | 任意长度字节流 | 写 `c`,自增计数器 |

内部状态结构:

```c
struct chacha_ctx { u_int input[16]; }   // 64 字节工作区
```

## 3. 核心算法构成(QUARTERROUND)

ChaCha20 的核心是 20 轮(2 轮/迭代 × 10 次"双轮")的 4×4 状态矩阵,每轮包含
**8 个并列的 quarterround**:

```c
QUARTERROUND(a,b,c,d):
  a += b; d ^= a; d <<<= 16
  c += d; b ^= c; b <<<= 12
  a += b; d ^= a; d <<<=  8
  c += d; b ^= c; b <<<=  7
```

每轮 16 个 32-bit 字参与运算,可证明是**对合的(同一操作可逆,且加密=解密)**,这是流密码 XOR 模式的关键属性。

## 4. 关键不变量(供 Architect 设计规约用)

### I1 — 常量选择
`kbits == 256` → 使用 `sigma = "expand 32-byte k"`(16 字节 key + 16 字节 key,共 32 字节 key material)
`kbits == 128` → 使用 `tau = "expand 16-byte k"`(16 字节 key 重复使用)

### I2 — 状态矩阵布局
`input[0..3]` = constants (4×u32)
`input[4..11]` = key (8×u32,256-bit 模式,128-bit 模式时 key 重复填充)
`input[12..13]` = counter low / high (u32,小端)
`input[14..15]` = iv (2×u32,小端)

### I3 — 计数器自增规则
每次 64 字节块加密后:
- `input[12] += 1`
- 如果溢出,`input[13] += 1`
- **不**继续向 `input[14..15]` 传播(2^70 bytes 边界由用户保证)

### I4 — 加/解密对称性
**F3 是同构的**:把密文当输入会得到原文(XOR 自反)。所以 MoonBit 实现不需要单独的 `decrypt` 函数,
`encrypt_bytes(decrypt_input, output, len)` 即为解密。

### I5 — 长度边界
- `F1.key`: `kbits ∈ {128, 256}`(其他值未定义)
- `F2.iv`: 严格 8 字节
- `F2.counter`: NULL 或 8 字节
- `F3.bytes`: 任意(包括 0,空输入直接返回)
- `F3.bytes < 64`: 内部拷贝到栈缓冲 64 字节,加完后只回写 `bytes` 字节(避免越界写)

## 5. 可形式化验证的子集分析

| 子集 | moon prove 可行性 | 难度 | 备注 |
|---|---|---|---|
| `QUARTERROUND` 单步 | ⭐⭐⭐⭐⭐ | 低 | 32-bit 加/异或/循环移位,Why3 SMT 友好 |
| 状态矩阵填充 `keysetup` | ⭐⭐⭐⭐ | 中 | 字节序转换 `U8TO32_LITTLE` 需建模 |
| 计数器自增不变量 | ⭐⭐⭐⭐⭐ | 低 | 简单的 u32 算术 |
| 完整 20 轮 block 函数 | ⭐⭐⭐ | 中高 | 20 次迭代展开会让 SMT 求解器卡住,**用 loop invariant 而不是展开** |
| 字节序函数 | ⭐⭐⭐⭐ | 中 | 需要数组切片与位运算建模 |

**建议**:对 `quarterround` 和 `keysetup` 写完整规约,block 函数用 loop invariant 标注关键不变量
(每轮后状态矩阵仍为 4×4 u32 形式,总能量守恒之类的可证明属性)。

## 6. 与 OpenSSH 内部的耦合

- `cipher.c` 通过 `chacha_ctx` 句柄调用,只读不修改结构
- `chacha.h` 提供 `__attribute__((__bounded__))` 编译期检查 buffer 长度 —— MoonBit 端由 Array 长度天然保证
- `poly1305.c` 配合做 AEAD,本轮不涉及

## 7. 转换风险点(给 Senior Dev 提个醒)

1. **整数溢出语义**:C 中 `u32` 加法溢出是回绕,`PLUS` 宏显式做 `& 0xFFFFFFFF`。MoonBit `UInt` 在 `+` 运算符下默认**回绕**(模 2^32),与 C 语义一致 —— 验证这一点
2. **字节序**:C 显式 `U8TO32_LITTLE`,MoonBit 标准库应该有 `FixedArray::from_bytes_le`,没有的话手写并加 prove 规约
3. **栈缓冲 64 字节**:C 用了 `u8 tmp[64]`,MoonBit 端用 `FixedArray[Byte]` 即可
4. **指针算术**:C 的 `m += 64` 在 MoonBit 里是切片偏移,语义一致但需要小心边界
5. **API 命名**:C 用 snake_case,MoonBit 习惯 snake_case 也 OK,但要避免与 `Int`/`UInt` 内置类型冲突

## 8. 一句话总结

`chacha.c` 是个**教科书级的小型纯函数算法模块**,只 3 个公开函数 + 1 个内部宏,
无副作用依赖、无文件 IO、无并发、无平台调用 —— 几乎是 moon prove 形式化验证的
**理想目标**。先做这个,把 loop 跑通,后续算法都按这个模板走。

---

**Navigator 交付**:本报告
**下一步**:交给 🏛️ Architect 设计 MoonBit 模块结构 + 规约契约
