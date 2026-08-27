# 🏛️ Software Architect Design — Poly1305 MoonBit 模块

> 输入:Navigator 报告 (`navigator-report.md`)
> 输出:MoonBit 模块结构 + 规约契约 + 实现策略
> 验证手段:由于 Why3 装不上(用户决定跳过),验证靠 KAT 字节级对比(RFC 8439 § 2.5.2)

---

## 1. 模块结构

```
openssh_moonbit/
├── moon.mod                       # 已存在
├── src/
│   ├── chacha/                    # ✅ Loop 1 完成
│   └── poly1305/                  # 🆕 本轮目标
│       ├── moon.pkg
│       ├── state.mbt               # Poly1305 状态类型 + 常量
│       ├── clamp.mbt              # clamp 256-bit key → 5 个 26-bit limb
│       ├── mul.mbt                # 5x5 矩阵乘 + carry chain(mod 2^130 - 5)
│       ├── process.mbt            # process_block + 循环
│       ├── final.mbt              # 归一化 + 加 s
│       ├── api.mbt                # 公开 API:poly1305_auth
│       ├── poly1305.mbt           # 模块入口 re-export
│       ├── poly1305_test.mbt      # 黑盒测试
│       └── poly1305_wbtest.mbt    # RFC 8439 KAT 字节级对比
```

**切分原则**:
- `clamp.mbt` 是纯位运算,易于加规约
- `mul.mbt` 是 5x5 矩阵 + 64-bit 中间结果,纯函数
- `process.mbt` 调度 block 循环(可能 1 个或多个)
- `final.mbt` 做归一化(常量时间关键)

## 2. 公开 API 设计

```moonbit
// src/poly1305/api.mbt
pub fn poly1305_auth(key : FixedArray[Byte], message : FixedArray[Byte]) -> FixedArray[Byte]
```

- 输入 key 32 字节
- 输入 message 任意长度(包含 0)
- 输出 16 字节 tag
- 错误:key 长度不对 → abort

为内部可调试,加上:
```moonbit
// src/poly1305/clamp.mbt(内部可见)
fn clamp_key(key : FixedArray[Byte]) -> (UInt, UInt, UInt, UInt, UInt)
```

## 3. 关键规约契约(文档化,Why3 环境缺失时仅作不变量记录)

### 3.1 `clamp_key`

```moonbit
fn clamp_key(key : FixedArray[Byte]) -> (UInt, UInt, UInt, UInt, UInt) {
  // @require: key.length() == 32
  // @post: r0 < 0x4000000  (26-bit)
  // @post: r1, r2, r3, r4 also < 2^26
  // @post: r0 & 0x03ffffff == ...
  ...
}
```

### 3.2 `mul_mod(h, r)` 模 2^130 - 5

```moonbit
fn mul_mod(h : FixedArray[UInt], r : FixedArray[UInt]) -> FixedArray[UInt] {
  // @post: length(result) == 5
  // @post: forall i, result[i] < 2^26
  // @post: result == (h * r) mod (2^130 - 5)  // 这一条 Why3 难自动证
  ...
}
```

### 3.3 `process_block`

```moonbit
fn process_block(h : FixedArray[UInt], block : FixedArray[UInt], r : FixedArray[UInt], is_last : Bool) -> FixedArray[UInt] {
  // 完整 block is_last=false: h = (h + (block | (1 << 24 in limb 4))) * r mod p
  // 完整 block is_last=true: 同上
  // 部分 block is_last=true: 末尾补 0x01 + 0x00
  ...
}
```

### 3.4 `poly1305_auth` 端到端

```moonbit
// @post: length(result) == 16
// @post: 与 RFC 8439 § 2.5.2 已知向量字节级一致(由 KAT 测试保证)
```

## 4. 数据建模

```moonbit
// state.mbt
const BLOCK_LEN : Int = 16
const KEY_LEN : Int = 32
const TAG_LEN : Int = 16
const LIMB_BITS : Int = 26
const LIMB_MASK : UInt = 0x3ffffffU  // 2^26 - 1
```

5 个 26-bit limb 用 `FixedArray[UInt]` 存,长度 5。所有加/乘/归一化用 UInt64 中间结果。

## 5. 算法实现策略

按 OpenBSD 代码(donna-unrolled)逐字翻译为 MoonBit:

1. **clamp**:按 OpenBSD C 代码的位运算 mask
2. **process_block**:5x5 矩阵用 UInt64 累加
3. **mul_mod**:32 个 mul + 5 行 carry chain + h0 += carry * 5
4. **final**:5 行 carry 归一化 + constant-time 选择

## 6. 不在范围内

- ❌ IETF 变体 vs 原始 DJB 变体:本版本(Andrew Moon's donna-unrolled)就是 IETF 兼容
- ❌ SIMD / 性能优化
- ❌ 多消息并行
- ❌ 与 `chacha20-poly1305@openssh.com` 组合(那是 Loop 5 的范围)

## 7. 测试策略

### 黑盒测试(`poly1305_test.mbt`)
- 单元:clamp_key 已知输出
- 单元:空 message
- 集成:对合性(`poly1305_auth(key, m) == poly1305_auth(key, m)`,即确定性)
- 边界:0 字节, 1 字节, 15 字节, 16 字节, 17 字节

### 白盒 KAT(`poly1305_wbtest.mbt`)
- **RFC 8439 § 2.5.2 Test Vector #1**:34 字节 message
- **RFC 8439 § 2.5.2 Test Vector #2**:空 message  
- **RFC 8439 § 2.5.2 Test Vector #3**:16 字节 message
- **RFC 8439 § 2.5.2 Test Vector #4**:375 字节 message(跨多 block)

## 8. 风险与缓解

| 风险 | 缓解 |
|---|---|
| 5x5 矩阵乘手写易错 | 直接对照 OpenBSD C 代码翻译;以 5x5 二维数组写,逐行注释 |
| carry chain 边界 | 单元测试覆盖归一化前后状态 |
| constant-time final 写错变 if-else | 明确用 `(h & nb) | (g & b)`,在代码注释中标"CONSTANT-TIME" |
| MoonBit 端 UInt64 加法溢出 | UInt64 默认 wrap(模 2^64),与 C 行为一致;但 5 个累加 t[k] 的总和可能超 2^64,需要再 carry |
| `Ref` 性能开销 | process 块循环用 `let mut` 局部变量,不引入 Ref |

## 9. 验收清单

- [ ] `moon build` 0 error
- [ ] `moon test` 全部通过
- [ ] RFC 8439 § 2.5.2 全部 4 个向量字节级一致
- [ ] 公开 API 与本设计 § 2 一致
- [ ] constant-time final 用位运算实现(无 if/else)
- [ ] 没有 panic-prone 代码
- [ ] 实现从零按规范重写,不直接 transpile

---

**Architect 交付**:本设计文档
**下一步**:交 💎 Senior Developer 写实现
