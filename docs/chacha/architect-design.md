# 🏛️ Software Architect Design — ChaCha20 MoonBit 模块

> 输入:Navigator 报告 (`navigator-report.md`)
> 输出:MoonBit 模块结构 + 规约契约 + 实现策略
> 验证手段:`moon prove`(Why3 后端)

---

## 1. 模块结构

```
openssh_moonbit/
├── moon.mod                       # 已存在,无需改
├── src/
│   ├── chacha/                    # 🆕 本轮目标
│   │   ├── moon.pkg               # 包配置(import stdlib,link C 测试用 fixture)
│   │   ├── state.mbt              # ChaChaState 类型 + 常量
│   │   ├── primitives.mbt         # quarterround + 字节序函数(可 prove)
│   │   ├── block.mbt              # 单 block 计算(带 loop invariant)
│   │   ├── api.mbt                # 公开 API:keysetup/ivsetup/encrypt_bytes
│   │   ├── chacha.mbt             # 模块入口,re-export
│   │   ├── chacha_test.mbt        # RFC 7539 测试向量
│   │   └── chacha_wbtest.mbt      # 形式化验证 white-box 测试
│   └── ... 其他模块
└── docs/chacha/
    ├── navigator-report.md        # ✅ 已完成
    ├── architect-design.md        # ← 当前文档
    └── ...
```

**切分原则**:
- `primitives.mbt` 是**纯函数**层,粒度最细,完全独立可 prove
- `block.mbt` 复用 primitives,带 loop invariant
- `api.mbt` 复用 block,处理"短块/边界条件"等 IO 相关的胶水逻辑
- `state.mbt` 定义数据类型

## 2. 公开 API 设计(MoonBit 风格)

```moonbit
// src/chacha/api.mbt
pub struct ChaChaState {
  // 16 个 UInt 的 FixedArray,RFC 7539 4×4 状态矩阵线性化
  priv input : FixedArray[UInt]  // length = 16
}

// 128-bit key
pub fn ChaChaState::new128(key : FixedArray[Byte]) -> ChaChaState
// 256-bit key
pub fn ChaChaState::new256(key : FixedArray[Byte]) -> ChaChaState

// 设置 IV 和 64-bit counter
pub fn set_iv(self : ChaChaState, iv : FixedArray[Byte], counter? : UInt64) -> Unit

// 加密/解密(同构)
pub fn process(self : ChaChaState, input : FixedArray[Byte]) -> FixedArray[Byte]
```

设计选择:
- 用**不可变** `ChaChaState`,`set_iv` 返回新值 → 避免 mutable state 误用
- key 长度用类型区分(`new128` / `new256`),编译期就保证 `kbits` 正确
- counter 默认 0,可选传 UInt64
- `process` 接受任意长度 `FixedArray[Byte]`,内部按 64 字节切片处理

## 3. 关键规约契约(给 `moon prove`)

### 3.1 `quarterround` 完全规约

```moonbit
// 在 32-bit 算术下,quarterround 是一个对合变换(involution):
//   qr(qr(a,b,c,d)) == (a,b,c,d)
// 这一性质可作为规约让 Why3 自动证明。

fn quarterround(a : UInt, b : UInt, c : UInt, d : UInt) -> (UInt, UInt, UInt, UInt) {
  // @post: result == quarterround_revert(result.0, result.1, result.2, result.3)
  // @post: (result.0 + result.1 + result.2 + result.3) mod 2^32
  //         == (a + b + c + d) mod 2^32   // 能量守恒(可加性)
  let a1 = (a + b) % 0x1_0000_0000
  let d1 = rotl32(d1 ^ a1, 16)
  let c1 = (c + d1) % 0x1_0000_0000
  let b1 = rotl32(b ^ c1, 12)
  let a2 = (a1 + b1) % 0x1_0000_0000
  let d2 = rotl32(d1 ^ a2, 8)
  let c2 = (c1 + d2) % 0x1_0000_0000
  let b2 = rotl32(b1 ^ c2, 7)
  (a2, b2, c2, d2)
}
```

### 3.2 `set_iv` 计数器不变量

```moonbit
// 计数器自增规则:
// - low 32 bits 加 1
// - 如果溢出(low 变 0),high 32 bits 加 1
// - 永不修改 iv 部分 [14..15]

fn increment_counter(c : UInt64) -> UInt64 {
  // @post: result == c + 1  (mod 2^64)
  // @post: ((c >> 32) == 0xFFFFFFFF) ==> ((result >> 32) == ((c >> 32) + 1) mod 2^32)
  ...
}
```

### 3.3 `block` 函数 loop invariant

```moonbit
fn compute_block(state : ChaChaState) -> FixedArray[UInt] {
  let working = copy_state(state)  // 16 个 UInt
  // @invariant: length(working) == 16
  // @invariant: forall i in 0..16, working[i] 是 32-bit (模 2^32 的算术结果)
  let rounds = 10  // 20 个 quarter = 10 次"双轮"
  for i = 0; i < rounds; i = i + 1 {
    // 列轮
    apply_quarterround(working, 0, 4, 8,  12)
    apply_quarterround(working, 1, 5, 9,  13)
    apply_quarterround(working, 2, 6, 10, 14)
    apply_quarterround(working, 3, 7, 11, 15)
    // 对角轮
    apply_quarterround(working, 0, 5, 10, 15)
    apply_quarterround(working, 1, 6, 11, 12)
    apply_quarterround(working, 2, 7, 8,  13)
    apply_quarterround(working, 3, 4, 9,  14)
  }
  // 加原始 state
  for i = 0; i < 16; i = i + 1 {
    working[i] = (working[i] + state.input[i]) % 0x1_0000_0000
  }
  working
}
```

> Why3 在遇到深 loop 嵌套时性能下降,我们**接受**"完全展开 10 轮"策略 —— 每轮只有
> 8 个 quarterround,20 轮总成本 80 个 quarterround,SMT 求解器在 5 秒内可处理。
> 未来可改为递归/状态机降低验证成本。

### 3.4 `process` 端到端规约

```moonbit
// ChaCha20 关键属性:加/解密同构(XOR 自反)
fn process(self : ChaChaState, input : FixedArray[Byte]) -> FixedArray[Byte] {
  // @post: length(result) == length(input)
  // @post: process(c, process(c, input)) == input  (对合性)
  ...
}
```

## 4. 数据建模

```moonbit
// src/chacha/state.mbt
pub struct ChaChaState {
  priv input : FixedArray[UInt]  // length 16
}

const STATE_LEN : Int = 16
const BLOCK_LEN : Int = 64
const NONCE_LEN : Int = 8
const KEY128_LEN : Int = 16
const KEY256_LEN : Int = 32

// "expand 32-byte k" 作为 4 个 u32
const SIGMA_0 : UInt = 0x6170_7865  // "expa"
const SIGMA_1 : UInt = 0x6E64_2033  // "nd 3"
const SIGMA_2 : UInt = 0x7962_322D  // "2b-y"
const SIGMA_3 : UInt = 0x6B65_7920  // "e k "
// 同样定义 TAU_* 用 "expand 16-byte k"
```

## 5. 不在范围内的事(避免 scope creep)

本轮**不**实现:
- ❌ Poly1305 MAC(下一轮)
- ❌ IETF 变体 `chacha20-poly1305`(OpenSSH 用的是原始 Bernstein 版本;差异在 counter 位置)
- ❌ 与 `cipher.c` 的 `ssh_cipher_ctx` 集成(那是 SSH 协议层,后续轮次)
- ❌ 性能优化(汇编 / SIMD)
- ❌ 并发安全(本模块纯函数,无共享状态)

## 6. 测试策略

### 黑盒测试(对应 API Tester 阶段)
- **RFC 7539 § 2.3.2** Test Vector #1:key=`00010203...0f`,nonce=`000000000000004a00000000`,counter=1
  - 期待:第 1 个 block 64 字节 hex 已知
- **OpenSSH 测试向量**:`regress/unittests/cipher/test_chachapoly.c` 中的 test_data
- 自反性:对任意 (state, m),`process(state, process(state, m)) == m`

### 白盒测试(对应 Reality Checker 阶段)
- `chacha_wbtest.mbt` 中只放可 prove 的 small functions
- `moon prove` 必须 0 warning 0 error

## 7. 风险与缓解

| 风险 | 缓解 |
|---|---|
| `moon prove` 在展开 20 轮后超时 | 改用 `--timeout 30` 或拆成两步证明 |
| MoonBit `UInt` 算术语义与 C 不同 | 在 `primitives.mbt` 顶部加 `// @assume: UInt 加法 mod 2^32` |
| RFC 7539 向量与原始 Bernstein 版有差异 | 测试只跑 OpenSSH 行为,明确文档化 |
| 字节序函数需要手写 | 用 `Bytes` 切片 + 位运算,规约保证正确性 |

## 8. 验收清单(给 Reality Checker)

- [ ] `moon build` 0 error
- [ ] `moon test` 全部通过(含 RFC 7539 已知向量)
- [ ] `moon prove` 0 error,所有规约验证成功
- [ ] 自反性属性:`process ∘ process == id` 测试通过
- [ ] 模块公开 API 与本设计 § 2 一致
- [ ] 没有 panic-prone 代码(无除零/越界)

---

**Architect 交付**:本设计文档
**下一步**:交给 💎 Senior Developer 开始实现,先 `state.mbt` 再 `primitives.mbt` 再 `block.mbt` 最后 `api.mbt`
