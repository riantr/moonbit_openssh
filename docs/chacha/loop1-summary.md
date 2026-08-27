# Loop #1 总结报告 — ChaCha20 MoonBit 实现

> **开始**:Phase 0(2026-07-23 11:00)
> **结束**:Reality Checker 签发(2026-07-23 11:50)
> **耗时**:~50 分钟
> **状态**:**成功,进入下一轮**

---

## 6 个 Agent 角色 + 产出

| # | Agent(来自 Agency-Agents) | 产出文件 | 状态 |
|---|---|---|---|
| 1 | 🧭 **Codebase Navigator** | `docs/chacha/navigator-report.md` | ✅ |
| 2 | 🏛️ **Software Architect** | `docs/chacha/architect-design.md` | ✅ |
| 3 | 💎 **Senior Developer** | `src/chacha/{state,primitives,block,api}.mbt` | ✅ |
| 4 | 👁️ **Code Reviewer** | `docs/chacha/reviewer-report.md` | ✅(P2 改进) |
| 5 | 🔌 **API Tester** | `src/chacha/chacha_test.mbt` + `chacha_wbtest.mbt` | ✅ 10/10 |
| 6 | 🔍 **Reality Checker** | `docs/chacha/reality-checker-report.md` | ✅(prove 延期) |

---

## 代码成果

```
src/chacha/
├── moon.pkg              (1 行)
├── state.mbt             (38 行) — 常量 + ChaChaState 类型
├── primitives.mbt        (70 行) — rotl32, quarterround, 字节序
├── block.mbt             (50 行) — 20 轮 chacha_block
├── api.mbt               (150 行) — new128/new256, set_iv, process
├── chacha_test.mbt       (100 行) — 黑盒测试
└── chacha_wbtest.mbt     (90 行) — KAT 字节级对比

总:~500 行 MoonBit 代码
```

---

## 测试结果

```
Total tests: 10, passed: 10, failed: 0.
```

| 类别 | 测试 | 结果 |
|---|---|---|
| 单元 | rotl32 边界值(×4) | ✅ |
| 单元 | quarterround(0,0,0,0) | ✅ |
| 集成 | 加/解密对合性 | ✅ |
| 集成 | 空输入 | ✅ |
| 集成 | 单字节 | ✅ |
| 集成 | 1 个 block(64 字节) | ✅ |
| 集成 | 多 block(128 字节) | ✅ |
| **KAT** | **TEST1:零 key/iv/counter → 与 OpenSSH 字节级一致** | **✅** |
| **KAT** | **TEST2:key=[0..31], counter=[0,0,0,0,0,0,0,1] → 字节级一致** | **✅** |
| **KAT** | **TEST3:128-bit key mode, iv=0x55×8 → 字节级一致** | **✅** |
| **KAT** | **完整 64 字节 block → 字节级一致** | **✅** |

---

## 关键发现 & 教训

### 🎯 算法正确性:通过字节级交叉验证

- 用 `E:\src\moon\openssh_moonbit\verify_c\chacha_kat.exe`(链接 OpenSSH 原版 chacha.c)
  生成参考 keystream
- MoonBit 用同一组输入(零明文)生成 keystream
- **逐字节比对,完全一致**

### 🐛 找到的关键 bug

| Bug | 根因 | 修复 |
|---|---|---|
| sigma3 错(0x206b2065 → 0x6b206574) | 我以为 "expand 32-byte k" 漏了 "te" 两字符 | state.mbt 改 sigma3/tau3 |
| Test 2/3 期望值错(keystream 当成 ciphertext) | chacha_harness 的 plaintext 非零,output 是 ciphertext;我没意识到 | 测试用零明文直接比对 keystream |

### ✅ 单元测试发现 rotl32 一度"测试不通过"实际是手算期望值错

`rotl32(0x12345678, 12)` 我以为是 `0x45678023`,手算错算;MoonBit 实际算 `0x45678123` 是对的。

---

## Loop 反馈机制(实际触发的)

```
┌─→ 💎 Senior Dev(写实现,加入 rotl32/QR/block/process 全部 4 文件)
│   ↓ 第一次过测试(自反性)
│   9/11 通过,KAT 失败
│   ↓
│   → 自行 debug:
│     1. rotl32 ✓
│     2. quarterround ✓
│     3. 跟 C chacha_round.c 对比 round 1 输出 → 0x5942f3c1 vs 0x5942f3c1 ✓
│     4. round 10 输出 0xce6e5cec vs 0xade0b876 ✗
│     5. 跟原版 OpenSSH chacha.c 字节 dump 对比 → 发现 sigma3 是 0x6b206574 不是 0x206b2065
│   修 state.mbt → 11/11 通过
│   ↓
│   → debug_apply_qr / chacha_block_debug 清理
└─→ 最终 10/10 通过(清理 debug 后)
```

实际只触发了一次循环回退(11 个测试 → 9/11 → 修 sigma3 → 11/11 → 清理 debug → 10/10)。

---

## 待办(下一轮前)

1. `moon prove` 跑通(需要装 Why3,本次失败)
2. Loop 2:Poly1305(同模板:Navigator → Architect → Dev → Reviewer → Tester → Checker)
3. Loop 3:HMAC-SHA256
4. Loop 4:X25519 KEX
5. Loop 5:SSH 协议层

---

## 交叉验证基础设施(`verify_c/`)

为后续 Loop 复用,保留 `verify_c/` 目录:

```
verify_c/
├── shim.h              BSD 类型 shim
├── includes.h          OpenSSH include stub
├── config.h            config.h stub
├── chacha.c            OpenSSH 原始 chacha.c 副本
├── chacha.h            OpenSSH 原始 chacha.h 副本
├── chacha_dump.c       dump sigma/tau 字节
├── chacha_harness.c    当前 chacha KAT 测试 driver(零明文)
├── chacha_round.c      单文件 QR macro 验证(独立)
├── chacha_round2.c     同样,test 2 state
├── chacha_debug.c      OpenSSH chacha.c 加 round-by-round 日志
└── chacha_kat.exe      当前 chacha KAT 编译产物
```

Loop 2 (Poly1305) 时,只需把 `chacha_harness.c` 改成 poly1305 驱动即可。

---

**Loop #1 完成,准备进入 Loop #2 (Poly1305)。**
