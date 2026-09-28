# Loop #15 Architect — 4 Target Byte-Exact 验证策略

**Date**: 2026-09-18
**Architect**: 6-agent workflow 设计阶段

## 验证目标

**核心断言**: openssh_moonbit 14 Loops 加密库在 MoonBit `--target {native, js, wasm, wasm-gc}` 4 个 target 下编译并运行,所有 233 个 KAT 测试 byte-exact 一致。

这是 SSH-WASM-SSH 项目的**决定性里程碑**:
- 通过 → 客户端加密基础能在 wasm 跑 = 浏览器 SSH 可行
- 不通过 → 需要回退到 native binding(违背 WASM 零依赖目标)

## 验证方法

### 主线:`moon test --target all`

```
$ moon test --target all
[wasm]    Total tests: 233, passed: 233, failed: 0.
[wasm-gc] Total tests: 233, passed: 233, failed: 0.
[js]      Total tests: 233, passed: 233, failed: 0.
[native]  Total tests: 233, passed: 233, failed: 0.
```

每行独立跑对应 target 的 233 测试。
- 每个测试通过 `abort("...")` 报告 mismatch
- 若输出 byte-level 不同 → abort fires → test fail
- 4 target 全部 233/233 = 所有断言在所有 target 都通过 = byte-exact 一致

### 副线:`moon test --target X` 单独跑

```
$ moon test --target native
$ moon test --target js
$ moon test --target wasm
$ moon test --target wasm-gc
```

每个目标独立。`--target all` 等价于串行跑这 4 个。单独跑用于调试(target-specific fail 时)。

## KAT 覆盖

233 测试按 Loop 分布:
- Loop #1 chacha — 11
- Loop #2 x25519 — 11
- Loop #3 ed25519 — 17
- Loop #4 hmac — 12
- Loop #5 hmac_sha512 — 11
- Loop #6 chacha — 17 (chacha wbtest + blackbox)
- Loop #7 poly1305 — 30+ (wbtest + blackbox)
- Loop #8 aead — 30+
- Loop #9 kexc25519 — 25
- Loop #10 bpacket — 30+
- Loop #11 hostkey — 21
- Loop #12 kexflow — 9
- Loop #13 knownhosts — 12
- Loop #14 knownhosts (+port +Revoked) — 5

合计 233 个。

## 4 Target 行为

| Target | Runtime | 输出 | 期望 |
|---|---|---|---|
| **native** | C compiled exe on Windows/Linux | stdout | 233/233 |
| **js** | Node.js | stdout | 233/233 |
| **wasm** | moonrun wasm32 stack reference | 需 wasm runtime | 233/233 |
| **wasm-gc** | moonrun wasm32-gc | 需 wasm runtime | 233/233 |

## 决策点

| # | 决策 | 选项 | 选定 |
|---|---|---|---|
| D1 | 验证方法 | (a) `--target all` 一次跑 (b) 单独跑 4 个 target | **(a)** 一次跑,副线单独跑用于调试 |
| D2 | 验收标准 | (a) 233/233 across 4 target (b) 100/233 + 有例外 | **(a)** 必须 byte-exact,任何 fail 视为 Loop #15 未通过 |
| D3 | 调试 vs release | (a) 仅 debug (b) 仅 release (c) 两个都跑 | **(a) debug**(`moon test` 默认 debug); release build 单独验证大小+是否能跑(可选 follow-up) |
| D4 | KAT 维度选择 | (a) 全部 233 (b) 抽样 10 个关键 | **(a)** 全部 233—— 一旦有问题立刻定位 |
| D5 | 失败时 debug | (a) 看 stderr (b) 单独跑对应 target (c) 加 printlns | **(b)** 单独跑 → 减少噪音 |
| D6 | 产出 .wasm 用于 ship | (a) `moon build` 默认 (b) 写 `cmd/main/main.mbt` entry (c) 等 Loop #17+ browser host | **(a)** 现在跑 `moon build --target wasm-gc` 看产物;**(c)** 浏览器 host 留 Loop #17+ |

## 范围裁定表

| 验证项 | 在本 Loop | 留 Loop #16+ |
|---|---|---|
| `moon test --target all` 全 4 target 233/233 | ✅ | - |
| 调试模式 byte-exact | ✅ | - |
| Release 模式 byte-exact | ❌ | Loop #16 |
| `moon build --target wasm-gc` 产物大小 | ✅ (基础) | Loop #17+ |
| 浏览器 host 包装 (`__moonbit_fs_unstable`) | ❌ | Loop #17+ |
| WebTransport / WebSocket TCP socket | ❌ | Loop #18+ |
| IndexedDB / LocalStorage fs shim | ❌ | Loop #19+ |

## 完成判据

- ✅ `moon test --target all` 输出 4 行 `Total tests: 233, passed: 233, failed: 0.`
- ✅ 各 target 独立报告,无 silent skip
- ✅ 232 + 5 个 knownhosts = 233 测试跨 target 一致
- ✅ `moon build --target wasm-gc --release` 至少产出 `_build/wasm-gc/release/build/cmd/main/main.wasm`(不要求大小优化)
- ✅ 已存 C harness + Python 三盲验证不被影响(native 仍是 ground truth)

进入实施阶段。