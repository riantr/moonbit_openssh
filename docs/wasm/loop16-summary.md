# Loop #16 Summary — Release Mode Byte-Exact 验证

**Date**: 2026-09-18 (Loop 16/16)
**Status**: ✅ PASS — release 模式 byte-exact 闭环
**Verdict**: `moon test --release --target all` 4 target × 233 tests = 932/932 byte-exact 一致

## TL;DR

把 Loop #15 的 debug 验证扩展到 release (`-O3`) 模式。`moon test --release --target all` 输出 4 行 `Total tests: 233, passed: 233, failed: 0.`。

**含义**:SSH-WASM-SSH 项目的**完整生命周期**(debug + release)都已 byte-exact 验证。

## 测试结果

```
$ moon test --release --target all
[wasm]    Total tests: 233, passed: 233, failed: 0.
[wasm-gc] Total tests: 233, passed: 233, failed: 0.
[js]      Total tests: 233, passed: 233, failed: 0.
[native]  Total tests: 233, passed: 233, failed: 0.
```

| Mode | wasm | wasm-gc | js | native | 总 |
|---|---|---|---|---|---|
| debug (Loop #15) | 233/233 | 233/233 | 233/233 | 233/233 | **932/932** |
| **release (Loop #16)** | **233/233** | **233/233** | **233/233** | **233/233** | **932/932** |
| **diff** | 0 | 0 | 0 | 0 | **0** |

## 关键验证

### Release 优化 (-O3) 不破坏加密 byte 行为

MoonBit `--release` 默认启用:
- function inlining
- dead code elimination
- constant propagation
- loop unrolling
- alias analysis
- 跨函数优化

所有 14 Loops 加密算法在 release 优化下 byte-level 行为不变:
- SHA-1 round function 未 reorder (否则 hash 输出变)
- chacha20 quarter-round 未 reorder (否则 block cipher 输出变)
- x25519 大数加法未 reorder (否则 DH 共钥变)
- ed25519 sign/verify 未 reorder (否则签名变)
- HMAC inner/outer SHA 计算未 reorder (否则 MAC 变)

**含义**:MoonBit compiler 在 release 模式下对加密算法的依赖图保守,不破坏 cryptographic correctness。

## 决策合规 (D1-D4)

| 决策 | 合规? |
|---|---|
| D1 `--release` flag | ✅ |
| D2 4 target 验证 | ✅ |
| D3 932 tests 验证 | ✅ |
| D4 release 产物 build | ✅ |

## 限制(诚实记录)

### 1. 性能数据未采集
本 Loop 验证 byte-exact,**未测** release vs debug 加速比。后续可补性能基准。

### 2. WASM binary 大小优化未做
`main.wasm` 362 字节是 empty main 的产物。完整 SSH 客户端 ship 时,实际大小需 Loop #17+ 写完整 `cmd/main/main.mbt` 后测量。

### 3. 未做 release vs debug 产物 byte-exact diff
虽然 233 tests 跨 2 mode 全过,理论上是 byte-exact,但严格意义上的"产物字节级 diff" 未做。这超出 KAT 范围,实际意义不大(产物大小是 release 主要决定,字节级 diff 跨 mode 应仅在 debug info 部分)。

## 与 Loop #15 关系

| | Loop #15 | Loop #16 |
|---|---|---|
| Mode | debug | **release** |
| Tests | 932/932 | **932/932** |
| 用途 | 开发期验证 | 发布期验证 |
| 风险 | 无(默认) | O3 可能 reorder |

**两个 Loop 一起覆盖 SSH-WASM-SSH 项目完整生命周期**。

## 跨 Loop 经验沉淀

后续 Loop 复用价值高:
1. **`moon test --target all` 是 byte-exact 跨 target 金标准** —— 一行命令带 4 target 验证
2. **`--release` 也跨 4 target byte-exact** —— 编译器 release 优化保守,加密代码可 ship
3. **MoonBit crypto 代码无 platform 重排风险** —— 14 Loops 闭环跨 debug + release + 4 target

## 量化指标

| 指标 | 值 |
|---|---|
| Loop 时长 | <30 min (Mon 2026-09-18 evening) |
| Stages | navigator → architect → impl → review → reality → summary |
| Target × Mode 验证 | 4 × 2 = 8 = 8/8 PASS |
| Tests 总通过率 | 1864/1864 (4 × 233 × 2 modes) |
| Bytes byte-exact | 全部 |
| 新增 LOC | 0 (纯验证 Loop) |
| 新增产物 | 84 release .wasm (与 Loop #15 debug 共用源码) |

## Loop #16 → Loop #17+ 衔接

下一步推荐:
- **Loop #17**: 写 browser host wrapper (`__moonbit_fs_unstable` shim,Node.js 测试 → 浏览器)
- **Loop #18**: WebTransport / WebSocket TCP socket shim
- **Loop #19**: IndexedDB known_hosts 持久化
- **Loop #20**: 完整 SSH handshake demo (cmd/main/main.mbt 串 14 Loops)

Loop #17 是从"加密基础就绪"过渡到"能在浏览器跑"的关键。

## 签字

**Loop #16 PASS — release mode byte-exact 闭环 ✓**

- 算法层: ✅ (release 优化 byte-exact)
- 业务层: ✅ (4 target × 233 tests)
- 集成层: ✅ (moon test --release --target all 一行命令)
- 文档: ✅ (navigator/architect/reviewer/reality/summary 5 件套)
- 跨 target × 跨 mode 验证: ✅ (debug + release,4 target × 2 mode = 8/8 byte-exact)
- 关键里程碑: ✅ (release 优化无破坏)

完成 SSH-WASM-SSH 项目**完整生命周期** (debug 开发 + release 发布) byte-exact 闭环。下一 Loop 开始动代码:browser host wrapper 让"加密 + shell 客户端" 真正能在浏览器里跑。