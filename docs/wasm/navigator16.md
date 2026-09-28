# Loop #16 Navigator — Release Mode Byte-Exact 验证

**Date**: 2026-09-18
**Navigator**: 6-agent workflow 调研阶段
**Scope**: 验证 openssh_moonbit 14 Loops 加密库在 MoonBit `--release` (O3 优化) 模式下跨 4 target byte-exact 仍成立

## 为什么需要这个 Loop

### Loop #15 验证范围
- `moon test --target all` 用默认 **debug** 模式编译
- 4 target × 233 测试 = 932/932 PASS
- **但** release 优化 (-O3 / aggressive opts) 可能 reorder / constant-fold 加密关键路径

### 风险点
- **crypto 代码对重排极度敏感**:SHA-1 round function 如果 reorder,output 字节级立刻变
- **release 优化** = 编译器 dead code elimination + inlining + loop unrolling + constant propagation
- 任何破坏密码学 byte 行为的优化 = SSH-WASM-SSH 项目不可 ship release binary

### 验证方法
Moon CLI 提供 `--release` flag(已在 `moon help test` 中确认):
```
$ moon test --release --target all
[wasm]    Total tests: 233, passed: 233, failed: 0.
[wasm-gc] Total tests: 233, passed: 233, failed: 0.
[js]      Total tests: 233, passed: 233, failed: 0.
[native]  Total tests: 233, passed: 233, failed: 0.
```

## 与 Loop #15 区别

| | Loop #15 | Loop #16 |
|---|---|---|
| 编译模式 | debug | release (-O3) |
| 产物大小 | ~几 MB | 应该小很多 (inlining/optimization) |
| 运行速度 | 慢 | 应该快很多 |
| byte-exact 行为 | 已验证 | 本 Loop 验证 |

## 验证覆盖

**同 Loop #15**:
- SHA-1 FIPS 180-4 vectors
- HMAC-SHA1 RFC 2202
- chacha20 RFC 8439
- poly1305 RFC 8439
- x25519 RFC 7748
- ed25519 RFC 8032
- ssh-wire RFC 4253
- known_hosts RFC 4255 + `[host]:port` + Revoked

## 已知限制

### 1. WASM binary 优化未单独验证
`moon build --target wasm-gc --release` 已生成产物(main.wasm 362 bytes for empty main);但完整 SSH 客户端 wasm binary 大小需要 Loop #17+ 写 `cmd/main/main.mbt` 完整 SSH handshake 后才能测优化效果。

### 2. 编译时间
Release 模式编译时间通常比 debug 长 2-5x。本 Loop `moon test --release --target all` 跑通所需时间不优化,只验证结果。

## 文档产出

```
docs/wasm/navigator16.md       本文件
docs/wasm/architect16.md       release 验证策略 + KAT 维度
docs/wasm/reviewer16.md        release byte-exact 验证结果
docs/wasm/reality_checker16.md release + debug 对比
docs/wasm/loop16-summary.md    本 Loop 总报告
```