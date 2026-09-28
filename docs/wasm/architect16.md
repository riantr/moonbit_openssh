# Loop #16 Architect — Release Mode Byte-Exact 验证策略

**Date**: 2026-09-18
**Architect**: 6-agent workflow 设计阶段

## 验证目标

**核心断言**: openssh_moonbit 14 Loops 加密库在 MoonBit `--release` (O3 优化) 模式下跨 4 target 仍 byte-exact。

这是 SSH-WASM-SSH 项目**发布版本**的决定性验证:debug 验证只是开发期,release 才是 ship 给用户的版本。

## 验证方法

### 主线:`moon test --release --target all`

```
$ moon test --release --target all
[wasm]    Total tests: 233, passed: 233, failed: 0.
[wasm-gc] Total tests: 233, passed: 233, failed: 0.
[js]      Total tests: 233, passed: 233, failed: 0.
[native]  Total tests: 233, passed: 233, failed: 0.
```

每行独立跑 release 模式 233 测试。所有 abort 在不匹配时 throw → fail。

### 副线:`moon build --target X --release` 产物大小

```
$ moon build --target wasm-gc --release
$ ls _build/wasm-gc/release/build/cmd/main/main.wasm
362 bytes
```

`cmd/main/main.mbt` 是 empty main,产物仅 362 字节。完整 SSH 客户端 ship 时 `cmd/main/main.mbt` 写完整 handshake 后才能看到 release 优化效果。

## KAT 覆盖

**同 Loop #15** (release 优化必须 byte-exact 等价 debug):
- SHA-1 FIPS 180-4 vectors (T1 + 3 internal vectors)
- HMAC-SHA1 RFC 2202 (T2)
- chacha20 RFC 8439 (wbtest)
- poly1305 RFC 8439 (wbtest)
- x25519 RFC 7748 (wbtest)
- ed25519 RFC 8032 (wbtest)
- ssh-wire byte encoding (kexflow, bpacket)
- KEX flow DH + sign/verify
- chacha20-poly1305 AEAD
- known_hosts parse + `[host]:port` + Revoked

## 决策点

| # | 决策 | 选项 | 选定 |
|---|---|---|---|
| D1 | release flag | (a) `--release` (b) 自定义 O3 | **(a)** moon CLI 标准 flag |
| D2 | 验证 target | (a) 4 target (b) 只 wasm (b) 默认 native | **(a)** 4 target 与 Loop #15 一致 |
| D3 | 比较 | (a) 4 target × 233 = 932 (b) 抽样 | **(a)** 与 Loop #15 同等强度 |
| D4 | release 产物 | (a) 跑 build (b) 不跑 | **(a)** 跑 + 记录大小 |
| D5 | 失败时 debug | (a) 加 printlns (b) 单独跑 target (c) 对比 debug | **(c)** 调试时 diff debug vs release 输出 |

## 范围裁定表

| 验证项 | 在本 Loop | 留 Loop #17+ |
|---|---|---|
| `moon test --release --target all` 932/932 | ✅ | - |
| `moon build --target wasm-gc --release` 产物大小 | ✅ | - |
| release vs debug 性能对比 | ❌ | Loop #17+ |
| Browser host wrapper | ❌ | Loop #17+ |
| TCP socket shim | ❌ | Loop #18+ |
| Complete SSH demo | ❌ | Loop #20+ |

## 完成判据

- ✅ `moon test --release --target all` 输出 4 行 `Total tests: 233, passed: 233, failed: 0.`
- ✅ release 优化无 byte-level 漂移
- ✅ 4 target 都通过

## 与 Loop #15 关系

- **Loop #15**: debug 模式 byte-exact (开发期验证)
- **Loop #16**: release 模式 byte-exact (发布期验证)

两者覆盖 SSH-WASM-SSH 项目的**完整生命周期**:
- 开发者用 debug 跑测试 (Loop #15 验证)
- 用户用 release binary (Loop #16 验证)

进入实施阶段。