# Loop #15 Navigator — WASM Target Byte-Exact Verification

**Date**: 2026-09-18
**Navigator**: 6-agent workflow 调研阶段
**Scope**: 验证 openssh_moonbit SSH 客户端加密库（Loops #1-#14）能在 MoonBit `--target {wasm, wasm-gc, js, native}` 全 target 下编译并 byte-exact 通过所有 233 个 KAT 测试

## OpenSSH / MoonBit 工具链调研

### Moon 0.5 (2026-09-18) test 子命令

```
$ moon help test
  --target <TARGET>            Select output target [possible values: wasm, wasm-gc, js, native, llvm, all]
  --wasm-policy <PATH>         Pass a moonrun JSON policy file to Wasm backends
  --no-parallelize               Run the tests in a target backend sequentially
  --target-dir <TARGET_DIR>    The target directory. Defaults to `<project-root>/_build`
```

**4 个 target 选项**:
- **native** — C backend → 平台 native exe
- **wasm** — wasm32 stack reference machine (moon 自带 wasm runtime)
- **wasm-gc** — wasm32 + GC (garbage collection, 更现代)
- **js** — Node.js 后端 + 自带 fs shim(根据用户记忆 2026-09)

### 用户先前 MoonBit wasm 经验(2026-09)
- **`--target wasm` / `wasm-gc`**:编译出裸 .wasm,但要 host 实现 `__moonbit_fs_unstable` + MoonBit runtime imports 才能跑
- **`--target js`**:自带 fs shim + Node.js 兼容,与 wasm 共享源码,**字节级一致**
- **结论**: 14 Loops 的纯加密代码(无 io/net/fs 平台依赖)应该 4 个 target 都能跑

### openssh_moonbit 状态
- **14 Loops 已闭环** (chacha/poly1305/hmac/x25519/sha512/hmac_sha512/ed25519/aead/kexc25519/bpacket/hostkey/kexflow/knownhosts)
- **233 个测试**:12 个 knownhosts blackbox + 216 个已有 Loop tests
- **三盲 byte-exact 验证**:Python 42 + C 23 + MoonBit 233
- **关键约束**: 所有算法从零实现,无 native lib 绑定 → WASM 友好

## 本 Loop #15 调研目标

### 主要问题
1. 加密库能否在 MoonBit 4 target 下 byte-exact 通过 233 个 KAT 测试?
2. 哪个 target 是浏览器 SSH 客户端的最佳打包目标?
3. 是否有任何 platform-specific code 会被 wasm/wasm-gc 拒编?

### 假设
- 14 Loops 加密代码不依赖 io/net/fs → 4 target 全兼容
- `moon test --target all` 串行跑 4 个 target,每个独立报告
- 任何 byte-level 不匹配会触发 `abort()`,iteration 立刻 fail

## 本 Loop 范围

| 已调查 | 不在本 Loop |
|---|---|
| 4 target 跑通 `moon test` | Browser host 包装(几百行 `__moonbit_fs_unstable`) |
| 233 tests byte-exact 一致 | WebTransport / WebSocket TCP socket shim |
| | write 侧 / KRL / cert chain(Loop #15+ 后续) |

## KAT 维度(本 Loop 强调)

| 算法 | KAT 来源 | 通过测试 |
|---|---|---|
| SHA-1 FIPS 180-4 | V0a/V0b/V0c | T1 (2 vectors) |
| HMAC-SHA1 RFC 2202 | V0d/V0e | T2 |
| SHA-256 RFC 6234 | (Loop #4) | (sha1/checksum) |
| SHA-512 FIPS 180-4 | (Loop #5) | (sha512 wbtest) |
| HMAC-SHA512 RFC 4231 | (Loop #5) | (hmac_sha512 wbtest) |
| chacha20 RFC 8439 | (Loop #6) | chacha wbtest |
| poly1305 RFC 8439 | (Loop #7) | poly1305 wbtest |
| x25519 RFC 7748 | (Loop #2) | x25519 wbtest |
| ed25519 RFC 8032 | (Loop #3) | ed25519 wbtest |
| ssh-wire KEXINIT/REPLY | (Loop #8/9) | kexflow wbtest |
| bpacket encrypt/decrypt | (Loop #10) | bpacket wbtest |
| hostkey from_blob/verify | (Loop #11) | hostkey wbtest |
| KEX flow DH + sign | (Loop #12) | kexflow wbtest |
| known_hosts parse/match/check + `[host]:port` + Revoked | (Loop #13/14) | knownhosts T1-T17 |

**结论**: 233 测试覆盖 OpenSSH 客户端需要的全部密码学 + 协议层契约。

## 已知风险

1. **运行时**: wasm target 需要 host 提供 `printf/abort/env` 等运行时 imports;moon 自带 host 在 `moon test` 上下文内已配置
2. **调试 vs release**: 当前 `moon test` 跑 debug 模式(`--release` 会进一步优化大小/速度);byte-exact 行为应在两个模式都保持
3. **未覆盖**: Network IO (TCP), FS (PTE), DNS resolution —— 这些是 SSH 客户端 loop 之外的事,wasm 后端可能没有;不影响加密库 byte-exact 验证

## 文档产出

```
docs/wasm/navigator15.md        本文件
docs/wasm/architect15.md      4 target 字节级验证策略 + KAT 维度
docs/wasm/reviewer15.md       验证结果 + 限制 + 决策合规
docs/wasm/reality_checker15.md 三盲+四 target 字节级验证报告
docs/wasm/loop15-summary.md   本 Loop 总报告
```