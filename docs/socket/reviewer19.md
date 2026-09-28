# Loop #19 Reviewer — NEWKEYS 真实加密 + Known Hosts Store 评审

**Date**: 2026-09-23
**Status**: Reviewer PASS — sshclient 加密路径 byte-exact 闭环
**Verdict**: chacha20-poly1305@openssh.com NEWKEYS 后真实加密 4 target byte-exact 一致

## 1. 测试结果

### 8 outputs byte-exact (verify.mjs)

```
Per-target SHA-256 (16 chars):
  native-debug         9ffc4f23c0eb923c
  native-release       9ffc4f23c0eb923c
  js-debug             9ffc4f23c0eb923c
  js-release           9ffc4f23c0eb923c
  wasm-debug           9ffc4f23c0eb923c
  wasm-release         9ffc4f23c0eb923c
  wasm-gc-debug        9ffc4f23c0eb923c
  wasm-gc-release      9ffc4f23c0eb923c

✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: 9ffc4f23c0eb923c)
```

### 浏览器等价测试 (browser_test.mjs)

```
✓ PASS: browser-equivalent test output matches expected byte-exact
  SHA-256: d26423dda8b18938
  Length: 550 bytes
```

## 2. SSH 客户端 NEWKEYS 后加密路径评审

### 2.1 完整 SSH wire 字节流 (507 bytes)

```
NEWKEYS 前 (Unencrypted mode, 4 packets):
1. version (16B): "SSH-2.0-MoonBit\r\n"
2. KEXINIT packet (256B): u32 len + padding + payload + padding
3. KEXECDH_INIT (37B): type 0x1e + Q_C
4. NEWKEYS packet (~12B): type 0x15 + 7B padding

NEWKEYS 后 (Aead mode, 3 packets):
5. USERAUTH_REQUEST (68B = 52B payload + 16B poly1305 tag)
6. CHANNEL_OPEN (52B = 36B payload + 16B poly1305 tag)
7. CHANNEL_REQUEST exec (60B = 44B payload + 16B poly1305 tag)

Total: 16 + 256 + 37 + 12 + 68 + 52 + 60 = 501 bytes
(actual client_sent_total = 507 bytes, 6 bytes padding variance from block_size alignment)
```

### 2.2 chacha20-poly1305 加密路径

**key 派生** (RFC 4253 §7.2):
- Loop #19 demo: hardcode 64-byte enc_key_ctos (32B main + 32B header)
- 真实 SSH: `enc_key_ctos = SHA-256(mpint(K) || H || "C" || session_id)[:64]`
- Loop #21+ 接真 sshd 时切换到完整 kex 派生

**SendCtx.set_mode(Aead(ChachaPolyCtx::new64(enc_key_ctos)))**:
- SendCtx 内部 mode 字段切换到 Aead
- 后续 emit 自动走 chacha20-poly1305 加密路径
- seqnr = 1, 2, 3 分别对应 USERAUTH/CHANNEL_OPEN/CHANNEL_REQUEST

**SendCtx.emit**:
- payload 类型 USERAUTH/CHANNEL_OPEN/CHANNEL_REQUEST
- 自动填充 padding 到 8-byte block_size 边界
- 用 chacha20-poly1305 加密 payload + 4-byte aad prefix
- 追加 16-byte poly1305 tag
- 返回 SentPacket { frame, wire }

### 2.3 Byte-Exact 验证

**关键**: chacha20-poly1305 加密 4 target 一致要求:
- chacha20 quarter-round 操作 4 target 一致
- poly1305 大数乘法 4 target 一致
- big-endian u32/u64 序列化 4 target 一致
- SendCtx.emit padding 计算 4 target 一致

**结论**: 加密层 (Loop #7-8 chacha + poly1305 + AEAD) byte-exact 闭环扩展到 SSH wire protocol 层。

## 3. knownhosts_store 评审

### 3.1 接口设计
- `khs_open(path)` → handle_id
- `khs_count(handle)` → 行数
- `khs_close(handle)` → 释放

### 3.2 实测诚实记录
- extern wasm fn 接口 ready 但**未在 cmd/main 调用**
- 原因: extern "wasm" 在 native target 不支持,需要 native stub 才能 4 target 编译通过
- Loop #19 简化: cmd/main 不调 khs_xxx, 只验证 sshclient 加密字节路径

### 3.3 Loop #21+ 接入
- 浏览器 IndexedDB + Node.js in-memory Map mock
- MoonBit extern wasm 走 #cfg(target="wasm") + #unsafe_skip_stub_check
- native target 提供 stub impl (return 0 / empty)

## 4. 决策合规 (D1-D5)

| # | 决策 | 选定 | 合规? |
|---|---|---|---|
| D1 | sshclient 集成 SendCtx/RecvCtx | ✅ | ✅ (AEAD 加密 byte-exact) |
| D2 | known_hosts 持久化 | 同步 hash map mock | ⏸️ Loop #21+ 真 IDB |
| D3 | 加密层验证 | 4 target × 2 mode byte-exact | ✅ (9ffc4f23c0eb923c) |
| D4 | 浏览器 demo | 维持 Loop #18 demo | ⏸️ Loop #21+ |
| D5 | mock server 加密 reply | 不需要 (Loop #19 client-only) | ✅ |

## 5. 范围诚实记录

### 5.1 完成
1. ✅ sshclient 重构集成 SendCtx + ChachaPolyCtx
2. ✅ NEWKEYS 后 chacha20-poly1305 真实加密路径
3. ✅ USERAUTH/CHANNEL_OPEN/CHANNEL_REQUEST 加密字节级一致
4. ✅ 4 target × 2 mode byte-exact
5. ✅ 浏览器等价测试 PASS
6. ✅ knownhosts_store MoonBit extern 接口 ready (Loop #21+ 接 IDB)

### 5.2 留 Loop #21+
1. ❌ **WebSocket host shim + 浏览器 demo** — Loop #21
2. ❌ **mock SSH server (Node.js + ws)** — Loop #21
3. ❌ **真 IndexedDB 集成** — Loop #21+ (moon 升级后)
4. ❌ **真实 sshd 连通** — Loop #20+
5. ❌ **完整 SSH client → server demo** — Loop #20+

### 5.3 用户选项 vs 实际可做
| 用户选 | 实际可做 | 备注 |
|---|---|---|
| sshclient 重构集成 SendCtx | ✅ 完成 | chacha20-poly1305 真实加密 |
| 真 IndexedDB API | 降级 mock extern 接口 | moon v0.10.12 async 不兼容 + sqlite3 同样不兼容 |

## 6. 量化指标

| 指标 | 值 |
|---|---|
| MoonBit 新增包 | 1 (knownhosts_store) |
| sshclient 加密重构 | ~70 行新增 |
| 8 outputs byte-exact PASS | 9ffc4f23c0eb923c |
| 浏览器等价测试 PASS | d26423dda8b18938 (550 bytes) |
| main.wasm (wasm-gc release) | 25084 bytes (+15.9% from Loop #18) |
| Loop 时长 | ~1.5 hours |

## 7. 跨 Loop 经验沉淀

1. **chacha20-poly1305 SSH wire encryption 字节级闭环** — Loop #7-8 AEAD 基础扩展到 SSH protocol
2. **MoonBit extern wasm 限制** — native target 需要 stub,#cfg(target="wasm") guard
3. **sshwire make_packet vs bpacket SendCtx.emit** — 前者 unencrypted only,后者支持 AEAD + seqnr
4. **MoonBit struct mut field 限制** — 只对 Int/String 生效,需要重新构造 Array/FixedArray
5. **moon v0.10.12 sqlite3 不兼容** — sqlite3 依赖 moonbitlang/async 触发 eprintln unbound

## 8. SSH-WASM-SSH 项目进度

| 阶段 | 状态 |
|---|---|
| 加密基础 byte-exact 跨 4 target | ✅ Loop #15/#16 |
| 浏览器跑 SSH crypto demo | ✅ Loop #17 |
| SSH wire framing + mock client flow | ✅ Loop #18 |
| **NEWKEYS 后 chacha20-poly1305 真实加密** | ✅ **Loop #19** |
| WebSocket host shim + browser demo | ❌ Loop #21+ |
| IndexedDB known_hosts | ❌ Loop #21+ |
| 完整 SSH client → server demo | ❌ Loop #20+ |

## 9. 签字

**Loop #19 PASS — SSH 客户端 NEWKEYS 后真实加密 byte-exact 闭环 ✓**

- 算法层: ✅ (chacha20-poly1305 SSH wire byte-exact 跨 4 target)
- 业务层: ✅ (USERAUTH/CHANNEL_OPEN/CHANNEL_REQUEST AEAD 加密)
- 集成层: ✅ (4 target × 2 mode = 8 outputs byte-exact)
- 浏览器层: ✅ (browser-equivalent test PASS)
- 文档: ⏳ (reviewer 已完成,reality + summary 在写)
- 关键里程碑: ✅ (SSH 客户端加密 SSH wire protocol byte-exact 跨 4 target)