# Loop #19 Summary — NEWKEYS 真实加密 + Known Hosts Mock Store

**Date**: 2026-09-23 (Loop 19/19)
**Status**: ✅ PASS — SSH 客户端 NEWKEYS 后 chacha20-poly1305 真实加密 byte-exact 跨 4 target
**Verdict**: `moon run cmd/main --target all` 输出 12 行 hex dump,8 outputs SHA-256 `9ffc4f23c0eb923c` (byte-exact)

## TL;DR

把 SSH 客户端从 Loop #18 的"unencrypted mode"扩展到 Loop #19 的"NEWKEYS 后真实加密":
1. **sshclient 重构集成 SendCtx/RecvCtx + ChachaPolyCtx** — NEWKEYS 后自动切 Aead mode
2. **chacha20-poly1305@openssh.com 真实加密** — USERAUTH/CHANNEL_OPEN/CHANNEL_REQUEST 三包加密字节级一致
3. **knownhosts_store 接口 ready** — MoonBit extern wasm 准备好,Loop #21+ 接真 IDB

**核心字节流**:client → mock server 发送 507 bytes SSH wire (16B version + 256B KEXINIT + 37B KEXECDH_INIT + 12B NEWKEYS + 68B USERAUTH_加密 + 52B CHANNEL_OPEN_加密 + 60B CHANNEL_REQUEST_加密)。

## 关键产出

```
openssh_moonbit/
├── src/sshclient/
│   └── client.mbt              (改: 重构集成 SendCtx + ChachaPolyCtx 真实加密)
├── src/knownhosts_store/        (新增)
│   ├── moon.pkg
│   └── store.mbt               (MoonBit extern wasm 接口 + 文档)
├── cmd/main/
│   ├── main.mbt                (改: 12 行 hex dump, 507 bytes sent)
│   └── moon.pkg
└── docs/socket/                 (新增 5 件套)
    ├── navigator19.md
    ├── architect19.md
    ├── reviewer19.md
    ├── reality_checker19.md
    └── loop19-summary.md
```

## 测试结果

### 4 target × 2 mode = 8 outputs byte-exact

```
$ node host/verify.mjs

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

### 浏览器等价测试

```
$ node host/browser_test.mjs

✓ PASS: browser-equivalent test output matches expected byte-exact
  SHA-256: d26423dda8b18938
  Length: 550 bytes
```

## SSH-WASM Demo (Loop #19) 12 行输出

```
=== SSH-WASM Demo (Loop #19) ===
client_pub: 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
server_pub: d13f5c5b91ae760ed147df65aebb97f5369640e47c03938f9f4c4e209c61ca02
shared_K: 7bda42e82d49a492388ef14fa2110d20d82465de9d1ca39482282f752b31590f
kexinit_len: 241
kexinit_head16: 0102030405060708090a0b0c0d0e0f10
kexdh_init_len: 37
kexdh_init: 1e000000208520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
packet_test_len: 17
userauth_wire_len: 68        # NEW: AEAD 加密
channel_open_wire_len: 52    # NEW: AEAD 加密
channel_exec_wire_len: 60    # NEW: AEAD 加密
client_sent_total: 507
```

## SSH Client 字节流 (507 bytes)

```
NEWKEYS 前 (Unencrypted mode, 4 packets):
1. version (16B): "SSH-2.0-MoonBit\r\n"
2. KEXINIT packet (256B): u32 len + padding + 241B payload + 8B padding
3. KEXECDH_INIT (37B): type 0x1e + Q_C
4. NEWKEYS packet (12B): type 0x15 + 7B padding

NEWKEYS 后 (Aead mode, 3 packets 含 16-byte poly1305 tag):
5. USERAUTH_REQUEST (68B = 52B payload + 16B tag)
6. CHANNEL_OPEN (52B = 36B payload + 16B tag)
7. CHANNEL_REQUEST exec (60B = 44B payload + 16B tag)

Total: 507 bytes
```

## 决策合规 (D1-D5)

| # | 决策 | 选定 | 合规? |
|---|---|---|---|
| D1 | sshclient 集成 SendCtx/RecvCtx | ✅ | ✅ (AEAD 加密 byte-exact) |
| D2 | known_hosts 持久化 | 同步 hash map mock | ⏸️ Loop #21+ 真 IDB |
| D3 | 加密层验证 | 4 target × 2 mode byte-exact | ✅ (9ffc4f23c0eb923c) |
| D4 | 浏览器 demo | 维持 Loop #18 demo | ⏸️ Loop #21+ |
| D5 | mock server 加密 reply | 不需要 (Loop #19 client-only) | ✅ |

## 用户选项 vs 实际可做 (诚实记录)

| 用户选 | 实际可做 | 备注 |
|---|---|---|
| sshclient 重构集成 SendCtx | ✅ 完成 | chacha20-poly1305 真实加密 |
| 真 IndexedDB API | 降级 mock extern 接口 | moon v0.10.12 async 不兼容 + sqlite3 同样不兼容 |

## 不在本 Loop 范围 (留 Loop #20+ / Loop #21+)

| 不覆盖 | 后续 Loop |
|---|---|
| WebSocket host shim (浏览器) + Node.js mock server | Loop #21 |
| 浏览器 demo (demo_ws.html) | Loop #21 |
| 真 IndexedDB / SQLite 持久化 | Loop #21+ (moon 升级后) |
| 完整 SSH client → server demo | Loop #20+ |
| 真实 sshd 连通 | Loop #20+ |
| cert chain / KRL / write 侧 | Loop #21+ |

## 关键发现

### 1. SSH wire AEAD byte-exact 闭环
chacha20-poly1305 加密 SSH protocol layer (USERAUTH/CHANNEL_OPEN/CHANNEL_REQUEST 三包) 在 4 个 MoonBit target byte-exact 一致。

### 2. MoonBit extern wasm 限制
- native target 不支持 (需要 stub 或 #cfg guard)
- String 类型不能直接传 (需要 Int ptr/len)
- async 路径不可行 (moon v0.10.12 async 不兼容)

### 3. sqlite3 moonbit-community 不可用
- 依赖 moonbitlang/async@0.21.2
- 实测触发 eprintln unbound 编译错误
- 留 Loop #21+ 等 moon 升级支持

## 量化指标

| 指标 | 值 |
|---|---|
| MoonBit 新增包 | 1 (knownhosts_store) |
| sshclient 加密重构 | ~70 行新增 |
| 8 outputs byte-exact PASS | 9ffc4f23c0eb923c |
| 浏览器等价测试 PASS | d26423dda8b18938 (550 bytes) |
| main.wasm (wasm-gc release) | 25084 bytes (+15.9% from Loop #18) |
| Loop 时长 | ~1.5 hours |

## SSH-WASM-SSH 项目进度

| 阶段 | 状态 |
|---|---|
| 加密基础 byte-exact 跨 4 target | ✅ Loop #15/#16 |
| 浏览器跑 SSH crypto demo | ✅ Loop #17 |
| SSH wire framing + mock client flow | ✅ Loop #18 |
| **NEWKEYS 后 chacha20-poly1305 真实加密** | ✅ **Loop #19** |
| WebSocket host shim + browser demo | ❌ Loop #21+ |
| IndexedDB known_hosts | ❌ Loop #21+ |
| 完整 SSH client → server demo | ❌ Loop #20+ |

## 跨 Loop 经验沉淀

1. **SSH wire AEAD byte-exact 闭环** — chacha20-poly1305 SSH protocol layer 4 target 一致
2. **MoonBit extern wasm 限制** — native target 不支持,String 类型不能直接传,async 路径不可行
3. **moon v0.10.12 sqlite3 不兼容** — 依赖 moonbitlang/async 触发 eprintln unbound
4. **sshwire make_packet vs bpacket SendCtx.emit** — 前者 unencrypted only,后者支持 AEAD + seqnr

## 签字

**Loop #19 PASS — NEWKEYS 后真实加密 byte-exact 闭环 ✓**

- 算法层: ✅ (chacha20-poly1305 SSH wire byte-exact 跨 4 target)
- 业务层: ✅ (USERAUTH/CHANNEL_OPEN/CHANNEL_REQUEST AEAD 加密)
- 集成层: ✅ (4 target × 2 mode = 8 outputs byte-exact)
- 浏览器层: ✅ (browser-equivalent test PASS)
- 文档: ✅ (navigator/architect/reviewer/reality/summary 5 件套)
- 关键里程碑: ✅ (SSH 客户端加密 SSH wire protocol byte-exact 跨 4 target)

完成 SSH-WASM-SSH 项目**加密 + SSH wire 协议层真实加密** byte-exact 闭环。下一步进入 **WebSocket host shim (Loop #21)** 让 SSH 客户端真能连 SSH server + **完整 SSH client demo (Loop #20+)**。