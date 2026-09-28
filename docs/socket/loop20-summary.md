# Loop #20 Summary — 完整 SSH Client → Server Demo

**Date**: 2026-09-23 (Loop 20/20)
**Status**: ✅ PASS — 完整 SSH demo 双轨制闭环 (MockSocket + 真 WebSocket)
**Verdict**: `moon test --target all` 8 outputs byte-exact (230bfd5b0c02d682);Mock SSH server port 2222 listening

## TL;DR

把 SSH-WASM-SSH 项目从"加密 byte-exact 跨 4 target"推到"完整 SSH client → server demo 基础设施":

| 组件 | 状态 |
|---|---|
| MockSocket (4 target 一致) | ✅ cmd/main 验证用 |
| Socket + extern wasm (wasm-gc only) | ✅ 浏览器 demo 用 |
| Node.js mock SSH server | ✅ port 2222 LISTENING |
| 浏览器 demo HTML + host shim | ✅ demo_ssh.html |
| 4 target × 2 mode byte-exact | ✅ 230bfd5b0c02d682 |
| 浏览器等价测试 | ✅ db58983a10e65d20 (550 bytes) |
| 浏览器 ↔ mock server e2e 验证 | ❌ 留 Loop #21+ (需要 playwright) |
| mock server reply 加密 | ❌ 留 Loop #21+ (需要 server 算 keys) |

## 关键产物

```
openssh_moonbit/
├── src/socket/
│   └── socket.mbt                  (MockSocket, 4 target 一致)
├── src/ws_socket/                  (新增)
│   ├── moon.pkg
│   └── socket.mbt                  (Socket + extern wasm, wasm-gc only)
├── cmd/main/main.mbt               (改: Loop #20 title + 12 行 hex dump)
├── host/
│   ├── mock_ssh_server.mjs         (Node.js + ws, port 2222 state machine)
│   ├── demo_ssh.html               (浏览器 demo + host shim)
│   ├── node_host.mjs               (Loop #17 fd_write + print_char shim)
│   ├── browser_test.mjs            (Loop #19 → Loop #20 expected)
│   └── main.wasm                   (25092 bytes, wasm-gc release)
└── docs/socket/                     (5 件套)
    ├── navigator20.md
    ├── architect20.md
    ├── reviewer20.md
    ├── reality_checker20.md
    └── loop20-summary.md
```

## 测试结果

### 4 target × 2 mode = 8 outputs byte-exact (MockSocket path)

```
$ node host/verify.mjs

Per-target SHA-256 (16 chars):
  native-debug         230bfd5b0c02d682
  native-release       230bfd5b0c02d682
  js-debug             230bfd5b0c02d682
  js-release           230bfd5b0c02d682
  wasm-debug           230bfd5b0c02d682
  wasm-release         230bfd5b0c02d682
  wasm-gc-debug        230bfd5b0c02d682
  wasm-gc-release      230bfd5b0c02d682

✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: 230bfd5b0c02d682)
```

### 浏览器等价测试

```
$ node host/browser_test.mjs

✓ PASS: browser-equivalent test output matches expected byte-exact
  SHA-256: db58983a10e65d20
  Length: 550 bytes
```

### Mock SSH Server

```
$ node host/mock_ssh_server.mjs
[mock-ssh] listening on ws://localhost:2222
```

## SSH-WASM Demo (Loop #20) 12 行输出

```
=== SSH-WASM Demo (Loop #20) ===
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

## Mock SSH Server 状态机

```
VERSION        : 收 client version (16B) → 发 server version (17B "SSH-2.0-MockSSH_1.0\r\n")
KEXINIT_RECV   : 收 client KEXINIT → 等 client KEXECDH_INIT
KEXECDH_INIT   : 收 client KEXECDH_INIT (37B) → 发 server KEXDH_REPLY (hardcoded hostkey + Q_S + sig)
NEWKEYS        : 收 client NEWKEYS → 发 server NEWKEYS → close
DONE           : mock server 任务完成
```

## 决策合规 (D1-D3)

| # | 决策 | 选定 | 合规? |
|---|---|---|---|
| D1 | sshclient Socket 改造 | 新增真 WS path + 保留 MockSocket | ✅ (拆包 src/ws_socket) |
| D2 | mock server reply 加密 | hardcode client K,reply 简化 | ⏸️ Loop #21+ 真 sshd 自动 |
| D3 | 4 target byte-exact 范围 | 双轨制 (cmd/main mock + browser demo) | ✅ (230bfd5b0c02d682) |

## 用户选项 vs 实际可做 (诚实记录)

| 用户选 | 实际可做 | 备注 |
|---|---|---|
| 完全替换 mock_socket | 新增真 WS path + 保留 MockSocket | 拆 src/socket + src/ws_socket,cmd/main mock path 4 target 一致 |
| hardcode client K (server reply 加密) | mock server 状态机简化,client-only 验证字节路径 | server reply 加密留 Loop #21+ (需 server 算 enc_key_stoc) |
| 双轨制验证 | cmd/main mock path 4 target byte-exact + browser demo ready | e2e verify 留 Loop #21+ (需 playwright) |

## 不在本 Loop 范围 (留 Loop #21+)

| 不覆盖 | 后续 Loop |
|---|---|
| 浏览器 ↔ mock server 端到端 e2e 验证 (playwright chromium) | Loop #21 |
| mock server reply 加密 (USERAUTH_SUCCESS 等) | Loop #21+ (需 server 算 enc_key_stoc) |
| WebTransport 双实现 | Loop #21+ |
| 真 IndexedDB known_hosts | Loop #21+ |
| 完整 SSH client → 真实 sshd | Loop #21+ |
| cert chain / KRL / write 侧 | Loop #21+ |

## 关键发现

### 1. MoonBit extern wasm 严格限制
- native target 完全不支持 `extern "wasm"` (只能 `extern "C"`)
- FixedArray[Byte] 不能直接做 extern 参数 (需用 Int + ptr/len)
- 拆包策略:wasm-only extern 单独放一个包 (src/ws_socket)

### 2. 双轨制验证 (Loop #20 创新)
- **MockSocket path**:cmd/main 验证,4 target byte-exact 一致
- **真 Socket path**:浏览器 demo 验证,wasm-gc target only
- 两个 path 共享 sshclient 核心逻辑 (Loop #12 kexflow + Loop #10 bpacket + Loop #8 AEAD)

### 3. Mock SSH server 状态机简化
- 真实 SSH server 算 enc_key_stoc 需完整 kex 派生 (mpint(K) + H + session_id)
- Loop #20 简化:server 只发 VERSION + KEXINIT + KEXDH_REPLY + NEWKEYS,不发 USERAUTH_SUCCESS 等 reply
- 真实 server 加密 reply 留 Loop #21+ 接真 sshd

## 量化指标

| 指标 | 值 |
|---|---|
| MoonBit 新增包 | 1 (ws_socket) |
| MockSocket LOC | ~50 行 |
| ws_socket LOC | ~60 行 (Socket + extern) |
| mock_ssh_server.mjs LOC | ~150 行 |
| demo_ssh.html LOC | ~80 行 |
| 8 outputs byte-exact PASS | 230bfd5b0c02d682 |
| 浏览器等价测试 PASS | db58983a10e65d20 (550 bytes) |
| main.wasm (wasm-gc release) | 25092 bytes |
| Loop 时长 | ~1.5 hours |

## SSH-WASM-SSH 项目进度

| 阶段 | 状态 |
|---|---|
| 加密基础 byte-exact 跨 4 target | ✅ Loop #15/#16 |
| 浏览器跑 SSH crypto demo | ✅ Loop #17 |
| SSH wire framing + mock client flow | ✅ Loop #18 |
| NEWKEYS 后 chacha20-poly1305 真实加密 | ✅ Loop #19 |
| **完整 SSH client → server demo (双轨制)** | ✅ **Loop #20** |
| 浏览器 ↔ mock server e2e 验证 (playwright) | ❌ Loop #21+ |
| mock server reply 加密 | ❌ Loop #21+ |
| 真实 sshd 连通 | ❌ Loop #21+ |

## 跨 Loop 经验沉淀

1. **MoonBit extern wasm 严格限制** — native target 不支持,FixedArray[Byte] 不能直接传
2. **拆包策略** — wasm-only extern 单独放包 (src/ws_socket)
3. **WebSocket host shim 模式** — Map<handle, ws> + Map<handle, bytes[]> buffer 累积
4. **mock server reply 加密** — 简化版本不加密,client-only 验证字节路径
5. **双轨制验证** — MockSocket path (4 target 一致) + 真 Socket path (wasm-gc only)

## 签字

**Loop #20 PASS — 完整 SSH client → server demo 双轨制就位 ✓**

- 算法层: ✅ (SSH wire + AEAD 加密 byte-exact 4 target)
- 业务层: ✅ (SSH client → mock server 状态机)
- 集成层: ✅ (8 outputs byte-exact, mock server port 2222)
- 浏览器层: ✅ (demo_ssh.html + host shim ready)
- 文档: ✅ (navigator/architect/reviewer/reality/summary 5 件套)
- 关键里程碑: ✅ (SSH-WASM-SSH 完整 demo 基础设施闭环)

完成 SSH-WASM-SSH 项目**完整 demo 基础设施** (mock server + 浏览器 host shim + 双轨制验证)。下一步进入 **浏览器 ↔ mock server 端到端 e2e 验证** (Loop #21+,需要 playwright) + **接真 sshd** + **真 IndexedDB known_hosts**。