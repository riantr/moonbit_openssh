# Loop #22 Navigator — SSH client write 侧完整字节级协议闭环 + IDB roundtrip

**Date**: 2026-09-28
**Status**: Navigator 调研中 → **Verdict**: 三件大事：(1) G1 SSH client 完整 USERAUTH/CHANNEL write 字节构造 + 服务端回包字节解析 (2) G2 Mock SSH server v2 状态机能收 USERAUTH/CHANNEL packets + 回 USERAUTH_SUCCESS/CHANNEL_OPEN_CONFIRMATION/CHANNEL_DATA/EOF/EXIT_STATUS (3) G3 IDB roundtrip byte-exact 跨刷新 playwright e2e

## TL;DR

| 子目标 | 实现路径 | 状态 |
|---|---|---|
| SSH client 完整 write 侧 | src/sshclient/client.mbt 加 userauth_password + channel_open/shell + read 回包解析 | 可行 |
| Mock SSH server v2 | host/mock_ssh_server.mjs 升级 state machine v2 (state 4..7 USERAUTH/CHANNEL/DATA/EXIT) | 可行 |
| IDB roundtrip 跨刷新 | host/demo_idb.html + playwright verify_idb.mjs | 可行 (~30 min) |
| 4 target byte-exact 维持 | 新增 ssh_client_full_unencrypted 函数,不破坏 Loop #19/20 路径 | 4 target 不破 |

## A. Loop #22 范围决策

### A.1 推荐 Loop #22+ 方向（来自 Loop #21 summary）
1. WebTransport HTTP/3 server + 真 sshd 连通（最高优先级）
2. IDB 完整 roundtrip 字节验证（Loop #21 留下的 gap）
3. cert chain / KRL / write 侧
4. release 性能基准

### A.2 选定 Loop #22 主题
**SSH client 完整 write 侧字节级协议闭环** + **IDB roundtrip byte-exact 跨刷新**

理由：
- Loop #19/#20 已经做了"client 发 + server 不回包"路径；Loop #22 推到"client 发 + server 回包 + client 收"完整协议闭环
- IDB roundtrip 是 Loop #21 demo ready 但未 byte-exact 验证的 gap，关掉它
- 不依赖 Docker / WSL sshd，环境兼容性好
- WebTransport server 推迟到 Loop #23+（HTTP/3 server 复杂度高，需要 TLS + quic 栈）

### A.3 不在 Loop #22 范围（已确认）
- WebTransport HTTP/3 server（Loop #23+）
- 真 sshd 连通（Loop #24+，需要 Docker 或 WSL sshd）
- AEAD 加密层回包验证（mock server 端 chacha20-poly1305 实现大工程，Loop #25+）
- cert chain / KRL（Loop #25+）

## B. SSH client write 侧协议拆解（RFC 4252/4254）

### B.1 RFC 4252 SSH-USERAUTH
- SSH_MSG_USERAUTH_REQUEST (0x32) payload:
  - string user
  - string service ("ssh-connection")
  - string method ("none" / "password" / "publickey" / "keyboard-interactive")
  - method-specific fields:
    - password: bool + string password
    - publickey: bool + string algo + string publickey_blob [+ string signature]

### B.2 RFC 4254 SSH-CONNECT
- SSH_MSG_CHANNEL_OPEN (0x5a) payload:
  - string channel_type ("session" / "forwarded-tcpip" / "direct-tcpip" / "x11")
  - uint32 sender_channel
  - uint32 initial_window_size
  - uint32 maximum_packet_size
  - channel_type-specific data ("session": empty)

- SSH_MSG_CHANNEL_OPEN_CONFIRMATION (0x5b) reply:
  - uint32 recipient_channel (= sender_channel)
  - uint32 sender_channel (server's local channel)
  - uint32 window_size
  - uint32 packet_size

- SSH_MSG_CHANNEL_REQUEST (0x62) payload:
  - uint32 recipient_channel
  - string request_type ("exec" / "shell" / "env" / "pty-req" / "x11-req" / "subsystem")
  - bool want_reply
  - request-specific data:
    - exec: string command
    - shell: empty
    - env: string name + string value
    - pty-req: string TERM + uint32 cols + rows + width + height + string modes

- SSH_MSG_CHANNEL_SUCCESS (0x63) reply:
  - uint32 recipient_channel

- SSH_MSG_CHANNEL_DATA (0x5e) reply:
  - uint32 recipient_channel
  - string data

- SSH_MSG_CHANNEL_EOF (0x5f) / SSH_MSG_CHANNEL_CLOSE (0x60):
  - uint32 recipient_channel

- SSH_MSG_CHANNEL_REQUEST "exit-status" reply (RFC 4254 §6.10):
  - uint32 recipient_channel
  - uint32 exit_status

### B.3 SSH client 完整 write 路径（unencrypted）
1. VERSION
2. KEXINIT (server 选 curve25519-sha256 + ed25519 + chacha20-poly1305)
3. KEXECDH_INIT + KEXDH_REPLY + NEWKEYS (双向)
4. **SSH_MSG_USERAUTH_REQUEST** "none" (probe server auth methods)
5. server 回 SSH_MSG_USERAUTH_FAILURE,允许方法列表
6. **SSH_MSG_USERAUTH_REQUEST** "password" (final auth)
7. server 回 SSH_MSG_USERAUTH_SUCCESS
8. **SSH_MSG_CHANNEL_OPEN** "session"
9. server 回 SSH_MSG_CHANNEL_OPEN_CONFIRMATION
10. **SSH_MSG_CHANNEL_REQUEST** "exec" "ls"
12. server 回 SSH_MSG_CHANNEL_SUCCESS + **SSH_MSG_CHANNEL_DATA** "..." + SSH_MSG_CHANNEL_EOF + **SSH_MSG_CHANNEL_REQUEST "exit-status"** (exit_code=0) + SSH_MSG_CHANNEL_CLOSE
13. client 收完所有 bytes, 打印 stdout + exit_code

## C. Mock SSH server v2 状态机

### C.1 state machine 升级
| state | 收 | 回 | 转入 |
|---|---|---|---|
| 0 VERSION | client version (ASCII \r\n) | server version | 1 KEXINIT |
| 1 KEXINIT | client KEXINIT (cookie + algs) | server KEXINIT | 2 KEXECDH_INIT |
| 2 KEXECDH_INIT | client KEXECDH_INIT (Q_C) | server KEXDH_REPLY (K_S + Q_S + sig) | 3 NEWKEYS |
| 3 NEWKEYS | client NEWKEYS | server NEWKEYS | **4 USERAUTH_PROBE** |
| 4 USERAUTH_PROBE | SSH_MSG_USERAUTH_REQUEST "none" | SSH_MSG_USERAUTH_FAILURE (允许 password) | **5 USERAUTH_FINAL** |
| 5 USERAUTH_FINAL | SSH_MSG_USERAUTH_REQUEST "password" | SSH_MSG_USERAUTH_SUCCESS | **6 CHANNEL_OPEN** |
| 6 CHANNEL_OPEN | SSH_MSG_CHANNEL_OPEN "session" | SSH_MSG_CHANNEL_OPEN_CONFIRMATION | **7 CHANNEL_REQUEST** |
| 7 CHANNEL_REQUEST | SSH_MSG_CHANNEL_REQUEST "exec" | SSH_MSG_CHANNEL_SUCCESS + DATA + EOF + exit-status + CLOSE | 8 DONE |

### C.2 字节级解析 client packets（unencrypted path）
- 跳过 SSH wire framing (4 byte len + 1 byte padlen + N byte payload)
- 校验 msg_type 字段
- 解析 payload fields (string/u32/read 完整 RFC 4251 wire format)

### C.3 字节级构造 server reply packets
- makeSimplePacket (msgType, payload) — 已有
- USERAUTH_SUCCESS: msg=0x34 payload=empty
- USERAUTH_FAILURE: msg=0x33 payload=name-list (allowedMethods "password\0publickey") + 1 byte partial success
- CHANNEL_OPEN_CONFIRMATION: msg=0x5b payload=4+4+4+4 bytes
- CHANNEL_SUCCESS: msg=0x63 payload=4 bytes (recipient_channel)
- CHANNEL_DATA: msg=0x5e payload=4 (channel) + 4 (len) + N (data)
- CHANNEL_EOF: msg=0x5f payload=4 bytes
- CHANNEL_REQUEST "exit-status": msg=0x62 payload=4 (channel) + 4 (exit_code)
- CHANNEL_CLOSE: msg=0x60 payload=4 bytes

### C.4 简化决策
- server packets 全程 **unencrypted**（Loop #22 mock 简化 — 协议层完整但加密层留到 Loop #25+）
- client packets 全程 **unencrypted**（mock server 不解密）
- 双方都接受 NEWKEYS 但立即切换到 "unencrypted-forever" 模式

## D. IDB roundtrip byte-exact 跨刷新

### D.1 现状（Loop #21 demo_idb.html）
- IDB put + API get
- demo 在同一个页面里跑：写 → 清 cache → 重读 → 验证
- 局限：没有跨刷新验证（清 cache 后从 IDB 拉回）

### D.2 Loop #22 升级
- playwright e2e 跨两个 page context：
  - page 1: 打开 demo_idb.html → put entry A → close
  - page 2 (新 context,模拟"刷新或重启"): 打开 demo_idb.html → 读 entry A → byte-exact 比对
- 验证 IDB 持久化跨 context 真实有效

### D.3 verify_idb.mjs 流程
```js
const context1 = await browser.newContext();
const page1 = await context1.newPage();
await page1.goto(...demo_idb.html);
await page1.fill('input[name=host]', 'example.com');
await page1.fill('input[name=key]', 'AAAA...');
await page1.click('button[id=add]');
await context1.close();  // close + persist

const context2 = await browser.newContext();  // new context (新 IDB store)
const page2 = await context2.newPage();
await page2.goto(...demo_idb.html);
const v = await page2.evaluate(() => idbGet('example.com'));
assert(v === 'AAAA...');
```

### D.4 不需要 MoonBit 改动
- IDB roundtrip 是浏览器 API 的特性，与 MoonBit extern wasm 无关
- MoonBit 端 MoonBit-known_hosts/check.mbt 已用 hash 比较 byte-exact，IDB 是其下层存储

## E. 4 target × 2 mode byte-exact 维持策略

### E.1 不破现有 8 outputs hash
- 现有 cmd/main/main.mbt 输出 12 行 hex dump（hash: 230bfd5b0c02d682）
- Loop #22 不改 main.mbt 现有 12 行
- 新增 ssh_client_full_unencrypted 函数给 verify_loop22.mjs 单独跑

### E.2 新增验证脚本 verify_loop22.mjs
- 跑完整 SSH client write 侧（unencrypted）
- 打印 USERAUTH/CHANNEL/DATA/EXIT_STATUS 各 reply 字节
- 跑 IDB roundtrip 跨 context byte-exact
- 输出 byte-exact hash

### E.3 维持策略
- main.mbt 维持现有 12 行不动（保证 hash 230bfd5b0c02d682 8 outputs 不破）
- 新增 src/sshclient_full/client_full.mbt (新包) 跑 Loop #22 完整路径
- verify.mjs (4 target byte-exact) 维持

## F. 时间预算

| 任务 | 预估 |
|---|---|
| G1 SSH client full unencrypted + parse 回包 | 2-3 hours |
| G2 Mock SSH server v2 状态机 | 1-2 hours |
| G3 IDB roundtrip playwright e2e | 1 hour |
| Loop #22 5 件套文档 (navigator/architect/reviewer/reality/summary) | 1 hour |
| 总计 | 5-7 hours |

## G. 决策点（待用户确认）

### G1: 是否新增 ssh_client_full_unencrypted 函数到 cmd/main 路径？
- A: 新增到 src/sshclient/client.mbt 内（路径维持单一 client.mbt）
- B: 新建 src/sshclient_full/ 包（解耦）
- C: 新建 cmd/ssh_full/main.mbt（独立验证）

### G2: IDB roundtrip 跨 context 还是跨 page？
- A: 跨 page context（模拟真实浏览器重启）
- B: 跨 page reload（同一 context）
- C: 两层都做

### G3: 8 outputs byte-exact 维持目标
- A: 维持 230bfd5b0c02d682 hash（main.mbt 不动）
- B: 新增 Loop #22 outputs 不强制 byte-exact
- C: 新增 Loop #22 outputs 也需 byte-exact

默认选 A+A+A（最保守、最小化破现有验证）。