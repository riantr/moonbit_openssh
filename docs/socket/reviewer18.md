# Loop #18 Reviewer — SSH Wire Framing + Client Flow 评审

**Date**: 2026-09-23
**Status**: Reviewer PASS — 4 target × 2 mode byte-exact 闭环
**Verdict**: SSH wire framing + mock client flow 字节级一致

## 1. 测试结果

### 8 outputs byte-exact (verify.mjs)

```
Per-target SHA-256 (16 chars):
  native-debug         c9d33d0f2cd2f92c
  native-release       c9d33d0f2cd2f92c
  js-debug             c9d33d0f2cd2f92c
  js-release           c9d33d0f2cd2f92c
  wasm-debug           c9d33d0f2cd2f92c
  wasm-release         c9d33d0f2cd2f92c
  wasm-gc-debug        c9d33d0f2cd2f92c
  wasm-gc-release      c9d33d0f2cd2f92c

✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致
```

### 浏览器等价测试 (browser_test.mjs)

```
✓ PASS: browser-equivalent test output matches expected byte-exact
  SHA-256: 576543884a872198
  Length: 474 bytes
```

## 2. SSH Wire Framing 实现评审

#### 2.1 SshBuf (字节流累积器)
```moonbit
pub struct SshBuf {
  recv_buffer : FixedArray[Byte]
  mut recv_pos : Int
}
```
- `feed(bytes)` 累积新字节到 buffer
- `try_parse()` 按 RFC 4253 §6 packet format 解析 (4-byte length + 1-byte padding + payload + padding)
- `compact()` 跳过已解析字节,节省内存

**实现细节**:
- packet_length 用 `(buf[pos].to_uint() << 24) | ...` 大端 u32 拼接
- padding_length 校验 `>= 4`
- payload_len = packet_length - padding_length - 1,validate `>= 0`
- 解析后 pos 前进 4 + packet_length 字节 (MAC 留 NEWKEYS 阶段处理)

#### 2.2 make_packet (RFC 4253 §6 构造)
```moonbit
pub fn make_packet(msg_type : Byte, payload : FixedArray[Byte]) -> FixedArray[Byte]
```
- payload_full = msg_type || payload
- padding_length = block_size(8) - (payload_full.length() + 5) % block_size, if < 4: + block_size
- packet_length = payload_full.length() + padding_length + 1
- 输出: u32(packet_length) || u8(padding_length) || payload_full || padding(0...)

**Loop #18 padding 是 0 字节** (deterministic for byte-exact 验证),Loop #19+ 改 random padding。

#### 2.3 SSH string / u32 / u64 序列化
- `read_ssh_string(buf, offset)` → (str, new_offset)
- `write_ssh_string(s)` → u32(len) || s
- `read_u32/write_u32` 大端 u32
- `read_u64/write_u64` 大端 u64

**实现细节**: u32 用 `UInt << 24 | UInt << 16 | UInt << 8 | UInt`,u64 用 `UInt64 << 56` 循环 8 次。

### 2.4 sshclient 客户端流程

完整 client flow (mock server, byte-exact 验证):
1. **版本字符串**: 发送 `"SSH-2.0-MoonBit\r\n"` (16 bytes)
2. **KEXINIT**: 用 kexflow::kexinit_payload 构造确定性 client KEXINIT (241 bytes) + sshwire::make_packet 包成 SSH packet (256 bytes total)
3. **KEXECDH_INIT**: 直接用 started.init_msg (type 30 + string32(Q_C), 37 bytes)
4. **NEWKEYS**: 1 字节 msg_type 0x15 + 7 字节 padding
5. **SSH-USERAUTH "none"**: userauth_request payload (user "moonbit" + service "ssh-connection" + method "none")
6. **CHANNEL OPEN "session"**: sender_channel(0) + window(2MB) + max_packet(32KB)
7. **CHANNEL REQUEST exec "echo hello"**: channel(0) + "exec" + want_reply(true) + command

client_sent_len = 451 bytes (含全部 SSH packet,byte-exact)。

## 3. SSH 协议包结构验证

每个 packet 都通过 roundtrip 验证 (make_packet → SshBuf.try_parse → byte-exact compare):

| Packet | msg_type | payload | roundtrip 验证 |
|---|---|---|---|
| test_packet | 0x14 | 6 bytes | ✓ msg_type + payload byte-exact 一致 |
| KEXINIT | 0x14 | 241 bytes | ✓ |
| KEXECDH_INIT | 0x1e | 32 bytes (type already in init_msg) | ✓ |
| NEWKEYS | 0x15 | 0 bytes | ✓ |
| USERAUTH_REQUEST | 0x32 | ~30 bytes | ✓ |
| CHANNEL_OPEN | 0x5a | ~25 bytes | ✓ |
| CHANNEL_REQUEST exec | 0x62 | ~14 bytes | ✓ |

## 4. 决策合规 (D1-D10)

| # | 决策 | 选定 | 合规? |
|---|---|---|---|
| D1 | Transport | WebSocket only (Loop #18 范围) | ✅ (mock 验证) |
| D2 | API 风格 | 同步 host shim (Loop #18 降级) | ✅ (mock socket 4 target 一致) |
| D3 | SSH framing | RFC 4253 §6 + RFC 4253 §11 padding | ✅ |
| D4 | 加密层 | unencrypted mode (NEWKEYS 后跳过加密) | ✅ (demo 简化) |
| D5 | USERAUTH | "none" method only | ✅ |
| D6 | Channel | session + exec command | ✅ |
| D7 | Mock server | MoonBit Socket::mock_server 预填 deterministic bytes | ✅ |
| D8 | 浏览器 demo | host/demo.html + main.wasm (Loop #19+) | 留 Loop #21+ |
| D9 | 4 target byte-exact | 强制 | ✅ (c9d33d0f2cd2f92c) |
| D10 | 真实 SSH server | 不连 | ✅ (mock only) |

## 5. 范围诚实记录

### 5.1 完成
1. ✅ SSH wire framing (RFC 4253 §6)
2. ✅ SSH string / u32 / u64 序列化 (RFC 4251 §5)
3. ✅ SSH client flow (kex + auth + channel)
4. ✅ MoonBit mock socket (累积字节 + 模拟 server 响应)
5. ✅ 4 target × 2 mode byte-exact (8/8 PASS)
6. ✅ 浏览器等价测试 PASS

### 5.2 留 Loop #19+ / Loop #21+
1. ❌ **WebSocket host shim (浏览器)** — Loop #21 (留)
2. ❌ **mock SSH server (Node.js + ws 包)** — Loop #21
3. ❌ **浏览器 demo HTML (demo_ws.html)** — Loop #21
4. ❌ **chacha20-poly1305 真实加密 (NEWKEYS 后)** — Loop #19
5. ❌ **WebTransport 双实现** — Loop #21+
6. ❌ **真实 sshd 连通** — Loop #20+

### 5.3 用户选项 vs 实际可做
| 用户选 | 实际可做 | 备注 |
|---|---|---|
| WebSocket+WT | WebSocket only (mock) | WebTransport 留 Loop #21+ |
| 同步 host + 异步 | 同步 host shim + mock | MoonBit async moon v0.10.12 不兼容 |
| 完整 client | kex + auth (none) + channel (exec) | ✓ |

## 6. 量化指标

| 指标 | 值 |
|---|---|
| MoonBit 新增包 | 3 (sshwire, socket, sshclient) |
| MoonBit 新增 LOC | ~550 行 |
| mock SSH flow 字节数 | 451 (client → mock server 完整 SSH wire) |
| 4 target × 2 mode = 8 outputs | byte-exact PASS (c9d33d0f2cd2f92c) |
| 浏览器等价测试 | PASS (576543884a872198, 474 bytes) |
| main.wasm (wasm-gc release) | 21646 bytes (Loop #17 15610 + 6036 = +39%) |
| main.wasm (wasm legacy release) | 39684 bytes (Loop #17 31485 + 8199) |
| Loop 时长 | ~2.5 hours |

## 7. 跨 Loop 经验沉淀

1. **`unused_mut` warning on Int field** — MoonBit 只能 mut Int/String,不能 mut Array/FixedArray (需要重新构造)
2. **`pkgtype(kind: "library")` not `lib`** — MoonBit v0.10.12 用 `library` 类型
3. **MoonBit async on moon v0.10.12 不兼容** — async 包内部 eprintln unbound,降级同步 host shim
4. **sshwire RFC 4253 §6 padding 简化** — Loop #18 padding 用 0,byte-exact 验证可重现;Loop #19+ 改 random
5. **sshclient mock socket** — Socket::mock_server 累积预填 bytes,简化 SSH client flow 验证无需真实 server

## 8. SSH-WASM-SSH 项目进度

| 阶段 | 状态 |
|---|---|
| 加密基础 byte-exact 跨 4 target | ✅ Loop #15/#16 |
| 浏览器跑 SSH crypto demo | ✅ Loop #17 |
| **SSH wire framing + mock client flow** | ✅ **Loop #18** |
| WebTransport 双实现 | ❌ Loop #21+ |
| WebSocket host shim + mock server + browser demo | ❌ Loop #21 |
| chacha20-poly1305 真实加密 | ❌ Loop #19 |
| 完整 SSH client → server demo | ❌ Loop #20+ |

## 9. 签字

**Loop #18 PASS — SSH wire framing + mock client flow byte-exact 闭环 ✓**

- 算法层: ✅ (RFC 4253 §6 packet roundtrip byte-exact)
- 业务层: ✅ (SSH client → mock server 完整 SSH wire 451 bytes)
- 集成层: ✅ (4 target × 2 mode = 8 outputs byte-exact)
- 浏览器层: ✅ (browser-equivalent test PASS)
- 文档: ⏳ (reviewer 已完成,reality + summary 在写)
- 关键里程碑: ✅ (SSH 客户端 SSH wire protocol byte-exact 跨 4 target)