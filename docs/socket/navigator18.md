# Loop #18 Navigator — TCP Socket Shim for Browser

**Date**: 2026-09-23
**Status**: Navigator 调研中
**Verdict**: 浏览器 SSH 客户端要连 SSH server,必须解决"TCP byte stream"在浏览器里没有 raw socket 的问题。3 个候选方案,各有取舍。

## TL;DR

SSH 是 TCP byte stream protocol (RFC 4253 §6): `length(4) + padding_length(1) + payload(N) + padding + MAC(20|32|64)`。浏览器**没有** raw TCP socket,只能通过 HTTP-based transport:

| 方案 | 浏览器 API | 字节流特性 | 服务器部署 | 成熟度 |
|---|---|---|---|---|
| **WebSocket (RFC 6455)** | `WebSocket.send(binary)` / `onmessage` binary | message-based,binary frame 拼成 byte stream | `ws://` server + SSH-over-WS proxy | ✅ **最成熟** |
| **WebTransport (W3C)** | `WebTransport.createBidirectionalStream()` | 原生 byte stream (QUIC stream) | HTTP/3 server (Node.js 需 rustls+quiche) | ⚠️ 现代浏览器支持 ~80% |
| **WebRTC DataChannel** | `RTCDataChannel.send(binary)` | SCTP over DTLS over UDP | 需 STUN/TURN + 信令 | ❌ P2P 不适合 client-server |

**推荐**: **WebSocket binary frames** 作为 Loop #18 主线。理由:浏览器 100% 兼容、Node.js `ws` 包原生支持、有 wstunnel / ssh -J 现成 proxy、SSH-over-WS 部署简单。

## 候选方案详细分析

### 方案 1: WebSocket (推荐) ✅

#### 浏览器 API
```js
const ws = new WebSocket('ws://server:22', ['binary']);
ws.binaryType = 'arraybuffer';  // 接收 ArrayBuffer 而不是 Blob

ws.onopen = () => { /* SSH handshake starts */ };
ws.onmessage = (e) => { /* e.data is ArrayBuffer = SSH wire bytes */ };
ws.onerror = (e) => { /* reconnect logic */ };

// 发送 SSH bytes:
ws.send(new Uint8Array([0x00, 0x00, 0x01, 0x14, ...]));  // SSH_MSG_KEXINIT
```

#### SSH-over-WS server 部署
- **wstunnel**: `wstunnel server wss://0.0.0.0:443 ssh://localhost:22` (TLS 终结 + SSH 转发)
- **websocat**: `websocat -E --binary ws-listen:0.0.0.0:22 tcp:localhost:22`
- **Cloudflare**: 自带 WebSocket 路由 + origin SSH server
- **sshd + socat**: `socat TCP-LISTEN:22,fork,reuseaddr TCP:localhost:22` (但没 WS,只是普通 SSH)

#### 缺点
- WebSocket 是**消息边界**协议,SSH 是**字节流**协议
- 需要 client 端做 byte stream reassembly (1 个 SSH 包可能被切成多个 WS message,或多个 SSH 包粘在一个 WS message)
- WebSocket frame 最大 ~2 GB,但实际 server 通常限制 64 KB-1 MB
- 客户端可能需要 framing:每个 WS message 前 4 字节 = SSH packet length (类似 SSH multiplex)

#### 简化方案
**直接拿 WebSocket binary message 当 byte chunk**:
- server: 收到 SSH TCP bytes → 发 1 个 WS binary message (含完整 SSH packet)
- client: 收到 1 个 WS binary message → 解 1 个 SSH packet
- 简单 1:1 映射,适合 demo

但真实 SSH-over-WS proxy (wstunnel) 是 raw byte stream passthrough:
- server: TCP socket 上每字节都即时转 WS binary frame
- client: 需要做 SSH packet reassembly (ssh_buffer 风格)

Loop #18 demo 选简化方案。

#### 主机 (browser) 实现
```js
// demo.html
const ws = new WebSocket('ws://localhost:2222');
ws.binaryType = 'arraybuffer';
ws.onopen = () => {
  // Send SSH_MSG_KEXINIT (already byte-exact from main.mbt)
  ws.send(new Uint8Array(kexinit_payload));
};
ws.onmessage = (e) => {
  const bytes = new Uint8Array(e.data);
  // Feed SSH packet to kexflow parser
  feed_ssh_bytes(bytes);
};
```

### 方案 2: WebTransport ⚠️

#### 浏览器 API
```js
const transport = new WebTransport('https://server:4433');
await transport.ready;
const stream = await transport.createBidirectionalStream();
const writer = stream.writable.getWriter();
const reader = stream.readable.getReader();

await writer.write(new Uint8Array([0x00, 0x00, 0x01, 0x14, ...]));
const { value: bytes } = await reader.read();
```

#### 优势
- 原生 bidirectional stream,接近 raw TCP
- HTTP/3 多路复用,无 head-of-line blocking
- 0-RTT 握手
- datagrams (适合 SSH keepalive)

#### 缺点
- 服务器需要 HTTP/3 + QUIC 栈
- Node.js 没原生支持,需 `node:http3` (实验) 或 `quiche` (Rust FFI)
- 浏览器支持:Chrome 97+, Firefox 114+, Safari 17.4+ (落后 ~18 个月)
- 部署复杂,需 TLS cert + HTTP/3 配置

### 方案 3: WebRTC DataChannel ❌

#### 浏览器 API
```js
const rtc = new RTCPeerConnection();
const dc = rtc.createDataChannel('ssh', { negotiated: true, id: 0 });
// 需要 SDP offer/answer + ICE candidate 交换
```

#### 缺点
- P2P 设计,不适合 SSH 客户端-服务器
- 需 STUN/TURN 服务器(ICE)
- 握手:ICE 协商可能 100ms-数秒
- SSH-over-DataChannel 有但部署复杂

**不适合 Loop #18**。

## SSH 协议在字节流上的特殊性

### RFC 4253 §6 Packet Format
```
uint32    packet_length    // 包长(不含 MAC)
byte      padding_length   // 0-255
byte      payload[packet_length - padding_length - 1]
byte      random padding[padding_length]
byte      mac[0..mac_length]  // 20 (hmac-sha1) / 32 (hmac-sha2-256) / 64 (hmac-sha2-512)
```

- packet_length 4 字节大端
- total = 4 + packet_length + mac_length (无加密+MAC)
- 含加密+AEAD (chacha20-poly1305@openssh.com):4 + packet_length + 16 (poly1305 tag)

### 字节流解析
SSH 客户端需要 ssh_buffer 风格:
- read 4 bytes → packet_length
- read packet_length bytes → SSH 包(可能含未完成包,需缓存)

WebSocket binary message 边界对 SSH 解析的影响:
- **粘包**: 多个 SSH 包在 1 个 WS message (rare, 但 wstunnel raw passthrough 可能发生)
- **拆包**: 1 个 SSH 包被切到 2 个 WS message (raw passthrough 必然发生)
- **client 必须做 byte stream reassembly**

### Loop #18 demo 简化
- **假设 1 WS message = 1 SSH 包** (wstunnel 默认行为, 容易理解)
- **不实现粘包/拆包** (留 Loop #20+ 完整 SSH client 写)
- **验证点**: 客户端发 1 个 KEXINIT (bigger than 0) → server 回 1 个 KEXINIT (or sshd banner) → client 解析

## MoonBit 集成考虑

### 现有 MoonBit 异步基础设施
MoonBit v0.10.12:
- `@async` 包提供 `async fn` + `Promise`
- 但 MoonBit core 标准库尚未完整,有些 platform-specific 包 (fs / net / process) 是 platform-conditional
- `--target wasm` 不带 `@platform_io` (no native fs/net/process)

### Loop #18 选型
**MoonBit 端不要直接调 WebSocket**。理由:
- WebSocket API 是 platform-specific (浏览器 vs Node.js)
- MoonBit `Promise` / `async` 在 wasm 上有 wasm suspend/resume 协议
- SSH byte stream 协议需要持续 read,适合 MoonBit 提供 trait + host 实现

**MoonBit 端接口设计 (Loop #18 主线)**:
```moonbit
// src/socket/socket.mbt

///| 字节流 socket (SSH byte stream transport)
pub struct ByteStreamSocket {
  host : Host  // opaque handle, 平台特定实现
  read_buffer : FixedArray[Byte]  // 累积的待解析字节
  closed : Bool
}

///| 连接:wss://host:port,host 是 WebSocket 代理,真实 SSH server 在另一端
pub fn ByteStreamSocket::connect(host : String, port : Int) -> Promise[ByteStreamSocket] {
  // Host 实现:浏览器 new WebSocket(); Node.js new WebSocket(ws 包)
  // 返回 Promise 完成 = connected
}

///| read(n) :从 socket 读 N 字节,可能 block 直到数据到
pub fn ByteStreamSocket::read(self : ByteStreamSocket, n : Int) -> Promise[FixedArray[Byte]] {
  // Host 实现:等 onmessage 累计够 N 字节
}

///| write(bytes) :发送 N 字节到 SSH server
pub fn ByteStreamSocket::write(self : ByteStreamSocket, bytes : FixedArray[Byte]) -> Unit {
  // Host 实现:ws.send(bytes)
}

///| close :关闭 socket
pub fn ByteStreamSocket::close(self : ByteStreamSocket) -> Unit {
  // Host 实现:ws.close()
}
```

**Host shim**:
```js
// host/ws_host.js
const HOST_SOCKET_PROTO = {
  connect: (host, port) => new WebSocket(`ws://${host}:${port}`),
  send: (handle, bytes) => handle.send(bytes),
  read: (handle, n) => /* 缓存 onmessage 直到够 N 字节 */,
  close: (handle) => handle.close(),
};

// 注册到 MoonBit wasm imports
imports['moonbit_socket'] = {
  connect: (host_ptr, host_len, port) => HOST_SOCKET_PROTO.connect(...),
  send: (handle, ptr, len) => HOST_SOCKET_PROTO.send(handle, ...),
  ...
};
```

但 MoonBit wasm 当前**没有**官方 `Promise` integration with wasm suspend/resume,所以 MoonBit 端可能用同步 `read_n(n: Int) -> Result[Bytes, Timeout]` + host 内部 polling 实现。

或者更简单:**Loop #18 不引入异步抽象**,MoonBit 端用一个简单同步 `read(n) -> Bytes?` + host polling:

```moonbit
pub fn ByteStreamSocket::try_read(self : ByteStreamSocket, n : Int) -> FixedArray[Byte]? {
  // Host 实现:非阻塞,返回累积的字节或 None
}
```

这个简单同步接口对 SSH byte stream 解析足够(主循环调用 try_read 直到有 N 字节)。

## 风险评估

| 风险 | 缓解 |
|---|---|
| MoonBit wasm 异步抽象不完整 | 用同步 try_read 接口 |
| WebSocket 二进制 binary message 与 SSH byte stream 边界不一致 | Loop #18 假设 1 message = 1 SSH packet |
| 浏览器 fetch main.wasm + WebSocket 需 HTTPS / localhost | localhost HTTP/WS 即可 |
| 真实 sshd 用 raw TCP,不接 WebSocket | demo 用 wstunnel / socat 桥接 (wstunnel 是 Loop #18 后段验证) |
| sshd banner 提前到 SSH handshake 前,client 可能误读 | Loop #18 不连真实 sshd;用 Node.js mock server echo |
| WSL Linux sshd 可能没装 | Loop #18 demo 用 Node.js mock SSH server,免依赖 sshd |

## 决策点 (待用户确认)

1. **D1**: SSH transport 选 WebSocket vs WebTransport vs WebRTC?
   - 推荐: WebSocket (Loop #18 主线), WebTransport 留 Loop #21+
2. **D2**: MoonBit 端 socket 接口 同步 vs 异步?
   - 推荐: 同步 try_read (足够 SSH byte stream 解析)
3. **D3**: SSH 协议 layer on top of byte stream?
   - 推荐: Loop #18 只验证 byte stream (no SSH framing),Loop #19+ 接 SSH protocol
4. **D4**: SSH server 选?
   - 推荐: Node.js mock SSH server (echo) — 避免依赖 sshd 部署
5. **D5**: 浏览器 HTTP fetch + WS 同源策略?
   - localhost HTTP + WS 都 OK,生产需 HTTPS + WSS

## 不在本 Loop 范围 (留 Loop #19+)

1. **真实 sshd 连通测试** — Loop #19 (需要真实 sshd + wstunnel)
2. **`__moonbit_fs_unstable` shim** — Loop #19 (IndexedDB known_hosts)
3. **完整 SSH client → server handshake** — Loop #20 (需要 SSH wire protocol framing over WS)
4. **cert chain / KRL / write 侧** — Loop #21+
5. **WebTransport fallback** — Loop #21+

## Loop #18 衔接

| | Loop #17 | **Loop #18** | Loop #19+ |
|---|---|---|---|
| 焦点 | demo 浏览器跑通 | **byte stream transport** | SSH framing / fs |
| 改代码? | ✅ main.mbt + host | **✅ socket 抽象 + host shim** | ✅ |
| 验证 | 8 outputs byte-exact | **browser→WS→Node mock echo** | SSH wire framing |
| 依赖 | WebAssembly + print_char | **WebSocket + Promise** | IndexedDB |

## 量化目标

| 指标 | 值 |
|---|---|
| MoonBit socket trait | ~50 行 |
| Host shim (browser + Node.js) | ~150 行 |
| Node.js mock SSH server | ~50 行 |
| 浏览器 demo (HTML + JS) | ~100 行 |
| E2E 验证耗时 | <30 min |
| Loop 时长 | 2-3 hours |

## 待用户确认

请确认:
- D1: WebSocket (推荐) / WebTransport / 混合?
- D2: 同步 try_read (推荐) / 异步 Promise?
- D3: 只 byte stream 不 SSH framing (推荐) / 直接 SSH 协议?