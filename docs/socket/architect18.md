# Loop #18 Architect v2 — 同步 Host Shim + SSH Client 实现规格

**Date**: 2026-09-23
**Status**: Architect v2 — 用户选最大范围,实测降级
**Verdict**: **MoonBit async 不兼容 moon v0.10.12** (async 包内部 eprintln unbound);降级到同步 host shim + 全局 WS handle table

## 关键发现 (诚实记录)

实测 `moon run cmd/ws_test --target native` 触发 MoonBit async 包内部编译错误:
```
.mooncakes/moonbitlang/async/src/internal/event_loop/event_loop.mbt:328:
The value identifier eprintln is unbound.
```

moon 0.1.20260904 + moonc v0.10.12 与 moonbitlang/async@0.22.2 不兼容。
async 包 `preferred_target = "native"` 设计上主要面向 native target,wasm stack switching 支持需要更新 moon 编译器。

## 用户选择 vs 实际可实现

| 用户选 | 实测结果 | 决策 |
|---|---|---|
| D1: WebSocket+WT 双实现 | WebSocket 主 (MoonBit 已有 `@websocket`),WebTransport 留 Loop #21+ (MoonBit 还没 `@webtransport` 包) | **WebSocket only** |
| D2: 同步 host + 异步包装 | moon v0.10.12 async 不兼容 | **降级: 同步 host shim (Loop #17 同款)** |
| D3: byte stream + SSH framing + 完整 client | SSH framing + 完整 client (kex + channel) over WebSocket | **保留** |

**降级范围诚实记录**: 异步包装留 Loop #21+ 等 moon 升级。当前 Loop #18 用同步 host shim。

## 实现架构 (同步 host shim)

```
┌─────────────────────────────────────────────────┐
│ Browser (Chrome)                                 │
│  ┌─────────────────────────────────────────┐    │
│  │ demo_ws.html                            │    │
│  │   ┌─────────────────────────────────┐  │    │
│  │   │ main.wasm (MoonBit compiled)     │  │    │
│  │   │ SSH Client 同步                  │  │    │
│  │   │  ├─ sshwire (packet read/write)   │  │    │
│  │   │  ├─ kex flow (Loop #12)          │  │    │
│  │   │  ├─ SSH-USERAUTH (none)          │  │    │
│  │   │  └─ SSH channel (exec)            │  │    │
│  │   │                                 │  │    │
│  │   │ host calls:                     │  │    │
│  │   │  ws_connect(url_ptr, url_len)    │  │    │
│  │   │  ws_send(handle, bytes)          │  │    │
│  │   │  ws_recv(handle, max_n)          │  │    │
│  │   │  ws_close(handle)                │  │    │
│  │   └─────────────────────────────────┘  │    │
│  │   ↓ host shim: ws_handles[id] = ws     │    │
│  └─────────────────────────────────────────┘    │
│           ↕ ws://localhost:2222 (binary frames)  │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│ Node.js (mock SSH server)                       │
│  host/mock_ssh_server.mjs                       │
│   - accept WebSocket binary frames               │
│   - SSH KEXINIT / KEXDH_REPLY / NEWKEYS / ...  │
│   - USERAUTH none / CHANNEL open / exec        │
│   - log all bytes for byte-exact verification   │
└─────────────────────────────────────────────────┘
```

## A. MoonBit Host Imports (同步, handle-table 模式)

```wat
(import "moonbit_socket" "ws_connect" (func $ws_connect (param i32 i32) (result i32)))
(import "moonbit_socket" "ws_send" (func $ws_send (param i32 i32 i32) (result i32)))
(import "moonbit_socket" "ws_recv" (func $ws_recv (param i32 i32 i32) (result i32)))
(import "moonbit_socket" "ws_close" (func $ws_close (param i32) (result i32)))
```

## B. MoonBit Socket Layer (src/socket/)

```moonbit
// src/socket/socket.mbt
pub struct Socket {
  handle : Int  // host-side WS handle id
  recv_buf : FixedArray[Byte]  // 累积字节
  recv_pos : Int
}

pub fn Socket::connect(url : String) -> Socket {
  // host ws_connect → handle id
  ...
}

pub fn Socket::send(self : Socket, bytes : FixedArray[Byte]) -> Unit {
  // host ws_send(handle, bytes)
}

pub fn Socket::try_recv(self : Socket, max_n : Int) -> FixedArray[Byte]? {
  // host ws_recv(handle, max_n) → 累积到 recv_buf
  // 如果 recv_buf.length() - recv_pos >= 1, 解析包头
}
```

## C. SSH Framing (src/sshwire/)

```moonbit
// src/sshwire/packet.mbt
pub struct SshPacket {
  msg_type : Byte
  payload : FixedArray[Byte]
}

pub fn read_packet(socket : Socket) -> SshPacket {
  // 1. try_recv(4) 直到拿到 packet_length
  // 2. try_recv(packet_length) 直到拿到完整包
  // 3. msg_type = packet[0]
  // 4. payload = packet[1..]
}

pub fn make_packet(msg_type : Byte, payload : FixedArray[Byte]) -> FixedArray[Byte] {
  // RFC 4253 §6: padding to 8-byte block, 4-byte length prefix
}
```

## D. SSH Client (src/sshclient/client.mbt)

```moonbit
fn ssh_client(url : String) -> Unit {
  let sock = Socket::connect(url)
  
  // 1. 发送 client version
  sock.send(ascii_bytes("SSH-2.0-MoonBit\r\n"))
  
  // 2. 收 server version (raw text, not SSH packet)
  let server_version = recv_until_crlf(sock)
  
  // 3. KEXINIT (RFC 4253 §7)
  let prop = Proposal::default_client(false)
  let cookie = ...
  let started = kexflow::flow_start(...)
  sock.send(make_packet(0x14, started.ic_payload))   // SSH_MSG_KEXINIT
  
  // 4. 收 server KEXINIT
  let server_kexinit = read_packet(sock)
  
  // 5. KEXECDH_INIT
  sock.send(started.init_msg)  // type 30 already included
  
  // 6. 收 server KEXDH_REPLY
  let server_reply = read_packet(sock)
  
  // 7. NEWKEYS 切换 (实际加密此处用 kexflow 已建立 keys)
  // ...
  
  // 8. SSH-USERAUTH (none)
  sock.send(make_packet(50, userauth_request_payload("moonbit", "none")))
  let auth_reply = read_packet(sock)
  
  // 9. CHANNEL OPEN
  sock.send(make_packet(90, channel_open_payload()))
  let open_reply = read_packet(sock)
  
  // 10. CHANNEL REQUEST exec "echo hello"
  sock.send(make_packet(98, channel_request_payload("echo hello")))
  
  // 11. 收 DATA + EOF + CLOSE
  let data_msg = read_packet(sock)
  let eof_msg = read_packet(sock)
  let close_msg = read_packet(sock)
  
  println("recv: " + to_string(data_msg.payload))
  sock.close()
}
```

## E. Host Shim (浏览器)

```js
// host/demo_ws.html
<script type="module">
const out = document.getElementById('out');
let wsHandle = 0;
const wsInstances = new Map();
const wsBuffers = new Map();
let nextHandle = 1;

const imports = {
  spectest: {
    print_char: (code) => out.textContent += String.fromCharCode(code & 0xFF),
  },
  moonbit_socket: {
    ws_connect: (urlPtr, urlLen) => {
      const mem = instance.exports.memory;
      const dv = new DataView(mem.buffer);
      const urlBytes = new Uint8Array(mem.buffer, urlPtr, urlLen);
      const url = new TextDecoder().decode(urlBytes);
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      const h = nextHandle++;
      wsInstances.set(h, ws);
      wsBuffers.set(h, []);
      ws.onmessage = (e) => {
        wsBuffers.get(h).push(new Uint8Array(e.data));
      };
      wsHandle = h;
      return h;
    },
    ws_send: (handle, ptr, len) => {
      const ws = wsInstances.get(handle);
      const mem = instance.exports.memory;
      const bytes = new Uint8Array(mem.buffer, ptr, len);
      ws.send(bytes);
      return 0;
    },
    ws_recv: (handle, maxN, outPtr) => {
      const ws = wsInstances.get(handle);
      const mem = instance.exports.memory;
      const buf = wsBuffers.get(handle);
      const total = buf.reduce((s, b) => s + b.length, 0);
      if (total === 0) return -1;  // no data
      const n = Math.min(total, maxN);
      // Concat first n bytes to mem[outPtr..outPtr+n]
      const dv = new DataView(mem.buffer);
      const u8 = new Uint8Array(mem.buffer);
      let remaining = n;
      let offset = 0;
      while (remaining > 0 && buf.length > 0) {
        const head = buf[0];
        const take = Math.min(head.length, remaining);
        u8.set(head.subarray(0, take), outPtr + offset);
        offset += take;
        remaining -= take;
        if (take === head.length) {
          buf.shift();
        } else {
          buf[0] = head.subarray(take);
        }
      }
      return n;
    },
    ws_close: (handle) => {
      wsInstances.get(handle).close();
      wsInstances.delete(handle);
      wsBuffers.delete(handle);
      return 0;
    },
  },
};

const wasmRes = await fetch('./main.wasm');
const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
instance.exports._start();
</script>
```

## F. Mock SSH Server

```js
// host/mock_ssh_server.mjs
import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 2222 });
wss.on('connection', (ws) => {
  console.log('client connected');
  let state = 'VERSION';
  let serverKex = null;
  ws.on('message', (data) => {
    const bytes = new Uint8Array(data);
    console.log(`recv ${bytes.length} bytes: ${bytes.toString('hex').substring(0, 40)}`);
    
    if (state === 'VERSION') {
      // client → server version string
      const version = new TextDecoder().decode(bytes);
      console.log('client version:', version);
      // server → client version
      ws.send(new TextEncoder().encode('SSH-2.0-MockSSH_1.0\r\n'));
      state = 'KEXINIT';
    } else if (state === 'KEXINIT') {
      // 收 client KEXINIT, 发 server KEXINIT
      ws.send(mockServerKexinit());
      state = 'KEXDH_INIT';
    } else if (state === 'KEXDH_INIT') {
      // 收 client KEXDH_INIT, 发 server KEXDH_REPLY
      ws.send(mockServerKexDhReply());
      state = 'NEWKEYS';
    } else if (state === 'NEWKEYS') {
      // 收 client NEWKEYS, 发 server NEWKEYS
      ws.send(mockNewkeys());
      state = 'USERAUTH';
    } else if (state === 'USERAUTH') {
      // 收 USERAUTH_REQUEST, 发 USERAUTH_SUCCESS
      ws.send(mockUserauthSuccess());
      state = 'CHANNEL';
    } else if (state === 'CHANNEL') {
      // 收 CHANNEL_OPEN, 发 CHANNEL_OPEN_CONFIRMATION
      ws.send(mockChannelOpenConfirm());
      state = 'EXEC';
    } else if (state === 'EXEC') {
      // 收 CHANNEL_REQUEST exec, 发 SUCCESS + DATA + EOF + CLOSE
      ws.send(mockChannelSuccess());
      ws.send(mockChannelData('hello moonbit\n'));
      ws.send(mockChannelEof());
      ws.send(mockChannelClose());
      state = 'DONE';
    }
  });
});

function mockServerKexinit() { ... }
function mockServerKexDhReply() { ... }
// ... 等
```

## G. 验收标准

| # | 标准 | 验证 |
|---|---|---|
| 1 | MoonBit 端 SSH framing byte-exact RFC 4253 §6 | sshwire packet test |
| 2 | SSH client 4 target × 2 mode byte-exact 输出 | verify.mjs 扩展 |
| 3 | mock SSH server 收到 byte-exact SSH wire | server console log diff |
| 4 | 浏览器 end-to-end: demo_ws.html → mock server → console "hello moonbit" | manual |

## H. 范围诚实记录

| 用户选 | 实际可做 |
|---|---|
| WebSocket + WebTransport | **WebSocket only (本 Loop)** + WebTransport stub (Loop #21+) |
| 同步 host + 异步包装 | **同步 host shim (本 Loop)** + 异步包装 (Loop #21+ 等 moon 升级) |
| byte stream + SSH framing + 完整 client | **全做** |

预计 3-4 hours。