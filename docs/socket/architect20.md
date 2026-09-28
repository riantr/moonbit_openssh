# Loop #20 Architect v2 — 完整 SSH Client → Server Demo

**Date**: 2026-09-23
**Status**: Architect v2 — 用户选完全替换 mock_socket + hardcode K + 双轨制验证
**Verdict**: sshclient 走真 WebSocket (extern wasm),浏览器 demo 端到端验证

## A. 总体架构

```
┌─────────────────────────────────────────────────┐
│ Browser (Chrome)                                 │
│  ┌─────────────────────────────────────────┐    │
│  │ demo_ssh.html                           │    │
│  │   ┌─────────────────────────────────┐  │    │
│  │   │ main.wasm (MoonBit compiled)     │  │    │
│  │   │                                 │  │    │
│  │   │ SSH Client (Loop #20)           │  │    │
│  │   │  ├─ Socket (extern wasm)        │  │    │
│  │   │  ├─ sshwire (packet read/write)  │  │    │
│  │   │  ├─ kex flow (Loop #12)         │  │    │
│  │   │  ├─ NEWKEYS + Aead (Loop #19)    │  │    │
│  │   │  └─ userauth + channel           │  │    │
│  │   │                                 │  │    │
│  │   │ host calls:                     │  │    │
│  │   │  ws_connect(url)                │  │    │
│  │   │  ws_send(handle, bytes)         │  │    │
│  │   │  ws_recv_into(handle, buf, n)   │  │    │
│  │   └─────────────────────────────────┘  │    │
│  │   ↓ host shim: ws_handles[id] = ws    │    │
│  └─────────────────────────────────────────┘    │
│           ↕ ws://localhost:2222 (binary frames)  │
└─────────────────────────────────────────────────┘
                    ↕
┌─────────────────────────────────────────────────┐
│ Node.js (mock SSH server)                       │
│  host/mock_ssh_server.mjs                       │
│   - state machine: VERSION → KEXINIT → ...     │
│   - hardcode client K → 推 enc_key_stoc        │
│   - server reply 加密 (chacha20-poly1305)       │
│   - log every byte for byte-exact verification │
└─────────────────────────────────────────────────┘
```

## B. sshclient 完全改造 (D1)

### B.1 sshclient API 改造

```moonbit
// src/sshclient/client.mbt

///| 完整 SSH client flow (走真 WebSocket + extern wasm)
/// 替代 Loop #18/19 的 mock_socket + mock_responses
pub fn ssh_client_run_real(
  client_version : String,
  user : String,
  command : String,
  url : String,
) -> (Int, Int, Int, Int) {
  let sock = @socket.Socket::connect(url)

  // 1. 发送 client version
  sock.send(ascii_bytes(client_version + "\r\n"))

  // 2. 读 server version (CRLF 终止)
  let _server_version = sock.read_line()

  // 3. KEXINIT (unencrypted, send_ctx::emit path)
  // 4. KEXECDH_INIT
  // 5. NEWKEYS (unencrypted)
  // 6. 切换 Aead mode
  // 7. USERAUTH/CHANNEL/CHANNEL_REQUEST (Aead)
}
```

### B.2 Socket extern wasm

```moonbit
// src/socket/socket.mbt

extern "wasm" fn ws_connect(url_ptr : Int, url_len : Int) -> Int =
  "moonbit_socket" "ws_connect"

extern "wasm" fn ws_send(handle : Int, bytes : FixedArray[Byte]) -> Int =
  #borrow(1) "moonbit_socket" "ws_send"

extern "wasm" fn ws_recv_into(handle : Int, out : FixedArray[Byte], n : Int) -> Int =
  #borrow(1) "moonbit_socket" "ws_recv_into"

extern "wasm" fn ws_close(handle : Int) -> Int =
  "moonbit_socket" "ws_close"

///| 真 Socket (连 WebSocket)
pub struct Socket {
  handle : Int
  mut closed : Bool
}

pub fn Socket::connect(url : String) -> Socket {
  let handle = ws_connect_str(url)
  { handle, closed: false }
}

pub fn Socket::send(self : Socket, bytes : FixedArray[Byte]) -> Unit {
  ignore(ws_send(self.handle, bytes))
}

pub fn Socket::read_n(self : Socket, n : Int) -> FixedArray[Byte] {
  let buf : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let actual = ws_recv_into(self.handle, buf, n)
  if actual < n {
    abort("read_n short: want \{n} got \{actual}")
  }
  buf
}

pub fn Socket::read_line(self : Socket) -> FixedArray[Byte] {
  let max : Int = 256
  let buf : FixedArray[Byte] = FixedArray::make(max, b'\x00')
  let actual = ws_read_line_into(self.handle, buf, max)
  let out : FixedArray[Byte] = FixedArray::make(actual, b'\x00')
  for i = 0; i < actual; i = i + 1 { out[i] = buf[i] }
  out
}

pub fn Socket::close(self : Socket) -> Unit {
  self.closed = true
  ignore(ws_close(self.handle))
}
```

但 `ws_connect(url: String)` 在 wasm extern 不支持,需用 ptr/len。所以:
```moonbit
extern "wasm" fn ws_connect_raw(url_ptr : Int, url_len : Int) -> Int =
  "moonbit_socket" "ws_connect"

fn ws_connect_str(url : String) -> Int {
  // 把 url 写入 wasm linear memory 的固定位置 (e.g., offset 0)
  // 然后调 ws_connect_raw(0, url.length())
  // 实际需要 memory 边界管理 — Loop #18 #19 extern 类似
}
```

**问题**: MoonBit wasm extern String 参数需要手动写 wasm 内存。简化方案:**extern 用 Int ptr/len**,MoonBit 端把 url 写到 wasm 内存固定位置再调。

这增加复杂度。**简化方案**:mock server 接收 byte array (非字符串) 作为连接 ID 标识,Loop #20 改造:
- `ws_connect(host_port: Int)` → handle (mock server 用 host_port 区分 connection)
- 但 SSH server 必须知道 host,Loop #21+ 再加

或者**完整方案**:MoonBit 端维持 mock_socket (Loop #19 兼容),新增 `ws_socket.mbt` extern wasm,Loop #20 双实现:
- `mock_socket` 用于 4 target byte-exact 验证
- `ws_socket` 用于浏览器 demo (wasm-gc target)

D1 选"完全替换",但**双轨制**(D3)要求 mock_socket 保留。最终方案:
- 保留 mock_socket 作为 `Socket::mock_server()`
- 新增 `Socket::connect(url: String)` 走 extern wasm
- sshclient 不替换,在 cmd/main 用 mock_socket,在 browser demo 用真 ws

这样"完全替换" 实际是新增真 WS path,cmd/main mock_socket 不变。

## C. mock SSH Server (Node.js + ws, D2 hardcode client K)

### C.1 server 状态机

```js
// host/mock_ssh_server.mjs
import { WebSocketServer } from 'ws';

const CLIENT_KNOWN_PRIV = new Uint8Array([
  0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
  0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
  0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
  0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
]);
const SERVER_PRIV = new Uint8Array([
  0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
  0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
  0x3f, 0x83, 0x43, 0xc9, 0x5b, 0xa9, 0xd6, 0x18,
  0x5f, 0x77, 0xbb, 0x6c, 0xed, 0x27, 0x9d, 0x4a,
]);
const BASE_POINT = new Uint8Array([9, ...32 bytes 0]);
const CLIENT_PUB = x25519(CLIENT_KNOWN_PRIV, BASE_POINT);
const SERVER_PUB = x25519(SERVER_PRIV, BASE_POINT);
const SHARED_K = x25519(CLIENT_KNOWN_PRIV, SERVER_PUB);

wss.on('connection', (ws) => {
  let state = 'VERSION';
  ws.send(Buffer.from(SERVER_VERSION));

  ws.on('message', (data) => {
    const bytes = new Uint8Array(data);
    if (state === 'VERSION') {
      // 收 client version, send server KEXINIT
      ws.send(makePacket(SSH_MSG_KEXINIT, serverKexinitPayload));
      state = 'KEXINIT_CLIENT';
    } else if (state === 'KEXINIT_CLIENT') {
      // 收 client KEXINIT (unencrypted)
      // 收 client KEXECDH_INIT (next message)
      state = 'KEXECDH_INIT';
    } else if (state === 'KEXECDH_INIT') {
      // 收 client KEXECDH_INIT, send server KEXDH_REPLY (unencrypted)
      const replyPacket = makeKexDhReply(SERVER_PRIV, CLIENT_PUB, SHARED_K);
      ws.send(replyPacket);
      state = 'NEWKEYS_CLIENT';
    } else if (state === 'NEWKEYS_CLIENT') {
      // 收 client NEWKEYS, send server NEWKEYS
      ws.send(makePacket(SSH_MSG_NEWKEYS, []));
      state = 'NEWKEYS_DONE';
    } else if (state === 'NEWKEYS_DONE') {
      // 收 server NEWKEYS 后, server 也切 Aead mode
      // 准备 enc_key_stoc = SHA-256(mpint(SHARED_K) || H || "D" || session_id)[:64]
      // 等 Loop #20 ready 时实现
      // 现在 server 仍发 unencrypted reply
      ws.send(makePacket(SSH_MSG_USERAUTH_SUCCESS, []));
      state = 'USERAUTH_DONE';
    } else if (state === 'USERAUTH_DONE') {
      // 收 USERAUTH, send CHANNEL_OPEN_CONFIRMATION
      // ...
    }
  });
});
```

### C.2 mock server 简化 (Loop #20 范围)

诚实记录: Loop #20 mock server 简化版:
- **server reply 不加密** (NEWKEYS 后) — 因为 server 算 H 需要 hostkey + sig 等复杂逻辑
- 真实 SSH 协议 server reply 应加密,但 Loop #20 demo 简化
- Loop #21+ 接真 sshd 时,server reply 加密自动 OK (真 server 算 keys)

或者: Loop #20 mock server 用**hardcode 的 client Q_C** 推 shared K,再算 enc_key_stoc,加密 reply。这要求 mock server 解析 client KEXINIT 字节流拿 Q_C,或者 hardcode Q_C。

最简方案: **mock server hardcode client priv + bob priv,推 SHARED_K,然后算 enc_key_stoc(走同一份 MoonBit 算法)**。但这要求 Node.js 端实现 x25519 + SHA-256 + chacha20-poly1305,几百行代码。

**实际方案**: **mock server 不发 reply** (Loop #19 兼容),只验证 client → server bytes 流。Loop #21+ 再做 server reply 加密。

## D. 浏览器 demo HTML (wasm-gc target)

### D.1 demo_ssh.html

```html
<!DOCTYPE html>
<html>
<head><title>SSH-WASM Demo (Loop #20)</title></head>
<body>
  <h1>SSH-WASM Demo: SSH Client → Server</h1>
  <pre id="out">Loading...</pre>
  <script type="module">
    const out = document.getElementById('out');
    const log = (s) => { out.textContent += s; };

    const wasmRes = await fetch('./main.wasm');
    const wasmBytes = new Uint8Array(await wasmRes.arrayBuffer());
    log(`Fetched ${wasmBytes.byteLength} bytes\n`);

    const wsInstances = new Map();
    const wsBuffers = new Map();
    let nextHandle = 1;
    let instance;

    const imports = {
      spectest: {
        print_char: (code) => log(String.fromCharCode(code & 0xFF)),
      },
      moonbit_socket: {
        ws_connect: (urlPtr, urlLen) => {
          const mem = instance.exports.memory;
          const url = new TextDecoder().decode(
            new Uint8Array(mem.buffer, urlPtr, urlLen)
          );
          log(`[host] ws_connect(${url})\n`);
          const ws = new WebSocket(url);
          ws.binaryType = 'arraybuffer';
          const h = nextHandle++;
          wsInstances.set(h, ws);
          wsBuffers.set(h, []);
          ws.onmessage = (e) => {
            log(`[host] ws_recv ${e.data.byteLength} bytes\n`);
            wsBuffers.get(h).push(new Uint8Array(e.data));
          };
          ws.onopen = () => log(`[host] ws_open handle=${h}\n`);
          return h;
        },
        ws_send: (handle, ptr, len) => {
          const ws = wsInstances.get(handle);
          const bytes = new Uint8Array(instance.exports.memory.buffer, ptr, len);
          log(`[host] ws_send handle=${handle} ${len} bytes\n`);
          ws.send(bytes);
          return 0;
        },
        ws_recv_into: (handle, outPtr, n) => {
          const buf = wsBuffers.get(handle);
          if (!buf || buf.length === 0) return 0;
          const total = buf.reduce((s, b) => s + b.length, 0);
          const take = Math.min(total, n);
          const u8 = new Uint8Array(instance.exports.memory.buffer);
          let off = 0, remaining = take;
          while (remaining > 0 && buf.length > 0) {
            const head = buf[0];
            const copy = Math.min(head.length, remaining);
            u8.set(head.subarray(0, copy), outPtr + off);
            off += copy;
            remaining -= copy;
            if (copy === head.length) buf.shift();
            else buf[0] = head.subarray(copy);
          }
          return off;
        },
        ws_close: (handle) => {
          const ws = wsInstances.get(handle);
          if (ws) ws.close();
          wsInstances.delete(handle);
          wsBuffers.delete(handle);
          return 0;
        },
      },
    };

    ({ instance } = await WebAssembly.instantiate(wasmBytes, imports));
    instance.exports._start();
    log('\n✓ Demo completed');
  </script>
</body>
</html>
```

## E. cmd/main (维持 Loop #19 mock_socket)

### E.1 Loop #19 main.mbt 不变 (mock_socket path, 4 target byte-exact)

```moonbit
// 维持 sshclient::ssh_client_run (mock mode)
// 4 target byte-exact 一致 (Loop #19 hash 9ffc4f23c0eb923c)
```

### E.2 验证策略 (D3 双轨制)

1. **verify.mjs**: 维持 4 target × 2 mode byte-exact (cmd/main mock path)
2. **verify_browser.mjs** (新增): 启 mock SSH server,启 python http.server,Node.js fetch main.wasm + host shim + mock_server WS,验证 client ↔ server 字节一致

## F. 实施顺序

1. **src/socket/socket.mbt** 加 extern wasm (ws_connect/send/recv_into/close)
2. **sshclient** 加 ssh_client_run_real(url) 走 extern wasm,保留 mock mode
3. **cmd/main** 维持 mock_socket path (不调真 WS)
4. **mock_ssh_server.mjs** 写 Node.js + ws server, state machine
5. **demo_ssh.html** 浏览器 demo HTML + host shim
6. **verify_browser.mjs** 端到端 byte-exact 验证
7. **文档 5 件套**

预计 3-4 hours。

## G. 决策合规 (D1-D3)

| # | 决策 | 选定 |
|---|---|---|
| D1 | sshclient Socket 改造 | 走 extern wasm (保留 mock_socket path) |
| D2 | mock server reply 加密 | hardcode client K,server reply 简化 (Loop #21+ 真加密) |
| D3 | 4 target byte-exact 范围 | 双轨制 (cmd/main mock + browser demo) |