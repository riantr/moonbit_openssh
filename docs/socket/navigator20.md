# Loop #20 Navigator — 完整 SSH Client → Server Demo

**Date**: 2026-09-23
**Status**: Navigator 调研中
**Verdict**: 端到端 SSH 客户端 demo:浏览器 wasm-gc 跑 main.wasm, 通过 WebSocket 连 Node.js mock SSH server

## TL;DR

Loop #20 把 SSH-WASM-SSH 项目从"加密 byte-exact 跨 4 target"推到"真能跑 SSH 客户端 demo":

| 子目标 | 实现路径 |
|---|---|
| Node.js mock SSH server | `ws` 包,接受 WebSocket binary frames,模拟 SSH server 状态机 |
| sshclient 真 Socket | 替换 mock_socket 为 extern wasm + 真 WebSocket |
| MoonBit extern wasm | `moonbit_socket.ws_connect/send/recv_into/close` |
| 浏览器 demo HTML | fetch main.wasm + host shim + WebSocket 连 mock server |
| 4 target byte-exact | wasm-gc 端到端 + 其他 3 target 走 mock_socket (Loop #19 兼容) |

## SSH Server 状态机 (mock)

### RFC 4253 完整流程
```
1. 连接 ws://localhost:2222
2. 服务端 → 客户端 version string "SSH-2.0-MockSSH_1.0\r\n"
3. 服务端 → 客户端 server KEXINIT packet (deterministic)
4. 客户端 → 服务端 KEXINIT + KEXECDH_INIT
5. 服务端 → 客户端 KEXDH_REPLY (deterministic K_S + Q_S + signature)
6. 服务端 + 客户端 NEWKEYS
7. 客户端 → 服务端 USERAUTH_REQUEST (none method) → 服务端 → USERAUTH_SUCCESS
8. 客户端 → 服务端 CHANNEL_OPEN (session) → 服务端 → CHANNEL_OPEN_CONFIRMATION
9. 客户端 → 服务端 CHANNEL_REQUEST exec "echo hello"
10. 服务端 → 客户端 CHANNEL_SUCCESS + CHANNEL_DATA("hello\n") + CHANNEL_EOF + CHANNEL_CLOSE
```

### mock server 实现
```js
// host/mock_ssh_server.mjs
import { WebSocketServer } from 'ws';

const wss = new WebSocketServer({ port: 2222 });

const SERVER_VERSION = 'SSH-2.0-MockSSH_1.0\r\n';
const SERVER_KEXINIT_PAYLOAD = hardcoded_deterministic_kexinit_payload();
const SERVER_KEXDH_REPLY_PAYLOAD = hardcoded_deterministic_reply();

wss.on('connection', (ws) => {
  let state = 'VERSION';
  ws.send(Buffer.from(SERVER_VERSION));

  ws.on('message', (data) => {
    const bytes = new Uint8Array(data);
    console.log(`[state=${state}] recv ${bytes.length} bytes`);
    
    if (state === 'VERSION') {
      const ver = new TextDecoder().decode(bytes);
      console.log(`client version: ${ver}`);
      ws.send(server_kexinit_packet());
      state = 'KEXINIT';
    } else if (state === 'KEXINIT') {
      // 收 client KEXINIT, 发 server KEXINIT, 然后等 KEXECDH_INIT
      ws.send(server_kexinit_packet());
      state = 'KEXECDH_INIT';
    } else if (state === 'KEXECDH_INIT') {
      // 收 client KEXECDH_INIT, 发 server KEXDH_REPLY
      ws.send(server_kexdh_reply_packet());
      state = 'NEWKEYS';
    } else if (state === 'NEWKEYS') {
      // 收 client NEWKEYS, 发 server NEWKEYS
      ws.send(newkeys_packet());
      state = 'NEWKEYS_DONE';
    } else if (state === 'NEWKEYS_DONE') {
      // 收 server NEWKEYS 后转 USERAUTH
      ws.send(userauth_success_packet());
      state = 'CHANNEL';
    }
    // ... 后续状态
  });
});
```

### 字节级确定性
- **Server KEXINIT payload**: hardcode byte array, 包含 kex="curve25519-sha256", hostkey="ssh-ed25519", enc="chacha20-poly1305@openssh.com"
- **Server K_S (hostkey)**: RFC 8032 ed25519 test vector
- **Server signature**: 用 server ed25519 private key 签 H (loop #3)
- **Server Q_S**: RFC 7748 §5.2 Bob scalar

## sshclient 真 Socket (替换 mock)

### 当前 Loop #19 问题
```moonbit
// sshwire/socket/socket.mbt
pub fn Socket::mock_server(server_responses : Array[FixedArray[Byte]]) -> Socket {
  // 累积字节 + 模拟 server
}
```
- 4 target 一致 (byte-exact)
- 但不连真 server

### Loop #20 改造
```moonbit
// src/socket/socket.mbt
extern "wasm" fn ws_connect(url : String) -> Int =
  "moonbit_socket" "ws_connect"

extern "wasm" fn ws_send(handle : Int, bytes : FixedArray[Byte]) -> Int =
  #borrow(1) "moonbit_socket" "ws_send"

extern "wasm" fn ws_recv_into(handle : Int, out : FixedArray[Byte], n : Int) -> Int =
  #borrow(1) "moonbit_socket" "ws_recv_into"

extern "wasm" fn ws_close(handle : Int) -> Int =
  "moonbit_socket" "ws_close"

pub fn Socket::connect(url : String) -> Socket {
  { handle: ws_connect(url), closed: false }
}

pub fn Socket::send(self : Socket, bytes : FixedArray[Byte]) -> Unit {
  ignore(ws_send(self.handle, bytes))
}

pub fn Socket::read_n(self : Socket, n : Int) -> FixedArray[Byte] {
  let buf : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let actual = ws_recv_into(self.handle, buf, n)
  if actual < n {
    abort("Socket::read_n: short read, expected \{n} got \{actual}")
  }
  buf
}
```

### 4 target 兼容策略
- **native target**: stub 实现 (return 0 / empty),native 不跑 WS
- **js target**: Node.js + ws 包,host shim 走 ws 库
- **wasm target**: host shim 提供 print_char + moonbit_socket
- **wasm-gc target**: 同 wasm target

或者**简化**: cmd/main 不调真 WS,只 wasm-gc target 端到端 demo。

## host shim 集成

### browser/demo_ssh.html
```html
<!DOCTYPE html>
<html>
<head><title>SSH-WASM Demo (Loop #20)</title></head>
<body>
<pre id="out">Loading...</pre>
<script type="module">
  const out = document.getElementById('out');
  const log = (s) => { out.textContent += s + '\n'; };
  
  // 1. Fetch main.wasm
  const wasmRes = await fetch('./main.wasm');
  const wasmBytes = new Uint8Array(await wasmRes.arrayBuffer());
  log(`Fetched ${wasmBytes.byteLength} bytes`);
  
  // 2. 共享 moonbit_socket shim + spectest print_char
  const wsInstances = new Map();
  const wsBuffers = new Map();
  let nextHandle = 1;
  
  const imports = {
    spectest: {
      print_char: (code) => log(String.fromCharCode(code & 0xFF)),
    },
    moonbit_socket: {
      ws_connect: (urlPtr, urlLen) => {
        const mem = instance.exports.memory;
        const url = new TextDecoder().decode(new Uint8Array(mem.buffer, urlPtr, urlLen));
        const ws = new WebSocket(url);
        ws.binaryType = 'arraybuffer';
        const h = nextHandle++;
        wsInstances.set(h, ws);
        wsBuffers.set(h, []);
        ws.onmessage = (e) => wsBuffers.get(h).push(new Uint8Array(e.data));
        return h;
      },
      ws_send: (handle, ptr, len) => {
        const ws = wsInstances.get(handle);
        ws.send(new Uint8Array(instance.exports.memory.buffer, ptr, len));
        return 0;
      },
      ws_recv_into: (handle, outPtr, n) => {
        const buf = wsBuffers.get(handle);
        if (buf.length === 0) return 0;
        const total = buf.reduce((s, b) => s + b.length, 0);
        const take = Math.min(total, n);
        const u8 = new Uint8Array(instance.exports.memory.buffer);
        let off = 0;
        while (take > 0 && buf.length > 0) {
          const head = buf[0];
          const copy = Math.min(head.length, take);
          u8.set(head.subarray(0, copy), outPtr + off);
          off += copy;
          take -= copy;
          if (copy === head.length) buf.shift();
          else buf[0] = head.subarray(copy);
        }
        return off;
      },
      ws_close: (handle) => {
        wsInstances.get(handle).close();
        wsInstances.delete(handle);
        wsBuffers.delete(handle);
        return 0;
      },
    },
  };
  
  const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
  instance.exports._start();
  log('Demo completed');
</script>
</body>
</html>
```

## 关键挑战与降级

### 挑战 1: MoonBit extern wasm String 参数
- `ws_connect(url: String)` 需要 host shim decode ptr+len → URL
- 4 target extern 一致,host shim 处理
- 已验证 Loop #19 knownhosts_store 编译通过 (但 cmd/main 不调)

### 挑战 2: Native target 走 WS
- native target 没有 ws 实例,需要 stub
- 或者 native 走 mock_socket (Loop #19 兼容),wasm target 走 WS

### 挑战 3: mock server 加密 reply
- NEWKEYS 后 server reply 需用 enc_key_stoc 加密
- mock server 需要计算 enc_key_stoc (需要 client KEXECDH_INIT + server private)
- **简化**: Loop #20 mock server 不发 reply (client-only 验证)
- 或者 mock server 用硬编码 client K → 推 enc_key_stoc

### 挑战 4: 4 target byte-exact
- native/js/wasm 走 mock_socket (Loop #19 byte-exact 一致)
- wasm-gc 走真 WS (字节流不同,但 demo 端到端 PASS)
- verify.mjs 维持 4 target byte-exact (cmd/main mock_socket path)
- 浏览器 demo (wasm-gc target) 端到端 byte-exact 验证另写脚本

### 挑战 5: sshclient::ssh_client_run 改造
- 当前用 mock_socket + mock_responses 预填
- Loop #20 重构成真 Socket::connect(url)
- mock_responses 移除 (真 server reply)
- 但 mock_responses[0] 是 server version (12 bytes) — 真 server 也要发这个

## 不在本 Loop 范围 (诚实记录)

1. **真实 sshd 连通** — Loop #21+
2. **RSA hostkey 验证** — 需要 RSA impl (复杂,留 Loop #21+)
3. **完整 KEX_REPLY 加密** — mock server 不发 reply,client-only 验证
4. **WebTransport** — 留 Loop #21+
5. **真 IndexedDB** — 留 Loop #21+

## Loop #20 衔接

| | Loop #19 | **Loop #20** | Loop #21+ |
|---|---|---|---|
| 焦点 | NEWKEYS 后 chacha20-poly1305 | **完整 SSH client → server demo** | 真实 sshd + WebTransport + IDB |
| 验证 | 4 target byte-exact (mock) | **端到端 (wasm-gc) + 4 target 兼容** | 浏览器 production ship |
| mock server | 无 | **Node.js + ws 状态机** | 真实 sshd |
| 浏览器 demo | 无 | **demo_ssh.html** | WebTransport variant |

## 决策点

### D1: sshclient 改造范围?
- A: 完全替换 mock_socket 为 extern wasm + 真 WS
- B: 新增 sshclient_ws 演示路径,保留 mock_socket
- C: 只在 cmd/ws_demo/ 新加 binary,不动 sshclient

### D2: mock server reply 加密?
- A: hardcode client K → 推 enc_key_stoc → 服务端 reply 加密
- B: mock server 不发 reply,client-only 验证字节路径
- C: mock server 发 unencrypted reply (违反 SSH 协议但便于 demo)

### D3: 4 target byte-exact 范围?
- A: 维持 Loop #19 (cmd/main mock_socket, 4 target byte-exact)
- B: wasm-gc 端到端 byte-exact (browser server 通信字节一致)
- C: 双轨制 — cmd/main 4 target byte-exact + 浏览器 demo 单独验证

## 量化目标

| 指标 | 值 |
|---|---|
| mock_ssh_server.mjs | ~150 行 (状态机) |
| demo_ssh.html | ~80 行 (host shim + fetch) |
| sshclient 改造 | ~30 行 (mock_socket → extern ws) |
| MoonBit extern wasm | 4 个 (ws_connect/send/recv_into/close) |
| 4 target byte-exact | 维持 (mock_socket path) |
| 浏览器端到端 | 验证 (server 收字节 == expected) |
| Loop 时长 | 2-3 hours |

## 待用户确认

请确认:
- D1: sshclient 改造策略?
- D2: mock server reply 加密?
- D3: 4 target byte-exact 范围?