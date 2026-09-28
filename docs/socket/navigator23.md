# Loop #23 Navigator — 浏览器 MoonBit SSH client 端到端 mock_ssh_server_v2 (WebSocket 整合)

**Date**: 2026-09-28
**Status**: Navigator 调研中 → **Verdict**: 三件大事：(1) G1 mock_ssh_server_v2 升级 — USERAUTH_REQUEST 后一次性发完所有 7 个 post-USERAUTH server reply packets (concat buffer); (2) G2 ssh_client_full_unencrypted_ws — MoonBit 端用 ws_socket::Socket 走相同协议路径; (3) G3 demo_ssh_full.html + verify_loop23.mjs — chromium wasm-gc + ws client + byte-exact 验证

## TL;DR

| 子目标 | 实现路径 | 状态 |
|---|---|---|
| **G1** mock_ssh_server_v2 一次性发 7 replies | mock_ssh_server_v2_v2.mjs — USERAUTH_REQUEST 收包后 concat 7 packets + 1 ws.send | 可行 (~30 min) |
| **G2** MoonBit ws_socket path | sshclient/client.mbt 加 ssh_client_full_unencrypted_ws (wasm-only) | 可行 (~30 min) |
| **G3** 浏览器 demo + verify | demo_ssh_full.html (load main.wasm + MoonBit client run) + verify_loop23.mjs (playwright + ws client) | 可行 (~1 hour) |
| 4 target byte-exact 维持 | 现有 Loop #20 hash (230bfd5b0c02d682) + Loop #22 hash (4ac5544049c297cf) 不变 | 维持 |

## A. Loop #23 范围决策

### A.1 候选方向（来自 Loop #22 + memory）
1. **浏览器 MoonBit SSH client 端到端 mock_ssh_server_v2 (WebSocket 整合)** ← 选定
2. WebTransport HTTP/3 server (cloudflare/quiche/quinn)
3. cert chain / KRL / write 侧 (interactive shell)
4. AEAD 加密层回包验证 (mock server 端 chacha20-poly1305)
5. 真 sshd 连通 (Docker / WSL)
6. ssh_config fnmatch (配置文件解析)
7. release 性能基准

### A.2 选定 Loop #23 理由
- **Loop #22 留下的真正 gap** — ssh_client_full_unencrypted 通了 MockSocket 字节级协议闭环,但**浏览器端 demo 还停在 Loop #20/21 握手路径** (VERSION + KEXINIT + KEXECDH_INIT + NEWKEYS),没接 mock_ssh_server_v2 完整 write 侧
- **用户目标"让 SSH 客户端在浏览器零依赖跑"** — Loop #23 推进一步:浏览器 MoonBit client → WebSocket → mock_ssh_server_v2 → 真实 SSH 协议流程字节级 byte-exact
- **不依赖 Docker / HTTP/3 / AEAD 加密** — 复用 Loop #22 unencrypted mock 路径,降低实施成本
- **架构闭环** — 完成 SSH-WASM-SSH 主线"浏览器 → mock server → byte-exact"端到端

### A.3 不在 Loop #23 范围（已确认）
- WebTransport HTTP/3 server（Loop #24+）
- 真 sshd 连通（Loop #24+）
- AEAD 加密层回包验证（Loop #25+）
- cert chain / KRL（Loop #25+）
- ssh_config fnmatch（Loop #26+）
- interactive shell（Loop #26+）

## B. mock_ssh_server_v2_v2 升级 (G1)

### B.1 现状
mock_ssh_server_v2.mjs (Loop #22 G2) 在 CHANNEL_REQUEST state 收包后**逐个发** 5 个 server reply packets (CHANNEL_SUCCESS + DATA + EOF + exit-status + CLOSE):
```js
ws.send(makeSimplePacket(SH_MSG_CHANNEL_SUCCESS, writeU32(senderChannel)));
ws.send(makeChannelData(senderChannel, Buffer.from(mockStdout, 'utf-8')));
ws.send(makeSimplePacket(SH_MSG_CHANNEL_EOF, writeU32(senderChannel)));
ws.send(makeExitStatus(senderChannel, 0));
ws.send(makeSimplePacket(SH_MSG_CHANNEL_CLOSE, writeU32(senderChannel)));
```

### B.2 Loop #23 升级
mock_ssh_server_v2_v2.mjs — USERAUTH_REQUEST 收包后**一次性发完**所有 7 个 post-USERAUTH server reply packets (concat 1 buffer + 1 ws.send):
```js
} else if (state === 'USERAUTH') {
  const parsed = parseUserauthRequest(bytes);
  // 一次性发 7 个 server reply (concat 1 buffer)
  const postAuth = Buffer.concat([
    makeSimplePacket(SH_MSG_USERAUTH_SUCCESS, Buffer.alloc(0)),
    makeOpenConfirmation(0, 100, 2097152, 32768),
    makeSimplePacket(SH_MSG_CHANNEL_SUCCESS, writeU32(0)),
    makeChannelData(0, Buffer.from('hello from mock server (cmd: ' + lastExecCommand + ')\n')),
    makeSimplePacket(SH_MSG_CHANNEL_EOF, writeU32(0)),
    makeExitStatus(0, 0),
    makeSimplePacket(SH_MSG_CHANNEL_CLOSE, writeU32(0)),
  ]);
  ws.send(postAuth);
  state = 'DONE';
  setTimeout(() => ws.close(), 1000);
}
```

### B.3 简化决策
- USERAUTH_REQUEST 收包后 client 不需要再发包 — 协议在 USERAUTH 之后 server 可以一次性发完所有 reply
- 实际 SSH: client 发 USERAUTH → server 回 SUCCESS → client 发 CHANNEL_OPEN → server 回 OPEN_CONFIRMATION → client 发 CHANNEL_REQUEST → server 回 SUCCESS + DATA + EOF + exit-status + CLOSE
- Loop #23 mock 简化: server 在 USERAUTH 收包后模拟 client 已发完所有包,一次性发回所有 reply (协议层路径压缩,但字节级一致)

## C. MoonBit ws_socket path (G2)

### C.1 ssh_client_full_unencrypted_ws 函数

```moonbit
// sshclient/client.mbt 新增
pub fn ssh_client_full_unencrypted_ws(
  user : String, password : String, command : String,
  ws_url : String,
) -> (FixedArray[Byte], FixedArray[Byte], String, Int, Int) {
  // 用 ws_socket::Socket 代替 MockSocket
  let sock = @ws_socket.Socket::connect(ws_url);

  // 1. VERSION
  sock.send(ascii_bytes("SSH-2.0-MoonBit\r\n"));
  let server_version_len = make_server_version_bytes().length();
  let _ = sock.read_n(server_version_len);

  // 2. KEXINIT + KEXECDH_INIT + NEWKEYS (复用)
  // ... 与 Loop #22 ssh_client_full_unencrypted 相同 ...

  // 3. USERAUTH_REQUEST "password"
  // ...

  // 4. 一次性读 7 个 server reply packets (concat buffer)
  let total_post_auth_len = compute_post_auth_reply_total_length();
  let post_auth_bytes = sock.read_n(total_post_auth_len);
  // 用 SshBuf.feed + 循环 try_parse 解析 7 个 reply packets

  // ...
}
```

### C.2 post-auth reply total length 计算

```moonbit
fn compute_post_auth_reply_total_length() -> Int {
  let packets = [
    make_server_userauth_success_reply(),
    make_server_channel_open_confirmation_reply(0, 100, 2097152, 32768),
    make_server_channel_success_reply(0),
    make_server_channel_data_reply(0, ascii_bytes("hello from mock server (cmd: ls)\n")),
    make_server_channel_eof_reply(0),
    make_server_exit_status_reply(0, 0),
    make_server_channel_close_reply(0),
  ];
  let mut total = 0;
  for p in packets {
    total = total + p.length();
  }
  total
}
```

### C.3 SshBuf 增量解析

```moonbit
// sshwire.SshBuf 已有 feed + try_parse
// Loop #23 加 read_n_ssh_packets(buf, bytes) 函数:
//   - buf.feed(bytes)
//   - 循环 buf.try_parse(),取出 7 个 reply packets

fn parse_n_ssh_packets(buf : @sshwire.SshBuf, expected_n : Int) -> Array[@sshwire.SshPacket] {
  let packets : Array[@sshwire.SshPacket] = [];
  for i = 0; i < expected_n; i = i + 1 {
    match buf.try_parse() {
      Some(p) => packets.push(p)
      None => abort("parse_n_ssh_packets: failed at \{i}")
    }
  }
  packets
}
```

### C.4 wasm-only 限制

ws_socket 是 wasm-only extern library。Loop #23 G2 函数 ssh_client_full_unencrypted_ws **不能在 native target 编译**。需要：

- 方案 A: 新增 cmd/ssh_full_ws/main.mbt (wasm-only),moon.pkg import ws_socket
- 方案 B: 用 moon 的 `if target.wasm-gc` 条件 (不确定是否支持)
- 方案 C: 让 ws_socket 在 native/js target 也编译 (extern 报错)

**选定 A**: cmd/ssh_full_ws/main.mbt 是 wasm-only exec。

## D. 浏览器 demo + verify (G3)

### D.1 host/demo_ssh_full.html

```html
<!DOCTYPE html>
<html>
<head><title>SSH-WASM-SSH Full Client (Loop #23)</title></head>
<body>
<h1>SSH-WASM-SSH Full Client Demo</h1>
<pre id="out">Loading wasm...</pre>
<script>
  // 1. load main.wasm (cmd/ssh_full_ws)
  // 2. MoonBit extern ws_shim 同步 ws client (类似 demo_ssh.html)
  // 3. 调用 MoonBit ssh_client_full_unencrypted_ws
  // 4. 打印 stdout + exit_code + sent/recv bytes
</script>
</body>
</html>
```

### D.2 host/ws_shim.js (或整合到 demo_ssh_full.html)

```js
const wsInstances = new Map();
const wsBuffers = new Map();  // handle → FIFO queue of bytes

const moonbit_socket = {
  ws_connect: (urlPtr, urlLen) => {
    const url = new TextDecoder().decode(mem.subarray(urlPtr, urlPtr + urlLen));
    const ws = new WebSocket(url);
    let handle = wsInstances.size + 1;
    wsInstances.set(handle, ws);
    wsBuffers.set(handle, []);
    ws.binaryType = 'arraybuffer';
    ws.onmessage = (e) => {
      const bytes = new Uint8Array(e.data);
      wsBuffers.get(handle).push(bytes);
    };
    return handle;
  },
  ws_send: (handle, ptr, len) => {
    const ws = wsInstances.get(handle);
    ws.send(new Uint8Array(mem.subarray(ptr, ptr + len)));
    return 0;
  },
  ws_recv_into: (handle, ptr, len) => {
    // 同步阻塞读 len bytes — 必须有 buffer 才能返回
    const queue = wsBuffers.get(handle);
    if (queue.length === 0 || queue[0].length < len) {
      abort('ws_recv_into: short buffer');
    }
    const bytes = queue[0];
    for (let i = 0; i < len; i++) mem[ptr + i] = bytes[i];
    if (bytes.length === len) queue.shift();
    else wsBuffers.set(handle, [bytes.subarray(len)]);
    return len;
  },
  ws_close: (handle) => {
    wsInstances.get(handle).close();
    return 0;
  },
};
```

### D.3 host/verify_loop23.mjs

```js
// 1. 启动 mock_ssh_server_v2_v2 (port 2223)
// 2. 启动 HTTP server (port 8765)
// 3. 启动 chromium (wasm-gc)
// 4. page.goto demo_ssh_full.html
// 5. 等 MoonBit 跑完 → 读 #out textContent
// 6. 验证:
//    - stdout = "hello from mock server (cmd: ls)\n" (byte-exact)
//    - exit_code = 0 (byte-exact)
//    - remote_channel = 100 (byte-exact)
//    - sent_bytes ≥ 459 (估计,实际值)
//    - mock server 收到 ≥ 7 个 client packets (VERSION + KEXINIT + KEXECDH + NEWKEYS + USERAUTH + CHANNEL_OPEN + CHANNEL_REQUEST)
```

## E. 4 target × 2 mode byte-exact 维持策略

| 验证 | hash | 目标 |
|---|---|---|
| verify.mjs (Loop #20 cmd/main) | 230bfd5b0c02d682 | 不动 |
| verify_loop22.mjs (Loop #22 cmd/ssh_full) | 4ac5544049c297cf | 不动 |
| verify_loop23.mjs (Loop #23 浏览器 demo + ws) | 新 hash | 仅 chromium wasm-gc 1 target (其他 target 由 verify_skip 跳过) |

cmd/ssh_full_ws 是 wasm-only exec,不能在 native/js/wasm target 编译,只有 wasm-gc target。verify_loop23.mjs 只跑 1 个 target。

如果需要维持 4 target 验证,某条路：
- 方案 1: cmd/ssh_full_ws 只跑 wasm-gc,verify_loop23.mjs 只验 wasm-gc
- 方案 2: 拆 src/sshclient_full/ssh_client_run_websocket 函数,用 conditional import ws_socket (MoonBit 不支持, 走方案 1)

**选定方案 1**: Loop #23 verify 只跑 wasm-gc target。

## F. 时间预算

| 任务 | 预估 |
|---|---|
| G1 mock_ssh_server_v2_v2 升级 (concat 7 replies) | 30 min |
| G2 ssh_client_full_unencrypted_ws 函数 + parse_n_ssh_packets | 1 hour |
| G3 demo_ssh_full.html + ws_shim.js + verify_loop23.mjs | 1-2 hours |
| Loop #23 5 件套文档 | 30 min |
| 总计 | 3-4 hours |

## G. 决策点（待用户确认）

### G1: mock_ssh_server_v2_v2 简化程度
- A: USERAUTH_REQUEST 收包后一次性发 7 个 post-auth replies (concat buffer) — 选定
- B: 维持逐个发 (5 个 ws.send) — 需要 read_one_packet extern,工作量 x2
- D: 维持 mock_ssh_server_v2 不变,client 用 read_n 读已知字节数

### G2: cmd/ssh_full_ws exec 模式
- A: 新增 cmd/ssh_full_ws/main.mbt (wasm-only exec) — 选定
- B: 让 cmd/ssh_full 同时支持 MockSocket (native/js) 和 ws_socket (wasm-gc)

### G3: 4 target 验证范围
- A: 仅 wasm-gc target (Loop #23 cmd/ssh_full_ws) — 选定
- B: 维持 4 target 但 ssh_client_full_unencrypted_ws 在 native/js 上用 mock (回退方案)

默认选 A+A+A（最简）。