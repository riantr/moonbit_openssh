# Loop #23 Architect — 浏览器 MoonBit SSH client 端到端 mock_ssh_server_v2 (WebSocket 整合)

**Date**: 2026-09-28
**Status**: Architect 设计 → **Verdict**: G1 = host/mock_ssh_server_v2_v2.mjs USERAUTH 后 1 ws.send 7 replies; G2 = src/sshclient/client.mbt 加 ssh_client_full_unencrypted_ws + parse_n_ssh_packets; G3 = cmd/ssh_full_ws/main.mbt (wasm-only) + host/demo_ssh_full.html + host/verify_loop23.mjs

## TL;DR

| 子目标 | 模块 | 新增 LOC | 关键产物 |
|---|---|---|---|
| **G1** mock server 升级 | host/mock_ssh_server_v2_v2.mjs (新) | ~30 | USERAUTH 后 1 ws.send 7 replies (concat buffer) |
| **G2** client ws path | src/sshclient/client.mbt (扩展) | ~80 | ssh_client_full_unencrypted_ws + parse_n_ssh_packets + compute_post_auth_total |
| **G3** 浏览器 demo + verify | cmd/ssh_full_ws/main.mbt + host/demo_ssh_full.html + verify_loop23.mjs | ~250 | chromium wasm-gc + ws client + byte-exact 验证 |

## A. G1 — host/mock_ssh_server_v2_v2.mjs (新)

### A.1 state machine 简化为 4 states
```
VERSION → KEXINIT → KEXECDH_INIT → NEWKEYS → USERAUTH → DONE
```
(移除原 CHANNEL_OPEN + CHANNEL_REQUEST state,因为 client 不再发 — 见 D 流程)

### A.2 USERAUTH 收包后 1 ws.send 7 replies

```js
} else if (state === 'USERAUTH') {
  const parsed = parseUserauthRequest(bytes);
  console.log(`[mock-ssh-v2] USERAUTH: user=${parsed.user} method=${parsed.method}`);
  
  // 一次性发 7 个 post-auth server replies
  const stdoutMsg = `hello from mock server (cmd: ls)\n`;
  const postAuth = Buffer.concat([
    makeSimplePacket(SH_MSG_USERAUTH_SUCCESS, Buffer.alloc(0)),     // USERAUTH_SUCCESS
    makeOpenConfirmation(0, 100, 2097152, 32768),                    // CHANNEL_OPEN_CONFIRMATION
    makeSimplePacket(SH_MSG_CHANNEL_SUCCESS, writeU32(0)),           // CHANNEL_SUCCESS
    makeChannelData(0, Buffer.from(stdoutMsg, 'utf-8')),             // CHANNEL_DATA
    makeSimplePacket(SH_MSG_CHANNEL_EOF, writeU32(0)),               // CHANNEL_EOF
    makeExitStatus(0, 0),                                              // exit-status
    makeSimplePacket(SH_MSG_CHANNEL_CLOSE, writeU32(0)),             // CHANNEL_CLOSE
  ]);
  console.log(`[mock-ssh-v2] sending 7 post-auth replies (${postAuth.length}B) in 1 ws.send`);
  ws.send(postAuth);
  
  state = 'DONE';
  setTimeout(() => ws.close(), 2000);
}
```

### A.3 简化决策
- Loop #23 mock 简化为"server 端在 USERAUTH 后 1 次发完所有 post-auth replies"
- 实际 SSH 协议 client 需先发 CHANNEL_OPEN 后 server 才回 OPEN_CONFIRMATION,但 mock 简化省掉中间握手
- 字节级一致:MoonBit client 用 SshBuf.feed(post_auth_bytes) + 循环 try_parse 解析 7 个 reply,每个 reply 的 msg_type + payload 字节级正确

## B. G2 — src/sshclient/client.mbt ssh_client_full_unencrypted_ws

### B.1 新增函数

```moonbit
///| Loop #23 G2: 完整 SSH client write 侧字节级协议闭环 (ws_socket path, wasm-only)
pub fn ssh_client_full_unencrypted_ws(
  user : String, password : String, command : String, ws_url : String,
) -> (FixedArray[Byte], FixedArray[Byte], String, Int, Int) {
  let stdout_msg = "hello from mock server (cmd: \{command})\n"
  let sock = @ws_socket.Socket::connect(ws_url)

  // 1. VERSION
  sock.send(ascii_bytes("SSH-2.0-MoonBit\r\n"))
  let _ = sock.read_n(make_server_version_bytes().length())

  // 2. KEXINIT + KEXECDH_INIT + NEWKEYS (复用 Loop #22 ssh_client_full_unencrypted 逻辑)
  let cookie : FixedArray[Byte] = FixedArray::from_array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10,
  ])
  let prop = @kexflow.Proposal::default_client(false)
  let ic_payload = @kexflow.kexinit_payload(cookie, prop)
  let alice_priv : FixedArray[Byte] = FixedArray::from_array([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
    0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  ])
  let started = @kexflow.flow_start(
    @kexflow.FlowConfig::make(
      ascii_bytes("SSH-2.0-MoonBit"),
      ascii_bytes("SSH-2.0-MockSSH_1.0"),
      cookie, alice_priv, false, "demo", 22, [],
    ),
    prop,
  )
  let kexinit_packet = @sshwire.make_packet(@sshwire.SSH_MSG_KEXINIT, ic_payload)
  sock.send(kexinit_packet)
  let _ = sock.read_n(make_server_kexinit_reply().length())
  sock.send(started.init_msg)
  let _ = sock.read_n(make_server_kexdh_reply_reply().length())
  let newkeys_packet = @sshwire.make_packet(@sshwire.SSH_MSG_NEWKEYS, FixedArray::make(0, b'\x00'))
  sock.send(newkeys_packet)
  let _ = sock.read_n(make_server_newkeys_reply().length())

  // 3. USERAUTH_REQUEST "password"
  let auth_payload = userauth_password_payload(user, password)
  let userauth_wire = @sshwire.make_packet(@sshwire.SSH_MSG_USERAUTH_REQUEST, auth_payload)
  sock.send(userauth_wire)

  // 4. 读 7 个 post-auth server replies (1 ws.send = concat buffer)
  let post_auth_len = compute_post_auth_total_length(stdout_msg)
  let post_auth_bytes = sock.read_n(post_auth_len)
  let buf = @sshwire.SshBuf::new()
  buf.feed(post_auth_bytes)
  let packets = parse_n_ssh_packets(buf, 7)
  
  // 5. 解析 7 个 reply packets
  let userauth_success_parsed = packets[0]
  if userauth_success_parsed.msg_type != @sshwire.SSH_MSG_USERAUTH_SUCCESS { abort(...) }
  
  let open_confirm_parsed = packets[1]
  if open_confirm_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_OPEN_CONFIRMATION { abort(...) }
  let (_, remote_channel, _, _) = parse_channel_open_confirmation_payload(open_confirm_parsed.payload)
  
  let success_parsed = packets[2]
  if success_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_SUCCESS { abort(...) }
  
  let data_parsed = packets[3]
  if data_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_DATA { abort(...) }
  let (_, stdout_bytes) = parse_channel_data_payload(data_parsed.payload)
  
  let eof_parsed = packets[4]
  if eof_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_EOF { abort(...) }
  
  let exit_parsed = packets[5]
  if exit_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_REQUEST { abort(...) }
  let (_, exit_code) = parse_exit_status_payload(exit_parsed.payload)
  
  let close_parsed = packets[6]
  if close_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_CLOSE { abort(...) }
  
  let stdout_str = bytes_to_ascii_string(stdout_bytes)
  sock.close()
  // sent_bytes: VERSION + KEXINIT + KEXECDH_INIT + NEWKEYS + USERAUTH_REQUEST (5 packets)
  // recv_bytes: server VERSION + KEXINIT + KEXDH_REPLY + NEWKEYS + post_auth (1 concat = 5+7 = 12 packets)
  // mock server reply 4 packets before USERAUTH, concat 7 after = 11 total
  ...
}
```

### B.2 新增 helper 函数

```moonbit
///| parse N 个连续 SSH packets from SshBuf.feed
fn parse_n_ssh_packets(buf : @sshwire.SshBuf, n : Int) -> Array[@sshwire.SshPacket] {
  let packets : Array[@sshwire.SshPacket] = []
  for i = 0; i < n; i = i + 1 {
    match buf.try_parse() {
      Some(p) => packets.push(p)
      None => abort("parse_n_ssh_packets: failed at \{i}/\{n}")
    }
  }
  packets
}

///| 7 个 post-auth server replies 总长度
fn compute_post_auth_total_length(stdout_msg : String) -> Int {
  let packets = [
    make_server_userauth_success_reply(),
    make_server_channel_open_confirmation_reply(0, 100, 2097152, 32768),
    make_server_channel_success_reply(0),
    make_server_channel_data_reply(0, ascii_bytes(stdout_msg)),
    make_server_channel_eof_reply(0),
    make_server_exit_status_reply(0, 0),
    make_server_channel_close_reply(0),
  ]
  let mut total = 0
  for p in packets {
    total = total + p.length()
  }
  total
}
```

## C. G3 — cmd/ssh_full_ws/main.mbt + host/demo_ssh_full.html + verify_loop23.mjs

### C.1 cmd/ssh_full_ws/moon.pkg (wasm-only exec)
```moonbit
import {
  "openssh/openssh_moonbit/src/sshclient",
  "openssh/openssh_moonbit/src/ws_socket",
  "openssh/openssh_moonbit/src/sshwire",
}
pkgtype(kind: "executable")
```

### C.2 cmd/ssh_full_ws/main.mbt
```moonbit
fn main {
  let ws_url = @env.args()[1]  // e.g. "ws://localhost:2223"
  let (sent, recv, stdout, exit_code, remote_channel) = 
    @sshclient.ssh_client_full_unencrypted_ws("moonbit", "sshpass", "ls", ws_url)
  
  println("=== SSH-WASM-SSH Loop #23 (Full Write Path, ws) ===")
  println("sent_bytes: " + sent.length().to_string())
  println("recv_bytes: " + recv.length().to_string())
  println("stdout: " + stdout)
  println("exit_code: " + exit_code.to_string())
  println("remote_channel: " + remote_channel.to_string())
}
```

### C.3 host/demo_ssh_full.html (浏览器 demo)
- load main.wasm (cmd/ssh_full_ws wasm-gc 产物)
- 同步 ws_shim (与 demo_ssh.html 类似的 host shim)
- 调 MoonBit ssh_client_full_unencrypted_ws
- 打印 stdout + exit_code 到 textContent

### C.4 host/verify_loop23.mjs
```js
// 1. 启动 mock_ssh_server_v2_v2 (port 2223)
// 2. 启动 HTTP server (port 8765)
// 3. 启动 chromium (wasm-gc, chromium-1217)
// 4. page.goto demo_ssh_full.html
// 5. 等 MoonBit 跑完 (sleep 3s)
// 6. page.textContent('#out') → 验证 stdout + exit_code + remote_channel byte-exact
// 7. mock server 端 console.log 验证 client packet 数
```

## D. 字节级 byte-exact 验证

### D.1 mock server 输出
- Client → Server 5 packets (Loop #23 G2 USERAUTH 之后无 client 包)
- Server → Client 4 packets (VERSION + KEXINIT + KEXDH_REPLY + NEWKEYS) before USERAUTH
- Server → Client 7 packets in 1 concat (USERAUTH_SUCCESS + OPEN_CONFIRMATION + SUCCESS + DATA + EOF + exit-status + CLOSE)

### D.2 MoonBit 客户端输出
- stdout byte-exact "hello from mock server (cmd: ls)\n"
- exit_code byte-exact 0
- remote_channel byte-exact 100
- sent_bytes (estimated): VERSION(17) + KEXINIT_packet(~256) + KEXECDH_INIT(37) + NEWKEYS(16) + USERAUTH(~64) = ~390B
- recv_bytes (estimated): server VERSION(21) + KEXINIT_packet(~256) + KEXDH_REPLY(~140) + NEWKEYS(16) + post_auth_7(~150) = ~583B

## E. 4 target byte-exact 维持策略

| 验证 | hash | 状态 |
|---|---|---|
| verify.mjs (Loop #20 cmd/main, native/js/wasm/wasm-gc) | 230bfd5b0c02d682 | 不动 |
| verify_loop22.mjs (Loop #22 cmd/ssh_full, native/js/wasm/wasm-gc) | 4ac5544049c297cf | 不动 |
| verify_loop23.mjs (Loop #23 cmd/ssh_full_ws + verify_e2e + chromium) | 新 hash | 仅 wasm-gc 1 target |

**Loop #23 不破现有 4 target byte-exact** — verify_loop23 是新验证路径,只跑 wasm-gc。

## F. 时间预算

| 任务 | 预估 |
|---|---|
| G1 mock_ssh_server_v2_v2 (concat 7 replies) | 30 min |
| G2 ssh_client_full_unencrypted_ws + helpers | 1 hour |
| G3 demo_ssh_full.html + ws_shim + verify_loop23.mjs | 1-2 hours |
| Loop #23 5 件套文档 | 30 min |
| 总计 | 3-4 hours |