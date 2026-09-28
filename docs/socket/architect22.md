# Loop #22 Architect — SSH client write 侧完整字节级协议闭环 + IDB roundtrip

**Date**: 2026-09-28
**Status**: Architect 设计 → **Verdict**: G1 = src/sshclient/client.mbt 加 ssh_client_full_unencrypted 函数；G2 = host/mock_ssh_server_v2.mjs 状态机 v2；G3 = host/demo_idb.html + host/verify_idb.mjs playwright e2e

## TL;DR

| 子目标 | 模块 | 新增 LOC | 关键产物 |
|---|---|---|---|
| **G1** client 完整 write | src/sshclient/client.mbt (扩展) | ~250 | ssh_client_full_unencrypted + parse functions |
| **G2** mock server v2 | host/mock_ssh_server_v2.mjs (新) | ~250 | state machine v2 (0..7) |
| **G3** IDB roundtrip | host/demo_idb.html + verify_idb.mjs | ~150 | playwright e2e 跨 context byte-exact |

## A. G1 — src/sshclient/client.mbt 扩展

### A.1 新增 payload 构造函数
```moonbit
// RFC 4252 §5 password method
fn userauth_password_payload(user : String, password : String) -> FixedArray[Byte] {
  let s_user = @sshwire.write_ssh_string(ascii_bytes(user))
  let s_service = @sshwire.write_ssh_string(ascii_bytes("ssh-connection"))
  let s_method = @sshwire.write_ssh_string(ascii_bytes("password"))
  let b_true = [b'\x01']
  let s_password = @sshwire.write_ssh_string(ascii_bytes(password))
  concat(concat(concat(concat(s_user, s_service), s_method), b_true), s_password)
}

// RFC 4254 §6.2 pty-req (terminal)
fn channel_request_pty_payload(
  channel : Int, term : String, cols : Int, rows : Int
) -> FixedArray[Byte] {
  let u_chan = @sshwire.write_u32(channel.reinterpret_as_uint())
  let s_type = @sshwire.write_ssh_string(ascii_bytes("pty-req"))
  let b_want = [b'\x01']
  let s_term = @sshwire.write_ssh_string(ascii_bytes(term))
  let u_cols = @sshwire.write_u32(cols.reinterpret_as_uint())
  let u_rows = @sshwire.write_u32(rows.reinterpret_as_uint())
  let u_w = @sshwire.write_u32(0U)
  let u_h = @sshwire.write_u32(0U)
  let s_modes = @sshwire.write_ssh_string(FixedArray::make(0, b'\x00'))
  concat_long([u_chan, s_type, b_want, s_term, u_cols, u_rows, u_w, u_h, s_modes])
}

// RFC 4254 §6.7 env
fn channel_request_env_payload(channel : Int, name : String, value : String) -> FixedArray[Byte] {
  let u_chan = @sshwire.write_u32(channel.reinterpret_as_uint())
  let s_type = @sshwire.write_ssh_string(ascii_bytes("env"))
  let b_want = [b'\x00']
  let s_name = @sshwire.write_ssh_string(ascii_bytes(name))
  let s_val = @sshwire.write_ssh_string(ascii_bytes(value))
  concat_long([u_chan, s_type, b_want, s_name, s_val])
}
```

### A.2 新增回包解析函数
```moonbit
// SSH wire SshBuf.parse → msg_type + payload
// RFC 4252 §5.1 USERAUTH_SUCCESS
fn parse_userauth_success(_packet : SshPacket) -> Bool { true }

// RFC 4254 §5.1 CHANNEL_OPEN_CONFIRMATION
struct ChannelOpenConfirm {
  recipient_channel : Int
  sender_channel : Int
  window_size : Int
  packet_size : Int
}
fn parse_channel_open_confirmation(packet : SshPacket) -> ChannelOpenConfirm { ... }

// RFC 4254 §6.10 exit-status
struct ExitStatus { recipient_channel : Int; exit_code : Int }
fn parse_channel_exit_status(packet : SshPacket) -> ExitStatus { ... }

// RFC 4254 §6.1 CHANNEL_DATA
struct ChannelData { recipient_channel : Int; data : FixedArray[Byte] }
fn parse_channel_data(packet : SshPacket) -> ChannelData { ... }
```

### A.3 ssh_client_full_unencrypted 主函数
```moonbit
pub fn ssh_client_full_unencrypted(
  user : String, password : String, command : String,
) -> (
  FixedArray[Byte],  // sent bytes
  FixedArray[Byte],  // recv bytes
  String,            // decoded stdout
  Int,               // exit_code
  Int,               // remote_channel
) {
  let sock = @socket.MockSocket::make(server_packets_v2);

  // 1. VERSION
  sock.send(ascii_bytes("SSH-2.0-MoonBit\r\n"));
  let _ = sock.read_n(server_version_len);

  // 2. KEXINIT + KEXECDH_INIT + NEWKEYS (复用 kexflow)
  // 3. USERAUTH probe "none" → read USERAUTH_FAILURE
  // 4. USERAUTH final "password" → read USERAUTH_SUCCESS
  // 5. CHANNEL_OPEN session → read CHANNEL_OPEN_CONFIRMATION
  // 6. CHANNEL_REQUEST exec command → read CHANNEL_SUCCESS
  // 7. read CHANNEL_DATA × N + CHANNEL_EOF
  // 8. read CHANNEL_REQUEST exit-status → exit_code
  // 9. read CHANNEL_CLOSE → close

  let stdout = concat_data_chunks(all_data_packets);
  (sent, recv, stdout, exit_code, remote_channel)
}
```

### A.4 server_packets_v2 mock responses
构造 8 个 server reply packets：
1. server VERSION (21 bytes "SSH-2.0-MockSSH_1.0\r\n")
2. server KEXINIT (256 bytes)
3. server KEXDH_REPLY (~140 bytes, deterministic)
4. server NEWKEYS
5. server USERAUTH_FAILURE (allowed: "password")
6. server USERAUTH_SUCCESS
7. server CHANNEL_OPEN_CONFIRMATION
8. server CHANNEL_SUCCESS + DATA "hello world\n" + EOF + exit-status (0) + CLOSE

mock socket 已支持 array[FixedArray[Byte]] 输入。

## B. G2 — host/mock_ssh_server_v2.mjs (新文件)

### B.1 state machine v2 升级
```js
let state = 'VERSION';

ws.on('message', (data) => {
  const bytes = Buffer.from(data);
  switch (state) {
    case 'VERSION':           // state 0
      ws.send(serverVersion);
      state = 'KEXINIT';
      break;
    case 'KEXINIT':           // state 1
      // parse client KEXINIT (verify msg=0x14, cookie + 10 algs)
      ws.send(makeKexInitPacket());
      state = 'KEXECDH_INIT';
      break;
    case 'KEXECDH_INIT':      // state 2
      ws.send(makeKexDhReplyPacket(bytes));
      state = 'NEWKEYS';
      break;
    case 'NEWKEYS':           // state 3
      ws.send(makeSimplePacket(0x15, Buffer.alloc(0)));  // server NEWKEYS
      state = 'USERAUTH_PROBE';
      break;
    case 'USERAUTH_PROBE':    // state 4
      // parse msg=0x32, "none" method
      ws.send(makeUserAuthFailure(['password', 'publickey']));
      state = 'USERAUTH_FINAL';
      break;
    case 'USERAUTH_FINAL':    // state 5
      // parse msg=0x32, "password" method, extract user + password
      ws.send(makeSimplePacket(0x34, Buffer.alloc(0)));  // USERAUTH_SUCCESS
      state = 'CHANNEL_OPEN';
      break;
    case 'CHANNEL_OPEN':      // state 6
      // parse msg=0x5a, "session", sender_channel
      const sender = parseSenderChannel(bytes);
      ws.send(makeOpenConfirmation(sender, 0, 2097152, 32768));
      state = 'CHANNEL_REQUEST';
      break;
    case 'CHANNEL_REQUEST':   // state 7
      // parse msg=0x62, "exec", command
      const cmd = parseExecCommand(bytes);
      ws.send(makeSimplePacket(0x63, writeU32(0)));  // CHANNEL_SUCCESS
      ws.send(makeChannelData(0, `mock output for: ${cmd}\n`));
      ws.send(makeSimplePacket(0x5f, writeU32(0)));  // CHANNEL_EOF
      ws.send(makeExitStatus(0, 0));
      ws.send(makeSimplePacket(0x60, writeU32(0)));  // CHANNEL_CLOSE
      state = 'DONE';
      break;
  }
});
```

### B.2 字节级解析 helper
```js
// 解析 SSH_MSG_USERAUTH_REQUEST
function parseUserauthRequest(bytes) {
  const payload = decodePacketPayload(bytes);  // 跳过 wire framing
  let off = 0;
  const user = readString(payload, off); off += 4 + user.length;
  const service = readString(payload, off); off += 4 + service.length;
  const method = readString(payload, off); off += 4 + method.length;
  // method-specific
  if (method === 'password') {
    const b = payload[off++];
    const password = readString(payload, off);
    return { user, service, method, password };
  }
  return { user, service, method };
}

// 解析 SSH_MSG_CHANNEL_OPEN
function parseChannelOpen(bytes) {
  const payload = decodePacketPayload(bytes);
  let off = 0;
  const type = readString(payload, off); off += 4 + type.length;
  const sender = payload.readUInt32BE(off); off += 4;
  // window + max_packet
  return { type: type.toString(), sender_channel: sender };
}

// 解析 SSH_MSG_CHANNEL_REQUEST exec
function parseChannelRequestExec(bytes) {
  const payload = decodePacketPayload(bytes);
  let off = 0;
  const chan = payload.readUInt32BE(off); off += 4;
  const type = readString(payload, off); off += 4 + type.length;
  const want = payload[off++];
  const cmd = readString(payload, off);
  return { channel: chan, type: type.toString(), want_reply: want === 1, command: cmd.toString() };
}
```

### B.3 字节级构造 server reply packets
```js
function makeUserAuthFailure(methods) {
  const m = Buffer.from(methods.join(',') + '\0', 'utf-8');  // name-list 编码
  const payload = Buffer.concat([writeString(m), Buffer.from([0])]);  // 0 = partial success
  return makeSimplePacket(0x33, payload);
}

function makeOpenConfirmation(recipient, sender, window, max) {
  const p = Buffer.alloc(16);
  p.writeUInt32BE(recipient, 0);
  p.writeUInt32BE(sender, 4);
  p.writeUInt32BE(window, 8);
  p.writeUInt32BE(max, 12);
  return makeSimplePacket(0x5b, p);
}

function makeChannelData(channel, data) {
  const dataBuf = Buffer.from(data, 'utf-8');
  const p = Buffer.concat([writeU32(channel), writeString(dataBuf)]);
  return makeSimplePacket(0x5e, p);
}

function makeExitStatus(channel, code) {
  const p = Buffer.concat([writeU32(channel), writeU32(code)]);
  return makeSimplePacket(0x62, p);  // 0x62 = SSH_MSG_CHANNEL_REQUEST
}
```

## C. G3 — host/demo_idb.html + host/verify_idb.mjs

### C.1 demo_idb.html 升级
- 加 form：input host + input key + button add
- JS function `addHost(host, key)` → idbPut(host, key)
- 启动时 auto-load 已有 entries
- 显示 entries table (host, key, time)

### C.2 verify_idb.mjs playwright 流程
```js
import { chromium } from 'playwright';

const browser = await chromium.launch();

// page 1: 写
const ctx1 = await browser.newContext();
const page1 = await ctx1.newPage();
await page1.goto('http://localhost:8765/demo_idb.html');
await page1.fill('#host', 'demo.example.com');
await page1.fill('#key', 'AAAA-ed25519-...');
await page1.click('#add');
await ctx1.close();  // IDB 持久化

// page 2: 新 context,模拟刷新/重启
const ctx2 = await browser.newContext();
const page2 = await ctx2.newPage();
await page2.goto('http://localhost:8765/demo_idb.html');
const persisted = await page2.evaluate(() => idbGet('demo.example.com'));
assert(persisted === 'AAAA-ed25519-...', `expected AAAA..., got: ${persisted}`);

console.log('[idb-roundtrip] ✓ PASS');
await browser.close();
```

### C.3 字节级比较
- 不只比较字符串,验证 bytes 0x41 == 0x41 (UTF-8 字节)
- 使用 Buffer.from(persisted, 'hex') 做字节对比

## D. 验证策略

### D.1 verify_loop22.mjs (新)
```js
// 1. build cmd/main 4 target × 2 mode
// 2. build cmd/ssh_full 4 target × 2 mode
// 3. 跑 cmd/ssh_full 输出 (USERAUTH/CHANNEL/DATA/EXIT 字节)
// 4. 计算 hash + 比对 8 outputs

const mainHash = ...; // 230bfd5b0c02d682 (Loop #20 维持)
const sshFullHash = ...; // Loop #22 新 hash

// 字节级验证 mock server 返回的 reply packets
// mock server 跑一次,接收 client packets → state machine 状态切换 → 回包
// 客户端 decode 回包 → 提取 stdout + exit_code → 验证

const expectedStdout = 'mock output for: ls\n';
const expectedExitCode = 0;
const actualStdout = ...; // 客户端收到
const actualExitCode = ...;
assert(actualStdout === expectedStdout);
assert(actualExitCode === expectedExitCode);
```

### D.2 verify_idb.mjs (新)
- playwright 跨 context 字节级 IDB 验证

### D.3 verify_e2e.mjs (Loop #21, 维持 6/6 PASS)
- 维持 6/6 PASS — 不破现有验证

## E. 8 outputs byte-exact 维持策略

| 文件 | 状态 |
|---|---|
| cmd/main/main.mbt | 不动（维持 12 行 hash 230bfd5b0c02d682） |
| cmd/main/moon.pkg | 不动 |
| src/sshclient/client.mbt | 扩展（加 ssh_client_full_unencrypted + parse helpers）|
| host/mock_ssh_server.mjs | 维持（demo loopback）|
| host/mock_ssh_server_v2.mjs | 新增（完整 write 侧状态机）|
| host/demo_idb.html | 升级（加 form）|
| host/verify.mjs | 不动 |
| host/verify_loop22.mjs | 新增 |
| host/verify_idb.mjs | 新增 |
| host/verify_e2e.mjs | 维持（不破 6/6 PASS）|

## F. 时间预算

| 任务 | 预估 |
|---|---|
| G1 client.mbt 扩展 + parse functions | 2-3 hours |
| G2 mock_ssh_server_v2.mjs | 1-2 hours |
| G3 demo_idb.html 升级 + verify_idb.mjs | 1 hour |
| verify_loop22.mjs + 4 target 跑通 | 1 hour |
| 文档 (5 件套) | 1 hour |
| 总计 | 6-8 hours |