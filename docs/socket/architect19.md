# Loop #19 Architect v2 — NEWKEYS 真实加密 + Known Hosts Mock Store

**Date**: 2026-09-23
**Status**: Architect v2 — 实测降级
**Verdict**: D1 sshclient 重构集成 chacha20-poly1305;D2 同步 hash map mock store (真 IDB/sqlite3 moon v0.10.12 不兼容)

## TL;DR

| 子目标 | 选定 | 备注 |
|---|---|---|
| **D1 sshclient 重构** | ✅ 集成 SendCtx/RecvCtx + ChachaPolyCtx | Loop #10 bpacket 已有,直接复用 |
| **D2 known_hosts 持久化** | 同步 hash map mock | 真 IDB/sqlite3 留 Loop #21+ (moon 升级后) |

## 关键发现 (实测诚实记录)

### moonbit-community/sqlite3 不可用
- sqlite3@0.2.2 依赖 `moonbitlang/async@0.21.2`
- 实测 `moon run cmd/sqlite3 --target native` 触发 `eprintln unbound` 编译错误 (与 Loop #18 ws_test 同款)
- sqlite3 在 wasm 上需要 `moonrun with PR #2185`,moonrun 0.1.20260904 不确定是否包含

### MoonBit extern wasm 异步限制
- MoonBit extern wasm fn 是同步调用
- IndexedDB 异步回调无法直接包装为 extern

### 降级方案:同步 host shim + JS hash map
- 浏览器 / Node.js 都维护一个 JS Map<string, Uint8Array>
- MoonBit extern wasm fn 同步读写 (fetch → read_at_offset, put_at_offset, etc.)
- 4 target byte-exact 验证 known_hosts 字节路径

## A. sshclient 重构 (D1)

### A.1 SSH client flow (加密后)

```
1. (Unencrypted mode):
   - 发送 client version
   - 收 server version
   - 发 KEXINIT (msg_type 0x14, payload 241 bytes)
   - 收 server KEXINIT
   - 发 KEXECDH_INIT (msg_type 0x1e + Q_C)
   - 收 KEXDH_REPLY (mock: deterministic K_S + Q_S + sig)
   - 发 NEWKEYS (msg_type 0x15, payload 0 bytes)
   - 收 NEWKEYS
   - 切换到 Aead mode:
       SendCtx::set_mode(Aead(ChachaPolyCtx::new64(enc_key_ctos)))
       RecvCtx::set_mode(Aead(ChachaPolyCtx::new64(enc_key_stoc)))

2. (Aead mode, seqnr = 1):
   - emit USERAUTH_REQUEST (msg_type 0x32, payload ~30 bytes)
   - wire = SendCtx.emit(...) → 含 16-byte poly1305 tag
   - sock.send(wire)

3. (Aead mode, seqnr = 2):
   - emit CHANNEL_OPEN (msg_type 0x5a, payload ~25 bytes)
   - wire = SendCtx.emit(...)
   - sock.send(wire)

4. (Aead mode, seqnr = 3):
   - emit CHANNEL_REQUEST exec (msg_type 0x62, payload ~14 bytes)
   - wire = SendCtx.emit(...)
   - sock.send(wire)
```

### A.2 SendCtx.emit API (Loop #10 bpacket)

```moonbit
pub fn SendCtx::emit(
  self : SendCtx,
  msg_type : Byte,
  payload : FixedArray[Byte],
  pad_src : FixedArray[Byte],  // random padding source (deterministic for byte-exact)
) -> EmitResult

// Returns:
pub struct SentPacket {
  frame : FixedArray[Byte]  // plaintext frame (4+packlen bytes)
  wire : FixedArray[Byte]   // encrypted wire bytes (含 16-byte poly1305 tag)
}
```

### A.3 key derivation (RFC 4253 §7.2)
- enc_key_ctos = SHA-256(K || H || "C" || session_id)[:64]
- enc_key_stoc = SHA-256(K || H || "D" || session_id)[:64]
- ChachaPolyCtx::new64(key) → main_key(32) + header_key(32)

### A.4 mock server (mock server 提供 encrypted reply)
Loop #19 mock server 加密所有 server → client 消息用 enc_key_stoc:
- 服务器 KEY = SHA-256(K || H || "D" || session_id)[:64]
- 服务器 ChachaPolyCtx::new64(server_KEY)
- USERAUTH_SUCCESS (msg_type 0x34) → wire bytes

**关键**:Loop #19 mock server 与 client 共享 K + H + session_id,保证 byte-exact。

## B. known_hosts 同步 hash map mock (D2 降级)

### B.1 MoonBit 端接口 (src/knownhosts_store/)

```moonbit
// 同步 hash map:host_pattern -> known_hosts_lines (string)
extern "wasm" fn khs_open(path : String) -> Int =
  "moonbit_khs" "open"

extern "wasm" fn khs_load_all(handle : Int) -> String =
  "moonbit_khs" "load_all"

extern "wasm" fn khs_put(handle : Int, line : String) -> Int =
  "moonbit_khs" "put"

extern "wasm" fn khs_close(handle : Int) -> Int =
  "moonbit_khs" "close"

///| 高层 API (MoonBit 端)
pub fn load_known_hosts(path : String) -> Array[String] {
  let h = khs_open(path)
  let all = khs_load_all(h)
  ignore(khs_close(h))
  // 按行 split
  split_lines(all)
}
```

### B.2 Host shim (浏览器 + Node.js)

```js
// host/knownhosts_store.js
const khsInstances = new Map();
let nextHandle = 1;

const imports = {
  moonbit_khs: {
    open: (pathPtr, pathLen) => {
      const path = readString(pathPtr, pathLen);
      const h = nextHandle++;
      khsInstances.set(h, { path, lines: [] });
      return h;
    },
    load_all: (handle) => {
      const inst = khsInstances.get(handle);
      return inst.lines.join('\n');
    },
    put: (handle, linePtr, lineLen) => {
      const inst = khsInstances.get(handle);
      const line = readString(linePtr, lineLen);
      inst.lines.push(line);
      return 0;
    },
    close: (handle) => {
      khsInstances.delete(handle);
      return 0;
    },
  },
};
```

### B.3 cmd/main 集成

```moonbit
// 在 sshclient_run 之前,从 known_hosts store 加载条目
let khs_lines = load_known_hosts("~/.ssh/known_hosts")
let entries = parse_known_hosts_lines(khs_lines)  // @knownhosts 包

// 用 entries 做 host_key_check
let host_status = @knownhosts.check_host_key_strict(
  entries, "demo", 22, server_hostkey_blob, false,
)
```

但 Loop #19 mock server 不能 sign,所以完整 host_key_check 不实际跑,只验证 known_hosts 字节路径(byte-exact)。

## C. cmd/main 输出 (12 行 byte-exact)

```
=== SSH-WASM Demo (Loop #19) ===
client_pub: 8520f009...
server_pub: d13f5c5b...
shared_K: 7bda42e8...
kexinit_len: 241
kexinit_head16: 01020304...
kexdh_init_len: 37
kexdh_init: 1e00000020...
userauth_wire_len: ~50     (NEW: AEAD encrypted)
channel_open_wire_len: ~40 (NEW: AEAD encrypted)
channel_exec_wire_len: ~30 (NEW: AEAD encrypted)
client_sent_total_len: ~580 (NEW: 含 AEAD tag)
```

## D. 4 target byte-exact 验证

```
$ node host/verify.mjs
✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: NEW_KEY)
```

## E. 风险评估

| 风险 | 概率 | 缓解 |
|---|---|---|
| SendCtx.emit 输出与 mock server decrypt 不一致 | 中 | bpacket + ChachaPolyCtx 已有 byte-exact 闭环 (Loop #10) |
| known_hosts mock host shim 内存 hash table 字节级一致 | 低 | 简单 KV 同步实现,4 target 一致 |
| padding 字节与 mock server 不同 | 中 | 用确定性 padding (0x00 字节),byte-exact |
| moonbit 编译 khs extern wasm 在 4 target 都跑通 | 中 | Loop #17 + #18 fd_write/print_char extern 已闭环 |

## F. 决策 D1-D5

| # | 决策 | 选定 |
|---|---|---|
| D1 | sshclient 集成 SendCtx/RecvCtx | ✅ |
| D2 | known_hosts 持久化 | 同步 hash map mock (Loop #21+ 真 IDB) |
| D3 | 加密层验证 | 4 target × 2 mode byte-exact (12 行 hex dump) |
| D4 | 浏览器 demo | Loop #21+ (WebSocket host shim 一起做) |
| D5 | mock server 加密 | Loop #18 mock + 用 server enc_key_stoc 加密 reply |

## G. 文件产出清单

```
openssh_moonbit/
├── src/sshclient/
│   └── client.mbt             (改: 集成 SendCtx + ChachaPolyCtx)
├── src/knownhosts_store/      (新增)
│   ├── moon.pkg
│   └── store.mbt              (MoonBit extern khs_xxx)
├── cmd/main/
│   ├── main.mbt               (改: AEAD 加密 + known_hosts load)
│   └── moon.pkg
└── docs/socket/
    ├── navigator19.md
    ├── architect19.md
    ├── reviewer19.md
    ├── reality_checker19.md
    └── loop19-summary.md
```

## H. 量化目标

| 指标 | 值 |
|---|---|
| sshclient 加密重构 | ~80 行新增 |
| knownhosts_store | ~50 行 |
| mock server 加密 reply | ~30 行 |
| cmd/main 12 行 byte-exact | 必须 |
| 4 target × 2 mode | byte-exact PASS |
| Loop 时长 | 2-3 hours |