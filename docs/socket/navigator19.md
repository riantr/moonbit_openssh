# Loop #19 Navigator — NEWKEYS 真实加密 + IndexedDB known_hosts

**Date**: 2026-09-23
**Status**: Navigator 调研中
**Verdict**: NEWKEYS 后启用 chacha20-poly1305@openssh.com 真实加密(已实现基础);IndexedDB known_hosts 持久化方案待定

## TL;DR

Loop #19 推进 SSH-WASM-SSH 项目的**协议层真实加密 + 浏览器持久化**:

| 子目标 | 现状 | 在本 Loop |
|---|---|---|
| NEWKEYS 后启用 chacha20-poly1305 | bpacket.SendCtx/RecvCtx 完整实现 + ChachaPolyCtx (Loop #7-8-12) | ✅ 集成到 sshclient |
| sshclient 重构用 SendCtx.emit | sshclient 直接调 @sshwire.make_packet (unencrypted) | ✅ 重构 |
| IndexedDB known_hosts | moon 0.10.12 extern wasm 复杂,async 不兼容 | ⏸️ 部分 (mock 验证 4 target byte-exact) |

## 现有基础 (无需重写)

### bpacket.SendCtx / RecvCtx (Loop #10)
- `SendCtx::new()` 初始化 Unencrypted mode, seqnr=0
- `SendCtx::emit(msg_type, payload, pad_src)` 返回 `SentPacket { frame, wire }`,wire 是字节级加密 SSH packet
- `SendCtx::set_mode(Aead(ctx))` 在 NEWKEYS 后切换 AEAD 模式
- `RecvCtx::recv(input)` 流式解析,返回 `RecvResult { consumed, event }` with `NeedMore / Packet / Failed`

### ChachaPolyCtx (Loop #8 AEAD)
- `ChachaPolyCtx::new64(key)` 64-byte key → main_key(32) + header_key(32)
- `ChachaPolyCtx::crypt(seqnr, src, aadlen, datalen, do_encrypt)` → 加密/解密 bytes
- `ChachaPolyCtx::get_length(seqnr, hdr_ct)` → 解密 4-byte 包头得到 packlen

### kexflow.flow_on_reply (Loop #12)
- 返回 `Established { session_id, keys: DerivedKeys, newkeys_msg }`
- `DerivedKeys.iv_ctos/iv_stoc/enc_key_ctos/enc_key_stoc/mac_key_ctos/mac_key_stoc`
- chacha20-poly1305@openssh.com 用 main_key + header_key(各 32 bytes),所以 `ChachaPolyCtx::new64(enc_key_ctos)`

## SSH 协议加密路径 (NEWKEYS 后)

### RFC 4253 §6 + chacha20-poly1305@openssh.com
```
client → server NEWKEYS  (Unencrypted mode, seqnr=0)
server → client NEWKEYS  (Unencrypted mode, seqnr=0)
双方切换到 AEAD mode:
  SendCtx::set_mode(Aead(ChachaPolyCtx::new64(enc_key_ctos)))
  RecvCtx::set_mode(Aead(ChachaPolyCtx::new64(enc_key_stoc)))
USERAUTH_REQUEST (Aead mode, seqnr=1)
  SendCtx::emit(50, userauth_request_payload, random_padding)
  → wire bytes (含 16-byte poly1305 tag)
CHANNEL_OPEN (Aead mode, seqnr=2)
...
```

### ChachaPolyCtx key 派生 (RFC 4253 §7.2)
- enc_key_ctos = SHA-256(K || H || "C" || session_id) 前 64 bytes (chacha32 + poly 头)
- iv_ctos = SHA-256(K || H || "A" || session_id) (16 bytes,但 chacha20-poly1305 用 seqnr 直接做 IV)
- mac_key_* 不需要 (AEAD 包含 MAC)

### 加密字节级验证
- 4 target 跑同样 deterministic shared K + H + session_id
- 派生的 enc_key_ctos byte-exact 一致
- chacha20-poly1305 ciphertext byte-exact 一致
- 4 target × 2 mode = 8 outputs byte-exact

## IndexedDB known_hosts 方案

### 浏览器 IndexedDB API
```js
const db = await indexedDB.open('openssh', 1);
db.onupgradeneeded = (e) => {
  e.target.result.createObjectStore('known_hosts');
};
const tx = db.transaction('known_hosts', 'readonly');
const store = tx.objectStore('known_hosts');
const getReq = store.get('example.com');
getReq.onsuccess = () => console.log(getReq.result);
```

### MoonBit 端接口
```moonbit
// src/knownhosts_idb/idb.mbt

///| Open IndexedDB database "openssh" + create object store "known_hosts"
extern "wasm" fn idb_open() -> Int = "moonbit_idb" "open"

///| Get known_hosts entry by host_pattern
extern "wasm" fn idb_get(db : Int, key : String) -> String =
  "moonbit_idb" "get"

///| Put known_hosts entry (host_pattern → entries JSON)
extern "wasm" fn idb_put(db : Int, key : String, value : String) -> Int =
  "moonbit_idb" "put"

///| List all keys
extern "wasm" fn idb_keys(db : Int) -> String =
  "moonbit_idb" "keys"

///| Delete entry
extern "wasm" fn idb_delete(db : Int, key : String) -> Int =
  "moonbit_idb" "delete"
```

### Host shim (浏览器 + Node.js)
- **浏览器**: 真 IndexedDB API
- **Node.js**: 内存 hash map 模拟 (byte-exact 验证)
- **cmd/main 4 target**: 用 Node.js 模拟 IDB,字节级一致

### 问题: MoonBit 异步 + extern
MoonBit `extern "wasm" fn idb_open() -> Int` 是同步,但浏览器 IndexedDB 是 async (返回 IDBRequest)。

**两个方案**:
1. **异步 extern** — MoonBit 0.10.12 extern 不支持 async,需要 moon 编译器升级
2. **同步轮询** — host shim 内部 polling,直到 IDBRequest 完成才返回

**简化方案** (Loop #19): 用 **synchronous in-memory mock** 替代 IndexedDB:
- host shim 在 JS 侧维护一个 hash table
- MoonBit 调 extern shim 直接读写 hash table (同步)
- **真 IndexedDB 集成留 Loop #21+** 等 moon 编译器支持 wasm async extern

## 风险评估

| 风险 | 概率 | 缓解 |
|---|---|---|
| bpacket SendCtx.emit 与 sshwire make_packet 输出不一致 | 低 | send.mbt + recv.mbt 已 loop #10 闭环 byte-exact |
| ChachaPolyCtx key 派生 byte-exact 不一致 | 低 | kexc25519.derive_keys 已 RFC 4253 KAT byte-exact |
| MoonBit struct mut field 复杂 | 中 | SendCtx/RecvCtx 已用 priv mut,直接复用 |
| IndexedDB 浏览器异步 mock 难 | 高 | Loop #19 同步 hash map mock,真 IDB 留 Loop #21+ |
| sshclient 重构破坏 Loop #18 byte-exact | 中 | 保留 mock flow 入口 + 新增 AEAD 入口,4 target byte-exact 两边验证 |

## 决策点 (待用户确认)

1. **D1**: sshclient 重构策略?
   - 完整集成 SendCtx/RecvCtx (重构后 chacha20-poly1305 真实加密 + 4 target byte-exact)
   - 新增独立 sshclient_aead demo (并行,不破坏 Loop #18)
2. **D2**: IndexedDB 实现?
   - 同步 hash map mock (Loop #19 内,4 target 一致,真 IDB 留 Loop #21+)
   - MoonBit async 集成 (Loop #21+ 等 moon 升级)
3. **D3**: 验证目标?
   - 4 target × 2 mode byte-exact 加密 SSH wire (sshclient_aead)
   - 浏览器 known_hosts 持久化端到端 (留 Loop #21+)

## 不在本 Loop 范围 (诚实记录)

1. **真实 IndexedDB API 集成** — MoonBit extern 不支持 async,留 Loop #21+ 等 moon 升级
2. **WebSocket host shim** — 留 Loop #21
3. **mock SSH server (Node.js)** — 留 Loop #21
4. **浏览器 demo HTML** — 留 Loop #21
5. **真实 sshd 连通** — 留 Loop #20+
6. **cert chain / KRL / write 侧** — 留 Loop #21+

## Loop #19 衔接

| | Loop #18 | **Loop #19** | Loop #21+ |
|---|---|---|---|
| 焦点 | SSH wire + mock flow (unencrypted) | **NEWKEYS 后 chacha20-poly1305 + IDB mock** | WebSocket + 真 IDB + browser demo |
| 改代码? | ✅ | **✅** (sshclient + new idb) | ✅ |
| 验证 | 8 outputs byte-exact (c9d33d0f2cd2f92c) | **8 outputs byte-exact (加密 SSH wire + IDB mock)** | 浏览器 end-to-end |
| 加密层 | Unencrypted mode only | **Aead mode enabled** | 全部 target 跑 Aead |
| 持久化 | 无 | **同步 hash map mock** | 真 IndexedDB (Loop #21+) |

## 量化目标

| 指标 | 值 |
|---|---|
| sshclient 重构 | ~100 行新增 (SendCtx 集成) |
| 加密 SSH wire byte-exact | 必须 (4 target × 2 mode = 8) |
| IndexedDB mock | ~50 行 (host shim) |
| MoonBit extern | ~5 个 (idb_open/get/put/keys/delete) |
| 4 target byte-exact | 必须 |
| Loop 时长 | 2-3 hours |

## 待用户确认

请确认:
- D1: sshclient 重构策略 (重构 vs 新增 demo)?
- D2: IndexedDB 实现策略 (同步 mock vs 留 Loop #21+)?
- D3: 验证目标 (字节级加密 SSH wire vs 真 IDB)?