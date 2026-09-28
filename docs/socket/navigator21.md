# Loop #21 Navigator — WebTransport + 浏览器 e2e + IndexedDB

**Date**: 2026-09-24
**Status**: Navigator 调研中
**Verdict**: 三件大事:(1) WebTransport 双实现补齐 Loop #18 选项;(2) playwright e2e 真实浏览器验证;(3) 真 IndexedDB known_hosts 持久化

## TL;DR

| 子目标 | 实现路径 | 状态 |
|---|---|---|
| WebTransport 浏览器 API | `new WebTransport(url)` + `createBidirectionalStream()` | 可行 |
| playwright chromium e2e | npx playwright install + verify_e2e.mjs 启动 demo_ssh.html | 可行 (~150 MB) |
| 真 IndexedDB known_hosts | browser IDB API + sync wrapper host shim | 可行 |
| 4 target byte-exact 维持 | MockSocket path 不变 + 新增 WtSocket | 4 target 不破坏 |

## A. WebTransport 浏览器 API

### A.1 WebTransport API (W3C)
```js
const transport = new WebTransport('https://localhost:443');
await transport.ready;

const stream = await transport.createBidirectionalStream();
const writer = stream.writable.getWriter();
const reader = stream.readable.getReader();

await writer.write(new Uint8Array([...]));
const { value, done } = await reader.read();
```

### A.2 SSH 协议 vs WebTransport stream
- SSH 是 byte stream protocol (RFC 4253 §6)
- WebTransport bidirectional stream 是 raw byte stream (similar to TCP)
- 比 WebSocket 更接近 raw socket,无 framing overhead
- 需要 HTTPS + HTTP/3 部署 (Chrome 97+, Edge 97+, Firefox 114+, Safari 17.4+)

### A.3 MoonBit 端 extern
类似 ws_socket 模式:
```moonbit
// src/wt_socket/socket.mbt
extern "wasm" fn wt_connect_extern(url_ptr : Int, url_len : Int) -> Int =
  "moonbit_wt" "wt_connect"

extern "wasm" fn wt_send_extern(handle : Int, bytes_ptr : Int, len : Int) -> Int =
  "moonbit_wt" "wt_send"

extern "wasm" fn wt_recv_into_extern(handle : Int, out_ptr : Int, n : Int) -> Int =
  "moonbit_wt" "wt_recv_into"

extern "wasm" fn wt_close_extern(handle : Int) -> Int =
  "moonbit_wt" "wt_close"
```

### A.4 浏览器 demo_wt.html
```js
const wtInstances = new Map();
const wtStreams = new Map();

const imports = {
  moonbit_wt: {
    wt_connect: (urlPtr, urlLen) => {
      const url = new TextDecoder().decode(...);
      const wt = new WebTransport(url);
      // 异步 ready,需要 host shim 内同步等待
      // 简化:同步 polling (Loop #17 host shim for-await pattern)
      const stream = wt.createBidirectionalStream();  // async
      // host shim 内部 Promise + 同步标志
      ...
    },
    ...
  },
};
```

### A.5 mock server 加 WebTransport 支持
- Node.js 没有 WebTransport 实现(需要 HTTP/3 server)
- **简化**: Loop #21 WebTransport 只在浏览器 + mock HTTP/3 proxy server 验证
- 或: WebTransport server 用 `node:http3` (实验) 或 `cloudflare/quiche` (Rust FFI)
- **诚实选择**: Loop #21 WebTransport host shim 接口 ready,实际 e2e 用 WebSocket path(WebTransport server 太复杂)
- 浏览器 demo_wt.html 实现完整 client side (HTML/JS)
- 不在 mock server 端模拟 WebTransport

## B. Playwright chromium e2e 验证

### B.1 playwright install
```
$ npx playwright install chromium
Chrome for Testing 145.0.7632.6 (~150 MB)
```

### B.2 verify_e2e.mjs 脚本
```js
// 1. 启 mock_ssh_server.mjs (后台, port 2222)
import { spawn } from 'node:child_process';
const server = spawn('node', ['host/mock_ssh_server.mjs']);

await new Promise(r => setTimeout(r, 1000)); // wait server up

// 2. 启 python http.server (serve host/)
import { spawn } from 'node:child_process';
const http = spawn('python', ['-m', 'http.server', '8000', '--directory', 'host']);
await new Promise(r => setTimeout(r, 500));

// 3. playwright launch chromium + fetch demo_ssh.html
import { chromium } from 'playwright';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

// 4. 启 console.log capture
const logs = [];
page.on('console', msg => logs.push(msg.text()));

// 5. 启 WS server log (mock_ssh_server stdout)
const serverOut = [];
server.stdout.on('data', d => serverOut.push(d.toString()));

// 6. 访问 demo_ssh.html
await page.goto('http://127.0.0.1:8000/demo_ssh.html');
await page.waitForTimeout(2000); // wait demo complete

// 7. 验证:
// - browser console 显示 SSH-WASM Demo 输出
// - mock server stdout 收到 client bytes (16B version + KEXINIT + KEXECDH_INIT + NEWKEYS)

// 8. cleanup
await browser.close();
http.kill();
server.kill();
```

### B.3 字节级 e2e 验证
- **客户端发出**:16B version + 256B KEXINIT + 37B KEXECDH_INIT + 12B NEWKEYS = 321B (前 4 个 unencrypted packet)
- **服务端收到**:同 321B
- **匹配**:byte-exact 等

## C. 真 IndexedDB known_hosts

### C.1 IndexedDB API (浏览器原生, 异步)
```js
const db = await new Promise((resolve, reject) => {
  const req = indexedDB.open('openssh', 1);
  req.onsuccess = () => resolve(req.result);
  req.onerror = () => reject(req.error);
});

// Schema migration
db.onupgradeneeded = (e) => {
  e.target.result.createObjectStore('known_hosts');
};

// Read
const tx = db.transaction('known_hosts', 'readonly');
const store = tx.objectStore('known_hosts');
const value = await new Promise((resolve, reject) => {
  const req = store.get('example.com');
  req.onsuccess = () => resolve(req.result);
});

// Write
const tx2 = db.transaction('known_hosts', 'readwrite');
tx2.objectStore('known_hosts').put('example.com ssh-ed25519 AAA...', 'example.com');
await new Promise((resolve, reject) => {
  tx2.oncomplete = () => resolve();
});
```

### C.2 同步 wrapper (MoonBit extern 同步接口)

host shim 内部维护 `Map<key, value>` + IndexedDB 持久化:
```js
const idbCache = new Map();
let idbReady = false;

// Init: load all from IDB into cache
const req = indexedDB.open('openssh', 1);
req.onsuccess = () => {
  const db = req.result;
  const tx = db.transaction('known_hosts', 'readonly');
  tx.objectStore('known_hosts').getAll().onsuccess = (e) => {
    // populate idbCache
    idbReady = true;
  };
};

const imports = {
  moonbit_idb: {
    idb_open: () => { /* sync: return handle */ },
    idb_get: (handle, keyPtr, keyLen) => {
      if (!idbReady) return 0; // not loaded yet
      const key = new TextDecoder().decode(...);
      const val = idbCache.get(key);
      if (!val) return 0;
      // 写 key + value 到 wasm 内存
      return val.length;
    },
    idb_put: (handle, keyPtr, keyLen, valPtr, valLen) => {
      const key = new TextDecoder().decode(...);
      const val = new TextDecoder().decode(...);
      idbCache.set(key, val);
      // 异步持久化到 IDB
      persist_to_idb(key, val);
      return 0;
    },
    idb_list_keys: () => { /* return count */ },
    idb_close: () => { /* cleanup */ },
  },
};
```

### C.3 MoonBit 端接口
```moonbit
// src/knownhosts_store/store.mbt (扩 Loop #19 准备好的 extern)
extern "wasm" fn idb_open() -> Int =
  "moonbit_idb" "open"

extern "wasm" fn idb_count(handle : Int) -> Int =
  "moonbit_idb" "count"

extern "wasm" fn idb_close(handle : Int) -> Int =
  "moonbit_idb" "close"
```

### C.4 限制
- IDB 数据是异步;MoonBit 端同步 → host shim 用 in-memory cache 同步返回
- 首次打开 IDB 异步 load → 后续 sync OK
- 数据持久化在浏览器重启后仍存在 (IDB 真实持久化)

## D. 实施路径

1. **src/wt_socket/socket.mbt** — WebTransport + extern wasm (wasm-gc only, 类似 ws_socket)
2. **host/demo_wt.html** — 浏览器 WebTransport demo (mock 不连)
3. **src/knownhosts_store/store.mbt** — 真 extern wasm idb_open/count/close (Loop #19 已写接口)
4. **host/idb_host.js** — 浏览器 IndexedDB sync wrapper
5. **host/demo_idb.html** — 浏览器 IndexedDB demo (load/store known_hosts)
6. **npx playwright install chromium** — install playwright
7. **verify_e2e.mjs** — playwright 启动 demo_ssh.html + mock server, 验证 client↔server 字节路径
8. **4 target byte-exact** 维持 MockSocket path

## E. 风险评估

| 风险 | 缓解 |
|---|---|
| playwright chromium 安装 150 MB | npm install 一次性,后续 test 用 |
| WebTransport 无 Node.js server | WebTransport client side only demo (server 留 Loop #21+) |
| IDB async vs MoonBit sync | host shim in-memory cache (sync read, async write) |
| e2e verify 时序 | mock server 先 up, demo sleep 1-2s 等 SSH client 跑完 |

## F. 不在本 Loop 范围 (诚实记录)

1. **WebTransport server (HTTP/3)** — Node.js 无原生支持,留 Loop #22+
2. **真 sshd 连通测试** — 留 Loop #22+ (需要本地 sshd 部署)
4. **KRL (Key Revocation List)** — 留 Loop #22+
5. **cert chain 验证** — 留 Loop #22+

## G. 决策点 (待用户确认)

### G1: WebTransport e2e 范围?
- A: 浏览器 demo_wt.html 完整 client (mock 不连,只为接口)
- B: 浏览器 demo + 简单 Node.js HTTP/3 proxy (loop back)
- C: 留 Loop #22+ (HTTP/3 server 复杂)

### G2: playwright e2e 验证范围?
- A: 验证 client → mock server 字节路径 (server stdout diff)
- B: 加验证 client → server → client echo (字节级别)
- C: 加验证 IDB 持久化 roundtrip

### G3: IndexedDB 范围?
- A: 浏览器 IDB 真实持久化 + 字节流验证
- B: host shim in-memory cache only (4 target 一致,真持久化留 Loop #22+)
- C: 仅写代码,不接入 cmd/main

## I. 量化目标

| 指标 | 值 |
|---|---|
| WebTransport host shim | ~80 行 |
| IndexedDB host shim | ~60 行 |
| demo_wt.html | ~80 行 |
| demo_idb.html | ~60 行 |
| verify_e2e.mjs | ~100 行 |
| 4 target byte-exact | 维持 (MockSocket path) |
| e2e 验证 | 字节路径 PASS |
| Loop 时长 | 3-5 hours |

## 待用户确认

- G1: WebTransport e2e 范围?
- G2: playwright e2e 验证范围?
- G3: IndexedDB 范围?