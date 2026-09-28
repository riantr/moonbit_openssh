# Loop #21 Architect — WebTransport + Playwright E2E + IndexedDB

**Date**: 2026-09-28
**Status**: Architect 完成 — 三件大事详细规格
**Verdict**: WebTransport 接口 ready + playwright 端到端验证 Loop #20 + 真 IndexedDB 持久化

## TL;DR

| 子目标 | 范围 | 状态 |
|---|---|---|
| WebTransport (Loop #18 选) | MoonBit extern + 浏览器 demo (client only) | ✅ 实施 |
| playwright e2e 验证 (Loop #21 推荐) | 启 demo_ssh.html + mock server, 验证 client ↔ server 字节 | ✅ **优先** |
| 真 IndexedDB (Loop #19 降级) | 浏览器 IDB API + sync wrapper host shim | ✅ 实施 |

## A. Playwright E2E 验证 (优先级 1)

### A.1 步骤

```bash
# 1. 装 playwright + chromium
$ npm install playwright --save-dev  # 添加到 package.json
$ npx playwright install chromium      # 装 chromium binary (~150 MB)
```

### A.2 verify_e2e.mjs 脚本

```js
// host/verify_e2e.mjs
import { spawn } from 'node:child_process';
import { chromium } from 'playwright';
import { readFile } from 'node:fs/promises';

console.log('[e2e] starting mock SSH server...');
const mockServer = spawn('node', ['host/mock_ssh_server.mjs'], {
  stdio: ['ignore', 'pipe', 'pipe'],
});

const mockServerLogs = [];
mockServer.stdout.on('data', (d) => mockServerLogs.push(d.toString()));
mockServer.stderr.on('data', (d) => mockServerLogs.push(d.toString()));

// wait server up
await new Promise((r) => setTimeout(r, 1500));

console.log('[e2e] starting HTTP server...');
const httpServer = spawn('python', ['-m', 'http.server', '8765', '--bind', '127.0.0.1'], {
  cwd: 'host',
  stdio: ['ignore', 'pipe', 'pipe'],
});

await new Promise((r) => setTimeout(r, 500));

console.log('[e2e] launching chromium...');
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();

// Capture browser console output
const browserLogs = [];
page.on('console', (msg) => {
  browserLogs.push(`[browser ${msg.type()}] ${msg.text()}`);
});

// Capture browser WebSocket frames
const browserWsFrames = [];
page.on('websocket', (ws) => {
  console.log(`[e2e] WS opened: ${ws.url()}`);
  ws.on('framesent', (e) => {
    const payload = e.payload;
    let bytes = null;
    if (payload instanceof Buffer) bytes = Array.from(payload);
    else if (payload instanceof ArrayBuffer) bytes = Array.from(new Uint8Array(payload));
    if (bytes) {
      const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
      console.log(`[e2e] WS→server ${bytes.length}B: ${hex.substring(0, 60)}`);
      browserWsFrames.push(bytes);
    }
  });
  ws.on('framereceived', (e) => {
    const payload = e.payload;
    let bytes = null;
    if (payload instanceof Buffer) bytes = Array.from(payload);
    else if (payload instanceof ArrayBuffer) bytes = Array.from(new Uint8Array(payload));
    if (bytes) {
      const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
      console.log(`[e2e] WS←server ${bytes.length}B: ${hex.substring(0, 60)}`);
    }
  });
});

console.log('[e2e] navigating to demo_ssh.html...');
await page.goto('http://127.0.0.1:8765/demo_ssh.html');

// wait for SSH demo to complete (3-5 seconds)
await page.waitForTimeout(5000);

// Verify browser console shows SSH-WASM Demo output
const demoOutput = browserLogs.find((l) => l.includes('SSH-WASM Demo')) || '';
const expected = 'SSH-WASM Demo (Loop #20)';
if (!demoOutput.includes(expected)) {
  console.log(`✗ FAIL: browser console missing "${expected}"`);
  console.log('Browser logs:');
  browserLogs.forEach((l) => console.log('  ' + l));
  process.exit(1);
}

// Verify mock server received client bytes
const serverLog = mockServerLogs.join('');
const expectedBytes = [
  'client version: SSH-2.0-MoonBit',
  'got client KEXINIT',
  'got client KEXECDH_INIT',
  'got client NEWKEYS',
];
const allFound = expectedBytes.every((s) => serverLog.includes(s));
if (!allFound) {
  console.log(`✗ FAIL: mock server missing some expected bytes`);
  console.log('Server logs:');
  console.log(serverLog);
  process.exit(1);
}

console.log('✓ PASS: e2e verify');
console.log(`  browser console: ${expected}`);
console.log(`  mock server received: 4 SSH packets (VERSION/KEXINIT/KEXECDH_INIT/NEWKEYS)`);

await browser.close();
mockServer.kill();
httpServer.kill();
process.exit(0);
```

### A.3 预期 e2e 结果

```
[e2e] starting mock SSH server...
[e2e] mock SSH server listening on ws://localhost:2222
[e2e] starting HTTP server...
[e2e] launching chromium...
[e2e] WS opened: ws://localhost:2222
[e2e] WS→server 16B: 5353482d322e302d4d6f6f6e4269740d0a  (SSH-2.0-MoonBit\r\n)
[e2e] WS→server 256B: 0000010014...  (KEXINIT packet)
[e2e] WS→server 37B: 1e00000020...  (KEXECDH_INIT)
[e2e] WS→server 12B: 0000000d1500...  (NEWKEYS)
[e2e] WS←server 17B: 5353482d322e302d4d6f636b5343485f...  (server version)
[e2e] WS←server 256B: 00000100140a0b0c0d...  (server KEXINIT)
[e2e] WS←server 144B: ...  (server KEXDH_REPLY)
[e2e] WS←server 12B: ...  (server NEWKEYS)

[e2e] ✓ PASS
```

### A.4 字节级验证

```js
// 验证 client→server 字节流 byte-exact
const expectedClientBytes = {
  'SSH-2.0-MoonBit\r\n': '5353482d322e302d4d6f6f6e4269740d0a',
  KEXINIT_packet_256B: '00000100140a...',
  KEXECDH_INIT_37B: '1e0000002085...',
  NEWKEYS_12B: '0000000d150000000000',
};
// diff browserWsFrames 与 expected
```

## B. WebTransport MoonBit Extern + 浏览器 Demo

### B.1 src/wt_socket/socket.mbt

```moonbit
pub struct WtSocket {
  handle : Int
  mut closed : Bool
}

let wt_buf : FixedArray[Byte] = FixedArray::make(4096, b'\x00')

fn wt_buf_write(bytes : FixedArray[Byte]) -> Int { ... }

pub fn WtSocket::connect(url : String) -> WtSocket {
  let url_len = wt_buf_write(ascii_bytes(url))
  let handle = wt_connect_extern(0, url_len)
  { handle, closed: false }
}

pub fn WtSocket::send(self : WtSocket, bytes : FixedArray[Byte]) -> Unit { ... }
pub fn WtSocket::read_n(self : WtSocket, n : Int) -> FixedArray[Byte] { ... }
pub fn WtSocket::close(self : WtSocket) -> Unit { ... }

extern "wasm" fn wt_connect_extern(url_ptr : Int, url_len : Int) -> Int =
  "moonbit_wt" "wt_connect"

extern "wasm" fn wt_send_extern(handle : Int, bytes_ptr : Int, len : Int) -> Int =
  "moonbit_wt" "wt_send"

extern "wasm" fn wt_recv_into_extern(handle : Int, out_ptr : Int, n : Int) -> Int =
  "moonbit_wt" "wt_recv_into"

extern "wasm" fn wt_close_extern(handle : Int) -> Int =
  "moonbit_wt" "wt_close"
```

### B.2 浏览器 demo_wt.html

```html
<script type="module">
const wtInstances = new Map();
const wtStreams = new Map();
const wtBuffers = new Map();

const imports = {
  spectest: {
    print_char: (code) => out.textContent += String.fromCharCode(code & 0xFF),
  },
  moonbit_wt: {
    wt_connect: async (urlPtr, urlLen) => {
      const url = new TextDecoder().decode(...);
      const wt = new WebTransport(url);
      await wt.ready;
      const stream = await wt.createBidirectionalStream();
      const h = nextHandle++;
      wtInstances.set(h, wt);
      wtStreams.set(h, stream);
      wtBuffers.set(h, []);
      
      // 启动 reader pump (写到 buffer 供 MoonBit 同步读)
      const reader = stream.readable.getReader();
      (async () => {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          wtBuffers.get(h).push(new Uint8Array(value));
        }
      })();
      return h;
    },
    wt_send: (handle, ptr, len) => {
      const stream = wtStreams.get(handle);
      const bytes = new Uint8Array(memory.buffer, ptr, len);
      const writer = stream.writable.getWriter();
      writer.write(bytes);
      return 0;
    },
    wt_recv_into: (handle, outPtr, n) => {
      // 类似 WebSocket host shim
    },
    wt_close: (handle) => {
      wtInstances.get(handle).close();
    },
  },
};
</script>
```

### B.3 限制
- WebTransport 需要 HTTPS + HTTP/3,localhost 需要自签证书
- Node.js 没有原生 HTTP/3 server,WebTransport 只能 client 演示
- Loop #21 范围:client only 完整实现,server 留 Loop #22+

## C. 浏览器 IndexedDB Known Hosts

### C.1 同步 wrapper host shim

```js
// host/idb_host.js (内嵌到 demo_idb.html)
const idbCache = new Map();
let idbReady = false;
let idbReadyPromise = null;

function initIDB() {
  if (idbReadyPromise) return idbReadyPromise;
  idbReadyPromise = new Promise((resolve) => {
    const req = indexedDB.open('openssh-mb', 1);
    req.onupgradeneeded = (e) => {
      e.target.result.createObjectStore('known_hosts');
    };
    req.onsuccess = () => {
      const db = req.result;
      const tx = db.transaction('known_hosts', 'readonly');
      const allReq = tx.objectStore('known_hosts').getAll();
      allReq.onsuccess = () => {
        // populate cache from IDB
        for (const item of allReq.result || []) {
          if (item && item.key) {
            idbCache.set(item.key, item.value);
          }
        }
        idbReady = true;
        resolve();
      };
    };
    req.onerror = () => {
      console.error('IDB open failed', req.error);
      resolve();
    };
  });
  return idbReadyPromise;
}

async function idbPut(key, value) {
  await initIDB();
  idbCache.set(key, value);
  // 异步持久化
  const req = indexedDB.open('openssh-mb', 1);
  req.onsuccess = () => {
    const db = req.result;
    const tx = db.transaction('known_hosts', 'readwrite');
    tx.objectStore('known_hosts').put({ key, value }, key);
  };
}

function idbGet(key) {
  return idbCache.get(key) || null;
}

// MoonBit host exports (synchronous for MoonBit):
const imports = {
  moonbit_idb: {
    idb_open: () => { initIDB(); return 1; }, // handle_id = 1
    idb_count: () => idbCache.size,
    idb_get: (handle, keyPtr, keyLen, valPtr, valCap) => {
      const key = readString(keyPtr, keyLen);
      const val = idbGet(key);
      if (!val) return 0;
      const bytes = new TextEncoder().encode(val);
      const n = Math.min(bytes.length, valCap);
      new Uint8Array(memory.buffer, valPtr, n).set(bytes.subarray(0, n));
      return n;
    },
    idb_put: (handle, keyPtr, keyLen, valPtr, valLen) => {
      const key = readString(keyPtr, keyLen);
      const val = readString(valPtr, valLen);
      idbPut(key, val);
      return 0;
    },
    idb_close: () => 0,
  },
};
```

### C.2 MoonBit 端

```moonbit
// src/knownhosts_store/store.mbt (扩 Loop #19 extern)
extern "wasm" fn idb_open() -> Int = "moonbit_idb" "open"
extern "wasm" fn idb_count(handle : Int) -> Int = "moonbit_idb" "count"
extern "wasm" fn idb_get(handle : Int, key_ptr : Int, key_len : Int, val_ptr : Int, val_cap : Int) -> Int =
  "moonbit_idb" "get"
extern "wasm" fn idb_put(handle : Int, key_ptr : Int, key_len : Int, val_ptr : Int, val_len : Int) -> Int =
  "moonbit_idb" "put"
extern "wasm" fn idb_close(handle : Int) -> Int = "moonbit_idb" "close"
```

### C.3 demo_idb.html

```html
<script type="module">
// 1. Fetch main.wasm
// 2. host shim: spectest + moonbit_idb (IDB sync wrapper)
// 3. WebAssembly.instantiate
// 4. 调用: idb_open() + idb_put(handle, "demo.com", known_hosts_line) + idb_count(handle)
// 5. 浏览器刷新页面,idb_count 不变 → 验证持久化
</script>
```

## D. 4 Target Byte-Exact 维持

- **cmd/main** 继续 MockSocket path (Loop #20 一致)
- **verify.mjs** 维持 4 target byte-exact (230bfd5b0c02d682)
- **verify_e2e.mjs** 新增,验证浏览器 ↔ mock server 字节路径 (Loop #21 新增)

## E. 实施顺序

1. **playwright install** (`npm install playwright --save-dev` + `npx playwright install chromium`)
2. **verify_e2e.mjs** 端到端验证 (启 mock_ssh_server + http.server + chromium 加载 demo_ssh.html)
3. **src/wt_socket/socket.mbt** WebTransport extern + 浏览器 demo_wt.html
4. **idb_host.js + demo_idb.html** 真 IDB 持久化
5. **5 件套文档**

预计 3-5 hours。

## F. 决策合规

| # | 决策 | 选定 |
|---|---|---|
| G1 WebTransport 范围 | 接口 + 浏览器 demo (client only) |
| G2 playwright 范围 | client→mock server 字节路径验证 |
| G3 IndexedDB 范围 | 真 IDB 持久化 + sync wrapper |