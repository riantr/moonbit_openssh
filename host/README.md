# SSH-WASM Host Wrapper — 浏览器 host runtime

**Loop #17** (2026-09-23) — 把 MoonBit 编译的 SSH crypto demo 在浏览器实际跑通。

## 文件清单

| 文件 | 大小 | 用途 |
|---|---|---|
| `node_host.mjs` | 65 行 | Node.js host wrapper(给 wasm + wasm-gc) |
| `demo.html` | 55 行 | 浏览器 demo 页面(直接 fetch + instantiate) |
| `verify.mjs` | 80 行 | 4 target × 2 mode byte-exact diff 验证 |
| `browser_test.mjs` | 55 行 | 浏览器等价测试(Node.js 模拟 Web API) |
| `main.wasm` | 15610 bytes | wasm-gc release 产物(copy from `_build/wasm-gc/release/build/cmd/main/`) |

## 用法

### 1. Node.js 跑 wasm 产物

```bash
# 跑 wasm-gc release 产物
node host/node_host.mjs _build/wasm-gc/release/build/cmd/main/main.wasm

# 跑 wasm (legacy) release 产物 (用 fd_write stub)
node host/node_host.mjs _build/wasm/release/build/cmd/main/main.wasm
```

### 2. 浏览器打开 demo.html

```bash
# 启动 http server (必需,因为浏览器 fetch main.wasm 不能 file://)
python -m http.server 8000 --bind 127.0.0.1

# 然后 Chrome 打开:
# http://127.0.0.1:8000/host/demo.html
```

支持的浏览器: Chrome 119+, Edge 119+, Safari 17+, Firefox 120+ (支持 WASM GC proposal)。

### 3. 全 4 target × 2 mode byte-exact 验证

```bash
node host/verify.mjs
```

输出 8 个 (target × mode) 组合的 stdout,SHA-256 验证唯一性。预期 `fd1bb8bb48083ed9`。

### 4. 浏览器等价测试 (无需安装 chromium)

```bash
node host/browser_test.mjs
```

模拟 browser environment (fetch + WebAssembly.instantiate + DOM `pre`),验证输出与 native 输出 byte-exact 一致。

## 实现细节

### MoonBit 编译产物 import section

| Target | Imports |
|---|---|
| `native` | C runtime (无 wasm host imports) |
| `js` | MoonBit fs shim (Node.js 提供) |
| `wasm` (legacy) | `wasi_snapshot_preview1.fd_write` |
| `wasm-gc` | `spectest.print_char` |

### Node.js host 提供

```js
const imports = {
  spectest: {
    print_char: (code) => stdout.write(String.fromCharCode(code & 0xFF)),
  },
  wasi_snapshot_preview1: {
    fd_write: (fd, iovecPtr, iovecLen, nwrittenPtr) => {
      // 解 iovec, 写 stdout
    },
  },
};
```

### 浏览器 host 提供 (demo.html)

```html
<script type="module">
const imports = {
  spectest: {
    print_char: (code) => out.textContent += String.fromCharCode(code & 0xFF),
  },
};
const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
instance.exports._start();
</script>
```

## 验证结果 (2026-09-23)

```
$ node host/verify.mjs
✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: fd1bb8bb48083ed9)

$ node host/browser_test.mjs
✓ PASS: browser-equivalent test output matches expected byte-exact
  SHA-256: 3bb0129117c6e5a4
  Length: 422 bytes
```

## 后续 Loop (#18+)

- **Loop #18**: WebTransport / WebSocket TCP socket shim (浏览器无 raw socket)
- **Loop #19**: `__moonbit_fs_unstable` 完整 shim + IndexedDB known_hosts
- **Loop #20**: 完整 SSH client → server demo