# Loop #17 Navigator — Browser Host Wrapper

**Date**: 2026-09-23 (Loop 17/17)
**Status**: Navigator 完成 — 调研产物 import section + 月 runtime 语义
**Verdict**: SSH-WASM-SSH 项目的"加密 byte-exact 跨 target"闭环已就绪(Loop #15/#16)。本 Loop 进入"在浏览器实际跑 .wasm"阶段。

## TL;DR

调研产物 `_build/{wasm,wasm-gc}/release/build/cmd/main/main.wasm` 和测试 `.wasm` 的 import section。`cmd/main/main.mbt` 当前是 MoonBit default empty Hello World(Loop #15 验证 byte-exact 用)。Loop #17 真正目标:

1. **写一个真实 SSH crypto demo**(`cmd/main/main.mbt` 替换 Hello World) — 用 SSH 协议层产出的 byte-exact KAT,做一个 mini SSH handshake 验证
2. **写 Node.js host wrapper** — instantiate main.wasm,提供 `spectest print_char`
3. **写 HTML demo page** — 在浏览器 instantiate main.wasm,console.log SSH handshake 字节流

## 关键 import section 调研

### main.wasm (release, 362 字节)

```wat
(import "spectest" "print_char" (func (param i32)))
```

只有 1 个 import。这是 wasm spec test 标准 1 字节输出接口(`(func (param i32))` = 输出 1 个 ASCII 字符)。

`moonrun` 自带实现这个 import。Node.js + 浏览器需要我们手动实现。

### test .wasm (debug + release, 7-47 KB)

```wat
(import "exception" "tag" (tag $moonbit.tag (type 124)))
(import "exception" "throw" (func (type 124)))
(import "__moonbit_fs_unstable" "finish_read_string" (func (type 125)))
(import "__moonbit_fs_unstable" "string_read_char" (func (type 126)))
(import "__moonbit_fs_unstable" "begin_read_string" (func (type 127)))
(import "spectest" "print_char" (func (type 128)))
```

5 个 import。test driver 需要 fs shim(用于 read test fixtures from stdin?)。

但 demo main.wasm **不需要 fs shim** —— main.mbt 用 println 即可,println 走 `spectest print_char`。

## 目标范围 (Loop #17)

| 目标 | 是否在 Loop #17 | 备注 |
|---|---|---|
| 写真实 SSH crypto demo main.mbt | ✅ | 串 14 Loops 加密层做 mini SSH handshake |
| Node.js host wrapper | ✅ | instantiate main.wasm + 提供 spectest print_char |
| HTML browser demo | ✅ | 浏览器 instantiate + console.log |
| Cross-target byte-exact 验证 | ✅ | 4 target main.mbt 输出 byte-exact |
| Browser fs shim (`__moonbit_fs_unstable`) | ❌ 留 Loop #19 | demo main 不调 fs |
| WebTransport TCP socket shim | ❌ 留 Loop #18 | demo main 不连 SSH server |
| IndexedDB known_hosts | ❌ 留 Loop #19 | demo main 无持久化 |

**关键边界**: Loop #17 只做"加密 demo 在浏览器跑",不做"完整 SSH 客户端连服务器"。后者是 Loop #18+。

## demo main.mbt 设计

### 目标
用 SSH 协议层 14 Loops 加密代码,模拟一个 **mini SSH transport layer handshake**(Client KEXINIT 部分),不连真实 server,在 stdout 输出 byte-exact 字节流。

### Mini handshake 内容
- 客户端构造 KEXINIT packet(RFC 4253 §7.1)
- 客户端构造 KEXDH_INIT / KEXECDH_INIT(RFC 4253 §8)
- 计算 shared secret K
- 计算 session id H_sig(RFC 4253 §8)
- 输出 hex dump 到 console

### 为什么这个 demo 是 byte-exact 验证
- KEXINIT packet format = 14 Loops bpacket + hostkey 包实现
- KEXDH_INIT x25519 scalar mul = Loop #2
- 共享密钥 HASH = Loop #11 SHA-256 (已嵌入) + Loop #1 SHA-1 (已嵌入)
- 全部 byte 操作,**无 io/net/fs 依赖** → 跨 4 target byte-exact

### 输出契约
demo 在 stdout 打印 hex dump:
```
KEXINIT (len=21): a402...
KEXECDH_INIT (len=33): 0300000215...
K = 0x1234... (32 bytes)
H = 0x5678... (32 bytes)
session_id = 0xabcd... (32 bytes)
```

这些 hex 字符串在 4 target (native / js / wasm / wasm-gc) 必须 byte-exact 相同。

## Host wrapper 设计

### Node.js host (`host/node_host.mjs`)

```js
import { readFile } from 'node:fs/promises';

const wasmBytes = await readFile(process.argv[2]);

const imports = {
  spectest: {
    print_char: (code) => process.stdout.write(String.fromCharCode(code)),
  },
};

const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
instance.exports._start();
```

### Browser HTML (`host/demOS.html`)

```html
<script type="module">
const wasmRes = await fetch('./main.wasm');
const wasmBytes = new Uint8Array(await wasmRes.arrayBuffer());

const imports = {
  spectest: {
    print_char: (code) => console.log(String.fromCharCode(code)),
  },
};

const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
instance.exports._start();
</script>
```

### MoonBit runtime issue
MoonBit wasm 还需要 `memory` + `table` + `global` imports? 看 main.wasm 验证:
```
(memory (;0;) 1)
(global (;0;) (ref 1) i32.const 1 array.new_default 1)
(export "_start" (func 4))
```

只有 1 个 memory,1 个 global (array)。**memory 是 defined 不是 imported**。所以 host wrapper 只需提供 `spectest.print_char`。

## Byte-Exact 跨 4 Target 验证

1. `moon run cmd/main --target native` → capture stdout
2. `moon run cmd/main --target js` → capture stdout
3. `moon run cmd/main --target wasm --release` → 用 Node.js host wrapper 跑 main.wasm, capture stdout
5. `moon run cmd/main --target wasm-gc --release` → 用 Node.js host wrapper 跑 main.wasm, capture stdout

4 个 stdout diff → 必须 byte-exact 完全相同(无差异)。

## 风险评估

| 风险 | 缓解 |
|---|---|
| MoonBit println 在 wasm target 走 print_char 吗? | wasm-tools print 看到 print_char 是 (param i32),println("Hello") 编译后 call print_char 多次,符合预期 |
| 浏览器 WebAssembly.instantiate 限制? | main.wasm 362 字节,无 security restriction |
| Demo 加密代码在 wasm 性能? | byte-exact 不依赖性能,后续 Loop 测加速比 |
| HTML demo 需不需要本地 server? | file:// 不能 instantiate fetch .wasm,需简单 http server(可用 `python -m http.server`) |

## 不在本 Loop 范围内 (留 Loop #18+)

1. **WebTransport / WebSocket TCP socket shim** — Loop #18
2. **`__moonfs_unstable` 完整 fs shim** — Loop #19 (IndexedDB known_hosts)
3. **完整 SSH client → server 连接** — Loop #20
4. **release vs debug 加速比** — 单独 benchmark Loop

## 决策 D1-D5

| # | 决策 | 选定 |
|---|---|---|
| D1 | demo 主线 | mini SSH handshake(KEXINIT + KEXDH_INIT + K + H + session_id) |
| D2 | demo 输入 | 全部 deterministic(无 random,seed 全 0) |
| D3 | 4 target 输出 byte-exact | 强制 |
| D4 | host wrapper 形式 | Node.js + 浏览器 HTML 双实现 |
| D6 | main.wasm 引入 fs shim? | 否,只 print_char |

## 关键文件清单 (Loop #17 计划产出)

1. `cmd/main/main.mbt` — SSH mini handshake demo (替换 Hello World)
2. `cmd/main/moon.pkg` — 可能需要加 deps (kex/hostkey/bpacket)
3. `host/node_host.mjs` — Node.js host wrapper
4. `host/demo.html` — 浏览器 demo page
5. `host/main.wasm` — copy from _build/wasm-gc/release/build/cmd/main/
6. `host/verify.mjs` — Node.js 跑 4 target byte-exact diff 脚本
7. `host/ssh_kexinit.hex` — 4 target 输出 hex 文件
8. `host/README.md` — host wrapper 使用说明
9. `docs/browser/{navigator,architect,reviewer,reality_checker,loop}-17.md`

## 量化目标

| 指标 | 值 |
|---|---|
| demo main.mbt 行数 | ~30-50 行 |
| host wrapper 行数 | <100 行 (Node.js + HTML) |
| 4 target output byte-exact diff | 0 字节 |
| main.wasm (release) 大小 | <5 KB (含 SSH crypto) |
| 验证时长 | < 30 min |

## Loop #17 衔接

| | Loop #15 | Loop #16 | **Loop #17** | Loop #18+ |
|---|---|---|---|---|
| 焦点 | debug 跨 4 target | release 跨 4 target | **浏览器跑 .wasm** | browser socket / fs |
| 改代码? | ❌ | ❌ | ✅ (main.mbt + host) | ✅ |
| 验证 | 932/932 byte-exact | 932/932 byte-exact | **demo 4 target byte-exact** | SSH client → server |
| moonrun 自动跑 | ✅ | ✅ | ✅ + Node.js host + 浏览器 | Node.js host + 浏览器 |

**Loop #17 是从"加密 byte-exact 跨 target"过渡到"在浏览器跑 SSH crypto demo"的关键 Loop**。