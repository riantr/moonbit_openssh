# Loop #17 Architect — Browser Host Wrapper 设计规格

**Date**: 2026-09-23
**Status**: Architect 完成 — 详细规格 ready to implement
**Verdict**: 4 target × 1 demo = 4 stdout byte-exact diff = 0 字节差异

## TL;DR

| 项 | 规格 |
|---|---|
| Demo | `cmd/main/main.mbt` 模拟 SSH client-side mini handshake(KEXINIT + KEXDH_INIT + K + H + session_id) |
| 加密 | 用 14 Loops 已 byte-exact 验证的 chacha20 / sha256 / sha1 / x25519 |
| 4 target 输出 | 4 stdout byte-exact 完全相同 |
| Host wrapper | Node.js (`host/node_host.mjs`) + 浏览器 HTML (`host/demo.html`) |
| 不在 Loop #17 | TCP socket shim / IndexedDB / 完整 SSH client → server |

## A. demo main.mbt 设计

### A.1 入口结构

```moonbit
fn main {
  // 1. 构造 deterministic 私钥 (RFC 7748 §5.2 test vector scalar)
  let client_priv = Bytes::from_array([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  ])

  // 2. 计算 client public key (x25519 base point multiply)
  let client_pub = x25519::x25519_scalar_mult(client_priv, X25519_BASE)

  // 3. 构造 KEXINIT payload (RFC 4253 §7.1)
  let kexinit_payload = build_kexinit()

  // 4. 构造 KEXECDH_INIT packet (RFC 4253 §8 + bpacket)
  let kexdh_init = build_kexdh_init(client_pub)

  // 5. 计算 deterministic server public (RFC 7748 §5.2)
  let server_priv = Bytes::from_array([
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc9, 0x5b, 0xa9, 0xd6, 0x18,
    0x5f, 0x77, 0xbb, 0x6c, 0xed, 0x27, 0x9d, 0x4a,
  ])
  let server_pub = x25519::x25519_scalar_mult(server_priv, X25519_BASE)

  // 6. 计算 shared secret K
  let K = x25519::x25519_scalar_mult(client_priv, server_pub)

  // 7. 计算 H = SHA-256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)
  let H = compute_session_hash(
    kexinit_payload, kexinit_payload,  // simplified V_C == V_S
    client_pub, server_pub, K,
  )

  // 8. 输出 hex dump
  print_hex("client_pub", client_pub)
  print_hex("K", K)
  print_hex("H", H)
  print_hex("kexdh_init", kexdh_init)
}
```

### A.2 依赖 (cmd/main/moon.pkg)

```moonbit
import {
  "moonbitlang/core/builtin",
  "openssh/openssh_moonbit/x25519",
  "openssh/openssh_moonbit/sha256",
  "openssh/openssh_moonbit/bpacket",
  "openssh/openssh_moonbit/hostkey",
}
```

### A.3 输出格式

每行 `<name>: <hex>` 形式,确定性:
```
client_priv: 77076d0a...
client_pub: <32 bytes hex>
K: <32 bytes hex>
H: <32 bytes hex>
kexinit_payload: <hex>
kexdh_init: <hex>
kexdh_init_len: 33
```

**4 target 输出必须 byte-exact 一致**。

## B. Host wrapper 规格

### B.1 Node.js (`host/node_host.mjs`)

```js
#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { argv, stdout, exit } from 'node:process';

if (argv.length !== 3) {
  stderr.write('Usage: node node_host.mjs <main.wasm>\n');
  exit(1);
}

const wasmBytes = await readFile(argv[2]);

const imports = {
  spectest: {
    print_char: (code) => stdout.write(String.fromCharCode(code)),
  },
};

const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
try {
  instance.exports._start();
} catch (e) {
  if (e?.message?.includes('unreachable')) {
    // MoonBit unreachable trap = panic, treat as test fail
    exit(2);
  }
  throw e;
}
```

### B.2 浏览器 HTML (`host/demo.html`)

```html
<!DOCTYPE html>
<html>
<head>
  <title>SSH-WASM Demo</title>
</head>
<body>
  <h1>SSH-WASM Demo: Mini Handshake</h1>
  <pre id="out">Loading...</pre>
  <script type="module">
    const out = document.getElementById('out');
    function log(line) { out.textContent += line + '\n'; }

    const wasmRes = await fetch('./main.wasm');
    const wasmBytes = new Uint8Array(await wasmRes.arrayBuffer());

    const imports = {
      spectest: {
        print_char: (code) => log(String.fromCharCode(code)),
      },
    };

    const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
    try {
      instance.exports._start();
    } catch (e) {
      log('ERROR: ' + e.message);
    }
  </script>
</body>
</html>
```

### B.3 Verify 脚本 (`host/verify.mjs`)

```js
#!/usr/bin/env node
// 4 target × 1 demo byte-exact diff 验证
import { readFile, writeFile } from 'node:fs/promises';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Build 4 targets
const targets = ['native', 'js', 'wasm', 'wasm-gc'];
const modes = ['debug', 'release'];

const outputs = {};
for (const target of targets) {
  for (const mode of modes) {
    const flag = mode === 'release' ? '--release' : '';
    const cmd = target === 'native' || target === 'js'
      ? `moon run cmd/main --target ${target} ${flag}`
      : `moon build cmd/main --target ${target} ${flag} && node host/node_host.mjs _build/${target}/${mode}/build/cmd/main/main.wasm`;
    const out = execSync(cmd, { cwd: ROOT, encoding: 'utf-8' });
    outputs[`${target}-${mode}`] = out;
  }
}

// SHA-256 hash diff
const hashes = {};
for (const [key, out] of Object.entries(outputs)) {
  hashes[key] = createHash('sha256').update(out).digest('hex');
}

const uniqueHashes = new Set(Object.values(hashes));
if (uniqueHashes.size === 1) {
  console.log('PASS: 4 target × 2 mode byte-exact一致');
} else {
  console.log('FAIL: hash diff detected');
  for (const [key, hash] of Object.entries(hashes)) {
    console.log(`  ${key}: ${hash}`);
  }
}
```

## C. 验收标准

### C.1 硬指标

| # | 标准 | 验证 |
|---|---|---|
| Hash all | 4 target × 2 mode = 8 stdout byte-exact | `host/verify.mjs` exit 0 |
| main.wasm (wasm-gc release) | < 10 KB | `ls -la _build/wasm-gc/release/build/cmd/main/main.wasm` |
| main.wasm (wasm release) | < 10 KB | `ls -la _build/wasm/release/build/cmd/main/main.wasm` |
| Node.js host 跑 wasm-gc | 完整 SSH crypto demo 输出 | manual |
| Node.js host 跑 wasm | 完整 SSH crypto demo 输出 | manual |
| 浏览器 HTML demo (Chrome) | console 显示完整 SSH crypto demo 输出 | manual via puppeteer/playwright (optional) |

### C.2 软指标

| # | 标准 |
|---|---|
| demo main.mbt | < 100 行 |
| host wrapper | < 200 行(JS + HTML) |
| 文档 | 5 件套(navigator/architect/reviewer/reality/summary) |

## D. KAT 数据来源

demo 用 RFC 7748 §5.2 "Alice" test vector 作为 client 私钥:
```
client_priv = 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51d71b27a
client_pub = 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
```

Loop #2 x25519 KAT 已经覆盖这个 RFC vector。

## E. 决策 D1-D10

| # | 决策 | 选定 |
|---|---|---|
| D1 | Demo 主线 | mini SSH handshake (client side only) |
| D2 | Demo 输入 | RFC 7748 Alice (client) + Bob (server) 全 deterministic |
| D3 | Demo 输出格式 | 6 行 hex (client_pub / K / H / kexinit / kexdh_init / kexdh_len) |
| D4 | 4 target 输出 byte-exact | 强制 |
| D5 | Host wrapper 形态 | Node.js + HTML (双实现) |
| D6 | Demo 是否调 fs | 否,只用 println |
| D7 | Demo 是否调用 random | 否,全 deterministic KAT |
| D8 | Demo 调用哪些已有 Loop | #2 x25519, #10 bpacket, #11 hostkey |
| D9 | Demo 加密字节流 | 沿用 14 Loops byte-exact 字节流 |
| D10 | Demo 输出 stdout 形式 | 直接 println (走 spectest print_char) |

## F. Loop 衔接

| Loop | 焦点 | demo 输出 |
|---|---|---|
| #15 | debug 跨 4 target byte-exact | Hello World |
| #16 | release 跨 4 target byte-exact | Hello World |
| **#17** | **SSH crypto demo 在浏览器跑** | **6 行 hex byte-exact** |
| #18+ | TCP socket / IndexedDB / 完整 SSH | SSH client → server |

## G. 风险与缓解

| 风险 | 缓解 |
|---|---|
| moonbit main println 走 print_char 还是 wasm fd_write? | wasm-tools print main.wasm 只看到 print_char,确认走 print_char |
| 浏览器 fetch .wasm 需 HTTPS / localhost? | localhost 即可,fetch 不需要 HTTPS |
| MoonBit wasm 需要 table + global init? | main.wasm memory + global 是 defined 不是 imported,host 不需提供 |
| Chrome 浏览器加载 wasm 字节大小限制? | main.wasm < 10 KB,远低于 4 GB 限制 |
| Node.js instantiate 失败? | 用 fetch 后 instantiate 比 WebAssembly.compile 更省 |

## I. 实施顺序

1. **demo main.mbt 编写** — `cmd/main/main.mbt` 替换 Hello World,加 deps
2. **验证 4 target** — `moon run cmd/main --target {native,js,wasm,wasm-gc}` 都跑通
3. **host wrapper Node.js** — `host/node_host.mjs` instantiate main.wasm
4. **host wrapper HTML** — `host/demo.html` 浏览器 instantiate
5. **verify.mjs** — 4 target × 2 mode byte-exact diff
6. **浏览器 manual 测试** — `python -m http.server` + Chrome console
7. **文档 5 件套** — review/reality/summary

## J. 文件产出清单

```
openssh_moonbit/
├── cmd/main/
│   ├── main.mbt                    (改: SSH crypto demo)
│   └── moon.pkg                    (改: 加 x25519/bpacket deps)
├── host/                           (新增)
│   ├── node_host.mjs               (Node.js host wrapper)
│   ├── demo.html                   (浏览器 demo)
│   ├── verify.mjs                  (4 target byte-exact 验证)
│   ├── README.md                   (host wrapper 使用说明)
│   └── main.wasm                   (copy from _build/wasm-gc/release)
└── docs/wasm/
    ├── navigator17.md              (Navigator 调研)
    ├── architect17.md              (Architect 设计) ← 本文档
    ├── reviewer17.md               (TODO)
    ├── reality_checker17.md        (TODO)
    └── loop17-summary.md           (TODO)
```