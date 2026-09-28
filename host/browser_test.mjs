#!/usr/bin/env node
// 浏览器等价测试:模拟 browser environment 跑 demo.html 的内嵌脚本。
//
// 验证点:
//   1. fetch('./main.wasm') 能拿到 wasm bytes
//   2. WebAssembly.instantiate + spectest.print_char host 跑通
//   3. 输出与 native/js/wasm/wasm-gc 一致 (byte-exact)
//
// 用法:  node host/browser_test.mjs

import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

// 模拟 browser environment:
const out = { textContent: '' };
const log = (text) => { out.textContent += text + '\n'; };

// 1. Fetch main.wasm (模拟 fetch('./main.wasm'))
const wasmBytes = await readFile('host/main.wasm');
log(`Fetched ${wasmBytes.byteLength} bytes.\n`);

// 2. WebAssembly.instantiate + host imports (与 demo.html 完全一致)
// wasm-gc target 用 spec test print_char 接口(char-by-char 输出)
let wasmOutput = '';
const imports = {
  spectest: {
    print_char: (code) => {
      wasmOutput += String.fromCharCode(code & 0xFF);
    },
  },
};

const { instance } = await WebAssembly.instantiate(wasmBytes, imports);
log('Instantiated. Calling _start...\n');

instance.exports._start();

log(wasmOutput);
log('✓ SSH-WASM Demo completed successfully (browser-equivalent test)');

// 3. 验证输出 byte-exact (Loop #20: 12 行 hex dump,含 AEAD 加密路径)
const expected = `=== SSH-WASM Demo (Loop #20) ===
client_pub: 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
server_pub: d13f5c5b91ae760ed147df65aebb97f5369640e47c03938f9f4c4e209c61ca02
shared_K: 7bda42e82d49a492388ef14fa2110d20d82465de9d1ca39482282f752b31590f
kexinit_len: 241
kexinit_head16: 0102030405060708090a0b0c0d0e0f10
kexdh_init_len: 37
kexdh_init: 1e000000208520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
packet_test_len: 17
userauth_wire_len: 68
channel_open_wire_len: 52
channel_exec_wire_len: 60
client_sent_total: 507
`;

const normalized = wasmOutput.replace(/\r\n/g, '\n').trim();
const expectedNorm = expected.replace(/\r\n/g, '\n').trim();

if (normalized === expectedNorm) {
  console.log('\n✓ PASS: browser-equivalent test output matches expected byte-exact');
  const hash = createHash('sha256').update(normalized).digest('hex').substring(0, 16);
  console.log(`  SHA-256: ${hash}`);
  console.log(`  Length: ${normalized.length} bytes`);
  process.exit(0);
} else {
  console.log('\n✗ FAIL: browser-equivalent test output mismatch');
  console.log('--- expected ---');
  console.log(expectedNorm);
  console.log('--- got ---');
  console.log(normalized);
  process.exit(1);
}