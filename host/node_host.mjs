#!/usr/bin/env node
// Node.js host wrapper for MoonBit wasm targets.
//
// 用法:  node host/node_host.mjs <main.wasm>
//
// 提供 MoonBit main.wasm 所需的 host imports:
//   - spectest.print_char: (i32) -> ()  输出 1 字节字符到 stdout
//   - 其他 module spec test / debug imports 按目标类型决定
//
// 验证 SSH-WASM demo 在浏览器外 (Node.js) 跑通。

import { readFile } from 'node:fs/promises';
import { argv, stdout, stderr, exit } from 'node:process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

if (argv.length !== 3) {
  stderr.write('Usage: node host/node_host.mjs <main.wasm>\n');
  exit(1);
}

const wasmFile = argv[2];
const wasmBytes = await readFile(wasmFile);

// spectest.print_char: (param i32) => 输出 1 ASCII 字节到 stdout
// wasi_snapshot_preview1.fd_write: (i32, i32, i32, i32) -> (i32)
//   args: (fd, iovec_ptr, iovec_len, nwritten_ptr) → 写入字节数
//   fd_write 读取 memory 中 iovec 数组 (buf_ptr, buf_len) pairs,写入对应 fd
const imports = {
  spectest: {
    print_char: (code) => {
      stdout.write(String.fromCharCode(code >>> 0));
    },
  },
  wasi_snapshot_preview1: {
    fd_write: (fd, iovecPtr, iovecLen, nwrittenPtr) => {
      if (fd !== 1) return 1; // EBADF
      const mem = instance.exports.memory;
      const dv = new DataView(mem.buffer);
      let totalWritten = 0;
      // iovec 在 wasm linear memory:每个 8 字节 (ptr:u32, len:u32)
      for (let i = 0; i < iovecLen; i++) {
        const bufPtr = dv.getUint32(iovecPtr + i * 8, true);
        const bufLen = dv.getUint32(iovecPtr + i * 8 + 4, true);
        const bytes = new Uint8Array(mem.buffer, bufPtr, bufLen);
        stdout.write(Buffer.from(bytes));
        totalWritten += bufLen;
      }
      dv.setUint32(nwrittenPtr, totalWritten, true);
      return 0;
    },
  },
};

let instance;
const module_ = await WebAssembly.compile(wasmBytes);
// 一些 wasm target 需要 memory 在 importObject 里提供 (不是 defined)
// 让 wasm 自带 memory 后再 instantiate
try {
  instance = await WebAssembly.instantiate(module_, imports);
} catch (e) {
  // 如果 module 是 wasm-gc (WASM GC proposal) 且 V8 不支持 → 报清楚错
  if (e instanceof WebAssembly.CompileError || e instanceof SyntaxError) {
    stderr.write(`Compile error: ${e.message}\n`);
    stderr.write('Note: V8 may not support wasm-gc (WASM GC proposal).\n' +
                 '      Try `--target wasm` (legacy wasm) instead.\n');
    exit(2);
  }
  throw e;
}

// 启动 wasm:调用 _start 入口 (MoonBit 编译约定)
try {
  instance.exports._start();
} catch (e) {
  if (e instanceof WebAssembly.RuntimeError) {
    // MoonBit unreachable trap (panic) → 退出码 3 表示 demo panic
    stderr.write(`Runtime error: ${e.message}\n`);
    exit(3);
  }
  throw e;
}