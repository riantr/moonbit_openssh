#!/usr/bin/env node
// Node.js host shim for MoonBit wasm-gc (Loop #23 G2 run in Node)
// 加载 ssh_full_ws.wasm + 提供 moonbit_socket + spectest::print_char shim
// 跑 MoonBit main() 并捕获 stdout
//
// 用法: node host/node_host_wasm.mjs [wasm_path]
//   默认 _build/wasm-gc/debug/build/cmd/ssh_full_ws/ssh_full_ws.wasm

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import WebSocket from 'ws';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const wasmPath = process.argv[2] || join(ROOT, '_build/wasm-gc/debug/build/cmd/ssh_full_ws/ssh_full_ws.wasm');

const bytes = await readFile(wasmPath);
console.log(`[node_host_wasm] loaded ${bytes.byteLength}B from ${wasmPath}`);

// WebSocket state (synchronous, blocking read for MoonBit main)
const wsInstances = new Map();
const wsBuffers = new Map();  // handle → FIFO queue of Uint8Array
let wsNextHandle = 1;

/**
 * Loop #63: this function had `await` inside a non-async function, so the whole
 * file failed to parse and **had never been executed by anything** -- there are
 * no callers, and `moon build` never loads this file, so nothing noticed.
 *
 * It is also unreachable from `ws_recv_into`, which deliberately throws on a
 * short buffer rather than block. That is not an oversight in this file: a wasm
 * frame is synchronous, the host cannot re-enter the module (wasm-gc exports
 * only `_start`), and WebSocket data arrives from `onmessage`, which needs the
 * event loop. Blocking here would deadlock rather than wait.
 *
 * Kept, and made correct, rather than deleted: it is the shape the host would
 * need if the transport could yield, and `verify_loop63.mjs` asserts both the
 * absence of blocking and the absence of callers, so nobody reads this as a
 * working path.
 */
async function ws_wait_for_bytes(handle, n, timeoutMs = 5000) {
  const buf = wsBuffers.get(handle);
  if (!buf) throw new Error(`ws_wait: invalid handle ${handle}`);
  const start = Date.now();
  while (true) {
    let total = 0;
    for (const chunk of buf) total += chunk.length;
    if (total >= n) return;
    if (Date.now() - start > timeoutMs) throw new Error(`ws_wait: timeout ${n}B (got ${total})`);
    // event loop tick
    await new Promise((r) => setImmediate(r));
  }
}

const moonbit_socket = {
  ws_connect: async (urlPtr, urlLen) => {
    const memView = new Uint8Array(memory.buffer);
    const url = new TextDecoder().decode(memView.subarray(urlPtr, urlPtr + urlLen));
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
      const handle = wsNextHandle++;
      wsInstances.set(handle, ws);
      wsBuffers.set(handle, []);
      ws.on('message', (data) => {
        const bytes = new Uint8Array(data);
        wsBuffers.get(handle).push(bytes);
      });
      ws.on('error', (e) => console.error(`[ws] handle=${handle} error:`, e.message));
      ws.on('open', () => resolve(handle));
      ws.on('close', () => console.error(`[ws] handle=${handle} closed`));
      setTimeout(() => reject(new Error('ws_connect timeout')), 5000);
    });
  },
  ws_send: (handle, ptr, len) => {
    const ws = wsInstances.get(handle);
    if (!ws) throw new Error(`ws_send: invalid handle ${handle}`);
    const memView = new Uint8Array(memory.buffer);
    const bytes = memView.slice(ptr, ptr + len);
    ws.send(bytes);
    return 0;
  },
  ws_recv_into: (handle, ptr, n) => {
    // 同步阻塞 — 但 wasm-gc 是同步函数,不能 await
    // 用 busy poll + setImmediate 让出 event loop
    const buf = wsBuffers.get(handle);
    if (!buf) throw new Error(`ws_recv_into: invalid handle ${handle}`);

    // 检查立即可读
    let total = 0;
    for (const chunk of buf) total += chunk.length;
    if (total < n) {
      // 同步阻塞 — 在 wasm-gc 这块不能 await
      // 但 Node.js 单线程 + ws.onmessage 是 event loop driven
      // 唯一办法:throw 让 MoonBit 重试 (但 MoonBit 没 retry)
      // OR: 在 wasm 启动前预填 buffer
      throw new Error(`ws_recv_into: short buffer, want ${n} got ${total} (sync block not supported)`);
    }
    // 消费 n bytes
    let remaining = n;
    let writeOffset = ptr;
    const memView = new Uint8Array(memory.buffer);
    while (remaining > 0) {
      const chunk = buf[0];
      if (chunk.length <= remaining) {
        memView.set(chunk, writeOffset);
        writeOffset += chunk.length;
        remaining -= chunk.length;
        buf.shift();
      } else {
        memView.set(chunk.subarray(0, remaining), writeOffset);
        buf[0] = chunk.subarray(remaining);
        remaining = 0;
      }
    }
    return n;
  },
  ws_close: (handle) => {
    const ws = wsInstances.get(handle);
    if (ws) {
      try { ws.close(); } catch {}
    }
    return 0;
  },
};

// spectest::print_char — MoonBit runtime 的 stdout shim
let stdoutBuf = '';
const spectest = {
  print_char: (ch) => {
    // ch 是 wasm-gc i32,转 char
    const c = String.fromCharCode(ch);
    stdoutBuf += c;
    process.stdout.write(c);
  },
};

const memory = new WebAssembly.Memory({ initial: 2, maximum: 10 });

// Instantiate
// 注意:wasm-gc 同步 instantiate,ws_connect 是 async — 不兼容
// 解决:pre-fill ws buffer — 但需要先 connect 才能填 buffer
// 替代:把 ws_connect 改成同步等待,阻塞到 ws.on('open')
// 这意味着 moonbit_socket.ws_connect 必须是 sync function (返回 handle)
//
// 让我们重新设计 ws_connect 为 sync,内部用 deasync 或 spawn-blocking
// 简化方案 — 启动 mock server, 在 instantiate 前 connect 然后手动填 handle
//
// 替代更简方案:用 ws sync API (Node 22+ 有 WebSocket sync?)
//
// 最实用:重写 shim 让 ws_connect 阻塞等 ws.on('open')

// 重写 ws_connect 为同步阻塞
const moonbit_socket_sync = {
  ws_connect: (urlPtr, urlLen) => {
    const memView = new Uint8Array(memory.buffer);
    const url = new TextDecoder().decode(memView.subarray(urlPtr, urlPtr + urlLen));
    console.error(`[ws] connecting to ${url}`);
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    const handle = wsNextHandle++;
    wsInstances.set(handle, ws);
    wsBuffers.set(handle, []);
    ws.on('message', (data) => {
      const bytes = new Uint8Array(data);
      wsBuffers.get(handle).push(bytes);
    });
    ws.on('error', (e) => console.error(`[ws] handle=${handle} error:`, e.message));
    ws.on('close', () => console.error(`[ws] handle=${handle} closed`));
    // 同步阻塞等 ws.on('open')
    require('deasync').sleep(100);  // 不引入 deasync 依赖
    while (ws.readyState !== WebSocket.OPEN) {
      require('child_process').execSync('node -e "setTimeout(()=>{},10)"');
    }
    return handle;
  },
  ws_send: moonbit_socket.ws_send,
  ws_recv_into: moonbit_socket.ws_recv_into,
  ws_close: moonbit_socket.ws_close,
};

console.log('[node_host_wasm] instantiating...');
// wasm-gc instantiate 不允许 async imports
// 必须 sync
const module = await WebAssembly.compile(bytes);
const instance = await WebAssembly.instantiate(module, {
  moonbit_socket: moonbit_socket_sync,
  spectest,
  env: {},
  js: { memory },
});

console.log('[node_host_wasm] calling _start (MoonBit main)...');
try {
  instance.exports._start();
} catch (e) {
  console.error('[node_host_wasm] _start threw:', e.message);
  process.exit(1);
}
console.log('[node_host_wasm] _start completed');
process.exit(0);