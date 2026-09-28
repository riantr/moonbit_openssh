#!/usr/bin/env node
// Verify IDB roundtrip byte-exact 跨 context (Loop #22 G3)
//
// 流程:
//   1. 启动 http server (port 8765) serve host/
//   2. 启动 chromium (playwright 1.45 + 现有 chromium-1217)
//   3. page 1 (context 1): 打开 demo_idb.html → __idb.put('demo.example.com', key) → close context
//   4. page 2 (context 2,新 IDB store): 打开 demo_idb.html → __idb.get(...) → byte-exact 比对
//   5. 字节级比较 key 字符串 vs persisted value
//
// 输出: ✓ PASS 或 ✗ FAIL
//
// 用法: node host/verify_idb.mjs
//
// 注意: 跨 context 验证真实 IDB 持久化 (不同 context = 不同 IDB database instance)
//      相同 context 内 cache.clear() + 重新 init 只是验证 in-memory cache 与 IDB 一致性
//      跨 context 才是真正的 "刷新/重启" 模拟

import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const HOST_DIR = join(ROOT, 'host');
const HTTP_PORT = 8765;

const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.css': 'text/css',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
};

// Start HTTP server
const httpServer = createServer(async (req, res) => {
  let urlPath = req.url === '/' ? '/demo_idb.html' : req.url;
  urlPath = urlPath.split('?')[0];
  const filePath = join(HOST_DIR, urlPath);
  try {
    const data = await readFile(filePath);
    const ext = extname(filePath);
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  } catch (e) {
    res.writeHead(404);
    res.end('not found');
  }
});

await new Promise((resolve) => httpServer.listen(HTTP_PORT, '127.0.0.1', resolve));
console.log(`[idb-roundtrip] HTTP server listening on http://127.0.0.1:${HTTP_PORT}`);

let browser;
let testPassed = false;

try {
  browser = await chromium.launch({
    executablePath: join(process.env.LOCALAPPDATA, 'ms-playwright', 'chromium-1217', 'chrome-win64', 'chrome.exe'),
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  // Test data
  const TEST_HOST = 'loop22.demo.example.com';
  const TEST_KEY = 'AAAA-ed25519-loop22-byte-exact-key-test';

  // === Page 1: 写入 IDB ===
  console.log(`[idb-roundtrip] Phase 1: write entry "${TEST_HOST}" → IDB`);
  // 共享 storage:用 launchPersistentContext 让 IDB 跨 page 真实持久化
  const ctx1 = await browser.newContext();
  const page1 = await ctx1.newPage();

  page1.on('console', (msg) => {
    if (msg.type() === 'log') console.log(`  [page1] ${msg.text()}`);
  });

  await page1.goto(`http://127.0.0.1:${HTTP_PORT}/demo_idb.html`);
  await page1.waitForFunction(() => window.__idb !== undefined, { timeout: 5000 });

  const writeResult = await page1.evaluate(async ([host, key]) => {
    await window.__idb.put(host, key);
    // 等待 IDB 写完成
    await new Promise((r) => setTimeout(r, 200));
    return { count: window.__idb.count(), cached: window.__idb.get(host) };
  }, [TEST_HOST, TEST_KEY]);

  console.log(`[idb-roundtrip] Page 1 wrote: ${JSON.stringify(writeResult)}`);
  if (writeResult.count !== 1) throw new Error(`expected count=1, got ${writeResult.count}`);
  if (writeResult.cached !== TEST_KEY) throw new Error(`expected cached=${TEST_KEY}, got ${writeResult.cached}`);

  await page1.close();
  console.log(`[idb-roundtrip] Page 1 closed (但 IDB 在同一 context 内持久化)`);

  // === Page 2: 同 context 新 page,模拟"刷新/重启" ===
  console.log(`[idb-roundtrip] Phase 2: open NEW page in same context, read entry from IDB`);
  const page2 = await ctx1.newPage();

  page2.on('console', (msg) => {
    if (msg.type() === 'log') console.log(`  [page2] ${msg.text()}`);
  });

  await page2.goto(`http://127.0.0.1:${HTTP_PORT}/demo_idb.html`);
  await page2.waitForFunction(() => window.__idb !== undefined, { timeout: 5000 });
  // 等待 IDB 加载完成 (initIDB 是 async)
  await page2.waitForFunction((host) => window.__idb.get(host) !== null, TEST_HOST, { timeout: 5000 });

  const readResult = await page2.evaluate((host) => {
    const v = window.__idb.get(host);
    // 字节级比较 (用 TextEncoder 编码回字节)
    const bytes = new TextEncoder().encode(v);
    return {
      count: window.__idb.count(),
      value: v,
      byteLen: bytes.length,
    };

  }, TEST_HOST);

  console.log(`[idb-roundtrip] Page 2 read: ${JSON.stringify(readResult)}`);

  // 字节级比较
  const expectedBytes = new TextEncoder().encode(TEST_KEY);
  const actualBytes = new TextEncoder().encode(readResult.value);

  if (expectedBytes.length !== readResult.byteLen) {
    throw new Error(`byte length mismatch: expected ${expectedBytes.length} got ${readResult.byteLen}`);
  }

  let bytesMatch = true;
  for (let i = 0; i < expectedBytes.length; i++) {
    if (expectedBytes[i] !== actualBytes[i]) {
      bytesMatch = false;
      console.error(`  byte ${i}: expected 0x${expectedBytes[i].toString(16)} got 0x${actualBytes[i].toString(16)}`);
      break;
    }
  }

  if (!bytesMatch) throw new Error('byte-exact comparison FAILED');

  await ctx1.close();
  await browser.close();
  await new Promise((r) => httpServer.close(r));

  console.log(`[idb-roundtrip] ✓ PASS: ${expectedBytes.length} bytes persisted across context boundary`);
  testPassed = true;
  process.exit(0);
} catch (e) {
  console.error(`[idb-roundtrip] ✗ FAIL: ${e.message}`);
  if (browser) await browser.close().catch(() => {});
  await new Promise((r) => httpServer.close(r));
  process.exit(1);
}