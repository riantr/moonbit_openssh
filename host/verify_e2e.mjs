#!/usr/bin/env node
// Loop #21 e2e 验证: 浏览器 ↔ mock SSH server 字节路径
//
// 流程:
//   1. 启 mock_ssh_server.mjs (port 2222)
//   2. 启 python -m http.server (serve host/ on port 8765)
//   3. playwright 启动 chromium 加载 demo_ssh.html
//   4. 浏览器 fetch main.wasm + WS 连 mock server
//   5. 验证 mock server stdout 收到 4 个 SSH packets
//   6. 验证浏览器 console 显示 SSH-WASM Demo 输出

import { spawn } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';
import { chromium } from 'playwright';
import { existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

// Loop #71: this was a two-element list of
//   'C:\\Users\\hp\\AppData\\Local\\ms-playwright\\chromium-1217\\chrome-win64\\chrome.exe'
//   'C:\\Users\\hp\\AppData\\Local\\ms-playwright\\chromium-1208\\chrome-win64\\chrome.exe'
// Two machine claims per line: one developer's home directory, and a
// Playwright browser revision. The revision is the worse of the two -- it
// changes every time Playwright is upgraded, and when it does, this function
// returns null and the e2e gate reports "no browser" on a machine that has
// one. Exactly the shape Loop #69 found in sshd_setup.mjs.
//
// So: read LOCALAPPDATA, list whatever chromium-* directories are actually
// there, newest first, and try the three layouts Playwright has shipped.
// Nothing here names a user, a revision, or a drive.
function findChromium() {
  const roots = [
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, 'ms-playwright'),
    process.env.PLAYWRIGHT_BROWSERS_PATH,
  ].filter(Boolean);
  for (const root of roots) {
    let entries;
    try {
      entries = readdirSync(root);
    } catch {
      continue; // not installed here; try the next root
    }
    const dirs = entries.filter((e) => e.startsWith('chromium-')).sort().reverse();
    for (const d of dirs) {
      for (const leaf of ['chrome-win64', 'chrome-win', 'chrome-win32']) {
        const p = join(root, d, leaf, 'chrome.exe');
        if (existsSync(p)) return p;
      }
    }
  }
  return null;
}

console.log('[e2e] starting mock SSH server...');
const mockServer = spawn('node', ['host/mock_ssh_server.mjs'], {
  cwd: ROOT,
  stdio: ['ignore', 'pipe', 'pipe'],
});

const serverLog = [];
mockServer.stdout.on('data', (d) => serverLog.push(d.toString()));
mockServer.stderr.on('data', (d) => serverLog.push(d.toString()));

await sleep(1500);

console.log('[e2e] starting HTTP server on port 8765...');
const httpServer = spawn('python', ['-m', 'http.server', '8765', '--bind', '127.0.0.1'], {
  cwd: join(ROOT, 'host'),
  stdio: ['ignore', 'pipe', 'pipe'],
});

await sleep(1000);

const chromiumPath = findChromium();
console.log('[e2e] chromium:', chromiumPath || '(playwright default)');

console.log('[e2e] launching chromium...');
const browser = await chromium.launch({
  headless: true,
  executablePath: chromiumPath,
}).catch((e) => {
  console.error('chromium launch failed:', e.message);
  cleanup();
});

const ctx = await browser.newContext();
const page = await ctx.newPage();

const browserLogs = [];
const wsFrames = { sent: [], received: [] };
page.on('console', (msg) => browserLogs.push(`[${msg.type()}] ${msg.text()}`));
page.on('websocket', (ws) => {
  console.log(`[e2e] WS opened: ${ws.url()}`);
  ws.on('framesent', (e) => {
    let bytes;
    if (e.payload instanceof Buffer) bytes = Array.from(e.payload);
    else if (e.payload && e.payload.buffer) bytes = Array.from(new Uint8Array(e.payload));
    if (bytes) {
      const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
      console.log(`[e2e] WS→server ${bytes.length}B: ${hex.substring(0, 80)}`);
      wsFrames.sent.push(bytes);
    }
  });
  ws.on('framereceived', (e) => {
    let bytes;
    if (e.payload instanceof Buffer) bytes = Array.from(e.payload);
    else if (e.payload && e.payload.buffer) bytes = Array.from(new Uint8Array(e.payload));
    if (bytes) {
      const hex = bytes.map((b) => b.toString(16).padStart(2, '0')).join('');
      console.log(`[e2e] WS←server ${bytes.length}B: ${hex.substring(0, 80)}`);
      wsFrames.received.push(bytes);
    }
  });
});

console.log('[e2e] navigating to demo_ssh.html...');
try {
  await page.goto('http://127.0.0.1:8765/demo_ssh.html', { timeout: 15000 });
} catch (e) {
  console.error('[e2e] navigation failed:', e.message);
  cleanup();
}

await sleep(5000);

// Capture page content (textContent, joined)
const pageText = await page.evaluate(() => {
  const el = document.getElementById('out');
  return el ? el.textContent : '';
}).catch(() => '');
const pageTextJoined = pageText.replace(/\s+/g, '');

console.log('[e2e] verifying results...');

const serverLogStr = serverLog.join('');

// Verification 1: mock server 收到 client bytes
const expectedServerMessages = [
  'client version: SSH-2.0-MoonBit',
  'got client KEXINIT',
  'got client KEXECDH_INIT',
  'got client NEWKEYS',
];

let serverPassed = 0;
for (const expected of expectedServerMessages) {
  if (serverLogStr.includes(expected)) {
    serverPassed++;
    console.log(`  ✓ mock server: ${expected}`);
  } else {
    console.log(`  ✗ mock server MISSING: ${expected}`);
  }
}

// Verification 2: 浏览器 textContent 显示 SSH demo 输出
// 检查 demo_ssh.html 的 [client] version (17B) 字符串 + client 4 SSH packets
let browserPassed = false;
if (pageTextJoined.includes('[client]version(17B)') && pageTextJoined.includes('[client]WSopened,sendingclientversion...')) {
  browserPassed = true;
  console.log(`  ✓ browser textContent: SSH demo log found (${pageText.length} chars)`);
} else {
  console.log(`  ✗ browser textContent: SSH demo log MISSING (pageText.length=${pageText.length})`);
  console.log(`  pageText first 300 chars: ${pageText.substring(0, 300)}`);
}

// Verification 3: WS frames sent (browser → mock server)
let wsPassed = false;
if (wsFrames.sent.length >= 4) {
  wsPassed = true;
  console.log(`  ✓ WS frames sent: ${wsFrames.sent.length} (≥ 4)`);
} else {
  console.log(`  ✗ WS frames sent: ${wsFrames.sent.length} (< 4)`);
}

// Verification 4: client version byte-exact
const clientVersionBytes = wsFrames.sent.find(
  (b) => new TextDecoder().decode(new Uint8Array(b)) === 'SSH-2.0-MoonBit\r\n',
);
if (clientVersionBytes) {
  console.log(`  ✓ client version byte-exact: ${clientVersionBytes.length}B`);
}

console.log('\n[e2e] ===== SUMMARY =====');
console.log(`  mock server received 4 SSH packets: ${serverPassed}/4`);
console.log(`  browser console SSH-WASM Demo: ${browserPassed ? '✓' : '✗'}`);
console.log(`  WS frames sent ≥ 4: ${wsPassed ? '✓' : '✗'}`);

await browser.close();

let exitCode = 0;
if (serverPassed !== 4 || !browserPassed || !wsPassed) {
  console.log('\n[e2e] ✗ FAIL');
  console.log('\n--- mock server log ---');
  console.log(serverLogStr);
  console.log('--- browser console log ---');
  browserLogs.forEach((l) => console.log(l));
  console.log('--- page text (first 500 chars) ---');
  console.log(pageText.substring(0, 500));
  exitCode = 1;
} else {
  console.log('\n[e2e] ✓ PASS');
}

function cleanup() {
  try { mockServer.kill(); } catch {}
  try { httpServer.kill(); } catch {}
  process.exit(exitCode);
}

cleanup();