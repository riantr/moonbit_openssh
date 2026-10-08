#!/usr/bin/env node
// rebase.mjs -- 打印 cmd/<pkg> 在 4 target x 2 mode 下的输出哈希
//
// 基线哈希是这个仓库唯一的"回归没动过"的凭据:改任何东西之后,除非能说清
// 为什么某个哈希**应该**变,否则它变了就是回归。
//
// 用法: node host/rebase.mjs ecdsa_test [userauth_test ...]
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkgs = process.argv.slice(2);

for (const pkg of pkgs) {
  const seen = new Map();
  for (const t of ['native', 'js', 'wasm', 'wasm-gc']) {
    for (const m of ['debug', 'release']) {
      const r = spawnSync(
        'cmd',
        ['/c', 'moon', 'run', `cmd/${pkg}`, '--target', t, '-d', m],
        { cwd: ROOT, encoding: 'utf-8' }
      );
      const out = `${r.stdout || ''}`.replace(/\r\n/g, '\n');
      const h = createHash('sha256').update(out).digest('hex').slice(0, 16);
      if (!seen.has(h)) seen.set(h, []);
      seen.get(h).push(`${t}/${m}(status ${r.status})`);
    }
  }
  console.log(`${pkg}: ${seen.size} distinct hash(es)`);
  for (const [h, where] of seen) console.log(`  ${h}  <- ${where.join(' ')}`);
}