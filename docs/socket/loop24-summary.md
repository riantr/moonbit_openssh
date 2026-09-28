# Loop #24 Summary — ssh_config fnmatch 解析 (OpenSSH 配置文件)

**Date**: 2026-09-28 (Loop 24/24)
**Status**: ✅ PASS — fnmatch/parser/match 字节级验证完整
**Verdict**: 4 target × 2 mode byte-exact (hash 7f69fdbe8860a78a) + fnmatch 23/23 KAT PASS + ssh_config parser 3 sections + 5 option matches byte-exact

## TL;DR

把 SSH-WASM-SSH 项目从"SSH 协议"扩展到"SSH client 启动路径关键模块 — ssh_config 解析":

| 子目标 | 状态 | 关键产物 |
|---|---|---|
| **G1** OpenSSH fnmatch | ✅ | src/sshconfig/fnmatch.mbt — NFA 双指针回溯 |
| **G2** ssh_config parser | ✅ | src/sshconfig/parser.mbt — 行级 (comment + Host + keyword=value) |
| **G3** Host pattern matching | ✅ | src/sshconfig/match.mbt — first-match-wins |
| **G4** 4 target byte-exact 维持 | ✅ | verify.mjs + verify_loop22.mjs 维持 |

## 关键产物

```
openssh_moonbit/
├── src/sshconfig/                        (新)
│   ├── moon.pkg                          (library)
│   ├── fnmatch.mbt                       (G1: OpenSSH match_pattern 简化版)
│   ├── parser.mbt                        (G2: ssh_config 行级解析)
│   └── match.mbt                         (G3: Host pattern matching)
├── cmd/sshconfig_test/                   (新 exec)
│   ├── moon.pkg
│   └── main.mbt                          (10 行 byte-exact 验证输出)
├── host/verify_loop24.mjs                (新 4 target × 2 mode 验证)
└── docs/socket/
    └── loop24-summary.md
```

## 测试结果

### verify_loop24.mjs (4 target × 2 mode byte-exact)

```
$ node host/verify_loop24.mjs

Per-target SHA-256 (16 chars):
  native-debug         7f69fdbe8860a78a
  native-release       7f69fdbe8860a78a
  js-debug             7f69fdbe8860a78a
  js-release           7f69fdbe8860a78a
  wasm-debug           7f69fdbe8860a78a
  wasm-release         7f69fdbe8860a78a
  wasm-gc-debug        7f69fdbe8860a78a
  wasm-gc-release      7f69fdbe8860a78a

✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: 7f69fdbe8860a78a)
  Loop #24 G1+G2+G3: ssh_config fnmatch/parser/match 完成
  ✓ fnmatch_pass: 23/23
  ✓ parsed_sections: 3
  ✓ foo.example.com match: yes
  ✓ foo.example.com User: foo
  ✓ foo.example.com Port: 2222
  ✓ ngs.fi User: bar
  ✓ ngs.fi HostName: real.host
  ✓ unknown.host ForwardAgent: no
  ✓ foo.example.com NonExistent: none
```

### verify.mjs (Loop #20 不破)

```
✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: 230bfd5b0c02d682)
```

### verify_loop22.mjs (Loop #22 不破)

```
✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致 (hash: 4ac5544049c297cf)
```

## SSH-WASM-SSH Demo (Loop #24) 10 行输出

```
fnmatch_pass: 23/23
parsed_sections: 3
foo.example.com match: yes
foo.example.com User: foo
foo.example.com Port: 2222
ngs.fi User: bar
ngs.fi HostName: real.host
unknown.host ForwardAgent: no
foo.example.com NonExistent: none
```

## 决策合规 (G1-G3)

| # | 决策 | 选定 | 合规? |
|---|---|---|---|
| G1 fnmatch 算法 | 双指针回溯 (NFA 等价简化) | ✅ |
| G2 ssh_config parser | 行级 (空行/comment/Host/keyword=value) | ✅ |
| G3 Host pattern matching | first-match-wins (OpenSSH 默认行为) | ✅ |
| G4 4 target byte-exact | 不破 verify.mjs + verify_loop22.mjs | ✅ |

## 关键发现

### 1. MoonBit String.to_string() 行为
- `Char.to_string()` 返回 decimal code point 字符串 (e.g. `'#'.to_string() == "35"`)
- 不是字面 char "字面" String
- 解决方案:用 `StringBuilder.write_char(char.unsafe_to_char())` 拼接字面 char
- 影响:parser.mbt 内 `s[i].to_string()` 拼接所有 char 必须改用 StringBuilder

### 2. OpenSSH fnmatch 简化
- OpenSSH match.c 用 NFA (epsilon_closure + state machine)
- Loop #24 用**双指针回溯** — 等价算法,代码量小 ~50 行 vs OpenSSH NFA ~100 行
- 测试 23 KAT 全 PASS (与 OpenBSD match_pattern 行为一致)
- 不支持 POSIX [] charclass (Loop #24 简化 — OpenSSH Host pattern 不用 charclass)

### 3. ssh_config parser 简化
- 行级处理 (空行 + # comment 跳过)
- Host PATTERNS... 解析 section header
- keyword value 解析 option
- value 允许多词 (OpenSSH 行为,空格分隔)
- 不支持 Match 块 (OpenSSH 8.x+) — Loop #24 简化
- 不支持 Include 指令

### 4. first-match-wins semantics
- OpenSSH ssh -F config.test 行为:第一个匹配的 Host section 返回 options
- match_host_section 顺序扫 sections,找到首个 fnmatch 匹配的 pattern 即返回
- "Host *" 永远匹配 — 用作 fallback
- example: foo.example.com → first section (*.example.com), unknown.host → third section (Host *)

## 量化指标

| 指标 | 值 |
|---|---|
| src/sshconfig/fnmatch.mbt LOC | 50 行 |
| src/sshconfig/parser.mbt LOC | 200 行 (含 parse + parse_debug) |
| src/sshconfig/match.mbt LOC | 50 行 |
| cmd/sshconfig_test/main.mbt LOC | 110 行 |
| host/verify_loop24.mjs LOC | 130 行 |
| fnmatch KAT tests | 23 个 (?, *, 多 pattern, 嵌套) |
| parser 测试 | 1 个 complex config (3 sections + 5 options + comments) |
| match 测试 | 5 个 hostname lookup + NonExistent fallback |
| 4 target byte-exact | 7f69fdbe8860a78a |
| Loop #20 hash 维持 | 230bfd5b0c02d682 ✅ |
| Loop #22 hash 维持 | 4ac5544049c297cf ✅ |
| Loop 时长 | ~3 hours |

## SSH-WASM-SSH 项目进度

| 阶段 | 状态 |
|---|---|
| 加密基础 byte-exact 跨 4 target | ✅ Loop #15/#16 |
| 浏览器跑 SSH crypto demo | ✅ Loop #17 |
| SSH wire framing + mock client flow | ✅ Loop #18 |
| NEWKEYS 后 chacha20-poly1305 真实加密 | ✅ Loop #19 |
| 完整 SSH client → server demo (双轨制) | ✅ Loop #20 |
| playwright e2e 端到端验证 | ✅ Loop #21 |
| SSH client 完整 write 侧字节级协议闭环 | ✅ Loop #22 |
| IDB roundtrip byte-exact 跨 page | ✅ Loop #22 |
| mock_ssh_server_v2 完整状态机 | ✅ Loop #22 |
| mock_ssh_server_v2_v2 1 ws.send 7 replies | ✅ Loop #23 |
| ssh_client_full_unencrypted_ws (wasm-only path) | ✅ Loop #23 |
| Node.js ws 端到端字节路径 byte-exact | ✅ Loop #23 |
| **OpenSSH fnmatch (?, *)** | ✅ **Loop #24** |
| **ssh_config parser (Host + keyword + comment)** | ✅ **Loop #24** |
| **Host pattern matching first-match-wins** | ✅ **Loop #24** |
| Web Worker + wasm-gc 浏览器端到端 | ⏸️ Loop #25+ |
| WebTransport HTTP/3 server + 真 sshd 连通 | ⏸️ Loop #26+ |
| cert chain / KRL / interactive shell | ⏸️ Loop #27+ |
| AEAD 加密层回包验证 | ⏸️ Loop #27+ |

## 经验教训 (Loop #24)

1. **MoonBit `Char.to_string()` 返回 decimal code point** — 不是字面 char
2. **用 StringBuilder.write_char(char.unsafe_to_char()) 拼接字面 char** — 适用于所有 char-by-char 字符串构造
3. **OpenSSH fnmatch 算法** — NFA 双指针回溯 (epsilon closure),简化实现 ~50 行 vs OpenBSD ~100 行
4. **ssh_config parser** — 行级处理 + first-match-wins semantics
5. **first-match-wins** — OpenSSH 默认行为,与"文件加载顺序"一致
6. **Loop #24 与 known_hosts/match_pattern** 模式相似 — MoonBit 模块从零实现 OpenSSH 子系统

## 不在 Loop #24 范围 (留 Loop #25+)

| 不做 | 后续 Loop |
|---|---|
| POSIX [] charclass in fnmatch | Loop #26+ (ssh_config Match block 需要) |
| ssh_config Match block (OpenSSH 8.x+) | Loop #26+ |
| ssh_config Include directive | Loop #26+ |
| Web Worker + wasm-gc 浏览器端到端 | Loop #25 |
| WebTransport HTTP/3 server | Loop #26+ |
| 真 sshd 连通 (Docker / WSL) | Loop #26+ |
| AEAD 加密层回包验证 | Loop #27+ |
| cert chain / KRL / interactive shell | Loop #27+ |

## 签字

**Loop #24 PASS** — ssh_config fnmatch/parser/match 字节级验证完整

- 算法层: ✅ fnmatch 23/23 KAT (?, * wildcards)
- 解析层: ✅ ssh_config parser 3 sections + 5 options byte-exact
- 匹配层: ✅ Host pattern matching first-match-wins byte-exact
- 4 target: ✅ 8 outputs byte-exact (hash 7f69fdbe8860a78a)
- 不破现有: ✅ Loop #20 (230bfd5b0c02d682) + Loop #22 (4ac5544049c297cf) 维持

完成 SSH-WASM-SSH 项目 "ssh_config 启动路径关键模块 (fnmatch/parser/match)" 从零实现 + byte-exact 验证。下一步进入 **Loop #25+ Web Worker + 浏览器 wasm-gc 端到端** 或 **cert chain / KRL / AEAD 加密层**。