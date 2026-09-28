# Loop #13 Navigator — known_hosts 解析 + host_key_check

**Date**: 2026-09-17
**Navigator**: 6-agent workflow 调研阶段
**Scope**: `src/knownhosts/`（新包）+ `src/kexflow/flow.mbt`（hook 接入）
**预期产物**: src/knownhosts/（~4 文件 ~10 KB）、verify_c/knownhosts_python_ref.py + gen + harness、docs/knownhosts/{navigator,architect,reviewer,reality-checker,loop13-summary}.md

## 目标

1. **解析 known_hosts 文件**：OpenSSH `~/.ssh/known_hosts` 格式（明文 + `|1|` HMAC-SHA1 哈希），一行一个条目，每个条目含主机模式列表（comma 分隔，支持 `*`/`!` 否定）、base64-encoded 密钥 blob、可选注释；标记 `@cert-authority` / `@revoked` 也需识别。
2. **host_key_check**：把协商得到的服务器主机密钥 blob 与 `known_hosts` 条目匹配；若 hostname 命中但密钥不匹配 → `HostKeyMismatch`；若 hostname 未命中且 strict-kex 未启用 → 静默放过（生产场景会"add host"），strict-kex 启用时 → `HostKeyUnknown`。
3. **接入 flow_on_reply**：在已有 `Established` 路径上插入 host_key_check（步骤 6.5，紧跟 sig verify 之后，NEWKEYS 之前）。
4. **三盲验证**：MoonBit 测试套 + C harness（用 OpenSSH sshbuf + sshkey + b64_ntop）+ Python `cryptography` 库生成 KAT 向量。

## 源码地图（E:\src\moon\openssh-C）

### hostfile.c — 主要实现

- **`hostfile_read_key(cpp, bitsp, ret)`** (hostfile.c:158-178)
  - 跳过前导空白 → `sshkey_read(ret, &cp)` → 跳过后导空白
  - `sshkey_read` 调用 `sshbuf_b64tod` 解码 base64，然后 `sshkey_fromb` 解析 SSH wire 格式
  - 不接触 hostname 字段，仅解析 `keytype base64key [comment]` 之后的部分

- **`hostkeys_foreach_file(path, f, callback, ctx, host, ip, options, note)`** (hostfile.c:790-963)
  - 主循环：`getline → 跳过空白/`#`/`\n` → check_markers (CA/revoked) → 找 hostname 终止符
  - hostname 匹配：`match_maybe_hashed(host, lineinfo.hosts, &hashed)` —— 支持明文 + `|1|salt|hash`
  - `hostfile_read_key(&cp, &kbits, lineinfo.key)` 解析 key
  - 调用 callback（带 lineinfo：path/linenum/status/marker/keytype/key/rawkey/comment）

- **`host_hash(host, name_from_hostfile, src_len)`** (hostfile.c:116-150)
  - HMAC-SHA1(salt, host) → b64(salt) `|1|` b64(result) 格式
  - **本子集不实现 host_hash**（生成侧），但**解析侧需要识别 `|1|...` 格式**并按相同算法验证 —— **关键决策点 D3**

- **`check_markers`** (hostfile.c:180-213)
  - `hostnames` 字段前允许 `@cert-authority` / `@revoked` 标记（只有一个）
  - 本子集不需要 CA/revoked 语义，但**解析时应正确识别并跳过**

- **`match_maybe_hashed`** (在 hostfile.c:854-879 内联使用)
  - 拆分逗号分隔的主机模式列表，对每项：
    - 若以 `|1|` 开头 → 提取 salt + HMAC-SHA1(salt, expected_host) 与提供的 hash 比较
    - 否则 → `match_pattern_list(expected_host, pattern)` 通配符匹配（`*`/`?`）
  - **必须区分负向 `!pattern`**

### match.c — 通配符匹配

- **`match_pattern(s, pattern)`** (match.c:82-152)
  - NFA 风格，`*` 匹配零或多字符，`?` 匹配单字符
  - 实现约 70 行（含 `epsilon_closure` 状态传播）
  - **本子集需要**: 完整的 `*`/`?` 通配符 + 逗号分隔的多模式列表

### sshkey.c — blob 解析入口

- **`sshkey_read(ret, cpp)`** (sshkey.c:1313-)
  - 读 keytype 字符串 → `peek_type_nid` 识别 → 读 base64 到 `sshbuf` → `sshkey_fromb` 解析 SSH wire 格式
  - **本子集不需要自己写**：MoonBit 已经有 `HostKey::from_blob(blob)` 接受 SSH wire blob（`string(alg) || string(key_data)`），只需要 base64-decode 后透传

### key_parse.mbt 既有能力

- `HostKey::from_blob(blob) -> ParseResult` 完整支持：
  - `string("ssh-ed25519") || string(pk32)` — Loop #11 V1 验证
  - `string("ssh-rsa") || string(e) || string(n)` — Loop #11 V6 验证
  - TrailingData / TypeMismatch / BigNumNegative 等 8 类错误
- `fingerprint_text(blob)` — Loop #11 fingerprint 测试覆盖
- **不需要改 hostkey 包**，只需 import 即可

## 可复用资产盘点（跨 loops #1–#12）

| 资产 | 位置 | 复用方式 |
|------|------|----------|
| `HostKey::from_blob` | `src/hostkey/key_parse.mbt` | 直接 import，解析 base64-decoded blob |
| `HostKey::verify` | `src/hostkey/sig_verify.mbt` | 已有，flow_on_reply 已在用 |
| `fingerprint_text` | `src/hostkey/fingerprint.mbt` | 可选，用于"host key changed"警告日志 |
| `Base64.ntop/b64 decode` | moonbitlang/core (stdlib) | base64 解码 b64_ntop 兼容 |
| `String.split(",")` | moonbitlang/core | 拆分逗号分隔的 hostnames |
| `match_maybe_hashed` 设计 | OpenSSH hostfile.c | 复刻逻辑（HMAC-SHA1 + 通配符） |
| `c25519_shared_key_mpint` | kexc25519 | Loop #12 已有 |
| `FlowConfig / flow_on_reply` | kexflow/flow.mbt | 在 step 6.5 插入 host_key_check |
| `Established / ReplyOutcome` | kexflow/flow.mbt | 新增 `HostKeyMismatch` / `HostKeyUnknown` 变体 |
| kexflow Python ref | verify_c/kexflow_python_ref.py | 复用：构造真实 known_hosts 条目供 V1/V2 向量 |

## 范围裁定（本子集 vs 全功能 OpenSSH）

| 范围 | 本子集 | OpenSSH 全功能 |
|------|--------|----------------|
| known_hosts 行解析 | ✅（含 comment、CA/revoked marker、空白/注释跳过） | ✅ |
| 逗号分隔多 hostname | ✅ | ✅ |
| 通配符 `*`/`?` | ✅（match_pattern 复刻） | ✅ |
| 否定 `!pattern` | ✅（跳过；本卷不需要 enforced 语义） | ✅ |
| `\|1\|` 哈希条目解析 | ✅（HMAC-SHA1 验证 host） | ✅ |
| `\|1\|` 哈希条目生成 | ❌（生成属集成层） | ✅ |
| 多 IP/CIDR 匹配 | ❌（本子集只需要 hostname 串匹配） | ✅ |
| 端口匹配 `[host]:port` | ❌ | ✅ |
| CA 信任锚 | ❌ | ✅ |
| revoked keys | ❌（标记识别但语义跳过） | ✅ |
| sshfp DNS 集成 | ❌ | ✅ |
| 重复条目去重 | ❌（last-match-wins 即可） | ✅ |
| 主机名校验（通配符拒绝子串攻击） | 基础（match_pattern 自身保证） | ✅ |

**关键决策 D1**：本子集实现"读侧"解析 + "匹配"逻辑，不实现"写侧"生成（`host_hash` 函数和 `add_host_to_hostfile`）。这与 kexflow 的"纯消息层"定位一致（D1 from Loop #12 Architect）。

**关键决策 D2**：匹配采用 **last-match-wins** 语义（OpenSSH 行为：循环遍历文件，后者覆盖前者）。这是 `load_hostkeys_file` 多次调用的结果，每次 `record_hostkey` 都 append 到 entries[]，查找时 `lookup_key_in_hostkeys_by_type` 返回最后一个匹配的条目。

## 三盲设计草案

### Python 参考（knownhosts_python_ref.py）

构造以下 KAT：

- **V1**: 标准 known_hosts 文件（含明文 + 哈希条目 + 注释 + 空行）
- **V2**: 单条目匹配成功（hostname 命中 + key 匹配）
- **V3**: hostname 命中但 key 不匹配（应触发 HostKeyMismatch）
- **V4**: hostname 未命中（应触发 HostKeyUnknown，且 strict_kex=false 时静默放过）
- **V5**: `|1|` 哈希条目匹配（用相同 HMAC-SHA1 salt）
- **V6**: 通配符匹配（`*.example.com` 命中 `foo.example.com`）
- **V7**: 篡改条目（base64 损坏、type 不匹配、trailing 数据）

每个 V 用 `cryptography.hazmat.primitives.serialization.load_ssh_public_key`（Python 3.13+）交叉验证 blob 解析。HMAC-SHA1 用 `hmac.new(salt, host, hashlib.sha1)` 直接算。

### MoonBit 测试（knownhosts_test.mbt）

由 `gen_knownhosts_test.py` 双产：

- **T1**: 解析标准 known_hosts 文件（5 行：注释、明文、哈希、注释、空行）
- **T2**: 解析 + 匹配 → HostStatus::Match (OK)
- **T3**: hostname 命中但 key 不匹配 → HostStatus::Mismatch
- **T4**: hostname 未命中 + strict_kex=true → HostStatus::UnknownStrict（错误）
- **T5**: hostname 未命中 + strict_kex=false → 静默放过（返回 OK + warn 标志）
- **T6**: `|1|` 哈希条目匹配（提供正确 host 触发 hash 计算验证）
- **T7**: 通配符 `*` 匹配
- **T8**: 通配符 `?` 匹配
- **T9**: 否定 `!pattern` 解析但不强制（语义跳过）
- **T10**: 篡改条目（base64 损坏） → ParseError

### C harness（knownhosts_harness.c）

复用现有 `kex_c25519_compat.h` + `sha2_stub.h` + `bsd-sha2.h` + `kex_sshbuf.c` + `kex_sshbuf_getput_basic.c` + `smult_curve25519_ref.c`。**新增需求**：
- HMAC-SHA1（hash 验证）—— 复用 OpenBSD `bsd-sha2.h` 不够，需 OpenSSH `hmac.c` 或简化内联实现（参考 Loop #11 `fingerprint.mbt` 中 SHA-512 的内联实现方式）
- base64-decode（OpenSSH `b64_pton`）—— `kex_sshbuf.c` 已有 `sshbuf_b64tod`，直接用
- 通配符匹配 —— 内联 ~50 行（match_pattern + match_pattern_list）

**预期测试规模**：~16 检查（4 文件 × 4 断言/文件）

## MoonBit 包结构提案

```
src/knownhosts/
├── moon.pkg             # imports: hostkey
├── entry.mbt            # KnownHostEntry struct, Marker enum
├── parse.mbt            # parse_line, parse_file, tokenize_hostnames
├── match.mbt            # match_pattern, match_host_list, match_maybe_hashed
├── check.mbt            # host_key_check (HostStatus enum)
└── knownhosts_test.mbt  # T1–T10 (generated)
```

**关键 API**：
```moonbit
pub(all) enum Marker { None, CertAuthority, Revoked }
pub(all) struct KnownHostEntry {
  marker : Marker
  host_patterns : Array[String]    // 拆分后的 hostname 列表
  host_raw : String                // 原始 "*.example.com,foo" 字符串
  key_type : String                // "ssh-ed25519"
  key_blob : FixedArray[Byte]      // base64-decoded SSH wire blob
  fingerprint : String             // SHA256 base64 fingerprint（可选）
  raw_line : String                // 整行原文）
}

pub(all) enum HostStatus {
  Ok              // 命中且 key 匹配
  Mismatch        // 命中但 key 不匹配 → 拒绝连接
  Unknown         // hostname 未命中（且 strict_kex 决定是否拒绝）
  InvalidEntry    // 行格式错误（解析期就拒绝）
}

pub fn parse_knownhosts(content : String) -> Array[KnownHostEntry]
pub fn lookup_host(entries : Array[KnownHostEntry], host : String, port : Int) -> HostStatus
pub fn check_host_key(entries, host, port, presented_blob, strict_kex) -> HostStatus
```

## 关键决策点汇总

| # | 决策 | 选项 | 选定 |
|---|------|------|------|
| D1 | known_hosts 写侧 | 不实现（集成层职责） | ✅ 选定 |
| D2 | 匹配语义 | last-match-wins（OpenSSH 行为） | ✅ 选定 |
| D3 | `\|1\|` 哈希条目 | 只读（HMAC-SHA1 验证 host） | ✅ 选定 |
| D4 | strict_kex 接入点 | flow_on_reply step 6.5（紧跟 sig verify） | ✅ 选定 |
| D5 | 通配符实现 | 完整 match_pattern（`*`/`?`，不包含 negated semantics 强制） | ✅ 选定 |
| D6 | 多 hostname 匹配 | 逗号分隔 + 任一命中即可 | ✅ 选定 |
| D7 | 端口处理 | 解析 `[host]:port` 形式，端口不匹配则视为不同 host | ✅ 选定（基础版） |
| D8 | base64 编码 | OpenSSH 兼容（`b64_pton`，含 padding） | ✅ 选定 |
| D9 | 与 kexflow 集成 | 在 FlowError 上加 `HostKeyMismatch(String)` / `HostKeyUnknown(String)` 变体 | ✅ 选定 |
| D10 | 测试 KAT 维度 | 7 类向量（V1–V7），覆盖明文/哈希/通配符/篡改 | ✅ 选定 |

## 三盲风险点

1. **HMAC-SHA1 实现**：moonbitlang/core 有 `crypto.hmac`，但 SHA-1 是否在 v0.10.3 默认启用？需要确认 —— 备选：内联实现（参考 OpenSSH hmac.c，~80 行）
2. **base64 解码**：moonbitlang/core `Base64::decode` 是 standard 编码，OpenSSH 兼容（含 `+`/`/`/`=` padding），但需要 verify 对长 base64 串（~200 字符）的解码结果
3. **通配符语义边界**：`*.example.com` 是否匹配 `example.com`？OpenSSH 行为是匹配（`*` 匹配零或多字符）—— 测试 T7 要覆盖这个边界
4. **空 hostname 列表**：`@cert-authority ssh-ed25519 ...` 没有 hostname 字段？OpenSSH 不会写入这种行，但解析端必须 robust 处理（拒绝）
5. **Python `cryptography` 的 known_hosts 支持**：3.13+ 有 `load_ssh_public_key` 但不一定支持 `ssh-rsa` 4096-bit；需要 fallback 到手动解析 base64 + bignum

## Loop #12 经验复用

- **D0（跨包 import）**：v0.10.9 支持，已在 kexflow 验证 → knownhosts 也用 import
- **D8（KAT 双产）**：gen_kexflow_test.py 模式可复用（`@@KEY@@` 占位符、字典替换、C 头生成）
- **Bug 模式**：`parse_kexinit` 的 PfCursor 传值 bug 教会我们：**mutable struct 在 MoonBit 里要小心**。knownhosts 的 `PfCursor`-like 解析器也要用直接索引而非 struct 字段
- **错误分类学**：OpenSSH `SSH_ERR_*` codes 已映射到 `KeyError` 8 变体；knownhosts 解析错误复用同样的分类学
- **不可变快照**：knownhosts 解析的输入是文件内容字符串（不可变），解析产物 `Array[KnownHostEntry]` 也不可变；运行时只做"匹配"和"指纹比较"

## 下一步

进入 Architect 阶段。Navigator 阶段结束。