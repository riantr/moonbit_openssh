# Loop #13 Architect — known_hosts 包设计 + host_key_check 接入

**Date**: 2026-09-17
**Architect**: 6-agent workflow 设计阶段

## 包结构

```
src/knownhosts/
├── moon.pkg               # imports: openssh/.../hostkey（仅）
├── entry.mbt              # KnownHostEntry, Marker, HostStatus, KnownHostsOptions
├── parse.mbt              # parse_line, parse_file, parse_base64_blob
├── match.mbt              # match_pattern, match_host_pattern, match_hashed_host
├── check.mbt              # host_key_check, build_knownhosts_from_blob
└── knownhosts_test.mbt    # T1–T10（generated）
```

**moon.pkg**：
```moonbit
// SSH known_hosts 解析 + host_key_check（last-match-wins 语义，
// OpenSSH hostfile.c:790-963 + match.c:82-152 转写）。
import {
  "openssh/openssh_moonbit/src/hostkey",
}
```

只依赖 `hostkey`（用于 `HostKey::from_blob` 解析 blob）。**不依赖** kexflow / kexc25519 / bpacket —— knownhosts 是独立子模块，kexflow 会反过来 import 它。

## 模块 API 设计

### `entry.mbt`

```moonbit
/// known_hosts 行标记
pub(all) enum Marker {
  None            // 普通条目
  CertAuthority   // @cert-authority 信任锚（语义跳过，不强制）
  Revoked         // @revoked 吊销（语义跳过）
}

/// 匹配结果
pub(all) enum HostStatus {
  Ok              // 命中且 key 匹配
  Mismatch        // 命中但 key 不匹配
  Unknown         // hostname 未命中（strict_kex 决定升级路径）
  InvalidEntry    // 行解析错误
}

/// 单个 known_hosts 条目
pub(all) struct KnownHostEntry {
  marker : Marker
  host_patterns : Array[String]    // 拆分后的 hostname 列表（已 trim）
  host_raw : String                // 原始 "*.example.com,foo.example.com"
  key_type : String                // "ssh-ed25519"
  key_blob : FixedArray[Byte]      // base64-decoded SSH wire blob
  raw_line : String                // 整行原文（用于错误消息）
  linenum : Int                    // 源文件行号（用于错误消息）
}
```

### `parse.mbt`

```moonbit
/// 解析单行 known_hosts 条目
pub fn parse_line(line : String, linenum : Int) -> KnownHostEntry? // None 表示注释/空行/无效

/// 解析完整 known_hosts 内容
pub fn parse_file(content : String) -> Array[KnownHostEntry]

/// base64 解码 SSH wire blob（OpenSSH b64_pton 兼容，含 padding）
fn parse_base64_blob(s : String) -> FixedArray[Byte]?
```

### `match.mbt`

```moonbit
/// NFA 通配符匹配（OpenSSH match_pattern 转写）
/// * 匹配零或多字符；? 匹配单字符
fn match_pattern(s : String, pattern : String) -> Bool

/// 逗号分隔模式列表匹配（OpenSSH match_pattern_list）
fn match_host_pattern(host : String, pattern_list : String) -> Bool

/// 检测 `|1|salt|hash` 哈希条目前缀
fn is_hashed_host(s : String) -> Bool

/// HMAC-SHA1(salt, expected_host) 验证哈希条目
fn match_hashed_host(expected_host : String, hashed_pattern : String) -> Bool
```

### `check.mbt`

```moonbit
/// last-match-wins 查找：遍历 entries，返回最后一个 hostname 命中
/// 的条目（不论 key 是否匹配——key 匹配由 caller 决定）
fn find_last_match(entries : Array[KnownHostEntry], host : String) -> KnownHostEntry?

/// host_key_check 主体逻辑（hostfile.c:408 check_key_in_hostkeys 转写）
/// 返回：
///   Ok        — 命中且 key blob 匹配（经 HostKey::from_blob 验证类型 + 字节相等）
///   Mismatch  — 命中但 key blob 不同（类型不符或字节不等）
///   Unknown   — hostname 未命中
///   InvalidEntry — entries 中有但无匹配（entries 为空也算此）
pub fn check_host_key(
  entries : Array[KnownHostEntry],
  host : String,
  presented_blob : FixedArray[Byte],
) -> HostStatus

/// strict-kex 感知：strict_kex=true 时把 Unknown 升级为拒绝
/// （kexflow 在 step 6.5 调用此函数）
pub fn check_host_key_strict(
  entries : Array[KnownHostEntry],
  host : String,
  presented_blob : FixedArray[Byte],
  strict_kex : Bool,
) -> HostStatus
```

## kexflow 集成（flow.mbt 修改）

**插入点**：step 6.5，紧跟 sig verify 之后，NEWKEYS 之前。

```moonbit
// ---- step 6.5: host_key_check（Loop #13 接入）----
// knownhosts.entries 由调用方传入（集成层读取 ~/.ssh/known_hosts）
// None 表示"没有 trusted_hosts 文件"或"调用方禁用 TOFU"
let host_status = match cfg.knownhosts_entries {
  Some(entries) => @knownhosts.check_host_key_strict(
    entries, cfg.hostname, rep.hostkey_blob, cfg.strict_kex,
  )
  None => @knownhosts.HostStatus::Ok  // 无 known_hosts：跳过检查（生产场景应禁用）
}
match host_status {
  Ok => ()
  Mismatch => return Failed(HostKeyMismatch(cfg.hostname))
  Unknown => if cfg.strict_kex {
    return Failed(HostKeyUnknown(cfg.hostname))
  }
  InvalidEntry => return Failed(ProtocolError)  // entries 中有无效行（非解析错误，而是 entries 自洽性失败）
}
```

### FlowError 扩展（flow.mbt）

```moonbit
pub(all) enum FlowError {
  /// 已有 5 个
  ProtocolError
  NoAgreement(NegotiationError)
  HostkeyInvalid
  SignatureInvalid
  SharedSecretInvalid
  /// 新增 2 个（Loop #13）
  HostKeyMismatch(String)    // hostname 命中但 key 不匹配
  HostKeyUnknown(String)     // strict_kex 下 hostname 未命中
}
```

### FlowConfig 扩展（flow.mbt）

```moonbit
pub(all) struct FlowConfig {
  version_client : FixedArray[Byte]
  version_server : FixedArray[Byte]
  cookie : FixedArray[Byte]
  client_seed : FixedArray[Byte]
  strict_kex : Bool
  /// 新增（Loop #13）
  hostname : String                              // 用于 host_key_check
  knownhosts_entries : Array[KnownHostEntry]?     // None = skip check
}
```

`FlowConfig::make` 增加 2 个参数。**KAT 兼容性**：所有现有调用需要更新 —— Loop #12 的 `kexflow_test.mbt` 中只有 `flow_start(cfg, my)` 和 `flow_on_reply(...)` 调用，需要把 `make` 的新参数填 `""` 和 `None`。

### flow.mbt step 6.5 实际接线（伪代码）

```moonbit
// ---- input_kex_gen_reply (现有 steps 1-6) ----
// 1. parse peer KEXINIT
// 2. negotiate
// 3. parse_reply (kexc25519)
// 4. hostkey.from_blob → ed25519 pk
// 5. shared secret mpint
// 6. kex_gen_hash → H
// 7. hostkey.verify(H, sig_blob)
// 8. NEW step 6.5: host_key_check (Loop #13)
let host_status = match cfg.knownhosts_entries {
  Some(entries) => @knownhosts.check_host_key_strict(
    entries, cfg.hostname, rep.hostkey_blob, cfg.strict_kex,
  )
  None => @knownhosts.HostStatus::Ok
}
match host_status {
  Ok => ()
  Mismatch => return Failed(HostKeyMismatch(cfg.hostname))
  Unknown =>
    if cfg.strict_kex { return Failed(HostKeyUnknown(cfg.hostname)) }
  InvalidEntry => return Failed(ProtocolError)
}
// 9. derive_keys + NEWKEYS
```

## 决策点

| # | 决策 | 选项 | 选定 |
|---|------|------|------|
| D1 | known_hosts 写侧 | 不实现 | ✅ |
| D2 | 匹配语义 | last-match-wins | ✅ |
| D3 | `\|1\|` 哈希 | 只读，HMAC-SHA1 验证 | ✅ |
| D4 | strict-kex 接入 | flow_on_reply step 6.5 | ✅ |
| D5 | 通配符 | 完整 `*`/`?` | ✅ |
| D6 | 多 hostname | 逗号分隔，任一命中 | ✅ |
| D7 | 端口 | `[host]:port` 解析 + 端口分离 | ✅（基础版） |
| D8 | base64 | OpenSSH 兼容 | ✅ |
| D9 | FlowError 扩展 | 新增 2 变体（HostKeyMismatch/HostKeyUnknown） | ✅ |
| D10 | KAT 维度 | V1–V7 | ✅ |
| **D11** | **HMAC-SHA1 实现** | **内联 SHA-1 + HMAC 包装（~80 行）** | ✅ |
| **D12** | **knownhosts 公开 vs priv** | **entry/marker/hoststatus pub；match/parse/check pub；中间 helpers priv** | ✅ |

### D11 详细说明

moonbitlang/core `crypto.hmac` 在 v0.10.3 默认可能不启用 SHA-1（部分发行版禁用了 SHA-1）。备选：
- 内联 SHA-1 实现（~150 行，参考 RFC 3174）
- 内联 HMAC wrapper（~30 行）

`knownhosts/match.mbt` 顶部声明：
```moonbit
///| 内联 SHA-1 + HMAC-SHA1（参考 RFC 3174 + RFC 2104）
///| 已知 moonshadow / crypto.hmac 在 v0.10.3 默认可能不启用 SHA-1
///| moonbitlang/core 的内联实现可绕过此限制
```

### D12 详细说明

| 函数 | 可见性 | 原因 |
|------|--------|------|
| `parse_line`, `parse_file`, `parse_base64_blob` | `pub` | 测试需要 |
| `match_pattern`, `match_host_pattern` | `pub` | 测试覆盖边界 |
| `is_hashed_host`, `match_hashed_host` | `pub` | 测试覆盖哈希条目 |
| `find_last_match` | `pub` | 测试需要（虽然 caller 一般用 check_host_key） |
| `check_host_key`, `check_host_key_strict` | `pub` | kexflow 入口 |
| `KnownHostEntry`, `Marker`, `HostStatus` | `pub(all)` | kexflow match 用 |
| SHA-1 / HMAC 内联函数 | `priv` | 内部辅助 |

## KAT 维度（10 个测试 T1–T10）

| # | 测试 | 验证内容 |
|---|------|----------|
| T1 | 解析标准 known_hosts | 5 行（注释、明文、哈希、注释、空行）→ 3 个有效条目 |
| T2 | 单条目匹配 | hostname 命中 + key 匹配 → Ok |
| T3 | hostname 命中但 key 不匹配 | → Mismatch |
| T4 | hostname 未命中 + strict_kex=false | → Unknown（但不拒） |
| T5 | hostname 未命中 + strict_kex=true | → Unknown → 升级为拒绝 |
| T6 | `\|1\|` 哈希条目匹配（提供正确 host） | → Ok |
| T7 | `\|1\|` 哈希条目不匹配（提供错误 host） | → Unknown |
| T8 | 通配符 `*.example.com` 匹配 `foo.example.com` | → Ok |
| T9 | 否定 `!pattern` 解析但不强制 | 解析为 pattern，不在匹配路径使用 |
| T10 | 篡改条目（base64 损坏） | → InvalidEntry |

每条测试用 `gen_knownhosts_test.py` 双产：
- `knownhosts_test.mbt`：字面量内嵌（hex 串 + 期望条目数 + 期望 HostStatus）
- `_knownhosts_kat.h`：C 头（uint8_t[] + size_t）

## 风险点与回退方案

| 风险 | 缓解 |
|------|------|
| HMAC-SHA1 实现 bug | 与 Python `hmac.new(salt, host, hashlib.sha1)` 交叉验证；内联 SHA-1 参考 RFC 3174 测试向量 |
| base64 兼容 | Python `base64.b64decode(s)` 与 MoonBit `Base64::decode` 字节级对比 |
| 通配符边界 | T8 覆盖 `*` 匹配零字符、多字符、单字符；T7 不覆盖 `*` 但 T8 + T9 互补 |
| `\|1\|` 哈希 salt 长度 | OpenSSH SHA1 = 20B salt + 20B hash；HMAC 验证为 `sha1(salt + host)` 等价 |
| FlowConfig 兼容性 | 改 `make` 签名后，所有 caller 必须更新；kexflow_test.mbt 自动重生成 |
| kexflow KAT H 不受影响 | step 6.5 插入对 steps 1-7 无影响；step 9 (derive_keys + NEWKEYS) 仅在 Ok/Unknown(非 strict) 时执行 |

## 时间线

1. **Navigator** ✅ (本文)
2. **Architect** ✅ (本文)
3. **实现** (~30 min)：写 entry/parse/match/check 4 个 .mbt 文件（~600 行）
4. **Python 参考 + 测试** (~20 min)：knownhosts_python_ref.py → V1-V7 + sanity；gen_knownhosts_test.py 双产
5. **MoonBit 测试** (~5 min)：moon test 应绿 216+10 = 226/226
6. **C harness** (~30 min)：knownhosts_harness.c + build 脚本；hmac.c + b64_pton 内联
8. **Reviewer + Reality Checker + loop13-summary** (~20 min)

## 下一步

进入实现阶段。Architect 阶段结束。