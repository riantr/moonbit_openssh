# Loop #14 Architect — `[host]:port` + Revoked 完整语义 设计

**Date**: 2026-09-18
**Architect**: 6-agent workflow 设计阶段

## 范围

| 已实现 (Loop #13) | 本 Loop #14 增量 | 留 Loop #15+ |
|---|---|---|
| Parser 单 host / 逗号 / 通配符 / `|1|` HMAC / `@cert-authority` / `@revoked` 识别 | **`[host]:port]` 拆分** + **`@revoked` 业务拒绝** | CA 完整 cert chain / 写侧 / KRL |
| last-match-wins Ok/Mismatch/Unknown | **last-match-wins + port-aware** + **Revoked 后置全局扫** | — |
| check_host_key (无 port 参数) | **check_host_key 加 port 参数** + backward-compat shim | — |

## 数据结构变更

### `KnownHostEntry` Loop #13
```moonbit
pub(all) struct KnownHostEntry {
  marker : Marker
  host_patterns : Array[String]    // 拆分后的 hostname 列表
  host_raw : String                // 原始 "example.com,*.example.com"
  key_type : String
  key_blob : FixedArray[Byte]
  raw_line : String
  linenum : Int
}
```

### `KnownHostEntry` Loop #14 (改后)
```moonbit
priv struct HostSpec {
  host_only : String              // inner "example.com" or "*.example.com"
  host_port : Int?                // Some(2200) for explicit port, None for default
}

pub(all) struct KnownHostEntry {
  marker : Marker
  host_patterns : Array[String]    // 拆分后的 string 列表（保留供 messages）
  host_specs : Array[HostSpec]     // 拆分 + 解析后的 (host_only, port?) — 与 host_patterns 平行
  host_raw : String
  key_type : String
  key_blob : FixedArray[Byte]
  raw_line : String
  linenum : Int
}
```

**关键设计决策**:
- 保留 `host_patterns : Array[String]` 原始字面,供 caller 做错误消息、`raw_line` 取值、debug 输出。
- 新增 `host_specs : Array[HostSpec]` 已 parse 的(host_only, port?)对,供 `check_host_key` 内部逻辑使用。
- 长度**严格平行**:`host_specs.length() == host_patterns.length()`,第 i 个对应同一个 pattern。
- `HostSpec` 是 `priv` struct(对外不暴露内部细节)— caller 只需看 `host_patterns` 调试。

## API 变更

### `check_host_key` 签名变更
```moonbit
// Loop #13:
pub fn check_host_key(
  entries : Array[KnownHostEntry],
  host : String,
  presented_blob : FixedArray[Byte],
) -> HostStatus

// Loop #14 (改后):
pub fn check_host_key(
  entries : Array[KnownHostEntry],
  host_str : String,         // 可以是 "example.com" or "[example.com]:2200" 二选一
  port : Int,                // 0 = SSH default 22
  presented_blob : FixedArray[Byte],
) -> HostStatus

// Loop #14 保留向后兼容(overload 风格):
pub fn check_host_key_legacy(
  entries : Array[KnownHostEntry],
  host : String,
  presented_blob : FixedArray[Byte],
) -> HostStatus {
  check_host_key(entries, host, 0, presented_blob)  // port=0 = default
}
```

### `check_host_key_strict` 同样改
```moonbit
pub fn check_host_key_strict(
  entries : Array[KnownHostEntry],
  host_str : String,
  port : Int,
  presented_blob : FixedArray[Byte],
  strict_kex : Bool,
) -> HostStatus
```

### `match_host_pattern` 内部
- 不公开签名(已是 `pub`)
- 但**语义**变:输入 `host` 现在可以是 `[host]:port` 格式,内部 normalize 后比
- **API breaking**: 任何外部 caller 直接调 `match_host_pattern(host, pattern)` 在 Ring #13 之后需要传 normalized host_only。新增兼容 wrapper `match_host_pattern_legacy(host, pattern)` 假设 host 不含 port。

## 算法: `check_host_key` 新流程

```
fn check_host_key(entries, host_str, port, presented_blob):
  if entries is empty:
    return Unknown

  // 1. Normalize caller's host_str
  let caller_host_only = split_host_str(host_str)  // 解包 "[host]:port"
  let caller_port = if port == 0: 22 else: port

  // 2. last-match-wins 找 match
  let mut last_match : KnownHostEntry? = None
  for entry in entries:
    for spec in entry.host_specs:
      if entry_marker_skip(entry) continue      // Revoked entries 不参与 host match 选 entry
                                               // 但后面会全局扫 @revoked
      // host pattern 匹配
      if not match_pattern_nfa(caller_host_only, spec.host_only):
        continue
      // port 必须匹配
      if spec.host_port exists && spec.host_port.value != caller_port:
        continue
      // 命中
      last_match = Some(entry)
      break  // spec 跳出,继续下一个 entry

  // 3. 后置:全 entries @revoked 检查
  for entry in entries:
    if entry.marker != Revoked:
      continue
    if blob_eq(entry.key_blob, presented_blob):
      return Mismatch   // Revoked hit, regardless of host match

  // 4. 决定最终 status
  match last_match:
    None => return Unknown
    Some(e) =>
      if blob_eq(e.key_blob, presented_blob):
        Ok
      else:
        Mismatch
```

### 关键行为改变点

| 场景 | Loop #13 行为 | Loop #14 行为 |
|---|---|---|
| `host_str="foo.com"` + entry `"foo.com"` | Ok | Ok（不变） |
| `host_str="foo.com"` + entry `"[foo.com]:2200"` | 字面不等 → Unknown | port mismatch → Unknown |
| `host_str="[foo.com]:2200"` + entry `"[foo.com]:2200"` | 字面 == → Ok | host_only match + port match → Ok |
| `host_str="foo.com"` `port=0` + entry `"foo.com"` | Ok | 同 |
| `@revoked foo.com A` + presented A | Ok（last-match 命中 foo.com A） | **Mismatch**（Revoked 后置扫） |
| `@revoked foo.com B` + `foo.com A` (later) + presented A | Ok(last-match 命中 A) | Ok（Revoked 是 B,不 hit presented A） |

### `split_host_str` 算法

```
fn split_host_str(s : String) -> String:
  // 解析 host_str;如果 "[host]" 或 "[host]:port" 格式 → 解括号返回 host 部分
  if s.length() >= 1 && s[0] == '[':
    let close = find ']' in s
    if close < 0:
      return s  // 错误;fallback
    return s.substring(1, close)   // inner host
  return s
```

简化版本仅处理 `[host]` 与 `[host]:port` 两种包装,不处理 nested IPv6 zones。

## KAT V9-V12

| 测试 | host_str | port | entries | blob | expected | OpenSSH 对应 |
|---|---|---|---|---|---|---|
| V9 plain host + default port | `"foo.example.com"` | 0 | `foo.example.com ssh-ed25519 A` | A | Ok | 字面 match |
| V10 `[host]:2200` explicit | `"[foo.example.com]:2200"` | 0(normalize) | `[foo.example.com]:2200 ssh-ed25519 A` | A | Ok | 字面 match via split |
| V11 port mismatch | `"foo.example.com"` | 0 | `[foo.example.com]:2200 ssh-ed25519 A` | A | Unknown(port) | 字面 mismatch |
| V12 @revoked reject | `"foo.example.com"` | 0 | `@revoked foo.example.com ssh-ed25519 B`<br>`foo.example.com ssh-ed25519 A`(后) | A | Mismatch(Revoked wins) | `HOST_REVOKED` |

### KAT 回归: V1-V8 不变
- 所有 V1-V8 (Loop #13) 必须仍 PASS(后向兼容)
- 实现后跑 moon test 期望 228 + 4 = 232 个测试通过

## kexflow 集成变更

### `FlowConfig` 加 `host_port : Int`
```moonbit
// Loop #13:
pub(all) struct FlowConfig {
  version_client, version_server, cookie, client_seed,
  strict_kex : Bool,
  hostname : String,
  knownhosts_entries : Array[KnownHostEntry],
}

// Loop #14:
pub(all) struct FlowConfig {
  ..., // 同上
  hostname : String,
  host_port : Int,                    // NEW:0 = default 22
  knownhosts_entries : Array[KnownHostEntry],
}
```

`FlowConfig::make` 签名同步加 `host_port : Int`(Loop #13 已经 7 字段,Loop #14 加 1,变 8 字段)。

### `flow.mbt` step 6.5 调用更新
```moonbit
// Loop #13:
let host_status = @knownhosts.check_host_key_strict(
  cfg.knownhosts_entries, cfg.hostname, rep.hostkey_blob, cfg.strict_kex,
)

// Loop #14:
let host_status = @knownhosts.check_host_key_strict(
  cfg.knownhosts_entries, cfg.hostname, cfg.host_port, rep.hostkey_blob, cfg.strict_kex,
)
```

`cfg.host_port = 22` (默认 SSH port)如果 caller 不想分端口。

## 决策点

| # | 决策 | 选项 | 选定 |
|---|---|---|---|
| D1 | `[host]:port` 字面 vs split | (a) 字面 (b) split (c) hybrid | **(c) hybrid**(API normalized entry 字段,caller 还能传字面) |
| D2 | port 字段类型 | `Int` (32-bit) vs `UInt16` (port) | **`Int`**(MoonBit String parse 路径已经返回 Int;UInt 转换代价高) |
| D3 | port=0 语义 | 默认 22 vs 任意 | **默认 22**(SSH_DEFAULT_PORT,匹配 OpenSSH) |
| D4 | Revoked 检查位置 | (a) 主循环内 (b) 后置全局扫 | **(b) 后置全局扫**(OpenSSH 行为) |
| D5 | Revoked 跟 last-match-wins 优先级 | (a) Revoked wins (b) last-match wins (c) 取决于 order | **(a) Revoked wins**(OpenSSH 行为 — key 在 @revoked 中永远拒) |
| D6 | Revoked 跟 strict_kex 关系 | (a) 独立 (b) 仅 strict 触发 | **(a) 独立**(OpenSSH 行为 — always on) |
| D7 | `|1|` hash + port | (a) 不支持 (b) host_only HMAC | **(b) host_only HMAC**(OpenSSH 行为) |
| D8 | HostSpec 可见性 | (a) `pub` (b) `priv` (c) `pub(all)` | **(b) priv**(只在本包内使用) |
| D9 | host_patterns 保留 | (a) 删 (b) 保留供 debug/messages | **(b) 保留**(供 error messages) |
| D10 | IPv6 字面 `[::1]:22` | 字符串 normalize 不展开 | 同 OpenSSH |
| **D11** | Revoked 字面 key_blob 比对 vs OpenSSH fingerprint | (a) key_blob byte-eq (b) fingerprint-text EQ | **(a) 简化版**(对应 sshkey_equal_public 行为;fingerprint 推 Loop #15+ KRL) |
| **D12** | API 兼容老 caller | 改签名 vs 加 `_legacy` shim | **改签名 + 同步改 kexflow**(避免两条 API 易混;kexflow 是 Loop #13 唯一 caller) |

## API 变更总表

| Loop #13 API | Loop #14 变更 |
|---|---|
| `KnownHostEntry { ..., host_patterns : Array[String] }` | + `host_specs : Array[HostSpec]` |
| `parse_line`, `parse_file` | 增加 `[host]:port` 拆分 |
| `match_host_pattern(host, pattern_list)` | 接受 caller host 可含 `[host]:port`,内部 normalize;语义升级 |
| `check_host_key(entries, host, blob)` | **改签名**:`+ port : Int` |
| `check_host_key_strict(entries, host, blob, strict_kex)` | **改签名**:`+ port : Int` |
| `FlowConfig::make(..., hostname, entries)` | + `host_port : Int` |
| `flow_on_reply` step 6.5 | 用 `cfg.host_port` 调 `check_host_key_strict` |

## 测试矩阵 T1-T12(扩展 → T1-T14)

| T | 内容 | 测试 |
|---|---|---|
| T1-T12 | Loop #13 已存 | (回归) |
| T13 | V9 plain + default port → Ok | 新增 |
| T14a | V10 `[host]:2200` → Ok | 新增 |
| T14b | V11 port mismatch → Unknown | 新增 |
| T14c | V12 @revoked wins → Mismatch | 新增 |

## 复杂度 / 行数预算

| 文件 | 增/改行 |
|---|---|
| `entry.mbt` | +30 (HostSpec + new fields) |
| `parse.mbt` | +60 (split `[]`:port` per pattern) |
| `match.mbt` | +30 (`split_host_str` + helper) |
| `check.mbt` | +50 (last-match-wins 路径 + Revoked 全局扫) |
| `flow.mbt` | +15 (FlowConfig field + host_port 接入) |
| `kexflow_test.mbt` | (回归不需改,因 KAT 不变 V1-V8) |
| `knownhosts_test.mbt` | +80 (V9-V12 blackbox) |
| **总** | ~265 行新增/改 |

## 风险与回退

1. **API breaking** Loop #13 唯一外部 caller `flow.mbt` 已知,同步改无遗漏风险
2. **`split_host_str` corner case**: `[host]:port` 内 host 包含 `]` — OpenSSH 不支持(`]` 是字面)。本 Loop 一致。
3. **IPv6 `[::1]:22`** 内含 `[`,`:`,`]`: OpenSSH `put_host_port` 只包一层 `[`,不做 IPv6 zone 处理;本 Loop 一致,不展开 IPv6 字面。
4. **Revoked strict KRL**: 本 Loop 不实现 KRL (key revocation list),只支持 plain text `~/.ssh/known_hosts` 形式 `@revoked` 行。生产场景中 attacker 通过 KRL 撤 key 时不会工作 — 留风险记录。

## 实施 / 文档 / 测试产物

| 类型 | 文件 |
|---|---|
| 源码 | `src/knownhosts/{entry,parse,match,check}.mbt` + `src/kexflow/flow.mbt` |
| 测试 | `src/knownhosts/knownhosts_test.mbt`(gen 加 V9-V12) |
| Python ref | `verify_c/knownhosts_python_ref.py`(扩 V9-V12,自检扩到 38+) |
| KAT gen | `verify_c/gen_knownhosts_test.py`(扩 V9-V12 placeholder 替换) |
| C harness | `verify_c/knownhosts_harness.c`(扩 V9-V12,扩 selfcheck) |
| 文档 | `docs/knownhosts/{navigator14,architect14,reviewer14,reality_checker14,loop14-summary}.md` |

## 完成判据

- moon info 0 errors + 0 new warnings(deprecated substring warning 保留,非阻断)
- moon test 232/232 全绿(228 已有 + 4 新增)
- C harness 22/22 全绿(18 已有 + 4 新增)
- Python self-check 38+/38+(34 已有 + 4 新增)
- 三盲 byte-exact:SHA-1/HMAC/NFA/parse/check/Revoked 全一致
- FlowConfig::make + host_port 调用,kexflow 回归 PASS

进入实施阶段。
