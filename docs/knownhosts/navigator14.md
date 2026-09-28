# Loop #14 Navigator — D7 [host]:port + Revoked 完整业务语义

**Date**: 2026-09-18
**Navigator**: 6-agent workflow 调研阶段
**Scope**: 补 Loop #13 留下的两个缺口 — `[host]:port` 端口拆分（D7 ⚠️ 部分）+ Revoked 完整业务语义（重大安全缺口）

## OpenSSH 源码调研

### D7 部分：`[host]:port` 端口处理

#### OpenSSH 没有 "port parsing" — 用 string-equal
- `misc.c:786` `put_host_port(host, port)`:
  - port == 0 or port == 22 (SSH_DEFAULT_PORT): 返回 `xstrdup(host)` (no brackets, no port)
  - otherwise: `[%s]:%d` (asprintf `[host]:port`)
- `sshconnect.c:1038` `get_hostfile_hostname_ipaddr(hostname, hostaddr, clobber_port ? 0 : port, &host, &ip)`:
  - 构造 **query host_str** = `put_host_port(hostname, port)`
  - 后续 `hostkeys_foreach_file(..., host_str, ...)` 在 hostfile.c 内部做 `match_maybe_hashed(host_str, lineinfo.hosts)`
- 在 `hostfile.c:769` `match_maybe_hashed`: 实际上只调用 `match_hostname(host, names)`,后者(`match.c:82`)是 NFA `*`/`?`,**port 是字面 string 的一部分**,不特别拆出。
- 结果: OpenSSH known_hosts hosts 字段**如果用户写了 `[host]:2200`,后续比对也用 `[host]:2200`** — 系统两端字符串一致即可。**内部完全不解析 port**。

#### Arch 决定分支
| 选项 | 行为 | 影响 |
|---|---|---|
| (a) Mirror OpenSSH 字面 | API 接受 host_str 完整 `[host]:port`,内部字面 match | 最小改动:caller 须构造匹配 host_str |
| (b) Mirror + normalize | parse_line 把 `[host]:port]` 拆 host + port 字段单独存;match 时独立比;caller 传 plain host + port | 需要新 API,全栈重构 |
| (c) Hybrid | parse_line 拆;新 `check_host_key(entries, host, port?, blob)`;同时保留旧 caller 兼容 | 推荐 |

#### 选 (c) Hybrid:
- `KnownHostEntry` 增加 `host_only : String` + `host_port : Int?` 字段 (parsed)
- `parse_line` 检测 `[host]:port]` host_pattern → 拆 host_only + port?,存 entry
- 新 API: `check_host_key(entries, host_str, host_port, presented_blob)`
  - host_str 可以是 plain `"example.com"` 或 `[host]:port]` 两种形式 → 内部 normalize
  - host_port 是 explicit 端口(0 = default port 22)
- Match 逻辑:
  - 先 normalize caller 的 `host_str` → (host_only_caller, port_caller)
  - 对每个 entry:
    - entry 的 hosts 字段 split → 多个 (host_only_entry, port_entry?)
    - host 部分按 `match_pattern_nfa(host_only_caller, host_only_entry)`
    - if entry has port, only match when port_caller == port_entry
    - **last-match-wins** (与 Loop #13 D2 一致)

### Revoked 业务语义

#### OpenSSH `check_key_not_revoked` (hostfile.c:315)

```c
static int
check_key_not_revoked(struct hostkeys *hostkeys, struct sshkey *k)
{
    int is_cert = sshkey_is_cert(k);
    u_int i;
    for (i = 0; i < hostkeys->num_entries; i++) {
        if (hostkeys->entries[i].marker != MRK_REVOKE)
            continue;
        if (sshkey_equal_public(k, hostkeys->entries[i].key))
            return -1;  // revoked!
        // cert 路径:比对 cert 的 signature_key (CA 的 key)
        if (is_cert && k != NULL &&
            sshkey_equal_public(k->cert->signature_key,
            hostkeys->entries[i].key))
            return -1;
    }
    return 0;
}
```

调用点 (hostfile.c:399) 在 `check_hostkeys_by_key_or_type` 末尾:
```c
if (check_key_not_revoked(hostkeys, k) != 0) {
    end_return = HOST_REVOKED;
    if (found != NULL)
        *found = NULL;
}
```

**Key takeaway**:
- Revoked 检查**全局** — 扫所有 entries,不管 marker 以外的 host pattern / hosts spec
- 比对的是**public key 字节** (`sshkey_equal_public`) — 不靠 fingerprint
- 命中 → `end_return = HOST_REVOKED`,found 置 NULL — 等价于"既不匹配也不接受"

#### Arch 决定 (Revoked)
- **算法**: 在 `check_host_key` 末段扫 entries,如果任何 `marker == Revoked && key_blob == presented_blob` → return **Mismatch** (我们 MoonBit 的 `HostStatus::Mismatch` 与 OpenSSH `HOST_REVOKED` 同义 — 都是拒绝)
- **优先级 vs last-match-wins**: Revoked 全局检查,**即使 last-match 命中某个非 Revoked entry,presented_blob 若在任意 Revoked entry → Mismatch(覆盖 last-match)**。这是 OpenSSH 真实行为。
- **`strict_kex` 影响**: Revoked 检查**独立于 strict_kex**,即 non-strict mode 下 presented key 也在 @revoked 列表中也拒绝。OpenSSH 行为一致。
- **cert 路径**: 本子集不实现 cert 解析,只支持 key_blob 比对(ed25519 公钥),与 OpenSSH 比 sshkey_equal_public 实质等价(byte-exact on ssh wire blob)

### CA 业务语义(不实现,记录)

OpenSSH `check_hostkeys_by_key_or_type` (hostfile.c:349):
- `want_marker = want_cert ? MRK_CA : MRK_NONE` (L356)
- L362: `if (hostkeys->entries[i].marker != want_marker) continue;`
- 如果 `want_cert=true`: 找 entry with `marker == MRK_CA`,比对 `k->cert->signature_key == entry.key`
- 否则: 找 entry with `marker == MRK_NONE`,比对 `k == entry.key`

完整 CA 实现需要:
1. 解析 X.509 cert (RFC 5280) 提取 `signature_key`
2. 维护 cert 链 (CA chain)  
3. cert validation (basic constraints, expiry, etc.)

**本 Loop 不实现** — 留 Loop #15+,标注风险给下游 caller。

## 可复用资产盘点

| 资产 | 来源 | 用于 |
|---|---|---|
| `@base64.decode(StringView)` | Loop #13 parse.mbt L218 | blob 字节比对 |
| `String::op_get(i) → UInt16`, `.to_int()` | Loop #13 match.mbt | chars 操作 |
| NFA `*`/`?` + epsilon_closure | Loop #13 match.mbt L287+ | 新 match_host_pattern_with_port |
| `@hostkey.HostKey::from_blob` | Loop #11 | presented_blob 类型校验 |
| MoonBit `Int` parse from hex string | kexflow_test.mbt | KAT 字节还原 |
| MoonBit struct 加 field + ctor 兼容 | entry.mbt L29+ | 新字段 host_port / host_only |

## 范围裁定表(本子集 vs OpenSSH)

| 行为 | OpenSSH | 本 Loop #14 子集 | 备注 |
|---|---|---|---|
| `[host]:port]` 字面比对 | ✓ | **✓** | 由 split-then-compare 实现更干净 |
| `[host]:port]` 中 `*` 通配 | ✓ NFA `*`吃字 | **✓**(host 部分) | 严格按 match.c:82 |
| `|` (reject sentinel) | ✓ (`!foo` literal) | 后续 Loop | 本 Loop 不动 |
| `@cert-authority` recognize | ✓ | ✓(识别 marker;**不强制** cert) | 后续 Loop |
| `@revoked` recognize + reject | ✓ | **✓(新增)** | Loop #14 核心 |
| `@revoked` via fingerprint | ✓(KRL) | ✗ | 本 Loop 不实现 KRL |
| `!marker` of `@revoked` | ✓ | ✗ | 本 Loop 不实现 |
| IPv6 `[host]:port:` 字面 | ✓ | **✓** | 跟 ssh-keyscan 同构 |
| KRL(Key Revocation List) | ✓ krl.c | ✗ | Loop #15+ |
| KRL 与 plain `@revoked` mix | ✓ | ✗ | Loop #15+ |

## KAT 维度

### Loop #14 新增 KAT (V9-V12)

| 测试 | host_str | port | entries | blob | 期望 | OpenSSH 对应 |
|---|---|---|---|---|---|---|
| V9 plain host + default port | "foo.example.com" | 0 | `foo.example.com ssh-ed25519 A` | A | Ok | 字面 match |
| V10 `[host]:2200` explicit port | "[foo.example.com]:2200" | 2200 | `[foo.example.com]:2200 ssh-ed25519 A` | A | Ok | 字面 match via split |
| V11 port mismatch | "foo.example.com" | 0 | `[foo.example.com]:2200 ssh-ed25519 A` | A | Mismatch | port 不符 → reject |
| V12 `@revoked` reject | "foo.example.com" | 0 | `@revoked foo.example.com ssh-ed25519 B`<br>`foo.example.com ssh-ed25519 A` (later) | A | Mismatch (Revoked wins) | OpenSSH `HOST_REVOKED` |

### 已有 V1-V8 全部回归

## 风险点

1. **API breaking change**: Loop #13 caller (`kexflow/flow.mbt`) 用 `check_host_key_strict(entries, host, blob, strict)`. 加 port 参数要求同步改 kexflow。
2. **port 0 vs 22 不同语义**: OpenSSH 默认 22 = no port;本 Loop 也用 22。但一些 user 可能用 0 表示 "任意端口"。规则: 0 = SSH default = no brackets。
3. **`[host]` 字面带空格**: `[foo .example.com]:2200` (host 部分含空格)? OpenSSH 不特殊处理。本子集也按字面,NFA match 时空 char 视为普通字符。
4. **多个 comma-split patterns 不同 port**: `foo.com,[bar.com]:2200` — 这种 entry 有两个 pattern,各自带不同 port。parse_line 应独立解析每个。
5. **hash 条目 `|1|...`** + port: `|1|salt|hash` hash 是对**plain host**的 HMAC,不包含 port。如果 user 写到 known_hosts 是 `|1|...|... :2200`,OpenSSH 行为:**不接受**[port part because hash is host-only] → match 失败。决定**保留该行为** — port 拆分后 hash pattern 只对 host_only 做 HMAC 比对。
6. **`@revoked` 跟 strict_kex 组合**: OpenSSH Revoked **不**依赖 strict_kex — always on。本 Loop 一致:check 后置,不论 strict_kex。

## 文档产出

本 Navigator 写入 `docs/knownhosts/navigator14.md`。Architect 阶段在此基础上写 `architect14.md`,实施后写 review/reality/summary 14 套件。
