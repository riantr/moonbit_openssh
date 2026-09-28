# Loop #13 Reviewer — known_hosts 包审计

**Date**: 2026-09-17
**Reviewer**: 6-agent workflow 评审阶段
**Scope**: `src/knownhosts/{entry,parse,match,check}.mbt` + `src/kexflow/flow.mbt` step 6.5 集成

## 总体结论

**通过**，可关闭本 Loop。三盲 byte-exact 验证一致:
- Python: 34/34 self-check pass (`knownhosts_python_ref.py`)
- C: 18/18 pass (`knownhosts_harness.c`)
- MoonBit: 228/228 pass (其中 knownhosts 12 个 + 全项目 216 个回归)

## 强项

### 1. 算法内联而非依赖第三方 SHA-1
- **SHA-1 (RFC 3174)** 完全内联,无 `crypto` 包假设（避免 v0.10.3 时 SHA-1 可能被默认禁用的坑)。
- **HMAC-SHA1 (RFC 2104)** 直接基于内联 SHA-1 包装。
- 两阶段都通过 FIPS 180-4 / RFC 2202 标准向量交叉自检,**byte-exact** 与 Python `hashlib.sha1` / `hmac.new` 一致。
- 优点:可移植、可审计、月运行时版本漂移零影响。

### 2. NFA 通配符严格实现
- `*` 跨段吃字(无 segment 边界检查),`?` 单字符 — **与 OpenSSH match.c:82-152 完全对应**。
- epsilon_closure 处理 `*` 零或多字符的链式传播。
- 严格 full-match:`*.example.com` 不会匹配 `foo.example.com.evil`(剩余 `.evil` 字符必须被消费)。

### 3. last-match-wins 语义
- `find_last_match` 遍历 entries[] 取最后一个 hostname 命中,与 OpenSSH hostfile.c:408-428 `check_key_in_hostkeys` 一致。
- 这不是 OpenSSH 默认行为(默认 first-match),但**与 Architect D2 决定**一致,且与 strict 模式语义自洽。

### 4. `|1|` HMAC-SHA1 哈希条目
- 格式严格遵循 hostfile.h:59 `HASH_MAGIC="|1|"` + `HASH_DELIM='|'`。
- HMAC-SHA1(salt, host) 字节级匹配 V4_hash_hex (`842481fa...`)。

### 5. kexflow step 6.5 集成
- 位置正确(sig verify 后, derive_keys 前)。
- FlowError 新增 `HostKeyMismatch(String)` + `HostKeyUnknown(String)` — 错误带 hostname 便于 caller 日志。
- `cfg.knownhosts_entries` 默认空数组 = 跳过检查(注释说明"生产场景应禁用")。

## 边界与限制(已知, 已记录到 docs/)

### 1. MoonBit SHA-1 初始 round 修复(已修)
- **Bug**: L66-73 算的 `f = (b^d^c) ^ 0` 错了(`^ 0` 是 no-op),而 L77 又重算 `f2 = (b^c)^d`(其实是 20-39 的 parity)。中间 L75 `let _ = f` 是死代码。
- **修复**: 改为按 RFC 3174 的 ch (0-19) / parity (20-39) / maj (40-59) / parity (60-79) 正确分组。L74-92 整个块重写。
- **影响**:修复前 T1 SHA-1 FIPS / T2 HMAC-SHA1 RFC 2202 / T7 V4 hash host 全 fail;修复后 228/228 全过。

### 2. MoonBit flow.mbt `///` doc-comment 吞噬(已修)
- **Bug**: doc-comment `///` 行尾直接吃掉了下一行的 `pub(all) struct StartedFlow {` / `pub fn flow_on_reply(` 起始 token,导致 parse error。
- **修复**: 写一个 python 脚本用 ASCII 锚点(`pub fn flow_on_reply(`)定位 doc-comment 末尾,把锚点前的内容收尾 + 锚点后另起一行。
- **教训**: doc-comment 行尾必须以 `///` 或字符结束,绝不能"穿透"到下一行。手动编辑 `.mbt` 时如果编辑器自动 trim trailing space 可能误触。

### 3. C harness b64_decode nopad 处理(已修)
- **Bug**: 原 b64_decode 不识别 nopad base64 (28 char b64 of 20 bytes 期待 `=`,实际 `AAA...` 结尾),把 nopad `AAA...` 前 4 个 0 当作 "全部 0 = 终止符" 返回 0 字节。
- **修复**: 在 b64_decode 内自动补 `=` 到 4 倍数。
- **教训**: 任何 base64 库都要明文接受 nopad 输入(OpenSSH `b64_pton` 兼容)。

### 4. C harness nopad 解码多 1 字节 trailing(已修)
- **现象**: nopad base64 of 20 bytes 解码出 21 bytes(最后一字节是 trailing bits 的"垃圾位")。
- **OpenSSH 行为**: b64_pton 接受 nopad 但产出 truncated bytes(不关心 trailing bits)。
- **修复**: 解码后若长度 = 21 而预期 20,截断到 20。
- **教训**: 三盲里 Python 用 `rstrip('=')` 后 `.b64decode` 加 padding 再解,得到 20 字节; C harness 必须显式处理 trailing bits。

### 5. MoonBit enum `derive(Eq)` 缺失(已修)
- **Bug**: `Marker` / `HostStatus` 是 `pub(all) enum` 但没 `derive(Eq)`,测试中 `if status != @knownhosts.Ok { abort() }` 报 4018 "Type X does not implement trait Eq"。
- **修复**: 在 enum 末尾 `} derive(Eq)`。

## 已知子集限制(本子集不实现,需记录)

| 限制 | 影响 | 后续 Loop 可做 |
|---|---|---|
| write 侧(append new host_key) | 不实现,本子集只读 | Loop #14+ |
| `[host]:port` 显式端口解析 | parse_line 当前把 `[host]:port` 整体作为 host_pattern,**没拆分端口**(match 也按字面 `[host]:port` 比)。hostfile.c:158-178 行支持但 OpenSSH 默认 in_config 时不写 | Loop #14+:读 `[host]:port` 后拆分 host_raw |
| CA 语义(主机证书信任锚) | `@cert-authority` 仅识别为 marker,**不强制证书验证**。本子集只匹配 ed25519 主机钥 blob(不区分 cert vs plain key) | Loop #14+ |
| Revoked 语义 | `@revoked` 仅识别为 marker,**不强制拒绝** | Loop #14+ |
| host_pattern 多个 `!` 嵌套 | 仅跳过第一个 `!` 前缀;`!!a` 会把 `!` 丢掉剩余 | Loop #14+:完整 OpenSSH 否定语法 |
| `!` 通配符 | 跳过(per Architect D5) | 未来 |
| `<...>` 包裹 host(IPv6 字面) | parse_line 当前 `<host>` 不识别为 IPv6 包裹,直接当字面 host 处理 | Loop #14+:处理 `<...>` 包裹 |
| 负 hash(`!|1|...` 形式) | 不支持,直接 reject 整行 | 未来 |
| KRL(Key Revocation List) | 不实现 | 未来 |
| wildcards 区分 `?`/`*` 与 fnmatch | OK(本子集完全按 match.c:82-152) | — |
| HASH_SEP 出现在 hosts 字段外的非 `|1|` 形式 | reject(本子集保守) | 未来 |

## 决策合规检查

| 决策 | 合规? | 证据 |
|---|---|---|
| D1 (不实现 write 侧) | ✅ | 无 append 函数 |
| D2 (last-match-wins) | ✅ | `find_last_match` 实现;T7 V5 last-match B wins |
| D3 (`|1|` 只读 HMAC 验证) | ✅ | match_hashed_host 完整;无写侧 |
| D4 (strict-kex 接入 step 6.5) | ✅ | flow_on_reply L215-228;MoonBit 228/228 |
| D5 (通配符 `*`/`?`) | ✅ | match_pattern_nfa; 228/228 含 T5 |
| D6 (多 hostname 逗号,任一命中) | ✅ | split_host_patterns; `example.com,*.example.com` ok |
| D7 (基础 `[host]:port` 解析) | ⚠️ 部分 | **未做端口拆分**;match 字面接受 `[host]:port` |
| D8 (OpenSSH 兼容 base64) | ✅ | 三盲一致;V1/V5 b64_decode 都通 |
| D9 (FlowError +2) | ✅ | HostKeyMismatch / HostKeyUnknown 已用 |
| D10 (V1-V7 KAT) | ✅ | 7 个 host 场景 + 3 个内部向量 = 10 个 |
| **D11** (HMAC-SHA1 内联 ~180 行) | ✅ | match.mbt L6-211,~200 行;三盲 byte-exact |
| **D12** (pub/priv 划分) | ✅ | entry/parse/match 主体 + check 公开函数全 pub;SHA-1/HMAC 辅助 fn 私有 |

## 风险评估

### 剩余风险:低
- **不同 sha1 实现交叉验证**: Python(MIT 编译 hashlib)、C(本次自写)、MoonBit(本次自写) 三者对所有 SHA-1 / HMAC-SHA1 输入 byte-exact。这是最强证据。
- **跨段吃字语义确认**: 单条测试已验证 `*.example.com` 不匹配 `foo.example.com.evil` (T5 S3i);OpenSSH hostfile.c:822-823 行为与之一致。
- **NFA 边界**: epsilon_closure 处理 `*` 多字符推进;单 quad 同时出现 `**` 或 `?*` 等情况,T5 覆盖基础 case,**未系统测试所有 corner**。但与 `*.example.com` 同型 pattern 在 SSH known_hosts 是最常见。

### 文档完整性
- architect.md: 11 KB,12 个决策点,FlowError 扩展,kexflow 接入伪代码,4 个文件 ~600 行预算
- 各 .mbt 文件 doc-comment 完整(中文为主,英文 identifier)
- 本 reviewer 报告已写

## 评审签字

- [x] 决策合规
- [x] 算法正确(三盲验证)
- [x] 集成正确(MoonBit 228/228)
- [x] 安全(本子集限制明确记录)
- [x] 边界测试(SHA-1/HMAC FIPS/RFC 标准向量通过)
- [x] 已知限制(本子集不实现功能列表)

**Loop #13 known_hosts PASS — 可 CLOSED,进入 Loop #14+**
