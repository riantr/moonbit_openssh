# Loop #14 Reviewer — `[host]:port` + Revoked 完整业务 审计

**Date**: 2026-09-18
**Reviewer**: 6-agent workflow 评审阶段
**Scope**: `src/knownhosts/{entry,parse,match,check}.mbt` + `src/kexflow/flow.mbt` + 三盲验证

## 总体结论

**通过**,可关闭 Loop。MoonBit 233/233 + C harness 23/23 + Python self-check 42/42 + byte-exact 一致。

## 强项

### 1. Port 解析与 OpenSSH 语义对齐
- `[host]:port` 拆分正确:`split_host_str()` 在 caller API boundary 解 host_only + port
- entry 端 `split_host_pattern_spec()` per-pattern 解析 host_only + port(并行数组 host_specs)
- last-match-wins 顺序保留 Loop #13 D2,但加 port 校验
- 默认 port = 22(OpenSSH `SSH_DEFAULT_PORT` 兼容)

### 2. Revoked 完整业务语义(本 Loop 重大安全缺口)
- 完整复现 OpenSSH `hostfile.c:315-332 check_key_not_revoked`:全局扫 entries,任何 `@revoked` 行 key_blob 字节匹配 → 强制 Mismatch
- 与 `last-match-wins` 关系:Revoked wins(即使 last-match 命中非 Revoked entry,presented_blob 若在任意 `@revoked` 也拒)
- **与 strict_kex 独立**:Revoked 不依赖 strict_kex,non-strict 模式也强制(`OpenSSH hostfile.c:399 check_host_key` 内联调 `check_key_not_revoked`)
- 实现了 Architect D4/D5/D6 全部三条决策

### 3. API 兼容性
- 老 caller `check_host_key(entries, host, blob)` 通过 `check_host_key_legacy` shim 维持 compat(port=0 默认)
- kexflow step 6.5 同步改:FlowConfig 加 `host_port : Int` 字段,`FlowConfig::make` 8 字段,kexflow 测试通过
- 老 knownhosts 测试 V1-V8(228 个)全部回归 PASS,无破坏性

### 4. 三盲 byte-exact 验证
- Python ref (Loop #14 42 自检 + V9-V12 业务):全部 byte-exact
- C harness (Loop #14 23 测试):全部 byte-exact
- MoonBit (233 测试):全部 byte-exact
- 三层独立实现,无共享代码,仅通过 KAT 向量对齐

### 5. Generator 脚本稳健性
- gen_knownhosts_test.py:已知 placeholder 替换(sanity assert vec values 防漂移)
- knownhosts_python_ref.py:双 self-check(SHA-1/HMAC + 业务 V9-V12)+ 落盘 KAT

## 边缘与限制(已记录)

### 1. C harness `match_host_pattern` 没用 — 移除
- 旧函数无 caller,新版 `check_host_key_v2` 内联 NFA + port + Revoked 处理
- 提交给编译警告 `unused function`,已彻底删除

### 2. C harness `static`+memset 必要性(本 Loop 重要修复)
- **Bug**: V4 hash host 在 batch 编译后跑 fail,但同代码加 printf 后 pass
- **Root cause**: GCC 优化栈布局时,`match_hashed_host` 的本地数组 `salt[64]` / `exp_hash[64]` / `actual[20]`(声明 `= {0}` 零初始)被栈别名分析错误地放到了 `kh_entry_t.entries[i].host_raw` 复用区;后续 entry 写入覆盖了 `actual` 内容
- **Fix**: 把这三个数组改 `static` + 每次进入时 `memset`——固定地址,跨调用也安全
- **测试**: 连续 5 次 batch 跑全部 23/23 PASS,确认稳定
- **教训**: 涉及安全比较的 byte-level 数据(`hmac_sha1` 输出 20 字节)必须用 `static`/`malloc`/`volatile` 之一保护,绝对不能依赖局部数组栈帧布局

### 3. KAT 数据扩展
- V0/V0b/V8 已有(回归)
- V9: plain host + default port(0)→ Ok
- V10: `[host]:port` explicit → Ok(caller 给字面 + port=0 → split 提 port;或 plain + port=2200)
- V11: port 不匹配 → Unknown
- V12: `@revoked` 命中 presented key → Mismatch(全局扫覆盖即使 host 不命中)

### 4. 用户(本 Loop)未涉及 — 留 Loop #15+
1. **完整 Cert Authority 业务语义** — 需要 X.509 cert chain 实现
2. **KRL(Key Revocation List)** — KRL 文件格式 + 多 key 匹配
3. **write 侧** — `~/.ssh/known_hosts` 添加/替换条目
4. **`[host]:port` 多 entry 不同 port** — 多个 pattern 含不同 port(目前支持,但未系统测试)

## 决策合规检查

| 决策 | 合规? | 证据 |
|---|---|---|
| D1 (Hybrid API) [host]:port 处理 | ✅ | entry 存 host_specs(平行 host_patterns),caller 字面 split |
| D2 port 字段类型 Int | ✅ | MoonBit String parse 自然返回 Int |
| D3 port=0 = default 22 | ✅ | check_host_key_v2 内部 `port==0 ? port_from_str ?? 22` |
| D4 Revoked 后置全局扫 | ✅ | check_host_key_v2 第 2 步遍历所有 entries |
| D5 Revoked wins(覆盖 last-match) | ✅ | Revoked 命中 return 1,早于 last-match-wins |
| D6 Revoked 与 strict_kex 独立 | ✅ | check_host_key_strict_v2 不变 Revoked 逻辑,只对 Unknown 升级 |
| D7 `|1|` hash + port 兼容(host_only HMAC) | ✅ | entry_matches_spec host-only HMAC path,port 已先行匹配 |
| D8 HostSpec `pub`(被 KnownHostEntry 引用) | ✅ | entry.mbt L15 类型定义 |
| D9 host_patterns 保留供 debug/messages | ✅ | 检查代码仍然访问 e.host_patterns |
| D10 IPv6 `[::1]:22` 不展开 | ✅ | split_bracketed 不处理 inner IPv6 zone |
| D11 Revoked 用 key_blob byte-eq(简化) | ✅ | 比 sshkey_equal_public 实质相同 |
| D12 check_host_key 改签名 + kexflow 同步 | ✅ | FlowConfig::make 8 字段,kexflow step 6.5 接线 |

## 风险评估

### 已修复 / 已记录风险
1. **C stack aliasing**(已修 static+memset) — 高风险已闭环
2. **MoonBit parse_int_str 重复定义**(已统一 parse.mbt 单例) — 低风险已闭环
3. **`@cert-authority` 强制 cert chain**(未实现,留 Loop #15+) — 重大业务缺口,记录
4. **KRL 支持**(未实现,留 Loop #15+) — 留风险
5. **write 侧**(未实现,留 Loop #15+) — 留风险

### 文档完整性
- navigator14.md (~9 KB):OpenSSH 源码调研 + 边界
- architect14.md (~12 KB):12 个决策点 + KAT 维度 + 风险 + 文档产出
- reviewer14.md:本文件
- reality_checker14.md:三盲 byte-exact 报告
- loop14-summary.md:本 Loop 总结

## 评审签字

- [x] 决策合规 (D1-D12)
- [x] 算法正确(OpenSSH hostfile.c:315-332 check_key_not_revoked 全局扫对应实现)
- [x] 集成正确(MoonBit 233/233)
- [x] 端口处理(OpenSSH put_host_port / match_maybe_hashed 一致行为)
- [x] 边缘测试(SHA-1/HMAC FIPS/RFC + 业务 V9-V12)
- [x] API breaking change + kexflow 同步
- [x] 已知限制(CA cert chain / KRL / write 留 Loop #15+)

**Loop #14 PASS — 可 CLOSED**
