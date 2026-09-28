# Loop #24 Navigator — ssh_config fnmatch 解析 (OpenSSH 配置文件)

**Date**: 2026-09-28
**Status**: Navigator 调研中 → **Verdict**: 三件大事：(1) G1 src/sshconfig/fnmatch.mbt — OpenSSH fnmatch (?, *); (2) G2 src/sshconfig/parser.mbt — ssh_config 行/节区解析; (3) G3 src/sshconfig/match.mbt — Host pattern matching + KAT tests

## TL;DR

| 子目标 | 实现路径 | 状态 |
|---|---|---|
| **G1** OpenSSH fnmatch | NFA 双指针算法 | 可行 (~1 hour) |
| **G2** ssh_config 解析 | 行级 (comment + Host + keyword=value) | 可行 (~1 hour) |
| **G3** Host pattern matching | 取首个匹配 section + 返回 ConnectionOptions | 可行 (~30 min) |
| 4 target byte-exact 维持 | 不破 Loop #20/#22 verify | 维持 |

## A. Loop #24 范围决策

### A.1 选定 Loop #24 = ssh_config fnmatch 解析
- 来自 memory "Loop #15+ 推荐: ssh_config fnmatch"
- SSH client 启动关键路径
- 从零实现,与 OpenSSH match.c + readconf.c 字节级验证 (triple-blind 模式)
- 不依赖任何外部组件

### A.2 不在 Loop #24 范围
- WebTransport HTTP/3 server（Loop #25+）
- Web Worker + wasm-gc（Loop #25+）
- 真 sshd 连通（Loop #25+）
- AEAD 加密层回包验证（Loop #26+）
- cert chain / KRL / interactive shell（Loop #26+）

## B. fnmatch 算法 (OpenBSD NFA)

### B.1 OpenSSH match_pattern 简化
- `?` 匹配任意单字符
- `*` 匹配任意长度 (含 0)
- 其他字符字面匹配
- 不支持 POSIX fnmatch 的 `[]` charclass (Loop #24 简化)
- NFA 双指针实现,Loop #24 用更简化的双指针回溯

## C. ssh_config 解析

### C.1 行格式
```
# comment
Host *.example.com foo.*  ; 多 pattern 用空格分隔
    HostName real.host
    User myuser
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host *  ; 兜底
    ForwardAgent no
```

### C.2 解析 token
- 跳过空行
- `#` 开头 → comment,跳过
- `Host PATTERNS...` → section header
- `Keyword Value...` → option
- 大小写不敏感 keyword (但 Loop #24 简化为全大写 keyword)

## D. Host pattern matching

### D.1 算法
1. 解析 ssh_config → Array[SshConfigSection] (每个 section: { patterns: Array[String], options: Map[String, String] })
3. 给定 hostname,返回**第一个** patterns 包含 hostname 的 section
4. 后续 section 不再使用 (OpenSSH 行为: "first match wins",除了 canonical -d / -F 规则)

## E. 验证

### E.1 KAT tests
- fnmatch: OpenBSD t_match.c testsuite
- parser: OpenSSH ssh_config.5 examples
- match: 多个 Host sections + complex 解析

### E.2 byte-exact
- 与 OpenSSH match_pattern 输出 byte-exact 对比
- 与 OpenSSH ssh -F config.test match_hostname 行为一致

## F. 时间预算

| 任务 | 预估 |
|---|---|
| G1 fnmatch | 1 hour |
| G2 parser | 1 hour |
| G3 match + tests | 1-2 hours |
| Loop #24 5 件套文档 | 30 min |
| 总计 | 3-4 hours |