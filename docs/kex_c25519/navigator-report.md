# Loop #9 Curve25519 KEX — Navigator Report

**Date:** 2026-08-25
**Role:** 🧭 Navigator
**Mission:** 摸清 OpenSSH `curve25519-sha256@libssh.org` 密钥交换的完整代码路径,确定移植范围、可复用积木与验证策略。

---

## 1. 源码路径(RFC 8731 + draft-ietf-curdle-ssh-kex-sha2 的 OpenSSH 实现)

| 文件 | 版本 | 角色 |
|------|------|------|
| `kexc25519.c` | v1.18 (2024-09-02) | c25519 密钥生成/共享密钥/keypair/enc/dec |
| `kexgen.c` | — | **通用** ECDH 客户端/服务端状态机 + 静态 `kex_gen_hash`(交换哈希) |
| `kex.c` | — | `derive_key`(会话密钥 KDF)+ `kex_derive_keys`(session_id 管理,NKEYS=6)|
| `sshbuf-getput-basic.c` | — | `sshbuf_put_bignum2_bytes`(mpint 编码)|

## 2. 协议全流程(客户端视角,kexgen.c `input_kex_gen_reply`)

```
1. keygen:  client_key ← random(32B); e = X25519(client_key, basepoint 9)
2. 发送 SSH2_MSG_KEX_ECDH_INIT(30): string(e)
3. 收 SSH2_MSG_KEX_ECDH_REPLY(31):  string(K_S_hostkeyblob) ‖ string(Q_S=f) ‖ string(sig)
4. 共享密钥: ss_raw = X25519(client_key, f);全零 → SSH_ERR_KEY_INVALID_EC_VALUE
             K = mpint(ss_raw)(非 raw 模式)
5. 交换哈希: H = SHA256(exchange_input)(见 § 3)
6. 验签:    sshkey_verify(hostkey, sig, H)(ssh-ed25519 时 Loop #7 已三盲验证)
7. 派生:    session_id = H(仅首次 kex);6 个密钥见 § 4
```

服务端(`input_kex_gen_init`)对称:keygen → f,`K = X25519(server_key, e)`,用主机私钥对 H 签名。

## 3. 交换哈希 `kex_gen_hash`(kexgen.c:48–96)逐字段

```
string(V_C)                      // 客户端版本串(如 "SSH-2.0-OpenSSH_9.x")
string(V_S)                      // 服务端版本串
u32(len(I_C)+1) u8(20) I_C       // ★ fake header:len 含类型字节,type=SSH2_MSG_KEXINIT
I_C                              // kex->my = 本方 kexinit payload(type 字节之后的部分)
u32(len(I_S)+1) u8(20) I_S
I_S                              // kex->peer
string(K_S)                      // 主机公钥 blob(即 REPLY 里的第一个 string 原样)
string(e)                        // 32B 客户端临时公钥
string(f)                        // 32B 服务端临时公钥
K                                // 注意:是 mpint 编码后的整个 sshbuf 内容原样追加
→ SHA-256
```

★ = 最易踩坑点:kexinit 在哈希里带"伪头部"(长度+1 覆盖类型字节),因为线上发送时它有包头而存进 `kex->my` 时剥掉了。

## 4. 会话密钥派生 `derive_key`(kex.c:1069–1118)

```
K1 = HASH( mpint_K ‖ H ‖ letter ‖ session_id )        // letter ∈ 'A'..'F'
Kn = HASH( mpint_K ‖ H ‖ K1‖…‖Kn-1 )                  // 不够长时链式扩展
Key = 取前 we_need 字节
```

- 6 个密钥:A/B = IV(c→s / s→c),C/D = 加密密钥,E/F = MAC 密钥
- `session_id`:首次 kex 时 = H 原样保存(rekey 时复用旧值)
- `we_need` 由 cipher/mac/iv 长度取 max 得出(chachapoly 场景 = 64:32 iv? 实为 key32+iv16? 由选路决定)——本卷作为参数传入

## 5. mpint 编码 `sshbuf_put_bignum2_bytes`(sshbuf-getput-basic.c:569)

```c
跳过前导零字节;
prepend = 最高位为 1 ? 1 : 0;      // 防"负数"解释
输出: u32(len_after_strip + prepend) 大端 ‖ [0x00] ‖ 有效字节
全零输入 → 仅 4 字节 u32(0)         // 空 mpint
```

32B 随机共享密钥命中高位为 1 的概率 50%,两条分支都必须有测试。

## 6. 复用积木与 inline 计划(moon 0.1.20260608 无跨包 import)

| 积木 | 来源卷 | 冲突检查 |
|------|--------|----------|
| `x25519(scalar, point)` | Loop #4 src/x25519 | 与 sha256 **零顶层标识符冲突**(fe_* 系)✓ |
| `sha256(message)` 一次性 | src/sha256 | 提供 `transform/pad/update/k256/init_H`,与新代码不撞 ✓ |

新包内新代码需避开:`update/pad/transform/freeze/mainloop/recip` 等已有名。计划命名空间:wire 缓冲助手用 `kx_` 前缀。

**Ed25519 验签不在本卷 inline**(ge_table 215KB + 与 x25519 包的 fe_* 全线撞名)。策略:**sig blob 解析在本包实现**(格式 `string("ssh-ed25519") ‖ string(64B R‖S)`),解析出的 (r,s) 与 Python 签名字节比对;密码学验证本体由 Loop #7 已三盲验证的 `src/ed25519` 在未来集成层承担——证据链闭环,避免本卷膨胀 250KB。

## 7. 移植范围

**In scope:**
- `kx_buf` 写侧助手(put_u8/u32/string/raw/mpint)
- `shared_key_ext`:X25519 + 全零拒绝(Option)+ raw/mpint 双模式
- `kex_gen_hash`(严格按 § 3 字段序)
- `derive_keys`:6×we_need + session_id 捕获
- 客户端 REPLY 解析(string×3 提取)+ sig 格式解析
- 服务端 enc 路径(keypair + enc,对称便宜)

**Out of scope(记录,不做):**
- sshpkt 传输层/分发器/rekey 状态机
- 主机信任决策(kex_verify_host_key 回调)
- sntrup761/mlkem768 混合 KEX
- KEXINIT 提案构造/协商(纯文本处理,后续卷)

## 8. 验证策略(triple-blind)

| 层 | MoonBit | Python 参考 | C harness |
|----|---------|-------------|-----------|
| X25519 一致 | x25519() | cryptography.X25519 | smult_curve25519_ref.c(verify_c 已有,Loop #4)|
| mpint | 自实现 | 手工按 C 规则构造 | **真实 sshbuf_put_bignum2_bytes**(stub 编译)|
| 交换哈希 H | kex_gen_hash | 同规则 Python 重算 | 真实 sshbuf + sha2.c(SHA-256,BSD,Loop #5 已入 verify_c)拼同一输入 |
| KDF 6 密钥 | derive_keys | 同公式重算 | derive_key 逻辑在 harness 内按 kex.c 抄录(标注)|
| 全零拒绝 | None | 异常路径 | SSH_ERR_KEY_INVALID_EC_VALUE |
| sig 解析 | 解出 r‖s | cryptography 签名生成 | —(格式层,C 侧 sshkey_verify 依赖过重)|

端到端向量设计:固定标量用 **RFC 7748 § 6.1** Alice/Bob 对(已验证过的锚点),V_C/V_S/I_C/I_S 用真实 OpenSSH 风格字符串,K_S 用一个自造 ssh-ed25519 blob。

## 9. 风险清单

1. **fake header off-by-one**(len+1 是否含 type)——Python/C 双锚定
2. mpint 高位分支只测一边 → 显式双分支向量
3. `kex->my` 边界语义:存的是 type 之后内容,harness 构造输入必须一致
4. we_need 传参化后与真实选路脱钩 —— 文档注明,集成层负责
5. session_id 在 rekey 场景的复用 —— out of scope,但 API 设计保留 initial 标志
