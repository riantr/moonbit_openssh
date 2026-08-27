# Loop #11 Code Reviewer — src/hostkey

日期:2026-08-27
审查范围:`src/hostkey/`(inline ed25519 组 11 文件 + s256_ 改名 sha256 组 6 文件 +
key_parse/sig_verify/fingerprint + hostkey_test.mbt)、
`verify_c/hostkey_python_ref.py`、`verify_c/gen_hostkey_test.py`、
`verify_c/hostkey_harness.c`。

## 1. 总评

**PASS**。hostkey 解析与验证链(ssh-ed25519 全链路 + ssh-rsa 结构解析 +
SHA256 指纹)三盲一致:MoonBit **199/199**(新增 t1-t9)、Python 自检
**6/6**、C harness **39/39 exit 0**(真实 sshbuf + 真实 ed25519.c)。
本 loop 抓出并修复了 **1 个真密码学编码 bug**(base64 查表缺失,见 §4.1)
和 **1 处实现-文档偏差**(sig trailing 错误类,§4.2)。遗留项均不阻塞(§5)。

## 2. 正确性要点核对

| 项 | 结论 |
|---|---|
| from_blob 流程 | get_cstring(ktype) → cert 分类 → 类型分派 → trailing(sshkey.c:2026/2035/2053)。cert 先于 unknown-type(C 同序);rsa 模长检查在 deserialize 内部、先于 trailing(navigator L51 已锁) |
| get_cstring 语义 | NUL 仅允许居末(vendored sshbuf-getput-basic.c:283-288 memchr 规则),内部 NUL → InvalidFormat;t5 nul_in_name 三方一致 |
| get_bignum2 规则 | MSB 负拒 / raw_len>2049 或 ==2049 且首非 0 拒 / trim 前导零——与 vendored get_bignum2_bytes_direct(:598)逐条对齐;2049 全零 → trim 空 → 0 bits → TooShort(t6 zero2049 锁定) |
| RSA 读序 | e 先 n 后。若反序,rsa_ok 的 n 首字节 0xC7(MSB 置位)会触发 BigNumNegative——t6/c6 数值级断言(e==010001、n 首字节、bitlen==2048)同时锁定顺序与值 |
| ssh_ed25519_verify 顺序 | 前置(siglen==0‖msg>1MB→InvalidArgument)→ sig 解析(MESSAGE_INCOMPLETE 族→InvalidFormat)→ **alg 比较(TypeMismatch)** → **trailing(TrailingData)** → len>64(InvalidFormat)→ open(len<64 放行必败→SignatureInvalid)——ssh-ed25519.c:232-300 精确序,t8 六断言含 alg-before-trailing 顺序锁 |
| len<64 等价捷径 | MoonBit 直接 SignatureInvalid;C leg 走真实 crypto_sign_ed25519_open(sm[0..63] 为签名,消息字节混入 → badsig)。c8_rs63_open_path 证明两条路径观测等价 |
| seed 锚点 | keypair_from_seed(SEED_A/B) 的 pk 与 sign 输出同 cryptography 库逐位一致(t2);C 侧 keypair_from_seed 同锚(c2) |
| 指纹文本 | "SHA256:" + 标准 b64 nopad;32 字节摘要恒 43 字符。t1/t9 与 Python hashlib+rstrip('=') 一致;c1/c9 与 harness RFC4648 转写一致 |

## 3. 安全性审查

- **abort 仅程序员错误**:hk_hex 非法字符/hex 长度奇数/seed≠32B 等;
  from_blob/verify 对任意攻击者输入只返回 Parsed/Rejected 或 Accepted/
  Rejected 值,fuzz 友好
- **内存界**:bignum 缓冲按 SSHBUF_MAX_BIGNUM=2048 上限静态分配;
  1MB 边界用例用静态缓冲(免栈帧超限)
- **无常量时间新决策**:ed25519 验签复用 Loop #7 实现(该 loop 已审计);
  本层无 tag 比较
- **RsaVerifyUnavailable 显式化**:不静默假装 RSA 可验,错误值可区分——
  未来接 modexp 后只需替换该分支

## 4. 本 loop 开发中发现并修复的问题(证据链)

1. **base64 编码缺字母表查表(真 bug,编译警告阶段抓获)**:
   `hk_b64_nopad` 初版把 6 位索引直接 `Char::from_int(idx)` 推入输出,
   产出码点 U+0000..U+003F 的控制字符而非 base64 字母;`alphabet` 变量
   从未被引用。清理 deprecated 警告时 `unused_value: Unused variable
   'alphabet'` 暴露。修复为 `alphabet[idx]` 查表(StringBuilder +
   unsafe_to_char)。**若无此修复,t1/t9 指纹比对必挂——KAT 文本比对是
   该错误类别的定点探测器。**
   **教训:新写编码函数时,"变量未使用"警告可能意味着算法核心步骤丢失,
   不只是风格问题。**
2. **sig trailing 错误类偏离文档**:初版 `HostSig::parse` 把 trailing 检查
   捆进 parse 并统一映射 InvalidFormat;navigator.md L20 明确写着
   UNEXPECTED_TRAILING_DATA。备 C harness 重读真实源码时发现真实顺序为
   alg 比较(:248-251)先于 trailing(:252-255)先于 len>64(:256-259)。
   重构 sig_verify.mbt 为精确序,新增错 alg+尾巴 → TypeMismatch 顺序锁
   用例;architect T7 行同步更正。
   **教训:中间解析层"统一归并错误"会悄悄吞掉 C 的错误分类学;转写必须
   让每个 goto out 的赋值点一一对应。**
3. **RSA 分支结构错误归并**:初版 verify 对 RSA 密钥也先解析 sig 结构
   (畸形 sig → InvalidFormat);重构后 RSA 在前置检查后直接显式
   RsaVerifyUnavailable,不冒充未实现的 rsa 结构保真度(注释注明)。
4. **Python 参考脚本两处断言错**(运行前修复):L78 对 raw bytes 调
   `.public_key()`;N_1023 位长断言 ==1016(伪随机流不保证,改 <1024)。
5. **生成器切片偏移险情**:PK_B/rs_B 从 blob hex 提取的偏移首版写 44/36
   (正确为 38 = (4+11+4)*2)。靠 sanity() 新增 wire 布局锚点断言
   (blob 102 chars、pk 64 chars、A/B 公钥互异等)在运行前拦截。
   **教训:hex 切片偏移必须由长度锚点断言保护,不能裸写魔数。**
6. **C harness KAT 命名映射**:KAT 成功语义记作 "Parsed"(python 侧),
   harness hk_err_name(HK_OK)="Ok",c6_rsa_1024 首跑 FAIL;harness 比较
   处加 Parsed↔HK_OK 等价映射后全绿。
7. KAT 头文件漏 HK_SIG_B_OVER_MAIN / HK_RSA_OK 两宏 → 生成器 scalars
   表补齐(链接期暴露,一次修复)。

## 5. 遗留建议(非阻塞)

1. RSA 验证需 bignum modexp —— 未来 loop 候选(顺带补齐 RsaKey 分支的
   结构错误分类学)
2. cert 体解析、ECDSA/SK/XMSS、known_hosts 均范围外(Loop #11 选型已记录);
   子集语义:表外已知名(ecdsa-sha2-* / sk-*)报 UnsupportedType 而非进入
   各自 deserializer,合成名 foo-cert-v01@... 报 CertNotAllowed 而 C 为
   UnknownKeyType——三方一致但与完整 OpenSSH 有别,已在 harness 头注与
   reality-checker §3 登记
3. `verify_c/_rename_sha256.py.done`、`_hk_c.txt.done`:一次性临时脚本,
   mavis-trash 本会话不可用,留待手动清理(不影响构建/测试/gitignore 外
   仅两个小文件)
4. 指纹 canonical-blob caveat:C 的 sshkey_fingerprint 对重序列化的
   canonical blob 求 hash;本实现对输入 blob 直解。良构 plain blob 下两者
   逐字节相等(fingerprint.mbt 头注已注明);若未来支持带残余/非规范输入
   的指纹需求需重新评估
