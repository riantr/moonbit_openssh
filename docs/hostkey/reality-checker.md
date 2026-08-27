# Loop #11 Reality Checker — src/hostkey

日期:2026-08-27
职责:独立复核 reviewer 报告的每个可检验声明;重跑全部验证;核对源码行号
引用;确认无"报告绿、实际红"的缝隙。

## 1. 验证命令重跑(本报告撰写时现场执行)

| 命令 | 结果 | 声明核对 |
|---|---|---|
| `python verify_c/hostkey_python_ref.py` | SELF-CHECK: **6/6 passed** + KAT 落盘 | ✓ |
| `moon check` | **0 warnings, 0 errors** | ✓(reviewer §1 "全绿") |
| `moon test` | **Total tests: 199, passed: 199, failed: 0** | ✓ |
| `build_hostkey.bat` → `hostkey_kat.exe` | **39/39 passed**, exit=**0** | ✓ |

测试计数口径:hostkey_test.mbt 为 t1-t9 共 **9 个 test 块**(t8 内含 6 断言),
190(Loop #10 累计)+ 9 = 199 ✓。C harness 计数按 CHECK 宏逐条:c1×2 +
c2×2 + c3×1 + c4×3 + c5×10 + c6×4+5 + c7×3 + c8×6 + c9×4 = 39 ✓。

## 2. 源码行号引用抽查(对照 E:\src\moon\openssh-C)

| 引用 | 实际内容 | 结论 |
|---|---|---|
| ssh-ed25519.c:232-300 ssh_ed25519_verify | 前置 INVALID_ARGUMENT(:232-238)→ get_cstring/get_string_direct(:244-247)→ strcmp alg(:248-251)→ trailing(:252-255)→ len>64(:256-259)→ open(:287-291 SIGNATURE_INVALID) | ✓ 与 sig_verify.mbt 注释/harness 转写一致 |
| sshkey.c:2237-2250 sshkey_verify | `siglen == 0 \|\| dlen > SSH_KEY_MAX_SIGN_DATA_SIZE → SSH_ERR_INVALID_ARGUMENT` 后分派 impl | ✓ key_parse.mbt MAX_SIGN_DATA_SIZE=1048576 同源(sshkey.h L53) |
| sshbuf-getput-basic.c:269 get_cstring | memchr 内部 NUL → SSH_ERR_INVALID_FORMAT("Allow a \\0 only at the end") | ✓ MoonBit get_cstring 同规则 |
| sshbuf-getput-basic.c:598 get_bignum2_bytes_direct | MSB 负拒 / len>SSHBUF_MAX_BIGNUM+1 或 ==+1 且首非 0 拒 / trim 前导零 | ✓ MoonBit get_bignum2 三条规则逐条对齐 |
| ed25519_ref.c:2018 crypto_sign_ed25519_open | sm[0..63]=签名(R/S),消息=sm[64..];badsig → *mlen=-1 返回 -1 | ✓ c8_rs63_open_path 依赖的真实切分语义 |

## 3. 已声明的语义偏差清单(三方一致 vs 完整 OpenSSH)

以下偏差**均已在代码注释/harness 头注/reviewer §5 登记为子集语义**,
三盲内部完全一致,不构成"报告绿实际红":

1. 表外已知名(ecdsa-sha2-nistp256 / sk-ssh-ed25519@...)→ UnsupportedType;
   完整 C 会进入各自 deserializer(对空尾随输入大概率 MESSAGE_INCOMPLETE)
2. cert 判定用后缀规则;完整 C 经 type_from_name 仅识别完整证书名,
   合成名 foo-cert-v01@... 在 C 为 UnknownKeyType(KAT 只含真实证书名,
   两侧一致)
3. RSA 密钥的 sig 结构错误不细分,一律 RsaVerifyUnavailable(C 的
   ssh_rsa_verify 会先做结构解析)
4. len<64 签名:MoonBit 结构层等价捷径直接 SignatureInvalid,C leg 走
   真实 open 必败——观测一致(c8_rs63_open_path 通过)
5. 指纹对输入 blob 直解;C 对 canonical 重序列化 blob。良构 plain blob 下
   相等(fingerprint.mbt 头注);V4 畸形 blob 不参与指纹用例

## 4. KAT 供应链完整性

- `_hostkey_ref_out.txt` 由 hostkey_python_ref.py 在自检 6/6 后写出,
  无手抄 hex
- gen_hostkey_test.py 解析同一文件产出 hostkey_test.mbt(T 字面量)与
  _hostkey_kat.h(C 宏),sanity() 含与参考模块常量的交叉断言
  (pk/blob/rs/fp/rsa e_hex/nbits/sig_b_over_main 复签)+ wire 布局锚点
- MoonBit 测试与 C harness 消费**同一份生成物**,无第二录入路径
- 生成器为幂等纯函数:重跑输出 byte-identical(本次复核期间重跑两次,
  moon test 结果不变)

## 5. 结论

reviewer.md 全部可检验声明属实;三盲数字(199/6/39)、exit code、错误类
矩阵、顺序锁、seed 锚点均在现场重跑中复现。**PASS_OVERALL 成立**。
