# Loop #11 Summary — SSH Hostkey 解析与签名验证

日期:2026-08-27
状态:**CLOSED — PASS_OVERALL**

## 交付物

| 产物 | 路径 |
|---|---|
| MoonBit 实现 | `src/hostkey/`(inline ed25519 组 11 文件 + s256_ 改名 sha256 组 + key_parse/sig_verify/fingerprint) |
| 测试 | **199/199 PASS**(新增 t1-t9;hostkey_test.mbt 由脚本生成,KAT 字面量内嵌) |
| Python 参考 | `verify_c/hostkey_python_ref.py`(6/6 自检)+ `_hostkey_ref_out.txt`(V1-V6 KAT) |
| 生成器 | `verify_c/gen_hostkey_test.py` → 同时产出 MoonBit 测试与 C 向量头 `_hostkey_kat.h` |
| C harness | `verify_c/hostkey_harness.c` + `build_hostkey.bat` → **39/39 PASS exit 0** |
| 报告 | `docs/hostkey/{navigator,architect,reviewer,reality-checker,loop11-summary}.md` |

## 实现内容

信任链从"形态解析"(Loop #9 REPLY)升级为"可验证"(对应 OpenSSH
sshkey.c from_blob/verify 子集):

- **ssh-ed25519 全链路**:blob 解析(pk 恰 32B)→ sig blob 精确序解析
  (alg 比较 → trailing → len>64 → open)→ 接通 Loop #7 ed25519 验签;
  seed 锚点证明与 cryptography 库逐位一致(RFC 8032 确定性)
- **ssh-rsa 结构解析**:e 先 n 后(get_bignum2_bytes_direct 规则:
  MSB 负拒 / >2049 拒 / trim 前导零)+ check_rsa_length ≥1024 bits
  (先于 trailing,C 同序);密码学验证显式 RsaVerifyUnavailable(需
  bignum modexp 属未来环)
- **错误分类学 11 变体**一一映射 ssherr:InvalidFormat / UnsupportedType /
  CertNotAllowed / TypeMismatch / TrailingData / BigNumNegative /
  BigNumTooLarge / RsaModulusTooShort / SignatureInvalid / InvalidArgument /
  RsaVerifyUnavailable
- **SHA256 指纹**:"SHA256:" + b64 nopad(strcspn 截断语义),与
  `ssh-keygen -lf` 文本形态一致

## 三盲验证

```
Python(hostkey_python_ref.py, cryptography 交叉) ──生成──> _hostkey_ref_out.txt (V1-V6)
   ↑ 自检 6/6                                              │ 同一字面量(gen_hostkey_test.py 双产)
MoonBit(t1-t9) <────────逐字节比对──────────────→ C harness(c1-c9)
   199/199                                                39/39 exit 0
                                                          (真 sshbuf get_cstring/get_string/
                                                           get_bignum2_bytes_direct + 真 ed25519.c)
```

- seed 锚点三方闭合:keypair_from_seed(SEED_A/B) 的 pk 与签名在 Python、
  MoonBit(t2)、C(c2)三侧同 cryptography 库逐位一致
- 错误矩阵三方一致:V4 十例畸形 blob + V5 六例 RSA + t8/c8 结构分类学
  (含 **alg-before-trailing 顺序锁**)
- 边界钉死:siglen==0、msg==1MB(过前置进真实 open 必败)vs 1MB+1
  (InvalidArgument)、pk 31/33 字节、raw_len 2049 全零(trim 后空)

## 本 loop 关键教训(reviewer §4 详述)

1. **编码函数的 unused-variable 警告可能意味着算法核心步骤丢失**——
   hk_b64_nopad 初版漏掉字母表查表(直接 Char::from_int(索引)),靠警告
   清理阶段抓获;KAT 指纹文本比对是该错误类的定点探测器
2. **中间解析层统一归并错误会吞掉 C 的错误分类学**——sig trailing 初版被
   并入 InvalidFormat;重读真实源码后按 alg→trailing→len>64 精确序重构。
   转写必须让每个 `goto out` 赋值点一一对应
3. **hex 切片偏移必须由长度锚点断言保护**——PK_B 提取偏移首版写错,
   sanity() 的 wire 布局锚点(blob=102 chars 等)运行前拦截
4. KAT 双产物模式(MoonBit 测试 + C 头文件由同一脚本生成)消除第二录入
   路径;生成器幂等,reality-checker 重跑两次输出不变

## 与既有积木的关系

- 复用 Loop #7 ed25519(120 tests)作为验签引擎——本 loop 的 t2 是其
  首次对外部库(Python cryptography)的确定性交叉锚定
- sha256 组 inline 时 9 个冲突名加 `s256_` 前缀(41 处改名,编译验证);
  入口名 `sha256(bytes)` 未改
- 为 Loop #12+ 候选铺路:known_hosts / KEX 回复链组装 / RSA modexp

## 待清理(非阻塞)

- `verify_c/_rename_sha256.py.done`、`verify_c/_hk_c.txt.done`:一次性
  临时文件(mavis-trash 本会话不可用),可手动删除
