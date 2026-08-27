# Loop #11 Architect — src/hostkey 设计

日期:2026-08-26
前置:navigator.md

## 1. 包结构

```
src/hostkey/
  moon.pkg
  ed25519_api.mbt          # ┐ inline 自 src/ed25519(原样)
  ed25519_fe.mbt           # │ (api/fe/ge/ge_table/sc + sha512×6)
  ed25519_ge.mbt           # │
  ed25519_ge_table.mbt     # │
  ed25519_sc.mbt           # │
  ed25519_sha512_*.mbt ×6  # ┘
  sha256_{api,block,final,primitives,state,update}.mbt  # inline + 9 名字加 s256_ 前缀
  key_parse.mbt            # HostKey/KeyError/HkCursor/from_blob(bignum2/cstring 规则)
  sig_verify.mbt           # HostSig 解析 + verify 分派 + ed25519 验证接线
  fingerprint.mbt          # sha256 指纹 + base64-nopad 文本
  hostkey_test.mbt         # 测试(Python KAT 锚点)
```

## 2. 类型

```moonbit
pub const MAX_SIGN_DATA_SIZE : Int = 1048576   // sshkey.h L53 (1<<20)
pub const RSA_MIN_MODULUS_BITS : Int = 1024    // sshkey.h L53
pub const MAX_BIGNUM_BYTES : Int = 2048        // SSHBUF_MAX_BIGNUM

pub(all) enum HostKey {
  Ed25519Key(FixedArray[Byte])             // pk 32B
  RsaKey(FixedArray[Byte], FixedArray[Byte]) // e(trimmed), n(trimmed)
}

pub(all) enum KeyError {
  InvalidFormat; UnsupportedType; CertNotAllowed; TypeMismatch; TrailingData
  BigNumNegative; BigNumTooLarge; RsaModulusTooShort; SignatureInvalid
  InvalidArgument; RsaVerifyUnavailable
}

pub(all) enum ParseResult { Parsed(HostKey); Rejected(KeyError) }
pub(all) enum VerifyResult { Accepted; Rejected(KeyError) }

// HkCursor:offset 式游标(get_cstring/get_string/get_bignum2),错误即短路
```

辅助:`is_cert_name(name)` = ends_with("-cert-v01@openssh.com");
`bit_length(bytes)`(trim 后):(len-1)*8 + 8-clz(top);空 → 0。

## 3. API 表面

```moonbit
pub fn HostKey::from_blob(blob) -> ParseResult          // allow_cert=false 语义
pub fn HostSig::parse(sig_blob, want_alg) -> SigResult? // 内部用,见下
pub fn HostKey::verify(self, msg, sig_blob) -> VerifyResult   // sshkey_verify+ssh_ed25519_verify
pub fn fingerprint_sha256(blob) -> FixedArray[Byte]      // 原始 32B
pub fn fingerprint_text(blob) -> String                  // "SHA256:<b64nopad>"
pub fn is_verified(res) -> Bool                          // 便捷
```

verify 流程(navigator §3):前置(siglen==0‖msg>1MB → InvalidArgument)→
sig blob 解析(alg 精确匹配/trailing/>64/<64)→ ed25519::verify(rs,msg,pk)。
RSA → Rejected(RsaVerifyUnavailable)。ed25519 参数序 **verify(sig, msg, pk)**。

## 4. 冲突审计

sha256 六文件内 9 个名字(block_len/ch/hash_len/maj/pad/rotr/serialize_state/
transform/update)→ `s256_` 前缀(defs+组内互引);其余保留。跑顶层标识符
审计脚本,重复集为空才继续。

## 5. 测试矩阵(T 编号)

| # | 用例 | 锚点 |
|---|---|---|
| T1 | ed25519 blob round-trip(V1)字段精确 | Python |
| T2 | 好签名验真(V2)Accepted | Python cryptography |
| T3 | 篡改 msg / rs / 换钥(V3/V6)→ SignatureInvalid | Python |
| T4 | malformed 矩阵 ×9(空/截断/NUL/未知/证书/ecdsa/sk/pk31·33/trailing)(V4) | Python |
| T5 | rsa parse(V5):e-first、n 带 0x00 前缀 trim、字段相等 | Python |
| T5b | rsa 1023 位拒 / 1024 位过 | Python |
| T5c | MSB 负数拒 / raw>2049 拒(2049 且首 0 过→trim) | Python |
| T6 | 指纹文本 == Python "SHA256:..."(V1.fp) | Python hashlib+b64 |
| T7 | sig blob 矩阵(ssh-ed25519.c:232-300 精确序):alg≠→TypeMismatch;**错 alg+尾巴→TypeMismatch(alg 先于 trailing)**;正确 alg+尾巴→TrailingData;rs63→SignatureInvalid;rs65→InvalidFormat;空 sig→InvalidArgument | Python |
| T8 | msg > 1MB → InvalidArgument | — |
| T9 | 多 seed keygen-sign-verify 属性环(自洽) | — |

## 6. Python 参考(verify_c/hostkey_python_ref.py)

- cryptography.hazmat Ed25519PrivateKey.from_private_parameters(fixed_seed)
  (确定性 → 向量可复现);sign 得 rs64
- wire 组包独立实现(string/bignum2 规则按 RFC 4251 自写,与 MoonBit/C 互证)
- 库级 verify 交叉;指纹 hashlib + base64.b64encode().rstrip(b'=')
- SELF-CHECK 全绿后输出 KAT 到 _hostkey_ref_out.txt:
  V1 blob+fp 文本;V2 sig+msg hex;V3 篡改组;V4 malformed 组(期望错误名);
  V5 rsa blob(e=010001,n=2^2047|k 形态)+ 1024/1023 位对照 + 负数/超长样本;
  V6 第二对密钥
- RSA 数值:手工构造良构 mpint(parse-only 用途,如实注明非真实密钥)

## 7. C harness(verify_c/hostkey_harness.c + build_hostkey.bat)

链接:kex_sshbuf.c + kex_sshbuf_getput_basic.c(真实 sshbuf:get_cstring/
get_string/get_string_direct/get_bignum2_bytes_direct)+ openssh-C 根目录
真实 ed25519.c(crypto_sign_ed25519_keypair/open)+ compat 头复用
kex_c25519_compat.h 经验。转写薄层:from_blob dispatch(sshkey.c:2003-2066
行号注释)+ ed25519 verify 包装(ssh-ed25519.c:227-295)+ rsa bit_length+
check(ssh-rsa.c/sshkey.c:1469)。用例对齐 MoonBit T1-T8,断言同一批
_hostkey_ref_out.txt 字面量。

风险预案:ed25519.c 若引用 crypto_api.h 缺失符号 → 按 Loop #9 方式补 stub;
sshbuf 头的 X_INTERNAL guard 坑(harness 不先 include 原版头,用 compat 头)。

## 8. 已知风险

- sha256 改名脚本必须 word-boundary 替换并跑编译验证(ch/update 这类短名易误伤注释——注释里出现也一并替换无害)
- ge_table.mbt 体量大(~215KB),拷贝即可勿改动
- C harness 的 crypto_sign_ed25519_open 是"combined"形态(sm=sig‖msg),
  与 detached verify 的桥接在转写层完成,注意 smlen/mlen 语义
