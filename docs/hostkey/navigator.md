# Loop #11 Navigator — Hostkey 公钥解析与签名验证

日期:2026-08-26
目标:SSH 公钥 blob / 签名 blob 的 wire 解析(ssh-ed25519 全链路 + ssh-rsa 结构解析),
接通 Loop #7 ed25519 验证,把 Loop #9 KEX REPLY 的 hostkey/sig 从"形态解析"
升级为"可验证信任链"。

## 1. 信源

| 文件 | 位置 | 内容 |
|---|---|---|
| `openssh-C/sshkey.c` | L2003-2086 | `sshkey_from_blob_internal`:get_cstring → type_from_name → cert 检查(allow_cert=1 默认,我们取 false 语义)→ impl deserialize_public → **trailing 检查(L2053)** |
| 同上 | L2070 | `sshkey_from_blob`(blob 入口, allow_cert=1) |
| 同上 | L2237-2252 | `sshkey_verify` 前置:siglen==0 或 dlen > SSH_KEY_MAX_SIGN_DATA_SIZE → INVALID_ARGUMENT;再分派 impl->verify |
| 同上 | L239-258+ | `type_from_name`:全名精确匹配(短名仅 allow_short);未命中 KEY_UNSPEC |
| 同上 | L1469-1483 | `sshkey_check_rsa_length`:nbits < SSH_RSA_MINIMUM_MODULUS_SIZE → SSH_ERR_KEY_LENGTH |
| `openssh-C/sshkey.h` | L53-54 | `SSH_RSA_MINIMUM_MODULUS_SIZE = 1024`;`SSH_KEY_MAX_SIGN_DATA_SIZE = (1<<20)` |
| `openssh-C/ssh-ed25519.c` | L102-117 | deserialize_public:get_string 后 len != ED25519_PK_SZ(32) → INVALID_FORMAT |
| 同上 | L185-224 | sig 编码:`string "ssh-ed25519" ‖ string sig64` |
| 同上 | L227-295 | verify:解析 sig blob(ktype 必须精确 "ssh-ed25519";trailing→UNEXPECTED_TRAILING_DATA;**len>64→INVALID_FORMAT;len<64 不在解析层拒**,进 open() 自然失败)→ sm=sig‖data 走 crypto_sign_ed25519_open → 失败或 mlen!=dlen → SIGNATURE_INVALID |
| `openssh-C/ssh-rsa.c` | deserialize_public | **先 e 后 n**(两个 get_bignum2),随后 check_rsa_length |
| `openssh-C/sshbuf-getput-basic.c` | L598+ | `get_bignum2_bytes_direct`:MSB set(len≠0)→ BIGNUM_IS_NEGATIVE;len>2049 或 ==2049 且首字节非 0 → BIGNUM_TOO_LARGE(SSHBUF_MAX_BIGNUM=16384/8=2048);**trim 前导零后返回** |
| 同上 | L269+ | `get_cstring`:\0 只允许出现在末位(memchr 命中且 < p+len-1 即 INVALID_FORMAT) |
| `openssh-C/sshkey.c` | L1031-1050 | fingerprint_b64:"SHA256:" + 标准 base64 + **strcspn(ret,"=") 截断 padding** |

## 2. 错误码映射(ssherr → KeyError 枚举)

| C | MoonBit |
|---|---|
| SSH_ERR_INVALID_FORMAT | InvalidFormat |
| SSH_ERR_KEY_TYPE_UNKNOWN(impl 表无此名) | UnsupportedType |
| SSH_ERR_KEY_CERT_INVALID_SIGN_KEY | CertNotAllowed |
| SSH_ERR_KEY_TYPE_MISMATCH(sig alg ≠ key type) | TypeMismatch |
| SSH_ERR_UNEXPECTED_TRAILING_DATA | TrailingData |
| SSH_ERR_BIGNUM_IS_NEGATIVE | BigNumNegative |
| SSH_ERR_BIGNUM_IS_NEGATIVE 之外的超长 | BigNumTooLarge |
| SSH_ERR_KEY_LENGTH(n < 1024 bits) | RsaModulusTooShort |
| SSH_ERR_SIGNATURE_INVALID | SignatureInvalid |
| SSH_ERR_INVALID_ARGUMENT(siglen==0 / dlen>1MB) | InvalidArgument |
| (范围外:RSA 密码学验证无 bignum modexp,显式) | RsaVerifyUnavailable |

## 3. 解析算法要点

### from_blob(allow_cert=false)
1. get_cstring(ktype):u32 len + bytes;\0 仅可居末;空串落 Unknown
2. 名字三分:**精确表 {ssh-ed25519, ssh-rsa}** / 以 `-cert-v01@openssh.com`
   结尾 → CertNotAllowed(C 的 !allow_cert 路径)/ 其余(ecdsa-*、sk-*、
   ssh-dss、sntrup* 等)→ UnsupportedType
3. ed25519:string pk,len 必须 ==32
4. rsa:bignum2 e → bignum2 n → bit_length(trim(n)) < 1024 → RsaModulusTooShort
   (C 在 deserialize 内部做长度检查,因此**优先于** trailing 检查——顺序保持)
5. 尾部残余 → TrailingData

### bignum2(与 put_mpint 对偶,Loop #9 规则的逆)
- u32 raw_len;raw_len≠0 且首字节 MSB set → Negative
- raw_len > 2049 || (==2049 且首字节≠0) → TooLarge
- trim 前导零得值字节;全零串 → 空数组(C BN_bin2bn 空=0,不额外拒绝;
  n=0 由 bit_length<1024 兜住,e=0 如实放行——C 也不查)

### verify(key, msg, sig_blob)(ssh_ed25519_verify 转写 + sshkey_verify 前置)
1. sig_blob.length()==0 ‖ msg.length() > 1MB → InvalidArgument
2. cstring alg;≠"ssh-ed25519" → TypeMismatch
3. string rs;sig buffer trailing → TrailingData
4. rs.len > 64 → InvalidFormat;rs.len < 64 → SignatureInvalid
   (C 放行进 open() 必败,可观测结果相同——文档注明捷径)
5. ed25519::verify(rs, msg, pk)?Accepted:SignatureInvalid
6. RSA key → RsaVerifyUnavailable(诚实标注)

### fingerprint(SHA256)
digest = sha256(blob)(plain blob 与 C 的重序列化输出逐字节一致);
文本形式 = "SHA256:" + base64(digest) 去 '='。

## 4. inline 清单与冲突预案(src/hostkey)

- **ed25519 组**(原样拷贝):api.mbt、fe.mbt、ge.mbt、ge_table.mbt、sc.mbt、
  sha512_{api,block,final,primitives,state,update}.mbt
  API:keypair_from_seed(seed)→(pk[32],sk[64]);sign(msg,sk)→sig[64];
  **verify(sig, msg, pk) -> Bool**(注意参数序!);内部自带 sha512
- **sha256 组**(拷贝自 src/sha256 六文件):api/block/final/primitives/state/update
- **冲突集(9 个名字)**:block_len、ch、hash_len、maj、pad、rotr、
  serialize_state、transform、update —— sha256 侧统一加前缀 `s256_`
  (defs + 组内互引一起改;sigma0_big 等命名不同不冲突;init_H/k256/
  be32_to_8/sha256 本身不冲突保留)
- 新代码命名避开两集:HkCursor、HostKey、HostSig、KeyError、ParseResult、
  VerifyResult、hk_base64_nopad 等

## 5. 三盲计划

- **MoonBit**:src/hostkey(独立实现)
- **Python**:cryptography 库生成固定 seed 的 Ed25519 对(RFC 8032 确定性签名,
  同 msg 必同 sig → 向量可复现);独立组包(blob/sig wire 格式)+ 独立解析 +
  库级验签交叉;RSA 用手工构造的良构 mpint(parse-only,如实注明);
  指纹 hashlib.sha256 + base64 nopad 对照
- **C harness**:链接真实 kex_sshbuf.c + kex_sshbuf_getput_basic.c
  (含 get_cstring/get_string/get_string_direct/get_bignum2_bytes_direct,
  L185/212/269/598 已确认存在)+ openssh-C 根目录真实 ed25519.c(ref10 自包含,
  crypto_sign_ed25519_keypair/open)+ 按 sshkey.c/ssh-ed25519.c 行号转写
  dispatch 薄层(~80 行)。RSA parse 走真实 get_bignum2_bytes_direct。

## 6. 测试矩阵(草案,T 编号见 architect)

round-trip / 验真 / 篡改三向(msg、rs、错钥)/ malformed 矩阵(空 blob、
截断、NUL-in-name、未知类型、证书名、ecdsa/sk 名、pk 31/33 字节、trailing)/
rsa(e-first 顺序、257 字节带前置零的 n、1023 vs 1024 位界、负数拒绝、
超长拒绝)/ 指纹文本对照 / sig-blob 矩阵(alg 错、trailing、63/65 字节)/
msg > 1MB / 多 seed keygen-sign-verify 属性环。

## 7. 范围裁定

**做**:ed25519 blob+sig 解析与密码学验证全链路;rsa blob 结构解析(含全部
mpint 规则与长度政策);SHA256 指纹(base64 文本);cert/ecdsa/sk 显式分类拒绝。

**不做**:证书体解析(RFC draft-miller-ssh-cert,未来 loop);ECDSA/SK;
RSA 密码学验证(需 bignum modexp,未来 loop;RsaVerifyUnavailable 显式报);
known_hosts/POF 语义(集成层)。
