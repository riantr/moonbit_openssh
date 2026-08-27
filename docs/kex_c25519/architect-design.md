# Loop #9 Curve25519 KEX — Architect Design

**Date:** 2026-08-25
**Role:** 📐 Architect
**Input:** navigator-report.md

---

## 1. 包结构

```
src/kexc25519/
├── moon.pkg                    // 无外部依赖(全部 inline)
├── x25519_*.mbt × 7            // Loop #4 积木 inline(api/arithmetic/freeze/mainloop/recip/select/state)
│                               //   不带 trace/debug 两个调试文件
├── sha256_*.mbt × 6            // src/sha256 inline(api/block/final/primitives/state/update)
├── sshbuf.mbt                  // kx_buf 写侧助手 + mpint 编码
├── shared_key.mbt              // kexc25519_keygen/shared_key_ext 对应物
├── exchange_hash.mbt           // kex_gen_hash 对应物
├── derive_keys.mbt             // derive_key/kex_derive_keys 对应物
├── client.mbt                  // REPLY 解析 + sig blob 解析 + 端到端编排
├── kexc25519_test.mbt          // blackbox
└── kexc25519_wbtest.mbt        // whitebox(mpint/哈希输入布局逐字节)
```

inline 方法:python 脚本拷贝文件并加 `// inlined from src/<pkg>/<file>` 头,零内容改动(Loop #8 先例)。两积木包顶层标识符已验证零冲突。

## 2. 公开 API 设计

```moonbit
// ---- sshbuf.mbt ----
pub struct KxBuf { ... }                      // 增长式字节缓冲
pub fn KxBuf::new() / to_bytes()
pub fn KxBuf::put_u8(self, UInt) / put_u32(self, UInt)      // 大端
pub fn KxBuf::put_bytes(self, FixedArray[Byte])              // raw 追加
pub fn KxBuf::put_string(self, FixedArray[Byte])             // u32(len)+raw
pub fn KxBuf::put_mpint(self, FixedArray[Byte])              // § 5 Navigator 规则

// ---- shared_key.mbt ----
pub fn c25519_keygen(scalar : FixedArray[Byte]) -> FixedArray[Byte]
    // e = X25519(scalar, basepoint9);scalar 由调用方提供(测试确定性;
    // 生产随机源属集成层职责,C 里是 arc4random_buf)
pub fn c25519_shared_key_raw(priv : FA[Byte], pub : FA[Byte]) -> FixedArray[Byte]?
    // X25519 + 全零检查 → None(对应 SSH_ERR_KEY_INVALID_EC_VALUE)
pub fn c25519_shared_key_mpint(priv, pub) -> FixedArray[Byte]?
    // = mpint(raw),即 C 的 shared_key_ext(..., raw=0)

// ---- exchange_hash.mbt ----
pub struct ExchangeInputs {
  client_version : FixedArray[Byte]     // V_C 裸串(不含 string 包装,函数内包装)
  server_version : FixedArray[Byte]
  client_kexinit : FixedArray[Byte]     // I_C:type 字节之后的内容(同 C 的 kex->my)
  server_kexinit : FixedArray[Byte]     // I_S
}
pub fn kex_gen_hash(
  inputs : ExchangeInputs,
  hostkey_blob : FixedArray[Byte],
  client_pub : FixedArray[Byte],       // e(32B,裸)
  server_pub : FixedArray[Byte],       // f(32B,裸)
  shared_secret_mpint : FixedArray[Byte], // 已编码的 K buf 全文
) -> FixedArray[Byte]                   // SHA-256 摘要

// ---- derive_keys.mbt ----
pub struct DerivedKeys {
  session_id : FixedArray[Byte]
  iv_ctos/stoc, key_ctos/stoc, mac_ctos/stoc : FixedArray[Byte]
}
pub fn derive_keys(hash : FA[Byte], shared_secret_mpint : FA[Byte],
                   we_need : Int) -> DerivedKeys
pub fn derive_single(id_letter : Byte, need : Int,
                     hash : FA[Byte], ss : FA[Byte],
                     session_id : FA[Byte]) -> FixedArray[Byte]
    // 单密钥导出(KDF 链式扩展),wbtest 用

// ---- client.mbt ----
pub struct KexReply {
  hostkey_blob : FixedArray[Byte]
  server_pub : FixedArray[Byte]
  sig_blob : FixedArray[Byte]          // 未解析的 string(sig)
}
pub fn parse_reply(wire : FixedArray[Byte]) -> KexReply?
    // 三段 string 提取;多余尾部 → None(严格)
pub struct Ed25519Sig { alg_name : FixedArray[Byte], rs : FixedArray[Byte] }
pub fn parse_sig(blob : FixedArray[Byte]) -> Ed25519Sig?
    // string(alg) ‖ string(rs);rs 必须 64B 才算 ed25519 合法形态
    // (本卷只解析+校验形态;密码学验证由 src/ed25519 集成层执行)

// ---- 服务端对称(轻量)----
pub fn server_shared_key_mpint(server_priv, client_pub_e) -> FixedArray[Byte]?
```

设计取舍:
- **错误通道统一 Option**:协议数据问题(长度、全零、截断)→ None;不引入错误枚举(C 的 SSH_ERR_* 在 MoonBit 侧无消费者)
- **mpint 输入输出都是"已编码全文"**:`kex_gen_hash` 与 `derive_keys` 直接吃 mpint 字节,与 C 的 `sshbuf_putb(b, shared_secret)` 语义一致,避免二次编码分歧
- **we_need 显式参数**:chachapoly 场景典型值在测试中用 64(key32/iv16/mac? 按 RFC 8731 组合),真实选路属未来传输层

## 3. 测试矩阵

### wbtest(白盒,逐字节)
- mpint:空/全零/高位1(prepend 分支)/高位0/前导多零折叠/1B 极端
- put_u32/u8/string 大端与布局
- exchange_hash 输入缓冲全布局(手工拼期望字节序列再 hash 对照 Python)
- derive_single:'A' 与链式扩展第二块(need > 32 时)

### blackbox(黑盒,Python 期望值)
- **端到端主向量**:RFC 7748 §6.1 Alice/Bob 标量对 + 固定 V_C/V_S/I_C/I_S/K_S:
  - shared_key_mpint 一致
  - H 一致
  - 6 密钥一致(we_need=64)
- 变体向量:不同 seqnr 式变体(I_C 差一字节)→ H 必须不同(防输入漏字段)
- 全零共享密钥:X25519(any, zero_pub)=0 → None(RFC 7748 明确此性质)
- parse_reply:正常/截断/尾随垃圾 → None
- parse_sig:合法 ssh-ed25519 包(Python cryptography sign 生成)/alg 不匹配/rs 非 64B → None

### Python 参考(`verify_c/kex_c25519_python_ref.py`)
- cryptography.X25519 计算 ss;按 C 规则手工构造 exchange input;hashlib.sha256;KDF 同公式
- 自检:cryptography 得到的 ss 高位两分支都要有向量(选标量使 ss[0]>=0x80 和 <0x80 各一)

### C harness(`verify_c/kex_harness.c`)
- include:`smult_curve25519_ref.c`(真 OpenSSH c25519 实现)、`sshbuf-getput-basic.c`(真 mpint!)、`sha2.c`(SHA-256)
- `kex_gen_hash` 主体逻辑按 kexgen.c 抄进 harness(标注来源行号),用它自己的 sshbuf+digest 替身跑同一向量
- 断言:ss/H/keys 三方一致;mpint 双分支直接对照真实现输出
```

## 4. 风险与对策(承接 Navigator §9)

| 风险 | 对策 |
|------|------|
| fake header len+1 | wbtest 手工布局断言 + Python/C 独立重算 |
| mpint 单分支覆盖 | 向量集显式含 ss[0]&0x80 两分支 |
| I_C 边界语义 | API 注释"不含 type 字节"+ 测试用真实 OpenSSH kexinit 截取 |
| inline 后撞名 | 已核验零冲突;新代码一律 kx_ 前缀 |
| ed25519 缺位 | 解析层单独验证;证据链写进 reality-checker |
