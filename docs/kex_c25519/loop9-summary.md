# Loop #9 Summary — Curve25519 KEX (curve25519-sha256@libssh.org)

**Closed:** 2026-08-25
**Status:** ✅ COMPLETE — 173/173 MoonBit tests, C harness 17/17 PASS (exit 0), triple-blind byte-exact across shared secret / mpint / exchange hash / 6 session keys

---

## 1. What we built

从零组装的 **SSH curve25519-sha256@libssh.org 密钥交换核心**(RFC 8731),把 Loop #4 的 X25519 接上了 SSH wire 格式、交换哈希与会话密钥派生——首次覆盖"算法之上的协议层"。

### 1.1 Source files (`src/kexc25519/`)

```
src/kexc25519/
├── moon.pkg
├── x25519_*.mbt × 7     (~28 KB) Loop #4 积木 inline(零改动,脚本拷贝)
├── sha256_*.mbt × 6     (~9 KB)  SHA-256 inline
├── sshbuf.mbt           (2.2 KB) KxBuf:put_u8/u32/string/mpint
├── shared_key.mbt       (1.5 KB) keygen + 共享密钥(全零拒绝)+ mpint 封装
├── exchange_hash.mbt    (2.5 KB) build_exchange_input + kex_gen_hash(SHA-256)
├── derive_keys.mbt      (3.2 KB) K1/Kn 链式 KDF + 六密钥(A-F)
├── client.mbt           (3.6 KB) REPLY 三段解析(Cursor 严格模式)+ ed25519 sig 形态
├── kexc25519_test.mbt   (12 KB)  13 blackbox
└── kexc25519_wbtest.mbt (4 KB)   6 whitebox(mpint 分支/fake header 布局)
```

### 1.2 Verification artifacts

```
verify_c/
├── kex_c25519_python_ref.py   # 参考生成器(X25519 自检 → mpint 双分支向量 → H/KDF → 签名包)
├── _kex_ref_out.txt           # 向量输出
├── kex_harness.c              # 单 TU:smult_ref + 真 sshbuf + sha2.c
├── kex_sshbuf.c/.h            # OpenSSH sshbuf 拷贝(include 重映射;真 put_bignum2_bytes)
├── kex_sshbuf_getput_basic.c
├── kex_c25519_compat.h        # 类型/ssherr/ROUNDUP/__predict/freezero/recallocarray stub
├── kex_kat.exe                # 17/17 PASS, exit 0
└── build_kex.bat

docs/kex_c25519/               # navigator / architect / reviewer / reality-checker / 本文件
```

### 1.3 协议语义锚点(C ↔ MoonBit 对应)

| C | MoonBit |
|---|---------|
| `kexc25519_keygen`(arc4random + scalarmult 9)| `c25519_keygen(scalar)` 标量注入式 |
| `kexc25519_shared_key_ext` 全零检查 | `c25519_shared_key_raw` → None |
| `sshbuf_put_bignum2_bytes` | `KxBuf::put_mpint` / `kx_mpint`(双分支)|
| `kex_gen_hash`(kexgen.c:48)fake header len+1 | `build_exchange_input`(wbtest 布局锁定)|
| `derive_key`(kex.c:1069)K1/Kn 链式 | `derive_single`(Kn 无 session_id!)|
| `kex_derive_keys` session_id = 首次 H | `derive_keys` |

---

## 2. Key Technical Decisions

### 2.1 不 inline Ed25519——用证据链代替代码合并

ed25519 包含 215KB 基点表且 fe_* 与 x25519 包全线撞名。本卷只做 sig blob **形态解析**(alg 名 + rs 64B),密码学验证委托给已三盲验证的 src/ed25519,证据链:cryptography 签名 H → 解析出的 rs 字节一致 → Loop #7 证明 verify 正确。集成层接线义务已在代码注释标注。

### 2.2 C harness 复用真实 sshbuf

mpint 编码不转写——直接编译 OpenSSH 原版 `sshbuf.c`+`getput-basic.c`(仅 include 重映射)。代价是补齐 7 个 compat 依赖(ROUNDUP/__predict_false/ssh_signal/freezero/recallocarray/VA_COPY/ssherr 码),换来 mpint 行为的零猜测。

**关键坑:include guard 吞内部段。** `kex_sshbuf.h` 的 SSHBUF_SIZE_INIT 等在 `#ifdef SSHBUF_INTERNAL` 内,harness 先 include 头再由 .c 定义宏重入时被 `_SSHBUF_H` guard 整体跳过。修法:harness 绝不先包含该头,让它经 .c 带 INTERNAL 进入。

### 2.3 inline 冲突程序化审计

拷贝脚本用正则扫描两积木包全部顶层标识符,输出重复集为空才算通过——x25519(fe_*系)与 sha256(transform/pad/k256)天然零冲突,但这个检查以后每卷 inline 都要跑。

---

## 3. Bugs Found & Fixed

| # | 级别 | Bug | 捕获者 |
|---|------|-----|--------|
| 1 | 🟡 | readonly struct 跨包构造受限([4036])→ 加 ExchangeInputs::make | moon check |
| 2 | 🟡 | const 大写/let 小写是语法约束([3002])| moon check |
| 3 | 🟢 | wbtest 手工期望串多写一段 mpint(126 vs 118 hex chars)| 字节级断言 + 长度对账 |
| 4 | 🟢 | RFC7748 ss 首字节 0x4a 高位为 0——A1/A2 分支假设反了 | python self-check assert |
| 5 | 🟢 | cryptography 对全零公钥库层即拒(与 C/MoonBit 拒绝层级不同)| 参考脚本 try/except 如实记录 |

无 🔴。Loop #8 的"移位宽度三连"没有再现——seqnr 类大端编码这次直接走 UInt64 域。

## 4. Verification Matrix

| 维度 | 结果 |
|------|------|
| `moon check` | clean |
| `moon test` | **173/173**(新增 19)|
| `moon fmt` / `moon info` | 已跑,复测 173/173 |
| Python ref | ALL SELF-CHECKS PASSED(exit 0)|
| C harness | **17/17 PASS**(A 组 10 + B 组 7),exit 0 |
| RFC 锚点 | keygen/shared secret = RFC 7748 §6.1 官方值 |
| 负向 | 全零拒绝三方一致;解析器四路拒绝;sig 形态两路拒绝 |

## 5. Lessons(沉淀候选)

1. **include guard 与条件内部段的相互作用**:带 `#ifdef X_INTERNAL` 的头文件绝不能在外部 TU 先 include,否则 guard 会吞掉后续带宏的重入。
2. **拒绝层级可以不同,结论必须一致**:全零公钥在三方的拒绝点各不相同(库校验/输出检查),Reality Checker 的职责是把"结论一致、路径不同"如实记录而非强行对齐。
3. **分支覆盖率要先问数据分布**:32B 随机值高位 50/50,测试向量必须显式覆盖两侧——mpint 这种"看起来只有一个公式"的编码最容易漏一半。
4. **inline 积木前跑冲突审计脚本**,目测靠不住。
5. **MoonBit 结构体可见性**:pub struct 字段默认公开可读但跨包构造受限;需要外部构造就给 make 构造器。

## 6. Loop 进度

**Loop #9 完成,进度 9/17**(核心循环)。已完成:ChaCha20、Poly1305、HMAC-SHA256、X25519、SHA-512、HMAC-SHA512、Ed25519、AEAD、Curve25519-KEX。

**下一环候选**(待确认):
- **SSH binary packet protocol**:包格式(packet length ‖ padding ‖ payload ‖ mac)+ 与 Loop #8 AEAD 对接——传输层闭环,kex 密钥真正"用起来"
- **RSA sshkey wire 解析**:mpint 组装大整数,hostkey 栈补全
