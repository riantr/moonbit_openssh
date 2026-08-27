# Loop #7 Summary — Ed25519

**Closed:** 2026-08-25
**Status:** ✅ COMPLETE — 120/120 MoonBit tests, triple-blind byte-exact (MoonBit ⊕ OpenSSH C ⊕ Python)

---

## 1. What we built

从零实现的 MoonBit **Ed25519 数字签名**（RFC 8032），对应 OpenSSH `ssh-ed25519` 的核心原语。这是 OpenSSH→MoonBit 移植的第 7 个算法，也是第一个**非对称签名**算法。

### 1.1 Source files (`src/ed25519/`)

```
src/ed25519/
├── moon.pkg
├── fe.mbt               (~10.7 KB) 域算术 mod p=2^255-19，32 × 8-bit limbs
├── sc.mbt               (~8.4 KB)  标量算术 mod L，Barrett 归约 + window3 + 2interleave2
├── ge.mbt               (~15 KB)   扭曲 Edwards 群运算 (p3/p2/p1p1/aff 四种投影坐标)
├── ge_table.mbt         (215 KB)   425-entry 预计算基点表（Python 解析 OpenSSH C 数组生成）
├── api.mbt              (~6.3 KB)  keypair_from_seed / sign / verify 公开 API
├── sha512_*.mbt × 6     (3rd inline copy)
├── ed25519_test.mbt     (10 blackbox: KAT×3 + determinism + tamper + wrong-pk + large-msg + sk-format + s≥L×2)
└── ed25519_wbtest.mbt   (11 internal: 3 RFC 8032 KAT + fe/sc/ge 单元)
```

### 1.2 Verification artifacts

```
verify_c/
├── ed25519_harness.c          # 直接 #include OpenSSH 原版 ed25519.c + sha2.c
├── ed25519_ref.c              # OpenSSH ed25519.c 拷贝（仅重映射两个 include）
├── ed25519_includes_stub.h    # includes.h 最小 stub
├── ed25519_crypto_api_stub.h  # crypto_api.h stub（crypto_hash_sha512 → sha2.c）
├── ed25519_kat.exe            # 4/4 PASS, exit 0
├── build_ed25519.bat
└── ed25519_python_ref.py      # Python cryptography 参考输出脚本

docs/ed25519/
├── navigator-report.md ✅
├── architect-design.md ✅
├── reviewer-report.md  ✅
├── reality-checker-report.md ✅
└── loop7-summary.md    ✅ (本文件)
```

---

## 2. Key Technical Decisions

### 2.1 Worker delegation + 主会话收尾

fe/sc/ge 三层数学由 worker agent 完成 Phase 1–3（含 215KB 查表转换），因 Token 上限中断在调试期。主会话接管后：
- 对照 OpenSSH C 原文逐函数审计（choose_t/mixadd2/dbl/window3/2interleave2/unpackneg 全部 line-by-line 核对）
- 定位并修复全部剩余 bug（见 § 3）

**教训：worker 中断后不要盲目重启 worker——先跑 `moon check` + `moon test` 盘点现场。这次 worker 留下的代码已 90% 正确。**

### 2.2 32 × 8-bit limb 结构

与 X25519（Loop #4）的 10 × 26-bit 不同，本卷严格跟随 OpenSSH ref10 的 32 字节布局：
- 优点：pack/unpack 是纯 memcpy，查表数据可直接复用；代码与 C 一一对应便于审计
- 代价：乘法中间值需 UInt64 承载（8-bit × 8-bit ≤ 16-bit，累加 32 项 ≤ 21-bit，安全）

### 2.3 Malleability 防护（OpenSSH 特有）

OpenSSH 在标准 TweetNaCl 之上加了 `sc25519_inrange`（s < L 检查）。移植时踩了一个隐蔽坑：

```moonbit
// ❌ 错误顺序: barrett_reduce 把任何输入映射到 [0,L)，检查永远通过
let s_sc = sc_from32bytes(s_bytes)
if !sc_is_in_range(s_sc) { return false }

// ✅ 正确: 先对原始字节检查，再归约
if !sc_is_in_range_bytes(s_bytes) { return false }
let s_sc = sc_from32bytes(s_bytes)
```

原 `s_at_l_rejected` 测试靠 R=identity "碰巧" 通过，掩盖了这个 bug。修复后用真签名的 R + s:=L / L+1 双向量锁定该路径。

---

## 3. Critical Bugs Found & Fixed

| # | Bug | 影响 | 修复 |
|---|-----|------|------|
| 1 | `ge_equal_i8` 用 `y >> 31`（UInt64 域得到 33-bit 大数而非 0/1），cmov 掩码全错 → 查表全错 | 9/119 测试失败（keypair/sign/verify 全崩） | `(y >> 63) & 1UL`。**与 fe.mbt 已修复的 `fe_equal16` 同源 bug，worker 只修了一处** |
| 2 | verify 的 s<L 检查在 barrett_reduce 之后执行（恒真） | 签名 malleability：s≥L 的伪造签名可被接受 | 新增 `sc_is_in_range_bytes`，归约前检查原始字节 |
| 3 | `ge_pack_unpack_roundtrip` 测试预期错误：unpackneg 返回 −P，符号位必然翻转 | 测试误报失败 | 断言改为"前 31 字节相同 + 尾字节低 7 位相同 + 符号位翻转" |
| 4 | `tampered_msg_rejected` 用 `hex_to_bytes("hello World")` —— 非法 hex 字符静默映射为 0，'w'/'W' 都变 0x00，消息实际未被篡改 | 测试空洞化 | 改用真实 hex（68656c6c6f20776f726c64 vs …576f726c64）|
| 5 | harness 的 `mout[16]` 过小，`crypto_sign_ed25519_open` 写入 mlen+64 字节造成栈溢出踩坏相邻变量 | C 验证显示混乱（memcmp 先于污染 PASS、hexdump 后于污染显示全 0） | 缓冲区扩到 mlen+64+16 |

**跨卷规律（第 3 次出现）：** 有损解析器（hex_digit 静默置 0）会让测试数据悄悄变成另一个值。测试输入必须走规范化字面量。

**Shift-width 规律（Loop #4 → #7 二次确认）：** 修一个 shift 语义 bug 后必须 grep 同文件所有同宽度 shift。

---

## 4. 验证矩阵

| 验证 | 工具 | 结果 |
|------|------|------|
| MoonBit 全套 | `moon test` | ✅ **120/120**（新增 2 个 malleability 测试后） |
| 编译干净 | `moon check` | ✅ 0 error 0 warning，无 stdout 噪音 |
| OpenSSH C 原版 | `ed25519_kat.exe` | ✅ 3×(pk+sig+verify) + tamper-reject + s==L reject，exit 0 |
| Python cryptography 44.0.1 | `ed25519_python_ref.py` | ✅ 3 KAT 逐字节 + 负向用例 + 1024-byte 大消息 |
| 三盲交叉 | — | ✅ 无任何分歧 |

---

## 5. 流程统计

| 阶段 | 产出 |
|------|------|
| Navigator | OpenSSH ed25519.c 三层结构分析 + RFC 8032 向量清单 |
| Architect | 模块划分 + 数据流图 + 风险表 |
| Senior Dev | worker 完成 fe/sc/ge/api/ge_table (~250 KB MoonBit)；主会话完成 bug fix |
| Code Reviewer | 5 bugs 定位修复 + C 逐行一致性核对 |
| API Tester | C harness 4/4 + Python 参考 |
| Reality Checker | 三盲闭环签字 |

---

## 6. Open Questions / Future Work

1. **DRY 债务升级**：SHA-512 现在有 **3 份拷贝**（src/sha512、hmac_sha512、ed25519）。Ed25519 若继续被 X25519 复合方案引用还会更多。等 moon 支持跨包 import 立即重构。
2. **性能**：215KB 查表是编译期 literal；`ge_double_scalarmult_vartime` 每次 verify 重建 16 点预计算表。正确性优先，性能优化留待后续卷。
3. **Constant-time 审计未做**：ref10 结构大体保留（cmov 查表 CT），但 unpack/pack/scalar 比较是 vartime（RFC 允许，公钥/签名是公开数据）。
4. **Loop #8 候选**：
   - **ChaCha20-Poly1305 AEAD 组合**（Loop #1+#2 已有积木，低风险高价值 —— ssh 传输层加密）
   - Curve25519 密钥交换完整流程（ssh kex）
   - RSA/DSA 解析层（sshkey wire format）

**推荐 Loop #8 = ChaCha20-Poly1305 AEAD**（把两条已验证的积木组合成 OpenSSH 实际使用的 cipher suite，顺带引入 AEAD 加密/解密的 wire 格式处理）。

**Loop #7 关闭。**

签字: ✅ 2026-08-25
