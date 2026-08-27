# Loop #9 Curve25519 KEX — Code Reviewer Report

**Date:** 2026-08-25
**Role:** 🧪 Code Reviewer
**Scope:** Audit `src/kexc25519/` against OpenSSH kexc25519.c v1.18 / kexgen.c / kex.c / sshbuf, RFC 8731 + RFC 7748, and Python cryptography

---

## 1. Files Audited

| File | Size | Role |
|------|------|------|
| `x25519_*.mbt` × 7 | ~28 KB | X25519 inline(Loop #4 验证过的积木;脚本拷贝,零内容改动)|
| `sha256_*.mbt` × 6 | ~9 KB | SHA-256 inline |
| `sshbuf.mbt` | 2.2 KB | KxBuf 写侧助手 + mpint(`kx_` 前缀防撞名)|
| `shared_key.mbt` | 1.5 KB | keygen / shared_key_raw / shared_key_mpint |
| `exchange_hash.mbt` | 2.5 KB | build_exchange_input + kex_gen_hash |
| `derive_keys.mbt` | 3.2 KB | derive_single(KDF 链式扩展)+ derive_keys 六密钥 |
| `client.mbt` | 3.6 KB | Cursor 严格解析:REPLY 三段 string + ssh-ed25519 sig 形态 |
| 测试 ×2 | 16 KB | 19 新测试(6 wbtest + 13 blackbox)|

**inline 冲突审计:** 脚本化正则扫描两积木包全部顶层标识符——**零重复**(程序化验证,非目测);新代码统一 `kx_/KX_` 前缀。这解决了 Loop #8 报告里预警的"x25519 与 ed25519 fe_* 全线撞名"问题——本卷通过**不 inline ed25519**回避。

---

## 2. Bugs Found & Fixed

### 2.1 🟡 `crypt`-类方向性检查的教训没有重演,但出现了新变体:`ExchangeInputs` 跨包构造受限

**现象:** 黑盒测试无法用字面量构造 readonly struct(MoonBit [4036] "Cannot create values of the read-only type")。

**Fix:** 提供 `ExchangeInputs::make()` 公开构造器。这是 MoonBit 结构体可见性模型与 Rust 的差异点:字段默认公开可读,但跨包字面量构造受限。

### 2.2 🟡 `const`/`let` 命名规则

MoonBit `const` 要求大写标识符、顶层 `let` 要求小写——初版用了 `const kx_digest_len`,报错后改 `KX_DIGEST_LEN`。**教训:MoonBit 常量命名大小写是语法约束而非风格建议。**

### 2.3 🟢 测试自身手误(wbtest 拼串多写一段)

`exchange_input_fake_header_length` 手工期望串把 mpint 输入段写成了 `"000000050000000000"`(9 字节),实际输入是 5 字节 `"0000000000"`——字节级断言当场抓住,长度对账(126 vs 118 hex chars)定位。严格解析器+逐字节断言的价值再次确认。

### 2.4 🟢 Python 参考侧:A3 全零公钥路径

cryptography 库在点校验层直接拒绝全零公钥(raise ValueError),不会算出全零共享密钥。而 OpenSSH C 和 MoonBit 都是"算出全零再拒绝"。三方结论一致(拒绝),但**拒绝发生的层级不同**——参考脚本如实记录这一差异,不强行伪造库行为。

---

## 3. Security Review

| 项目 | 结论 |
|------|------|
| 全零共享密钥拒绝 | ✅ 对应 C `timingsafe_bcmp` 检查(kexc25519.c:70);测试锁定 |
| 解析器健壮性 | Cursor 严格模式:截断/尾随垃圾/u32→Int 溢出防护(`>0x7FFFFFFF` 拒绝)/Q_S 必须 32B(C 同款检查)|
| 签名校验缺失(**设计决定**) | 本包只解析 sig blob 形态(alg 名 + rs 64B);密码学验证由 Loop #7 已三盲验证的 src/ed25519 在集成层执行。**风险**:若未来接线错误,H 之外的数据被签名验证,证据链断裂。已在 client.mbt 注释中标注接线义务 |
| 时序泄露 | shared_key 全零检查用提前退出循环(vartime)vs C timingsafe_bcmp——全零判定本身不泄露密钥信息(ss 是输出而非秘密输入),可接受;记录差异 |
| 随机源 | c25519_keygen 标量由调用方注入(C 用 arc4random_buf)。确定性设计利于测试,生产接线时必须接 CSPRNG——文档标注 |

---

## 4. Test Suite Assessment

- **19 个新测试**(6 wbtest + 13 blackbox),全套 **173/173 PASS**
- mpint 双分支显式覆盖(no-prepend / prepend)+ 前导零折叠 + 全零/空
- fake header off-by-one 高危点有专项布局测试(手工拼完整期望字节)
- H 字段敏感性:I_C 单比特翻转 → H 必须变化(防漏字段)
- KDF 前缀稳定性:we_need=33 的前 32 字节必须等于 we_need=32 的输出(链式扩展正确性)
- REPLY 解析:合法/截断/尾随垃圾/Q_S 非 32B 四路覆盖
- sig 解析:合法 blob / rs=63B / 非 ed25519 alg

**结论:PASS — 可交付。** 无 🔴 级问题;两个 🟡 均为 MoonBit 语言语义适应成本,已修复并有测试锁定。
