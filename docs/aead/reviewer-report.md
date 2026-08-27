# Loop #8 ChaCha20-Poly1305 AEAD — Code Reviewer Report

**Date:** 2026-08-25
**Role:** 🧪 Code Reviewer
**Scope:** Audit `src/aead/` (RFC 8439 core + OpenSSH wire wrapper) against RFC 8439, OpenSSH `cipher-chachapoly.c` v1.10, and Python `cryptography` 44.0.1

---

## 1. Files Audited

| File | Size | Role |
|------|------|------|
| `chacha_*.mbt` × 4 | ~12 KB | ChaCha20 inline copy #2 (from Loop #1 `src/chacha/`) |
| `poly1305_*.mbt` × 6 | ~13 KB | Poly1305 inline copy #2 (from Loop #2 `src/poly1305/`, `poly_` 前缀防撞名) |
| `rfc8439.mbt` | 5.4 KB | RFC 8439 核心 AEAD(12B nonce,IETF state 布局) |
| `ssh_wire.mbt` | 5.2 KB | OpenSSH wire 包装(`ChachaPolyCtx`:双 key、BE64 seqnr、ctr=0/0/1) |
| `aead_test.mbt` | 15 KB | 24 blackbox 测试(KAT + 边界 + 负向 + wrapper) |
| `aead_wbtest.mbt` | 6 KB | 10 whitebox 测试(state 布局 / mac_data 结构 / 内部一致性) |

moon 0.1.20260608 不支持跨包 import,chacha×4 + poly1305×6 必须 inline 进本包——与 SHA-512 三份拷贝同类的已知 DRY 债务。命名冲突用前缀解决:`u8_to_32_le`(chacha 侧)与 `poly_u8_to_32_le`(poly1305 clamp 内),`block_len/key_len/tag_len`(chacha 侧)与 `poly_*` 版本。

---

## 2. Critical Bugs Found & Fixed

### 2.1 🔴 RFC 8439 counter off-by-one(poly_key ctr=1 → 应为 ctr=0)

**Location:** `rfc8439.mbt` — `aead_poly_key` / `aead_encrypt` / `aead_decrypt`

**Bug:**
```moonbit
// ❌ 初版:pk = block(counter=1),payload 从 counter=2 起
let st = rfc8439_state(key, nonce, 1U)
```

RFC 8439 § 2.6 的表述是 "encrypting 32 zero bytes"(即 block counter **0** 的首个 keystream block 前 32 字节),payload 从 counter **1** 起。初版误读为 pk=block(1)/payload=block(2)——恰好是 Bernstein/OpenSSH 惯例的错位平移。

**捕获方式:** Python 参考脚本的 self-check 断言——自做模拟与 `cryptography.ChaCha20Poly1305` 输出不一致当场 raise。这正是 Architect 设计文档预警的"counter off-by-one 由官方 KAT 即时捕获"。

**Fix:** pk=block(0)[:32],payload 从 ctr=1。修复后 ct 首块 `d31a8d34…`、tag `1ae10b59…` 与 RFC § 2.8.2 已知值一致(Python/MoonBit/C 三方同时命中)。

**教训:两种惯例的 poly_key 都是"第一块",但起点不同**(Bernstein 计数器从 0 开始,payload 从 1 起;IETF AEAD 显式规定 pk=block 0)。写跨变体代码时,counter 语义必须从 spec 原文确认,不能凭记忆迁移。

### 2.2 🔴 `seq_to_be64`:UInt 域移位宽度 bug(loop #7 同类第三发)

**Location:** `ssh_wire.mbt`

**Bug:**
```moonbit
// seqnr : UInt(32 位)
buf[i] = ((seqnr >> ((7 - i) * 8)) & 0xFFU).to_byte()
// i=0 时 >>56 被 MoonBit 掩码为 >>24(移位量 &31)
// seqnr=0x11223344 产出 1122334411223344 而非 0000000011223344
```

C 的 `POKE_U64(seqbuf, seqnr)` 先把 u_int 零扩展为 uint64_t 再逐字节存大端。MoonBit 的 UInt 移位量按 32 位域取模,≥32 的移位全部回绕,高 4 字节变成了低 4 字节的重复。

**捕获方式:** wbtest 的字节级断言 `seq_to_be64_mid/max` 直接 abort——严格 hex 解析器 + 逐字节比较再次证明其价值(有损解析或长度断言都抓不住这个)。

**Fix:**
```moonbit
let v : UInt64 = seqnr.to_uint64()
buf[i] = ((v >> ((7 - i) * 8)) & 0xFFUL).to_byte()
```

**教训固化:** 这是 Loop #4(X25519 shift)、Loop #7(`ge_equal_i8` y>>31)之后**同一类 bug 第三次出现**。规则升级为:**任何从 C 翻译的移位,先确认目标整数域宽度;修一处必须 grep 同域全部同类移位**。本次已 grep `src/aead/` 全部 `>>` 确认无残留。

### 2.3 🟡 `crypt()` 长度检查未区分加密/解密方向

**Location:** `ssh_wire.mbt` — `ChachaPolyCtx::crypt`

**Bug:** 初版统一要求 `src.length() >= aadlen + datalen + 16`。但 C 语义里:
- 加密时 src 只有 header‖payload(tag 还不存在,由 dest 承载);
- 解密时 src 才含 tag。

结果所有加密调用直接返回 None,wrapper 测试全灭。

**Fix:** 方向分支——encrypt 要求 `>= body_len`,decrypt 要求 `>= body_len + 16`。

### 2.4 🟡 decrypt 返回布局与 C 不一致(设计偏差,主动收敛)

初版解密路径把原 tag 拷到输出尾部("保持 C 缓冲布局"),但 C 实际只写 `dest[0..aadlen+len)`。既然返回的是新分配数组而非复用缓冲,布局对齐毫无意义。**Fix:** 解密返回恰为 `aadlen+datalen` 字节(头‖明文 payload),文档注明与 C `dest` 语义一致。

### 2.5 🟢 测试自身两处错误(masked implementation correctness)

1. **wrong-key 用例改错了字节**:翻转 `key[63]`(header_key)不会使 MAC 失败——encrypt-then-MAC 的 tag 只依赖密文和 poly_key(源自 main_key),与两个 ChaCha key 都无关。这不是实现 bug,是协议性质(C 行为相同:错误 header key 下 MAC 仍通过,包头解出垃圾)。**Fix:** 改翻 `key[0]`;并新增 `wrapper_wrong_header_key_still_decrypts_payload` 反向锁定该性质(payload 正确 + 包头必非原值),防止后人"修复"成错误语义。
2. **`pt.is_empty()` 弃用告警** → 改为显式 match。

### 2.6 🟢 Python 参考脚本自身 bug

`Poly1305(key).finalize()` 漏调 `.update(msg)` 就比对——self-check 第一道闸先抓住自己,修正后才开始产出向量。三盲流程中参考侧自检先行是正确投资。

---

## 3. Security Review

| 项目 | 结论 |
|------|------|
| Tag 比较 | vartime 逐字节比较(MoonBit 与 C `timingsafe_bcmp` 不同)。tag 是公开数据,MAC 验证 vartime 泄露的信息不构成实际攻击面;OpenSSH 用 timingsafe 属于纵深防御。**记录为已知差异,不阻塞。** |
| 密钥清零 | C 有 explicit_bzero;MoonBit GC 语言无法保证擦除,FixedArray 引用丢弃后由 GC 处理。与 Loop #4/#7 结论一致,不阻塞。 |
| 重放/序号 | wrapper 层不做反重放(C 层由 ssh.c 的 session_state 管理,不在 cipher-chachapoly 职责内),忠实复刻 ✓ |
| 错误通道 | 解密失败统一 None,不区分 MAC 错/格式错——与 C 的 SSH_ERR_MAC_INVALID 语义映射在 harness 中锁定 |
| abort 使用 | 仅用于 API 误用(new64 非 64 字节、get_length <4 字节);协议数据触发的失败一律走 Option ✓ |

---

## 4. Test Suite Assessment

- **34 个新测试**(24 blackbox + 10 whitebox),全套 154/154 PASS
- KAT:RFC 8439 § 2.8.2 官方输入 + A2/A3/A4 空边界(aad 空/pt 空/双空),期望值全部来自 Python cryptography
- 多块边界:0/1/63/64/65/128/129/300 字节 roundtrip
- 负向:篡改 ct/tag、错 key(main)、错 nonce、错 aad、截断输入、错 seqnr、短缓冲——共 11 条拒绝路径
- 协议性质锁定:wrong-header-key 行为(§ 2.5)
- 白盒:state 布局逐 word、mac_data 布局逐字节(pad 位置 + LE64 长度尾)、seq_to_be64、pad16_len、poly_key=block(0) 前缀一致性、xor 自逆性

**结论:PASS — 可交付。** 两处 🔴 均在三盲闭环内被捕获并修复,无遗留阻塞项。
