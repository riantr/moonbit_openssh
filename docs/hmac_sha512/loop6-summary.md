# Loop #6 Summary — HMAC-SHA512

**Closed:** 2026-07-28
**Status:** ✅ COMPLETE (after KAT hand-transcription fix)

---

## 1. What we built

From-scratch MoonBit 实现 of **HMAC-SHA512** (RFC 2104 + RFC 4231), byte-exact 匹配 OpenBSD C (`sha2.c` + custom HMAC wrapper) 和 Python `hmac.new(key, msg, hashlib.sha512)`。

HMAC-SHA512 是 OpenSSH `hmac-sha2-512` 协议的核心原语：
- KEX (`diffie-hellman-group14-sha256`, `curve25519-sha256` 用其派生 session ID)
- Hostkey signing (`rsa-sha2-512`)
- Packet MAC (少用,主要用 `hmac-sha2-256`)

### 1.1 Source files (`src/hmac_sha512/`)

```
src/hmac_sha512/
├── moon.pkg
├── api.mbt                    (block_size=128, output_size=64, hmac_sha512 entry, prep_key, inner/outer hash)
├── sha512_state.mbt           (k512[80], init_h[8], block_len=128, hash_len=64) [inlined from src/sha512/]
├── sha512_primitives.mbt      (rotr64, ch, maj, big_sigma0/1, small_sigma0/1, be8_to_64, be64_to_8) [inlined]
├── sha512_block.mbt           (80 轮 compression, UInt64 域) [inlined]
├── sha512_update.mbt          (incremental + 128-bit Merkle-Damgård padding) [inlined]
├── sha512_final.mbt           (serialize 8 × UInt64 → 64 bytes BE) [inlined]
├── sha512_api.mbt             (public sha512(msg) entry, used internally) [inlined]
├── hmac_sha512_test.mbt       (8 blackbox tests)
├── hmac_sha512_wbtest.mbt     (6 RFC 4231 KAT + 1 truncation length check)
└── hmac_sha512_trace.mbt      (3 roundtrip + 2 blackbox smoke)
```

**Total: ~815 lines MoonBit code (其中 ~430 行是 inlined SHA-512)**

### 1.2 C verification harness

```
verify_c/
├── sha2.c                       (OpenBSD original, copy — provides SHA512Init/Update/Final)
├── hmac_sha512_harness.c        (custom HMAC-SHA512 wrapper, 6 RFC 4231 KAT vectors)
├── hmac_sha512_kat.exe          (compiled: 6/6 PASS)
└── build_hmac_sha512.bat        (build script)
```

### 1.3 Agent reports (`docs/hmac_sha512/`)

```
docs/hmac_sha512/
├── navigator-report.md          ✅
├── architect-design.md          ✅
├── reviewer-report.md           ✅
├── reality-checker-report.md    ✅
└── loop6-summary.md             ✅ (本文件)
```

---

## 2. Key Technical Decisions

### 2.1 复用 Loop #3 + Loop #5

Loop #6 几乎是 Loop #3 HMAC-SHA256 的"放大版":
- HMAC 结构完全相同 (`prep_key`, `inner_hash`, `outer_hash`)
- 只是把 SHA-256 换成 SHA-512,block_size 64→128, output 32→64
- Inlined SHA-512 = Loop #5 `src/sha512/` 的直接 copy

### 2.2 Cross-package import workaround (loop #3 → loop #6 复用)

`moon 0.1.20260608` 不支持跨包 import:
```
Error: [4042] Cannot find import 'openssh/openssh_moonbit/sha512'
```

**对策:** 直接把 SHA-512 6 个 .mbt 复制进 `hmac_sha512` 包内。Loop #3 已经验证过这个 workaround 工作。

**代价:** `src/sha512/` 和 `src/hmac_sha512/` 各自含一份 SHA-512 实现 (~430 行 × 2 = 860 行)。等 moon 修跨包 import bug 后再 refactor。

### 2.3 KAT 抄错教训 (loop #5 → loop #6 重复验证)

**Loop #5 学到的教训**: 永远用 Python `hashlib` 当 golden reference,不要从 RFC 文本手抄 expected。

**Loop #6 重复犯了这个错**: 我手抄了 6 个 RFC 4231 expected 数组,**全部都至少有一个字节错**。例子:
- Test 1, position 10: 抄成 `0x42`,真值 `0xb4` (算法对了,expected 抄错)
- Test 4, position 5: 抄成 `0x1d`,真值 `0x45`
- Test 6, position 36: 抄成 `0xe5`,真值 `0xe0` (后 32 字节整段都错)
- Test 6, position 21-22: 抄成 `0xee 0xc1`,真值 `0xee 0xc1` (这次碰巧对了)

**对策:** 
1. 加 `dump_test_N` 输出 MoonBit 实际 hex
2. 跟 Python 生成的 hex 对比
3. 全部用 Python `hmac.new(key, msg, hashlib.sha512).hexdigest()` 重写 expected

**结论:** 算法始终是对的,**只是 expected hex 抄错**。这种错在 Triple-blind 下会自然暴露(因为 OpenBSD C 跟 Python 也会输出相同的真值,跟 hand-typed expected 不同)。

### 2.4 Debug `println` 副作用 (loop #6 自己发现)

最初 `api.mbt` 里有 debug `println("key[:5]: " + sb.to_string().unsafe_substring(start=0, end=20))` 这种调用,当 key 长度 < 20 时会崩(`unsafe_substring` 不允许 start=length)。

**对策:** 公开 API (`api.mbt`) **零 `println`**,所有调试输出放到 `hmac_sha512_trace.mbt` 这种独立文件里。

---

## 3. 验证矩阵

| 验证 | 工具 | 结果 |
|------|------|------|
| MoonBit 算法正确 (RFC 4231) | `moon test` (hmac_sha512_wbtest) | ✅ 6/6 |
| MoonBit blackbox | `moon test` (hmac_sha512_test) | ✅ 8/8 |
| MoonBit hex roundtrip + smoke | `moon test` (hmac_sha512_trace) | ✅ 3/3 |
| MoonBit vs OpenBSD C (sha2.c) | `verify_c/hmac_sha512_kat.exe` | ✅ 6/6 byte-exact |
| MoonBit vs Python `hmac` | Python 独立 | ✅ 6/6 byte-exact |
| OpenBSD C vs Python | 独立交叉验证 | ✅ 6/6 (sanity) |
| 编译干净 | `moon check` | ✅ 0 warnings |

**Total: 17 MoonBit HMAC-SHA512 tests + 6 C harness = 23 independent verifications, all PASS.**

(Loop #6 整体 `moon test` 是 97/97,因为其他 79 个测试来自 SHA-256 / SHA-512 / ChaCha20 / Poly1305 / X25519 / HMAC-SHA256 模块,也都通过。)

---

## 4. Critical bugs found & fixed

### 4.1 KAT expected 全部 6 个抄错 (RFC 4231 hand-typed)

**Bug:** Loop #5 时定下的"永远用 Python 当 reference"原则,**Loop #6 实施时忘了**,直接手抄 RFC 文本。

**Symptom:** `moon test` 报 6 个 KAT fail,byte-level diff (e.g. `0xb4 != 0x42`, `0x45 != 0x1d`)。

**Discovery:**
1. 写了 `hmac_sha512_trace.mbt` 加 `dump_test_N` 输出实际 hex
2. 对比 dump 输出 vs Python `hmac.new(key, msg, hashlib.sha512).hexdigest()`
3. 发现**完全一致** → 算法对
4. 对比 dump 输出 vs wbtest hand-typed expected → 6 个全有 byte diff
5. 用 Python hex 覆盖所有 6 个 expected 数组

**Fix:** `hmac_sha512_wbtest.mbt` 全部 6 个 expected 数组重写。

**Lesson (再次强化):** **永远用 Python `hmac` 当 golden reference,不要从 RFC 4231 文本手抄 expected hex。** 这条 Loop #5 定下的原则必须在每次出题时主动 reuse。

### 4.2 `api.mbt` 残留 debug `println` 引起 `unsafe_substring` 崩溃

**Bug:** `api.mbt` 里 `let sb_key = StringBuilder::new(); ...; sb_key.to_string().unsafe_substring(start=0, end=20)` 这种调用,当 `key.length() < 20` 时直接抛 `Error: FixedArray::blit_from_string`。

**Symptom:** 5 个 blackbox 测试 `Error` 退出(不是干净 assert fail)。

**Fix:** 删掉 `api.mbt` 里的所有 debug `println` (从 12 个降为 0)。`grep -n println api.mbt` 现在 0 命中。

---

## 5. Open Questions / Future Work

1. **Ed25519** — 完整签名算法,基于 X25519 (Loop #4) + SHA-512 (Loop #5) + 签名编码 (clamp, scalar mult, R/S encoding)。RFC 8032。**Loop #7 首选。** 预计 inline SHA-512 + inline 椭圆曲线 (复用 X25519 的曲线层但改 base point)。
2. **DRY 清理** — `src/sha512/` (430 行) + `src/hmac_sha512/sha512_*.mbt` (430 行) + 未来 Ed25519 还会再 inline 一次。**3 份 SHA-512 是 bug 隐患**(改了一处忘改另外两处就不同步)。等 moon 加跨包 import 后立即 refactor。
3. **Side-channel 评估** — MoonBit UInt64 操作大部分 constant-time,但 `if (key.length() > block_size)` 是 length-dependent branch。OpenSSH 协议里 key 长度是公开的(在 wire 里),所以这不构成协议级漏洞。但如果未来用作 KDF 需要 CT 的话,要加 fix-time 长度处理。
4. **C 跑 HMAC-SHA512 1M-byte message** — RFC 4231 没给 KAT 测这个,skip。

---

## 6. 流程统计

| 阶段 | 耗时估计 | 关键产出 |
|------|---------|----------|
| Navigator | 5 min | `navigator-report.md` |
| Architect | 5 min | `architect-design.md` |
| Senior Dev (实现) | 30 min | 11 个 .mbt, ~815 行 (含 inlined SHA-512) |
| Code Reviewer (含 KAT 抄错 fix) | 30 min | Self-debug 发现 6 个 KAT 抄错 + `api.mbt` debug println 残留 |
| API Tester | 15 min | C harness 6/6 + Python cross-check |
| Reality Checker | 10 min | Triple-blind verification complete |
| **Total** | **~95 min** | **11 source files, 17 tests, 5 reports** |

**Loop #6 比 Loop #5 略慢** (~95 min vs 60 min),因为:
1. KAT 抄错教训**又**踩了一遍 (Loop #5 已经踩过, Loop #6 主动忘)
2. debug println 残留 (新坑)
3. SHA-512 inlined (430 行 copy, 不能 link)

**Loop #6 是 5/17 完成中第 6 个**,主要教学价值: **Triple-blind 验证的真正作用不是"再多一个 reference",而是"在 hand-typed reference 出错时自动发现"**。Python 跟 OpenBSD C 都跟 hand-typed expected 不同,**只有它们三个互相一致**才能说明算法对,而不是"我抄了 RFC 应该没问题"。

---

## 7. 下一轮 (Loop #7)

**Loop #7 候选 (按依赖性排序):**

1. **Ed25519** ⭐ 推荐 — 基于 X25519 (Loop #4) + SHA-512 (Loop #5) + SHA-512 (Loop #6 inlined)。RFC 8032 签名算法。需要:
   - Scalar clamping (类似 X25519 但 offset 不同)
   - Point multiplication with base point
   - Signature encoding: `R || s` 64 bytes
   - Verify: `sB == R + [k]A` (cofactored)
   - 预计 ~600 行 .mbt + 2-3 个 RFC 8032 KAT

2. **AES-CTR / AES-GCM** — OpenSSH 多种 cipher 用 (`aes128-ctr`, `aes256-gcm@openssh.com`)。复杂(AES NI / T-table / bitslice 三种实现选择),可以拖到后期。

3. **UMAC / Poly1305-AES** — MAC 算法,Loop #2 Poly1305 是 ChaCha20-Poly1305 用的。已部分覆盖。

4. **ChaCha20-Poly1305 AEAD** — Loop #1 + Loop #2 都有,只是没组合。**简单组合,推荐作为 Loop #7 候选** if Ed25519 太大。

**推荐:** Loop #7 = **Ed25519** (高价值, RFC 8032 主流, 复用 X25519/SHA-512, 单元测试 + 集成测试双层), Loop #8 = **ChaCha20-Poly1305 AEAD 组合** (低风险, 直接合两模块)。

**Loop #6 关闭 — 进入 Loop #7。**

签字: ✅ 2026-07-28
