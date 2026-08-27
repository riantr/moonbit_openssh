# Loop #8 Summary — ChaCha20-Poly1305 AEAD

**Closed:** 2026-08-25
**Status:** ✅ COMPLETE — 154/154 MoonBit tests, C harness 26/26 PASS (exit 0), triple-blind byte-exact (MoonBit ⊕ OpenSSH C ⊕ Python cryptography)

---

## 1. What we built

从零实现的 **ChaCha20-Poly1305 AEAD**,对应 OpenSSH 的 `chacha20-poly1305@openssh.com`——当前 SSH 传输层的默认加密算法。本卷采用**双层架构**,每层独立验证:

- **Layer 1 — RFC 8439 核心 AEAD**(`rfc8439.mbt`):12 字节 nonce 的 IETF 标准构造,可三盲验证(Python cryptography 原生支持 + C harness 手工构造 IETF state)
- **Layer 2 — OpenSSH wire 包装**(`ssh_wire.mbt`):双 key、BE64 seqnr、counter 0/0/1 的 @openssh.com 特化格式,C harness 直接跑原版 `cipher-chachapoly.c` 锁定

### 1.1 Source files (`src/aead/`)

```
src/aead/
├── moon.pkg
├── chacha_*.mbt × 4      (~12 KB) ChaCha20 inline 拷贝 #2(自 src/chacha/)
├── poly1305_*.mbt × 6    (~13 KB) Poly1305 inline 拷贝 #2(自 src/poly1305/,poly_ 前缀防撞名)
├── rfc8439.mbt           (5.4 KB) IETF state 构造 + aead_encrypt/decrypt(Option)
├── ssh_wire.mbt          (5.2 KB) ChachaPolyCtx::new64/crypt/get_length
├── aead_test.mbt         (15 KB)  24 blackbox(KAT + 边界 + 负向 + wrapper 三向量)
└── aead_wbtest.mbt       (6 KB)   10 whitebox(state/mac_data 布局逐字节)
```

### 1.2 Verification artifacts

```
verify_c/
├── aead_python_ref.py        # 参考生成器:cryptography 交叉自检 → 输出 A/B 组向量
├── _aead_ref_out.txt         # 向量输出(MoonBit/C 测试的期望值来源)
├── aead_harness.c            # 单 TU:chacha.c + poly1305.c + cipher-chachapoly 原版
├── aead_chachapoly_ref.c     # OpenSSH v1.10 拷贝,仅 include 重映射(脚本生成)
├── aead_ssh_compat.h         # POKE_U64/PEEK_U32/timingsafe_bcmp/freezero stub
├── poly1305.c/.h             # 自 openssh-C 拷入
├── aead_kat.exe              # 26/26 PASS, exit 0
└── build_aead.bat
```

### 1.3 关键语义(C ↔ MoonBit 对应)

| C(cipher-chachapoly.c) | MoonBit |
|---|---|
| `POKE_U64(seqbuf, seqnr)` | `seq_to_be64`(UInt64 域移位)|
| `chacha_ivsetup(main, seqbuf, NULL)` + encrypt 32 零字节 | `ChaChaState::new256(main).set_iv(be64, counter=0UL).process(zeros)` |
| header: `ivsetup(header_ctx, seqbuf, NULL)` ctr=0 | `new256(header_key).set_iv(be64, 0UL)` |
| payload: `ivsetup(main_ctx, seqbuf, one)` ctr=1 | `new256(main_key).set_iv(be64, 1UL)` |
| 解密先 `poly1305_auth` 验 tag 再动任何解密 | 同序,失败 None |
| MAC 输入 = 密文头‖密文payload 裸拼接 | 无 pad16 / 无长度后缀(与 RFC 8439 层相反!) |

RFC 8439 层与 wire 层的三点差异(易混点,测试已双向锁定):
1. state 布局:IETF [12]=32bit ctr + [13..16)=12B nonce vs Bernstein [12..14)=64bit ctr + [14..16)=8B IV → **不能复用 set_iv**
2. MAC 输入:IETF 有 pad16 + LE64 长度尾;OpenSSH 是裸拼接
3. poly_key:IETF 取 block(counter=0) 前 32B;OpenSSH 用 K_main 对 IV=seqbuf ctr=0 加密零字节——数值上同为"首块",但 key/nonce 语义不同

---

## 2. Key Technical Decisions

### 2.1 双层架构的验证经济学

Architect 把可三盲验证的 RFC 8439 核心与只有 OpenSSH 有的 wire 包装分开。结果:
- 核心 bug(off-by-one)被 Python 库在**向量生成阶段**就抓住,没进过任何实现
- wire 层的三个 wrapped 向量由 Python 模拟(OpenSSL raw ChaCha20 16B-IV 形式映射回 64-bit counter + BE64 IV)与 C 原版**双向**锁定——Navigator 报告原本判断"wrapper 仅 C 可验",实际做到了三方盲验

### 2.2 C harness 直接操纵 `struct chacha_ctx.input[16]`

OpenSSH 的 chacha.c 不支持 IETF 12B nonce。harness 利用其公开的 state 结构体手工填 sigma‖key‖ctr32‖nonce96,再走原版块函数——不改动一行 OpenSSH 代码,同时拿到 Layer 1 的 C 侧覆盖。

### 2.3 期望值溯源链(Loop #5/#6 规则的完整实践)

Python 脚本先自检(poly1305 内联实现对 cryptography;RFC 模拟对库 AEAD)→ 通过后才产出向量 → 分发给 MoonBit 测试与 C harness。全程零手抄,tag/ct 全部机器生成。

---

## 3. Bugs Found & Fixed(详见 reviewer-report)

| # | 级别 | Bug | 捕获者 |
|---|------|-----|--------|
| 1 | 🔴 | RFC 8439 counter off-by-one:pk=block(1)/payload=block(2),应为 0/1 | Python self-check(生成阶段) |
| 2 | 🔴 | `seq_to_be64` UInt 移位回绕:`>>56` 实为 `>>24`,BE64 高位重复 | wbtest 字节断言 |
| 3 | 🟡 | crypt 长度检查未分方向:加密路径误要求 +16 → 恒 None | blackbox wrapper 测试 |
| 4 | 🟡 | decrypt 返回布局多拷了 tag(与 C dest 语义不符) | b1_decrypt 断言 |
| 5 | 🟢 | wrong-key 测试改错字节(header_key 不影响 MAC——协议性质非 bug) | 结果分析 |
| 6 | 🟢 | Python 参考脚本 Poly1305 漏 update 就 finalize | 脚本自检 |

**跨卷规律第三次命中:整数域移位宽度**(Loop #4 X25519 → Loop #7 ge_equal_i8 → 本轮 seq_to_be64)。规则升级:凡翻译 C 移位,先确认 MoonBit 目标域宽;修一处 grep 同域全部同类。

---

## 4. Verification Matrix

| 维度 | 结果 |
|------|------|
| `moon check` | clean(0 warnings) |
| `moon test` | **154/154**(新增 34 = 24 blackbox + 10 whitebox) |
| `moon fmt` / `moon info` | 已跑,fmt 后复测仍 154/154 |
| Python ref | ALL SELF-CHECKS PASSED(exit 0) |
| C harness | **26/26 PASS**(A 组 8 + B 组 18),exit 0,-Wall 无警告 |
| KAT 锚点 | ct 首块 d31a8d34… / tag 1ae10b59… 与 RFC § 2.8.2 一致 |
| 负向行为 | 三方在篡改/错 seqnr 上全部拒绝对齐 |

---

## 5. Lessons(沉淀到范式库候选)

1. **"第一块"歧义**:Bernstein 与 IETF 惯例里 poly_key 都来自"第一个 keystream block",但 counter 起点/语义不同。跨变体写代码时 counter 必须回到 spec 原文核对。
2. **移位宽度三连**:同一类 bug 在三卷反复出现,说明它不是笔误而是**语言语义差异的系统性陷阱**——MoonBit 移位量按目标域宽取模,C 整型提升后移位。应进 paradigm_kb。
3. **encrypt-then-MAC 的可测性质**:改 header_key 不影响 MAC——把它写成正向测试锁住,防止后人把"错误行为"修成"正确行为"。
4. **方向性 API 校验**:同一函数处理加/解密两个方向时,输入长度约束可能不同;统一检查会静默杀死一个方向(本轮加密路径恒 None)。
5. **参考脚本先行自检**:参考实现自己先跟权威库对齐,再产出期望值——错误在源头就被拦截,下游两个消费者全部受益。

---

## 6. Loop 进度

**Loop #8 完成,进度 8/17**(核心循环)。已完成:ChaCha20、Poly1305、HMAC-SHA256、X25519、SHA-512、HMAC-SHA512、Ed25519、AEAD。

**Loop #9 候选**(待用户确认):
- **Curve25519 kex 完整流程**(`curve25519-sha256@libssh.org`):Loop #4 X25519 接 hash + wire 编码,kexinit→exchange→confirm 全流程,延续三盲优势
- **RSA sshkey wire 解析层**:ssh-rsa 公钥格式 PEM/Packet 解析,补 key 格式栈,为 hostkey 验证铺路
