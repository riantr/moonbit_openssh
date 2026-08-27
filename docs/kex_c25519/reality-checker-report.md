# Loop #9 Curve25519 KEX — Reality Checker Report

**Date:** 2026-08-25
**Role:** 🔍 Reality Checker
**Scope:** Independent triple-blind verification — does MoonBit curve25519-sha256@libssh.org KEX core produce byte-identical results to two unrelated references across shared secret, mpint encoding, exchange hash, and session key derivation?

---

## 1. Verification Policy

`moon prove` (Why3) remains unavailable on Windows (Loops #1–#8 history). Loop #9 ships under the established triple-blind policy, with a **four-layer evidence chain**:

| Blind | Implementation | Independence |
|-------|----------------|--------------|
| 1 | **MoonBit** (`src/kexc25519/`, from-scratch assembly of proven parts + new wire/hash/KDF code) | Under test |
| 2 | **Python**: `cryptography` (X25519 primitive + Ed25519 signing) + hand-built wire/hash/KDF following C source line-by-line | Different language, different test path |
| 3 | **OpenSSH C originals** in one TU: `smult_curve25519_ref.c` (scalarmult), **real `sshbuf_put_bignum2_bytes`** (mpint), `sha2.c` (digest) | Same lineage as target, different implementation path |
| Anchor | RFC 7748 §6.1 Alice/Bob vectors; kexgen.c/kex.c transcriptions annotated with line numbers | Spec-level |

Key structural facts:
- The mpint comparison runs against the **real OpenSSH function**, not a reimplementation.
- The exchange-hash input assembly in C is a **transcription** of static `kex_gen_hash` (kexgen.c:48–96) because that function drags sshkey/sshpkt dependencies; every field operation maps 1:1 onto real sshbuf calls (`sshbuf_put_string/u32/u8/put`).
- Same for `derive_key` (kex.c:1069–1118): formula transcribed, digest via real sha2.c.

Acceptance: byte-exact agreement on shared secrets (both mpint branches), exchange hash H, and all six derived keys; rejection agreement on the all-zero path.

---

## 2. Expected-Value Provenance

All expected values computed by `verify_c/kex_c25519_python_ref.py`:

1. X25519 self-check against `cryptography` ✓ (RFC 7748 §6.1 pair)
2. mpint branch coverage enforced by assertion: A1 ss starts 0x4a (**no-prepend**), A2 searches a fixed clamped scalar giving ss starting 0xb7 (**prepend**) ✓
3. I_C mutation self-check: flipping one bit must change H ✓
4. Vectors emitted only after all self-checks passed

Fixed inputs shared by all three sides: RFC 7748 scalars; V_C=`SSH-2.0-MoonBitPort_1.0\r\n`; V_S=`SSH-2.0-OpenSSH_10.0\r\n`; realistic I_C/I_S kexinit payloads (curve25519-sha256 / ssh-ed25519,ssh-rsa / chachapoly,aes-*); self-made ssh-ed25519 K_S blob; we_need=64.

---

## 3. Agreement Matrix

### Section A — shared secret & mpint

| Check | MoonBit | Python | OpenSSH C |
|-------|---------|--------|-----------|
| keygen e = X25519(sk, 9) = RFC7748 pk | ✅ | ✅ | ✅ |
| ss_raw (Alice×Bob, both directions) | ✅ `4a5d9d5b…` | ✅ | ✅ |
| mpint no-prepend branch | ✅ `00000020 4a…` | ✅ | ✅ (**real put_bignum2_bytes**) |
| mpint prepend branch (A2) | ✅ `00000021 00b7…` | ✅ | ✅ |
| leading-zero collapse + empty/all-zero → u32(0) | ✅ (wbtest) | ✅ | ✅ |
| zero pub → REJECT | ✅ None | ✅ library-level reject | ✅ computes zero then rejects |

Note on A3: three implementations agree on the *conclusion* (REJECT) but the rejection layer differs for Python (point validation) vs MoonBit/C (all-zero output check). Documented, not a defect.

### Section B — exchange hash & KDF

| Check | MoonBit | Python | OpenSSH C |
|-------|---------|--------|-----------|
| H = SHA256(exchange input) | ✅ `2cbabe0f…22d5f` | ✅ | ✅ (real sshbuf + sha2.c) |
| fake header len+1 semantics | ✅ (wbtest layout) | ✅ | ✅ |
| I_C bit-flip sensitivity | ✅ H changes | ✅ self-check | n/a (same input path as H) |
| session_id == first H | ✅ | ✅ | ✅ (kex.c:1143 semantics) |
| iv/enc/mac × ctos/stoc (we_need=64) | ✅ ×6 | ✅ ×6 | ✅ ×6 |
| KDF chain expansion prefix stability | ✅ (wbtest) | ✅ | ✅ |

### Section C — reply parsing & signature form

| Check | MoonBit | Python |
|-------|---------|--------|
| parse_reply(valid wire) → K_S/f/sig 三段正确拆出 | ✅ | ✅ generated |
| parse_reply(truncated / trailing garbage / Q_S≠32B) → reject | ✅ ×3 | n/a |
| parse_sig(ssh-ed25519 blob) → rs == cryptography 签名原文 | ✅ | ✅ |
| parse_sig(rs=63B) → reject;非 ed25519 alg 非 64B rs → reject | ✅ | n/a |

**Signature crypto verification delegation**: the actual Ed25519 verify over H is performed by `src/ed25519` at integration time (Loop #7: triple-blind verified, 120/120). Evidence chain: cryptography signs H → sig blob bytes match MoonBit's parsed rs → Loop #7 proves verify(r,s,H) correctness. The glue obligation is annotated in `client.mbt`.

---

## 4. Command Transcripts

```
# MoonBit
PS> moon check          # clean
PS> moon test           # Total tests: 173, passed: 173, failed: 0  (+fmt/info 复测同)

# Python reference
PS> python verify_c\kex_c25519_python_ref.py
    [self-check] X25519 == cryptography : OK
    [self-check] I_C mutation changes H : OK
    === ALL SELF-CHECKS PASSED ===            exit 0

# C harness
PS> verify_c\build_kex.bat      # BUILD OK
    --- Section A: scalarmult + mpint ... 10 PASS
    --- Section B: exchange hash + KDF ... 7 PASS
    === ALL PASS (fails=0) ===                exit 0
```

Exit codes verified via `Start-Process -PassThru`(既定规避法)。

---

## 5. Residual Risks & Deviations (documented, non-blocking)

1. **kex_gen_hash / derive_key 在 C 侧是转写而非原函数**——原函数静态且依赖 sshkey/sshpkt。缓解:字段操作全部落在真实 sshbuf 调用上,公式逐行对照源码并标注行号;三方字节一致。
2. **sig 验证接线义务**(见 §3)——集成层必须调用 src/ed25519.verify(rs, H),否则证据链断裂。
3. **随机源未实现**——c25519_keygen 标量注入式设计;生产需 CSPRNG。
4. **we_need 为参数**——真实值由 cipher 选路决定(chachapoly 场景典型 64),选路逻辑属未来传输层。
5. **rekey 场景**——derive_keys_with_session 已保留 API 形态,C 的 KEX_INITIAL 状态机不在本卷。
6. **DRY 债务**:x25519 第 2 份、sha256 第 2 份 inline。

---

## 6. Verdict

**PASS_OVERALL** — 四层证据链闭环:共享密钥(RFC 7748 锚点)、mpint(真实 OpenSSH 函数)、交换哈希与六个会话密钥(三方字节一致)、签名形态(Python 签名 ↔ 解析字节)。负向路径全对齐。Loop #9 可以关闭。

Loop 进度 **9/17**(核心循环)。下一环候选:**SSH transport 包装层**(binary packet protocol:BNE2 包格式 + 本卷密钥接上 Loop #8 AEAD 加解密)或 **RSA sshkey 解析**。
