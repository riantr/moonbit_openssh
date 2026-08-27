# Loop #8 ChaCha20-Poly1305 AEAD — Reality Checker Report

**Date:** 2026-08-25
**Role:** 🔍 Reality Checker
**Scope:** Independent triple-blind verification — does MoonBit ChaCha20-Poly1305 produce output identical to two unrelated reference implementations, on both the RFC 8439 core and the OpenSSH wire wrapper?

---

## 1. Verification Policy

`moon prove` (Why3) remains unavailable on Windows (Loops #1–#7 history), so Loop #8 ships under the established **triple-blind** policy — with a structural upgrade for this loop: **two independent verification layers**, each anchored differently.

| Blind | Implementation | Independence |
|-------|----------------|--------------|
| 1 | **MoonBit** (`src/aead/`, from-scratch) | Under test |
| 2a | **Python `cryptography` 44.0.1** (`ChaCha20Poly1305` AEAD + raw `ChaCha20` cipher) | Completely different codebase; anchors RFC 8439 core AND emulates OpenSSH wire format |
| 2b | **OpenSSH C originals**: `cipher-chachapoly.c` v1.10 + `chacha.c` + `poly1305.c`, compiled unmodified (only include lines remapped) | Different language, same source lineage as target; anchors wire layer byte-exactly |
| 2c | RFC 8439 § 2.8.2 known answer values (ct first block `d31a8d34…`, tag `1ae10b59…`) | Spec-level anchor confirming all three sides interpret the vector identically |

Key structural point: OpenSSH's `chacha.c` is Bernstein-layout only (8-byte IV), so it cannot natively exercise the IETF 12-byte-nonce construction. The C harness therefore builds the IETF state **directly in `struct chacha_ctx`'s public `input[16]`** (sigma‖key‖ctr32‖nonce96) and drives djb's original block function through it — giving Layer 1 real C coverage instead of skipping it.

Acceptance: all three must agree **byte-exact** on every positive vector and agree on rejection for every tampered input.

---

## 2. Expected-Value Provenance (Loop #5/#6 rule)

All expected values were **computed by `verify_c/aead_python_ref.py`**, never hand-copied:

1. Inline Poly1305 self-check against `cryptography.Poly1305` ✓
2. RFC 8439 emulation self-check against `cryptography.ChaCha20Poly1305.encrypt()` — **this caught the counter off-by-one before any other consumer saw the vectors** ✓
3. Roundtrip + tamper self-tests inside the reference itself ✓
4. Only then vectors emitted to MoonBit tests and C harness

Vector inputs shared by all three sides:

| Vector | Inputs |
|--------|--------|
| A1 (KAT) | key=80…9f, nonce=070000004041424344454647, aad=50515253c0c1c2c3c4c5c6c7, pt=sunscreen 名句(114B) |
| A2/A3/A4 | 同 key/nonce;aad 空 / pt 空 / 双空 |
| B1 | seqnr=0x00000000, header=deadbeef, payload="hello chachapoly wrapper!"(25B) |
| B2 | seqnr=0x11223344, header=00000100, payload=100B 模式(i*7+11,跨 64B 块边界) |
| B3 | seqnr=0xffffffff, header=0000001c, payload=41414141(最小) |
| 共享 key64 | bytes 0x00..0x3F |

---

## 3. Layer 1 — RFC 8439 Core AEAD

### Positive agreement

| Check | MoonBit | Python | OpenSSH C (IETF state via chacha.c) |
|-------|---------|--------|-------------------------------------|
| A1 ct (114B) = `d31a8d34…64b6116` | ✅ | ✅ (= library) | ✅ |
| A1 tag = `1ae10b594f09e26a7e902ecbd0600691` | ✅ | ✅ | ✅ |
| A1 decrypt → pt | ✅ | ✅ | ✅ |
| A2 empty-aad tag = `6a23a468…` | ✅ | ✅ (= library) | ✅ |
| A3 empty-pt tag = `e622e564…` | ✅ | ✅ (= library) | ✅ |
| A4 empty-both tag = `a0784d7a…` | ✅ | ✅ (= library) | ✅ |
| Multi-block roundtrip 0..129B (MoonBit 内部) | ✅ | — | — |

Note: Python side is doubly anchored here — our emulation must equal `cryptography`'s output **and** the well-known § 2.8.2 values. Both held.

### Negative agreement (rejection)

| Scenario | MoonBit | OpenSSH C | Python |
|----------|---------|-----------|--------|
| Tampered ciphertext rejected | ✅ None | ✅ tag mismatch | ✅ None |
| Tampered tag rejected | ✅ None | ✅ tag mismatch | ✅ None |
| Wrong key / wrong nonce / wrong aad | ✅ None ×3 | — | ✅ (self-test) |
| Truncated input (<16B) | ✅ None | n/a | — |

---

## 4. Layer 2 — OpenSSH wire wrapper (`chacha20-poly1305@openssh.com`)

### Positive agreement — wrapped packet byte-exact across all three sides

| Vector | Wrapped output (hdr_ct ‖ pay_ct ‖ tag) | M=C=P? |
|--------|----------------------------------------|--------|
| B1 seq=0, hdr=deadbeef | `4ae8b0b670dd2e5d…fb` (45B) | ✅ |
| B2 seq=11223344, hdr=00000100, 100B payload | `9e19c7b7d7d64788…64f` (120B) | ✅ |
| B3 seq=ffffffff, hdr=0000001c | `b90ee4ac48d34dda…a2c` (24B) | ✅ |

B2 is the critical one: payload crosses the 64-byte block boundary **and** seqnr exercises all four bytes of the BE64 IV encoding.

### get_length agreement

| Case | MoonBit | OpenSSH C |
|------|---------|-----------|
| B1 hdr_ct `4ae8b0b6` @seq=0 | `0xdeadbeef` | `0xdeadbeef` |
| B2 hdr_ct `9e19c7b7` @seq=11223344 | `0x00000100` | `0x00000100` |
| B3 hdr_ct `b90ee4ac` @seq=ffffffff | `0x0000001c` | `0x0000001c` |

### Negative agreement

| Scenario | MoonBit | OpenSSH C |
|----------|---------|-----------|
| Tampered payload byte | ✅ None | ✅ `SSH_ERR_MAC_INVALID` |
| Tampered last tag byte | ✅ None | ✅ `SSH_ERR_MAC_INVALID` |
| Wrong seqnr at decrypt | ✅ None | ✅ `SSH_ERR_MAC_INVALID` |
| Short buffer (tag incomplete) | ✅ None | (C reads caller-sized buffers; guard differs) |
| **Corrupted header_key** (key[63]) | MAC still passes, payload correct, header garbage — **locked by test** as protocol property | Same behavior by construction (encrypt-then-MAC) |

The corrupted-header-key row deserves emphasis: both implementations agree that MAC validity is **independent of both ChaCha keys**, so key corruption manifests as garbage plaintext after successful tag verification, never as a MAC failure. This is faithful encrypt-then-MAC semantics, now pinned by `wrapper_wrong_header_key_still_decrypts_payload`.

---

## 5. Command Transcripts

```
# MoonBit
PS> moon check          # clean, 0 warnings
PS> moon test           # Total tests: 154, passed: 154, failed: 0
    (+ moon fmt / moon info 后复跑仍 154/154)

# Python reference
PS> python verify_c\aead_python_ref.py
    [self-check] inline poly1305 == cryptography.Poly1305 : OK
    [self-check] RFC8439 emulation == cryptography.ChaCha20Poly1305 : OK
    === ALL SELF-CHECKS PASSED ===        exit 0

# C harness (OpenSSH originals)
PS> verify_c\build_aead.bat     # gcc -O2 -Wall, BUILD OK, no warnings
    --- Section A: RFC 8439 core ... 8 PASS
    --- Section B: cipher-chachapoly.c wrapper ... 18 PASS
    === ALL PASS (fails=0) ===            exit 0
```

Exit codes verified via `Start-Process -PassThru`(PowerShell stderr 合流下 `$LASTEXITCODE` 不可靠的老坑,沿用既定规避法)。

---

## 6. Residual Risks & Deviations (documented, non-blocking)

1. **Vartime tag compare**(MoonBit)— 与 C `timingsafe_bcmp` 的已知差异,Reviewer 报告 § 3 论证不构成实际攻击面。
2. **abort vs 错误码**:`new64`/`get_length` 对 API 误用 abort,C 返回 NULL/SSH_ERR_MESSAGE_INCOMPLETE。协议路径失败一律 Option/None,已映射锁定。
3. **Counter 回绕**:RFC 8439 层 32-bit counter 回绕由调用者保证(MoonBit 注释 + C harness 同约束);OpenSSH wrapper 层 seqnr 是 u32,与 C 完全一致。
4. **DRY 债务**:本包含 chacha 第 2 份、poly1305 第 2 份 inline 拷贝(SHA-512 已 3 份)。等 moon 支持跨包 import 后应收敛。
5. **未覆盖**:>2^32 字节单包(协议不可能)、并发 ctx 复用(C 无此语义,MoonBit 结构体每次 crypt 全新建 state,天然安全)。

---

## 7. Verdict

**PASS_OVERALL** — 双层架构在三个独立实现上字节级一致,负向行为全部对齐,期望值溯源链完整(Python 自检先行 → 向量分发 → 三方消费)。Loop #8 可以关闭。

建议下一环(Loop #9):Curve25519 kex 完整流程(curve25519-sha256@libssh.org,把 Loop #4 的 X25519 接上 hash 与 wire 格式)或 RSA sshkey wire 解析层。前者延续三盲验证优势,后者补齐 key 格式栈。
