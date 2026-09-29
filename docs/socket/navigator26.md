# Loop #26 Navigator — BigInt 库 + DH group 14 KEX

**Date**: 2026-09-29
**Status**: Navigator 调研中 → **Verdict**: 三件大事：(1) G1 src/bigint/ — 256/2048-bit BigInt + Montgomery mod exp (DH/RSA/ECDSA 基础); (2) G2 src/kexdh/exchange.mbt — DH group 14 KEX (RFC 3526 + RFC 4253 §8); (3) G3 cmd/bigint_test/ + cmd/kexdh_test/ + verify_loop26.mjs — 4 target × 2 mode + Python int reference byte-exact

## TL;DR

| 子目标 | 路径 | 状态 |
|---|---|---|
| **G1** BigInt 库 | FixedArray[UInt64] + Montgomery modular multiplication + 256/2048-bit | 可行 (~500 行) |
| **G2** DH group 14 KEX | RFC 3526 group 14 (2048-bit MODP) + RFC 4253 §8 SSH-DH-SHA256 | 可行 (~300 行) |
| **G3** 验证 | 4 target × 2 mode byte-exact + Python int reference KAT | 可行 (~150 行) |
| 4 target byte-exact 维持 | 不破 verify.mjs/loop22/loop24/loop25 | 维持 |

## A. Loop #26 范围决策

### A.1 选定 BigInt + DH group 14
- BigInt 是 RSA/ECDSA/DH 共同基础
- DH group 14 = 2048-bit MODP,RFC 3526 group 14
- RFC 4253 §8 SSH-DH-SHA256 protocol
- 用户目标 "围绕让 SSH 客户端在浏览器零依赖跑" + "默认从零实现加密算法"

### A.2 不在 Loop #26 范围（已确认）
- RSA host key verify + sign (BigInt 复用，Loop #27+)
- ECDSA host key verify + sign (EC arithmetic, Loop #27+)
- DH group 16/18 (更复杂, Loop #27+)
- ECDH KEX (EC arithmetic, Loop #27+)
- AEAD 加密层回包验证 (Loop #28+)

## B. BigInt 库架构

### B.1 表示法
- FixedArray[UInt64] limbs (little-endian word order, RFC 3447 PKCS#1 v1.5 convention)
- 支持 64-bit words
- 256-bit = 4 limbs (用于 ECDSA P-256)
- 2048-bit = 32 limbs (用于 DH group 14, RSA-2048)

### B.2 基础操作
- 比较 (cmp)
- 加减 (add, sub)
- 乘法 (mul): O(n^2) schoolbook
- Montgomery modular multiplication: O(n^2) for n limbs

### B.3 算法
- Montgomery modular multiplication (MRED)
- Montgomery modular exponentiation (binary exponentiation with MRED)
- Barrett reduction (可选)

### B.4 SSH wire format: mpint
RFC 4251 §5:
- mpint: u32 length + bytes
- Leading zero byte (0x00) if MSB of magnitude is set (to keep positive)
- 0 represented as empty string (length=0)

## C. DH group 14 KEX (RFC 4253 §8)

### C.1 RFC 3526 group 14 (2048-bit MODP)
- Generator g = 2
- Prime p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
  - Exact value: p starts with FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08 8A67CC74 ...
  - End: ... 93AD1CA6 9F45D3AC 8094D5B0 ... (last bytes 1F47BCE4 E33D89B3 8B9B1B3E 7CC1AD2E FFFFFFFFFFFFFFFF)

### C.2 RFC 4253 §8 SSH-DH-SHA256 protocol
1. Client → Server: SSH_MSG_KEXDH_INIT (0x1e) || string e (client DH public key mpint)
3. Server → Client: SSH_MSG_KEXDH_REPLY (0x1f) || hostkey_blob || string f (server DH public key mpint) || signature
4. Client computes K = f^x mod p (where x is client's private key, e = g^x mod p)

### C.3 Shared secret K encoding (mpint)
- K is encoded as mpint (RFC 4253 §8: "K is encoded as mpint and concatenated")
- If K has leading zero byte, prepend extra 0x00

### C.4 Exchange hash H
H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
- V_C, V_S: version strings (RFC 4253 §8: without trailing \r\n)
- I_C, I_S: KEXINIT payloads (full payloads, including msg_type 0x14)
- K_S: server host key blob
- e, f: client/server DH public values (mpint encoded)
- K: shared secret (mpint encoded)

## D. 测试策略

### D.1 BigInt KAT
- 加减乘法 vs Python int
- Montgomery modular multiplication vs Python pow(a, b, p)
- Big exponentiation (e.g. pow(2, 1024, prime)) vs Python pow

### D.2 DH group 14 KAT
- e = pow(2, x, p) vs Python
- f = pow(2, y, p) vs Python
- K = pow(f, x, p) vs Python
- K == pow(e, y, p) (一致性)
- exchange hash H = SHA-256(...) vs Python

### D.3 byte-exact vs OpenSSL EVP_PKEY_derive
- OpenSSL DH_compute_key(f, x, g, p) ≡ K (验证 K)

## E. 工作量估算

| 任务 | 预估 |
|---|---|
| G1 BigInt library | 4-5 hours |
| G2 DH group 14 KEX | 2-3 hours |
| G3 verify + KAT | 1-2 hours |
| Loop #26 5 件套文档 | 30 min |
| 总计 | 7-10 hours |

## F. 决策点（已确认）

### F1: BigInt limb 大小
- A: 32-bit limbs (4 bytes, 64 个 limbs for 2048-bit) — 选定
- B: 64-bit limbs (8 bytes, 32 个 limbs for 2048-bit)
- C: 8-bit limbs (256 个 limbs for 2048-bit)

64-bit limbs 在 MoonBit 是 UInt64 (原生支持),性能好。

### F2: DH group 14 KAT
- A: 自己生成 KAT (deterministic x, y + SHA-256 exchange hash vs Python hashlib) — 选定
- B: 用 OpenSSL CLI 生成 KAT

### F3: BigInt API 命名
- A: 仿 GMP 命名 (mpz_*) — 选定
- B: 仿 Python (BigInt + methods)

默认选 A+A+A。