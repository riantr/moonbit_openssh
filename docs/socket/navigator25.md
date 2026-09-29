# Loop #25 Navigator — KEX 完整化（AES + DH group 14 + kex-names）

**Date**: 2026-09-29
**Status**: Navigator 调研中 → **Verdict**: 三件大事：(1) G1 src/aes/cipher.mbt — AES-128/256 block + CTR + GCM (RFC 5647); (2) G2 src/kex_names/algorithms.mbt — kex/cipher/mac algorithm name ↔ ID mapping (RFC 4250); (3) G3 src/kexdh/exchange.mbt — DH group 14 KEX (RFC 3526 group 14 + RFC 4253 §8)

## TL;DR

| 子目标 | 路径 | 状态 |
|---|---|---|
| **G1** AES-128/256 + CTR + GCM | FIPS 197 + NIST SP 800-38A/D + RFC 5647 | 可行 (~500 行) |
| **G2** kex-names algorithm mapping | RFC 4250 + OpenSSH ext (kex-names.c) | 可行 (~150 行) |
| **G3** DH group 14 KEX | RFC 4253 §8 + RFC 3526 group 14 | 可行 (~400 行 + BigInt) |
| 4 target byte-exact 维持 | 不破 verify.mjs/loop22/loop23/loop24 | 维持 |

## A. Loop #25 范围决策

### A.1 选定范围（user 明确要求）
User: "开始推#25 KEX完整化(AES+RSA+ECDH) + Host key 完整（ECDSA+RSA）"

但实际工作量超出单 Loop：
- AES-CTR + AES-GCM cipher: ~500 行
- RSA verify (BigInt + PKCS#1 v1.5): ~600 行
- ECDSA verify + sign: ~800 行 + BigInt
- ECDH KEX: ~300 行 + EC arithmetic
- DH group 14 KEX: ~400 行 + BigInt

**Loop #25 优先完成 G1 + G2 + G3**（AES + kex-names + DH group 14）：
- AES 替换 chacha20-poly1305 作为可协商 cipher
- kex-names 让现有 proposal.mbt 协商支持完整 algorithm set
- DH group 14 KEX 是 RFC 4253 §8 标准之一（OpenSSH 默认支持之一）

**Loop #26+ 后续**:
- RSA verify + sign + key encoding (BigInt)
- ECDSA verify + sign + key encoding (BigInt + EC arithmetic)
- ECDH P-256/384/521 KEX

## B. 算法背景

#### B.1 AES block cipher (FIPS 197)
- 128-bit block size
- Key size: 128 / 192 / 256 bits
- 10 / 12 / 14 rounds (key-size dependent)
- 4 round functions: SubBytes (S-box), ShiftRows, MixColumns, AddRoundKey
- Key schedule: Nk-round key expansion

#### B.2 AES-CTR (NIST SP 800-38A §6.5)
- Counter mode: cipher_block(counter + nonce) XOR plaintext
- Counter increment: last byte (little-endian) — OpenSSH convention
- IV format: SSH wire uint64 (高 4 bytes 不用,低 4 bytes counter) + nonce = 8 bytes total
  - Actually OpenSSH AES-CTR iv: 16 bytes initial counter = upper 4 bytes fixed + lower 12 bytes counter (big-endian)
  - Reference: RFC 4344 §4 (SSH CTR mode) — counter = upper 4 bytes + lower 12 bytes (big-endian)
- No padding, output = input length

#### B.3 AES-GCM (NIST SP 800-38D)
- AEAD = encrypt + auth tag (16 bytes default)
- GHASH: multiplication in GF(2^128)
- IV: 12 bytes default (OpenSSH AES-GCM IV = 12 bytes nonce + 4 bytes counter)
- AAD (associated data): OpenSSH convention = 4 bytes packet_length (RFC 5647 §7)

#### B.4 RFC 5647 SSH AES-GCM AEAD
- packet_length (4 bytes) | encrypted_payload (block_size-1 aligned) | tag (16 bytes)
- IV (nonce): 12 bytes explicit nonce + 4 bytes invocation counter (incrementing from 1)
- AAD: packet_length (4 bytes)
- Block size: 16 bytes (AES)

## C. AES-CTR/GCM 实现策略

### C.1 moon.mod 无 AES 包
- 不能用现成库,需从零实现
- OpenSSH kexnames.c + cipher.c 是参考实现
- byte-exact: 用 OpenSSL EVP_aes_256_ctr / EVP_aes_256_gcm 做 reference (Python `cryptography` 库作 harness)

### C.2 算法性能
- AES-128 ~200 cycles/block (MoonBit 解释执行会更慢)
- 对 SSH 实际 I/O 吞吐(几十 KB/s) 性能足够

## D. kex-names 范围

### D.1 RFC 4250 §4.11.2 + OpenSSH extension list
- KEX: curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256/384/521, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha256, diffie-hellman-group16-sha512, etc.
- Hostkey: ssh-ed25519, ecdsa-sha2-nistp256/384/521, ssh-rsa, rsa-sha2-256/512, ssh-dss
- Cipher: aes128-ctr, aes192-ctr, aes256-ctr, aes128-gcm@openssh.com, aes256-gcm@openssh.com, chacha20-poly1305@openssh.com
- MAC: hmac-sha2-256, hmac-sha2-512, hmac-sha1, hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com
- Compression: none, zlib@openssh.com

### D.2 name → ID mapping (RFC 4250)
- "curve25519-sha256" → 0x00 (curve25519-sha256@libssh.org)
- "ssh-ed25519" → "ssh-ed25519" (key encoding only, not algorithm ID)
- KEX 没有 wire format algorithm ID — KEXINIT 提议是 name list

### D.3 实际产出
- algorithm name 规范化（trim + 内部 enum）
- lookup 函数:given name → enum variant
- reverse lookup:enum → name
- 全 algorithm list (供 proposal.mbt default 扩展)

## E. DH group 14 KEX

### E.1 RFC 3526 group 14 (2048-bit MODP)
- Prime p = 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }
- Generator g = 2
- Order q = (p - 1) / 2

### E.2 RFC 4253 §8 KEXDH_SHA256 protocol
1. Client → Server: SSH_MSG_KEXDH_INIT (e = g^x mod p)
2. Server → Client: SSH_MSG_KEXDH_REPLY (hostkey_blob + f = g^y mod p + signature)
3. Shared secret K = f^x mod p = e^y mod p

### E.3 BigInt mod exp
- MoonBit 没有 BigInt 原生类型
- 需要自己实现 256-bit / 512-bit / 2048-bit 整数
- Montgomery multiplication (高效 mod exp)
- 工作量 ~300 行 (2048-bit + Montgomery)

### E.4 RFC 4253 §8 exchange hash H = SHA-256(V_C || V_S || I_C || I_S || K_S || e || f || K)
- V_C, V_S: version strings
- I_C, I_S: KEXINIT payloads
- K_S: host key blob
- e, f: DH values
- K: shared secret (mpint encoding)

## F. 工作量估算

| 任务 | 预估 |
|---|---|
| G1 AES-CTR | 250 行 (block cipher + key schedule + CTR) |
| G1 AES-GCM | 200 行 (GHASH + counter + tag) |
| G1 cipher API | 100 行 |
| G1 triple-blind verify | 50 行 MoonBit + 100 行 C reference |
| G2 kex-names | 150 行 |
| G3 BigInt library | 250 行 (uint256 + uint2048) |
| G3 DH mod exp | 150 行 (Montgomery) |
| G3 KEXDH_SHA256 protocol | 200 行 |
| G3 triple-blind verify | 50 行 MoonBit + 100 行 C reference |
| Loop #25 5 件套文档 | 30 min |
| 总计 | ~1500 行 MoonBit + 200 行 C reference |

预估总时长: 5-8 hours (实操时间)

## G. 决策点（待用户确认）

### G1: AES-CTR/GCM 实现 vs RFC 5647
- A: 从零实现 AES + CTR + GCM (~500 行 MoonBit, byte-exact vs OpenSSL EVP) — 选定
- B: 用 mizchi/rsa 等第三方包 (MoonBit 生态不成熟,可能不兼容)
- C: 留 Loop #26+, Loop #25 只做 kex-names + DH group 14

### G2: kex-names 范围
- A: 完整 OpenSSH algorithm list (~30 algorithms) — 选定
- B: 只覆盖现有 proposal.mbt 用的 algorithms (curve25519-sha256 + ssh-ed25519 + chacha20-poly1305)

### G3: DH group 14 vs ECDH P-256
- A: DH group 14 (2048-bit MODP, RFC 3526 + RFC 4253 §8) — 选定
- B: ECDH P-256 (NIST P-256, RFC 5656) — 需要 EC arithmetic
- C: 两者都做

默认选 A+A+A（最一致）。