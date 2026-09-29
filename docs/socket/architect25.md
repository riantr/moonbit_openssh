# Loop #25 Architect — KEX 完整化：AES cipher + kex-names

**Date**: 2026-09-29
**Status**: Architect 设计 → **Verdict**: G1 = src/aes/cipher.mbt — AES-128/256 + CTR + GCM (FIPS 197 + NIST SP 800-38A/D + RFC 5647); G2 = src/kex_names/algorithms.mbt — algorithm name ↔ enum mapping (RFC 4250 + OpenSSH ext); G3 = cmd/aes_test/ + verify_loop25.mjs — 4 target × 2 mode byte-exact + triple-blind vs OpenSSL EVP

## TL;DR

| 子目标 | 模块 | LOC | 关键产物 |
|---|---|---|---|
| **G1** AES cipher | src/aes/{moon.pkg, cipher.mbt, ghash.mbt} | 680 | AES block + CTR (RFC 4344) + GCM (RFC 5647) |
| **G2** kex-names | src/kex_names/{moon.pkg, algorithms.mbt} | 150 | RFC 4250 + OpenSSH algorithm name mapping |
| **G3** verify | cmd/aes_test/ + verify_c/aes_kat/ + verify_loop25.mjs | 250 | 4 target × 2 mode + OpenSSL EVP reference byte-exact |

## A. G1 — src/aes/cipher.mbt

### A.1 AES block cipher (FIPS 197)

#### A.1.1 S-box (256 字节)
```moonbit
// FIPS 197 §5.1.1 InvSubBytes transformation
const AES_SBOX : FixedArray[Byte] = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  ...
]
```

#### A.1.2 Key schedule (10/12/14 rounds based on key size)
- Nk = 4 (AES-128) / 6 (AES-192) / 8 (AES-256)
- Nr = 10 / 12 / 14
- Nb = 4 (固定)

#### A.1.3 Encrypt single block (16 bytes → 16 bytes)
```
state ← plaintext ⊕ round_keys[0]
for round = 1 to Nr-1:
  SubBytes(state)
  ShiftRows(state)
  MixColumns(state)
  state ⊕ round_keys[round]
SubBytes(state)
ShiftRows(state)
state ⊕ round_keys[Nr]
return state
```

### A.2 AES-CTR (RFC 4344 §4)

```moonbit
pub fn aes_ctr_encrypt(
  key : FixedArray[Byte],    // 16/24/32 bytes
  iv : FixedArray[Byte],     // 16 bytes (RFC 4344: upper 4 bytes fixed + lower 12 bytes counter big-endian)
  plaintext : FixedArray[Byte],
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(plaintext.length(), b'\x00')
  let mut counter = FixedArray::copy(iv)
  let mut off = 0
  while off < plaintext.length() {
    let keystream_block = aes_encrypt_block(key, counter)
    let chunk = if plaintext.length() - off > 16 { 16 } else { plaintext.length() - off }
    for i = 0; i < chunk; i = i + 1 {
      out[off + i] = plaintext[off + i] ^ keystream_block[i]
    }
    // increment counter (last 8 bytes big-endian)
    increment_counter_be(counter, 8)
    off = off + 16
  }
  out
}
```

### A.3 AES-GCM (RFC 5647 + NIST SP 800-38D)

```moonbit
pub fn aes_gcm_encrypt(
  key : FixedArray[Byte],       // 16/32 bytes
  iv : FixedArray[Byte],        // 12 bytes (nonce) + 4 bytes (counter, big-endian)
  aad : FixedArray[Byte],       // additional authenticated data
  plaintext : FixedArray[Byte],
) -> (FixedArray[Byte], FixedArray[Byte]) {  // (ciphertext, tag)
  // 1. H = AES_K(0^128)
  let h = aes_encrypt_block(key, FixedArray::make(16, b'\x00'))
  // 2. J0 = IV || 0^31 || 1 (counter starts at 1)
  let j0 = build_j0(iv)
  // 3. CTR mode encrypt with J0 (counter increments from J0+1)
  let ciphertext = aes_ctr_encrypt_with_j0(key, j0, plaintext)
  // 4. S = GHASH_H(AAD || pad(AAD) || CT || pad(CT) || len(AAD) || len(CT))
  let s = ghash(h, aad, ciphertext)
  // 5. T = S ⊕ AES_K(J0)
  let tag_block = aes_encrypt_block(key, j0)
  let tag = xor(s, tag_block)
  (ciphertext, tag)
}
```

### A.4 GHASH (NIST SP 800-38D §6.3)

```moonbit
fn ghash_mul(x : FixedArray[Byte], y : FixedArray[Byte]) -> FixedArray[Byte] {
  // GF(2^128) multiplication (MSB-first)
  let z = FixedArray::make(16, b'\x00')
  let mut v = FixedArray::copy(y)
  for i = 0; i < 128; i = i + 1 {
    let bit = (x[i / 8].to_uint() >> (7 - i % 8)) & 1U
    if bit == 1U {
      z = xor(z, v)
    }
    let lsb = v[15].to_uint() & 1U
    v = shift_right_1(v)
    if lsb == 1U {
      v[0] = v[0] ^ 0xE1  // reduction polynomial
    }
  }
  z
}
```

### A.5 SSH cipher 集成接口

```moonbit
pub(all) enum SshCipherAlg {
  Chacha20Poly1305OpensshCom  // Loop #19 已有
  Aes128Ctr
  Aes192Ctr
  Aes256Ctr
  Aes128GcmOpensshCom         // RFC 5647
  Aes256GcmOpensshCom
}

pub fn aes_ssh_encrypt(
  alg : SshCipherAlg,
  key : FixedArray[Byte],
  iv : FixedArray[Byte],
  packet_length : UInt32,    // AAD for GCM (4 bytes big-endian)
  plaintext : FixedArray[Byte],
) -> (FixedArray[Byte], FixedArray[Byte]) {
  match alg {
    Aes128Ctr | Aes192Ctr | Aes256Ctr => (aes_ctr_encrypt(key, iv, plaintext), FixedArray::make(0, b'\x00'))
    Aes128GcmOpensshCom | Aes256GcmOpensshCom => aes_gcm_ssh(key, iv, packet_length, plaintext)
  }
}
```

## B. G2 — src/kex_names/algorithms.mbt

### B.1 Algorithm 枚举

```moonbit
pub(all) enum KexAlg {
  Curve25519Sha256
  Curve25519Sha256Libssh
  EcdhSha2Nistp256
  EcdhSha2Nistp384
  EcdhSha2Nistp521
  DhGroup14Sha256
  DhGroupExchangeSha256
  Sntrup761X25519Sha512   // PQ
  Mlkem768X25519          // PQ
}

pub(all) enum HostkeyAlg {
  SshEd25519
  SshRsa
  RsaSha2_256
  RsaSha2_512
  EcdsaSha2Nistp256
  EcdsaSha2Nistp384
  EcdsaSha2Nistp521
  SshDss
}

pub(all) enum CipherAlg {
  Aes128Ctr
  Aes192Ctr
  Aes256Ctr
  Aes128GcmOpensshCom
  Aes256GcmOpensshCom
  Chacha20Poly1305OpensshCom
}

pub(all) enum MacAlg {
  HmacSha2_256
  HmacSha2_512
  HmacSha1
  HmacSha2_256EtmOpensshCom
  HmacSha2_512EtmOpensshCom
}
```

### B.2 Lookup functions

```moonbit
pub fn kex_alg_from_name(name : String) -> KexAlg? {
  match name {
    "curve25519-sha256" => Some(Curve25519Sha256)
    "curve25519-sha256@libssh.org" => Some(Curve25519Sha256Libssh)
    "ecdh-sha2-nistp256" => Some(EcdhSha2Nistp256)
    "ecdh-sha2-nistp384" => Some(EcdhSha2Nistp384)
    "ecdh-sha2-nistp521" => Some(EcdhSha2Nistp521)
    "diffie-hellman-group14-sha256" => Some(DhGroup14Sha256)
    "diffie-hellman-group-exchange-sha256" => Some(DhGroupExchangeSha256)
    _ => None
  }
}

pub fn kex_alg_to_name(alg : KexAlg) -> String {
  match alg {
    Curve25519Sha256 => "curve25519-sha256"
    DhGroup14Sha256 => "diffie-hellman-group14-sha256"
    // ...
  }
}
```

### B.3 Default proposal 扩展

```moonbit
pub fn Proposal::default_client_extended(strict_kex : Bool) -> Proposal {
  let kex = if strict_kex {
    "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,\{KEX_STRICT_MARKER_C}"
  } else {
    "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256"
  }
  {
    kex_algs: kex,
    hostkey_algs: "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-rsa",
    enc_ctos: "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    enc_stoc: "chacha20-poly1305@openssh.com,aes128-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com",
    mac_ctos: "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
    mac_stoc: "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
    comp_ctos: "none",
    comp_stoc: "none",
    lang_ctos: "",
    lang_stoc: "",
  }
}
```

## C. G3 — cmd/aes_test/ + verify_loop25.mjs

### C.1 cmd/aes_test/main.mbt 输出

```
=== SSH-WASM-SSH Loop #25 (AES + kex-names) ===
aes128_ctr_kat: PASS  (NIST SP 800-38A test vector)
aes256_ctr_kat: PASS
aes128_gcm_kat: PASS  (NIST SP 800-38D test vector)
aes256_gcm_kat: PASS
kex_names_count: 9
hostkey_names_count: 7
cipher_names_count: 6
mac_names_count: 5
kex_dh14_lookup: found
kex_dh14_name: diffie-hellman-group14-sha256
cipher_aes256ctr_name: aes256-ctr
hostkey_rsa_name: rsa-sha2-512
```

### C.2 verify_loop25.mjs (4 target × 2 mode)

```js
// 跑 cmd/aes_test 4 target × 2 mode = 8 outputs byte-exact
// 输出 hash + 各 KAT test vector verification
```

### C.3 NIST KAT (verify_c/aes_kat/)

```c
// AES-128-CTR KAT (FIPS 197 + NIST SP 800-38A)
const uint8_t k1[16] = {...};
const uint8_t iv1[16] = {...};
const uint8_t pt1[16] = {...};
const uint8_t ct1[16] = {...};

int main() {
  // 用 OpenSSL EVP_aes_128_ctr
  // 计算 ct, 比对 expected
  // 输出 hex 与 MoonBit 一致
}
```

## D. 验证

### D.1 4 target byte-exact
```
$ node host/verify_loop25.mjs
✓ PASS: 4 target × 2 mode = 8 outputs byte-exact 一致
  + aes128_ctr_kat: PASS
  + aes256_ctr_kat: PASS
  + aes128_gcm_kat: PASS
  + aes256_gcm_kat: PASS
  + kex-names count byte-exact
```

### D.2 Triple-blind (MoonBit vs OpenSSL)
- NIST SP 800-38A CTR test vectors (AES-128/256)
- NIST SP 800-38D GCM test vectors (AES-128/256)
- encrypt + decrypt round-trip

## E. 4 target byte-exact 维持

| 验证 | 维持 hash |
|---|---|
| verify.mjs | 230bfd5b0c02d682 |
| verify_loop22.mjs | 4ac5544049c297cf |
| verify_loop23.mjs | (Node.js ws, no byte-exact hash) |
| verify_loop24.mjs | 7f69fdbe8860a78a |
| verify_loop25.mjs | 新 hash (cmd/aes_test) |

Loop #25 不破 Loop #20/#22/#24 cmd/main 输出（cmd/aes_test 是新 exec 独立路径）。

## F. 时间预算

| 任务 | 预估 |
|---|---|
| G1 AES block + CTR + GCM | 4-5 hours |
| G2 kex-names | 30 min |
| G3 verify + KAT | 1-2 hours |
| Loop #25 5 件套文档 | 30 min |
| 总计 | 6-8 hours |