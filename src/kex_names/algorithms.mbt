///| SSH algorithm enum + name mapping (Loop #25 G2)
///
/// 实现:
///   - KexAlg / HostkeyAlg / CipherAlg / MacAlg / CompAlg 枚举
///   - name ↔ enum lookup 函数
///   - default proposal 构造 (curve25519 + ed25519 + chacha20-poly1305 + aes-ctr/gcm + hmac-sha2-256)

///|
/// KEX 算法 (RFC 4253 + RFC 5656 + RFC 8268 + RFC 8332)
pub(all) enum KexAlg {
  Curve25519Sha256
  Curve25519Sha256Libssh
  EcdhSha2Nistp256
  EcdhSha2Nistp384
  EcdhSha2Nistp521
  DhGroup14Sha256
  DhGroup16Sha512
  DhGroupExchangeSha256
  Sntrup761X25519Sha512
  Mlkem768X25519
  KexStrictCV00
}

///|
/// Host key 算法 (RFC 4253 + RFC 5656 + RFC 8332)
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

///|
/// Cipher 算法 (RFC 4344 + RFC 5647 + OpenSSH ext)
pub(all) enum CipherAlg {
  Aes128Ctr
  Aes192Ctr
  Aes256Ctr
  Aes128GcmOpensshCom
  Aes256GcmOpensshCom
  Chacha20Poly1305OpensshCom
}

///|
/// MAC 算法 (RFC 4253 + RFC 6668 + OpenSSH ext)
pub(all) enum MacAlg {
  HmacSha2_256
  HmacSha2_512
  HmacSha1
  HmacSha2_256EtmOpensshCom
  HmacSha2_512EtmOpensshCom
  HmacSha1EtmOpensshCom
}

///|
/// Compression 算法 (RFC 4253)
pub(all) enum CompAlg {
  None
  ZlibOpensshCom
  Zlib
}

// ============================================================================
// Lookup functions: name → enum
// ============================================================================

///|
/// KEX algorithm name → enum (OpenSSH canonical)
pub fn kex_alg_from_name(name : String) -> KexAlg? {
  if name == "curve25519-sha256" {
    return Some(Curve25519Sha256)
  }
  if name == "curve25519-sha256@libssh.org" {
    return Some(Curve25519Sha256Libssh)
  }
  if name == "ecdh-sha2-nistp256" {
    return Some(EcdhSha2Nistp256)
  }
  if name == "ecdh-sha2-nistp384" {
    return Some(EcdhSha2Nistp384)
  }
  if name == "ecdh-sha2-nistp521" {
    return Some(EcdhSha2Nistp521)
  }
  if name == "diffie-hellman-group14-sha256" {
    return Some(DhGroup14Sha256)
  }
  if name == "diffie-hellman-group16-sha512" {
    return Some(DhGroup16Sha512)
  }
  if name == "diffie-hellman-group-exchange-sha256" {
    return Some(DhGroupExchangeSha256)
  }
  if name == "sntrup761x25519-sha512@openssh.com" {
    return Some(Sntrup761X25519Sha512)
  }
  if name == "mlkem768x25519-sha256" {
    return Some(Mlkem768X25519)
  }
  if name == "kex-strict-c-v00@openssh.com" {
    return Some(KexStrictCV00)
  }
  None
}

///|
/// Host key algorithm name → enum
pub fn hostkey_alg_from_name(name : String) -> HostkeyAlg? {
  if name == "ssh-ed25519" {
    return Some(SshEd25519)
  }
  if name == "ssh-rsa" {
    return Some(SshRsa)
  }
  if name == "rsa-sha2-256" {
    return Some(RsaSha2_256)
  }
  if name == "rsa-sha2-512" {
    return Some(RsaSha2_512)
  }
  if name == "ecdsa-sha2-nistp256" {
    return Some(EcdsaSha2Nistp256)
  }
  if name == "ecdsa-sha2-nistp384" {
    return Some(EcdsaSha2Nistp384)
  }
  if name == "ecdsa-sha2-nistp521" {
    return Some(EcdsaSha2Nistp521)
  }
  if name == "ssh-dss" {
    return Some(SshDss)
  }
  None
}

///|
/// Cipher algorithm name → enum
pub fn cipher_alg_from_name(name : String) -> CipherAlg? {
  if name == "aes128-ctr" {
    return Some(Aes128Ctr)
  }
  if name == "aes192-ctr" {
    return Some(Aes192Ctr)
  }
  if name == "aes256-ctr" {
    return Some(Aes256Ctr)
  }
  if name == "aes128-gcm@openssh.com" {
    return Some(Aes128GcmOpensshCom)
  }
  if name == "aes256-gcm@openssh.com" {
    return Some(Aes256GcmOpensshCom)
  }
  if name == "chacha20-poly1305@openssh.com" {
    return Some(Chacha20Poly1305OpensshCom)
  }
  None
}

///|
/// MAC algorithm name → enum
pub fn mac_alg_from_name(name : String) -> MacAlg? {
  if name == "hmac-sha2-256" {
    return Some(HmacSha2_256)
  }
  if name == "hmac-sha2-512" {
    return Some(HmacSha2_512)
  }
  if name == "hmac-sha1" {
    return Some(HmacSha1)
  }
  if name == "hmac-sha2-256-etm@openssh.com" {
    return Some(HmacSha2_256EtmOpensshCom)
  }
  if name == "hmac-sha2-512-etm@openssh.com" {
    return Some(HmacSha2_512EtmOpensshCom)
  }
  if name == "hmac-sha1-etm@openssh.com" {
    return Some(HmacSha1EtmOpensshCom)
  }
  None
}

// ============================================================================
// Reverse lookup: enum → name
// ============================================================================

///|
pub fn kex_alg_to_name(alg : KexAlg) -> String {
  match alg {
    Curve25519Sha256 => "curve25519-sha256"
    Curve25519Sha256Libssh => "curve25519-sha256@libssh.org"
    EcdhSha2Nistp256 => "ecdh-sha2-nistp256"
    EcdhSha2Nistp384 => "ecdh-sha2-nistp384"
    EcdhSha2Nistp521 => "ecdh-sha2-nistp521"
    DhGroup14Sha256 => "diffie-hellman-group14-sha256"
    DhGroup16Sha512 => "diffie-hellman-group16-sha512"
    DhGroupExchangeSha256 => "diffie-hellman-group-exchange-sha256"
    Sntrup761X25519Sha512 => "sntrup761x25519-sha512@openssh.com"
    Mlkem768X25519 => "mlkem768x25519-sha256"
    KexStrictCV00 => "kex-strict-c-v00@openssh.com"
  }
}

///|
pub fn hostkey_alg_to_name(alg : HostkeyAlg) -> String {
  match alg {
    SshEd25519 => "ssh-ed25519"
    SshRsa => "ssh-rsa"
    RsaSha2_256 => "rsa-sha2-256"
    RsaSha2_512 => "rsa-sha2-512"
    EcdsaSha2Nistp256 => "ecdsa-sha2-nistp256"
    EcdsaSha2Nistp384 => "ecdsa-sha2-nistp384"
    EcdsaSha2Nistp521 => "ecdsa-sha2-nistp521"
    SshDss => "ssh-dss"
  }
}

///|
pub fn cipher_alg_to_name(alg : CipherAlg) -> String {
  match alg {
    Aes128Ctr => "aes128-ctr"
    Aes192Ctr => "aes192-ctr"
    Aes256Ctr => "aes256-ctr"
    Aes128GcmOpensshCom => "aes128-gcm@openssh.com"
    Aes256GcmOpensshCom => "aes256-gcm@openssh.com"
    Chacha20Poly1305OpensshCom => "chacha20-poly1305@openssh.com"
  }
}

// ============================================================================
// Default proposal lists -- REMOVED in Loop #60
// ============================================================================
//
// `kex_algs_default` / `hostkey_algs_default` / `cipher_algs_default` /
// `mac_algs_default` used to live here. Nothing imported them (the same
// finding as Loop #57's orphan-package inventory, which is what surfaced this
// file as a third source of truth for algorithm names). They were four
// proposals for a client that does not exist: of the six ciphers named here,
// exactly one, `aes128-ctr`, has a `Mode` branch in `src/bpacket`; of the six
// MACs, exactly one, `hmac-sha2-256`. The two GCM ciphers are the sharpest
// case -- `src/aes` really does implement AES-GCM, so "the name resolves" and
// "the transport runs it" look identical from the outside.
//
// They were deleted rather than trimmed to the runnable names because a
// hand-copied list is the defect, not the length of the list. The runnable set
// now has exactly one home: `src/bpacket::runnable_cipher_names` /
// `runnable_mac_names`, with `@bpacket.check_runnable` as the gate over it.
//
// The name <-> enum mapping above stays: it is a spelling table, it is used by
// `cmd/aes_test`, and it makes no claim about what can be executed.

// ============================================================================
// Algorithm counts (for kex-names coverage tests)
// ============================================================================

///|
pub fn kex_alg_count() -> Int32 {
  11
}

///|
pub fn hostkey_alg_count() -> Int32 {
  8
}

///|
pub fn cipher_alg_count() -> Int32 {
  6
}

///|
pub fn mac_alg_count() -> Int32 {
  6
}
