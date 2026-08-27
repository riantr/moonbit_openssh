///| Curve25519 共享密钥计算(对应 OpenSSH kexc25519.c)

///|
/// RFC 7748 basepoint 9(每次新分配,避免共享可变状态)
fn curve25519_basepoint() -> FixedArray[Byte] {
  let bp : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  bp[0] = b'\x09'
  bp
}

///| 对应 kexc25519_keygen(kexc25519.c:50):

///| e = X25519(scalar, basepoint9)。

///| 标量由调用方提供——C 里是 arc4random_buf,随机源属集成层职责,

///|
/// 本层保持确定性以便测试。
pub fn c25519_keygen(scalar : FixedArray[Byte]) -> FixedArray[Byte] {
  x25519(scalar, curve25519_basepoint())
}

///| 对应 kexc25519_shared_key_ext 的 raw 路径(kexc25519.c:59):

///| ss = X25519(priv, pub);全零 → None(C: SSH_ERR_KEY_INVALID_EC_VALUE)。

///|
/// 全零检查对应 C 的 timingsafe_bcmp(zero, shared_key, 32)。
pub fn c25519_shared_key_raw(
  privk : FixedArray[Byte],
  pubk : FixedArray[Byte],
) -> FixedArray[Byte]? {
  let ss = x25519(privk, pubk)
  let mut all_zero = true
  for i = 0; i < 32; i = i + 1 {
    if ss[i] != b'\x00' {
      all_zero = false
    }
  }
  if all_zero {
    return None
  }
  Some(ss)
}

///| 对应 kexc25519_shared_key(raw=0 默认路径,kexc25519.c:85):

///|
/// 共享密钥以 mpint 编码进输出(供 exchange hash 与 KDF 直接使用)。
pub fn c25519_shared_key_mpint(
  privk : FixedArray[Byte],
  pubk : FixedArray[Byte],
) -> FixedArray[Byte]? {
  match c25519_shared_key_raw(privk, pubk) {
    Some(ss) => Some(kx_mpint(ss))
    None => None
  }
}
