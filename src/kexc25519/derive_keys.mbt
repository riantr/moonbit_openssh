///| 会话密钥派生(对应 kex.c:1069 derive_key 与 kex.c:1134 kex_derive_keys)

///|

///| K1 = HASH( mpint_K ‖ H ‖ letter ‖ session_id )

///| Kn = HASH( mpint_K ‖ H ‖ K1‖…‖Kn-1 )     ← 注意扩展阶段无 session_id

///| 输出取前 need 字节。

///| 6 密钥:A/B=IV(c→s/s→c) C/D=加密 E/F=MAC;session_id = 首次 kex 的 H。

///|
/// SHA-256 摘要长度
const KX_DIGEST_LEN : Int = 32

///|
/// 单密钥派生(kex.c derive_key 完整对应,含链式扩展)
pub fn derive_single(
  letter : Byte,
  need : Int,
  hash : FixedArray[Byte],
  shared_secret_mpint : FixedArray[Byte],
  session_id : FixedArray[Byte],
) -> FixedArray[Byte] {
  // 承载 ROUNDUP(need,32) 字节的中间缓冲
  let blocks = (need + KX_DIGEST_LEN - 1) / KX_DIGEST_LEN
  let digest : FixedArray[Byte] = FixedArray::make(
    blocks * KX_DIGEST_LEN,
    b'\x00',
  )
  // K1 = HASH(K ‖ H ‖ letter ‖ session_id)
  let b1 = KxBuf::new()
  b1.put_bytes(shared_secret_mpint)
  b1.put_bytes(hash)
  b1.put_u8(letter.to_uint())
  b1.put_bytes(session_id)
  let d1 = sha256(b1.to_bytes())
  for i = 0; i < KX_DIGEST_LEN; i = i + 1 {
    digest[i] = d1[i]
  }
  let mut have = KX_DIGEST_LEN
  // Kn = HASH(K ‖ H ‖ digest[0..have))——无 session_id
  while have < need {
    let bn = KxBuf::new()
    bn.put_bytes(shared_secret_mpint)
    bn.put_bytes(hash)
    for i = 0; i < have; i = i + 1 {
      bn.put_u8(digest[i].to_uint())
    }
    let dn = sha256(bn.to_bytes())
    for i = 0; i < KX_DIGEST_LEN; i = i + 1 {
      digest[have + i] = dn[i]
    }
    have = have + KX_DIGEST_LEN
  }
  // 截取前 need 字节
  let out : FixedArray[Byte] = FixedArray::make(need, b'\x00')
  for i = 0; i < need; i = i + 1 {
    out[i] = digest[i]
  }
  out
}

///|
/// 六密钥集(session_id 取首次 kex 的 H,kex.c:1143)
pub struct DerivedKeys {
  session_id : FixedArray[Byte]
  iv_ctos : FixedArray[Byte] // 'A'
  iv_stoc : FixedArray[Byte] // 'B'
  enc_key_ctos : FixedArray[Byte] // 'C'
  enc_key_stoc : FixedArray[Byte] // 'D'
  mac_key_ctos : FixedArray[Byte] // 'E'
  mac_key_stoc : FixedArray[Byte] // 'F'
}

///|
/// 派生全部会话密钥
pub fn derive_keys(
  hash : FixedArray[Byte],
  shared_secret_mpint : FixedArray[Byte],
  we_need : Int,
) -> DerivedKeys {
  let sid = hash // 首次 kex:session_id = H(C 里拷贝进 buf,值等价)
  DerivedKeys::derive_keys_with_session(hash, shared_secret_mpint, we_need, sid)
}

///|
/// rekey 场景:session_id 复用旧值(C 里 kex->session_id 已存在时)
pub fn DerivedKeys::derive_keys_with_session(
  hash : FixedArray[Byte],
  shared_secret_mpint : FixedArray[Byte],
  we_need : Int,
  session_id : FixedArray[Byte],
) -> DerivedKeys {
  {
    session_id,
    iv_ctos: derive_single(b'A', we_need, hash, shared_secret_mpint, session_id),
    iv_stoc: derive_single(b'B', we_need, hash, shared_secret_mpint, session_id),
    enc_key_ctos: derive_single(
      b'C', we_need, hash, shared_secret_mpint, session_id,
    ),
    enc_key_stoc: derive_single(
      b'D', we_need, hash, shared_secret_mpint, session_id,
    ),
    mac_key_ctos: derive_single(
      b'E', we_need, hash, shared_secret_mpint, session_id,
    ),
    mac_key_stoc: derive_single(
      b'F', we_need, hash, shared_secret_mpint, session_id,
    ),
  }
}

// ---------------------------------------------------------------------------
// 只读访问器
// ---------------------------------------------------------------------------

///|
/// 字段保持私有,外部只能通过这些访问器取密钥。
///
/// 不是洁癖:DerivedKeys 里装的是**已经能解密整条连接**的会话密钥,把它变成
/// 到处可随手序列化的公开字段,等于在一个打印结构体的调试语句旁边埋一次泄漏。

///|
/// 'A' —— 客户端→服务器的计数器/IV
pub fn DerivedKeys::iv_ctos(self : DerivedKeys) -> FixedArray[Byte] {
  self.iv_ctos
}

///|
/// 'B' —— 服务器→客户端的计数器/IV
pub fn DerivedKeys::iv_stoc(self : DerivedKeys) -> FixedArray[Byte] {
  self.iv_stoc
}

///|
/// 'C' —— 客户端→服务器的加密密钥
pub fn DerivedKeys::enc_key_ctos(self : DerivedKeys) -> FixedArray[Byte] {
  self.enc_key_ctos
}

///|
/// 'D' —— 服务器→客户端的加密密钥
pub fn DerivedKeys::enc_key_stoc(self : DerivedKeys) -> FixedArray[Byte] {
  self.enc_key_stoc
}

///|
/// 'E' —— 客户端→服务器的 MAC 密钥
pub fn DerivedKeys::mac_key_ctos(self : DerivedKeys) -> FixedArray[Byte] {
  self.mac_key_ctos
}

///|
/// 'F' —— 服务器→客户端的 MAC 密钥
pub fn DerivedKeys::mac_key_stoc(self : DerivedKeys) -> FixedArray[Byte] {
  self.mac_key_stoc
}

///|
/// 首次 KEX 的 H,重连时复用(kex.c:1137-1146)
pub fn DerivedKeys::session_id(self : DerivedKeys) -> FixedArray[Byte] {
  self.session_id
}
