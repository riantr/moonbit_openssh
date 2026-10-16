///| OpenSSH chacha20-poly1305@openssh.com wire 格式包装

///| 对应 OpenSSH cipher-chachapoly.c

///|

///| 与 RFC 8439 的关键差异:

///|   - 两个独立 32-byte key: K_main(key[0..32)) + K_header(key[32..64))

///|   - IV = 8 字节大端 seqnr(包序号)

///|   - poly_key = ChaCha20(K_main, seqIV, counter=0) 输出的 32 字节

///|   - 4 字节包头用 K_header 加密(counter=0)

///|   - payload 用 K_main 从 counter=1 开始

///|   - MAC 输入 = 密文头 ‖ 密文payload 的原始拼接(无 pad16/长度后缀)

///|
/// 包上下文:两个独立 key
pub struct ChachaPolyCtx {
  priv main_key : FixedArray[Byte] // 32 bytes
  priv header_key : FixedArray[Byte] // 32 bytes
}

///|
/// 从 64 字节 key material 构造(前 32 = main,后 32 = header)
pub fn ChachaPolyCtx::new64(key : FixedArray[Byte]) -> ChachaPolyCtx {
  if key.length() != 64 {
    abort("ChachaPolyCtx::new64: key must be 64 bytes")
  }
  let main_key : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  let header_key : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    main_key[i] = key[i]
    header_key[i] = key[32 + i]
  }
  { main_key, header_key, }
}

///| seqnr → 8 字节大端(对应 C POKE_U64)

///| 注意:必须先提升到 UInt64 再移位——UInt 是 32 位,

///|
/// 移位量会被掩码(&31),>>56 实际是 >>24,产生重复字节。
fn seq_to_be64(seqnr : UInt32) -> FixedArray[Byte] {
  let v : UInt64 = seqnr.to_uint64()
  let buf : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    buf[i] = ((v >> ((7 - i) * 8)) & 0xFFUL).to_byte()
  }
  buf
}

///| 派生 per-packet Poly1305 key:

///|
/// ChaCha20(K_main, iv=seqbuf, counter=0) 处理 32 个零字节
fn chachapoly_poly_key(ctx : ChachaPolyCtx, seqnr : UInt32) -> FixedArray[Byte] {
  let state = ChaChaState::new256(ctx.main_key)
  let with_iv = state.set_iv(seq_to_be64(seqnr), counter=0UL)
  let zeros : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  with_iv.process(zeros)
}

///| chachapoly_crypt 对应实现

///|

///| src 布局:

///|   加密:src[0..aadlen) 包头 ‖ src[aadlen..aadlen+datalen) payload

///|         (协议中 aadlen 恒为 4;tag 尚不存在,由本函数生成)

///|   解密:同上,且 src[aadlen+datalen .. +16) 为待验证 tag

///|

///| do_encrypt=true:  返回 dest = 加密头 ‖ 加密payload ‖ tag(长 body+16)

///| do_encrypt=false: 先验 tag(encrypt-then-MAC),失败返回 None;

///|
///                   成功返回解密后的 头‖payload(长 body,C 的 dest 只写这些)
pub fn ChachaPolyCtx::crypt(
  self : ChachaPolyCtx,
  seqnr : UInt32,
  src : FixedArray[Byte],
  aadlen : Int32,
  datalen : Int32,
  do_encrypt : Bool,
) -> FixedArray[Byte]? {
  let body_len = aadlen + datalen
  if do_encrypt {
    if src.length() < body_len {
      return None
    }
  } else if src.length() < body_len + 16 {
    return None
  }
  let poly_key = chachapoly_poly_key(self, seqnr)

  // ---- 解密路径:先验证 tag(encrypt-then-MAC)----
  // 注意:tag 只依赖密文与 poly_key,与两个 ChaCha key 无关,
  // 所以错误 key 无法通过篡改绕过 MAC——它只会让解密结果变垃圾。
  if !do_encrypt {
    let expect = poly1305_auth(poly_key, src_sub(src, 0, body_len))
    for i = 0; i < 16; i = i + 1 {
      if expect[i] != src[body_len + i] {
        return None
      }
    }
  }

  let out : FixedArray[Byte] = FixedArray::make(
    if do_encrypt {
      body_len + 16
    } else {
      body_len
    },
    b'\x00',
  )

  // ---- 包头:K_header,counter=0 ----
  let hdr_state = ChaChaState::new256(self.header_key)
  let hdr_iv = hdr_state.set_iv(seq_to_be64(seqnr), counter=0UL)
  let hdr_out = hdr_iv.process(src_sub(src, 0, aadlen))
  for i = 0; i < aadlen; i = i + 1 {
    out[i] = hdr_out[i]
  }

  // ---- payload:K_main,counter=1 ----
  let main_state = ChaChaState::new256(self.main_key)
  let main_iv = main_state.set_iv(seq_to_be64(seqnr), counter=1UL)
  let pay_out = main_iv.process(src_sub(src, aadlen, body_len))
  for i = 0; i < datalen; i = i + 1 {
    out[aadlen + i] = pay_out[i]
  }

  // ---- tag ----
  if do_encrypt {
    // 加密:对 out[0..body_len) 计算 tag 并追加
    let tag = poly1305_auth(poly_key, src_sub(out, 0, body_len))
    for i = 0; i < 16; i = i + 1 {
      out[body_len + i] = tag[i]
    }
  }
  Some(out)
}

///|
/// 取 bytes[from..to) 的拷贝(小工具,避免到处手写循环)
fn src_sub(
  bytes : FixedArray[Byte],
  from : Int32,
  to : Int32,
) -> FixedArray[Byte] {
  let n = to - from
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = bytes[from + i]
  }
  arr
}

///|
/// 解密 4 字节包头得到包长(对应 chachapoly_get_length)
pub fn ChachaPolyCtx::get_length(
  self : ChachaPolyCtx,
  seqnr : UInt32,
  hdr_ct : FixedArray[Byte],
) -> UInt32 {
  if hdr_ct.length() < 4 {
    abort("get_length: need at least 4 bytes")
  }
  let state = ChaChaState::new256(self.header_key)
  let with_iv = state.set_iv(seq_to_be64(seqnr), counter=0UL)
  let pt = with_iv.process(hdr_ct)
  // PEEK_U32 大端
  (pt[0].to_uint() << 24) |
  (pt[1].to_uint() << 16) |
  (pt[2].to_uint() << 8) |
  pt[3].to_uint()
}
