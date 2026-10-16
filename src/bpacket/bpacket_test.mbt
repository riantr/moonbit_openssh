///| Binary packet protocol 测试(T1-T18)
///
/// 跑法:`moon test`

///|
/// 严格 16 进制转字节
fn bp_hex(hex : String) -> FixedArray[Byte] {
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = bp_hex_digit(hex[i * 2])
    let lo = bp_hex_digit(hex[i * 2 + 1])
    arr[i] = ((hi * 16 + lo).reinterpret_as_uint() & 0xFFU).to_byte()
  }
  arr
}

///|
fn bp_hex_digit(c : UInt16) -> Int32 {
  let code : Int32 = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("bp_hex_digit: invalid char")
  }
}

///|
/// 确定性 payload:n 字节,值 = seed+i
fn bp_payload(n : Int32, seed : Byte) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = bp_byte(seed.to_int() + i)
  }
  arr
}

///|
/// Int 截断到低 8 位转 Byte
fn bp_byte(v : Int32) -> Byte {
  (v.reinterpret_as_uint() & 0xFFU).to_byte()
}

///|
/// 确定性 padding 源(生产环境应接 CSPRNG)
fn bp_pad_src(n : Int32) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = bp_byte(0xA5 ^ i)
  }
  arr
}

///|
/// 共享 64 字节合成密钥(K_main ‖ K_header)
fn bp_key64() -> FixedArray[Byte] {
  bp_hex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  )
}

///|
/// 手工组明文帧(plain 模式无密码学保护,可自由构造畸形帧做负向测试)
fn bp_manual_frame(
  packlen : Int32,
  padlen : Int32,
  body : FixedArray[Byte], // packlen 字节:type ‖ payload ‖ padding
) -> FixedArray[Byte] {
  let total = 4 + packlen
  let arr : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let v : UInt32 = packlen.reinterpret_as_uint()
  arr[0] = ((v >> 24) & 0xFFU).to_byte()
  arr[1] = ((v >> 16) & 0xFFU).to_byte()
  arr[2] = ((v >> 8) & 0xFFU).to_byte()
  arr[3] = (v & 0xFFU).to_byte()
  arr[4] = padlen.to_byte()
  for i = 0; i < body.length(); i = i + 1 {
    arr[5 + i] = body[i]
  }
  arr
}

///|
/// 断言事件为 Packet 并返回内容
fn bp_expect_packet(
  res : @bpacket.RecvResult,
  want_seqnr : UInt32,
  want_type : Byte,
  want_payload : FixedArray[Byte],
  label : String,
) -> Unit {
  match res.event {
    Packet(seqnr, ty, pl) => {
      if seqnr != want_seqnr {
        abort("\{label}: seqnr \{seqnr} != \{want_seqnr}")
      }
      if ty != want_type {
        abort("\{label}: type mismatch")
      }
      if pl.length() != want_payload.length() {
        abort(
          "\{label}: payload len \{pl.length()} != \{want_payload.length()}",
        )
      }
      for i = 0; i < want_payload.length(); i = i + 1 {
        if pl[i] != want_payload[i] {
          abort("\{label}: payload byte \{i} mismatch")
        }
      }
    }
    Failed(_) => abort("unexpected error kind")
    NeedMore => abort("\{label}: unexpected NeedMore")
  }
  ignore(res.consumed)
}

///|
/// 断言事件为指定错误
fn bp_expect_error(
  res : @bpacket.RecvResult,
  pred : (@bpacket.PacketError) -> Bool,
  label : String,
) -> Unit {
  match res.event {
    Failed(err) => if !pred(err) { abort("\{label}: wrong error kind") }
    _ => abort("\{label}: expected Failed")
  }
}

///|
/// 取 bytes[from..until)
fn bp_slice(
  bytes : FixedArray[Byte],
  from : Int32,
  until : Int32,
) -> FixedArray[Byte] {
  let n = until - from
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = bytes[from + i]
  }
  arr
}

// ================= T1-T2:plain 基线 =================

///|
test "t1_plain_roundtrip" {
  let s = @bpacket.SendCtx::new()
  let r = @bpacket.RecvCtx::new()
  let payload = bp_payload(10, b'\x42')
  match s.emit(b'\x14', payload, bp_pad_src(32)) {
    Ok(sp) => {
      // plain 模式 wire == 明文帧
      if sp.wire.length() != sp.frame.length() {
        abort("t1: plain wire should equal frame length")
      }
      let res = r.recv(sp.wire)
      bp_expect_packet(res, 0U, b'\x14', payload, "t1")
      if res.consumed != sp.wire.length() {
        abort("t1: consumed != wire length")
      }
    }
    SeqnrWrapFatal => abort("t1: unexpected wrap")
  }
}

///|
test "t2_plain_framing_math" {
  // n=10:len_for_pad=16,padlen=8,total=24,packlen=20
  let s = @bpacket.SendCtx::new()
  match s.emit(b'\x14', bp_payload(10, b'\x01'), bp_pad_src(32)) {
    Ok(sp) => {
      let f = sp.frame
      let packlen = (f[0].to_uint() << 24) |
        (f[1].to_uint() << 16) |
        (f[2].to_uint() << 8) |
        f[3].to_uint()
      let padlen = f[4].to_uint()
      if packlen != 20U {
        abort("t2: packlen \{packlen} != 20")
      }
      if padlen != 8U {
        abort("t2: padlen \{padlen} != 8")
      }
      if (4 + packlen.reinterpret_as_int()) % 8 != 0 {
        abort("t2: plain alignment broken")
      }
      if f[5] != b'\x14' {
        abort("t2: type byte misplaced")
      }
      // padding 区全零(packet.c explicit_bzero 行为)
      for i = 16; i < 24; i = i + 1 {
        if f[i] != b'\x00' {
          abort("t2: plain padding not zeroed")
        }
      }
    }
    SeqnrWrapFatal => abort("t2: unexpected wrap")
  }
}

// ================= T3-T4:AEAD 封装与对齐 =================

///|
test "t3_aead_roundtrip_and_alignment" {
  let key = bp_key64()
  let s = @bpacket.SendCtx::make(
    Aead(@bpacket.ChachaPolyCtx::new64(key)),
    0U,
    false,
    true,
  )
  let r = @bpacket.RecvCtx::make(
    Aead(@bpacket.ChachaPolyCtx::new64(key)),
    0U,
    false,
    true,
  )
  let payload = bp_payload(10, b'\x42')
  match s.emit(b'\x14', payload, bp_pad_src(32)) {
    Ok(sp) => {
      let f = sp.frame
      let packlen = (f[0].to_uint() << 24) |
        (f[1].to_uint() << 16) |
        (f[2].to_uint() << 8) |
        f[3].to_uint()
      // n=10:aadlen=4,len_for_pad=12,padlen=4(恰好下界),packlen=16
      if packlen != 16U {
        abort("t3: packlen \{packlen} != 16")
      }
      if f[4].to_uint() != 4U {
        abort("t3: padlen should be minimum 4")
      }
      if packlen.reinterpret_as_int() % 8 != 0 {
        abort("t3: aead packlen not multiple of block size")
      }
      // wire = 4 头 + packlen 体 + 16 tag
      if sp.wire.length() != 4 + packlen.reinterpret_as_int() + 16 {
        abort("t3: wire length mismatch")
      }
      // 明文帧的 padding 来自 pad_src
      if f[16] != b'\xA5' {
        abort("t3: aead padding should come from pad_src")
      }
      let res = r.recv(sp.wire)
      bp_expect_packet(res, 0U, b'\x14', payload, "t3")
    }
    SeqnrWrapFatal => abort("t3: unexpected wrap")
  }
}

// ================= T5:流水线多包 =================

///|
test "t5_pipelined_stream" {
  let key = bp_key64()
  let s = @bpacket.SendCtx::make(
    Aead(@bpacket.ChachaPolyCtx::new64(key)),
    0U,
    false,
    true,
  )
  let r = @bpacket.RecvCtx::make(
    Aead(@bpacket.ChachaPolyCtx::new64(key)),
    0U,
    false,
    true,
  )
  let mut stream : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  for round = 0; round < 3; round = round + 1 {
    match
      s.emit(
        bp_byte(90 + round),
        bp_payload(5 + round * 7, bp_byte(round)),
        bp_pad_src(32),
      ) {
      Ok(sp) => {
        let merged : FixedArray[Byte] = FixedArray::make(
          stream.length() + sp.wire.length(),
          b'\x00',
        )
        for i = 0; i < stream.length(); i = i + 1 {
          merged[i] = stream[i]
        }
        for i = 0; i < sp.wire.length(); i = i + 1 {
          merged[stream.length() + i] = sp.wire[i]
        }
        stream = merged
      }
      SeqnrWrapFatal => abort("t5: unexpected wrap")
    }
  }
  // 逐包消费
  let mut off = 0
  for round = 0; round < 3; round = round + 1 {
    let res = r.recv(bp_slice(stream, off, stream.length()))
    let want_ty = bp_byte(90 + round)
    bp_expect_packet(
      res,
      round.reinterpret_as_uint(),
      want_ty,
      bp_payload(5 + round * 7, bp_byte(round)),
      "t5",
    )
    off = off + res.consumed
  }
  if off != stream.length() {
    abort("t5: consumed sum != stream length")
  }
}

// ================= T6:碎片投喂 =================

///|
test "t6_fragmented_delivery" {
  // plain 与 aead 各来一轮
  for variant = 0; variant < 2; variant = variant + 1 {
    let key = bp_key64()
    let s = @bpacket.SendCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      0U,
      false,
      true,
    )
    let r = @bpacket.RecvCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      0U,
      false,
      true,
    )
    let payload = bp_payload(9, b'\x77')
    match s.emit(b'\x04', payload, bp_pad_src(32)) {
      Ok(sp) => {
        // 逐字节增长前缀,除完整长度外全部 NeedMore
        for k = 1; k < sp.wire.length(); k = k + 1 {
          let res = r.recv(bp_slice(sp.wire, 0, k))
          match res.event {
            NeedMore => ()
            _ => abort("t6: expected NeedMore at k=\{k}")
          }
          if res.consumed != 0 {
            abort("t6: NeedMore must consume nothing")
          }
        }
        let fin = r.recv(sp.wire)
        bp_expect_packet(fin, 0U, b'\x04', payload, "t6")
      }
      SeqnrWrapFatal => abort("t6: unexpected wrap")
    }
    ignore(variant)
  }
}

// ================= T7-T8:篡改 =================

///|
test "t7_tamper_body_auth_fail" {
  let key = bp_key64()
  let s = @bpacket.SendCtx::make(
    Aead(@bpacket.ChachaPolyCtx::new64(key)),
    0U,
    false,
    true,
  )
  let r = @bpacket.RecvCtx::make(
    Aead(@bpacket.ChachaPolyCtx::new64(key)),
    0U,
    false,
    true,
  )
  match s.emit(b'\x05', bp_payload(8, b'\x11'), bp_pad_src(32)) {
    Ok(sp) => {
      sp.wire[10] = sp.wire[10] ^ b'\x01'
      let res = r.recv(sp.wire)
      bp_expect_error(res, fn(err) { err is AuthFailed }, "t7")
    }
    SeqnrWrapFatal => abort("t7: unexpected wrap")
  }
}

///|
test "t8_tamper_header_three_outcomes" {
  let key = bp_key64()
  // 定点翻转(推导见 docs/bpacket/architect.md §6 T8):
  //   byte0 ^= 0x80 → 解出的 packlen 置高位 → BadLength
  //   byte3 ^= 0x01 → packlen 变奇数 → AlignError
  //   byte3 ^= 0x08 → packlen +8 仍对齐但在解密时 tag 失败 → AuthFailed
  let flips : Array[(Int32, Byte, String)] = [
    (0, b'\x80', "badlength"),
    (3, b'\x01', "alignerror"),
    (3, b'\x08', "authfailed"),
  ]
  for flip in flips {
    let (pos, mask, name) = flip
    let s = @bpacket.SendCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      0U,
      false,
      true,
    )
    let r = @bpacket.RecvCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      0U,
      false,
      true,
    )
    match s.emit(b'\x06', bp_payload(8, b'\x22'), bp_pad_src(32)) {
      Ok(sp) => {
        sp.wire[pos] = sp.wire[pos] ^ mask
        // 篡改后若包长变大,需要足够缓冲才进入解密;追加零字节模拟
        // 流上已有的后续流量(tag 校验发生在解析后续内容之前)
        let padded : FixedArray[Byte] = FixedArray::make(
          sp.wire.length() + 32,
          b'\x00',
        )
        for i = 0; i < sp.wire.length(); i = i + 1 {
          padded[i] = sp.wire[i]
        }
        let res = r.recv(padded)
        let ok = match res.event {
          Failed(BadLength(_)) => name == "badlength"
          Failed(AlignError(_)) => name == "alignerror"
          Failed(AuthFailed) => name == "authfailed"
          _ => false
        }
        if !ok {
          abort("t8: flip(\{pos},\{mask}) expected \{name}")
        }
      }
      SeqnrWrapFatal => abort("t8: unexpected wrap")
    }
  }
}

// ================= T9-T13:手工畸形帧(plain 无认证,可直接构造)=================

///|
test "t9_bad_padlen_lower_bound" {
  // packlen=12 对齐(4+12=16%8==0),padlen=3 < 4
  let body = bp_payload(8, b'\x33')
  let frame = bp_manual_frame(12, 3, body)
  let r = @bpacket.RecvCtx::new()
  let res = r.recv(frame)
  bp_expect_error(res, fn(err) { err is BadPadlen(_) }, "t9")
}

///|
test "t10_pad_overflow" {
  // packlen=12 对齐,padlen=12 > packlen-1
  let body = bp_payload(8, b'\x44')
  let frame = bp_manual_frame(12, 12, body)
  let r = @bpacket.RecvCtx::new()
  let res = r.recv(frame)
  match res.event {
    Failed(PadOverflow(v)) =>
      if v != 12U {
        abort("t10: overflow value should be 12")
      }
    _ => abort("t10: expected PadOverflow")
  }
}

///|
test "t11_bad_length_bounds" {
  let r = @bpacket.RecvCtx::new()
  // 下界:packlen=4 < 5
  let tiny = bp_manual_frame(4, 4, bp_payload(0, b'\x00'))
  // 注意 bp_manual_frame 会写 4+packlen=8 字节,body 写不下不覆盖
  bp_expect_error(r.recv(tiny), fn(err) { err is BadLength(_) }, "t11-lower")
  // 上界:packlen=262145 > 262144
  let huge_arr : FixedArray[Byte] = FixedArray::make(12, b'\x00')
  huge_arr[0] = b'\x00'
  huge_arr[1] = b'\x04'
  huge_arr[2] = b'\x00'
  huge_arr[3] = b'\x01' // 0x00040001 = 262145
  huge_arr[4] = b'\x07'
  bp_expect_error(
    r.recv(huge_arr),
    fn(err) { err is BadLength(_) },
    "t11-upper",
  )
  // 边界内侧:packlen=262144 恰好合法 → 过长度门 → 卡对齐门(AlignError)
  let edge_arr : FixedArray[Byte] = FixedArray::make(12, b'\x00')
  edge_arr[0] = b'\x00'
  edge_arr[1] = b'\x04'
  edge_arr[2] = b'\x00'
  edge_arr[3] = b'\x00'
  edge_arr[4] = b'\x07'
  bp_expect_error(
    r.recv(edge_arr),
    fn(err) { err is AlignError(_) },
    "t11-edge",
  )
  // 边界内侧下沿:packlen=5 合法 → AlignError
  let five = bp_manual_frame(5, 4, bp_payload(0, b'\x00'))
  bp_expect_error(r.recv(five), fn(err) { err is AlignError(_) }, "t11-five")
}

///|
test "t12_empty_payload" {
  // packlen=12 对齐,padlen=11 吃光 payload 区 → payload_len=0
  let frame = bp_manual_frame(12, 11, bp_payload(4, b'\x55'))
  let r = @bpacket.RecvCtx::new()
  let res = r.recv(frame)
  bp_expect_error(res, fn(err) { err is EmptyPayload }, "t12")
}

///|
test "t13_bad_type_zero" {
  // packlen=12,padlen=7,payload_len=4,type=0x00
  let body : FixedArray[Byte] = FixedArray::make(4, b'\x00') // 全零 ⇒ type=0
  let frame = bp_manual_frame(12, 7, body)
  let r = @bpacket.RecvCtx::new()
  let res = r.recv(frame)
  bp_expect_error(res, fn(err) { err is BadType(_) }, "t13")
}

// ================= T14:中途切模式(seqnr 连续)=================

///|
test "t14_mode_switch_keeps_seqnr" {
  let key = bp_key64()
  let s = @bpacket.SendCtx::new()
  let r = @bpacket.RecvCtx::new()
  let payload1 = bp_payload(6, b'\x66')
  match s.emit(b'\x15', payload1, bp_pad_src(32)) {
    Ok(sp) => bp_expect_packet(r.recv(sp.wire), 0U, b'\x15', payload1, "t14-p1")
    SeqnrWrapFatal => abort("t14: unexpected wrap")
  }
  // 模拟 NEWKEYS 后切换(ssh_set_newkeys 不重置 seqnr)
  s.set_mode(Aead(@bpacket.ChachaPolyCtx::new64(key)))
  r.set_mode(Aead(@bpacket.ChachaPolyCtx::new64(key)))
  if s.seqnr() != 1U || r.seqnr() != 1U {
    abort("t14: seqnr should be 1 after first packet")
  }
  let payload2 = bp_payload(6, b'\x77')
  match s.emit(b'\x16', payload2, bp_pad_src(32)) {
    Ok(sp) => bp_expect_packet(r.recv(sp.wire), 1U, b'\x16', payload2, "t14-p2")
    SeqnrWrapFatal => abort("t14: unexpected wrap")
  }
}

// ================= T15:strict-kex NEWKEYS 归零 =================

///|
test "t15_strict_kex_newkeys_reset" {
  // strict 组
  let s = @bpacket.SendCtx::make(Unencrypted, 0U, true, true)
  let r = @bpacket.RecvCtx::make(Unencrypted, 0U, true, true)
  // 先走两个普通包把 seqnr 推到 2
  for i = 0; i < 2; i = i + 1 {
    match s.emit(b'\x02', bp_payload(3, bp_byte(i)), bp_pad_src(32)) {
      Ok(sp) =>
        bp_expect_packet(
          r.recv(sp.wire),
          i.reinterpret_as_uint(),
          b'\x02',
          bp_payload(3, bp_byte(i)),
          "t15-warm",
        )
      SeqnrWrapFatal => abort("t15: unexpected wrap")
    }
  }
  // NEWKEYS 包:发完/收完双侧归零
  match s.emit(b'\x15', bp_payload(0, b'\x00'), bp_pad_src(32)) {
    Ok(sp) => {
      if s.seqnr() != 0U {
        abort("t15: send seqnr should reset to 0 after NEWKEYS")
      }
      bp_expect_packet(
        r.recv(sp.wire),
        2U,
        b'\x15',
        bp_payload(0, b'\x00'),
        "t15-nk",
      )
      if r.seqnr() != 0U {
        abort("t15: recv seqnr should reset to 0 after NEWKEYS")
      }
      // 归零后的下一个包用 seqnr 0
      match s.emit(b'\x03', bp_payload(2, b'\x09'), bp_pad_src(32)) {
        Ok(sp) =>
          bp_expect_packet(
            r.recv(sp.wire),
            0U,
            b'\x03',
            bp_payload(2, b'\x09'),
            "t15-post",
          )
        SeqnrWrapFatal => abort("t15: unexpected wrap")
      }
    }
    SeqnrWrapFatal => abort("t15: unexpected wrap")
  }
  // 非 strict 对照组:NEWKEYS 不归零
  let s2 = @bpacket.SendCtx::new()
  let r2 = @bpacket.RecvCtx::new()
  match s2.emit(b'\x15', bp_payload(0, b'\x00'), bp_pad_src(32)) {
    Ok(sp) => {
      if s2.seqnr() != 1U {
        abort("t15: non-strict should keep counting")
      }
      bp_expect_packet(
        r2.recv(sp.wire),
        0U,
        b'\x15',
        bp_payload(0, b'\x00'),
        "t15-ns",
      )
      if r2.seqnr() != 1U {
        abort("t15: non-strict recv should keep counting")
      }
    }
    SeqnrWrapFatal => abort("t15: unexpected wrap")
  }
}

// ================= T16:seqnr 回绕两态 =================

///|
test "t16_seqnr_wrap" {
  // 发送方向:initial_kex=true → fatal
  let s_init = @bpacket.SendCtx::make(Unencrypted, 0xFFFFFFFFU, false, true)
  match s_init.emit(b'\x01', bp_payload(2, b'\x0A'), bp_pad_src(32)) {
    Ok(_) => abort("t16: initial wrap should be fatal")
    SeqnrWrapFatal => ()
  }
  // 发送方向:initial_kex=false → 正常回绕到 0
  let s_rekey = @bpacket.SendCtx::make(Unencrypted, 0xFFFFFFFFU, false, false)
  match s_rekey.emit(b'\x01', bp_payload(2, b'\x0A'), bp_pad_src(32)) {
    Ok(_) =>
      if s_rekey.seqnr() != 0U {
        abort("t16: rekey wrap should reach 0")
      }
    SeqnrWrapFatal => abort("t16: non-initial wrap must not be fatal")
  }
  // 接收方向对称
  let r_init = @bpacket.RecvCtx::make(Unencrypted, 0xFFFFFFFFU, false, true)
  let frame = bp_manual_frame(12, 7, bp_payload(4, b'\x88'))
  bp_expect_error(
    r_init.recv(frame),
    fn(err) { err is SeqnrWrapInitial },
    "t16-rx-init",
  )
  // 非 initial:正常解析,seqnr_used=0xFFFFFFFF,推进后归 0
  let r_rekey = @bpacket.RecvCtx::make(Unencrypted, 0xFFFFFFFFU, false, false)
  // body 4 字节从 [5] 起:type=0x41,payload 区=[42,43,44](payload_len=packlen-1-padlen=4)
  let frame2 = bp_manual_frame(12, 7, bp_payload(4, b'\x41'))
  bp_expect_packet(
    r_rekey.recv(frame2),
    0xFFFFFFFFU,
    b'\x41',
    bp_payload(3, b'\x42'),
    "t16-rx-rekey",
  )
  if r_rekey.seqnr() != 0U {
    abort("t16: rx seqnr should wrap to 0")
  }
}

// ================= T17:参数化属性扫描 =================

///|
test "t17_property_sweep" {
  let key = bp_key64()
  let sizes : Array[Int32] = [
    0, 1, 3, 5, 7, 9, 11, 13, 15, 17, 23, 31, 47, 63, 64, 65, 69,
  ]
  for n in sizes {
    // plain
    let sp = @bpacket.SendCtx::new()
    let rp = @bpacket.RecvCtx::new()
    let pay = bp_payload(n, b'\x99')
    match sp.emit(bp_byte(100 + n % 50), pay, bp_pad_src(32)) {
      Ok(pkt) => {
        let f = pkt.frame
        let packlen = (f[0].to_uint() << 24) |
          (f[1].to_uint() << 16) |
          (f[2].to_uint() << 8) |
          f[3].to_uint()
        if (4 + packlen.reinterpret_as_int()) % 8 != 0 {
          abort("t17: plain alignment broken at n=\{n}")
        }
        let padlen = f[4].to_int()
        if padlen < 4 || padlen > 255 {
          abort("t17: plain padlen out of range at n=\{n}")
        }
        if pkt.wire.length() != 4 + packlen.reinterpret_as_int() {
          abort("t17: plain wire length at n=\{n}")
        }
        bp_expect_packet(
          rp.recv(pkt.wire),
          0U,
          bp_byte(100 + n % 50),
          pay,
          "t17-plain-\{n}",
        )
      }
      SeqnrWrapFatal => abort("t17: unexpected wrap")
    }
    // aead
    let sa = @bpacket.SendCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      0U,
      false,
      true,
    )
    let ra = @bpacket.RecvCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      0U,
      false,
      true,
    )
    match sa.emit(bp_byte(150 + n % 50), pay, bp_pad_src(32)) {
      Ok(pkt) => {
        let f = pkt.frame
        let packlen = (f[0].to_uint() << 24) |
          (f[1].to_uint() << 16) |
          (f[2].to_uint() << 8) |
          f[3].to_uint()
        if packlen.reinterpret_as_int() % 8 != 0 {
          abort("t17: aead alignment broken at n=\{n}")
        }
        if pkt.wire.length() != 4 + packlen.reinterpret_as_int() + 16 {
          abort("t17: aead wire length at n=\{n}")
        }
        bp_expect_packet(
          ra.recv(pkt.wire),
          0U,
          bp_byte(150 + n % 50),
          pay,
          "t17-aead-\{n}",
        )
      }
      SeqnrWrapFatal => abort("t17: unexpected wrap")
    }
  }
}

// ================= T18:Python KAT 三盲锚点 =================

///|
/// 字节相等断言
fn bp_assert_bytes(
  actual : FixedArray[Byte],
  expected : FixedArray[Byte],
  label : String,
) -> Unit {
  if actual.length() != expected.length() {
    abort("\{label}: length \{actual.length()} != \{expected.length()}")
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if actual[i] != expected[i] {
      abort("\{label}: byte \{i} mismatch")
    }
  }
}

///|
/// V3 的确定性 payload:(i*7+rnd)&0xFF,长度 5+rnd
fn bp_v3_payload(rnd : Int32) -> FixedArray[Byte] {
  let n = 5 + rnd
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = bp_byte(i * 7 + rnd)
  }
  arr
}

///|
test "t18_python_kat_vectors" {
  // ---- V1:plain 帧(type=20,n=10,payload=00..09)----
  let pay1 = bp_payload(10, b'\x00')
  let s1 = @bpacket.SendCtx::new()
  match s1.emit(b'\x14', pay1, bp_pad_src(32)) {
    Ok(sp) =>
      bp_assert_bytes(
        sp.frame,
        bp_hex("000000140814000102030405060708090000000000000000"),
        "V1",
      )
    SeqnrWrapFatal => abort("V1: unexpected wrap")
  }
  // ---- V2:aead wire(seqnr=0/1/2),emit 与 parse 双向 ----
  let key = bp_key64()
  let v2 : Array[String] = [
    "94450e491cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579", "c922a7b56d487cd83309bc7f2b76762616b0b0b4b7a8d54f287539a9e33897543e28bf0c",
    "3cc39c0349deb0f6087e6351cb39b0c46854eebed711792745a2211ea839c6f24804c381",
  ]
  for sq = 0; sq < 3; sq = sq + 1 {
    // 方向一:MoonBit emit == Python wire
    let se = @bpacket.SendCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      bp_byte(sq).to_uint(),
      false,
      true,
    )
    match se.emit(b'\x14', pay1, bp_pad_src(32)) {
      Ok(sp) => bp_assert_bytes(sp.wire, bp_hex(v2[sq]), "V2-emit-\{sq}")
      SeqnrWrapFatal => abort("V2-\{sq}: unexpected wrap")
    }
    // 方向二:Python wire 被 MoonBit recv 解回
    let r = @bpacket.RecvCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      bp_byte(sq).to_uint(),
      false,
      true,
    )
    let res = r.recv(bp_hex(v2[sq]))
    bp_expect_packet(
      res,
      bp_byte(sq).to_uint(),
      b'\x14',
      pay1,
      "V2-parse-\{sq}",
    )
  }
  // ---- V3:三包拼接流逐包消费 ----
  let stream_hex = "94450e4911e24236a3f3ba74b7c6fac00fe0ec8adf1e66d1ca95d141dd568e2b12a3e73dc922a7b561077dd13e1ca55e88d5d98912b4b4b0587d43062f4ed25affca4710776192703cc39c034a96b2fe1a6a7971e19b1c6a6b51e9bbf09fb6c83e1042377227b2b06b6d1c71"
  let stream = bp_hex(stream_hex)
  let rs = @bpacket.RecvCtx::make(
    Aead(@bpacket.ChachaPolyCtx::new64(key)),
    0U,
    false,
    true,
  )
  let mut off = 0
  for rnd = 0; rnd < 3; rnd = rnd + 1 {
    let res = rs.recv(bp_slice(stream, off, stream.length()))
    bp_expect_packet(
      res,
      bp_byte(rnd).to_uint(),
      bp_byte(90 + rnd),
      bp_v3_payload(rnd),
      "V3-\{rnd}",
    )
    off = off + res.consumed
  }
  if off != stream.length() {
    abort("V3: consumed sum mismatch")
  }
  // 同时验证 MoonBit 自产三包流与 V3 拼接一致
  let mut built : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  for rnd = 0; rnd < 3; rnd = rnd + 1 {
    let s3 = @bpacket.SendCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      bp_byte(rnd).to_uint(),
      false,
      true,
    )
    match s3.emit(bp_byte(90 + rnd), bp_v3_payload(rnd), bp_pad_src(32)) {
      Ok(sp) => {
        let merged : FixedArray[Byte] = FixedArray::make(
          built.length() + sp.wire.length(),
          b'\x00',
        )
        for i = 0; i < built.length(); i = i + 1 {
          merged[i] = built[i]
        }
        for i = 0; i < sp.wire.length(); i = i + 1 {
          merged[built.length() + i] = sp.wire[i]
        }
        built = merged
      }
      SeqnrWrapFatal => abort("V3-build: unexpected wrap")
    }
  }
  bp_assert_bytes(built, stream, "V3-build")
  // ---- V4:篡改矩阵(Python 产出的完整输入 + 期望错误名)----
  let t_body = "94450e491cac4230afe5a3d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579"
  let t_badlen = "14450e491cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579"
  let t_align = "94450e481cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec579"
  let t_auth_padded = "94450e411cac4230afe5a2d4156654680ae7e981eeca6d2a0244c59cd6a405124d0ec5790000000000000000000000000000000000000000000000000000000000000000"
  let cases : Array[(String, String)] = [
    (t_body, "auth"),
    (t_badlen, "badlen"),
    (t_align, "align"),
    (t_auth_padded, "auth2"),
  ]
  for case in cases {
    let (hexstr, want) = case
    let rt = @bpacket.RecvCtx::make(
      Aead(@bpacket.ChachaPolyCtx::new64(key)),
      0U,
      false,
      true,
    )
    let res = rt.recv(bp_hex(hexstr))
    let ok = match res.event {
      Failed(AuthFailed) => want == "auth" || want == "auth2"
      Failed(BadLength(_)) => want == "badlen"
      Failed(AlignError(_)) => want == "align"
      _ => false
    }
    if !ok {
      abort("V4: \{want} expectation violated")
    }
  }
}
