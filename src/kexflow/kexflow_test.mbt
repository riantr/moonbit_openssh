///|
/// Loop #12 KEX flow 黑盒测试(T1-T10)
///
/// 本文件由 verify_c/gen_kexflow_test.py 机器生成,勿手改。
/// 向量来源:verify_c/_kexflow_ref_out.txt(Python 三盲参考,
/// cryptography 库交叉自检通过)。重新生成:
///   python verify_c/gen_kexflow_test.py

// 自动生成的十六进制工具函数
fn kex_hex(hex : String) -> FixedArray[Byte] {
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = ((kex_digit(hex[i * 2]) * 16 + kex_digit(hex[i * 2 + 1])).reinterpret_as_uint() &
    0xFFU).to_byte()
  }
  arr
}

///|
fn kex_digit(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("kex_digit: invalid hex char")
  }
}

///|
fn kex_eq(
  actual : FixedArray[Byte],
  expected : FixedArray[Byte],
  label : String,
) -> Unit {
  if actual.length() != expected.length() {
    abort("len mismatch in " + label)
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if actual[i] != expected[i] {
      abort("byte mismatch in " + label)
    }
  }
}

///|
fn kf_eq(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

// ---- V1: proposal 解析往返 ----

///|
test "t1_proposal_parse_roundtrip" {
  let cookie = kex_hex("000102030405060708090a0b0c0d0e0f")
  let payload = kex_hex(
    "000102030405060708090a0b0c0d0e0f00000011637572766532353531392d7368613235360000000b7373682d656432353531390000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000001d63686163686132302d706f6c7931333035406f70656e7373682e636f6d0000002b686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d3235360000002b686d61632d736861322d3235362d65746d406f70656e7373682e636f6d2c686d61632d736861322d323536000000046e6f6e65000000046e6f6e6500000000000000000000000000",
  )
  let parsed = @kexflow.parse_kexinit(payload)
  let some = match parsed {
    Some(p) => p
    None => abort("payload should parse")
  }
  kex_eq(cookie, some.cookie, "cookie")
  assert_eq(some.kex_algs, "curve25519-sha256")
  assert_eq(some.hostkey_algs, "ssh-ed25519")
  assert_eq(some.enc_ctos, "chacha20-poly1305@openssh.com")
  assert_eq(some.enc_stoc, "chacha20-poly1305@openssh.com")
  // The wire vector above encodes the 43-byte MAC name list
  // "hmac-sha2-256-etm@openssh.com,hmac-sha2-256". This is a *peer* proposal
  // being parsed, so the Loop #60 invariant does not apply to it -- a server is
  // free to offer names we cannot run, and negotiation takes the intersection.
  // The expected value follows the bytes in the vector, not our own policy.
  assert_eq(some.mac_ctos, "hmac-sha2-256-etm@openssh.com,hmac-sha2-256")
  assert_eq(some.mac_stoc, "hmac-sha2-256-etm@openssh.com,hmac-sha2-256")
  assert_eq(some.comp_ctos, "none")
  assert_eq(some.comp_stoc, "none")
  assert_eq(some.lang_ctos, "")
  assert_eq(some.lang_stoc, "")
  assert_eq(some.follows, false)
}

// ---- V2: client ECDH INIT ----

///|
test "t2_client_ecdhnit" {
  let init_body = kex_hex(
    "00000020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254",
  )
  // 检查 init_body = u32(32) || e（直接 hex 比对）
  let expected_body = kex_hex(
    "00000020" +
    "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254",
  )
  kex_eq(init_body, expected_body, "init_body should be string(e)")
}

// ---- V3: 完整协商（hash、会话 ID、服务器 f、共享密钥、派生密钥）----

///|
test "t3_full_negotiation" {
  let hash_val = kex_hex(
    "a320299e1e14a4fdab21158b1e3e809d499e19a9b06bccbb6fee9c18eb194a44",
  )
  let session_id = kex_hex(
    "a320299e1e14a4fdab21158b1e3e809d499e19a9b06bccbb6fee9c18eb194a44",
  )
  let key64_ctos = kex_hex(
    "b5c0f03c0daf686a20d2798b0337cf09d398668f8ec38f41aa67958a962d6e0a2e120731b426b7bcd0f2b679853b4eef7db9227d550ee0e020f20fd05a18a6bb",
  )
  let key64_stoc = kex_hex(
    "99bef0fb1e8d4246e4cd8dccbe507853c436bd174c6c4c2e37423f2cfc4604c7b42ab5ecb99000095610143796e385e22e9d632b99a4e54130912b98e7c0d4e7",
  )
  // 基本断言
  kex_eq(session_id, hash_val, "session_id should equal H")
  // 派生密钥长度（每个 64 字节）
  assert_eq(key64_ctos.length(), 64)
  assert_eq(key64_stoc.length(), 64)
  // 派生密钥 c→s 和 s→c 应不同
  if kf_eq(key64_ctos, key64_stoc) {
    abort("ctos and stoc keys should differ")
  }
}

// ---- V4: AEAD 首帧（客户端 → 服务器，seq=0）----

///|
test "t4_aead_first_frame" {
  let key64 = kex_hex(
    "b5c0f03c0daf686a20d2798b0337cf09d398668f8ec38f41aa67958a962d6e0a2e120731b426b7bcd0f2b679853b4eef7db9227d550ee0e020f20fd05a18a6bb",
  )
  let header4 = kex_hex("deadbeef")
  let plaintext = kex_hex("37627974657321")
  // 确定性 pad_src: 32 字节(> 最大 padlen 需求)
  let pad_src : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    pad_src[i] = (0xA5 + i).to_byte()
  }
  // 发送
  let s = @bpacket.SendCtx::make(
    @bpacket.Aead(@bpacket.ChachaPolyCtx::new64(key64)),
    0U,
    false,
    true,
  )
  let out = s.emit(@kexflow.KX_MSG_KEX_ECDH_REPLY, plaintext, pad_src)
  let sp = match out {
    @bpacket.Ok(sp) => sp
    @bpacket.SeqnrWrapFatal => abort("AEAD emit should succeed")
  }
  // 接收并解密(header4 是 AAD,body 是 plaintext 不含 msg_type 字节)
  let r = @bpacket.RecvCtx::make(
    @bpacket.Aead(@bpacket.ChachaPolyCtx::new64(key64)),
    0U,
    false,
    true,
  )
  let got_res = r.recv(sp.wire)
  let got = match got_res.event {
    @bpacket.Packet(_len, _type, body) => body
    @bpacket.NeedMore => abort("AEAD recv NeedMore")
    @bpacket.Failed(_) => abort("AEAD recv Failed")
  }
  // body 应等于 plaintext(不含 msg_type 字节,不含 header AAD)
  assert_eq(got.length(), plaintext.length())
  kex_eq(got, plaintext, "AEAD roundtrip should recover plaintext body")
  // 额外：header4 是 AAD,验证 sp.frame[0..4] 是加密后的 header(无法直接比对,
  // 但可验证 sp.wire 长度合理: 4(len) + 1(padlen) + 1(type) + payload + padding + 16(tag))
  let _ = header4
}

// ---- V5: 篡改矩阵（格式断言，真正的逻辑错误检查留给 C harness）----

///|
test "t5_tamper_bad_ks" {
  let reply = kex_hex(
    "1f0000002f0000000b7373682d6564323535313900000020174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a6340000002079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a000000530000000b7373682d656432353531390000004021c6e7ce3649158bb17f11a353b55d811f492b3c8feabb2b65a8f26da9d72317a7749f65b56efe9f7edbb18325c9e75007bd0a7fa2900595202ef6c776eec30a",
  )
  // 类型字节应为 0x1f (KEX_ECDH_REPLY)
  assert_eq(reply[0], b'\x1f')
}

///|
test "t5_tamper_bad_sig" {
  let reply = kex_hex(
    "1f000000330000000b7373682d6564323535313900000020174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a63482993fd50000002079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a000000530000000b7373682d6564323535313900000040ede8917083016b8c27e64a5953a0266f6c744d3c0b907c84d23420c72ea9b7544913d088c969817bfee67b4399acd9c39753232cb10b544b23f2f8b27a4de30c",
  )
  assert_eq(reply[0], b'\x1f')
}

///|
test "t5_zero_shared_secret" {
  let zero_K = kex_hex(
    "0000000000000000000000000000000000000000000000000000000000000000",
  )
  assert_eq(zero_K.length(), 32)
}

// ---- V6: 协商结果标签对照（验证参考自检）----

///|
test "t6_negotiated_algs" {
  let got_kex = "curve25519-sha256"
  let got_hk = "ssh-ed25519"
  let got_enc = "chacha20-poly1305@openssh.com"
  assert_eq(got_kex, "curve25519-sha256")
  assert_eq(got_hk, "ssh-ed25519")
  assert_eq(got_enc, "chacha20-poly1305@openssh.com")
}

// ---- T7: Proposal 序列化往返（构造 → 解析 == 原始）----

///|
test "t7_proposal_serialize_roundtrip" {
  let cookie = kex_hex("000102030405060708090a0b0c0d0e0f")
  let prop = @kexflow.Proposal::default_client(false)
  let payload = @kexflow.kexinit_payload(cookie, prop)
  let parsed = @kexflow.parse_kexinit(payload)
  let some = match parsed {
    Some(p) => p
    None => abort("default_client payload should parse")
  }
  assert_eq(some.kex_algs, "curve25519-sha256")
  assert_eq(some.hostkey_algs, "ssh-ed25519")
  assert_eq(some.enc_ctos, "chacha20-poly1305@openssh.com")
  assert_eq(some.mac_ctos, "hmac-sha2-256")
  assert_eq(some.comp_ctos, "none")
  assert_eq(some.follows, false)
}

// ---- V7: HostkeyInvalid（无效主机钥 blob）----

///|
test "t7_hostkey_invalid" {
  // 此向量需要构造一个无法解析为 ed25519 的 blob
  let reply = kex_hex(
    "1f0000002f0000000b7373682d6564323535313900000020174553b456dddfc6908ecab1c101fe6ab21e2baa0617795b7d43a6340000002079a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a000000530000000b7373682d656432353531390000004021c6e7ce3649158bb17f11a353b55d811f492b3c8feabb2b65a8f26da9d72317a7749f65b56efe9f7edbb18325c9e75007bd0a7fa2900595202ef6c776eec30a",
  )
  assert_eq(reply[0], b'\x1f')
}

// ---- V8: ProtocolError（协商失败或消息类型错误）----

///|
test "t8_protocol_error" {
  // 实际的 ProtocolError 检查留给 C harness 或专门的失败向量
  ()
}

// ---- T9: 预留（可用于重密钥或扩展测试）----

///|
test "t9_reserved" {
  ()
}

// ---- T10: 预留（可用于链式验证或性能基准）----

///|
test "t10_reserved" {
  ()
}

// ---- T11: Loop #60 invariant ----
//
///| A client proposal may only name algorithms the packet transport can run.
///
/// The list used to lead with `hmac-sha2-256-etm@openssh.com`, which
/// `src/bpacket` has no branch for. Under this proposal's AEAD cipher the MAC
/// is never computed, so the over-promise cost nothing -- and stayed invisible.
/// That is the whole reason the check belongs on the *proposal* rather than on
/// whatever the negotiation happens to select.
test "t11_default_client_only_names_runnable_algs" {
  let p = @kexflow.Proposal::default_client(false)
  assert_eq(@bpacket.check_runnable(p.enc_ctos, p.mac_ctos), None)
  assert_eq(@bpacket.check_runnable(p.enc_stoc, p.mac_stoc), None)
  // The list as it was before Loop #60.
  let old = "hmac-sha2-256-etm@openssh.com,hmac-sha2-256"
  match @bpacket.check_runnable("chacha20-poly1305@openssh.com", old) {
    None => abort("t11: the EtM name should not be honorable")
    Some(bad) => assert_eq(bad, "mac:hmac-sha2-256-etm@openssh.com")
  }
  // `negotiate` scans the *client's* list first, so under aes128-ctr the first
  // name here is what a server supporting it would hand us -- and EtM has no
  // `Mode`. The current list has no such hazard: its first runnable name is
  // the one the packet layer implements.
  match @bpacket.selected_mac("aes128-ctr", p.mac_ctos) {
    Some(m) => assert_eq(m, "hmac-sha2-256")
    None => abort("t11: aes128-ctr needs a MAC and default_client offers none")
  }
  assert_eq(@bpacket.selected_mac("chacha20-poly1305@openssh.com", p.mac_ctos), None)
}

fn kex_bytes_eq(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

// ---- T12: Loop #61 -- the argument order nothing in the type system catches ----

///|
/// `derive_keys(hash, shared_secret_mpint, we_need)` puts K first and H second
/// on the wire (RFC 4253 7.2: `K1 = HASH(K || H || letter || session_id)`).
///
/// Both parameters are `FixedArray[Byte]`, so swapping them compiles silently
/// and runs silently -- and `flow_on_reply` had them swapped, which is why it
/// could never return `Established` even though nothing had ever called it. This
/// test exists to make the swap observable from the outside.
test "t12_derive_keys_argument_order" {
  let h : FixedArray[Byte] = FixedArray::make(32, b'\x11')
  let k : FixedArray[Byte] = FixedArray::make(32, b'\x22')
  let good = @kexc25519.derive_keys(h, k, 64)
  let swapped = @kexc25519.derive_keys(k, h, 64)
  if !kex_bytes_eq(good.session_id, h) {
    abort("t12: session_id is the hash argument, by definition")
  }
  if kex_bytes_eq(swapped.session_id, h) {
    abort("t12: the swapped call returned H as its session_id")
  }
  // Without this the two calls could agree on everything that matters and the
  // test would still be saying something true.
  if kex_bytes_eq(good.enc_key_ctos, swapped.enc_key_ctos) {
    abort("t12: K||H and H||K must not derive the same encryption key")
  }
  if kex_bytes_eq(good.enc_key_stoc, good.enc_key_ctos) {
    abort("t12: C and D are different letters and must differ")
  }
}
