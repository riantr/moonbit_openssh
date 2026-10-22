///| cmd/agent_kat -- Loop #80: the agent protocol, on its own.
///

///|
/// The agent protocol is small enough to pin down byte for byte without a
/// server anywhere near it. This program prints every byte the protocol
/// produces, for one fixed sample, and the gate compares each line with
/// `host/agent_oracle.py` -- an independent implementation written from
/// OpenSSH's `authfd.c`, not from this code.
///

///|
/// What gets pinned:
///
///   * the **framing**: `uint32 length` + `byte type` + payload, where the
///     length counts the type byte and the payload but not itself
///   * the **IDENTITIES_ANSWER payload**: `uint32 count` + per entry
///     `string blob` + `string comment`
///   * the **SIGN_REQUEST payload**: `string blob` + `string data` +
///     `uint32 flags`
///   * the **SIGN_RESPONSE payload**: `string signature`
///   * the **publickey probe** (RFC 4252 section 7, boolean FALSE)
///

///|
/// The signature in here is produced by our own ECDSA over the same bytes the
/// oracle signs, and it has to come out identical. That is a deliberate
/// cross-check rather than a convenience: the agent path never signs
/// anything itself, it only carries a signature from the agent to the
/// server, so the only way to know the agent's signature is *the* signature
/// is to have both sides sign the same bytes with the same key and compare.

///|
/// The sample is the RFC 6979 A.2.5 key -- the same one Loop #34 uses -- so
/// the vectors here and the vectors there describe the same key, and a
/// mismatch points at the agent layer rather than at the curve arithmetic.

///|
/// This program depends on `src/agent`, `src/ecdsa` and `src/userauth`, and
/// on **no socket at all**, so it runs unchanged on every backend.

///|
/// ## Why the output is `key: value` and not JSON

///|
/// Every other driver in this repository prints `key: value` lines, and the
/// gates parse them with a regex. JSON would need a parser on the MoonBit
/// side or a hand-written one on the gate side; the line format has neither
/// problem and has survived forty loops of gates.

///|
/// The gate compares against the oracle's JSON, so the two formats meet in
/// the gate, not in either implementation.

///|
fn main {
  let curve = @ecdsa.Curve::p256()
  let d = test_key()
  // ---- the sample identity ----
  let q = match curve.public_key(d) {
    None => {
      println("result: FAILED")
      println("error: the test key is not on the curve")
      return
    }
    Some(p) => p
  }
  let blob = match @ecdsa.encode_pubkey_blob(curve, q) {
    None => {
      println("result: FAILED")
      println("error: could not encode the public key blob")
      return
    }
    Some(b) => b
  }
  let key_type = curve.ssh_key_type()
  let comment = "loop80@agent"
  let data = sample_data()
  let session_id = sample_data()
  // ---- 1. the framing ----
  let frame_identities = @agent.agent_frame(
    @agent.AGENTC_REQUEST_IDENTITIES,
    FixedArray::make(0, b'\x00'),
  )
  println("frame_request_identities: " + @ecdsa.bytes_to_hex(frame_identities))
  // ---- 2. IDENTITIES_ANSWER ----
  let entries : Array[@agent.AgentIdentity] = [{ key_blob: blob, comment, }]
  let identities_payload = @agent.agent_reference_identities_payload(entries)
  println("identities_payload: " + @ecdsa.bytes_to_hex(identities_payload))
  // Parse it back, the way a client would after the agent answered.
  let parsed = match @agent.agent_parse_identities(identities_payload) {
    None => {
      println("result: FAILED")
      println("error: could not parse the identities payload we just built")
      return
    }
    Some(v) => v
  }
  println("identities_count: " + parsed.length().to_string())
  if parsed.length() > 0 {
    println(
      "identity_key_type: " +
      @agent.agent_key_type(parsed[0].key_blob).unwrap_or("?"),
    )
    println("identity_comment: " + parsed[0].comment)
    println("identity_blob: " + @ecdsa.bytes_to_hex(parsed[0].key_blob))
  }
  // ---- 3. SIGN_REQUEST ----
  let sign_payload = @agent.agent_sign_payload(blob, data, 0)
  println("sign_request_payload: " + @ecdsa.bytes_to_hex(sign_payload))
  let frame_sign = @agent.agent_frame(@agent.AGENTC_SIGN_REQUEST, sign_payload)
  println("frame_sign_request: " + @ecdsa.bytes_to_hex(frame_sign))
  // ---- 4. the signature, and SIGN_RESPONSE ----
  let sig = match @ecdsa.ecdsa_sign(curve, d, data) {
    None => {
      println("result: FAILED")
      println("error: could not sign the sample data")
      return
    }
    Some(s) => s
  }
  let sig_blob = @ecdsa.encode_sig_blob(curve, sig)
  println("sig_blob: " + @ecdsa.bytes_to_hex(sig_blob))
  // The SIGN_RESPONSE payload is `string signature`; build it the way the
  // agent would, then read it back the way the client would.
  let response_payload = @sshwire.write_ssh_string(sig_blob)
  println("sign_response_payload: " + @ecdsa.bytes_to_hex(response_payload))
  let parsed_sig = match @agent.agent_parse_signature(response_payload) {
    None => {
      println("result: FAILED")
      println("error: could not parse the sign response we just built")
      return
    }
    Some(s) => s
  }
  println("parsed_sig_blob: " + @ecdsa.bytes_to_hex(parsed_sig))
  // ---- 5. the publickey probe ----
  let probe = @userauth.userauth_publickey_probe_request(
    "loop80",
    @userauth.AUTH_SERVICE_CONNECTION,
    key_type,
    blob,
  )
  println("probe_payload: " + @ecdsa.bytes_to_hex(probe))
  // ---- 6. and the bytes the agent would have signed in a real session ----
  let signed = @userauth.userauth_signed_blob(
    session_id,
    "loop80",
    @userauth.AUTH_SERVICE_CONNECTION,
    key_type,
    blob,
  )
  println("signed_blob: " + @ecdsa.bytes_to_hex(signed))
  println("pubkey_blob: " + @ecdsa.bytes_to_hex(blob))
  println("data: " + @ecdsa.bytes_to_hex(data))
  println("key_type: " + key_type)
  println("comment: " + comment)
  // ---- 7. 边界:对端能说什么、不能说什么 ----
  //
  // agent 的载荷完全由对端控制:回复长度、身份条数、字符串长度,三个都是
  // **先查后分配**。少了任何一道,一个坏掉的 agent 就能让客户端去申请
  // 4 GiB 内存,或者让它照着一个说「我有 40 亿把钥匙」的表循环。
  //
  // 下面这五条把三道闸门都钉住:每一条的左边是「必须被拒绝」,右边是
  // 「一旦放行,客户端要么会去分配巨量内存,要么会拿到一份胡说八道的表」。
  println("reply_limit: " + verdict(reply_limit_holds()))
  println("reply_zero_length: " + verdict(reply_zero_length_holds()))
  println("identities_count_limit: " + verdict(identities_count_limit_holds()))
  println("identities_truncated: " + verdict(identities_truncated_holds()))
  println("signature_truncated: " + verdict(signature_truncated_holds()))
  println("result: OK")
}

///|
/// 一个只会重复同一段字节的通道。
///
/// 它存在的意义是制造一个**由对端决定长度**的场景:agent 说的「回复有
/// 1 MiB」就是 1 MiB,客户端要么在分配之前把它挡下来,要么就真的去申请
/// 那块内存。
///
/// 这个通道不做状态机:它每次都从头返回同一段字节(不够就补零)。对上限
/// 那一道闸门来说这已经够了——闸门在读完 4 字节的长度之后就该决定要不要
/// 继续读,根本读不到第二次。
fn fixed_channel(reply : FixedArray[Byte]) -> @agent.AgentChannel {
  {
    write: fn(_d) { true },
    read_exact: fn(n) {
      let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
      for i = 0; i < n; i = i + 1 {
        out[i] = if i < reply.length() { reply[i] } else { b'\x00' }
      }
      Some(out)
    },
    close: fn() { () },
  }
}

///|
/// 一个说「回复有 1 MiB」的 agent(上限是 256 KiB)。
fn reply_limit_holds() -> Bool {
  let chan = fixed_channel(
    FixedArray::from_array([b'\x00', b'\x10', b'\x00', b'\x00']),
  )
  match
    @agent.agent_exchange(
      chan,
      @agent.AGENTC_REQUEST_IDENTITIES,
      FixedArray::make(0, b'\x00'),
    ) {
    None => true
    Some(_) => false
  }
}

///|
/// 一个说「回复有 0 字节」的 agent。长度 0 的消息连类型字节都没有。
fn reply_zero_length_holds() -> Bool {
  let chan = fixed_channel(
    FixedArray::from_array([b'\x00', b'\x00', b'\x00', b'\x00']),
  )
  match
    @agent.agent_exchange(
      chan,
      @agent.AGENTC_REQUEST_IDENTITIES,
      FixedArray::make(0, b'\x00'),
    ) {
    None => true
    Some(_) => false
  }
}

///|
/// 一个说「我有 1 048 576 把钥匙」的 agent(上限是 2048)。
///
/// 载荷是**真的**造出来的:2049 条小到不能再小的身份,每条 10 字节,总共
/// 20 KiB 上下。这样「上限被去掉」和「上限生效」两种情况会给出**不同**的
/// 结果——去掉上限时解析会成功,而成功就意味着客户端拿到了一份它根本
/// 没资格拿的表。只用一个说谎的条数是测不出这个的:那种情况下两种实现
/// 都会因为载荷不够长而失败。
fn identities_count_limit_holds() -> Bool {
  let over = 2049
  let mut payload : FixedArray[Byte] = FixedArray::from_array([
    ((over >> 24) & 0xFF).to_byte(),
    ((over >> 16) & 0xFF).to_byte(),
    ((over >> 8) & 0xFF).to_byte(),
    (over & 0xFF).to_byte(),
  ])
  let mut i = 0
  while i < over {
    // string(1 字节) + string(1 字节)
    let entry : FixedArray[Byte] = FixedArray::from_array([
      b'\x00', b'\x00', b'\x00', b'\x01', b'A', b'\x00', b'\x00', b'\x00', b'\x01',
      b'B',
    ])
    payload = cat(payload, entry)
    i = i + 1
  }
  match @agent.agent_parse_identities(payload) {
    None => true
    Some(_) => false
  }
}

///|
/// 一份说「有 1 把钥匙」但正文被截断的载荷。
fn identities_truncated_holds() -> Bool {
  let payload : FixedArray[Byte] = FixedArray::from_array([
    b'\x00', b'\x00', b'\x00', b'\x01', // 一把钥匙
     b'\x00', b'\x00', b'\x00', b'\x08', // 说公钥有 8 字节
     b'A', b'B', // 只有 2 字节
  ])
  match @agent.agent_parse_identities(payload) {
    None => true
    Some(_) => false
  }
}

///|
/// 一份被截断的 SIGN_RESPONSE:`string signature` 的长度说有 8 字节,只有 2。
fn signature_truncated_holds() -> Bool {
  let payload : FixedArray[Byte] = FixedArray::from_array([
    b'\x00', b'\x00', b'\x00', b'\x08', b'A', b'B',
  ])
  match @agent.agent_parse_signature(payload) {
    None => true
    Some(_) => false
  }
}

///|
/// 拼接两个字节数组
fn cat(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(
    a.length() + b.length(),
    b'\x00',
  )
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  out
}

///|
/// 把一个布尔值写成 PASS / FAIL。
fn verdict(ok : Bool) -> String {
  if ok {
    "PASS"
  } else {
    "FAIL"
  }
}

///|
/// Loop #34 的测试私钥:即 RFC 6979 A.2.5 公布的 NIST P-256 key。
///
/// 这把私钥出现在 RFC 原文里,只可能用于本 loop 那台一次性 sshd 的
/// authorized_keys。**绝不能**用在真实主机上——公开的私钥等于没有私钥。
fn test_key() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67,
    0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A,
    0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
/// 32 bytes, 0xA0..0xBF.
///
/// 固定的一段字节,两边都一样。它当「让 agent 签的数据」用,也当
/// 「会话标识」用——后者让签名的输入在两次运行之间完全一致,签名因此
/// 可复现、可逐字节比较(RFC 6979)。
fn sample_data() -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = (0xA0 + i).to_byte()
  }
  out
}
