///| SSH 完整 client flow (RFC 4253/4252/4254):
///|   1. 版本字符串交换 (RFC 4253 §4.2)
///|   2. KEXINIT 协商 (RFC 4253 §7)
///|   3. KEXDH_INIT + KEXDH_REPLY + NEWKEYS (RFC 4253 §8)
///|   4. NEWKEYS 后切换 chacha20-poly1305 (RFC 4253 §6 + chacha20-poly1305@openssh.com)
///|   5. SSH-USERAUTH "none" (RFC 4252)
///|   6. CHANNEL OPEN + exec (RFC 4254)
///|   7. 读 DATA + EOF + CLOSE (mock)
///|
/// Loop #19: 加入 SendCtx.emit (NEWKEYS 后 chacha20-poly1305 真实加密)

///|
/// ASCII string → FixedArray[Byte](辅助)
fn ascii_bytes(s : String) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    arr[i] = s[i].to_byte()
  }
  arr
}

///|
/// 拼两个 FixedArray
fn concat(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(a.length() + b.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  out
}

///|
/// SSH-USERAUTH_REQUEST "none" method (RFC 4252 §5)
fn userauth_none_payload(user : String) -> FixedArray[Byte] {
  let s1 = @sshwire.write_ssh_string(ascii_bytes(user))
  let s2 = @sshwire.write_ssh_string(ascii_bytes("ssh-connection"))
  let s3 = @sshwire.write_ssh_string(ascii_bytes("none"))
  concat(concat(s1, s2), s3)
}

///|
/// CHANNEL_OPEN session (RFC 4254 §5.1)
fn channel_open_payload(sender : Int, window : Int, max_packet : Int) -> FixedArray[Byte] {
  let s = @sshwire.write_ssh_string(ascii_bytes("session"))
  let u1 = @sshwire.write_u32(sender.reinterpret_as_uint())
  let u2 = @sshwire.write_u32(window.reinterpret_as_uint())
  let u3 = @sshwire.write_u32(max_packet.reinterpret_as_uint())
  concat(concat(concat(s, u1), u2), u3)
}

///|
/// CHANNEL_REQUEST exec (RFC 4254 §6.2)
fn channel_request_exec_payload(channel : Int, command : String) -> FixedArray[Byte] {
  let u1 = @sshwire.write_u32(channel.reinterpret_as_uint())
  let s1 = @sshwire.write_ssh_string(ascii_bytes("exec"))
  let want : FixedArray[Byte] = FixedArray::from_array([b'\x01']) // true
  let s2 = @sshwire.write_ssh_string(ascii_bytes(command))
  concat(concat(concat(u1, s1), want), s2)
}

///|
/// 派生 chacha20-poly1305@openssh.com 64-byte enc key
///
/// 简化版 (Loop #19 demo): 不依赖完整 kex flow 的 H + session_id
/// 直接构造 64-byte deterministic key (32B main + 32B header)
/// 真实 SSH: enc_key = SHA-256(mpint(K) || H || "C" || session_id)[:64]
fn make_enc_key_ctos_demo() -> FixedArray[Byte] {
  // 64-byte deterministic key
  let key : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  // Pattern: 0xCC 0x10 .. 0xCF 0x10 (main_key=0..31 + header_key=32..63)
  for i = 0; i < 64; i = i + 1 {
    key[i] = ((i & 0xFF).to_byte())
  }
  // 覆盖部分字节做标识 (让 main_key 和 header_key 不同)
  for i = 0; i < 32; i = i + 1 {
    key[i] = (0xC0 + i).to_byte()
  }
  for i = 32; i < 64; i = i + 1 {
    key[i] = (0xD0 + (i - 32)).to_byte()
  }
  key
}

///|
/// 把 SendCtx::EmitResult 展开为 wire bytes
fn emit_result_wire(r : @bpacket.EmitResult) -> FixedArray[Byte] {
  match r {
    @bpacket.Ok(p) => p.wire
    @bpacket.SeqnrWrapFatal => abort("send: seqnr wrap fatal")
  }
}

///|
/// SendCtx::emit pad_src 参数 (deterministic for byte-exact,全 0x00)
fn zero_pad_src(max : Int) -> FixedArray[Byte] {
  FixedArray::make(max, b'\x00')
}

///|
/// 完整 SSH client flow (NEWKEYS 后启用 chacha20-poly1305 真实加密)
///|
/// 返回 (sent_bytes_to_server, recv_bytes_from_server, userauth_wire_len,
///        channel_open_wire_len, channel_exec_wire_len)
pub fn ssh_client_run(
  client_version : String,
  user : String,
  command : String,
  mock_responses : Array[FixedArray[Byte]],
) -> (FixedArray[Byte], FixedArray[Byte], Int, Int, Int) {
  let sock = @socket.MockSocket::make(mock_responses)

  // 1. 发送 client version (unencrypted)
  sock.send(ascii_bytes(client_version + "\r\n"))

  // 2. 读 server version (mock)
  let _server_version = sock.read_n(mock_responses[0].length())

  // 3. KEXINIT (unencrypted, Loop #12 kexflow::kexinit_payload)
  let cookie : FixedArray[Byte] = FixedArray::from_array([
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10,
  ])
  let prop = @kexflow.Proposal::default_client(false)
  let ic_payload = @kexflow.kexinit_payload(cookie, prop)

  let alice_priv : FixedArray[Byte] = FixedArray::from_array([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
    0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  ])
  let started = @kexflow.flow_start(
    @kexflow.FlowConfig::make(
      ascii_bytes("SSH-2.0-MoonBit"),
      ascii_bytes("SSH-2.0-OpenSSH_8.4"),
      cookie, alice_priv, false, "demo", 22, [],
    ),
    prop,
  )

  // 4. 发 KEXINIT (unencrypted, sshwire.make_packet path)
  let kexinit_packet = @sshwire.make_packet(@sshwire.SSH_MSG_KEXINIT, ic_payload)
  sock.send(kexinit_packet)

  // 5. 发 KEXECDH_INIT (started.init_msg 已经含 type + len + Q_C)
  sock.send(started.init_msg)

  // 6. NEWKEYS (unencrypted, send_ctx::emit path)
  let send_ctx = @bpacket.SendCtx::new()
  let newkeys_initial_packet = emit_result_wire(
    send_ctx.emit(@sshwire.SSH_MSG_NEWKEYS, FixedArray::make(0, b'\x00'), zero_pad_src(64)),
  )
  sock.send(newkeys_initial_packet)

  // 7. **Loop #19: 切换到 Aead mode** (NEWKEYS 后)
  let enc_key_ctos = make_enc_key_ctos_demo()
  let aead_ctx = @bpacket.ChachaPolyCtx::new64(enc_key_ctos)
  send_ctx.set_mode(@bpacket.Aead(aead_ctx))

  // 8. SSH-USERAUTH (Aead mode, seqnr = 1)
  let auth_payload = userauth_none_payload(user)
  let userauth_wire = emit_result_wire(
    send_ctx.emit(@sshwire.SSH_MSG_USERAUTH_REQUEST, auth_payload, zero_pad_src(64)),
  )
  sock.send(userauth_wire)

  // 9. CHANNEL OPEN (Aead mode, seqnr = 2)
  let open_payload = channel_open_payload(0, 2097152, 32768)
  let open_wire = emit_result_wire(
    send_ctx.emit(@sshwire.SSH_MSG_CHANNEL_OPEN, open_payload, zero_pad_src(64)),
  )
  sock.send(open_wire)

  // 10. CHANNEL REQUEST exec (Aead mode, seqnr = 3)
  let exec_payload = channel_request_exec_payload(0, command)
  let exec_wire = emit_result_wire(
    send_ctx.emit(@sshwire.SSH_MSG_CHANNEL_REQUEST, exec_payload, zero_pad_src(64)),
  )
  sock.send(exec_wire)

  // 11. 收集所有 send bytes
  let sent = sock.sent_bytes()
  sock.close()

  // 12. recv 数据:Loop #19 mock 不发回 reply,空 bytes
  let recv : FixedArray[Byte] = FixedArray::make(0, b'\x00')

  (sent, recv, userauth_wire.length(), open_wire.length(), exec_wire.length())
}