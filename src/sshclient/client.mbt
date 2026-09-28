///| SSH 完整 client flow (RFC 4253/4252/4254):
///|   1. 版本字符串交换 (RFC 4253 §4.2)
///|   2. KEXINIT 协商 (RFC 4253 §7)
///|   3. KEXDH_INIT + KEXDH_REPLY + NEWKEYS (RFC 4253 §8)
///|   4. NEWKEYS 后切换 chacha20-poly1305 (RFC 4253 §6 + chacha20-poly1305@openssh.com)
///|   5. SSH-USERAUTH "none" (RFC 4252)
///|   6. CHANNEL OPEN + exec (RFC 4254)
///|   7. 读 DATA + EOF + CLOSE (mock)
//|
/// Loop #19: 加入 SendCtx.emit (NEWKEYS 后 chacha20-poly1305 真实加密)
/// Loop #22: 加入 ssh_client_full_unencrypted (完整 write 侧字节级协议闭环)

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
///
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

// ============================================================================
// Loop #22 G1: 完整 SSH client write 侧字节级协议闭环 (unencrypted path)
// ============================================================================

///|
/// 拼接多个 FixedArray[Byte] (concat_long)
fn concat_long(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i = 0; i < p.length(); i = i + 1 {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  out
}

///|
/// SSH-USERAUTH_REQUEST "password" method (RFC 4252 §5)
/// payload = string user || string service "ssh-connection" || string "password" || bool true || string password
fn userauth_password_payload(
  user : String,
  password : String,
) -> FixedArray[Byte] {
  concat_long([
    @sshwire.write_ssh_string(ascii_bytes(user)),
    @sshwire.write_ssh_string(ascii_bytes("ssh-connection")),
    @sshwire.write_ssh_string(ascii_bytes("password")),
    FixedArray::from_array([b'\x01']), // bool true
    @sshwire.write_ssh_string(ascii_bytes(password)),
  ])
}

///|
/// 构造 server reply packet (RFC 4253 §6) — mock v2 helper
fn make_server_packet(
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> FixedArray[Byte] {
  @sshwire.make_packet(msg_type, payload)
}

///|
/// 构造 server VERSION reply (raw bytes, 无 packet framing)
fn make_server_version_bytes() -> FixedArray[Byte] {
  ascii_bytes("SSH-2.0-MockSSH_1.0\r\n")
}

///|
/// 构造 server KEXINIT reply (deterministic, mock v2)
fn make_server_kexinit_reply() -> FixedArray[Byte] {
  // cookie 16 bytes deterministic (0xA0..0xAF)
  let cookie : FixedArray[Byte] = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    cookie[i] = (0xA0 + i).to_byte()
  }
  let algs : Array[String] = [
    "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com",
    "chacha20-poly1305@openssh.com", "hmac-sha2-256-etm@openssh.com,hmac-sha2-256",
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-256", "none", "none", "", "",
  ]
  let parts : Array[FixedArray[Byte]] = [cookie]
  for alg in algs {
    parts.push(@sshwire.write_ssh_string(ascii_bytes(alg)))
  }
  parts.push(FixedArray::from_array([b'\x00'])) // follows
  parts.push(@sshwire.write_u32(0U)) // reserved
  let payload = concat_long(parts)
  make_server_packet(@sshwire.SSH_MSG_KEXINIT, payload)
}

///|
/// 构造 server KEXDH_REPLY reply (mock v2, simplified)
fn make_server_kexdh_reply_reply() -> FixedArray[Byte] {
  let alg_part : FixedArray[Byte] = @sshwire.write_ssh_string(ascii_bytes("ssh-ed25519"))
  let pub_bytes : FixedArray[Byte] = FixedArray::make(32, b'\x42')
  let ks_blob = concat_long([alg_part, pub_bytes])
  let ks_str = @sshwire.write_ssh_string(ks_blob)
  let qs : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    qs[i] = ((i * 7) & 0xFF).to_byte()
  }
  let qs_str = @sshwire.write_ssh_string(qs)
  let sig : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  let sig_str = @sshwire.write_ssh_string(sig)
  make_server_packet(
    @sshwire.SSH_MSG_KEX_ECDH_REPLY,
    concat_long([ks_str, qs_str, sig_str]),
  )
}

///|
/// 构造 server NEWKEYS reply (empty payload)
fn make_server_newkeys_reply() -> FixedArray[Byte] {
  make_server_packet(@sshwire.SSH_MSG_NEWKEYS, FixedArray::make(0, b'\x00'))
}

///|
/// 构造 server USERAUTH_SUCCESS reply (empty payload)
fn make_server_userauth_success_reply() -> FixedArray[Byte] {
  make_server_packet(
    @sshwire.SSH_MSG_USERAUTH_SUCCESS,
    FixedArray::make(0, b'\x00'),
  )
}

///|
/// 构造 server CHANNEL_OPEN_CONFIRMATION reply (4 fields, 16 bytes payload)
fn make_server_channel_open_confirmation_reply(
  recipient_channel : Int,
  sender_channel : Int,
  window_size : Int,
  packet_size : Int,
) -> FixedArray[Byte] {
  let payload = concat_long([
    @sshwire.write_u32(recipient_channel.reinterpret_as_uint()),
    @sshwire.write_u32(sender_channel.reinterpret_as_uint()),
    @sshwire.write_u32(window_size.reinterpret_as_uint()),
    @sshwire.write_u32(packet_size.reinterpret_as_uint()),
  ])
  make_server_packet(@sshwire.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, payload)
}

///|
/// 构造 server CHANNEL_SUCCESS reply (4 bytes channel)
fn make_server_channel_success_reply(channel : Int) -> FixedArray[Byte] {
  make_server_packet(
    @sshwire.SSH_MSG_CHANNEL_SUCCESS,
    @sshwire.write_u32(channel.reinterpret_as_uint()),
  )
}

///|
/// 构造 server CHANNEL_DATA reply
fn make_server_channel_data_reply(
  channel : Int,
  data : FixedArray[Byte],
) -> FixedArray[Byte] {
  let payload = concat_long([
    @sshwire.write_u32(channel.reinterpret_as_uint()),
    @sshwire.write_ssh_string(data),
  ])
  make_server_packet(@sshwire.SSH_MSG_CHANNEL_DATA, payload)
}

///|
/// 构造 server CHANNEL_EOF reply
fn make_server_channel_eof_reply(channel : Int) -> FixedArray[Byte] {
  make_server_packet(
    @sshwire.SSH_MSG_CHANNEL_EOF,
    @sshwire.write_u32(channel.reinterpret_as_uint()),
  )
}

///|
/// 构造 server CHANNEL_CLOSE reply
fn make_server_channel_close_reply(channel : Int) -> FixedArray[Byte] {
  make_server_packet(
    @sshwire.SSH_MSG_CHANNEL_CLOSE,
    @sshwire.write_u32(channel.reinterpret_as_uint()),
  )
}

///|
/// 构造 server CHANNEL_REQUEST "exit-status" reply (RFC 4254 §6.10)
fn make_server_exit_status_reply(
  channel : Int,
  exit_status : Int,
) -> FixedArray[Byte] {
  let payload = concat_long([
    @sshwire.write_u32(channel.reinterpret_as_uint()),
    @sshwire.write_u32(exit_status.reinterpret_as_uint()),
  ])
  make_server_packet(@sshwire.SSH_MSG_CHANNEL_REQUEST, payload)
}

///|
/// 解析 server CHANNEL_OPEN_CONFIRMATION payload → (recipient, sender, window, packet_size)
fn parse_channel_open_confirmation_payload(
  payload : FixedArray[Byte],
) -> (Int, Int, Int, Int) {
  let recipient = @sshwire.read_u32(payload, 0).reinterpret_as_int()
  let sender = @sshwire.read_u32(payload, 4).reinterpret_as_int()
  let window = @sshwire.read_u32(payload, 8).reinterpret_as_int()
  let packet = @sshwire.read_u32(payload, 12).reinterpret_as_int()
  (recipient, sender, window, packet)
}

///|
/// 解析 server CHANNEL_DATA payload → (channel, data bytes)
fn parse_channel_data_payload(
  payload : FixedArray[Byte],
) -> (Int, FixedArray[Byte]) {
  let channel = @sshwire.read_u32(payload, 0).reinterpret_as_int()
  let (data, _) = @sshwire.read_ssh_string(payload, 4)
  (channel, data)
}

///|
/// 解析 server CHANNEL_REQUEST "exit-status" payload → (channel, exit_code)
fn parse_exit_status_payload(payload : FixedArray[Byte]) -> (Int, Int) {
  let channel = @sshwire.read_u32(payload, 0).reinterpret_as_int()
  let exit_code = @sshwire.read_u32(payload, 4).reinterpret_as_int()
  (channel, exit_code)
}

///|
/// 构造 mock server packets v2 (11 reply packets for full SSH write path)
fn make_server_packets_v2(stdout_msg : String) -> Array[FixedArray[Byte]] {
  let stdout_bytes = ascii_bytes(stdout_msg)
  [
    make_server_version_bytes(),
    make_server_kexinit_reply(),
    make_server_kexdh_reply_reply(),
    make_server_newkeys_reply(),
    make_server_userauth_success_reply(),
    make_server_channel_open_confirmation_reply(0, 100, 2097152, 32768),
    make_server_channel_success_reply(0),
    make_server_channel_data_reply(0, stdout_bytes),
    make_server_channel_eof_reply(0),
    make_server_exit_status_reply(0, 0),
    make_server_channel_close_reply(0),
  ]
}

///|
/// 完整 SSH client 写 + 收协议闭环 (Loop #22 G1, unencrypted path)
///
/// 走完整 RFC 4252/4254 流程:
///   VERSION → KEXINIT → KEXECDH_INIT → NEWKEYS → USERAUTH(password)
///   → CHANNEL_OPEN(session) → CHANNEL_REQUEST(exec)
///   → 收 USERAUTH_SUCCESS + CHANNEL_OPEN_CONFIRMATION
///   → 收 CHANNEL_SUCCESS + CHANNEL_DATA + EOF + exit-status + CLOSE
///
/// 返回 (sent_bytes, recv_bytes, stdout_str, exit_code, remote_channel)
pub fn ssh_client_full_unencrypted(
  user : String,
  password : String,
  command : String,
) -> (FixedArray[Byte], FixedArray[Byte], String, Int, Int) {
  let stdout_msg = "hello from mock server\n"
  let server_packets = make_server_packets_v2(stdout_msg)
  let sock = @socket.MockSocket::make(server_packets)

  // ---- 1. VERSION ----
  sock.send(ascii_bytes("SSH-2.0-MoonBit\r\n"))
  let _ = sock.read_n(server_packets[0].length())

  // ---- 2. KEXINIT ----
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
      ascii_bytes("SSH-2.0-MockSSH_1.0"),
      cookie, alice_priv, false, "demo", 22, [],
    ),
    prop,
  )
  let kexinit_packet = @sshwire.make_packet(@sshwire.SSH_MSG_KEXINIT, ic_payload)
  sock.send(kexinit_packet)
  let _ = sock.read_n(server_packets[1].length())
  sock.send(started.init_msg)
  let _ = sock.read_n(server_packets[2].length())
  let newkeys_packet = @sshwire.make_packet(
    @sshwire.SSH_MSG_NEWKEYS,
    FixedArray::make(0, b'\x00'),
  )
  sock.send(newkeys_packet)
  let _ = sock.read_n(server_packets[3].length())

  // ---- 3. USERAUTH_REQUEST "password" ----
  let auth_payload = userauth_password_payload(user, password)
  let userauth_wire = @sshwire.make_packet(
    @sshwire.SSH_MSG_USERAUTH_REQUEST,
    auth_payload,
  )
  sock.send(userauth_wire)
  let userauth_success_reply = sock.read_n(server_packets[4].length())
  let userauth_success_buf = @sshwire.SshBuf::new()
  userauth_success_buf.feed(userauth_success_reply)
  let userauth_success_parsed = match userauth_success_buf.try_parse() {
    Some(p) => p
    None => abort("userauth_success parse failed")
  }
  if userauth_success_parsed.msg_type != @sshwire.SSH_MSG_USERAUTH_SUCCESS {
    abort("userauth: expected 0x34 got")
  }

  // ---- 4. CHANNEL_OPEN session ----
  let open_payload = channel_open_payload(0, 2097152, 32768)
  let open_wire = @sshwire.make_packet(@sshwire.SSH_MSG_CHANNEL_OPEN, open_payload)
  sock.send(open_wire)
  let open_confirm_reply = sock.read_n(server_packets[5].length())
  let open_confirm_buf = @sshwire.SshBuf::new()
  open_confirm_buf.feed(open_confirm_reply)
  let open_confirm_parsed = match open_confirm_buf.try_parse() {
    Some(p) => p
    None => abort("channel_open_confirm parse failed")
  }
  if open_confirm_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_OPEN_CONFIRMATION {
    abort("open_confirm: expected 0x5b got")
  }
  let (_, remote_channel, _, _) = parse_channel_open_confirmation_payload(
    open_confirm_parsed.payload,
  )

  // ---- 5. CHANNEL_REQUEST exec ----
  let exec_payload = channel_request_exec_payload(0, command)
  let exec_wire = @sshwire.make_packet(
    @sshwire.SSH_MSG_CHANNEL_REQUEST,
    exec_payload,
  )
  sock.send(exec_wire)

  // ---- 6. 收 CHANNEL_SUCCESS + DATA + EOF + exit-status + CLOSE ----
  // 6.1 CHANNEL_SUCCESS
  let success_reply = sock.read_n(server_packets[6].length())
  let success_buf = @sshwire.SshBuf::new()
  success_buf.feed(success_reply)
  let success_parsed = match success_buf.try_parse() {
    Some(p) => p
    None => abort("channel_success parse failed")
  }
  if success_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_SUCCESS {
    abort("channel_success: expected 0x63 got")
  }
  // 6.2 CHANNEL_DATA
  let data_reply = sock.read_n(server_packets[7].length())
  let data_buf = @sshwire.SshBuf::new()
  data_buf.feed(data_reply)
  let data_parsed = match data_buf.try_parse() {
    Some(p) => p
    None => abort("channel_data parse failed")
  }
  if data_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_DATA {
    abort("channel_data: expected 0x5e got")
  }
  let (_, stdout_bytes) = parse_channel_data_payload(data_parsed.payload)
  // 6.3 CHANNEL_EOF
  let eof_reply = sock.read_n(server_packets[8].length())
  let eof_buf = @sshwire.SshBuf::new()
  eof_buf.feed(eof_reply)
  let eof_parsed = match eof_buf.try_parse() {
    Some(p) => p
    None => abort("channel_eof parse failed")
  }
  if eof_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_EOF {
    abort("channel_eof: expected 0x5f got")
  }
  // 6.4 CHANNEL_REQUEST exit-status
  let exit_reply = sock.read_n(server_packets[9].length())
  let exit_buf = @sshwire.SshBuf::new()
  exit_buf.feed(exit_reply)
  let exit_parsed = match exit_buf.try_parse() {
    Some(p) => p
    None => abort("exit_status parse failed")
  }
  if exit_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_REQUEST {
    abort("exit_status: expected 0x62 got")
  }
  let (_, exit_code) = parse_exit_status_payload(exit_parsed.payload)
  // 6.5 CHANNEL_CLOSE
  let close_reply = sock.read_n(server_packets[10].length())
  let close_buf = @sshwire.SshBuf::new()
  close_buf.feed(close_reply)
  let close_parsed = match close_buf.try_parse() {
    Some(p) => p
    None => abort("channel_close parse failed")
  }
  if close_parsed.msg_type != @sshwire.SSH_MSG_CHANNEL_CLOSE {
    abort("channel_close: expected 0x60 got")
  }

  // ---- 7. stdout bytes → ASCII string ----
  let stdout_str = bytes_to_ascii_string(stdout_bytes)

  let sent = sock.sent_bytes()
  sock.close()
  let recv = concat_long([
    userauth_success_reply, open_confirm_reply, success_reply, data_reply,
    eof_reply, exit_reply, close_reply,
  ])
  (sent, recv, stdout_str, exit_code, remote_channel)
}

///|
/// FixedArray[Byte] (ASCII) → String (loop, byte-exact)
fn bytes_to_ascii_string(bytes : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < bytes.length(); i = i + 1 {
    sb.write_char(bytes[i].to_int().unsafe_to_char())
  }
  sb.to_string()
}