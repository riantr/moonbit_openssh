///|
/// SSH-WASM-SSH Demo (Loop #19):
///   - Loop #17:SSH crypto demo (4 target byte-exact)
///   - Loop #18:+ SSH wire framing + mock client flow (unencrypted)
///   - Loop #19:+ NEWKEYS 后 chacha20-poly1305@openssh.com 真实加密 (Aead mode)

///|
/// 输出 12 行 hex dump,跨 4 target byte-exact
fn main {
  // ---- RFC 7748 §5.2 Alice/Bob scalar (deterministic client/server 私钥) ----
  let alice_priv : FixedArray[Byte] = [
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51,
    0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77,
    0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  ]
  let bob_priv : FixedArray[Byte] = [
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec,
    0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc9, 0x5b, 0xa9, 0xd6, 0x18, 0x5f, 0x77,
    0xbb, 0x6c, 0xed, 0x27, 0x9d, 0x4a,
  ]
  let base_point : FixedArray[Byte] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0,
  ]
  let alice_pub : FixedArray[Byte] = @x25519.x25519(alice_priv, base_point)
  let bob_pub : FixedArray[Byte] = @x25519.x25519(bob_priv, base_point)
  let shared_k : FixedArray[Byte] = @x25519.x25519(alice_priv, bob_pub)

  // ---- Loop #17/18 KEXINIT + KEXECDH_INIT ----
  let cookie : FixedArray[Byte] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
    0x0e, 0x0f, 0x10,
  ]
  let prop = @kexflow.Proposal::default_client(false)
  let ic_payload : FixedArray[Byte] = @kexflow.kexinit_payload(cookie, prop)
  let started = @kexflow.flow_start(
    @kexflow.FlowConfig::make(
      ascii_bytes("SSH-2.0-MoonBit"),
      ascii_bytes("SSH-2.0-OpenSSH_8.4"),
      cookie,
      alice_priv,
      false,
      "demo",
      22,
      [],
    ),
    prop,
  )

  // ---- Loop #18 SSH wire framing roundtrip ----
  let test_payload : FixedArray[Byte] = FixedArray::from_array([
    0x14, 0x14, 0x02, 0x03, 0x04,
  ])
  let test_packet = @sshwire.make_packet(b'\x14', test_payload)
  let buf = @sshwire.SshBuf::new()
  buf.feed(test_packet)
  let parsed = match buf.try_parse() {
    Some(p) => p
    None => abort("parse failed")
  }
  if parsed.msg_type != b'\x14' {
    abort("msg_type mismatch")
  }

  // ---- Loop #19 NEWKEYS 后 chacha20-poly1305 真实加密 ----
  let mock_responses : Array[FixedArray[Byte]] = [
    // [0]: server version string (12 bytes "SSH-2.0-X\r\n")
    FixedArray::from_array([
      0x53, 0x53, 0x48, 0x2d, 0x32, 0x2e, 0x30, 0x2d, 0x58, 0x0d, 0x0a, 0x00,
    ]),
  ]
  let (sent_bytes, _, userauth_wire_len, open_wire_len, exec_wire_len) = @sshclient.ssh_client_run(
    "SSH-2.0-MoonBit", "moonbit", "echo hello", mock_responses,
  )

  // ---- 12. 输出 hex dump (byte-exact) ----
  println("=== SSH-WASM Demo (Loop #20) ===")
  println("client_pub: " + to_hex_str(alice_pub))
  println("server_pub: " + to_hex_str(bob_pub))
  println("shared_K: " + to_hex_str(shared_k))
  println("kexinit_len: " + ic_payload.length().to_string())
  println("kexinit_head16: " + to_hex_str(slice_first(ic_payload, 16)))
  println("kexdh_init_len: " + started.init_msg.length().to_string())
  println("kexdh_init: " + to_hex_str(started.init_msg))
  println("packet_test_len: " + test_packet.length().to_string())
  println("userauth_wire_len: " + userauth_wire_len.to_string())
  println("channel_open_wire_len: " + open_wire_len.to_string())
  println("channel_exec_wire_len: " + exec_wire_len.to_string())
  println("client_sent_total: " + sent_bytes.length().to_string())
}

///|
/// ASCII string → FixedArray[Byte]
fn ascii_bytes(s : String) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    arr[i] = s[i].to_byte()
  }
  arr
}

///|
/// 取前 N 字节
fn slice_first(b : FixedArray[Byte], n : Int32) -> FixedArray[Byte] {
  let len = if b.length() < n { b.length() } else { n }
  let out : FixedArray[Byte] = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = b[i]
  }
  out
}

///|
/// FixedArray[Byte] → lowercase hex string
let hex_chars : String = "0123456789abcdef"

///|
fn to_hex_str(arr : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < arr.length(); i = i + 1 {
    let h = arr[i].to_uint() / 16U
    let l = arr[i].to_uint() % 16U
    let h_c = hex_chars.unsafe_substring(
      start=h.reinterpret_as_int(),
      end=h.reinterpret_as_int() + 1,
    )
    let l_c = hex_chars.unsafe_substring(
      start=l.reinterpret_as_int(),
      end=l.reinterpret_as_int() + 1,
    )
    sb.write_string(h_c)
    sb.write_string(l_c)
  }
  sb.to_string()
}
