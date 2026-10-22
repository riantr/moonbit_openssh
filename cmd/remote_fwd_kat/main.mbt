///| cmd/remote_fwd_kat -- Loop #78: the `ssh -R` half, byte for byte.
///

///|
/// Prints the exact bytes this client puts on the wire (and how it decodes
/// the ones it receives), one line per case:
///
///     REQ     <label> <hex>    -- the "tcpip-forward" GLOBAL_REQUEST payload
///     CONFIRM <label> <hex>    -- the CHANNEL_OPEN_CONFIRMATION payload
///     FAIL    <label> <hex>    -- the CHANNEL_OPEN_FAILURE payload
///     PARSE   <label> <type> <sender> <window> <max_packet>
///             <host> <port> <originator_ip> <originator_port>
///
/// The expected lines come from `host/gen_remote_fwd_vectors.py`, which builds
/// and decodes them with **paramiko's own encoder and decoder** -- an
/// implementation that shares no code with this repository.
///
/// Why pin the bytes when a real server accepts them anyway: the server is
/// *tolerant* about the fields it does not use. A layout that is right where
/// the server looks and wrong where it does not would pass every end-to-end
/// test and still be a wrong wire format. Pinning the whole payload is what
/// catches that.
///
/// The PARSE case is the one that settles a question the RFC leaves open:
/// the u32 in a "forwarded-tcpip" open is the port the server was
/// **listening** on, not the ephemeral port of the accepted connection. P1's
/// bytes are the ones a real OpenSSH 8.0p1 server actually sent.
///

///|
fn main {
  // ---- REQ: the "tcpip-forward" request ----
  // R1 asks for port 0 (the server allocates one and says so in the reply);
  // R2 names a port; R3 names an address as well.
  emit_req("R1", "", 0)
  emit_req("R2", "localhost", 23456)
  emit_req("R3", "127.0.0.1", 65535)
  // ---- CONFIRM: we answer the server's channel open ----
  // C1 is the shape this client actually sends: the recipient is the
  // SERVER's channel number, the sender is ours.
  emit_confirm("C1", 2, 0, 2097152, 32768)
  emit_confirm("C2", 0, 7, 64, 32)
  // C3 用 -1 当作 0xffffffff:这个 moon 版本的 Int32 装不下 4294967295,
  // 而线上那一位就是要「全 1」。reinterpret_as_uint 把 -1 变成 0xffffffff,
  // 和 paramiko 的 add_int(-1) 编码出来的四个字节一样。
  emit_confirm("C3", -1, 1, 0, 0)
  // ---- FAIL: we refuse a channel we did not ask for ----
  emit_fail("F1", 2, 1, "unsupported channel type: x11", "")
  emit_fail(
    "F2", 0, 1, "forwarded channel does not match the requested listener", "",
  )
  // ---- PARSE: the opens the server sends us ----
  // P1 is the real server's bytes (captured by host/remote_fwd_capture.py).
  emit_parse(
    "P1",
    // string "forwarded-tcpip"
    "0000000f666f727761726465642d7463706970" +
    // uint32 sender channel = 2
    "00000002" +
    // uint32 initial window = 2 MiB
    "00200000" +
    // uint32 max packet = 32 KiB
    "00008000" +
    // string host = ""
    "00000000" +
    // uint32 port = 65113 (the LISTEN port)
    "0000fe59" +
    // string originator ip
    "000000093132372e302e302e31" +
    // uint32 originator port = 65114
    "0000fe5a",
  )
  emit_parse(
    "P2",
    // string "direct-tcpip"
    "0000000c6469726563742d7463706970" +
    // uint32 sender channel
    "00000000" +
    // uint32 initial window
    "00200000" +
    // uint32 max packet
    "00008000" +
    // string host
    "0000000b6578616d706c652e636f6d" +
    // uint32 port
    "0000c350" +
    // string originator ip
    "0000000831302e302e302e31" +
    // uint32 originator port
    "00003039",
  )
  emit_parse(
    "P3",
    // string "session"
    "0000000773657373696f6e" +
    // uint32 sender channel
    "00000000" +
    // uint32 initial window
    "00200000" +
    // uint32 max packet
    "00008000",
  )
}

///|
/// One request, one line.
fn emit_req(label : String, listen_host : String, listen_port : Int32) -> Unit {
  let payload = @channel.tcpip_forward_request_payload(listen_host, listen_port)
  println("REQ " + label + " " + @ecdsa.bytes_to_hex(payload))
}

///|
/// One confirmation, one line.
fn emit_confirm(
  label : String,
  recipient : Int32,
  sender : Int32,
  window : Int32,
  max_packet : Int32,
) -> Unit {
  let payload = @channel.channel_open_confirmation_payload(
    recipient, sender, window, max_packet,
  )
  println("CONFIRM " + label + " " + @ecdsa.bytes_to_hex(payload))
}

///|
/// One refusal, one line.
fn emit_fail(
  label : String,
  recipient : Int32,
  reason : Int32,
  description : String,
  language : String,
) -> Unit {
  let payload = @channel.channel_open_failure_payload(
    recipient, reason, description, language,
  )
  println("FAIL " + label + " " + @ecdsa.bytes_to_hex(payload))
}

///|
/// One decode, one line. 解析不出来就打印一行 `PARSE <label> none`,而**不是**
/// 什么都不打印——那样门禁只会看到「少了一行」,不知道是解析器错了还是
/// 这个用例本来就不该有输出。
fn emit_parse(label : String, hex : String) -> Unit {
  let raw = hex_to_bytes(hex)
  match @channel.parse_channel_open(raw) {
    None => println("PARSE " + label + " none")
    Some(o) =>
      println(
        "PARSE " +
        label +
        " " +
        o.ctype +
        " " +
        o.sender.to_string() +
        " " +
        o.window.to_string() +
        " " +
        o.max_packet.to_string() +
        " " +
        o.host +
        " " +
        o.port.to_string() +
        " " +
        o.originator_ip +
        " " +
        o.originator_port.to_string(),
      )
  }
}

///|
/// 16 进制字符串转 FixedArray[Byte]。
///
/// 自己写一份而不是从别处借:借来的那个在某些包里对非法字符直接 abort,
/// 而这里只需要「合法输入」这一种情况。
fn hex_to_bytes(hex : String) -> FixedArray[Byte] {
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut i = 0
  while i < n {
    arr[i] = parse_byte(hex[i * 2], hex[i * 2 + 1])
    i = i + 1
  }
  arr
}

///|
fn parse_byte(hi : UInt16, lo : UInt16) -> Byte {
  let h : Int32 = hex_digit(hi)
  let l : Int32 = hex_digit(lo)
  ((h * 16 + l).reinterpret_as_uint() & 0xFFU).to_byte()
}

///|
/// 一个十六进制字符的值
fn hex_digit(c : UInt16) -> Int32 {
  let code : Int32 = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    0
  }
}
