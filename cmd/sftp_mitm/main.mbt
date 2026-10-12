///| The MoonBit end of a man-in-the-middle SFTP session
///|
///| Package header for why this exists. The short version: Loops #41-M2 and
///| #43 drove ten malformed replies into `SftpSession` and into `ChanState`,
///| and neither can reach a transport adapter, because `run_sftp_session` is
///| private and starts from a post-authentication session state. So
///| `host/sftp_mitm.py` performs a real handshake and then misbehaves, and
///| this drives the real `live_sftp` against it.
///|
///| The claim under test is that **the SFTP layer cannot tell where the bytes
///| came from**. The expectations are the same vector table the other two
///| gates use, unchanged. A difference here would be in the transport, which
///| is the one layer nothing else reaches.

// ---------------------------------------------------------------------------
// hex
// ---------------------------------------------------------------------------

fn hex_nibble(c : UInt16) -> Int {
  let n = c.to_int()
  if n >= 48 && n <= 57 {
    return n - 48
  }
  if n >= 97 && n <= 102 {
    return n - 87
  }
  abort("bad hex digit")
}

fn hex_to_bytes(s : String) -> FixedArray[Byte] {
  let n = s.length() / 2
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s[i * 2])
    let lo = hex_nibble(s[i * 2 + 1])
    out[i] = ((hi << 4) | lo).to_byte()
  }
  out
}

const HEXCHARS : String = "0123456789abcdef"

fn to_hex(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_string(
      HEXCHARS.unsafe_substring(start=v / 16, end=v / 16 + 1) +
      HEXCHARS.unsafe_substring(start=v % 16, end=v % 16 + 1),
    )
  }
  sb.to_string()
}

// ---------------------------------------------------------------------------
// rendering, identical to cmd/sftp_test and cmd/sftp_fault
// ---------------------------------------------------------------------------

fn opt_int(v : Int?) -> String {
  match v {
    None => "-"
    Some(x) => x.to_string()
  }
}

fn opt_u64(v : UInt64?) -> String {
  match v {
    None => "-"
    Some(x) => @sftp.sftp_u64_to_int(x).to_string()
  }
}

fn render_attrs(a : @sftp.SftpAttrs) -> String {
  let is_dir = match a.permissions {
    Some(p) => (p & 0xF000) == 0x4000
    None => false
  }
  "size=" + opt_u64(a.size) +
  ",uid=" + opt_int(a.uid) +
  ",gid=" + opt_int(a.gid) +
  ",perm=" + opt_int(a.permissions) +
  ",isdir=" + (if is_dir { "1" } else { "0" })
}

fn msg_ascii(msg : String) -> FixedArray[Byte] {
  let out : Array[Byte] = []
  for i = 0; i < msg.length(); i = i + 1 {
    out.push(msg[i].to_byte())
  }
  let fa : FixedArray[Byte] = FixedArray::make(out.length(), b'\x00')
  for i = 0; i < out.length(); i = i + 1 {
    fa[i] = out[i]
  }
  fa
}

fn render_result(r : @sftp.SftpOpResult) -> String {
  match r {
    RealpathOk(p) => "realpath=" + to_hex(@sftp.sftp_ascii(p))
    Attrs(a) => "attrs=" + render_attrs(a)
    Listing(entries) => {
      let sb = StringBuilder()
      sb.write_string("listing=")
      for i = 0; i < entries.length(); i = i + 1 {
        if i > 0 {
          sb.write_char(';')
        }
        let e = entries[i]
        sb.write_string("name=")
        sb.write_string(to_hex(@sftp.sftp_ascii(e.0)))
        sb.write_string(":size=")
        sb.write_string(e.1.to_string())
        sb.write_string(":dir=")
        sb.write_string(if e.2 { "1" } else { "0" })
      }
      sb.to_string()
    }
    Contents(b) => "contents=" + to_hex(b)
    Wrote(n) => "wrote=" + n.to_string()
    Changed => "changed"
    Failed(code, msg) =>
      "failed=code=" + code.to_string() + ":msg=" + to_hex(msg_ascii(msg))
  }
}

fn exec_error_name(e : @sshclient.ExecError) -> String {
  match e {
    NoSessionState => "NoSessionState"
    SubsystemRejected => "SubsystemRejected"
    SendFailed => "SendFailed"
    BadPacket(w) => "BadPacket(" + w + ")"
    Closed => "Closed"
    _ => "ExecError"
  }
}

///| The transport's own failure vocabulary, rendered. `Protocol(w)` is the one
///| that matters here: it is the session's `failure_reason` handed up through
///| the adapter, and it is how a malformed reply becomes a reportable outcome
///| instead of a hang.
fn sftp_error_name(e : @sshclient.SftpError) -> String {
  match e {
    AuthFailed(a) => "AuthFailed(" + auth_error_name(a) + ")"
    ChannelFailed(c) => "ChannelFailed(" + exec_error_name(c) + ")"
    Protocol(w) => "Protocol(" + w + ")"
    TooManyPackets => "TooManyPackets"
    Closed => "Closed"
  }
}

fn auth_error_name(e : @sshclient.AuthError) -> String {
  match e {
    _ => "AuthError"
  }
}

// ---------------------------------------------------------------------------
// one scenario over a real socket
// ---------------------------------------------------------------------------

fn ops_of(c : FaultCase) -> Array[@sftp.SftpOp] {
  let ops : Array[@sftp.SftpOp] = []
  for i = 0; i < c.ops.length(); i = i + 1 {
    let o = c.ops[i]
    ops.push(
      match o.kind {
        0 => @sftp.SftpOp::Realpath(o.path)
        1 => @sftp.SftpOp::Stat(o.path)
        4 => @sftp.SftpOp::WriteFile(o.path, hex_to_bytes(o.arg))
        _ => @sftp.SftpOp::Rename(o.path, o.arg)
      },
    )
  }
  ops
}

///| A throwaway ECDSA private scalar.
///
///| The man in the middle accepts any public key -- see its module header --
///| so this key exists only to get through the door. It is the same published
/// test key `cmd/ssh_live` uses, and **must never** be used anywhere else.
fn test_auth_key() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67,
    0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A,
    0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///| Run one scenario and print its verdict in the shape `host/verify_loop45.mjs`
///| parses. One scenario per process invocation, because each one needs its
///| own MITM listening on its own port -- and because a process that dies on
///| a hang should take only that scenario with it.
fn run_one(port : Int, c : FaultCase) -> Unit {
  println("scenario: " + c.name)
  println("intent: " + c.intent)
  println("port: " + port.to_string())
  let conn = match @tcp.TcpConn::connect("127.0.0.1", port) {
    None => {
      println("result: CONNECT_FAILED")
      return
    }
    Some(x) => x
  }
  println("connected: true")
  let outcome = @sshclient.live_sftp(
    conn,
    test_auth_key(),
    "probe",
    test_auth_key(),
    ops_of(c),
    // Loop #48: 固定是可选的,这里不传 known_hosts。这个门禁测的是 SFTP 层对
    // 畸形应答的反应,不是主机密钥固定;把策略换成 strict 会让十个场景全在握手
    // 阶段就失败,而那与被测的东西无关。
    @knownhosts.KnownHostsPolicy::skip(),
  )
  match outcome {
    Done(r) => {
      println("outcome: done")
      println("version: " + r.version.to_string())
      println("extensions: " + r.extensions.to_string())
      println("requests_sent: " + r.requests_sent.to_string())
      println("replies_recv: " + r.replies_recv.to_string())
      println("sftp_bytes_in: " + r.sftp_bytes_in.to_string())
      for i = 0; i < r.ops.length(); i = i + 1 {
        println("op" + i.to_string() + ": " + render_result(r.ops[i]))
      }
    }
    Failed(e) => {
      println("outcome: failed")
      println("error: " + sftp_error_name(e))
    }
  }
  conn.close()
}

fn main {
  let argv = @env.args()
  // `moon run cmd/sftp_mitm -- a b` puts the user's arguments after the
  // executable; under the js backend argv would carry `node` and the script
  // path first. This package is native-only, so one skip is correct -- and
  // stating it is cheaper than the day it is not.
  let args : Array[String] = []
  for i = 1; i < argv.length(); i = i + 1 {
    args.push(argv[i])
  }
  if args.length() < 2 {
    println("usage: sftp_mitm <port> <scenario>")
    println("  scenarios:")
    for i = 0; i < fault_cases.length(); i = i + 1 {
      println("    " + fault_cases[i].name)
    }
    return
  }
  let port = parse_port(args[0])
  run_one(port, find_case(args[1]))
}

fn find_case(name : String) -> FaultCase {
  for i = 0; i < fault_cases.length(); i = i + 1 {
    if fault_cases[i].name == name {
      return fault_cases[i]
    }
  }
  abort("unknown scenario: " + name)
}

///| A bare decimal port, or `abort`. Deliberately not a general parser: the
///| standard library's integer parsing surface has moved between MoonBit
///| releases, and this driver only ever takes five digits.
fn parse_port(s : String) -> Int {
  let mut n = 0
  for i = 0; i < s.length(); i = i + 1 {
    let c = s[i].to_int()
    if c < 48 || c > 57 {
      abort("port is not a bare number: " + s)
    }
    n = n * 10 + (c - 48)
  }
  n
}
