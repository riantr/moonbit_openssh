///| cmd/sftp_test -- Loop #39 SFTP v3, byte-exact against a real server

///|

///| Four layers, and the fourth is the one that matters:
///

///|  1. the frames we emit must equal `host/sftp_oracle.py`'s, which was

///|     cross-checked against the requests paramiko actually framed in the

///|     same session as the capture;
///  2. the replies we parse must be real OpenSSH 8.0p1 `internal-sftp`

///|     bytes, so a mis-numbered message type or a wrongly placed field

///|     shows up as a wrong result rather than as a plausible one;

///|  3. CHANNEL_DATA boundaries are chosen by the vector, not by the server,

///|     because they are unrelated to SFTP packet boundaries and the whole

///|     reason `SftpInbuf` exists;
///  4. results are rendered to one line each and compared as strings, so the

///|     Python oracle and this file have to agree about what a directory

///|     listing *is* -- not merely about how many bytes arrived.
///

///| Depends on `src/sftp` only, which reaches neither `src/tcp` nor `src/wt`,

///| so the whole KAT runs on all four backends in both modes.
///

///| Three reply shapes this file is built around, all of them from the

///| capture rather than from the draft:
///

///|  - the reply numbers are 101 STATUS / 102 HANDLE / 103 DATA / 104 NAME /

///|    105 ATTRS.  Sorted by *name* the same five numbers read

///|    101 DATA / 102 HANDLE / 103 NAME / 104 ATTRS / 105 STATUS, which is

///|    what an implementer writes down from memory -- and a parser built on

///|    that ordering accepts every reply it is fed.

///|  - VERSION carries extension pairs after the version number (six on this

///|    server), so end-of-packet after the version is simply wrong.

///|  - STATUS carries a language tag after the message, so `expect_end`

///|
///    before reading it fails on every STATUS a real server sends.

// ---------------------------------------------------------------------------
// hex helpers
// ---------------------------------------------------------------------------

fn hex_nibble(c : UInt16) -> Int32 {
  let n = c.to_int()
  if n >= 48 && n <= 57 {
    return n - 48
  }
  if n >= 97 && n <= 102 {
    return n - 87
  }
  abort("bad hex digit")
}

///|
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

///|
const HEXCHARS : String = "0123456789abcdef"

///|
fn to_hex(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    // `unsafe_to_char(0)` would be NUL, not '0': the hex alphabet is ASCII, so
    // the digit has to come from the alphabet rather than from the code point.
    sb.write_string(
      HEXCHARS.unsafe_substring(start=v / 16, end=v / 16 + 1) +
      HEXCHARS.unsafe_substring(start=v % 16, end=v % 16 + 1),
    )
  }
  sb.to_string()
}

///|
/// 把字符串按字节取出来,用于 realpath / 消息文本的十六进制渲染
fn bytes_of(s : String) -> FixedArray[Byte] {
  @sftp.sftp_ascii(s)
}

///|
fn opt_int(v : Int32?) -> String {
  match v {
    None => "-"
    Some(x) => x.to_string()
  }
}

///|
fn opt_u64(v : UInt64?) -> String {
  match v {
    None => "-"
    Some(x) => @sftp.sftp_u64_to_int(x).to_string()
  }
}

// ---------------------------------------------------------------------------
// rendering one result, the way `host/sftp_oracle.py` renders it
// ---------------------------------------------------------------------------

///|
fn render_attrs(a : @sftp.SftpAttrs) -> String {
  let is_dir = match a.permissions {
    Some(p) => (p & 0xF000) == 0x4000
    None => false
  }
  let dir = if is_dir { "1" } else { "0" }
  "size=" +
  opt_u64(a.size) +
  ",uid=" +
  opt_int(a.uid) +
  ",gid=" +
  opt_int(a.gid) +
  ",perm=" +
  opt_int(a.permissions) +
  ",isdir=" +
  dir
}

///|
fn render_result(r : @sftp.SftpOpResult) -> String {
  match r {
    RealpathOk(p) => "realpath=" + to_hex(bytes_of(p))
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
        sb.write_string(to_hex(bytes_of(e.0)))
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
      "failed=code=" + code.to_string() + ":msg=" + to_hex(bytes_of(msg))
  }
}

// ---------------------------------------------------------------------------
// one case
// ---------------------------------------------------------------------------

///| 驱动一次会话:pump → 取请求 → 喂下一个 chunk,直到完成、失败或字节用尽。
///

///| `pump` 在 `take_out` **之后**、下一轮 `feed` 之前都调,是因为应答可能已经

///| 躺在重组缓冲里,而通道已经没有东西可读了。少这一次 pump,客户端就会去等一个

///| 它自己已经收到的包。

///| Vector 的属性字段。`-1` 表示**不提这个字段**,和「提到但值是 0」是两种

///|
/// 不同的请求:`chmod 000` 是合法且偶尔想要的,所以不能把它们合并。
fn attrs_of(o : Op) -> @sftp.SftpAttrs {
  let a = @sftp.SftpAttrs::none()
  if o.perms != -1 {
    a.permissions = Some(o.perms)
  }
  if o.atime != -1 {
    a.atime = Some(o.atime)
  }
  if o.mtime != -1 {
    a.mtime = Some(o.mtime)
  }
  a
}

///|
fn run_case(
  c : Case,
) -> (Array[String], Array[String], Bool, Bool, Int32, Int32, String) {
  let ops : Array[@sftp.SftpOp] = []
  for i = 0; i < c.ops.length(); i = i + 1 {
    let o = c.ops[i]
    let op = match o.kind {
      0 => @sftp.SftpOp::Realpath(o.path)
      1 => @sftp.SftpOp::Stat(o.path)
      2 => @sftp.SftpOp::ListDir(o.path)
      3 => @sftp.SftpOp::ReadFile(o.path)
      4 => @sftp.SftpOp::WriteFile(o.path, hex_to_bytes(o.payload))
      5 => @sftp.SftpOp::SetAttrs(o.path, attrs_of(o))
      6 => @sftp.SftpOp::MakeDir(o.path, attrs_of(o))
      7 => @sftp.SftpOp::RemovePath(o.path)
      8 => @sftp.SftpOp::RemoveDir(o.path)
      _ => @sftp.SftpOp::Rename(o.path, o.path2)
    }
    ops.push(op)
  }
  let sess = @sftp.SftpSession::new(ops)
  let sent : Array[String] = []
  let mut ci = 0
  let mut rounds = 0
  let mut done = false
  let mut failed = false
  while rounds < 4000 {
    rounds = rounds + 1
    let out = sess.take_out()
    for i = 0; i < out.length(); i = i + 1 {
      sent.push(to_hex(out[i]))
    }
    sess.pump()
    if sess.done() || sess.failed() {
      break
    }
    if ci >= c.chunks.length() {
      break
    }
    sess.feed(hex_to_bytes(c.chunks[ci]))
    ci = ci + 1
  }
  done = sess.done()
  failed = sess.failed()
  let results : Array[String] = []
  let rs = sess.results_of()
  for i = 0; i < rs.length(); i = i + 1 {
    results.push(render_result(rs[i]))
  }
  (
    sent,
    results,
    done,
    failed,
    sess.version_of(),
    sess.extensions_of(),
    sess.failure_reason(),
  )
}

// ---------------------------------------------------------------------------
// SftpInbuf, directly
// ---------------------------------------------------------------------------

///|
/// 一个 chunk 里两个包,只能在这一层测。
///
/// `SftpSession` 一次只挂一个请求,所以「两个应答挤在一个 CHANNEL_DATA 里」
/// 在会话层**没有**对应物:第二个应答对应的请求,那时还没发出去。把它写成一个
/// 会话用例,等于要求实现忽略先到的应答——那是错的。
///
/// 但缓冲层必须能处理它,因为那是服务器的分组自由:OpenSSH 两侧都用
/// `atomicio6` 循环读满(sftp-client.c:185-204),CHANNEL_DATA 的边界和 SFTP 包
/// 的边界之间没有任何关系。丢第二个包的症状是「文件莫名其妙少一半」,而且只在
/// 某个特定包大小的服务器上出现。
pub(all) struct InbufCase {
  name : String
  feeds : Array[String]
  expect_packets : Array[String]
  expect_pending : Int32
  expect_failed : Bool
}

///|
/// 造一个帧:`uint32 len || body`
fn framed_hex(body : String) -> String {
  let n = body.length() / 2
  let len = to_hex(hex_to_bytes(u32_hex(n)))
  len + body
}

///|
fn u32_hex(n : Int32) -> String {
  to_hex(fixed4(n))
}

///|
fn fixed4(n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  out[0] = ((n >> 24) & 0xFF).to_byte()
  out[1] = ((n >> 16) & 0xFF).to_byte()
  out[2] = ((n >> 8) & 0xFF).to_byte()
  out[3] = (n & 0xFF).to_byte()
  out
}

///|
fn inbuf_cases() -> Array[InbufCase] {
  // Two small, valid packets.  INIT-like and STATUS-like bodies; the buffer
  // does not parse, it only frames, so the contents do not matter here.
  let p1 = "05" + "0100000003"
  let p2 = "0d" + "0400000002000000000000"
  let f1 = framed_hex(p1)
  let f2 = framed_hex(p2)
  [
    {
      name: "two_packets_one_feed",
      feeds: [f1 + f2],
      expect_packets: [p1, p2],
      expect_pending: 0,
      expect_failed: false,
    },
    {
      name: "second_packet_only_after_another_feed",
      feeds: [f1, f2],
      expect_packets: [p1, p2],
      expect_pending: 0,
      expect_failed: false,
    },
    {
      name: "lenprefix_3_1",
      feeds: [f1[:6].to_owned(), f1[6:].to_owned()],
      expect_packets: [p1],
      expect_pending: 0,
      expect_failed: false,
    },
    {
      name: "lenprefix_2_2",
      feeds: [f1[:4].to_owned(), f1[4:].to_owned()],
      expect_packets: [p1],
      expect_pending: 0,
      expect_failed: false,
    },
    {
      name: "trailing_residue_kept",
      // A whole packet and then two bytes that belong to nothing yet.
      feeds: [f1 + "0000"],
      expect_packets: [p1],
      expect_pending: 2,
      expect_failed: false,
    },
    {
      name: "one_byte_at_a_time",
      feeds: [
        f1[:2].to_owned(),
        f1[2:4].to_owned(),
        f1[4:6].to_owned(),
        f1[6:8].to_owned(),
        f1[8:].to_owned(),
      ],
      expect_packets: [p1],
      expect_pending: 0,
      expect_failed: false,
    },
    {
      name: "length_over_max_refused",
      // 0x00100000 = 1 MiB, over SFTP_MAX_MSG_LENGTH (256 KiB).  The refusal
      // has to happen before anything is sized from the field.
      feeds: ["00100000" + "6900000001" + "00000000"],
      expect_packets: [],
      // 4 length bytes + 5 body bytes + 4 more: the refused prefix is *not*
      // consumed, because the buffer never learned what it was part of.
      expect_pending: 13,
      expect_failed: true,
    },
  ]
}

///|
fn run_inbuf(c : InbufCase) -> (Array[String], Int32, Bool) {
  let buf = @sftp.SftpInbuf::new()
  let all : Array[String] = []
  for i = 0; i < c.feeds.length(); i = i + 1 {
    buf.feed(hex_to_bytes(c.feeds[i]))
    let got = buf.drain()
    for j = 0; j < got.length(); j = j + 1 {
      all.push(to_hex(got[j]))
    }
  }
  let failed = match buf.failure() {
    None => false
    Some(_) => true
  }
  (all, buf.pending(), failed)
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

///|
fn check_arrays(
  label : String,
  name : String,
  got : Array[String],
  want : Array[String],
  fails : Array[String],
) -> Unit {
  if got.length() != want.length() {
    fails.push(
      name +
      ": " +
      label +
      " count " +
      got.length().to_string() +
      " != expected " +
      want.length().to_string(),
    )
    return
  }
  for i = 0; i < want.length(); i = i + 1 {
    if got[i] != want[i] {
      fails.push(
        name +
        ": " +
        label +
        "[" +
        i.to_string() +
        "]\n      got  " +
        got[i] +
        "\n      want " +
        want[i],
      )
      return
    }
  }
}

///|
fn main {
  println(
    "SFTP KAT: " +
    cases.length().to_string() +
    " cases from a real OpenSSH internal-sftp capture",
  )
  println(
    "  capture: version " +
    CAPTURE_VERSION.to_string() +
    ", " +
    CAPTURE_EXTENSIONS.to_string() +
    " extension pairs after the version",
  )
  let fails : Array[String] = []
  for i = 0; i < cases.length(); i = i + 1 {
    let c = cases[i]
    let (sent, results, done, failed, ver, exts, why) = run_case(c)
    let case_fails : Array[String] = []
    check_arrays("requests", c.name, sent, c.requests, case_fails)
    check_arrays("results", c.name, results, c.results, case_fails)
    if done != c.expect_done {
      case_fails.push(
        c.name +
        ": done=" +
        done.to_string() +
        " expected " +
        c.expect_done.to_string(),
      )
    }
    if failed != c.expect_failed {
      case_fails.push(
        c.name +
        ": failed=" +
        failed.to_string() +
        " expected " +
        c.expect_failed.to_string() +
        (if why == "" { "" } else { " (" + why + ")" }),
      )
    }
    if c.expect_done {
      if ver != CAPTURE_VERSION {
        case_fails.push(c.name + ": version " + ver.to_string())
      }
      if exts != CAPTURE_EXTENSIONS {
        case_fails.push(
          c.name +
          ": " +
          exts.to_string() +
          " extension pairs, expected " +
          CAPTURE_EXTENSIONS.to_string(),
        )
      }
    }
    if case_fails.length() == 0 {
      println("  PASS  " + c.name)
    } else {
      println("  FAIL  " + c.name + "  (" + c.note + ")")
      for j = 0; j < case_fails.length(); j = j + 1 {
        println("      - " + case_fails[j])
      }
      for j = 0; j < case_fails.length(); j = j + 1 {
        fails.push(case_fails[j])
      }
    }
  }
  // ---- SftpInbuf, directly: the boundaries a serial session cannot reach --
  println("")
  println("SftpInbuf boundaries (SftpInbuf, not SftpSession):")
  let ibs = inbuf_cases()
  for i = 0; i < ibs.length(); i = i + 1 {
    let c = ibs[i]
    let (pkts, pending, failed) = run_inbuf(c)
    let bad : Array[String] = []
    check_arrays("packets", c.name, pkts, c.expect_packets, bad)
    if pending != c.expect_pending {
      bad.push(
        c.name +
        ": pending " +
        pending.to_string() +
        " expected " +
        c.expect_pending.to_string(),
      )
    }
    if failed != c.expect_failed {
      bad.push(
        c.name +
        ": failed=" +
        failed.to_string() +
        " expected " +
        c.expect_failed.to_string(),
      )
    }
    if bad.length() == 0 {
      println("  PASS  " + c.name)
    } else {
      println("  FAIL  " + c.name)
      for j = 0; j < bad.length(); j = j + 1 {
        println("      - " + bad[j])
        fails.push(bad[j])
      }
    }
  }

  if fails.length() == 0 {
    println("")
    println(
      "ALL PASS (" +
      cases.length().to_string() +
      " session cases, " +
      ibs.length().to_string() +
      " inbuf cases)",
    )
  } else {
    // `main` must return Unit, so the verdict is carried by the text -- the
    // same convention `cmd/channel_test` uses and `host/verify_loop39.mjs`
    // greps for.  Each failure line starts with "FAIL".
    println(fails.length().to_string() + " FAILURES")
    for i = 0; i < fails.length(); i = i + 1 {
      println("FAIL " + fails[i])
    }
  }
}
