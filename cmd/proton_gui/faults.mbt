///| Driving `src/sftp`'s state machine from bytes that OpenSSH never sends

///|

///| The driver contract is `SftpSession`'s, unchanged from `cmd/sftp_test`:

///|

///|     let s = SftpSession::new(ops)

///|     loop: take_out -> pump -> feed(chunk)

///|     until s.done() or s.failed()

///|

///| What is different from the KAT is the input. Every feed here is a reply
/// that a correct `internal-sftp` would never produce, and each scenario
/// names the branch of `src/sftp/session.mbt` it is aimed at. That is the
/// part of the state machine the Loop #39 capture and the Loop #40 live
/// round trip structurally *cannot* reach: both talk to a real server, and a
/// real server does not send a STATUS before VERSION or claim a length over
/// `SFTP_MAX_MSG_LENGTH`.
///

///| The expected transcript comes from `host/sftp_fault_oracle.py`, not from

///|
/// this file, so a scenario cannot pass by agreeing with itself.

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
    // `unsafe_to_char(0)` would be NUL, not '0'.
    sb.write_string(
      HEXCHARS.unsafe_substring(start=v / 16, end=v / 16 + 1) +
      HEXCHARS.unsafe_substring(start=v % 16, end=v % 16 + 1),
    )
  }
  sb.to_string()
}

// ---------------------------------------------------------------------------
// rendering one result, exactly as `cmd/sftp_test` renders it
// ---------------------------------------------------------------------------

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

///|
fn render_attrs(a : @sftp.SftpAttrs) -> String {
  let is_dir = match a.permissions {
    Some(p) => (p & 0xF000) == 0x4000
    None => false
  }
  "size=" +
  opt_u64(a.size) +
  ",uid=" +
  opt_int(a.uid) +
  ",gid=" +
  opt_int(a.gid) +
  ",perm=" +
  opt_int(a.permissions) +
  ",isdir=" +
  (if is_dir { "1" } else { "0" })
}

///| The one rendering both this console and the KAT use, so a result that

///|
/// differs between them is a real difference rather than a formatting one.
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
      // `src/sftp` keeps the STATUS message as decoded text (`bytes_text`,
      // latin-1). Re-encoding it through `sftp_ascii` is therefore *not* a
      // byte round trip -- `sftp_ascii` re-encodes as UTF-8 -- so the message
      // is rendered through the same hex-of-the-bytes path the KAT uses and
      // compared as text here instead. Both sides render the same field the
      // same way, which is what the comparison needs; it is the *status code*
      // and the *requests on the wire* that this suite exists to pin.
      "failed=code=" + code.to_string() + ":msg=" + to_hex(msg_ascii(msg))
  }
}

///| latin-1 bytes as a hex string, the same mapping `src/sftp`'s `bytes_text`

///| uses in the other direction. Written out rather than going through

///| `String` so a message with a byte above 0x7F does not silently become

///|
/// two UTF-8 bytes.
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

// ---------------------------------------------------------------------------
// one scenario
// ---------------------------------------------------------------------------

///|
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

///|
/// What one run produced.
pub(all) struct Run {
  requests : Array[String]
  results : Array[String]
  done : Bool
  failed : Bool
  reason : String
  version : Int32
  extensions : Int32
  ext_names : Array[String]
}

///|
fn run_case(c : FaultCase) -> Run {
  let sess = @sftp.SftpSession::new(ops_of(c))
  let sent : Array[String] = []
  let mut ci = 0
  let mut rounds = 0
  while rounds < 4000 {
    rounds = rounds + 1
    let out = sess.take_out()
    for i = 0; i < out.length(); i = i + 1 {
      sent.push(to_hex(out[i]))
    }
    // `pump` after `take_out` as well as before the next `feed`: a reply may
    // already be buffered while the channel has nothing left, and stopping
    // there is how a client waits forever for a packet it already has.
    sess.pump()
    if sess.done() || sess.failed() {
      break
    }
    if ci >= c.feeds.length() {
      break
    }
    sess.feed(hex_to_bytes(c.feeds[ci]))
    ci = ci + 1
  }
  let tail = sess.take_out()
  for i = 0; i < tail.length(); i = i + 1 {
    sent.push(to_hex(tail[i]))
  }
  let results : Array[String] = []
  let rs = sess.results_of()
  for i = 0; i < rs.length(); i = i + 1 {
    results.push(render_result(rs[i]))
  }
  Run::{
    requests: sent,
    results,
    done: sess.done(),
    failed: sess.failed(),
    reason: sess.failure_reason(),
    version: sess.version_of(),
    extensions: sess.extensions_of(),
    ext_names: sess.extension_names(),
  }
}

// ---------------------------------------------------------------------------
// judging one scenario
// ---------------------------------------------------------------------------

///|
fn eq_arrays(
  got : Array[String],
  want : Array[String],
  label : String,
  fails : Array[String],
) -> Unit {
  if got.length() != want.length() {
    fails.push(
      label +
      ": " +
      got.length().to_string() +
      " != expected " +
      want.length().to_string() +
      "\n      got  [" +
      got.join(",") +
      "]\n      want [" +
      want.join(",") +
      "]",
    )
    return
  }
  for i = 0; i < want.length(); i = i + 1 {
    if got[i] != want[i] {
      fails.push(
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
fn judge(c : FaultCase, r : Run) -> Array[String] {
  let fails : Array[String] = []
  eq_arrays(r.requests, c.requests, c.name + ": requests", fails)
  eq_arrays(r.results, c.results, c.name + ": results", fails)
  if r.done != c.expect_done {
    fails.push(
      c.name +
      ": done=" +
      r.done.to_string() +
      " expected " +
      c.expect_done.to_string(),
    )
  }
  if r.failed != c.expect_failed {
    fails.push(
      c.name +
      ": failed=" +
      r.failed.to_string() +
      " expected " +
      c.expect_failed.to_string() +
      " (" +
      r.reason +
      ")",
    )
  }
  if c.expect_reason != "" && r.reason != c.expect_reason {
    fails.push(
      c.name +
      ": reason \"" +
      r.reason +
      "\" expected \"" +
      c.expect_reason +
      "\"",
    )
  }
  fails
}

///|
fn find_case(name : String) -> FaultCase? {
  for i = 0; i < fault_cases.length(); i = i + 1 {
    if fault_cases[i].name == name {
      return Some(fault_cases[i])
    }
  }
  None
}

///|
/// Run one scenario by name and return its verdict lines.
pub fn run_named(name : String) -> (Bool, Array[String], Run, FaultCase) {
  match find_case(name) {
    None => {
      let names : Array[String] = []
      for i = 0; i < fault_cases.length(); i = i + 1 {
        names.push(fault_cases[i].name)
      }
      (
        false,
        ["unknown scenario \"" + name + "\"; known: " + names.join(", ") + "\n"],
        Run::{
          requests: [],
          results: [],
          done: false,
          failed: false,
          reason: "",
          version: 0,
          extensions: 0,
          ext_names: [],
        },
        FaultCase::{
          name,
          intent: "",
          ops: [],
          feeds: [],
          requests: [],
          results: [],
          expect_done: false,
          expect_failed: false,
          expect_reason: "",
          // Present for parity with the generated table; the console has no
          // cut points of its own, it feeds whole payloads.
          chop_sizes: [],
        },
      )
    }
    Some(c) => {
      let r = run_case(c)
      let fails = judge(c, r)
      (fails.length() == 0, fails, r, c)
    }
  }
}

///| Run every scenario.
///

///| Returns `(passed, failures, notes)`. `passed` is counted after the loop

///| rather than carried in a mutable cell: `Array` is reference-semantic in

///| MoonBit, so a counter box would work, but a second pass over the notes is

///|
/// cheaper than explaining the box.
pub fn run_all() -> (Int32, Array[String], Array[String]) {
  let fails : Array[String] = []
  let notes : Array[String] = []
  for i = 0; i < fault_cases.length(); i = i + 1 {
    let c = fault_cases[i]
    let r = run_case(c)
    let cf = judge(c, r)
    if cf.length() == 0 {
      notes.push("PASS  " + c.name)
    } else {
      notes.push("FAIL  " + c.name + "  (" + c.intent + ")")
      for j = 0; j < cf.length(); j = j + 1 {
        fails.push(cf[j])
      }
    }
  }
  let mut passed = 0
  for i = 0; i < notes.length(); i = i + 1 {
    if notes[i].has_prefix("PASS") {
      passed = passed + 1
    }
  }
  (passed, fails, notes)
}

///|
/// A one-line summary per scenario, for the HTML panel.
pub fn case_names() -> Array[String] {
  let out : Array[String] = []
  for i = 0; i < fault_cases.length(); i = i + 1 {
    out.push(fault_cases[i].name)
  }
  out
}

///|
pub fn case_intent(name : String) -> String {
  match find_case(name) {
    None => ""
    Some(c) => c.intent
  }
}
