///| The fake peer, and the invariant it exists to test

///|

///| See the package header for why this is a package at all. The short

///| version: `cmd/proton_gui` feeds malformed bytes straight into

///| `SftpSession::feed`, which proves the state machine. This drives the same

///| vectors through `ChanState` first, which proves the layer the two

///| transports share but that neither of them is allowed to duplicate.
///

///| The peer is a function, not a mock framework: `respond(chan_state,

///| msg_type, payload)` pushes one inbound packet through `chan_step` and

///| returns the new state plus whatever actions the channel wants us to send

///|
/// back. Everything is bytes.

// ---------------------------------------------------------------------------
// hex
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
    sb.write_string(
      HEXCHARS.unsafe_substring(start=v / 16, end=v / 16 + 1) +
      HEXCHARS.unsafe_substring(start=v % 16, end=v % 16 + 1),
    )
  }
  sb.to_string()
}

// ---------------------------------------------------------------------------
// peer-side packet builders
// ---------------------------------------------------------------------------

///|
fn u32b(n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  out[0] = ((n >> 24) & 0xFF).to_byte()
  out[1] = ((n >> 16) & 0xFF).to_byte()
  out[2] = ((n >> 8) & 0xFF).to_byte()
  out[3] = (n & 0xFF).to_byte()
  out
}

///|
fn cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut n = 0
  for i = 0; i < parts.length(); i = i + 1 {
    n = n + parts[i].length()
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut at = 0
  for i = 0; i < parts.length(); i = i + 1 {
    for j = 0; j < parts[i].length(); j = j + 1 {
      out[at] = parts[i][j]
      at = at + 1
    }
  }
  out
}

///|
/// Split `data` into `size`-byte pieces. 0 or less means "leave it alone".
fn chop(data : FixedArray[Byte], size : Int32) -> Array[FixedArray[Byte]] {
  if size <= 0 {
    return [data]
  }
  let out : Array[FixedArray[Byte]] = []
  let mut at = 0
  while at < data.length() {
    let n = if data.length() - at < size { data.length() - at } else { size }
    out.push(sub(data, at, n))
    at = at + n
  }
  out
}

///|
fn sub(data : FixedArray[Byte], at : Int32, n : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = data[at + i]
  }
  out
}

// ---------------------------------------------------------------------------
// driving one session through the channel layer
// ---------------------------------------------------------------------------

///|
const LOCAL_CHANNEL : Int32 = 0

///| The window we advertise to the peer, and the window we give the peer.

///| Large enough that no vector stalls on it -- the window clamp is tested by

///| `cmd/ssh_live`'s write path, and a scenario that deadlocked here would

///|
/// test the fake peer rather than the client.
const PEER_WINDOW : Int32 = 2097152

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
/// One run of one case at one cut point.
pub(all) struct Run {
  requests : Array[String]
  results : Array[String]
  done : Bool
  failed : Bool
  reason : String
}

///|
fn run_case(c : FaultCase, chop_size : Int32) -> Run {
  let sess = @sftp.SftpSession::new(ops_of(c))
  let chan0 = @channel.ChanState::new(LOCAL_CHANNEL)
  // The peer's reassembly buffer for what the client sends us. The client's
  // own inbound buffer lives inside `SftpSession` (`SftpInbuf` is a field of
  // it), which is the point -- there is exactly one place that reassembles
  // inbound SFTP, and this driver goes through it rather than around it.
  let server_in = @sftp.SftpInbuf::new()
  let peer_requests : Array[String] = []
  let mut chan = chan0

  // 1) The client's CHANNEL_OPEN. This fake peer does not parse it -- it
  //    answers the next thing regardless -- but producing it keeps the
  //    client's own ordering exercised.
  ignore(chan.open_action())

  // 2) CHANNEL_OPEN_CONFIRMATION from the peer: this is where `remote_id` and
  //    the peer's window come from, and `stdin_take` needs both.
  let confirm = cat([
    u32b(LOCAL_CHANNEL),
    u32b(7), // remote id
    u32b(PEER_WINDOW),
    u32b(32768), // remote max packet
  ])
  chan = step(chan, 0x5b, confirm)
  if !chan.open_done {
    return Run::{
      requests: [],
      results: [],
      done: false,
      failed: true,
      reason: "peer: no open_done after CONFIRMATION",
    }
  }

  // 3) The subsystem request is the client's; the peer only has to acknowledge
  //    it, and only because `run_sftp_session` waits for CHANNEL_SUCCESS
  //    before putting INIT on the wire. Getting the numbering wrong here would
  //    show up as a transcript that never reaches VERSION.
  chan = match chan.subsystem_action("sftp") {
    None =>
      return Run::{
        requests: [],
        results: [],
        done: false,
        failed: true,
        reason: "peer: subsystem_action refused",
      }
    Some(@channel.Send(_t, _payload)) => chan
  }
  chan = step(chan, 0x63, u32b(LOCAL_CHANNEL)) // CHANNEL_SUCCESS

  // 4) Script. Each round: hand the client the queued requests (through the
  //    window), then deliver the next inbound payload re-sliced at `chop_size`
  //    as CHANNEL_DATA, then pump.
  let mut ci = 0
  let mut rounds = 0
  while rounds < 4000 {
    rounds = rounds + 1
    // client -> peer
    let out = sess.take_out()
    let mut rest : FixedArray[Byte] = FixedArray::make(0, b'\x00')
    for i = 0; i < out.length(); i = i + 1 {
      rest = cat([rest, out[i]])
    }
    let mut spins = 0
    while rest.length() > 0 && spins < 4096 {
      spins = spins + 1
      let (c1, action, left) = chan.stdin_take(rest)
      chan = c1
      match action {
        None => break
        Some(@channel.Send(_t, payload)) => {
          // Read the request out of the CHANNEL_DATA, exactly as a server
          // would, and reassemble the SFTP stream from it.
          match @channel.parse_data(payload) {
            None => ()
            Some((_who, d)) => server_in.feed(d)
          }
          let got = server_in.drain()
          for j = 0; j < got.length(); j = j + 1 {
            // `SftpInbuf::drain` hands back packet **bodies** -- the four-byte
            // length prefix is consumed by the buffer and never appears in
            // them. The vectors record whole frames (that is what `take_out`
            // produces on the client side), so the prefix is re-attached here
            // with the one function that owns framing. Without this the peer
            // reports `0100000003` where the expectation says
            // `000000050100000003`, which is a difference in this driver's
            // bookkeeping rather than anything about the protocol.
            peer_requests.push(to_hex(@sftp.sftp_frame(got[j])))
          }
        }
      }
      rest = left
    }

    sess.pump()
    if sess.done() || sess.failed() {
      break
    }
    if ci >= c.feeds.length() {
      break
    }
    // peer -> client, re-sliced. The CHANNEL_DATA boundary is the whole point:
    // it must not change what `SftpInbuf` reassembles.
    let payload = hex_to_bytes(c.feeds[ci])
    ci = ci + 1
    let pieces = chop(payload, chop_size)
    for i = 0; i < pieces.length(); i = i + 1 {
      // `chan_step` advances the *channel*; handing the payload to the SFTP
      // state machine is the driver's job, and both `run_sftp_session`
      // implementations do it right after, in this order: step the channel,
      // then parse the CHANNEL_DATA and feed it. Skipping the feed is not a
      // shortcut that happens to work -- the session never sees the reply and
      // waits forever, which is what the first version of this driver did.
      let payload = @channel.channel_data_payload(7, pieces[i])
      chan = step(chan, 0x5e, payload)
      match @channel.parse_data(payload) {
        None => ()
        Some((_who, d)) => sess.feed(d)
      }
      // Pump even without a complete packet: the reply may already be
      // buffered while the channel has nothing left, and stopping there is
      // how a client waits forever for a packet it already has.
      sess.pump()
      if sess.done() || sess.failed() {
        break
      }
    }
    sess.pump()
  }

  Run::{
    requests: peer_requests,
    results: render_results(sess),
    done: sess.done(),
    failed: sess.failed(),
    reason: sess.failure_reason(),
  }
}

///| One inbound packet through `chan_step`. Anything the channel wants to send

///| back is discarded: this peer has nothing to say, and WINDOW_ADJUST in

///|
/// particular is a real reply the client must survive.
fn step(
  st : @channel.ChanState,
  t : Byte,
  payload : FixedArray[Byte],
) -> @channel.ChanState {
  let (next, _actions, _err) = @channel.chan_step(st, t, payload)
  next
}

///|
fn render_results(sess : @sftp.SftpSession) -> Array[String] {
  let out : Array[String] = []
  let rs = sess.results_of()
  for i = 0; i < rs.length(); i = i + 1 {
    out.push(render_result(rs[i]))
  }
  out
}

// ---------------------------------------------------------------------------
// rendering, identical to `cmd/sftp_test` and `cmd/proton_gui`
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

///|
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

///|
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

// ---------------------------------------------------------------------------
// judging
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
fn judge(c : FaultCase, r : Run, chop_size : Int32) -> Array[String] {
  let tag = c.name + "@chop" + chop_size.to_string()
  let fails : Array[String] = []
  eq_arrays(r.requests, c.requests, tag + ": requests", fails)
  eq_arrays(r.results, c.results, tag + ": results", fails)
  if r.done != c.expect_done {
    fails.push(
      tag +
      ": done=" +
      r.done.to_string() +
      " expected " +
      c.expect_done.to_string(),
    )
  }
  if r.failed != c.expect_failed {
    fails.push(
      tag +
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
      tag + ": reason \"" + r.reason + "\" expected \"" + c.expect_reason + "\"",
    )
  }
  fails
}

///|
fn main {
  println(
    "SFTP fault vectors through the channel layer: " +
    fault_cases.length().to_string() +
    " scenarios",
  )
  println(
    "  invariant: re-slicing the inbound stream at a different CHANNEL_DATA",
  )
  println("  cut point must not change requests, results, or the verdict.")
  let fails : Array[String] = []
  let mut total = 0
  let mut passed = 0
  for i = 0; i < fault_cases.length(); i = i + 1 {
    let c = fault_cases[i]
    // The whole-payload case first, so a failure there is a plain protocol
    // failure and not a framing one.
    let base = run_case(c, 0)
    let base_fails = judge(c, base, 0)
    total = total + 1
    if base_fails.length() == 0 {
      passed = passed + 1
      println("  PASS  " + c.name + " (whole payload)")
    } else {
      println("  FAIL  " + c.name + " (whole payload)  -- " + c.intent)
      for j = 0; j < base_fails.length(); j = j + 1 {
        println("      - " + base_fails[j])
        fails.push(base_fails[j])
      }
    }
    // Then every cut point, each asserted against the whole-payload answer --
    // not just against the expectation. Comparing a chopped run to the
    // chopped expectation would let a shared error pass twice.
    for k = 0; k < c.chop_sizes.length(); k = k + 1 {
      let size = c.chop_sizes[k]
      let r = run_case(c, size)
      total = total + 1
      let cf = judge(c, r, size)
      // The cross-check that is the point of this package.
      let same_requests = same_arrays(r.requests, base.requests)
      let same_results = same_arrays(r.results, base.results)
      let same_verdict = r.done == base.done &&
        r.failed == base.failed &&
        r.reason == base.reason
      if cf.length() == 0 && same_requests && same_results && same_verdict {
        passed = passed + 1
        println("  PASS  " + c.name + " @chop" + size.to_string())
      } else {
        println(
          "  FAIL  " + c.name + " @chop" + size.to_string() + "  -- " + c.intent,
        )
        for j = 0; j < cf.length(); j = j + 1 {
          println("      - " + cf[j])
          fails.push(cf[j])
        }
        if !same_requests {
          println(
            "      - cut point changed the requests: whole=" +
            base.requests.join(",") +
            " chopped=" +
            r.requests.join(","),
          )
          fails.push(
            c.name +
            "@chop" +
            size.to_string() +
            ": requests differ from whole payload",
          )
        }
        if !same_results {
          println(
            "      - cut point changed the results: whole=" +
            base.results.join(",") +
            " chopped=" +
            r.results.join(","),
          )
          fails.push(
            c.name +
            "@chop" +
            size.to_string() +
            ": results differ from whole payload",
          )
        }
        if !same_verdict {
          println(
            "      - cut point changed the verdict: whole=[" +
            base.done.to_string() +
            "," +
            base.failed.to_string() +
            "," +
            base.reason +
            "] chopped=[" +
            r.done.to_string() +
            "," +
            r.failed.to_string() +
            "," +
            r.reason +
            "]",
          )
          fails.push(
            c.name +
            "@chop" +
            size.to_string() +
            ": verdict differs from whole payload",
          )
        }
      }
    }
  }
  println("")
  if fails.length() == 0 {
    println(
      "ALL PASS (" +
      passed.to_string() +
      "/" +
      total.to_string() +
      " runs, " +
      fault_cases.length().to_string() +
      " scenarios x " +
      (1 + fault_cases[0].chop_sizes.length()).to_string() +
      " cut points)",
    )
  } else {
    println(fails.length().to_string() + " FAILURES")
    for i = 0; i < fails.length(); i = i + 1 {
      println("FAIL " + fails[i])
    }
  }
}

///|
fn same_arrays(a : Array[String], b : Array[String]) -> Bool {
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
