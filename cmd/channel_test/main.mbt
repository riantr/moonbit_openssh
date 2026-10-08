///| cmd/channel_test -- Loop #35 RFC 4254 通道层 byte-exact
///|
///| 只依赖 `src/channel` 和 `src/sshwire`,两者都不碰 `@tcp`,所以四个后端
///| 都能跑。和 Loop #34 拆 `src/userauth` 是同一个理由:只能在一个后端上跑的
///| KAT,覆盖率只有这个仓库要求的四分之一。
///|
///| 分四层对着 `host/channel_oracle.py` 的独立实现核对:
///|
///|   1. 常量 —— window / max_packet 必须等于 channels.h:231-232
///|   2. 组包器 —— 每种消息逐字节重建后与向量比对
///|   3. 解析器 —— 解回字段;截断 / 尾部残余必须判 None
///|   4. 状态机 + 窗口 —— 整段 transcript 喂进 `chan_step`,比对每一次回包、
///|      stdout / stderr / exit-status / 窗口调整次数
///|
///| 第 4 层是关键。`src/channel/exec.mbt` 出过两个本地检查全都发现不了的错:
///| WINDOW_ADJUST 取的是 `take_adjust` **之后**的窗口,而那时 consumed 已经归零,
///| 于是每次都发 0 字节;以及把收包里的 recipient 和**对端**的通道号比。
///| 两者在「自己和对方都恰好是 0 号通道」时都不显形,所以向量里专门放了
///| `exec_nonzero_ids`(local=3 / remote=7)和 `exec_bulk_window` 两个用例。
///|
///| 风格上全部写成纯函数 + 失败数组:MoonBit 不允许把嵌套 `match` 直接当
///| 分支体(报了也看不出真正原因的 parse error),而且 `Array` 是引用,不需要
///| `mut` 就能 push。

// ---------------------------------------------------------------------------
// hex / byte helpers
// ---------------------------------------------------------------------------

fn hex_nibble(c : UInt16) -> Int {
  let n = c.to_int()
  if n >= 48 && n <= 57 {
    return n - 48
  }
  if n >= 97 && n <= 102 {
    return n - 87
  }
  abort("hex_to_bytes: bad digit")
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

fn ascii(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  out
}

fn byte_to_hex(b : Byte) -> String {
  let hex_chars : String = "0123456789abcdef"
  let hi = b.to_int() / 16
  let lo = b.to_int() % 16
  hex_chars.unsafe_substring(start=hi, end=hi + 1) +
  hex_chars.unsafe_substring(start=lo, end=lo + 1)
}

///| 截到 48 字节,够定位问题又不至于刷屏
fn short_hex(b : FixedArray[Byte]) -> String {
  let n = if b.length() > 48 { 48 } else { b.length() }
  let head = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    head[i] = b[i]
  }
  let sb = StringBuilder()
  for i = 0; i < n; i = i + 1 {
    sb.write_string(byte_to_hex(head[i]))
  }
  sb.to_string()
}

fn bytes_equal(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i].to_int() != b[i].to_int() {
      return false
    }
  }
  true
}

fn ints_equal(a : Array[Int], b : Array[Int]) -> Bool {
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

fn pf(ok : Bool) -> String {
  if ok {
    "PASS"
  } else {
    "FAIL"
  }
}

fn fill_bytes(byte : Int, n : Int) -> FixedArray[Byte] {
  FixedArray::make(n, (byte & 0xFF).to_byte())
}

///| 空数组(FixedArray::from_array([]) 推不出类型)
fn empty_bytes() -> FixedArray[Byte] {
  FixedArray::make(0, b'\x00')
}

// ---------------------------------------------------------------------------
// vector reconstruction
// ---------------------------------------------------------------------------

///|
///| 把向量里的一个包还原成真正的字节。
///|
///| `payload_hex` 非空时直接解码;否则按 `msg_type` 重新组一份 DATA /
///| EXTENDED_DATA —— 头部的 channel 号用的是 `ours`,也就是**我们**的通道号。
///| 这里顺便也在测那件事:如果组包器把 recipient 当成 remote,重建出来的东西
///| 就对不上。
fn packet_payload(p : Packet, ours : Int) -> FixedArray[Byte] {
  if p.payload_hex != "" {
    return hex_to_bytes(p.payload_hex)
  }
  let fill = fill_bytes(p.fill_byte, p.fill_len)
  if p.msg_type == 95 {
    @channel.channel_extended_data_payload(ours, p.fill_code, fill)
  } else {
    @channel.channel_data_payload(ours, fill)
  }
}

fn stream_bytes(s : Stream) -> FixedArray[Byte] {
  if s.hex != "" {
    hex_to_bytes(s.hex)
  } else {
    fill_bytes(s.byte, s.len)
  }
}

///| ChanError 没有 Debug,自己写标签
fn describe(e : @channel.ChanError) -> String {
  match e {
    OpenFailed(r, d) => "OpenFailed(" + r.to_string() + ", " + d + ")"
    ExecRejected => "ExecRejected"
    Malformed(m) => "Malformed(" + m + ")"
  }
}

fn action_bytes(a : @channel.ChanAction) -> (Int, FixedArray[Byte]) {
  match a {
    Send(t, p) => (t.to_int(), p)
  }
}

// ---------------------------------------------------------------------------
// per-case checks (pure)
// ---------------------------------------------------------------------------

fn chk_open(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_open_payload(c.sender, c.window, c.max_packet),
    hex_to_bytes(c.open_hex),
  )
}

fn chk_exec(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_exec_payload(c.sender, c.exec_command),
    hex_to_bytes(c.exec_hex),
  )
}

fn chk_data(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_data_payload(c.sender, ascii(c.data_text)),
    hex_to_bytes(c.data_hex),
  )
}

fn chk_ext(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_extended_data_payload(
      c.sender,
      c.extdata_code,
      ascii(c.extdata_text),
    ),
    hex_to_bytes(c.extdata_hex),
  )
}

fn chk_adjust(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_window_adjust_payload(c.sender, c.adjust_bytes),
    hex_to_bytes(c.adjust_hex),
  )
}

fn chk_bare(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_bare_payload(c.sender),
    hex_to_bytes(c.bare_hex),
  )
}

///| exit-status 的**发送**方向是服务端,但字段布局在 RFC 4254 6.1 是共用的,
///| 所以用 `channel_request_payload` 重建:u32 || string("exit-status") || FALSE || u32
fn chk_exit(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_request_payload(
      c.sender,
      "exit-status",
      false,
      @sshwire.write_u32(c.exit_status_code.reinterpret_as_uint()),
    ),
    hex_to_bytes(c.exit_status_hex),
  )
}

///|
///| CHANNEL_OPEN_FAILURE 只有收方向,没有组包器。
///| 这里既用 sshwire 原语重建字节(证明字段顺序),又解析回来核对值。
fn chk_open_failure(c : PayloadCase) -> Bool {
  let rebuilt = @channel.ch_cat_all([
    @sshwire.write_u32(c.sender.reinterpret_as_uint()),
    @sshwire.write_u32(c.open_failure_reason.reinterpret_as_uint()),
    @sshwire.write_ssh_string(ascii(c.open_failure_desc)),
    @sshwire.write_ssh_string(empty_bytes()),
  ])
  if !bytes_equal(rebuilt, hex_to_bytes(c.open_failure_hex)) {
    return false
  }
  match @channel.parse_open_failure(hex_to_bytes(c.open_failure_hex)) {
    None => false
    Some((reason, desc)) =>
      reason == c.open_failure_reason && desc == c.open_failure_desc
  }
}

fn chk_parse_data(c : PayloadCase) -> Bool {
  match @channel.parse_data(hex_to_bytes(c.data_hex)) {
    None => false
    Some((who, d)) => who == c.sender && bytes_equal(d, ascii(c.data_text))
  }
}

fn chk_parse_ext(c : PayloadCase) -> Bool {
  match @channel.parse_extended_data(hex_to_bytes(c.extdata_hex)) {
    None => false
    Some((who, code, d)) =>
      who == c.sender && code == c.extdata_code &&
      bytes_equal(d, ascii(c.extdata_text))
  }
}

fn chk_parse_request(c : PayloadCase) -> Bool {
  let raw = hex_to_bytes(c.exit_status_hex)
  match @channel.parse_request_header(raw) {
    None => false
    Some((who, rtype, want, off)) => {
      let head_ok = who == c.sender && rtype == "exit-status" && !want
      match @channel.read_u32_at(raw, off) {
        None => false
        Some((st, o2)) =>
          head_ok && st == c.exit_status_code && o2 == raw.length()
      }
    }
  }
}

///| 解析器负例:截断一个字节、加一个字节的尾部残余,都必须判 None
fn chk_parsers_reject(c : PayloadCase) -> Bool {
  let good = hex_to_bytes(c.data_hex)
  let short = FixedArray::make(good.length() - 1, b'\x00')
  for i = 0; i < short.length(); i = i + 1 {
    short[i] = good[i]
  }
  let long = @channel.ch_cat(good, FixedArray::from_array([b'\x01']))
  let fail = @channel.parse_data(short) is None &&
    @channel.parse_data(long) is None &&
    @channel.parse_open_confirmation(short) is None &&
    @channel.parse_open_confirmation(long) is None &&
    @channel.parse_extended_data(short) is None &&
    @channel.parse_window_adjust(short) is None &&
    @channel.parse_channel_id(short) is None &&
    @channel.parse_channel_id(long) is None
  fail
}

// ---------------------------------------------------------------------------
// window replay
// ---------------------------------------------------------------------------

///|
///| 按 `sizes` 回放窗口记账,返回 `(每次调整的字节数, 结束时的窗口)`。
///|
///| 注意量必须在 `take_adjust` **之前**读:那一步已经把 consumed 清零,
///| 从新状态上读会得到 0,而 0 字节的 WINDOW_ADJUST 照样「能跑完」,
///| 只是窗口永远补不回来 —— 这正是它当初没被本地检查发现的原因。
///| 递归而不是 fold:MoonBit 的 `Array::fold` 在这个闭包形态下推不出累加器
///| 类型,而递归版本没有任何歧义。
fn replay_window_go(
  sizes : Array[Int],
  idx : Int,
  acc : @channel.LocalWindow,
  amounts : Array[Int],
) -> @channel.LocalWindow {
  if idx >= sizes.length() {
    return acc
  }
  let w = acc.consume(sizes[idx])
  match w.take_adjust() {
    None => replay_window_go(sizes, idx + 1, w, amounts)
    Some(w2) => {
      amounts.push(w.adjust_amount())
      replay_window_go(sizes, idx + 1, w2, amounts)
    }
  }
}

fn replay_window(
  sizes : Array[Int],
) -> (Array[Int], @channel.LocalWindow) {
  let amounts : Array[Int] = []
  let win = replay_window_go(
    sizes,
    0,
    @channel.LocalWindow::new(),
    amounts,
  )
  (amounts, win)
}

fn chk_window(wc : WindowCase) -> Bool {
  let (amounts, win) = replay_window(wc.sizes)
  ints_equal(amounts, wc.adjust_amounts) &&
  win.cur == wc.final_cur &&
  win.consumed == wc.final_consumed
}

// ---------------------------------------------------------------------------
// session replay
// ---------------------------------------------------------------------------

fn run_session_go(
  c : SessionCase,
  idx : Int,
  st : @channel.ChanState,
  replies : Array[@channel.ChanAction],
  errors : Array[String],
) -> @channel.ChanState {
  if idx >= c.packets.length() {
    return st
  }
  let p = c.packets[idx]
  let payload = packet_payload(p, c.local_channel)
  let (st1, actions, e) = @channel.chan_step(st, p.msg_type.to_byte(), payload)
  match e {
    None => ()
    Some(chan_err) => errors.push("packet " + idx.to_string() + ": " + describe(chan_err))
  }
  for j = 0; j < actions.length(); j = j + 1 {
    replies.push(actions[j])
  }
  run_session_go(c, idx + 1, st1, replies, errors)
}

fn run_session(c : SessionCase) -> (Array[@channel.ChanAction], @channel.ExecReport, String) {
  let replies : Array[@channel.ChanAction] = []
  let errors : Array[String] = []
  let st = run_session_go(c, 0, @channel.ChanState::new(c.local_channel), replies, errors)
  let first = if errors.length() == 0 { "" } else { errors[0] }
  (replies, st.report(), first)
}

///|
///| 跑一遍 transcript 并把每处不符写进 `fails`。
///|
///| 单独返回错误字符串而不是就地判定,是因为 1.5 MiB 的 bulk 用例不该为了
///| 打印一条诊断跑三遍。
fn check_session(
  c : SessionCase,
  fails : Array[String],
) -> (@channel.ExecReport, Int) {
  let mut payload_bad = false
  for i = 0; i < c.packets.length(); i = i + 1 {
    let p = c.packets[i]
    if packet_payload(p, c.local_channel).length() != p.payload_len {
      fails.push(
        c.name + ": packet " + i.to_string() + " rebuilt to the wrong length",
      )
      payload_bad = true
      break
    }
  }
  if payload_bad {
    return (@channel.ChanState::new(c.local_channel).report(), 0)
  }
  let (replies, report, err) = run_session(c)
  if err != "" {
    fails.push(c.name + ": " + err)
    return (report, replies.length())
  }
  if replies.length() != c.replies.length() {
    fails.push(
      c.name + ": " + replies.length().to_string() + " replies, vector says " +
      c.replies.length().to_string(),
    )
  } else {
    for i = 0; i < replies.length(); i = i + 1 {
      let (t, p) = action_bytes(replies[i])
      let want = c.replies[i]
      let ok = t == want.msg_type &&
        bytes_equal(p, hex_to_bytes(want.payload_hex))
      if !ok {
        fails.push(
          c.name + ": reply " + i.to_string() + " is type " + t.to_string() +
          " " + short_hex(p) + ", expected type " + want.msg_type.to_string() +
          " " + want.payload_hex,
        )
      }
    }
  }
  let so = stream_bytes(c.stdout)
  let se = stream_bytes(c.stderr)
  if !bytes_equal(report.stdout, so) {
    fails.push(
      c.name + ": stdout " + report.stdout.length().to_string() +
      " bytes, expected " + so.length().to_string(),
    )
  }
  if !bytes_equal(report.stderr, se) {
    fails.push(
      c.name + ": stderr " + report.stderr.length().to_string() +
      " bytes, expected " + se.length().to_string(),
    )
  }
  if report.exit_status != c.exit_status {
    fails.push(
      c.name + ": exit " + report.exit_status.to_string() + ", expected " +
      c.exit_status.to_string(),
    )
  }
  if report.adjusts_sent != c.adjusts_sent {
    fails.push(
      c.name + ": " + report.adjusts_sent.to_string() + " adjusts, expected " +
      c.adjusts_sent.to_string(),
    )
  }
  if report.remote_id != c.remote_channel {
    fails.push(c.name + ": remote id " + report.remote_id.to_string())
  }
  (report, c.adjusts_sent)
}

///| 把一组用例跑一遍,任一不符就往 `fails` 追加一条
fn all_payloads(
  f : (PayloadCase) -> Bool,
  label : String,
  fails : Array[String],
) -> Bool {
  for i = 0; i < kat_payload_cases.length(); i = i + 1 {
    if !f(kat_payload_cases[i]) {
      fails.push(label + ": " + kat_payload_cases[i].name)
      return false
    }
  }
  true
}

fn main {
  let fails : Array[String] = []

  // ---- 1. 常量(channels.h:231-232)----
  println(
    "chan_constants: " +
    pf(
      @channel.CHAN_PACKET_DEFAULT == KAT_CHAN_PACKET_DEFAULT &&
      @channel.CHAN_WINDOW_DEFAULT == KAT_CHAN_WINDOW_DEFAULT &&
      @channel.EXTENDED_DATA_STDERR == 1,
    ),
  )

  // ---- 2. 组包器 / 解析器 ----
  println("chan_open_payload: " + pf(all_payloads(chk_open, "open", fails)))
  println("chan_exec_payload: " + pf(all_payloads(chk_exec, "exec", fails)))
  println("chan_data_payload: " + pf(all_payloads(chk_data, "data", fails)))
  println("chan_extdata_payload: " + pf(all_payloads(chk_ext, "extdata", fails)))
  println("chan_adjust_payload: " + pf(all_payloads(chk_adjust, "adjust", fails)))
  println("chan_bare_payload: " + pf(all_payloads(chk_bare, "bare", fails)))
  println("chan_exit_status_payload: " + pf(all_payloads(chk_exit, "exit", fails)))
  println(
    "chan_open_failure_payload: " +
    pf(all_payloads(chk_open_failure, "open_failure", fails)),
  )
  println(
    "chan_parsers_roundtrip: " +
    pf(
      all_payloads(chk_parse_data, "parse_data", fails) &&
      all_payloads(chk_parse_ext, "parse_extdata", fails) &&
      all_payloads(chk_parse_request, "parse_request", fails),
    ),
  )
  println(
    "chan_parsers_reject_bad: " +
    pf(all_payloads(chk_parsers_reject, "parsers_reject", fails)),
  )

  // ---- 3. 窗口记账 ----
  let win_ok = kat_window_cases.all(wc => chk_window(wc))
  let has_adjust = kat_window_cases.any(wc => wc.adjust_amounts.length() > 0)
  let has_quiet = kat_window_cases.any(wc => wc.adjust_amounts.length() == 0)
  println("chan_window_plan: " + pf(win_ok))
  // 防「向量集退化成什么都测不到」:既要有一次也不发的用例,也要有反复发的
  println(
    "chan_window_cases_diverse: " +
    pf(has_adjust && has_quiet && kat_window_cases.length() >= 6),
  )

  // ---- 4. 整段 transcript ----
  let sess_fails : Array[String] = []
  let reports : Array[@channel.ExecReport] = []
  let adjusts : Array[Int] = []
  for i = 0; i < kat_session_cases.length(); i = i + 1 {
    let (report, n) = check_session(kat_session_cases[i], sess_fails)
    reports.push(report)
    adjusts.push(n)
  }
  println("chan_sessions: " + pf(sess_fails.length() == 0))
  for i = 0; i < sess_fails.length(); i = i + 1 {
    println("  chan_session_fail: " + sess_fails[i])
  }
  // 没有 local != remote 的用例就测不出收包 recipient 的语义;
  // 没有多次调整的用例,窗口算法就退化成「一次也不发」。
  //
  // 计数单独打出来,而不是合成一个布尔:验证脚本要能分别断言这两件事,
  // 一个笼统的 PASS 会让两个同义检查看起来像两份覆盖。
  let ids_split = kat_session_cases.filter(c => c.local_channel != c.remote_channel).length()
  let multi_adjust = kat_session_cases.filter(c => c.adjusts_sent > 1).length()
  let no_status = kat_session_cases.filter(c => c.exit_status == 255).length()
  println("chan_session_cases: " + kat_session_cases.length().to_string())
  println("chan_session_ids_split_cases: " + ids_split.to_string())
  println("chan_session_multi_adjust_cases: " + multi_adjust.to_string())
  println("chan_session_no_status_cases: " + no_status.to_string())

  // ---- 5. 没收到 exit-status 时按 SSH 惯例回 255 ----
  let fallback_ok = kat_session_cases.all(c => {
    if c.name == "exec_no_exit_status" {
      let (report, _) = check_session(c, sess_fails)
      report.exit_status == 255
    } else {
      true
    }
  })
  println("chan_exit_status_fallback_255: " + pf(fallback_ok))

  let first = if fails.length() == 0 { "none" } else { fails[0] }
  println("chan_first_failure: " + first)
}
