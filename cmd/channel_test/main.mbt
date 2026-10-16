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

///|
/// `mut` 就能 push。

// ---------------------------------------------------------------------------
// hex / byte helpers
// ---------------------------------------------------------------------------

fn hex_nibble(c : UInt16) -> Int32 {
  let n = c.to_int()
  if n >= 48 && n <= 57 {
    return n - 48
  }
  if n >= 97 && n <= 102 {
    return n - 87
  }
  abort("hex_to_bytes: bad digit")
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
fn ascii(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  out
}

///|
fn byte_to_hex(b : Byte) -> String {
  let hex_chars : String = "0123456789abcdef"
  let hi = b.to_int() / 16
  let lo = b.to_int() % 16
  hex_chars.unsafe_substring(start=hi, end=hi + 1) +
  hex_chars.unsafe_substring(start=lo, end=lo + 1)
}

///|
/// 截到 48 字节,够定位问题又不至于刷屏
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

///|
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

///|
fn ints_equal(a : Array[Int32], b : Array[Int32]) -> Bool {
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

///|
fn pf(ok : Bool) -> String {
  if ok {
    "PASS"
  } else {
    "FAIL"
  }
}

///|
fn fill_bytes(byte : Int32, n : Int32) -> FixedArray[Byte] {
  FixedArray::make(n, (byte & 0xFF).to_byte())
}

///|
/// 空数组(FixedArray::from_array([]) 推不出类型)
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

///|
/// 就对不上。
fn packet_payload(p : Packet, ours : Int32) -> FixedArray[Byte] {
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

///|
/// 把向量里的一个**回复方向**包还原成真正的字节。
///
/// 与 `packet_payload` 的唯一区别是 channel 号:收包方向的 recipient 是我们
/// 自己的号,发包方向的是对端给的号。这个区别就是 Loop #35 抓到过的一个 bug
/// ——首通道两边都是 0,所以它当时完全看不出来。
fn reply_payload(p : Packet, remote : Int32) -> FixedArray[Byte] {
  if p.payload_hex != "" {
    return hex_to_bytes(p.payload_hex)
  }
  let fill = fill_bytes(p.fill_byte, p.fill_len)
  if p.msg_type == 95 {
    @channel.channel_extended_data_payload(remote, p.fill_code, fill)
  } else {
    @channel.channel_data_payload(remote, fill)
  }
}

///|
fn stream_bytes(s : Stream) -> FixedArray[Byte] {
  if s.hex != "" {
    hex_to_bytes(s.hex)
  } else {
    fill_bytes(s.byte, s.len)
  }
}

///|
/// ChanError 没有 Debug,自己写标签
fn describe(e : @channel.ChanError) -> String {
  match e {
    OpenFailed(r, d) => "OpenFailed(" + r.to_string() + ", " + d + ")"
    ExecRejected => "ExecRejected"
    SubsystemRejected => "SubsystemRejected"
    Malformed(m) => "Malformed(" + m + ")"
  }
}

///|
fn action_bytes(a : @channel.ChanAction) -> (Int32, FixedArray[Byte]) {
  match a {
    Send(t, p) => (t.to_int(), p)
  }
}

// ---------------------------------------------------------------------------
// per-case checks (pure)
// ---------------------------------------------------------------------------

///|
fn chk_open(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_open_payload(c.sender, c.window, c.max_packet),
    hex_to_bytes(c.open_hex),
  )
}

///|
fn chk_exec(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_exec_payload(c.sender, c.exec_command),
    hex_to_bytes(c.exec_hex),
  )
}

///|
fn chk_data(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_data_payload(c.sender, ascii(c.data_text)),
    hex_to_bytes(c.data_hex),
  )
}

///|
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

///|
fn chk_adjust(c : PayloadCase) -> Bool {
  bytes_equal(
    @channel.channel_window_adjust_payload(c.sender, c.adjust_bytes),
    hex_to_bytes(c.adjust_hex),
  )
}

///|
fn chk_bare(c : PayloadCase) -> Bool {
  bytes_equal(@channel.channel_bare_payload(c.sender), hex_to_bytes(c.bare_hex))
}

///| exit-status 的**发送**方向是服务端,但字段布局在 RFC 4254 6.1 是共用的,

///|
/// 所以用 `channel_request_payload` 重建:u32 || string("exit-status") || FALSE || u32
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

///|
/// 这里既用 sshwire 原语重建字节(证明字段顺序),又解析回来核对值。
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

///|
fn chk_parse_data(c : PayloadCase) -> Bool {
  match @channel.parse_data(hex_to_bytes(c.data_hex)) {
    None => false
    Some((who, d)) => who == c.sender && bytes_equal(d, ascii(c.data_text))
  }
}

///|
fn chk_parse_ext(c : PayloadCase) -> Bool {
  match @channel.parse_extended_data(hex_to_bytes(c.extdata_hex)) {
    None => false
    Some((who, code, d)) =>
      who == c.sender &&
      code == c.extdata_code &&
      bytes_equal(d, ascii(c.extdata_text))
  }
}

///|
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

///|
/// 解析器负例:截断一个字节、加一个字节的尾部残余,都必须判 None
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
// Interactive: pty-req / shell / window-change / exit-signal
// ---------------------------------------------------------------------------

///|
/// 逐条重建交互消息。
///
/// `modes` 的 string 包装是最容易漏的一层(`ttymodes.c:329-333`:先
/// `put_u8(TTY_OP_END)` 再 `put_stringb`),漏掉它服务端会把 4 字节的长度前缀
/// 当成 opcode——而那样**仍然是合法 pty**,只是终端模式全乱。
fn chk_shell_payloads(c : ShellPayloadCase) -> Bool {
  let modes = hex_to_bytes(c.modes_hex)
  if !bytes_equal(
      @channel.channel_pty_req_payload(
        c.recipient,
        c.term,
        c.cols,
        c.rows,
        c.width_px,
        c.height_px,
        modes,
      ),
      hex_to_bytes(c.pty_req_hex),
    ) {
    return false
  }
  if !bytes_equal(@channel.tty_modes_bytes(38400), modes) {
    return false
  }
  if !bytes_equal(
      @channel.channel_shell_payload(c.recipient),
      hex_to_bytes(c.shell_hex),
    ) {
    return false
  }
  if !bytes_equal(
      @channel.channel_window_change_payload(
        c.recipient,
        c.resize_cols,
        c.resize_rows,
        0,
        0,
      ),
      hex_to_bytes(c.window_change_hex),
    ) {
    return false
  }
  if !bytes_equal(
      @channel.channel_data_payload(c.recipient, ascii("x\r\n")),
      hex_to_bytes(c.stdin_hex),
    ) {
    return false
  }
  let raw = hex_to_bytes(c.exit_signal_hex)
  if !bytes_equal(
      @channel.channel_request_payload(
        c.recipient,
        "exit-signal",
        false,
        @channel.ch_cat_all([
          @sshwire.write_ssh_string(ascii(c.exit_signal_name)),
          FixedArray::from_array([
            if c.exit_signal_core {
              b'\x01'
            } else {
              b'\x00'
            },
          ]),
          @sshwire.write_ssh_string(empty_bytes()),
          @sshwire.write_ssh_string(ascii(c.exit_signal_message)),
        ]),
      ),
      raw,
    ) {
    return false
  }
  // exit-signal 的解析:头部 + 四个字段必须原样回来。
  let parsed = match @channel.parse_request_header(raw) {
    None => None
    Some((who, rtype, want, off)) =>
      if who != c.recipient || rtype != "exit-signal" || want {
        None
      } else {
        @channel.parse_exit_signal(raw, off)
      }
  }
  match parsed {
    None => false
    Some((name, core, msg)) =>
      name == c.exit_signal_name &&
      core == c.exit_signal_core &&
      msg == c.exit_signal_message
  }
}

///|
/// exit-signal 负例:字段被截断 / 尾部有残余都必须判 None
fn chk_exit_signal_rejects(c : ShellPayloadCase) -> Bool {
  let raw = hex_to_bytes(c.exit_signal_hex)
  let short = FixedArray::make(raw.length() - 1, b'\x00')
  for i = 0; i < short.length(); i = i + 1 {
    short[i] = raw[i]
  }
  let off = match @channel.parse_request_header(raw) {
    None => return false
    Some((_, _, _, o)) => o
  }
  // 合法的那个必须**解得出来**,只有被截断 / 尾部有残余的两个必须判 None。
  // 写成三个 `is None` 的与会把正例也否掉,而断言方向错了的检查和没有检查
  // 一样有害。
  @channel.parse_exit_signal(raw, off) is Some(_) &&
  @channel.parse_exit_signal(short, off) is None &&
  @channel.parse_exit_signal(
    @channel.ch_cat(raw, FixedArray::from_array([b'\x01'])),
    off,
  )
  is None
}

///|
/// 按 `after` 时序回放一段交互式会话。
///
/// 顺序是这里唯一值得测的东西:收到第 N 个服务端包之后,驱动依次发
/// pty-req / shell / resize / stdin,状态机自己吐出的 WINDOW_ADJUST 和 CLOSE
/// 插在中间。逐字节比对整个 client→server 序列,顺序错一步就会露出来。
///
/// 诚实说明覆盖面:`client_sends` 里的字节是从向量读的,不是在 KAT 里重新
/// 组装的——组包器本身由 `chk_shell_payloads` 按参数重建验证,这里验证的是
/// **时序**。两端都验才不重复;只验一头会漏掉「顺序对但字节错」。
fn replay_shell_timed(
  c : ShellCase,
) -> (Array[@channel.ChanAction], @channel.ShellReport, String) {
  let replies : Array[@channel.ChanAction] = []
  let mut st = @channel.ChanState::new_interactive(c.local_channel)
  let mut err = ""
  let mut send_idx = 0
  for i = 0; i < c.packets.length(); i = i + 1 {
    let p = c.packets[i]
    let payload = packet_payload(p, c.local_channel)
    let (st1, actions, e) = @channel.chan_step(
      st,
      p.msg_type.to_byte(),
      payload,
    )
    st = st1
    if err == "" {
      match e {
        None => ()
        Some(chan_err) => err = describe(chan_err)
      }
    }
    for j = 0; j < actions.length(); j = j + 1 {
      replies.push(actions[j])
    }
    // 处理完第 i 个包之后 seen = i + 1
    let seen = i + 1
    let mut k = send_idx
    while k < c.client_sends.length() && c.client_sends[k].after <= seen {
      replies.push(
        Send(
          c.client_sends[k].msg_type.to_byte(),
          hex_to_bytes(c.client_sends[k].payload_hex),
        ),
      )
      k = k + 1
    }
    send_idx = k
  }
  (replies, st.shell_report(), err)
}

///|
/// 交互式会话的检查:时序、字节、最终报告三项都要对上
fn check_shell(c : ShellCase, fails : Array[String]) -> @channel.ShellReport {
  let (replies, report, err) = replay_shell_timed(c)
  if err != "" {
    fails.push(c.name + ": " + err)
    return report
  }
  if replies.length() != c.replies.length() {
    fails.push(
      c.name +
      ": " +
      replies.length().to_string() +
      " client packets, vector says " +
      c.replies.length().to_string(),
    )
  } else {
    for i = 0; i < replies.length(); i = i + 1 {
      let (t, p) = action_bytes(replies[i])
      let want = c.replies[i]
      if t != want.msg_type || !bytes_equal(p, hex_to_bytes(want.payload_hex)) {
        fails.push(
          c.name +
          ": client packet " +
          i.to_string() +
          " is type " +
          t.to_string() +
          " " +
          short_hex(p) +
          ", expected type " +
          want.msg_type.to_string() +
          " " +
          want.payload_hex,
        )
      }
    }
  }
  let so = stream_bytes(c.stdout)
  if !bytes_equal(report.stdout, so) {
    fails.push(
      c.name +
      ": stdout " +
      report.stdout.length().to_string() +
      " bytes, expected " +
      so.length().to_string(),
    )
  }
  if report.exit_status != c.exit_status {
    fails.push(
      c.name +
      ": exit " +
      report.exit_status.to_string() +
      ", expected " +
      c.exit_status.to_string(),
    )
  }
  let got_sig = match report.exit_signal {
    None => ""
    Some((n, _core)) => n
  }
  if got_sig != c.exit_signal {
    fails.push(
      c.name + ": exit signal " + got_sig + ", expected " + c.exit_signal,
    )
  }
  if report.adjusts_sent != c.adjusts_sent {
    fails.push(
      c.name +
      ": " +
      report.adjusts_sent.to_string() +
      " adjusts, expected " +
      c.adjusts_sent.to_string(),
    )
  }
  if report.success_count != c.success_count {
    fails.push(
      c.name +
      ": " +
      report.success_count.to_string() +
      " successes, expected " +
      c.success_count.to_string(),
    )
  }
  report
}

///|
fn all_shell_payloads(
  f : (ShellPayloadCase) -> Bool,
  label : String,
  fails : Array[String],
) -> Bool {
  for i = 0; i < kat_shell_payload_cases.length(); i = i + 1 {
    if !f(kat_shell_payload_cases[i]) {
      fails.push(label + ": " + kat_shell_payload_cases[i].name)
      return false
    }
  }
  true
}

// ---------------------------------------------------------------------------
// Loop #37: env request / stdin flow control
// ---------------------------------------------------------------------------

///|
/// 重建 `env` 请求,以及收尾的 CHANNEL_EOF。
///
/// 三件事分别验,因为它们各自的失败方式都是**静默**的:
///
///   1. 字节本身。两个 string,顺序是 name 在前(session.c:2042-2043),
///      后面不能再有字段(`sshpkt_get_end` 就在那里)。
///   2. **不得**等于 `want_reply = TRUE` 的那一份。RFC 4254 §6.4 明写
///      "No response is returned by the server",OpenSSH 客户端也发的是 0
///      (clientloop.c:2706)。写成 TRUE 不会断链,只会让服务端在名字不在
///      `AcceptEnv` 里(默认就是空的)回一条 CHANNEL_FAILURE,于是每个 env
///      都变成一次多余的往返。断言「不等于」比在注释里说明它更有用。
///   3. EOF 的 payload 就是对端给的通道号(nchan.c:192-193),而且同一个通道
///      只能发一次。
fn chk_env_payloads(c : EnvPayloadCase) -> Bool {
  let raw = hex_to_bytes(c.env_hex)
  if !bytes_equal(
      @channel.channel_env_payload(c.recipient, c.var_name, c.var_value),
      raw,
    ) {
    return false
  }
  if bytes_equal(raw, hex_to_bytes(c.env_want_reply_hex)) {
    return false
  }
  if !bytes_equal(
      @channel.channel_env_payload(c.recipient, "LANG", ""),
      hex_to_bytes(c.empty_value_env_hex),
    ) {
    return false
  }
  if !bytes_equal(
      @channel.channel_bare_payload(c.recipient),
      hex_to_bytes(c.eof_hex),
    ) {
    return false
  }
  // 结构:recipient || "env" || want_reply=FALSE || name || value,正好到底。
  // 「正好到底」是 `sshpkt_get_end` 的要求;多一个字节服务端是 sshpkt_fatal。
  let off = match @channel.parse_request_header(raw) {
    None => return false
    Some((who, rtype, want, o)) => {
      if who != c.recipient || rtype != "env" || want {
        return false
      }
      o
    }
  }
  match @channel.read_string_at(raw, off) {
    None => false
    Some((name, o1)) =>
      match @channel.read_string_at(raw, o1) {
        None => false
        Some((value, o2)) =>
          o2 == raw.length() &&
          @channel.bytes_to_ascii_str(name) == c.var_name &&
          @channel.bytes_to_ascii_str(value) == c.var_value
      }
  }
}

///|
/// 开着通道、拿到 remote_id 之后的状态,专供动作类断言用
fn io_ready_state(recipient : Int32) -> @channel.ChanState {
  { ..@channel.ChanState::new(0), remote_id: recipient, open_done: true, }
}

///|
/// EOF 动作:发一次,之后不再发。
///
/// 第二次必须返回 None。发两次不会报错,只是让对端看到一个已经结束的输入方向
/// 又来了个结束标记——这类「不会断链」的错误正是它当初能一路跑到真服务器
/// 才暴露的原因。
fn chk_eof_action(c : EnvPayloadCase) -> Bool {
  let st = io_ready_state(c.recipient)
  let (st1, a) = st.eof_action()
  match a {
    None => false
    Some(act) => {
      let (t, payload) = action_bytes(act)
      if t != 0x60 {
        return false
      }
      if !bytes_equal(payload, hex_to_bytes(c.eof_hex)) {
        return false
      }
      if !st1.eof_sent {
        return false
      }
      let (_st2, again) = st1.eof_action()
      again is None
    }
  }
}

///|
/// 回放一条夹取计划(channels.c:3085-3100)。
///
/// 返回 `(每个 CHANNEL_DATA 的字节数, 累计字节, 停顿次数, 用掉的 adjust 数,
/// 停顿时缓冲是否原样退回)`。
///
/// 停顿的语义和 oracle 一致:窗口空了、又没 adjust 可用,就是「这轮没轮到发」,
/// 不是错误。把它当成错误会让连接挂死;把它当成成功会让剩下的字节被悄悄丢掉。
///
/// 最后那个布尔是 `stdin_take` 的契约本身:返回 `None` 时**第三个返回值必须是
/// 原封不动的缓冲**。少这一条的话,一个「停顿时就声称剩下的字节都发出去了」
/// 的实现能通过全部用例——因为重放只看 `Some` 分支里 `rest` 的变化。
fn replay_stdin_plan(
  c : StdinCase,
) -> (Array[Int32], Int32, Int32, Int32, Bool) {
  let mut st = {
    ..@channel.ChanState::new(0),
    remote_window: c.window,
    remote_max_packet: c.max_packet,
  }
  let mut rest = fill_bytes(c.byte, c.size)
  let sizes : Array[Int32] = []
  let mut sent = 0
  let mut stalls = 0
  let mut used_adjusts = 0
  let mut preserved = true
  let mut steps = 0
  while rest.length() > 0 {
    steps = steps + 1
    if steps > 1000000 {
      break
    }
    let (st1, action, left) = st.stdin_take(rest)
    st = st1
    match action {
      None => {
        if !bytes_equal(left, rest) {
          preserved = false
        }
        if used_adjusts < c.adjusts.length() {
          // 对端的 WINDOW_ADJUST 走的是收包路径,和 stdin 走同一条 chan_step 分支。
          let (st2, _acts, _e) = @channel.chan_step(
            st,
            0x5d,
            @channel.channel_window_adjust_payload(0, c.adjusts[used_adjusts]),
          )
          st = st2
          used_adjusts = used_adjusts + 1
        } else {
          stalls = stalls + 1
          break
        }
      }
      Some(a) => {
        let (_t, payload) = action_bytes(a)
        match @channel.parse_data(payload) {
          None => break
          Some((_who, d)) => {
            sizes.push(d.length())
            sent = sent + d.length()
          }
        }
        rest = left
      }
    }
  }
  (sizes, sent, stalls, used_adjusts, preserved)
}

///|
/// 夹取计划:包长序列、累计字节、停顿次数、缓冲契约都要对上
fn chk_stdin_plan(c : StdinCase) -> Bool {
  let (sizes, sent, stalls, used, preserved) = replay_stdin_plan(c)
  if !preserved {
    return false
  }
  if sizes.length() != c.packets.length() {
    return false
  }
  for i = 0; i < sizes.length(); i = i + 1 {
    if sizes[i] != c.packets[i] {
      return false
    }
  }
  if sent != c.sent || stalls != c.stalls || used != c.consumed_adjusts {
    return false
  }
  // 排空与否决定会不会发 EOF——先发 EOF 再补数据,对端只会安静地少读。
  (c.size - sent == 0) == c.eof
}

///|
/// 回放一条 env + stdin transcript。
///
/// 顺序就是 oracle 记录的顺序,每一步都会影响最终字节流:
/// 状态机吐出的动作 → 到期的驱动发送 → 按窗口夹取的 stdin → 排空后才发的 EOF。
///
/// 返回 `replies` 给调用方逐字节比,状态留给报告字段。
fn replay_io(
  c : IoCase,
) -> (Array[@channel.ChanAction], @channel.ChanState, String, Bool) {
  let replies : Array[@channel.ChanAction] = []
  let mut st = @channel.ChanState::new(c.local_channel)
  let mut err = ""
  let mut send_idx = 0
  let mut preserved = true
  let mut pending = fill_bytes(c.stdin_byte, c.stdin_size)
  for i = 0; i < c.packets.length(); i = i + 1 {
    let p = c.packets[i]
    let payload = packet_payload(p, c.local_channel)
    let (st1, actions, e) = @channel.chan_step(
      st,
      p.msg_type.to_byte(),
      payload,
    )
    st = st1
    if err == "" {
      match e {
        None => ()
        Some(chan_err) => err = describe(chan_err)
      }
    }
    for j = 0; j < actions.length(); j = j + 1 {
      replies.push(actions[j])
    }
    let seen = i + 1
    while send_idx < c.client_sends.length() &&
          c.client_sends[send_idx].after <= seen {
      replies.push(
        Send(
          c.client_sends[send_idx].msg_type.to_byte(),
          hex_to_bytes(c.client_sends[send_idx].payload_hex),
        ),
      )
      send_idx = send_idx + 1
    }
    // stdin,按窗口夹取。夹到 0 就停在这里等下一个 WINDOW_ADJUST,
    // 而且此时缓冲必须原样退回——见 replay_stdin_plan 的说明。
    while pending.length() > 0 {
      let (c1, action, rest) = st.stdin_take(pending)
      st = c1
      match action {
        None => {
          if !bytes_equal(rest, pending) {
            preserved = false
          }
          break
        }
        Some(a) => {
          replies.push(a)
          pending = rest
        }
      }
    }
    // 缓冲排空才发 EOF。
    if pending.length() == 0 {
      let (c1, a) = st.eof_action()
      st = c1
      match a {
        None => ()
        Some(x) => replies.push(x)
      }
    }
  }
  (replies, st, err, preserved)
}

///|
/// env + stdin transcript 的完整比对。
///
/// `replies` 里含 stdin DATA 与 EOF,它们是**重建**出来的而不是照抄向量——否则
/// 一个把夹取写错的实现只要把向量的字节原样吐回去就能通过。
fn check_io(c : IoCase, fails : Array[String]) -> Unit {
  let (replies, st, err, preserved) = replay_io(c)
  if err != "" {
    fails.push(c.name + ": " + err)
    return
  }
  if !preserved {
    fails.push(c.name + ": stdin buffer was not returned intact on a stall")
    return
  }
  if replies.length() != c.replies.length() {
    fails.push(
      c.name +
      ": " +
      replies.length().to_string() +
      " client packets, vector says " +
      c.replies.length().to_string(),
    )
  } else {
    for i = 0; i < replies.length(); i = i + 1 {
      let (t, p) = action_bytes(replies[i])
      let want = c.replies[i]
      // 回复方向用的是**对端**给的通道号,和收包方向(我们自己的号)相反。
      let expect = reply_payload(want, c.remote_channel)
      if t != want.msg_type || !bytes_equal(p, expect) {
        fails.push(
          c.name +
          ": client packet " +
          i.to_string() +
          " is type " +
          t.to_string() +
          " " +
          short_hex(p) +
          ", expected type " +
          want.msg_type.to_string() +
          " " +
          want.payload_hex,
        )
        return
      }
    }
  }
  let report = st.report()
  if report.stdin_sent != c.stdin_sent ||
    report.stdin_packets != c.stdin_packets ||
    report.eof_sent != c.eof_sent {
    fails.push(
      c.name +
      ": stdin " +
      report.stdin_sent.to_string() +
      "B in " +
      report.stdin_packets.to_string() +
      " packets, eof=" +
      report.eof_sent.to_string() +
      "; vector says " +
      c.stdin_sent.to_string() +
      "B in " +
      c.stdin_packets.to_string() +
      ", eof=" +
      c.eof_sent.to_string(),
    )
  }
  let remaining = c.stdin_size - c.stdin_sent
  if remaining != c.stdin_remaining {
    fails.push(
      c.name +
      ": " +
      remaining.to_string() +
      " bytes left, vector says " +
      c.stdin_remaining.to_string(),
    )
  }
  if st.success_count != c.success_count {
    fails.push(
      c.name +
      ": " +
      st.success_count.to_string() +
      " successes, expected " +
      c.success_count.to_string(),
    )
  }
  if report.adjusts_sent != c.adjusts_sent {
    fails.push(
      c.name +
      ": " +
      report.adjusts_sent.to_string() +
      " adjusts, expected " +
      c.adjusts_sent.to_string(),
    )
  }
  if !bytes_equal(report.stdout, stream_bytes(c.stdout)) {
    fails.push(c.name + ": stdout mismatch")
  }
  if !bytes_equal(report.stderr, stream_bytes(c.stderr)) {
    fails.push(c.name + ": stderr mismatch")
  }
  if report.exit_status != c.exit_status {
    fails.push(
      c.name +
      ": exit " +
      report.exit_status.to_string() +
      ", expected " +
      c.exit_status.to_string(),
    )
  }
  if st.window.cur != c.final_cur {
    fails.push(
      c.name +
      ": local window " +
      st.window.cur.to_string() +
      ", expected " +
      c.final_cur.to_string(),
    )
  }
  if st.remote_window != c.final_remote_window {
    fails.push(
      c.name +
      ": remote window " +
      st.remote_window.to_string() +
      ", expected " +
      c.final_remote_window.to_string(),
    )
  }
}

///|
fn all_env_payloads(
  f : (EnvPayloadCase) -> Bool,
  label : String,
  fails : Array[String],
) -> Bool {
  for i = 0; i < kat_env_payload_cases.length(); i = i + 1 {
    if !f(kat_env_payload_cases[i]) {
      fails.push(label + ": " + kat_env_payload_cases[i].name)
      return false
    }
  }
  true
}

///|
fn all_stdin_cases(
  f : (StdinCase) -> Bool,
  label : String,
  fails : Array[String],
) -> Bool {
  for i = 0; i < kat_stdin_cases.length(); i = i + 1 {
    if !f(kat_stdin_cases[i]) {
      fails.push(label + ": " + kat_stdin_cases[i].name)
      return false
    }
  }
  true
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

///|
/// 类型,而递归版本没有任何歧义。
fn replay_window_go(
  sizes : Array[Int32],
  idx : Int32,
  acc : @channel.LocalWindow,
  amounts : Array[Int32],
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

///|
fn replay_window(sizes : Array[Int32]) -> (Array[Int32], @channel.LocalWindow) {
  let amounts : Array[Int32] = []
  let win = replay_window_go(sizes, 0, @channel.LocalWindow::new(), amounts)
  (amounts, win)
}

///|
fn chk_window(wc : WindowCase) -> Bool {
  let (amounts, win) = replay_window(wc.sizes)
  ints_equal(amounts, wc.adjust_amounts) &&
  win.cur == wc.final_cur &&
  win.consumed == wc.final_consumed
}

// ---------------------------------------------------------------------------
// session replay
// ---------------------------------------------------------------------------

///|
fn run_session_go(
  c : SessionCase,
  idx : Int32,
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
    Some(chan_err) =>
      errors.push("packet " + idx.to_string() + ": " + describe(chan_err))
  }
  for j = 0; j < actions.length(); j = j + 1 {
    replies.push(actions[j])
  }
  run_session_go(c, idx + 1, st1, replies, errors)
}

///|
fn run_session(
  c : SessionCase,
) -> (Array[@channel.ChanAction], @channel.ExecReport, String) {
  let replies : Array[@channel.ChanAction] = []
  let errors : Array[String] = []
  let st = run_session_go(
    c,
    0,
    @channel.ChanState::new(c.local_channel),
    replies,
    errors,
  )
  let first = if errors.length() == 0 { "" } else { errors[0] }
  (replies, st.report(), first)
}

///|

///| 跑一遍 transcript 并把每处不符写进 `fails`。

///|

///| 单独返回错误字符串而不是就地判定,是因为 1.5 MiB 的 bulk 用例不该为了

///|
/// 打印一条诊断跑三遍。
fn check_session(
  c : SessionCase,
  fails : Array[String],
) -> (@channel.ExecReport, Int32) {
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
      c.name +
      ": " +
      replies.length().to_string() +
      " replies, vector says " +
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
          c.name +
          ": reply " +
          i.to_string() +
          " is type " +
          t.to_string() +
          " " +
          short_hex(p) +
          ", expected type " +
          want.msg_type.to_string() +
          " " +
          want.payload_hex,
        )
      }
    }
  }
  let so = stream_bytes(c.stdout)
  let se = stream_bytes(c.stderr)
  if !bytes_equal(report.stdout, so) {
    fails.push(
      c.name +
      ": stdout " +
      report.stdout.length().to_string() +
      " bytes, expected " +
      so.length().to_string(),
    )
  }
  if !bytes_equal(report.stderr, se) {
    fails.push(
      c.name +
      ": stderr " +
      report.stderr.length().to_string() +
      " bytes, expected " +
      se.length().to_string(),
    )
  }
  if report.exit_status != c.exit_status {
    fails.push(
      c.name +
      ": exit " +
      report.exit_status.to_string() +
      ", expected " +
      c.exit_status.to_string(),
    )
  }
  if report.adjusts_sent != c.adjusts_sent {
    fails.push(
      c.name +
      ": " +
      report.adjusts_sent.to_string() +
      " adjusts, expected " +
      c.adjusts_sent.to_string(),
    )
  }
  if report.remote_id != c.remote_channel {
    fails.push(c.name + ": remote id " + report.remote_id.to_string())
  }
  (report, c.adjusts_sent)
}

///|
/// 把一组用例跑一遍,任一不符就往 `fails` 追加一条
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

///|
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
  println(
    "chan_extdata_payload: " + pf(all_payloads(chk_ext, "extdata", fails)),
  )
  println(
    "chan_adjust_payload: " + pf(all_payloads(chk_adjust, "adjust", fails)),
  )
  println("chan_bare_payload: " + pf(all_payloads(chk_bare, "bare", fails)))
  println(
    "chan_exit_status_payload: " + pf(all_payloads(chk_exit, "exit", fails)),
  )
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
  let adjusts : Array[Int32] = []
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
  let ids_split = kat_session_cases
    .filter(c => c.local_channel != c.remote_channel)
    .length()
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

  // ---- 6. 交互式:pty-req / shell / window-change / exit-signal ----
  println(
    "chan_pty_payloads: " +
    pf(all_shell_payloads(chk_shell_payloads, "shell_payloads", fails)),
  )
  println(
    "chan_exit_signal_parser: " +
    pf(all_shell_payloads(chk_exit_signal_rejects, "exit_signal", fails)),
  )
  let shell_fails : Array[String] = []
  for i = 0; i < kat_shell_cases.length(); i = i + 1 {
    let _r = check_shell(kat_shell_cases[i], shell_fails)
  }
  println("chan_shell_sessions: " + pf(shell_fails.length() == 0))
  for i = 0; i < shell_fails.length(); i = i + 1 {
    println("  chan_shell_fail: " + shell_fails[i])
  }
  // 防退化:没有「pty 被拒」的用例,就测不出驱动会不会正确降级;
  // 没有 resize 的用例,就测不出「window-change 不等回复」这件事。
  let has_no_pty = kat_shell_cases.any(c => c.name == "shell_no_pty")
  let has_resize = kat_shell_cases.any(c => c.name == "shell_resize")
  let has_signal = kat_shell_cases.any(c => c.name == "shell_exit_signal")
  println("chan_shell_cases: " + kat_shell_cases.length().to_string())
  println(
    "chan_shell_coverage: " +
    pf(has_no_pty && has_resize && has_signal && kat_shell_cases.length() >= 6),
  )

  // ---- 7. env 请求 + stdin 流控(channels.c:3085-3100)----
  println(
    "chan_env_payloads: " +
    pf(all_env_payloads(chk_env_payloads, "env_payloads", fails)),
  )
  println(
    "chan_eof_action: " +
    pf(all_env_payloads(chk_eof_action, "eof_action", fails)),
  )
  println(
    "chan_stdin_clamp: " +
    pf(all_stdin_cases(chk_stdin_plan, "stdin_clamp", fails)),
  )
  // 防退化:一个「有夹取」的用例和一个「夹到 0 也正常停」的用例都必须有。
  // 只有前者的实现会把窗口用光后当成错误,只有后者的实现会以为永远发得完。
  let clamp_stalls = kat_stdin_cases.filter(c => c.stalls > 0).length()
  let clamp_resumes = kat_stdin_cases
    .filter(c => c.consumed_adjusts > 0)
    .length()
  let clamp_by_window = kat_stdin_cases
    .filter(c => {
      c.window < c.max_packet && c.size > c.window && c.consumed_adjusts > 0
    })
    .length()
  println("chan_stdin_cases: " + kat_stdin_cases.length().to_string())
  println("chan_stdin_stall_cases: " + clamp_stalls.to_string())
  println("chan_stdin_resume_cases: " + clamp_resumes.to_string())
  println(
    "chan_stdin_window_tighter_than_packet: " + clamp_by_window.to_string(),
  )
  let io_fails : Array[String] = []
  for i = 0; i < kat_io_cases.length(); i = i + 1 {
    check_io(kat_io_cases[i], io_fails)
  }
  println("chan_io_sessions: " + pf(io_fails.length() == 0))
  for i = 0; i < io_fails.length(); i = i + 1 {
    println("  chan_io_fail: " + io_fails[i])
  }
  // env 必须排在 exec 之前,而 env 不带回包(§6.4),所以一条 env + 一条 exec
  // 只应得到 **1** 个 CHANNEL_SUCCESS。有 env 用例但没有「成功数只有 1」的
  // 断言,就测不出驱动是不是在等一个永远不会来的 env 确认。
  let env_cases = kat_io_cases.filter(c => c.name == "io_env_no_stdin")
  let one_success = env_cases.all(c => c.success_count == 1)
  let has_env = env_cases.length() > 0
  let has_stdin = kat_io_cases.any(c => c.stdin_packets > 0)
  let has_stalled = kat_io_cases.any(c => !c.eof_sent)
  let has_ids_split = kat_io_cases.any(c => c.local_channel != c.remote_channel)
  println("chan_io_cases: " + kat_io_cases.length().to_string())
  println(
    "chan_io_coverage: " +
    pf(has_env && one_success && has_stdin && has_stalled && has_ids_split),
  )
}
