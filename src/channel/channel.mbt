///| SSH connection protocol (RFC 4254) -- channel messages and the exec flow.
///
/// 权威依据全部取自 OpenSSH 的 C 源码,而不是从 RFC 的措辞推断——两处会
/// 直接决定远端命令能不能跑完:
///
///   * `channels.h:231-232`
///         #define CHAN_SES_PACKET_DEFAULT	(32*1024)
///         #define CHAN_SES_WINDOW_DEFAULT	(64*CHAN_SES_PACKET_DEFAULT)
///     即 window = 2 MiB,max_packet = 32 KiB。
///   * `channels.c:2444-2462` `channel_check_window`:WINDOW_ADJUST 的发送
///     条件不是「收够了就发」,而是
///     `local_consumed > 0 && (max - cur > maxpacket*3 || cur < max/2)`,
///     且发出去的数量是 `local_consumed`(累积量),发完清零。
///   * `session.c:2344-2347`:`exit-status` 是一条 **CHANNEL_REQUEST**
///     (`want_reply = 0`),后面跟 4 字节 u32 —— 不是 CHANNEL_DATA,也不是
///     EXTENDED_DATA。这是最容易写错的一处:解析器按 DATA 去读会一直等不到。
///   * `channels.c:3505-3523`:收到 DATA 时先扣 `local_window` 再累加
///     `local_consumed`,注释写明「发送方在发送时已经减过窗口,这边必须假装
///     消费掉,否则连接会死锁」。

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

///| 单个 channel 的最大包长(channels.h:231 CHAN_SES_PACKET_DEFAULT)
pub const CHAN_PACKET_DEFAULT : Int = 32 * 1024

///| 本端初始窗口(channels.h:232 CHAN_SES_WINDOW_DEFAULT = 64 * 32 KiB)
pub const CHAN_WINDOW_DEFAULT : Int = 64 * CHAN_PACKET_DEFAULT

///| SSH2_EXTENDED_DATA_STDERR(channels.c:3128)
pub const EXTENDED_DATA_STDERR : Int = 1

///| 我们作为客户端使用的本地 channel 号
pub const LOCAL_CHANNEL : Int = 0

///| 我们作为客户端使用的本地 channel 号(可传别的值)
pub const DEFAULT_LOCAL_CHANNEL : Int = 0

// ---------------------------------------------------------------------------
// Outbound payloads
// ---------------------------------------------------------------------------

///| ASCII 文本 -> 字节。与 `src/userauth` 里的同名私有函数重复是有意的:
/// 从 `src/sshclient` 拿会把 `@tcp` 拖进来,而 `src/sshwire` 不依赖任何东西。
fn ch_ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///| 字节串拼接
pub fn ch_cat(
  a : FixedArray[Byte],
  b : FixedArray[Byte],
) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(
    a.length() + b.length(),
    b'\x00',
  )
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  out
}

///|
/// 拼若干段
pub fn ch_cat_all(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut at = 0
  for p in parts {
    for i = 0; i < p.length(); i = i + 1 {
      out[at + i] = p[i]
    }
    at = at + p.length()
  }
  out
}

///| u32 小端写入(channels.c 用的是 `sshpkt_put_u32`,即网络字节序大端)
fn u32be(v : Int) -> FixedArray[Byte] {
  @sshwire.write_u32(v.reinterpret_as_uint())
}

///|
/// CHANNEL_OPEN (RFC 4254 §5.1 / channels.c:1171-1175)
///
///     string  "session"
///     uint32  sender channel
///     uint32  initial window size
///     uint32  maximum packet size
pub fn channel_open_payload(
  sender : Int,
  window : Int,
  max_packet : Int,
) -> FixedArray[Byte] {
  ch_cat_all([
    @sshwire.write_ssh_string(ch_ascii("session")),
    u32be(sender),
    u32be(window),
    u32be(max_packet),
  ])
}

///|
/// CHANNEL_REQUEST (RFC 4254 §6.1 / channels.c:1948)
///
///     uint32  recipient channel
///     string  request type
///     boolean want reply
///     ...    type-specific
pub fn channel_request_payload(
  recipient : Int,
  request_type : String,
  want_reply : Bool,
  extra : FixedArray[Byte],
) -> FixedArray[Byte] {
  ch_cat_all([
    u32be(recipient),
    @sshwire.write_ssh_string(ch_ascii(request_type)),
    FixedArray::from_array([if want_reply { b'\x01' } else { b'\x00' }]),
    extra,
  ])
}

///|
/// CHANNEL_REQUEST "exec"(RFC 4254 §6.2 / sshconnect2.c)
///
///     uint32  recipient channel
///     string  "exec"
///     boolean TRUE
///     string  command
pub fn channel_exec_payload(
  recipient : Int,
  command : String,
) -> FixedArray[Byte] {
  channel_request_payload(
    recipient,
    "exec",
    true,
    @sshwire.write_ssh_string(ch_ascii(command)),
  )
}

///|
/// CHANNEL_REQUEST "env"(RFC 4254 §6.4 / clientloop.c:2700-2711)
///
///     uint32  recipient channel
///     string  "env"
///     boolean FALSE
///     string  name
///     string  value
///
/// **只有 name 和 value 两个 string**,后面紧跟服务端的 `sshpkt_get_end`
/// (session.c:2042-2044)。多写一个字段会被判成协议错误——而服务端的反应是
/// `sshpkt_fatal`,直接断链,不是忽略。
///
/// `want_reply` 是 **FALSE**,两个权威一致:RFC 4254 §6.4 原文 "No response is
/// returned by the server";客户端 `client_send_env` 也是
/// `channel_request_start(ssh, id, "env", 0)`(clientloop.c:2706)。
/// 写 TRUE 也能通(服务端的 want_reply 是通用的,会回 CHANNEL_FAILURE),
/// 但那样「服务端没配 AcceptEnv」就变成每次连接一条额外来回——而 OpenSSH
/// 行为上就是完全静默。
///
/// 顺带一个只有读 C 才看得到的约束:`env` 只在会话还是 **LARVAL** 状态时才被
/// 处理(session.c:2175-2192),也就是必须在 exec / shell 之前发;发晚了
/// `session_input_channel_req` 直接不进那个 if,请求被无声丢弃。
pub fn channel_env_payload(
  recipient : Int,
  name : String,
  value : String,
) -> FixedArray[Byte] {
  channel_request_payload(
    recipient,
    "env",
    false,
    ch_cat_all([
      @sshwire.write_ssh_string(ch_ascii(name)),
      @sshwire.write_ssh_string(ch_ascii(value)),
    ]),
  )
}

///| CHANNEL_WINDOW_ADJUST 的 payload(uint32 recipient, uint32 bytes)
pub fn channel_window_adjust_payload(
  recipient : Int,
  bytes : Int,
) -> FixedArray[Byte] {
  ch_cat(u32be(recipient), u32be(bytes))
}

///| CHANNEL_DATA 的 payload(uint32 recipient, string data)
pub fn channel_data_payload(
  recipient : Int,
  data : FixedArray[Byte],
) -> FixedArray[Byte] {
  ch_cat(u32be(recipient), @sshwire.write_ssh_string(data))
}

///| CHANNEL_EXTENDED_DATA 的 payload(uint32 recipient, uint32 code, string data)
pub fn channel_extended_data_payload(
  recipient : Int,
  code : Int,
  data : FixedArray[Byte],
) -> FixedArray[Byte] {
  ch_cat_all([
    u32be(recipient),
    u32be(code),
    @sshwire.write_ssh_string(data),
  ])
}

///| 只有 channel 号的 payload(CHANNEL_SUCCESS / FAILURE / EOF / CLOSE)
pub fn channel_bare_payload(recipient : Int) -> FixedArray[Byte] {
  u32be(recipient)
}

// ---------------------------------------------------------------------------
// Interactive: pty-req / shell / window-change
// ---------------------------------------------------------------------------

///| tty modes 串的结束符(ttymodes.c:60 `TTY_OP_END`)
pub const TTY_OP_END : Byte = b'\x00'

///| 波特率 opcode(ttymodes.c:64 `TTY_OP_ISPEED = 128`)
pub const TTY_OP_ISPEED : Byte = b'\x80'

///| 波特率 opcode(ttymodes.c:65 `TTY_OP_OSPEED = 129`)
pub const TTY_OP_OSPEED : Byte = b'\x81'

///| 空 string(pty/shell 请求的尾部就是它)
fn empty_wire() -> FixedArray[Byte] {
  FixedArray::make(0, b'\x00')
}

///|
/// tty modes 串:`opcode-u32` 对,最后跟一个 `TTY_OP_END`(ttymodes.c:371-376)
///
/// **注意这个串外面还包了一层 string**——`ssh_tty_make_modes` 先
/// `sshbuf_put_u8(buf, TTY_OP_END)` 再 `sshbuf_put_stringb(ssh, buf)`
/// (ttymodes.c:331-332),服务端 `ssh_tty_parse_modes` 第一件事也是
/// `sshpkt_get_string_direct`(:352)。少包这一层的话,服务端会把 4 字节的
/// 长度前缀当成 opcode。
///
/// 只发一个结束符是合法且最小的:modes 里的 opcode 本来就是「客户端报它知道
/// 的、服务端忽略它不认识的」,不发任何东西服务端也能接受
/// (`ttymodes.c:354` 的 `if (len == 0) return;`,paramiko 就是这么发的)。
/// 我们跟 OpenSSH 客户端(`clientloop.c:2746`)一样把结束符带上。
pub fn tty_modes_bytes(baud : Int) -> FixedArray[Byte] {
  ch_cat_all([
    FixedArray::from_array([TTY_OP_ISPEED]),
    u32be(baud),
    FixedArray::from_array([TTY_OP_OSPEED]),
    u32be(baud),
    FixedArray::from_array([TTY_OP_END]),
  ])
}

///|
/// CHANNEL_REQUEST "pty-req"(RFC 4254 §6.2 / clientloop.c:2735-2748)
///
///     uint32  recipient channel
///     string  "pty-req"
///     boolean TRUE
///     string  TERM
///     uint32  terminal width  (characters)
///     uint32  terminal height (characters)
///     uint32  terminal width  (pixels)
///     uint32  terminal height (pixels)
///     string  modes
///
/// 字段顺序是**先宽后高**:客户端 `sshpkt_put_u32(ws.ws_col)` 在前
/// (clientloop.c:2739),服务端 `sshpkt_get_u32(&s->col)` 也在前
/// (session.c:1872)。写成 row-then-col 的话 pty 照样能开,但窗口尺寸整个
/// 转置,而「转置后仍然是合法 pty」正是它容易蒙混过关的原因。
pub fn channel_pty_req_payload(
  recipient : Int,
  term : String,
  cols : Int,
  rows : Int,
  pixel_width : Int,
  pixel_height : Int,
  modes : FixedArray[Byte],
) -> FixedArray[Byte] {
  channel_request_payload(
    recipient,
    "pty-req",
    true,
    ch_cat_all([
      @sshwire.write_ssh_string(ch_ascii(term)),
      u32be(cols),
      u32be(rows),
      u32be(pixel_width),
      u32be(pixel_height),
      @sshwire.write_ssh_string(modes),
    ]),
  )
}

///|
/// CHANNEL_REQUEST "shell"(RFC 4254 §6.5)
///
/// 除了公共前缀之外没有别的字段——交互式 shell 不带命令,命令由之后
/// CHANNEL_DATA(stdin)送上去。
pub fn channel_shell_payload(recipient : Int) -> FixedArray[Byte] {
  channel_request_payload(recipient, "shell", true, empty_wire())
}

///|
/// CHANNEL_REQUEST "subsystem"(RFC 4254 §6.5 / clientloop.c:2799-2811)
///
///     uint32  recipient channel
///     string  "subsystem"
///     boolean TRUE
///     string  subsystem name
///
/// `want_reply` 是 TRUE,而且**必须**是 TRUE。OpenSSH 客户端发的是
/// `channel_request_start(ssh, id, "subsystem", 1)` 紧跟一个
/// `client_expect_confirm(ssh, id, "subsystem", CONFIRM_CLOSE)`
/// (clientloop.c:2801-2803)——它会**等**服务端回 CHANNEL_SUCCESS,拿不到就
/// 关掉通道。这和 `env`(want_reply=FALSE,永不回包)是反的,也是本项目里
/// 第一个「必须等回包」的通道请求:子系统名写错时服务端回 CHANNEL_FAILURE,
/// 而这个 FAILURE 是唯一能告诉你「名字不对」的信号。
///
/// 服务端读法是 `sshpkt_get_cstring` 紧跟 `sshpkt_get_end`
/// (session.c:1915-1916),所以 name 之后多一个字节就是协议错误——和
/// `window-change` 一样,这里不放 modes 串。
///
/// 另外 `exec` 和 `shell` 之后通道里是「远端进程的字节」,`subsystem` 之后是
/// 「子系统自己的字节」:SFTP 的包被原样塞进 CHANNEL_DATA,两端都不解释它。
/// 这一点不是这里实现的——它在 `src/sftp`,而这层只负责把请求发出去。
pub fn channel_subsystem_payload(
  recipient : Int,
  name : String,
) -> FixedArray[Byte] {
  channel_request_payload(
    recipient,
    "subsystem",
    true,
    @sshwire.write_ssh_string(ch_ascii(name)),
  )
}

///|
/// CHANNEL_REQUEST "window-change"(RFC 4254 §6.7 / session.c:1847-1851)
///
///     uint32  recipient channel
///     string  "window-change"
///     boolean FALSE
///     uint32  columns
///     uint32  rows
///     uint32  pixel width
///     uint32  pixel height
///
/// `want_reply` 是 FALSE:服务端 `session_window_change_req` 直接
/// `return 1` 不回任何东西,我们若等一个 CHANNEL_SUCCESS 就会一直等下去。
///
/// 这里也没有 modes 串——服务端读完这四个 u32 紧跟一个
/// `sshpkt_get_end`(:1851),多写字节会被当成协议错误。
pub fn channel_window_change_payload(
  recipient : Int,
  cols : Int,
  rows : Int,
  pixel_width : Int,
  pixel_height : Int,
) -> FixedArray[Byte] {
  channel_request_payload(
    recipient,
    "window-change",
    false,
    ch_cat_all([
      u32be(cols),
      u32be(rows),
      u32be(pixel_width),
      u32be(pixel_height),
    ]),
  )
}

///|
/// CHANNEL_REQUEST "exit-signal"(RFC 4254 §6.10)——**收方向**的解析
///
///     string  signal name       ("TERM" / "KILL" / ...)
///     boolean core dumped
///     string  language tag
///     string  error message
///
/// 远端命令被信号杀死时,服务端发的是这个而不是 `exit-status`。只认
/// `exit-status` 的客户端会等不到退出码,最后以「连接关闭、没有状态」收场——
/// 看起来就像命令没产生任何输出。
pub fn parse_exit_signal(
  payload : FixedArray[Byte],
  off : Int,
) -> ((String, Bool, String)?) {
  match read_string_at(payload, off) {
    None => None
    Some((name, o1)) =>
      if o1 >= payload.length() {
        None
      } else {
        let core = payload[o1] == b'\x01'
        match read_string_at(payload, o1 + 1) {
          None => None
          // 语言标记按 RFC 4254 §6.10 是「发送方建议的 RFC 1766 语言」,实践中恒为空。
          // 我们不翻译,所以直接丢掉。
          Some((_lang, o2)) =>
            match read_string_at(payload, o2) {
              None => None
              Some((msg, o3)) =>
                if o3 != payload.length() {
                  None
                } else {
                  Some((
                    bytes_to_ascii_str(name),
                    core,
                    bytes_to_ascii_str(msg),
                  ))
                }
            }
        }
      }
  }
}

// ---------------------------------------------------------------------------
// Inbound parsers
// ---------------------------------------------------------------------------

///| 从 `off` 处读 u32,返回 `(值, 新偏移)`;越界返回 None
pub fn read_u32_at(
  b : FixedArray[Byte],
  off : Int,
) -> (Int, Int)? {
  if off < 0 || off + 4 > b.length() {
    return None
  }
  let v =
    (b[off].to_int() << 24) |
    (b[off + 1].to_int() << 16) |
    (b[off + 2].to_int() << 8) |
    b[off + 3].to_int()
  Some((v, off + 4))
}

///| 从 `off` 处读 string,返回 `(字节, 新偏移)`
pub fn read_string_at(
  b : FixedArray[Byte],
  off : Int,
) -> (FixedArray[Byte], Int)? {
  match read_u32_at(b, off) {
    None => None
    Some((n, o)) =>
      if o + n > b.length() {
        None
      } else {
        let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
        for i = 0; i < n; i = i + 1 {
          out[i] = b[o + i]
        }
        Some((out, o + n))
      }
  }
}

///| 把字节当 ASCII 串(只用于和协议里的字面量比较)
pub fn bytes_to_ascii_str(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
/// CHANNEL_OPEN_CONFIRMATION (§5.1)
///
///     uint32  recipient channel (ours)
///     uint32  sender channel (theirs -- **this** is what later messages address)
///     uint32  initial window size
///     uint32  maximum packet size
///
/// 注意第二个字段:后面所有发回去的包(REQUEST / DATA / WINDOW_ADJUST / EOF /
/// CLOSE)用的都是对端给的这个号,不是我们自己开通道时用的 0。
pub fn parse_open_confirmation(
  payload : FixedArray[Byte],
) -> (Int, Int, Int)? {
  match read_u32_at(payload, 0) {
    None => None
    Some((_, o1)) =>
      match read_u32_at(payload, o1) {
        None => None
        Some((sender, o2)) =>
          match read_u32_at(payload, o2) {
            None => None
            Some((window, o3)) =>
              match read_u32_at(payload, o3) {
                None => None
                Some((maxp, o4)) =>
                  if o4 != payload.length() {
                    None
                  } else {
                    Some((sender, window, maxp))
                  }
              }
          }
      }
  }
}

///|
/// CHANNEL_OPEN_FAILURE (§5.1):uint32 recipient, uint32 reason, string description,
/// string language tag
pub fn parse_open_failure(
  payload : FixedArray[Byte],
) -> (Int, String)? {
  match read_u32_at(payload, 0) {
    None => None
    Some((_, o1)) =>
      match read_u32_at(payload, o1) {
        None => None
        Some((reason, o2)) =>
          match read_string_at(payload, o2) {
            None => None
            Some((desc, o3)) =>
              match read_string_at(payload, o3) {
                None => None
                Some((_, o4)) =>
                  if o4 != payload.length() {
                    None
                  } else {
                    Some((reason, bytes_to_ascii_str(desc)))
                  }
              }
          }
      }
  }
}

///| CHANNEL_DATA:uint32 recipient, string data
pub fn parse_data(
  payload : FixedArray[Byte],
) -> (Int, FixedArray[Byte])? {
  match read_u32_at(payload, 0) {
    None => None
    Some((who, o1)) =>
      match read_string_at(payload, o1) {
        None => None
        Some((d, o2)) =>
          if o2 != payload.length() {
            None
          } else {
            Some((who, d))
          }
      }
  }
}

///| CHANNEL_EXTENDED_DATA:uint32 recipient, uint32 code, string data
pub fn parse_extended_data(
  payload : FixedArray[Byte],
) -> (Int, Int, FixedArray[Byte])? {
  match read_u32_at(payload, 0) {
    None => None
    Some((who, o1)) =>
      match read_u32_at(payload, o1) {
        None => None
        Some((code, o2)) =>
          match read_string_at(payload, o2) {
            None => None
            Some((d, o3)) =>
              if o3 != payload.length() {
                None
              } else {
                Some((who, code, d))
              }
          }
      }
  }
}

///| CHANNEL_WINDOW_ADJUST:uint32 recipient, uint32 bytes to add
pub fn parse_window_adjust(
  payload : FixedArray[Byte],
) -> (Int, Int)? {
  match read_u32_at(payload, 0) {
    None => None
    Some((who, o1)) =>
      match read_u32_at(payload, o1) {
        None => None
        Some((n, o2)) =>
          if o2 != payload.length() {
            None
          } else {
            Some((who, n))
          }
      }
  }
}

///|
/// CHANNEL_REQUEST 的公共前缀:uint32 recipient, string type, boolean want_reply
///
/// 第三个返回值是 type-specific 部分的起始偏移——`exit-status` 的 u32 就从
/// 这里开始读(session.c:2345 `sshpkt_put_u32` 紧跟在 `channel_request_start`
/// 之后)。返回 None 表示 want_reply 之后连一个字节都没有。
pub fn parse_request_header(
  payload : FixedArray[Byte],
) -> (Int, String, Bool, Int)? {
  match read_u32_at(payload, 0) {
    None => None
    Some((who, o1)) =>
      match read_string_at(payload, o1) {
        None => None
        Some((t, o2)) =>
          if o2 >= payload.length() {
            None
          } else {
            let want = payload[o2] == b'\x01'
            Some((who, bytes_to_ascii_str(t), want, o2 + 1))
          }
      }
  }
}

///| 只有 channel 号的包(SUCCESS / FAILURE / EOF / CLOSE)
pub fn parse_channel_id(payload : FixedArray[Byte]) -> Int? {
  match read_u32_at(payload, 0) {
    None => None
    Some((v, o1)) => if o1 == payload.length() { Some(v) } else { None }
  }
}

// ---------------------------------------------------------------------------
// Local window bookkeeping
// ---------------------------------------------------------------------------

///|
/// 本端窗口记账,逐字对应 channels.c 的 `local_window` / `local_window_max` /
/// `local_consumed` 三个字段。
///
/// `consumed` 是**已消费但还没发 WINDOW_ADJUST 的字节数**。发出去的是这个
/// 累积量而不是「补到多少」——两者都能让连接继续,但只有累积量与 C 一致,
/// 对拍时不会差一个常数。
pub(all) struct LocalWindow {
  max : Int
  cur : Int
  consumed : Int
  max_packet : Int
}

///| 初始窗口:max = cur = CHAN_WINDOW_DEFAULT,consumed = 0
pub fn LocalWindow::new() -> LocalWindow {
  {
    max: CHAN_WINDOW_DEFAULT,
    cur: CHAN_WINDOW_DEFAULT,
    consumed: 0,
    max_packet: CHAN_PACKET_DEFAULT,
  }
}

///|
/// 消费 `n` 字节(channels.c:3518-3523)
///
/// 扣减用饱和语义:窗口不足时置 0 而不是绕回。绕回会让后续每一次消费都
/// 「成功」,而实际早就没有窗口了。
pub fn LocalWindow::consume(self : LocalWindow, n : Int) -> LocalWindow {
  let next = if n > self.cur { 0 } else { self.cur - n }
  { max: self.max, cur: next, consumed: self.consumed + n, max_packet: self.max_packet }
}

///|
/// 是否到了该发 WINDOW_ADJUST 的时候(channels.c:2444-2449)
///
///     local_consumed > 0 &&
///     (local_window_max - local_window > local_maxpacket*3 ||
///      local_window < local_window_max/2)
///
/// 写成一个函数而不是散在驱动里,是因为这两个条件缺一个都会死锁:只按
/// 「消费过半」判会在 fastlane 上退化成每个包都发一个 WINDOW_ADJUST。
pub fn LocalWindow::should_adjust(self : LocalWindow) -> Bool {
  if self.consumed <= 0 {
    return false
  }
  (self.max - self.cur > self.max_packet * 3) ||
  (self.cur < self.max / 2)
}

///|
/// 取走这次要发出去的调整量,并把窗口加回去(channels.c:2455/2461-2462)
///
/// 返回 None 表示现在不该发。`take` 之后 `consumed` 归零、`cur` 增加。
pub fn LocalWindow::take_adjust(self : LocalWindow) -> LocalWindow? {
  if !self.should_adjust() {
    return None
  }
  Some({
    max: self.max,
    cur: self.cur + self.consumed,
    consumed: 0,
    max_packet: self.max_packet,
  })
}

///| 这次调整要发多少字节
pub fn LocalWindow::adjust_amount(self : LocalWindow) -> Int {
  self.consumed
}