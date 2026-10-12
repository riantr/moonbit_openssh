///| cmd/ssh_live -- Loop #31 real handshake against a live OpenSSH server

///|

///|   Usage: ssh_live <port>   (default 22222)
///

///|   Every field printed here came off a real socket. `result: ESTABLISHED`

///|   means an OpenSSH 8.0p1 server accepted our KEXINIT, we computed the same

///|   exchange hash it did, and it signed that hash with an ECDSA P-256 host key

///|   that our own verifier accepted.

///|
/// DH private exponent. A production client draws this from the CSPRNG and
/// never reuses it; fixing it here keeps the byte transcript reproducible so a
/// diff against the paramiko capture is meaningful. The value is well above
/// 2^ so it is not a toy magnitude for a 2048-bit group.
fn fixed_x() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0x5A, 0x17, 0xC3, 0x9E, 0x44, 0xB2, 0x6D, 0xF1, 0x08, 0xA7, 0x35, 0xCC, 0x91,
    0x2E, 0x60, 0xD3, 0x74, 0x18, 0x9F, 0xE2, 0x50, 0xB7, 0xC6, 0x3D, 0x81, 0x0A,
    0xF5, 0x29, 0x64, 0xC8, 0x7B, 0x1E,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
fn live_error_name(e : @sshclient.LiveError) -> String {
  match e {
    ConnectFailed => "ConnectFailed"
    NoServerIdent => "NoServerIdent"
    KexinitSendFailed => "KexinitSendFailed"
    NoPeerKexinit => "NoPeerKexinit"
    KexinitParseFailed => "KexinitParseFailed"
    NoAgreement(_) => "NoAgreement"
    EcdhInitSendFailed => "EcdhInitSendFailed"
    NoEcdhReply => "NoEcdhReply"
    EcdhReplyMalformed => "EcdhReplyMalformed"
    HostkeyInvalid => "HostkeyInvalid"
    SignatureInvalid(h) => "SignatureInvalid"
    // Loop #48: pinning failures get their own labels because "we refused"
    // and "we refused *because the key is not the one we pinned*" call for
    // different responses, and collapsing them would make the second one
    // indistinguishable from a network fault.
    HostkeyMismatch(h) => "HostkeyMismatch"
    HostkeyUnknown(h) => "HostkeyUnknown"
    NewkeysSendFailed => "NewkeysSendFailed"
    NoNewkeys => "NoNewkeys"
    BadPacket => "BadPacket"
  }
}

///|
fn session_error_name(e : @sshclient.SessionError) -> String {
  match e {
    @sshclient.HandshakeFailed(h) => "handshake:" + live_error_name(h)
    @sshclient.NoServiceAccept => "NoServiceAccept"
    @sshclient.UnexpectedService(s) => "UnexpectedService:" + s
    // BadPacket 带上原因而不是一个光秃秃的标签:它是整条链上唯一能区分
    // 「对端没说话」和「对端说了但我们解不开」的地方。
    @sshclient.BadPacket(w) => "BadPacket:" + w
  }
}

///|
/// AuthRejected 携带的证据(原因 + 我们签的那串字节 + 签名)由调用方直接打印,
/// 这里只给一个短标签。理由字段在这一层已经丢了,细节不该藏在一个拼接出来的
/// 字符串里——它得能被单独解析。
fn auth_error_name(e : @sshclient.AuthError) -> String {
  match e {
    @sshclient.Transport(s) => "transport:" + session_error_name(s)
    @sshclient.SignFailed => "SignFailed"
    @sshclient.NoAuthReply => "NoAuthReply"
    @sshclient.AuthRejected(_, _, _) => "AuthRejected"
    @sshclient.BadPacket(w) => "BadPacket:" + w
  }
}

///|
fn print_auth_rejection(e : @sshclient.AuthError) -> Unit {
  match e {
    @sshclient.AuthRejected(r, sb, sg) => {
      println("result: USERAUTH_FAILURE")
      println("reason: " + r)
      println("signed_blob: " + sb)
      println("sig_blob: " + sg)
    }
    _ => ()
  }
}

///|
/// Loop #34 的测试私钥:即 RFC 6979 A.2.5 公布的 NIST P-256 key。
///
/// 这把私钥出现在 RFC 原文里,只可能用于本 loop 那台一次性 sshd 的
/// authorized_keys。**绝不能**用在真实主机上——公开的私钥等于没有私钥。
/// 生产客户端必须从 CSPRNG 取 d,并且用完即弃。
fn test_auth_key() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67,
    0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A,
    0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
/// Decimal string to Int, or `fallback` if it is not a bare 1-5 digit number.
/// Kept local rather than reaching for a parser from the standard library,
/// whose surface differs across MoonBit releases and this driver only ever
/// needs a port number. `fallback = 0` means "not a port", which lets the
/// caller scan argv without a separate validity flag.
fn parse_port(s : String, fallback : Int) -> Int {
  let n = s.length()
  if n == 0 || n > 5 {
    return fallback
  }
  let mut acc = 0
  let mut i = 0
  while i < n {
    let c = s[i].to_int()
    if c < 48 || c > 57 {
      return fallback
    }
    acc = acc * 10 + (c - 48)
    i = i + 1
  }
  acc
}

///|
/// Pick the port out of argv, whatever the backend's argv looks like.
///
/// The native backend passes [exe_path, ...user]. The js backend passes
/// process.argv, so argv[1] is the script path rather than a user argument,
/// and blindly indexing argv[1] silently falls back to the default port
/// instead of honouring what the caller asked for. Scanning for the first
/// argument that actually parses as a port is backend-agnostic and cannot
/// pick up a path component by accident -- a path segment is not all digits.
fn find_port(argv : Array[String]) -> Int {
  let mut i = 1
  while i < argv.length() {
    match parse_port(argv[i], 0) {
      0 => ()
      p => return p
    }
    i = i + 1
  }
  22222
}

///|

///|
/// Does the caller want the Loop #33 encrypted-session run instead of the
/// Loop #31 handshake-only run?
///
/// `--session` is scanned rather than read as argv[1] for the same reason the
/// port is: the native and js backends disagree about what argv[1] means.
fn wants_session(argv : Array[String]) -> Bool {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--session" {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// Loop #34 模式?(`--auth`)
///
/// 用户名来自 `--user <name>`。不猜:Windows 的 sshd 用的是本机账号名,
/// 而 MoonBit 没有一个跨后端可靠的 USERNAME 读取口(会拖进 `__moonbit_fs_unstable`),
/// 所以由调用方(verify_loop34.mjs)从 `process.env.USERNAME` 传进来。
/// 没传就用一个显眼的占位名,让它失败得清楚而不是连错账号。
fn auth_mode(argv : Array[String]) -> Bool {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--auth" {
      return true
    }
    i = i + 1
  }
  false
}

fn find_user(argv : Array[String]) -> String {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--user" && i + 1 < argv.length() {
      return argv[i + 1]
    }
    i = i + 1
  }
  "<no-user-given>"
}

///|
/// Loop #48: 主机密钥固定策略。
///
/// `--known-hosts-text <text>` 给的是 known_hosts 的**内容**,不是路径,而这是
/// 被迫的、也是对的:本项目的 moon 版本 core 里没有读文件的 API(`@env` 只有
/// argv / env / time),而 `src/wt` 更是 js-only、浏览器里根本没有文件系统。
/// 一个只在原生下可用的「读 known_hosts 文件」会把两条传输层驱动拆成两种行为,
/// 那正是这个仓库反复在付代价的漂移。文本两边都能带,判定也只有一个实现。
///
/// 附带的效果是:调用方必须自己已经拿着这份文本,这恰好是浏览器应用的真实处境。
///
/// `--kh-host <name>` 指明比哪个主机名,`--kh-port` 指明端口(默认沿用连接端口),
/// `--kh-strict` 让「这个主机压根没被固定过」也算失败。
///
/// **不带 `--known-hosts-text` 时是 skip,不是拒绝。** 这是本项目当前的策略,写
/// 在这里是因为它不安全:跳过固定意味着第一次连接、以及对端换过密钥之后的连接,
/// 都仍然可被中间人接管。OpenSSH 的默认是「比」,不是「跳」。
///
/// 没有把默认直接改成拒绝,是因为那会一次性改掉所有现有门禁的语义;「提供
/// 固定能力」和「默认拒绝」是两件事,混在一次改动里做,失败时无法判断是哪一半
/// 出了问题。
fn argv_value(argv : Array[String], name : String) -> String {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == name && i + 1 < argv.length() {
      return argv[i + 1]
    }
    i = i + 1
  }
  ""
}

fn has_switch(argv : Array[String], name : String) -> Bool {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == name {
      return true
    }
    i = i + 1
  }
  false
}

/// 端口只接受十进制数字,其它一律回落到 0。0 的含义是「端口从 `kh_host` 的
/// `[host]:port` 形式里读」——这是和 `cmd/wt_ssh` 的 `kh_port` 缺省值一样的
/// 语义,两条驱动必须一致,否则同一份 known_hosts 在两边会落到不同条目上。
/// 端口写错尤其难查:22 是最常见的那个,一个拼错的端口常常让比对**看起来通过**
/// 或**看起来是 Unknown**,两种都更像「配置没问题」。
fn parse_port_arg(s : String, fallback : Int) -> Int {
  if s.length() == 0 {
    return fallback
  }
  let mut acc = 0
  let mut i = 0
  while i < s.length() {
    let d = s[i].to_int() - 48
    if d < 0 || d > 9 {
      return 0
    }
    acc = acc * 10 + d
    i = i + 1
  }
  acc
}

fn kh_policy(argv : Array[String], port : Int) -> @knownhosts.KnownHostsPolicy {
  let text = argv_value(argv, "--known-hosts-text")
  if text == "" {
    return @knownhosts.KnownHostsPolicy::skip()
  }
  let p = @knownhosts.KnownHostsPolicy::from_text(
    text,
    argv_value(argv, "--kh-host"),
    parse_port_arg(argv_value(argv, "--kh-port"), 0),
    has_switch(argv, "--kh-strict"),
  )
  // 「给了文本但一条都没解析出来」必须报错,不能安静地变成 skip。
  // `verify` 看到空条目就返回 Skip,而调用方「要求固定」和「忘了固定」在那一层
  // 完全一样——一个看起来跑过的检查比没跑过的检查更危险。
  if p.entries.length() == 0 {
    println(
      "known_hosts: --known-hosts-text 解析出 0 条 -- 拒绝继续,而不是悄悄" +
      "跳过固定",
    )
    abort("known_hosts parsed to nothing")
  }
  p
}

///|
/// `--exec <cmd>` 之后的整段命令行就是远端命令(带空格也不拆)。
///
/// 同样不能假设 argv[1] 是用户参数:native 的 argv[0] 是 exe 路径,js 的
/// `process.argv` 前两个是 `[node, main.js]`。所以先扫描出 `--exec` 的位置,
/// 再把**后面全部**拼起来。
///
/// 遇到下一个 `--` 开头的参数就停。`--shell` 那边已经因为同样的理由踩过一次:
/// 不停的话 `--exec ... --env FOO=bar` 会把 `--env FOO=bar` 一起敲给远端命令,
/// 而远端照样跑成功、照样有输出——**只有远端命令本身解析参数时才看得出不对**,
/// 验证脚本会以为一切正常。
fn exec_command(argv : Array[String]) -> String? {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--exec" && i + 1 < argv.length() {
      let sb = StringBuilder()
      for j = i + 1; j < argv.length(); j = j + 1 {
        if is_switch(argv[j]) {
          break
        }
        if sb.to_string().length() > 0 {
          sb.write_char(' ')
        }
        sb.write_string(argv[j])
      }
      return Some(sb.to_string())
    }
    i = i + 1
  }
  None
}

///|
/// Loop #35:在真 sshd 上跑一条远端命令。
///
/// stdout / stderr 原样打出来(不做任何解码或转义),但同时给出长度和
/// SHA-256 摘要。验证脚本要比的是字节数与摘要,不是人眼读一遍——后者在输出
/// 里混进 ANSI 序列或非 ASCII 时会骗人。
fn run_exec(
  port : Int,
  command : String,
  stdin_data : FixedArray[Byte],
  envs : Array[@sshclient.EnvVar],
) -> Unit {
  let user = find_user(@env.args())
  println("=== Loop #35 exec vs real sshd ===")
  println("port: " + port.to_string())
  println("user: " + user)
  println("command: " + command)
  println("stdin_bytes: " + stdin_data.length().to_string())
  for i = 0; i < envs.length(); i = i + 1 {
    println("env: " + envs[i].name + "=" + envs[i].value)
  }
  match @tcp.TcpConn::connect("127.0.0.1", port) {
    None => {
      println("result: CONNECT_FAILED")
      return
    }
    Some(conn) => {
      let outcome = @sshclient.live_exec_io(
        conn,
        fixed_x(),
        user,
        test_auth_key(),
        command,
        stdin_data,
        envs,
        kh_policy(@env.args(), port),
      )
      conn.close()
      match outcome {
        @sshclient.Done(r) => {
          println("result: EXEC_DONE")
          println("stdout_len: " + r.stdout.length().to_string())
          println("stdout_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stdout)))
          // 原始字节也打成十六进制:长度和摘要对不上时,只有它能分清是「收到的
          // 字节不对」还是「摘要算错了」。超过 128 字节就截断并标注——长度和
          // 摘要才是判据,1.5 MB 的十六进制既刷屏又会顶掉后面的行。
          println("stdout_hex: " + dump_prefix(r.stdout))
          println("stderr_len: " + r.stderr.length().to_string())
          println("stderr_hex: " + @ecdsa.bytes_to_hex(r.stderr))
          println("stderr_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stderr)))
          println("exit_status: " + r.exit_status.to_string())
          println("remote_id: " + r.remote_id.to_string())
          println("adjusts_sent: " + r.adjusts_sent.to_string())
          // 流控的三个数:发出去多少字节、拆成几包、EOF 有没有跟上。
          // 字节数对但包数不对,说明夹取用的是错误的上限;EOF 没发,远端读到的是
          // 一个永远不结束的 stdin。
          println("stdin_sent: " + r.stdin_sent.to_string())
          println("stdin_packets: " + r.stdin_packets.to_string())
          println("eof_sent: " + yn(r.eof_sent))
          println("env_sent: " + r.env_sent.to_string())
          println("total_sent_bytes: " + r.sent_bytes.to_string())
          println("total_recv_bytes: " + r.recv_bytes.to_string())
          print_bytes(r.stdout)
          print_bytes(r.stderr)
        }
        @sshclient.AuthFailed(e) => {
          println("result: AUTH_FAILED")
          print_auth_rejection(e)
          println("error: " + auth_error_name(e))
        }
        @sshclient.ChannelFailed(e) => {
          println("result: CHANNEL_FAILED")
          println("error: " + exec_error_name(e))
        }
      }
    }
  }
}

///| 原始字节打进标记块,方便人看;验证脚本只读上面那几行数字。
///|
///| 截断上限 512 而不是 128:`Loop #37 的远端 fixture 会把 stdin 的字节数、摘要、
///| 首尾各 16 字节**和**环境变量一起打出来,一共将近 200 字节。128 会把最后
///| 几行静默吃掉,而截断块里没有任何提示说「后面还有内容被丢了」——验证脚本
///| 于是只能报一句「首尾不一致」,而真实原因是它根本没看到首尾。
fn print_bytes(b : FixedArray[Byte]) -> Unit {
  if b.length() == 0 {
    return
  }
  let n = if b.length() > 512 { 512 } else { b.length() }
  let sb = StringBuilder()
  for i = 0; i < n; i = i + 1 {
    sb.write_char(Int::unsafe_to_char(b[i].to_int()))
  }
  println("--- raw ---")
  println(sb.to_string())
  if n < b.length() {
    println("--- raw truncated at 512 of " + b.length().to_string() + " ---")
  }
  println("--- end raw ---")
}

///| 十六进制前缀,超过 512 字节同样截断并标注
fn dump_prefix(b : FixedArray[Byte]) -> String {
  let n = if b.length() > 512 { 512 } else { b.length() }
  let head = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    head[i] = b[i]
  }
  let s = @ecdsa.bytes_to_hex(head)
  if n < b.length() {
    s + "...(" + b.length().to_string() + " bytes total)"
  } else {
    s
  }
}

fn yn(b : Bool) -> String {
  if b {
    "true"
  } else {
    "false"
  }
}

fn exec_error_name(e : @sshclient.ExecError) -> String {
  match e {
    NoSessionState => "NoSessionState"
    Malformed(m) => "Malformed(" + m + ")"
    OpenFailed(r, d) => "OpenFailed(" + r.to_string() + ", " + d + ")"
    ExecRejected => "ExecRejected"
    SubsystemRejected => "SubsystemRejected"
    SendFailed => "SendFailed"
    BadPacket(w) => "BadPacket(" + w + ")"
    Closed => "Closed"
    TooManyPackets => "TooManyPackets"
    StdinStalled => "StdinStalled"
  }
}

///|
/// Loop #37:构造要送进远端 stdin 的字节。
///
/// 两个来源:`--stdin-bytes N` 造一段确定性数据,`--stdin-text <str>` 直接给字面量。
/// 没有「读文件」这条路——MoonBit 的 core 里没有 fs 包,硬塞一个 `@fs` 依赖只会
/// 让四条 target 的构建面变宽,而验证脚本要的是一段**能逐字节复现**的输入。
///
/// 模式串本体在 `@sshclient.ssh_stdin_pattern`:原生和 Worker 必须用同一份,
/// 否则「两条路径字节一致」这条断言就只是在比两段各自不同的数据。
fn stdin_pattern(n : Int) -> FixedArray[Byte] {
  @sshclient.ssh_stdin_pattern(n)
}

///| `--stdin-text <str>`;没给就返回空
fn text_flag(argv : Array[String]) -> FixedArray[Byte] {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--stdin-text" && i + 1 < argv.length() {
      return @sshclient.sh_ascii(argv[i + 1])
    }
    i = i + 1
  }
  FixedArray::make(0, b'\x00')
}

///| 组装 stdin:`--stdin-bytes` 优先,其次 `--stdin-text`,都没有就是空(等于 `ssh -n`)
fn stdin_bytes(argv : Array[String]) -> FixedArray[Byte] {
  let n = int_flag(argv, "--stdin-bytes", 0)
  if n > 0 {
    return stdin_pattern(n)
  }
  text_flag(argv)
}

///| 第一个 `=` 的下标;没有就返回 -1
fn index_of_eq(s : String) -> Int {
  for i = 0; i < s.length(); i = i + 1 {
    if s[i].to_int() == 61 {
      return i
    }
  }
  -1
}

///| 取 `s[from, to)`
fn slice_str(s : String, from : Int, to : Int) -> String {
  let sb = StringBuilder()
  let mut i = from
  while i < to {
    sb.write_char(Int::unsafe_to_char(s[i].to_int()))
    i = i + 1
  }
  sb.to_string()
}

///|
/// 收下所有 `--env NAME=VALUE`。
///
/// 重复的 `--env` 全部保留,不是「找到第一个就停」——`SendEnv` 本来就是一条一个,
/// 只认第一个会让多变量场景悄悄退化成单变量,而 KAT 里正好有一个两条 env 的用例。
///
/// 名字为空(`=VALUE`)直接丢掉:服务端的 `session_env_req` 对空名字只是走
/// `match_pattern` 失败然后静默忽略,发出去除了多一个包没有任何意义。
fn env_flags(argv : Array[String]) -> Array[@sshclient.EnvVar] {
  let out : Array[@sshclient.EnvVar] = []
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--env" && i + 1 < argv.length() {
      let spec = argv[i + 1]
      let at = index_of_eq(spec)
      if at > 0 {
        out.push({
          name: slice_str(spec, 0, at),
          value: slice_str(spec, at + 1, spec.length()),
        })
      }
    }
    i = i + 1
  }
  out
}

///|
/// `--shell <cmd>` 之后的整段是远端要敲的命令,`--cols/--rows/--resize` 控制
/// 窗口尺寸(给了 `--resize` 就再发一条 window-change)。
fn shell_mode(argv : Array[String]) -> (String, Int, Int, (Int, Int)?) {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--shell" && i + 1 < argv.length() {
      let sb = StringBuilder()
      for j = i + 1; j < argv.length(); j = j + 1 {
        // 遇到下一个开关就停。不停的话 `--shell echo hi --resize 132x43`
        // 会把 "--resize 132x43" 当成远端命令的一部分敲给 shell,而 shell
        // 照样会回显它——于是 marker 照样出现,一切「看起来」正常。
        if is_switch(argv[j]) {
          break
        }
        if sb.to_string().length() > 0 {
          sb.write_char(' ')
        }
        sb.write_string(argv[j])
      }
      return (sb.to_string(), 80, 24, None)
    }
    i = i + 1
  }
  ("", 80, 24, None)
}

///|
/// 一串十进制数字 -> Int;没有数字就 0。
///
/// `Int::from_string` is not usable here: it does not raise on a bad string,
/// so the `try`/`unwrap_or` around it is dead code, and on a backend where it
/// did raise the failure would be a crash rather than a default. Scanning
/// digits is what `int_flag` already does, and one rule for the whole driver
/// is worth more than a second, subtly different one.
fn parse_uint(s : String) -> Int {
  let mut v = 0
  let mut k = 0
  let mut any = false
  while k < s.length() {
    let d = s[k].to_int()
    if d >= 48 && d <= 57 {
      v = v * 10 + (d - 48)
      any = true
    }
    k = k + 1
  }
  if any { v } else { 0 }
}

///| 扫一个 `--flag <n>` 形式的数值参数
fn int_flag(argv : Array[String], name : String, fallback : Int) -> Int {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == name && i + 1 < argv.length() {
      let s = argv[i + 1]
      let mut v = 0
      let mut k = 0
      let mut any = false
      while k < s.length() {
        let d = s[k].to_int()
        if d >= 48 && d <= 57 {
          v = v * 10 + (d - 48)
          any = true
        }
        k = k + 1
      }
      if any {
        return v
      }
    }
    i = i + 1
  }
  fallback
}

///| 把 "132x43" 这样的字符串拆成 `(132, 43)`;不是这个形状就返回 None
///
/// 守卫用一个显式的 `seen_x`,而不是拿 `second` 是否为 0 代替——后者在读完
/// 第一个数、还没遇到 'x' 时也是 0,于是 "132x43" 被判成非法,而失败方式
/// 是「resize 没生效」而不是报错。
fn parse_size(s : String) -> (Int, Int)? {
  let mut first = -1
  let mut second = -1
  let mut seen_x = false
  let mut any_digit = false
  for i = 0; i < s.length(); i = i + 1 {
    let d = s[i].to_int()
    if d >= 48 && d <= 57 {
      if seen_x {
        if second < 0 {
          second = d - 48
        } else {
          second = second * 10 + (d - 48)
        }
      } else {
        if first < 0 {
          first = d - 48
        } else {
          first = first * 10 + (d - 48)
        }
      }
      any_digit = true
    } else if d == 120 || d == 88 {
      if seen_x || first <= 0 {
        return None
      }
      seen_x = true
    } else {
      return None
    }
  }
  if !seen_x || !any_digit || first <= 0 || second <= 0 {
    None
  } else {
    Some((first, second))
  }
}

///| `--resize <cols>x<rows>`;没给就返回 None(不发 window-change)
fn resize_flag(argv : Array[String]) -> (Int, Int)? {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--resize" && i + 1 < argv.length() {
      return parse_size(argv[i + 1])
    }
    i = i + 1
  }
  None
}

///|
/// Loop #36:开一个交互式 shell(带 pty),敲一条命令,可选地 resize,再退出。
fn run_shell(
  port : Int,
  command : String,
  cols : Int,
  rows : Int,
  resize : (Int, Int)?,
) -> Unit {
  let user = find_user(@env.args())
  println("=== Loop #36 interactive shell vs real sshd ===")
  println("port: " + port.to_string())
  println("user: " + user)
  println("command: " + command)
  println("cols: " + cols.to_string())
  println("rows: " + rows.to_string())
  match resize {
    Some((c, r)) => println("resize: " + c.to_string() + "x" + r.to_string())
    None => println("resize: none")
  }
  match @tcp.TcpConn::connect("127.0.0.1", port) {
    None => {
      println("result: CONNECT_FAILED")
      return
    }
    Some(conn) => {
      let outcome = @sshclient.live_shell(
        conn,
        fixed_x(),
        user,
        test_auth_key(),
        command,
        "xterm-256color",
        cols,
        rows,
        resize,
        kh_policy(@env.args(), port),
      )
      conn.close()
      match outcome {
        @sshclient.Done(r) => {
          println("result: SHELL_DONE")
          println("pty_granted: " + yn(r.pty_granted))
          println("resize_sent: " + yn(r.resize_sent))
          println("stdout_len: " + r.stdout.length().to_string())
          println("stdout_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stdout)))
          println("stderr_len: " + r.stderr.length().to_string())
          println("stderr_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stderr)))
          println("exit_status: " + r.exit_status.to_string())
          match r.exit_signal {
            None => println("exit_signal: none")
            Some((n, core)) =>
              println(
                "exit_signal: " + n + " core=" + yn(core),
              )
          }
          println("adjusts_sent: " + r.adjusts_sent.to_string())
          println("total_sent_bytes: " + r.sent_bytes.to_string())
          println("total_recv_bytes: " + r.recv_bytes.to_string())
          // 标志串是否出现在 stdout 里:pty 会把命令回显出来,这是「shell 真的
          // 跑起来了」最直接的证据——exit-status 0 只说明它正常退出了。
          let seen = @sshclient.sh_contains_bytes(r.stdout, @sshclient.sh_ascii(command))
          println("marker_seen: " + yn(seen))
          print_bytes(r.stdout)
          print_bytes(r.stderr)
        }
        @sshclient.AuthFailed(e) => {
          println("result: AUTH_FAILED")
          print_auth_rejection(e)
          println("error: " + auth_error_name(e))
        }
        @sshclient.ChannelFailed(e) => {
          println("result: CHANNEL_FAILED")
          println("error: " + exec_error_name(e))
        }
      }
    }
  }
}

///| 参数是不是一个开关(以 `--` 开头)
fn is_switch(s : String) -> Bool {
  s.length() > 2 && s[0].to_int() == 45 && s[1].to_int() == 45
}

///|
///|
/// `--proposal`: print the algorithm set this client offers, then exit.
///
/// Deliberately connects to nothing.  Loop #38's whole point is that the
/// proposal has to be complete *before* any server is involved, and a check
/// that needs a server running cannot tell "we offered fewer algorithms" from
/// "the server only had one".
fn proposal_flag(argv : Array[String]) -> Bool {
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--proposal" {
      return true
    }
    i = i + 1
  }
  false
}

fn run_proposal() -> Unit {
  let p = @sshclient.live_proposal()
  println("=== proposal (no connection attempted) ===")
  println("kex_algs: " + p.kex_algs)
  println("hostkey_algs: " + p.hostkey_algs)
  println("enc_ctos: " + p.enc_ctos)
  println("enc_stoc: " + p.enc_stoc)
  println("mac_ctos: " + p.mac_ctos)
  println("mac_stoc: " + p.mac_stoc)
  println("comp_ctos: " + p.comp_ctos)
  println("comp_stoc: " + p.comp_stoc)
}

///
/// Loop #39:SFTP / subsystem。
///
/// `--sftp <dir>` 是要列的目录,`--sftp-read <path>` 是要读的文件,`--sftp-missing`
/// 用来跑负面用例。输出全部是**长度 + SHA-256**,文件内容只给前 128 字节的
/// 十六进制:验证脚本要比的是字节,不是人眼读一遍,而 200 KB 的十六进制既刷屏
/// 又会把后面的行顶掉。
///
/// `--subsystem <name>` 故意传一个不存在的子系统名。这时必须报
/// `SubsystemRejected`,而不是「发了 INIT 之后莫名其妙没反应」:want_reply=TRUE
/// 的 CHANNEL_FAILURE 是「没有这个子系统」的唯一信号(session.c:1945-1948)。
///|
/// The payload a `--sftp-write` produces, from its length alone.
///
/// Written as a rule rather than read from a file because the browser path
/// cannot read one: `cmd/wt_ssh` runs in a Worker, where there is no
/// filesystem. Duplicating a literal blob in three places would be a way to
/// make the three disagree; a three-line arithmetic rule that the gate
/// re-derives in Python and compares by SHA-256 makes disagreement *visible*
/// instead. There is no SHA-256, no RNG and no encoding step here precisely
/// so that native, js, wasm and wasm-gc cannot produce different bytes.
fn payload_of(n : Int) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ((i * 31 + 7) % 256).to_byte()
  }
  out
}

///| 最后一个 `@` 的下标;没有就 -1。
///
/// 手写而不是用 `last_index_of`:那个方法在本仓这版 moon 上不存在,而为一个
/// 只用一次的查找去引新依赖不值得。
fn last_at(s : String) -> Int {
  let mut k = s.length()
  while k > 0 {
    k = k - 1
    if s[k].to_int() == 64 {
      return k
    }
  }
  -1
}

///|
/// `<path>@<size>` 一整个 token,而不是 `<path> <size>` 两个槽。
///
/// 原因不是偷懒:这个驱动的端口是**裸数字**参数(`cmd/ssh_live ... 18781`),
/// `find_port` 扫的就是第一个能解析成端口的参数。size 若单独占一个槽,在端口
/// 之前就会被当成端口,然后连 127.0.0.1:40000 也连不上——报出来的是
/// CONNECT_FAILED,看起来像客户端坏了,其实是一个自造的参数冲突。
///
/// 分隔符用 `@` 而不是 `:`:Windows 路径 `C:/...` 里本来就有冒号。
fn split_at_last(spec : String) -> (String, Int) {
  let at = last_at(spec)
  if at < 0 {
    return (spec, 0)
  }
  (spec.unsafe_substring(start=0, end=at),
   parse_uint(spec.unsafe_substring(start=at + 1, end=spec.length())))
}

fn sftp_mode(argv : Array[String], port : Int) -> Bool {
  let mut dir : String? = None
  // 可以给多次:`--sftp-read a --sftp-read b` 就是脚本里的两个 ReadFile。
  // 只保留最后一个的话,验证脚本就没法在一次会话里同时读小文件和大文件,而
  // 「大文件要跨很多次 READ」正是这一轮要证明的事。
  let mut missing = false
  let mut subsystem = "sftp"
  // 写侧:`--sftp-write <path>@<size>` / `--sftp-mkdir <p>` / `--sftp-rmdir <p>`
  // / `--sftp-remove <p>` / `--sftp-rename <from>@<to>`。
  //
  // 这些**在扫描 argv 的当下就进 `ops`**,而不是先分门别类收进几个数组、事后
  // 再拼回去。早先那版是分组入队的,于是 `--sftp-mkdir d --sftp-write d/f`
  // 实际发成「先写再建目录」,写必然失败,而命令行的读法完全相反。更糟的是
  // 当时函数上的注释写着「按命令行顺序」——注释和行为分叉,比任一个单独存在
  // 都更容易让人相信那个错的顺序。顺序在这里是有语义的:`mkdir` 必须排在
  // 往里面写的 `write` 前面。
  let ops : Array[@sftp.SftpOp] = []
  let mut saw_any = false
  let mut i = 1
  while i < argv.length() {
    if argv[i] == "--sftp" && i + 1 < argv.length() {
      dir = Some(argv[i + 1])
      i = i + 2
      continue
    }
    if argv[i] == "--sftp-read" && i + 1 < argv.length() {
      ops.push(@sftp.SftpOp::ReadFile(argv[i + 1]))
      saw_any = true
      i = i + 2
      continue
    }
    if argv[i] == "--sftp-write" && i + 1 < argv.length() {
      let (p, n) = split_at_last(argv[i + 1])
      ops.push(@sftp.SftpOp::WriteFile(p, payload_of(n)))
      saw_any = true
      i = i + 2
      continue
    }
    if argv[i] == "--sftp-mkdir" && i + 1 < argv.length() {
      ops.push(@sftp.SftpOp::MakeDir(argv[i + 1], @sftp.SftpAttrs::none()))
      saw_any = true
      i = i + 2
      continue
    }
    if argv[i] == "--sftp-rmdir" && i + 1 < argv.length() {
      ops.push(@sftp.SftpOp::RemoveDir(argv[i + 1]))
      saw_any = true
      i = i + 2
      continue
    }
    if argv[i] == "--sftp-remove" && i + 1 < argv.length() {
      ops.push(@sftp.SftpOp::RemovePath(argv[i + 1]))
      saw_any = true
      i = i + 2
      continue
    }
    if argv[i] == "--sftp-rename" && i + 1 < argv.length() {
      let at = last_at(argv[i + 1])
      if at >= 0 {
        ops.push(
          @sftp.SftpOp::Rename(
            argv[i + 1].unsafe_substring(start=0, end=at),
            argv[i + 1].unsafe_substring(
              start=at + 1,
              end=argv[i + 1].length(),
            ),
          ),
        )
        saw_any = true
      }
      i = i + 2
      continue
    }
    if argv[i] == "--sftp-missing" {
      missing = true
      i = i + 1
      continue
    }
    if argv[i] == "--subsystem" && i + 1 < argv.length() {
      subsystem = argv[i + 1]
      i = i + 2
      continue
    }
    i = i + 1
  }
  if dir is None && !missing && !saw_any {
    return false
  }
  let user = find_user(@env.args())
  println("=== Loop #40 SFTP write side vs real sshd ===")
  println("port: " + port.to_string())
  println("user: " + user)
  println("subsystem: " + subsystem)
  // REALPATH 打头,其余按命令行顺序接在后面。
  let script : Array[@sftp.SftpOp] = [@sftp.SftpOp::Realpath(".")]
  match dir {
    Some(d) => script.push(@sftp.SftpOp::ListDir(d))
    None => ()
  }
  for j = 0; j < ops.length(); j = j + 1 {
    script.push(ops[j])
  }
  if missing {
    script.push(@sftp.SftpOp::Stat(no_such_path()))
  }
  let ops = script
  match @tcp.TcpConn::connect("127.0.0.1", port) {
    None => {
      println("result: CONNECT_FAILED")
      return true
    }
    Some(conn) => {
      let outcome = @sshclient.live_sftp_named(
        conn,
        fixed_x(),
        user,
        test_auth_key(),
        subsystem,
        ops,
        kh_policy(@env.args(), port),
      )
      conn.close()
      print_sftp_outcome(outcome)
      return true
    }
  }
}

///| 一个必定不存在的路径,拿来跑「不是传输错误,而是一次成功的 SFTP 交换」。
fn no_such_path() -> String {
  ".loop39/definitely-not-here-" + "0f3a91c7"
}

fn print_sftp_outcome(outcome : @sshclient.SftpOutcome) -> Unit {
  match outcome {
    @sshclient.SftpOutcome::Done(r) => {
      println("result: SFTP_DONE")
      println("version: " + r.version.to_string())
      println("extensions: " + r.extensions.to_string())
      println("requests_sent: " + r.requests_sent.to_string())
      println("replies_recv: " + r.replies_recv.to_string())
      println("sftp_bytes_in: " + r.sftp_bytes_in.to_string())
      println("total_sent_bytes: " + r.total_sent_bytes.to_string())
      println("total_recv_bytes: " + r.total_recv_bytes.to_string())
      for i = 0; i < r.ops.length(); i = i + 1 {
        print_sftp_op(i, r.ops[i])
      }
    }
    @sshclient.SftpOutcome::Failed(e) => {
      println("result: SFTP_FAILED")
      println("error: " + sftp_error_name(e))
    }
  }
}

fn print_sftp_op(i : Int, op : @sftp.SftpOpResult) -> Unit {
  let tag = "op" + i.to_string()
  match op {
    @sftp.SftpOpResult::RealpathOk(p) => {
      println(tag + ": REALPATH")
      println(tag + "_path: " + @sftp.sftp_ascii(p).length().to_string())
      println(tag + "_hex: " + dump_prefix(@sftp.sftp_ascii(p)))
    }
    @sftp.SftpOpResult::Attrs(a) => {
      println(tag + ": ATTRS")
      println(tag + "_size: " + opt_u64_text(a.size))
      println(tag + "_uid: " + opt_int_text(a.uid))
      println(tag + "_gid: " + opt_int_text(a.gid))
      println(tag + "_perm: " + opt_int_text(a.permissions))
    }
    @sftp.SftpOpResult::Listing(entries) => {
      println(tag + ": LISTING")
      println(tag + "_count: " + entries.length().to_string())
      for j = 0; j < entries.length(); j = j + 1 {
        println(
          tag + "_entry" + j.to_string() + ": " +
          dump_prefix(@sftp.sftp_ascii(entries[j].0)) + " " +
          entries[j].1.to_string() + " " +
          (if entries[j].2 { "dir" } else { "file" }),
        )
      }
    }
    @sftp.SftpOpResult::Contents(b) => {
      println(tag + ": CONTENTS")
      println(tag + "_len: " + b.length().to_string())
      println(tag + "_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(b)))
      println(tag + "_hex: " + dump_prefix(b))
    }
    @sftp.SftpOpResult::Wrote(n) => {
      println(tag + ": WROTE")
      println(tag + "_bytes: " + n.to_string())
    }
    @sftp.SftpOpResult::Changed => {
      println(tag + ": CHANGED")
    }
    @sftp.SftpOpResult::Failed(code, msg) => {
      println(tag + ": FAILED")
      println(tag + "_code: " + code.to_string())
      println(tag + "_msg_hex: " + dump_prefix(@sftp.sftp_ascii(msg)))
    }
  }
}

fn opt_int_text(v : Int?) -> String {
  match v {
    None => "-"
    Some(x) => x.to_string()
  }
}

fn opt_u64_text(v : UInt64?) -> String {
  match v {
    None => "-"
    Some(x) => @sftp.sftp_u64_to_int(x).to_string()
  }
}

fn sftp_error_name(e : @sshclient.SftpError) -> String {
  match e {
    AuthFailed(a) => "AUTH_FAILED " + auth_error_name(a)
    ChannelFailed(c) => "CHANNEL_FAILED " + exec_error_name(c)
    Protocol(m) => "PROTOCOL " + m
    TooManyPackets => "TooManyPackets"
    Closed => "Closed"
  }
}

fn main {
  let argv = @env.args()
  // Loop #38: dump the proposal and exit, without opening a socket.
  //
  // The reason this exists: "the connection succeeded" does not show *which*
  // algorithms were offered. For thirty-seven loops the test server pinned
  // HostKeyAlgorithms to ECDSA, so an ECDSA-only proposal and a complete one
  // were indistinguishable from the outside. Asserting on the proposal string
  // is the only way a regression that silently narrows it can be caught.
  if proposal_flag(argv) {
    run_proposal()
    return
  }
  let port = find_port(argv)
  if sftp_mode(argv, port) {
    return
  }
  let (shell_cmd, def_cols, def_rows, _) = shell_mode(argv)
  if shell_cmd != "" {
    let cols = int_flag(argv, "--cols", def_cols)
    let rows = int_flag(argv, "--rows", def_rows)
    run_shell(port, shell_cmd, cols, rows, resize_flag(argv))
    return
  }
  match exec_command(argv) {
    Some(cmd) => {
      run_exec(port, cmd, stdin_bytes(argv), env_flags(argv))
      return
    }
    None => ()
  }
  if auth_mode(argv) {
    let user = find_user(argv)
    println("=== Loop #34 publickey auth vs real sshd ===")
    println("port: " + port.to_string())
    println("user: " + user)
    match @tcp.TcpConn::connect("127.0.0.1", port) {
      None => {
        println("result: CONNECT_FAILED")
        return
      }
      Some(conn) => {
        let outcome = @sshclient.live_auth(
          conn,
          fixed_x(),
          user,
          test_auth_key(),
          kh_policy(@env.args(), port),
        )
        conn.close()
        match outcome {
          @sshclient.Authenticated(r) => {
            println("result: USERAUTH_SUCCESS")
            println("user: " + r.user)
            println("method: " + r.method)
            println("key_type: " + r.key_type)
            // Loop #38: which host key algorithm was negotiated, which key type
            // it turned out to be, and how big that key is.  Printed here as
            // well as on the session path because `--auth` returns before the
            // session runs, and this is the shortest path from a handshake to
            // an answer -- so it is the one a per-algorithm sweep uses.
            //
            // RFC 8332 下前两个字段**本来就不同**(协商 rsa-sha2-512,blob 写
            // ssh-rsa),两个都印出来才看得出走的哪条路;只印一个会把「协商名」
            // 和「密钥类型」混为一谈,而那正是 Loop #38 要修的那个混淆。
            println("hostkey_alg: " + r.session.handshake.hostkey_alg)
            println("hostkey_type: " + r.session.handshake.hostkey_type)
            println("hostkey_bits: " + r.session.handshake.hostkey_bits.to_string())
            println("signed_blob: " + r.signed_blob_hex)
            println("sig_blob: " + r.sig_blob_hex)
            // 请求载荷也一并带出来:验证脚本要能**独立地**从它重建出
            // signed_blob 并逐字节比对——那正是服务端做的事。用自己签的
            // 那串字节证明"我签的和请求里的一样"是没有意义的。
            println("request: " + r.request_hex)
            println(
              "session_id_head: " + r.session.session_id_head,
            )
            println(
              "handshake_sent_bytes: " +
              r.session.handshake.sent_bytes.to_string(),
            )
            println(
              "handshake_recv_bytes: " +
              r.session.handshake.recv_bytes.to_string(),
            )
            println(
              "total_sent_bytes: " + r.session.sent_bytes.to_string(),
            )
            println(
              "total_recv_bytes: " + r.session.recv_bytes.to_string(),
            )
          }
          @sshclient.Failed(e) => {
            println("result: FAILED")
            print_auth_rejection(e)
            println("error: " + auth_error_name(e))
          }
        }
      }
    }
    return
  }

  if wants_session(argv) {
    println("=== Loop #33 encrypted session vs real sshd ===")
    println("port: " + port.to_string())
    match @tcp.TcpConn::connect("127.0.0.1", port) {
      None => {
        println("result: CONNECT_FAILED")
        return
      }
      Some(conn) => {
        let outcome =
          @sshclient.live_session(conn, fixed_x(), kh_policy(@env.args(), port))
        conn.close()
        match outcome {
          @sshclient.ServiceAccepted(r) => {
            println("result: SERVICE_ACCEPTED")
            println("service: " + r.service_name)
            println("accepted: " + r.accepted_service)
            println("we_need: " + r.we_need.to_string())
            println("cipher_ctos: " + r.handshake.cipher_ctos)
            println("mac_ctos: " + r.handshake.mac_ctos)
            // Loop #38: 协商出的主机密钥算法名,和密钥 blob 里的类型名。
            // RFC 8332 下这两个**本来就不同**(协商 rsa-sha2-512,blob 写 ssh-rsa),
            // 所以两个都印出来——只印一个就看不出到底走的是哪条路。
            println("hostkey_alg: " + r.handshake.hostkey_alg)
            println("hostkey_type: " + r.handshake.hostkey_type)
            println("hostkey_bits: " + r.handshake.hostkey_bits.to_string())
            println("key_tag: " + r.key_tag)
            println("session_id_head: " + r.session_id_head)
            println(
              "handshake_sent_bytes: " + r.handshake.sent_bytes.to_string(),
            )
            println(
              "handshake_recv_bytes: " + r.handshake.recv_bytes.to_string(),
            )
            println("total_sent_bytes: " + r.sent_bytes.to_string())
            println("total_recv_bytes: " + r.recv_bytes.to_string())
          }
          @sshclient.Failed(e) => {
            println("result: FAILED")
            println("error: " + session_error_name(e))
          }
        }
      }
    }
    return
  }
  println("=== Loop #31 live SSH handshake vs real sshd ===")
  println("port: " + port.to_string())
  match @tcp.TcpConn::connect("127.0.0.1", port) {
    None => {
      println("result: CONNECT_FAILED")
      return
    }
    Some(conn) => {
      let outcome =
        @sshclient.live_handshake(conn, fixed_x(), kh_policy(@env.args(), port))
      conn.close()
      match outcome {
        @sshclient.Established(r) => {
          println("result: ESTABLISHED")
          println("server_ident: " + r.server_ident)
          println("client_ident: " + r.client_ident)
          println("kex_alg: " + r.kex_alg)
          println("hostkey_alg: " + r.hostkey_alg)
          println("hostkey_type: " + r.hostkey_type)
          println("hostkey_bits: " + r.hostkey_bits.to_string())
          println("cipher_ctos: " + r.cipher_ctos)
          println("cipher_stoc: " + r.cipher_stoc)
          println("mac_ctos: " + r.mac_ctos)
          println("mac_stoc: " + r.mac_stoc)
          println("hostkey_blob_hex: " + @ecdsa.bytes_to_hex(r.hostkey_blob))
          println("exchange_hash: " + @ecdsa.bytes_to_hex(r.exchange_hash))
          println("shared_secret_head: " + r.shared_secret_head)
          println("sent_bytes: " + r.sent_bytes.to_string())
          println("recv_bytes: " + r.recv_bytes.to_string())
        }
        @sshclient.Failed(e) => {
          println("result: FAILED")
          println("error: " + live_error_name(e))
          // On a signature failure the exchange hash is the whole question, so
          // print it: an independent implementation can recompute H from the
          // same transcript and the two either agree or name the divergence.
          match e {
            @sshclient.SignatureInvalid(h) =>
              println("exchange_hash: " + @ecdsa.bytes_to_hex(h))
            _ => ()
          }
        }
      }
    }
  }
}
