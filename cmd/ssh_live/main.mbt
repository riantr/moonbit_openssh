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
    // Loop #51: 不叫 HostkeyMismatch,也不叫 HostkeyUnknown。前者会让人去查中间人
    // (没有),后者会让人去找一条直接条目(这个客户端给不了)。见 policy.mbt。
    HostkeyCertAuthority(h, r) => "HostkeyCertAuthority"
    // Loop #53: 「压根没配信任锚」——加一行就解决，而把它报成上面任何一种都
    // 会让人查错方向。
    HostkeyCertUntrusted(h) => "HostkeyCertUntrusted"
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
///|
/// 固定类失败的一句话说明。**打印在 `error:` 之后**,因为 `error:` 是机器读的那
/// 一行,人话跟在后面。
///
/// Loop #51 的全部论点就是「名字决定用户下一步做什么」,而一个没人认识的错误名
/// 不改变任何行为——它只会让人继续走熟悉的老路:看到 HOST_CHANGED 就把钥匙加上。
/// 对 `HostkeyCertAuthority` 来说那条老路恰好是最坏的一条,所以这里必须说清楚。
fn print_pin_hint(e : @sshclient.AuthError) -> Unit {
  // 固定类失败住在 `LiveError` 里,握手期的那个经 `Transport`/`HandshakeFailed`
  // 到达这里——这也正是 `error:` 那一行会打成 `transport:handshake:...` 的原因。
  let inner = match e {
    @sshclient.Transport(@sshclient.HandshakeFailed(h)) => h
    _ => return
  }
  match inner {
    @sshclient.HostkeyCertAuthority(host, reason) =>
      // Loop #53: 载荷是 (主机名, 理由)。这几种的处置完全不同，所以提示必须按
      // 理由给，不能给一句通用的话——而门禁断言的正是提示里提到了该提的那件事。
      if reason == "no-certificate-expected" {
        println(
          "hint: " + host + " is pinned via a @cert-authority entry, but the " +
          "server sent a plain key instead of a certificate. Pin the host key " +
          "directly (ssh-keyscan -t ecdsa " + host + ") if that is what you want.",
        )
      } else if reason == "expired" || reason == "not-yet-valid" {
        println(
          "hint: the host certificate presented is outside its validity window " +
          "(reason: " + reason + "). Check the clock on both ends, then re-issue " +
          "the certificate on the server (ssh-keygen -s <ca> -h -I <id> " +
          "-n " + host + ").",
        )
      } else if reason == "principal-mismatch" {
        println(
          "hint: the host certificate does not list " + host +
          " among its principals. Issue one whose principal is the name you " +
          "connect to, or connect by a name the certificate already covers.",
        )
      } else if reason == "ca-revoked" {
        println(
          "hint: the certificate was signed by a CA that appears in an @revoked " +
          "entry. That is deliberate on this machine; remove the @revoked line if " +
          "it is stale.",
        )
      } else if reason == "not-a-host-certificate" {
        println(
          "hint: the server sent a USER certificate. User certificates prove which " +
          "user someone is, not which host they are talking to, and this client " +
          "will never accept one as a host identity.",
        )
      } else {
        println(
          "hint: the host certificate did not validate (reason: " + reason +
          "). --kh-tofu does NOT apply to certificates: a certificate without a " +
          "pinned CA looks exactly like what a man in the middle would send.",
        )
      }
    @sshclient.HostkeyCertUntrusted(h) =>
      println(
        "hint: the server sent a host certificate signed by a CA that has no " +
        "@cert-authority entry here for " + h + ". Add the CA's public key as " +
        "@cert-authority " + h + " ssh-ed25519 <base64>, or connect to a host whose " +
        "CA you already pin. --kh-tofu does not apply to certificates.",
      )
    @sshclient.HostkeyMismatch(h) =>
      println(
        "hint: the key " + h + " presented does not match the pinned one. Treat this " +
        "as a man in the middle until you have checked otherwise; --kh-tofu is the " +
        "way to accept the new key and stop asking.",
      )
    @sshclient.HostkeyUnknown(h) =>
      println(
        "hint: " + h + " has no key pinned at all. Add one, or pass --kh-tofu to " +
        "accept and write back the key you are being shown now.",
      )
    _ => ()
  }
}

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
    // Loop #58: 跳过取值的那个 token。`--target 2222` 里的 2222 是主机名位置上的
    // 字符串,不是端口;`-o Port=2222` 同理。之前没有这些参数时不存在这个歧义,
    // 现在有了,扫描就必须知道哪个参数会吃掉下一个 token。
    if argv[i] == "--target" || argv[i] == "-o" || argv[i] == "-F" {
      i = i + 2
      continue
    }
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
/// `--kh-host <name>` 指明比哪个主机名,`--kh-port` 指明端口(缺省 0 = 从
/// kh_host 的 `[host]:port` 形式里读),`--kh-tofu` 显式表示「接受并写回新钥匙」
/// (=`StrictHostKeyChecking=accept-new`)。
///
/// **Loop #50:默认是拒绝。** 不给 `--kh-tofu`,就没有任何办法让一个没被固定过的
/// 主机通过,而那正是 Loop #48 留下的缺口。
///
/// `--kh-strict` 已删:它是 Loop #48 的显式 strict 开关,默认反过来之后它就成了
/// 一个方向相反的开关。少一个配置项就少一个能配错的地方。
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

///|
/// Loop #54:主机固定配置**解析一次**的结果
///
/// `kh_policy` 之前在 6 个调用点各被调一次,每个调用点自己 `argv_value` 一遍。
/// 这个形状有两个问题,都不是这一轮引入的:
///
/// 1. 读侧和写侧**各自**重新解析一遍参数。两边问同一个问题的答案一旦不同,
///    写回写进文件的和下一次读出来比对的就不是同一条,失败点在几天之后。
/// 2. 加一个 `--kh-file` 就要读一次文件,而读文件是 async 的。6 个调用点
///    各自 async 化会把整个 `main` 的 dispatch 一起拖成 async。
///
/// 改成在 `main` 里解析一次、把结果传下去,两个问题一起消失:文件只读一次,
/// 而 `run_*` 全部保持同步(它们只是多收一个参数)。
pub(all) struct KhConfig {
  /// 判定用的策略。读侧唯一的输入。
  policy : @knownhosts.KnownHostsPolicy
  /// 要写回的 host field。判定和写回问同一个问题,答案在这里只有一个。
  host : String
  /// `--kh-file` 给的路径;空串 = 不落盘,退回打印。
  file : String
  /// 启动时读到的文本,用于写回前的重复判定。
  text : String
  /// 是否给了 `--kh-tofu`
  tofu : Bool
}

///|
/// Loop #49 的写回。只有在**真的接受之后**才做,而且只在「这个主机本来没被固定过」
/// 时做——已经固定过的那把要么匹配(无事可做)要么已经被拒(拒绝之后不能把对端那把
/// 记下来,那等于把一次劫持变成一次「已信任」)。
///
/// 打印而不是落盘,理由见调用点。门禁读 `tofu: ` 那一行。
///
/// **这是诚实的 TOFU,不是安全的 TOFU。** 第一次连接仍然 susceptible:中间人在
/// 那一刻可以出示它自己的钥匙,而我们会记下来并此后信任。OpenSSH 的
/// `StrictHostKeyChecking=accept-new` 有一模一样的性质,差别只在于它把这件事
/// 明说了。所以这里也明说——门禁读 `tofu: accepted-unpinned` 这一行来判断这次
/// 连接到底有没有凭据出去。
///
/// Loop #54:给了 `--kh-file` 就**真的落盘**,不再只打印。写不进去必须是一个
/// 看得见的失败:打印 `accepted-unpinned` 然后悄悄丢掉 pin,正是 Loop #52 在
/// 浏览器侧刚消灭掉的 silent-accept 缺陷,换个平台不构成理由。
async fn kh_report_tofu(kh : KhConfig, r : @sshclient.AuthReport) -> Unit {
  if !kh.tofu {
    return
  }
  // 行格式由 src/knownhosts 决定,和浏览器那一侧同一串字节。写的是**刚刚比过
  // 的那把 blob**,不是对端自述的任何东西——后者会变成一次「信任对端的自我
  // 陈述」,恰好把这一层要防的东西放了进来。
  let line = @knownhosts.KnownHostEntry::to_line(
    kh.host,
    r.session.handshake.hostkey_type,
    r.session.handshake.hostkey_blob,
  )
  println("tofu: accepted-unpinned")
  if kh.file == "" {
    // 没有落盘目标:退回 Loop #49 的打印。整段内容都打出来,包括结尾换行,
    // 门禁读这一行并落盘,再用写回来的那份重连。
    let written = @knownhosts.append_line(
      kh.text,
      kh.host,
      r.session.handshake.hostkey_type,
      r.session.handshake.hostkey_blob,
    )
    println("tofu: " + written)
    return
  }
  // 重复判定:写回是在「给了 --kh-tofu」时做的,不是只在「新钥匙被接受」时做的。
  // 所以对一台已经钉住的主机再跑一次 TOFU 也会走到这里,没有这道判断文件就会
  // 每次连接长出一行一模一样的条目。
  if @knownhosts.has_line(kh.text, line) {
    println("tofu: already in " + kh.file)
    return
  }
  match @khfile.append_terminated(kh.file, line) {
    @khfile.AppendResult::Appended => println("tofu: written to " + kh.file)
    @khfile.AppendResult::Failed(why) => {
      // **凭据已经出去了**,这次连接是成功的;失败的是「记住」。这两件事必须
      // 分开说:报成连接失败会让用户以为拒绝了什么,报成成功会让用户以为记住了。
      println(
        "tofu: NOT written to " + kh.file + " (" + why + ") -- this connection " +
        "was accepted, but the pin was not remembered and the next one to " +
        kh.host + " will need --kh-tofu again",
      )
    }
  }
}

///| Loop #50:主机密钥固定的**默认**,以及为什么它住在这一层。
///
/// Loop #48 把固定接了进来,但默认是「不给 known_hosts 就跳过」——一个不安全的
/// 默认,而每一次忘记配置都静默地落到它上面。这一轮把默认反过来:**不给任何
/// known_hosts,拒绝连接**。接受新钥匙变成一个必须明写的开关,也就是
/// `StrictHostKeyChecking=accept-new` 的等价物。
///
/// 这个形状本身是论点的一半:在安全的默认里,「不安全」需要**敲一个字**;而在
/// 旧形状里,「安全」需要一个文件**并且**需要一个开关。少一个配置项就掉回不安全
/// ——这正是要把默认值放在安全那一侧的原因,也是为什么 kh-strict 被删掉了:它是
/// Loop #48 的显式 strict 开关,默认反过来之后它就成了一个方向相反的开关,而两个
/// 名字相反的开关里总有一个没人会去读。
///
/// 与 OpenSSH 的差别只有一处,而且是刻意的:accept-new 在这里既表示「接受新
/// 钥匙」也表示「写回」,而 OpenSSH 要另外给 UserKnownHostsFile 一个可写的路径。
/// 这个 moon 版本没有文件 IO(见 Loop #48),所以驱动只能把写回打印出来,由调用方
/// 落盘。浏览器那一侧的答案是 localStorage,不是文件。
///| 要在 known_hosts 里查的主机名。`--kh-host` 没给就退回实际拨号的那个。
///
///|
///
/// 判定(`kh_policy`)和写回(`kh_report_tofu`)必须问同一个问题:如果写回写的是
/// 「另一个」主机名,下一次连接查的就不是刚写进去的那一条,而拒绝信息也会指向
/// 一个我们从没提过的名字。两个调用点各自 `argv_value` 的形状,就是这类漂移的
/// 起点。
fn kh_host_name(argv : Array[String]) -> String {
  let given = argv_value(argv, "--kh-host")
  // Loop #59: `--target` 给了就用它,而不是硬编码的 127.0.0.1。
  //
  // 记的是**用户输入的那个名字**,不是 `HostName` 解析出来的那个。OpenSSH 的
  // `add_host_to_hostfile(filename, host, key, store_hash)` 只收一个 host,
  // `write_host_entry(f, host, NULL, ...)` 的 ip 恒为 NULL
  // (hostfile.c:542 / :476)——`HostName` 根本不参与 pin 的键。记成解析后的名字,
  // 下一次用同一个别名连就查不到,于是每次都像第一次。
  if given == "" {
    let target = argv_value(argv, "--target")
    if target == "" { "127.0.0.1" } else { target }
  } else {
    given
  }
}

///|
/// Loop #53: 当前 Unix 秒，给证书有效期判定用。
///
///| `@env.now()` 返回的是**毫秒**——量出来的，不是照文档抄的（见
///| `cmd/wt_ssh/main.mbt` 的同名函数，两边的注释指向同一件事）。
///| 猜错单位的后果很安静：比较差 1000 倍，有效期判定放行该拒的、拒掉该放的，
///| 没有任何报错可以指过去。
fn kh_now_seconds() -> UInt64 {
  @env.now() / 1000UL
}

///|
/// Loop #54: 读一次 `--known-hosts-text` 或 `--kh-file`，建出判定与写回共用的配置。
///
///| **优先级与浏览器那一侧逐字相同**：显式给的 `--known-hosts-text` 优先，
/// **包括显式给空串**——「我就是要这次不固定」是一个正当的意图，和「我没配」
/// 不是一回事，而这个客户端的缺省（Loop #50）恰好是拒绝，所以这两者必须能分开。
/// 没有显式文本才去读 `--kh-file`。
///
///| **读不出来必须说话。** 一个读不到自己信任锚的用户，不该在第二次连接时才发现，
/// 而 discover 到的应该是「我读不到」而不是「这里没有条目」——后者在 strict 下
/// 表现为拒绝，方向对，但理由是错的。
async fn kh_resolve(argv : Array[String], port : Int) -> KhConfig {
  let host = kh_host_name(argv)
  let file = argv_value(argv, "--kh-file")
  let tofu = has_switch(argv, "--kh-tofu")
  // Loop #53: 证书的有效期判定必须有真实时钟。`KnownHostsPolicy::now` 的缺省值是
  // 0，刻意的 fail-closed——「忘了传时钟」必须表现为拒绝而不是「不检查就放行」。
  let now = kh_now_seconds()
  let kh_port = parse_port_arg(argv_value(argv, "--kh-port"), 0)
  // 默认 strict;accept-new 是那个需要明写的例外。
  let strict = !tofu
  let given = argv_value(argv, "--known-hosts-text")
  // 显式给了文本(哪怕是空串)就用它,不碰文件。
  if given != "" || file == "" {
    let p = kh_policy_from(
      given,
      host,
      kh_port,
      strict,
      now,
      "--known-hosts-text",
    )
    return { policy: p, host, file: if given != "" { "" } else { file }, text: given, tofu }
  }
  let loaded = @khfile.load(file)
  let text = match loaded {
    @khfile.LoadResult::Read(t) => t
    @khfile.LoadResult::Missing => ""
    @khfile.LoadResult::Unreadable(why) => {
      // 不中止:连接本身是好的,坏的是「记住」的能力。strict 下这仍会拒绝,
      // 而非 strict 下会放行——后者是危险的,所以下面把 strict 强制打开。
      //
      // 强制 strict 是这里唯一正确的答案。一个读不到自己信任锚的人**绝不该**
      // 因为读不到而被放行:那等于把「存储坏了」翻译成「信任一切」。
      println(
        "known_hosts: cannot read " + file + " (" + why + ") -- pinning is forced " +
        "on for this connection, because not being able to read your own trust " +
        "anchors must never mean trusting whatever is offered",
      )
      let p = @knownhosts.KnownHostsPolicy::from_text_at(
        "",
        host,
        kh_port,
        true,
        now,
      )
      return { policy: p, host, file, text: "", tofu }
    }
  }
  println("known_hosts: " + text.length().to_string() + " bytes from " + file)
  if text.length() == 0 {
    // 文件在但是空的:这和「文件不存在」在**信任**上是同一件事(没被固定过),
    // 但原因不同,所以说出来。一个空文件不报错,也不该报错——它是合法的
    // known_hosts,只是里面还没有条目。
    println("known_hosts: " + file + " is empty -- nothing is pinned here")
    let p = @knownhosts.KnownHostsPolicy::from_text_at(
      "",
      host,
      kh_port,
      strict,
      now,
    )
    return { policy: p, host, file, text, tofu }
  }
  let p = kh_policy_from(text, host, kh_port, strict, now, file)
  { policy: p, host, file, text, tofu }
}

///|
/// 建策略 + 那道「解析出 0 条就报错」的闸
///
///| `source` 只是给错误信息用的:用户要看到是哪个来源坏了,而不是「known_hosts
/// 坏了」。两个调用点各写一遍这条闸,迟早有一处漏掉 `abort`。
fn kh_policy_from(
  text : String,
  host : String,
  kh_port : Int,
  strict : Bool,
  now : UInt64,
  source : String,
) -> @knownhosts.KnownHostsPolicy {
  if text.length() == 0 {
    // 什么都没给。strict 下的答案是拒绝,而且这个拒绝是由**固定规则本身**产生的:
    // 这个主机「没被固定过」。走一条真的 strict 路径而不是 `skip()`,这样拒绝
    // 走的是和「钉住的钥匙对不上」同一条代码,不会有一条例外路径悄悄绕过它。
    return @knownhosts.KnownHostsPolicy::from_text_at("", host, 0, strict, now)
  }
  let p = @knownhosts.KnownHostsPolicy::from_text_at(text, host, kh_port, strict, now)
  // 「给了文本但一条都没解析出来」必须报错,不能安静地变成 skip。
  // `verify` 看到空条目就返回 Skip,而调用方「要求固定」和「忘了固定」在那一层
  // 完全一样——一个看起来跑过的检查比没跑过的检查更危险。
  //
  // 「给了文本但一条都没解析出来」在这里分掉,因为它有**两种**读法而处置不同:
  // 「你的 known_hosts 坏了」(该报错)和「这个主机没被固定过」(该走 Unknown)。
  // 放它过去的话,一个语法错误或空文件会被报告成后者——一个看起来像配置还没做的
  // 理由,而真正的原因永远不会被看见。
  if p.entries.length() == 0 {
    println(
      "known_hosts: " + source + " 解析出 0 条 -- 拒绝继续,而不是把它读成" +
      "「这个主机没被固定过」",
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
  host : String,
  port : Int,
  command : String,
  stdin_data : FixedArray[Byte],
  envs : Array[@sshclient.EnvVar],
  user : String,
  kh : KhConfig,
) -> Unit {
  println("=== Loop #35 exec vs real sshd ===")
  println("port: " + port.to_string())
  println("user: " + user)
  println("command: " + command)
  println("stdin_bytes: " + stdin_data.length().to_string())
  for i = 0; i < envs.length(); i = i + 1 {
    println("env: " + envs[i].name + "=" + envs[i].value)
  }
  match @tcp.TcpConn::connect(host, port) {
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
        kh.policy,
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
          print_pin_hint(e)
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
  host : String,
  port : Int,
  command : String,
  cols : Int,
  rows : Int,
  resize : (Int, Int)?,
  user : String,
  kh : KhConfig,
) -> Unit {
  let user = user
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
  match @tcp.TcpConn::connect(host, port) {
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
        kh.policy,
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
          print_pin_hint(e)
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

fn sftp_mode(
  argv : Array[String],
  host : String,
  port : Int,
  user : String,
  kh : KhConfig,
) -> Bool {
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
  match @tcp.TcpConn::connect(host, port) {
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
        kh.policy,
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

///|
/// Loop #54: `main` 现在是 async，因为读 `--kh-file` 是 async 的。
///
/// 只有 `main` 和 `kh_resolve` 是 async；`run_*` 全部保持**同步**，只是多收一个
/// `KhConfig`。另一种做法是让每个 `run_*` 自己去解析，于是读文件的代价变成 6 次、
/// 参数解析也变成 6 次，而且读侧和写侧各拿一份——那正是这个结构最初要消灭的漂移。
///|
/// Loop #58: connection parameters resolved from an ssh_config file.
///
/// src/sshconfig existed since Loop #24 with nothing outside its own test command
/// calling it, and by Loop #57 its resolver was proven against OpenSSH's `ssh -G`
/// while still having no user. That is the state Loop #57's own findings describe:
/// correct code nobody reaches rots the way wrong code does.
///
/// **Precedence, and it is the whole point.** OpenSSH takes the first value
/// obtained for each keyword, and the command line is read before any file. So:
/// `--user` / an explicit port argument > `-o Key=Value` > the config file > this
/// client's built-in defaults. Checked against OpenSSH: `ssh -G -F fallback.conf
/// -o User=cliu -o Port=2200 web1` answers `user cliu`, `port 2200` -- the command
/// line wins over a file that sets both.
///
/// If the file were consulted only when the caller said nothing, then a user with
/// a config file could never override one from the command line, which is the
/// everyday case. That is why `-o` is here and not left for later.
///
/// **Nothing changes without `--config`.** Every field is empty unless a file was
/// given, and `main` substitutes only non-empty ones. Every existing gate dials
/// 127.0.0.1:22222 and passes `--user` explicitly; none of them pass `--config`,
/// so none of them can move.
pub struct ConnConfig {
  /// 配置文件路径;空串 = 没给 `-F`/`--config`
  config_path : String
  /// 要匹配的 Host 模式的目标名
  target : String
  /// `HostName`
  hostname : String
  /// `User`
  user : String
  /// `Port`
  port : String
  /// `IdentityFile`(多值,按文件顺序)
  identity_files : Array[String]
}

///|
fn config_path_arg(argv : Array[String]) -> String {
  let long = argv_value(argv, "--config")
  if long != "" {
    return long
  }
  let mut i = 1
  while i + 1 < argv.length() {
    if argv[i] == "-F" {
      return argv[i + 1]
    }
    i = i + 1
  }
  ""
}

///|
fn config_effective_flag(argv : Array[String]) -> Bool {
  has_switch(argv, "--config-effective")
}

///|
fn target_arg(argv : Array[String]) -> String {
  let given = argv_value(argv, "--target")
  if given != "" {
    return given
  }
  kh_host_name(argv)
}

///| 收下所有 `-o Key=Value`,大小写不敏感地存成 key→value。
fn o_overrides(argv : Array[String]) -> Array[(String, String)] {
  let out : Array[(String, String)] = []
  let mut i = 1
  while i + 1 < argv.length() {
    if argv[i] == "-o" {
      let spec = argv[i + 1]
      let mut eq = -1
      let mut k = 0
      while k < spec.length() {
        if spec[k].to_int() == 61 {
          eq = k
          break
        }
        k = k + 1
      }
      if eq > 0 {
        let key = ci_lower(cc_slice(spec, 0, eq))
        let value = cc_trim(cc_slice(spec, eq + 1, spec.length()))
        let mut replaced = false
        let mut j = 0
        while j < out.length() {
          if out[j].0 == key {
            out[j] = (key, value)
            replaced = true
          }
          j = j + 1
        }
        if !replaced {
          out.push((key, value))
        }
      }
    }
    i = i + 1
  }
  out
}

///|
fn o_lookup(overrides : Array[(String, String)], key : String) -> String {
  let k = ci_lower(key)
  let mut i = 0
  while i < overrides.length() {
    if overrides[i].0 == k {
      return overrides[i].1
    }
    i = i + 1
  }
  ""
}

///|
fn ci_lower(s : String) -> String {
  let b = StringBuilder()
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    b.write_char(if c >= 65 && c <= 90 { (c + 32).unsafe_to_char() } else { s[i].unsafe_to_char() })
    i = i + 1
  }
  b.to_string()
}

///|
fn cc_slice(s : String, from : Int, to : Int) -> String {
  let b = StringBuilder()
  let mut i = from
  let hi = if to > s.length() { s.length() } else { to }
  while i < hi {
    b.write_char(s[i].unsafe_to_char())
    i = i + 1
  }
  b.to_string()
}

///|
fn cc_trim(s : String) -> String {
  let mut a = 0
  let mut b = s.length()
  while a < b && cc_space(s[a].to_int()) { a = a + 1 }
  while b > a && cc_space(s[b - 1].to_int()) { b = b - 1 }
  cc_slice(s, a, b)
}

///|
fn cc_space(c : Int) -> Bool { c == 32 || c == 9 || c == 13 }

///|
/// 读一次配置文件、解析一次、算出最终参数。判定侧和拨号侧共用这一份——
/// 和 `KhConfig` 同一个理由：两个调用点各自解析，答案就会漂。
async fn cfg_resolve(argv : Array[String]) -> ConnConfig {
  let path = config_path_arg(argv)
  let target = target_arg(argv)
  let overrides = o_overrides(argv)
  // 整条优先级链在这里一次算完:`--user` > `-o` > 配置文件。分散在拨号侧算的话,
  // `--config-effective` 就只能反映其中一段,而"命令行压过文件"这条规则正是本轮
  // 要证明的东西——证明它的那条路径必须能看到全部三段。
  let explicit_user = find_user(argv)
  let o_user = o_lookup(overrides, "user")
  let hostname = o_lookup(overrides, "hostname")
  let port = o_lookup(overrides, "port")
  let ids : Array[String] = []
  let user = if explicit_user != "<no-user-given>" {
    explicit_user
  } else {
    o_user
  }
  if path == "" {
    // 没有配置文件：只有命令行给的那些。
    let o_id = o_lookup(overrides, "identityfile")
    if o_id != "" {
      ids.push(o_id)
    }
    return { config_path: "", target, hostname, user, port, identity_files: ids }
  }
  let text = try { (@fs.read_file(path)).text() } catch { _ => abort("cannot read config " + path) }
  let sections = @sshconfig.parse_ssh_config(text)
  // `-o` 赢过文件，所以先问命令行，问不到再问文件。
  let hostname = if hostname != "" { hostname } else { @sshconfig.resolved_value(target, sections, "HostName") }
  let user = if user != "" { user } else { @sshconfig.resolved_value(target, sections, "User") }
  let port = if port != "" { port } else { @sshconfig.resolved_value(target, sections, "Port") }
  let file_ids = @sshconfig.resolved_values(target, sections, "IdentityFile")
  let o_id = o_lookup(overrides, "identityfile")
  if o_id != "" {
    // `IdentityFile` 在 OpenSSH 里是累积的多值关键字，`-o` 给的是最先得到的值，
    // 所以它排在文件给的前面而不是替换掉整个列表。
    ids.push(o_id)
    let mut i = 0
    while i < file_ids.length() {
      ids.push(file_ids[i])
      i = i + 1
    }
  } else {
    let mut i = 0
    while i < file_ids.length() {
      ids.push(file_ids[i])
      i = i + 1
    }
  }
  { config_path: path, target, hostname, user, port, identity_files: ids }
}

///|
/// `--config-effective`:打印最终生效的连接参数然后退出,不建 socket。
///
/// 和 Loop #38 的 `--proposal` 同一个理由——「连接成功了」看不出**用了哪份配置**,
/// 所以必须有一条纯离线的路径把答案本身印出来。放在任何拨号之前返回,
/// 所以它不受也不影响 `--kh-file` 的解析。
fn print_conn_effective(cfg : ConnConfig) -> Unit {
  println("=== ssh_config effective ===")
  println("config: " + (if cfg.config_path == "" { "(none)" } else { cfg.config_path }))
  println("target: " + cfg.target)
  if cfg.hostname != "" { println("hostname = " + cfg.hostname) }
  if cfg.user != "" { println("user = " + cfg.user) }
  if cfg.port != "" { println("port = " + cfg.port) }
  if cfg.identity_files.length() > 0 {
    let b = StringBuilder()
    let mut i = 0
    while i < cfg.identity_files.length() {
      if i > 0 { b.write_char('|') }
      b.write_string(cfg.identity_files[i])
      i = i + 1
    }
    println("identityfile = " + b.to_string())
  }
  println("=== end ===")
}

///|
async fn main {
  let argv = @env.args()
  // Loop #38: dump the proposal and exit, without opening a socket.
  //
  // The reason this exists: "the connection succeeded" does not show *which*
  // algorithms were offered. For thirty-seven loops the test server pinned
  // HostKeyAlgorithms to ECDSA, so an ECDSA-only proposal and a complete one
  // were indistinguishable from the outside. Asserting on the proposal string
  // is the only way a regression that silently narrows it can be caught.
  //
  // 这条路径在解析之前就返回,所以 `--kh-file` 的解析**不会**影响 `--proposal`
  // 的输出——那是一个纯离线的 dump,读不读文件都该给出同一串字节。
  if proposal_flag(argv) {
    run_proposal()
    return
  }
  // Loop #58: 纯离线的配置解析 dump,和 `--proposal` 一样在任何拨号之前返回。
  if config_effective_flag(argv) {
    print_conn_effective(cfg_resolve(argv))
    return
  }
  // Loop #58: 解析一次,之后拨号侧和打印侧共用这一份。没有 `--config` 时每个字段
  // 都是空的,`find_port` / `find_user` 的缺省原样保留——既有门禁一个都没传
  // `--config`,所以它们看到的字节不会变。
  let cfg = cfg_resolve(argv)
  // Loop #59: 拨号目标也来自配置。`HostName` 解析出来的是**连哪里**,而
  // known_hosts 记的仍然是**用户输入的那个名字**——OpenSSH 的
  // `add_host_to_hostfile(filename, host, key, ...)` 只收一个 host 参数,
  // `write_host_entry(f, host, NULL, ...)` 的 ip 恒为 NULL(hostfile.c:542/476),
  // 所以 `HostName` 根本不参与 pin 的键。记成解析后的名字会让下一次连接查不到。
  let host = if cfg.hostname != "" { cfg.hostname } else { "127.0.0.1" }
  // Loop #59: user 也在 main 里算一次,给所有会话路径。之前 `run_exec` /
  // `run_shell` 各自 `find_user(@env.args())` 重新解析一遍——Loop #54 明确
  // 消灭过这种「读侧写侧各问一次」的漂移,而 Loop #58 解析出来的 user 到不了
  // 那两条路径。空串仍然换成 `find_user` 那个刻意的标记而不是默认值。
  let user = if cfg.user != "" { cfg.user } else { find_user(argv) }
  let port = if cfg.port != "" {
    match parse_port(cfg.port, 0) {
      0 => find_port(argv)
      p => p
    }
  } else {
    find_port(argv)
  }
  // 解析一次,之后读侧和写侧共用这一份。见 `KhConfig` 的说明。
  let kh = kh_resolve(argv, port)
  if sftp_mode(argv, host, port, user, kh) {
    return
  }
  let (shell_cmd, def_cols, def_rows, _) = shell_mode(argv)
  if shell_cmd != "" {
    let cols = int_flag(argv, "--cols", def_cols)
    let rows = int_flag(argv, "--rows", def_rows)
    run_shell(host, port, shell_cmd, cols, rows, resize_flag(argv), user, kh)
    return
  }
  match exec_command(argv) {
    Some(cmd) => {
      run_exec(host, port, cmd, stdin_bytes(argv), env_flags(argv), user, kh)
      return
    }
    None => ()
  }
  if auth_mode(argv) {
    println("=== Loop #34 publickey auth vs real sshd ===")
    println("port: " + port.to_string())
    println("user: " + user)
    match @tcp.TcpConn::connect(host, port) {
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
          kh.policy,
        )
        conn.close()
        match outcome {
          @sshclient.Authenticated(r) => {
            println("result: USERAUTH_SUCCESS")
            // Loop #49: TOFU 的 S。接受之后就记住,否则「记住」没有发生,下一次
            // 连接仍然是一次全新的、无凭据的接受。
            //
            // 写的是**刚刚比过的那把 blob**(`r.session.handshake.hostkey_blob`),
            // 不是对端自述的任何东西——后者会变成一次「信任对端的自我陈述」,
            // 恰好把这一层要防的东西放了进来。
            //
            // 打印而不是写盘:这个 moon 版本的 core 没有文件 IO,而 `src/wt` 是
            // js-only、浏览器里根本没有文件系统(见 AGENTS.md Loop #48)。所以
            // 「长什么样」由 `src/knownhosts` 决定(两边同一串字节),「写到哪去」
            // 由驱动决定。门禁捕获这一行并落盘,然后用写回来的那份重连。
            kh_report_tofu(kh, r)
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
            print_pin_hint(e)
          }
        }
      }
    }
    return
  }

  if wants_session(argv) {
    println("=== Loop #33 encrypted session vs real sshd ===")
    println("port: " + port.to_string())
    match @tcp.TcpConn::connect(host, port) {
      None => {
        println("result: CONNECT_FAILED")
        return
      }
      Some(conn) => {
        let outcome =
          @sshclient.live_session(conn, fixed_x(), kh.policy)
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
  match @tcp.TcpConn::connect(host, port) {
    None => {
      println("result: CONNECT_FAILED")
      return
    }
    Some(conn) => {
      let outcome =
        @sshclient.live_handshake(conn, fixed_x(), kh.policy)
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
