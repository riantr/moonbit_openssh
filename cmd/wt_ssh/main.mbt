///| cmd/wt_ssh -- Loop #32 G3: SSH transport handshake inside a browser.

///|

///|   Runs the same protocol as cmd/ssh_live, but over a browser transport

///|   (WebTransport or WebSocket, chosen by the URL the Worker passes in) and

///|   inside a Web Worker. `result: ESTABLISHED` means a real OpenSSH server

///|   accepted the handshake, our client computed the same exchange hash it

///|   did, and it signed that hash with an ECDSA P-256 host key that our own

///|   verifier accepted -- all inside the browser.
///

///|   The DH private exponent is fixed for a reproducible transcript, exactly

///|   as in cmd/ssh_live. A production client draws it from the CSPRNG and

///|   never reuses it.

///|

///| Read one value out of the bootstrap-supplied config global. A browser has

///| no argv, so configuration arrives this way rather than through @env.args

///|
/// (which would drag a `__moonbit_fs_unstable` import into the Worker).
extern "js" fn cfg(name : String) -> String = "((n) => (globalThis.__wt_cfg && globalThis.__wt_cfg[n] != null) ? String(globalThis.__wt_cfg[n]) : '')"

///|

///| Hand the result back to the Worker. MoonBit's entry is an `async fn`, so

///|
/// the Worker cannot treat "importScripts returned" as completion.
extern "js" fn wt_finish(ok : Bool, detail : String) -> Unit = "((ok, detail) => { globalThis.__wt_finish({ ok: ok, detail: detail }) })"

///| One vector from `fault_vectors.mbt` -- the same generated table
///| `cmd/sftp_mitm` and `cmd/sftp_fault` carry. Three copies of one file is
///| why `host/verify_loop41.mjs` checks the tables agree.
fn wt_fault_case(name : String) -> FaultCase {
  for i = 0; i < fault_cases.length(); i = i + 1 {
    if fault_cases[i].name == name {
      return fault_cases[i]
    }
  }
  abort("unknown scenario: " + name)
}

///| hex -> bytes, for a writefile payload. Written out rather than reached for
///| because this package has no hex helper yet and the standard library's
///| `hex_to_bytes` silently drops a trailing odd digit -- a fault vector
///| mistyped by one character would then be a *different* vector rather than a
///| compile error.
fn wt_hex_to_bytes(s : String) -> FixedArray[Byte] {
  let n = s.length() / 2
  if s.length() % 2 != 0 {
    abort("odd-length hex")
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ((wt_hex_nibble(s[i * 2]) << 4) | wt_hex_nibble(s[i * 2 + 1])).to_byte()
  }
  out
}

fn wt_hex_nibble(c : UInt16) -> Int {
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
/// Loop #48: 主机密钥固定策略。配置键 `known_hosts` 给的是 known_hosts 的
/// **文本**(不是路径):浏览器里没有文件系统,而 `src/wt` 是 js-only,所以两条
/// 传输层驱动都只接受文本,判定也只有一个实现(`src/knownhosts`)。
/// `kh_host` / `kh_port` / `kh_tofu` 与 `cmd/ssh_live` 的同名开关一一对应。
///
/// **Loop #50:默认是拒绝。** 不给 `known_hosts` 也不给 `kh_tofu`,这个主机就是
/// 「没被固定过」,而答案是否定。`kh_tofu` 是那个需要明写的例外,等于
/// `StrictHostKeyChecking=accept-new`。`kh_strict` 已删:默认反过来之后它就成了
/// 一个方向相反的开关,而两个名字相反的开关里总有一个没人会去读。
fn cfg_kh_host() -> String {
  let given = cfg("kh_host")
  if given == "" { "127.0.0.1" } else { given }
}

async fn cfg_kh_policy() -> @knownhosts.KnownHostsPolicy {
  let given = cfg("known_hosts")
  let mut text = given
  let host = cfg_kh_host()
  let tofu = cfg("kh_tofu") == "1" || cfg("kh_tofu") == "true"
  // Loop #52: 没显式给文本就去读存储。**显式给的优先**,包括显式给空串——因为
  // 「我就是要这次不 pin」是一个正当的意图,和「我没配」不是一回事,而 Loop #50
  // 刚把后者的默认值定成拒绝。
  if given == "" {
    text = @khstore.load(host)
    if text != "" {
      println("known_hosts: " + text.length().to_string() + " bytes from storage")
    }
  }
  if text == "" {
    // 和 `cmd/ssh_live` 一样:走一条真的 strict 路径而不是 `skip()`,让这个
    // 拒绝由固定规则本身产生,而不是一条绕过它的旁路。
    return @knownhosts.KnownHostsPolicy::from_text("", host, 0, !tofu)
  }
  let p = @knownhosts.KnownHostsPolicy::from_text(
    text,
    host,
    // 0 = 「端口从 kh_host 的 `[host]:port` 形式里读」,和 `cmd/ssh_live`
    // 的 `--kh-port` 缺省值一致。两条驱动的默认值必须相同,否则同一份
    // known_hosts 在两边会落到不同的条目上——而那种差异只有在连接失败时
    // 才显形。
    cfg_int("kh_port", 0),
    !tofu,
  )
  // 「给了文本却一条都没解析出来」必须报错:它有「文件坏了」和「这个主机没被固定
  // 过」两种读法,而处置不同。放过去的话,一个空文件会被报告成后者,而真正的
  // 原因永远不会被看见。见 `cmd/ssh_live` 里同一处的注释。
  if p.entries.length() == 0 {
    println(
      "known_hosts: parsed 0 entries -- refusing instead of reading it as " +
      "'this host was never pinned'",
    )
    abort("known_hosts parsed to nothing")
  }
  p
}

///| Loop #52: 写回真正落到 localStorage,打印只是它的一份副本。
///
/// Loop #49/#50 的写回是**打印**的,门禁捕获那一行再手工喂回去。那对测试是够的,
/// 对产品是零:浏览器里没人读 stdout,所以周二敲了 `--kh-tofu` 的用户,周三会发现
/// pin 没了——而那正是 TOFU 要修、`accept-new` 不该留下的状态。
///
/// 顺序是**先存后打**,不是二选一:存了才说「记住了」,否则用户会以为记住了。
/// 存失败不改变这次连接的结果——连接本身是成功的,丢的只是以后那次不用再敲
/// 开关的能力——但必须**说出来**,否则用户会带着「我已经 pin 了」的错觉离开。
///
/// 存的**内容**仍然由 `src/knownhosts` 决定,和原生侧同一串字节;这里只决定写到哪。
///
/// **诚实的 TOFU,不是安全的 TOFU。** 第一次连接仍然 susceptible;OpenSSH 的
/// `StrictHostKeyChecking=accept-new` 性质一模一样,差别只在于它明说了。
async fn cfg_report_tofu(r : @wtlive.WtAuthReport) -> Unit {
  if cfg("kh_tofu") != "1" && cfg("kh_tofu") != "true" {
    return
  }
  let host = cfg_kh_host()
  let written = @knownhosts.append_line(
    cfg("known_hosts"),
    host,
    r.session.handshake.hostkey_type,
    r.session.handshake.hostkey_blob,
  )
  let stored = @khstore.save(host, written)
  if stored {
    println("tofu: accepted-unpinned")
    println("tofu: stored")
  } else {
    // Loop #52: 这一行是这个循环存在的理由。写不进去(隐私模式、配额满、被策略
    // 禁掉)不是连接失败,而是「下次还得再敲一次」——不告诉用户的话,他会带着
    // 「我已经 pin 了」的错觉离开,直到下一次连接又被拒。
    println("tofu: accepted-unpinned")
    println(
      "tofu: NOT stored -- storage refused the write, so the next connection to " +
      host + " will need kh_tofu again",
    )
  }
  // 仍然打印这一行:它既是给门禁捕获的,也让用户在 DevTools 之外看得到自己
  // pin 了什么。`src/knownhosts` 保证末尾有换行。
  println("tofu: " + written)
}

///|
fn fixed_x() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0x5A, 0x17, 0xC3, 0x9E, 0x44, 0xB2, 0x6D, 0xF1, 0x08, 0xA7, 0x35, 0xCC, 0x91,
    0x2E, 0x60, 0xD3, 0x74, 0x18, 0x9F, 0xE2, 0x50, 0xB7, 0xC6, 0x3D, 0x81, 0x0A,
    0xF5, 0x29, 0x64, 0xC8, 0x7B, 0x1E,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
fn error_name(e : @wtlive.WtLiveError) -> String {
  match e {
    ConnectFailed(_) => "ConnectFailed"
    NoServerIdent => "NoServerIdent"
    KexinitSendFailed => "KexinitSendFailed"
    NoPeerKexinit => "NoPeerKexinit"
    KexinitParseFailed => "KexinitParseFailed"
    NoAgreement(_) => "NoAgreement"
    EcdhInitSendFailed => "EcdhInitSendFailed"
    NoEcdhReply => "NoEcdhReply"
    EcdhReplyMalformed => "EcdhReplyMalformed"
    HostkeyInvalid => "HostkeyInvalid"
    SignatureInvalid(_) => "SignatureInvalid"
    // Loop #48: same two labels as `cmd/ssh_live`'s `live_error_name`, and the
    // same reason -- 「我们拒绝了」和「我们因为钥匙不是钉住的那把而拒绝」
    // 需要不同的处置，塌成一个标签就分不出来了。
    HostkeyMismatch(_) => "HostkeyMismatch"
    HostkeyUnknown(_) => "HostkeyUnknown"
    // Loop #51: 与原生路径同名同义,理由见 `cmd/ssh_live` 里同一处。
    HostkeyCertAuthority(_) => "HostkeyCertAuthority"
    NewkeysSendFailed => "NewkeysSendFailed"
    NoNewkeys => "NoNewkeys"
    BadPacket(w) => "BadPacket:" + w
  }
}

///|
fn session_error_name(e : @wtlive.WtSessionError) -> String {
  match e {
    @wtlive.HandshakeFailed(h) => "handshake:" + error_name(h)
    @wtlive.NoServiceAccept => "NoServiceAccept"
    @wtlive.UnexpectedService(s) => "UnexpectedService:" + s
    @wtlive.BadPacket(w) => "BadPacket:" + w
  }
}

///|
/// Loop #34 的测试私钥:即 RFC 6979 A.2.5 公布的 NIST P-256 key。
///
/// 与 cmd/ssh_live 用的是同一把,这样浏览器路径和原生路径签出来的公钥
/// 才能和同一份 authorized_keys 对上——两边用不同的私钥就没有可比性。
/// 这把私钥印在 RFC 原文里,**绝不能**用在真实主机上。
fn test_auth_key() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0xC9, 0xAF, 0xA9, 0xD8, 0x45, 0xBA, 0x75, 0x16, 0x6B, 0x5C, 0x21, 0x57, 0x67,
    0xB1, 0xD6, 0x93, 0x4E, 0x50, 0xC3, 0xDB, 0x36, 0xE8, 0x9B, 0x12, 0x7B, 0x8A,
    0x62, 0x2B, 0x12, 0x0F, 0x67, 0x21,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
/// AuthRejected 携带的三样证据原样打印,理由字段不在这一层被拼进字符串里,
/// 它得能被单独解析。
///|
/// 固定类失败的一句话说明,与 `cmd/ssh_live` 的同名函数逐字一致。
///
/// 两条驱动的文案必须一样:用户先在浏览器里遇到,再在终端里复现,文案不同就会
/// 变成「浏览器复现不了」这种猜测。理由见 `cmd/ssh_live` 里同一处。
fn print_pin_hint(e : @wtlive.WtAuthError) -> Unit {
  // 同 `cmd/ssh_live`:固定类失败住在 `WtLiveError` 里,握手期的那个经
  // `HandshakeFailed` 到达这里(这一侧没有 `Transport` 那一层,直接就是它)。
  let inner = match e {
    @wtlive.HandshakeFailed(h) => h
    _ => return
  }
  match inner {
    @wtlive.HostkeyCertAuthority(h) =>
      println(
        "hint: " + h + " is pinned via a @cert-authority entry, and this client does " +
        "not validate host certificates. This is not a man in the middle: pin the " +
        "host key directly (ssh-keyscan -t ecdsa " + h + "), or use kh_tofu and " +
        "know that the pin will break when the host renews its certificate.",
      )
    @wtlive.HostkeyMismatch(h) =>
      println(
        "hint: the key " + h + " presented does not match the pinned one. Treat this " +
        "as a man in the middle until you have checked otherwise; kh_tofu is the " +
        "way to accept the new key and stop asking.",
      )
    @wtlive.HostkeyUnknown(h) =>
      println(
        "hint: " + h + " has no key pinned at all. Add one, or pass kh_tofu to " +
        "accept and write back the key you are being shown now.",
      )
    _ => ()
  }
}

fn print_auth_rejection(e : @wtlive.WtAuthError) -> Unit {
  match e {
    @wtlive.AuthRejected(r, sb, sg) => {
      println("result: USERAUTH_FAILURE")
      println("reason: " + r)
      println("signed_blob: " + sb)
      println("sig_blob: " + sg)
    }
    _ => ()
  }
}

///|
fn auth_error_name(e : @wtlive.WtAuthError) -> String {
  match e {
    @wtlive.HandshakeFailed(h) => "handshake:" + error_name(h)
    @wtlive.NoServiceAccept => "NoServiceAccept"
    @wtlive.UnexpectedService(s) => "UnexpectedService:" + s
    @wtlive.SignFailed => "SignFailed"
    @wtlive.NoAuthReply => "NoAuthReply"
    @wtlive.AuthRejected(_, _, _) => "AuthRejected"
    @wtlive.BadPacket(w) => "BadPacket:" + w
  }
}

///|

///| `async fn main` because awaiting is itself an async operation, and MoonBit

///|
/// tracks asyncness statically: a sync `fn main` may not touch the transport.
///|
/// 原始字节打进标记块,和 cmd/ssh_live 同一套标记,好让两条路径的输出能直接
/// 逐行对比。验证脚本只读上面那几行数字。
///
/// 前 128 字节的十六进制。截断长度与 `cmd/ssh_live` 的 `dump_prefix` 一致,
/// 否则两条路径的输出会在长路径或长文件上分叉,而分叉的是**断言**本身。
fn wt_dump_prefix(b : FixedArray[Byte]) -> String {
  let n = if b.length() > 128 { 128 } else { b.length() }
  let sb = StringBuilder()
  for i = 0; i < n; i = i + 1 {
    let one : FixedArray[Byte] = FixedArray::from_array([b[i]])
    sb.write_string(@ecdsa.bytes_to_hex(one))
  }
  sb.to_string()
}

fn wt_print_bytes(b : FixedArray[Byte]) -> Unit {
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

fn wt_yn(b : Bool) -> String {
  if b {
    "true"
  } else {
    "false"
  }
}

fn cfg_int(name : String, fallback : Int) -> Int {
  let s = cfg(name)
  if s == "" {
    return fallback
  }
  let mut v = 0
  let mut any = false
  for i = 0; i < s.length(); i = i + 1 {
    let d = s[i].to_int()
    if d >= 48 && d <= 57 {
      v = v * 10 + (d - 48)
      any = true
    }
  }
  if any {
    v
  } else {
    fallback
  }
}

///| `cfg("resize")` 形如 "132x43";没给或格式不对就返回 None
fn cfg_resize() -> (Int, Int)? {
  let s = cfg("resize")
  if s == "" {
    return None
  }
  let mut first = -1
  let mut second = -1
  let mut seen_x = false
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
    } else if d == 120 || d == 88 {
      if seen_x || first <= 0 {
        return None
      }
      seen_x = true
    } else {
      return None
    }
  }
  if !seen_x || first <= 0 || second <= 0 {
    None
  } else {
    Some((first, second))
  }
}

///|
/// Loop #37:`cfg("stdin_bytes")` 给一个长度,`cfg("stdin_text")` 给一段字面量。
///
/// 模式串本体走 `@sshclient.ssh_stdin_pattern`——原生 CLI 用的是同一个函数,
/// 这样「两条路径发出的字节完全相同」才是一条关于协议的断言,而不是在比两段
/// 碰巧长得一样的数据。
fn cfg_stdin_bytes() -> FixedArray[Byte] {
  let text = cfg("stdin_text")
  if text != "" {
    return @sshclient.sh_ascii(text)
  }
  let n = cfg_int("stdin_bytes", 0)
  if n > 0 {
    return @sshclient.ssh_stdin_pattern(n)
  }
  FixedArray::make(0, b'\x00')
}

///|
/// `cfg("env")` 形如 `"NAME=VALUE;OTHER=thing"`。
///
/// 用分号而不是逗号分隔:`NAME=VALUE` 里出现逗号比出现分号常见得多(值里带分号是
/// 病态情况),而解析器不转义——它按第一个 `=` 切开名字和值、其余原样。
fn cfg_envs() -> Array[@sshclient.EnvVar] {
  let out : Array[@sshclient.EnvVar] = []
  let spec = cfg("env")
  if spec == "" {
    return out
  }
  let mut start = 0
  let mut i = 0
  while i <= spec.length() {
    if i == spec.length() || spec[i].to_int() == 59 {
      if i > start {
        let one = cfg_slice(spec, start, i)
        let at = cfg_index_of_eq(one)
        if at > 0 {
          out.push({
            name: cfg_slice(one, 0, at),
            value: cfg_slice(one, at + 1, one.length()),
          })
        }
      }
      start = i + 1
    }
    i = i + 1
  }
  out
}

///| 取 `s[from, to)`
fn cfg_slice(s : String, from : Int, to : Int) -> String {
  let sb = StringBuilder()
  let mut i = from
  while i < to {
    sb.write_char(Int::unsafe_to_char(s[i].to_int()))
    i = i + 1
  }
  sb.to_string()
}

///| 第一个 `=` 的下标;没有就返回 -1
fn cfg_index_of_eq(s : String) -> Int {
  for i = 0; i < s.length(); i = i + 1 {
    if s[i].to_int() == 61 {
      return i
    }
  }
  -1
}

fn wt_exec_error_name(e : @wtlive.WtExecError) -> String {
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
///
/// Loop #39:SFTP / subsystem,跑在浏览器 Worker 里。
///
/// 输出字段与 `cmd/ssh_live` 的 SFTP 模式**逐字相同**,验证脚本因此可以直接把
/// 两条输出按行对比——这才是「协议只有一份实现」的可检验形式:如果这里另写一套
/// 打印逻辑,两份输出就会在措辞上分叉,而分叉的恰好是**断言**本身。
///|
/// 与 `cmd/ssh_live` 的 `payload_of` 逐行相同的规则。
///
/// 这是**故意重复**的:Worker 里没有文件系统,没法把一份 blob 传进去,而把
/// 规则抄一遍的风险由门禁消掉——两条路径写出的文件由同一个 Python 规则算出
/// SHA-256 再对比,一旦有一侧算错,哈希立刻不等。所以这里宁可重复三行算术,
/// 也不要引入一个「共用的生成器」再给每个后端多加一条依赖。
fn wt_payload_of(n : Int) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ((i * 31 + 7) % 256).to_byte()
  }
  out
}

async fn wt_sftp_fault_run(url : String) -> Unit {
  let name = cfg("sftp_fault")
  if name == "" {
    wt_finish(false, "sftp_fault needs a scenario name")
    return
  }
  let c = wt_fault_case(name)
  let user = cfg("user")
  let uname = if user == "" { "hp" } else { user }
  println("scenario: " + c.name)
  println("intent: " + c.intent)
  let ops : Array[@sftp.SftpOp] = []
  for i = 0; i < c.ops.length(); i = i + 1 {
    let o = c.ops[i]
    ops.push(
      match o.kind {
        0 => @sftp.SftpOp::Realpath(o.path)
        1 => @sftp.SftpOp::Stat(o.path)
        4 => @sftp.SftpOp::WriteFile(o.path, wt_hex_to_bytes(o.arg))
        _ => @sftp.SftpOp::Rename(o.path, o.arg)
      },
    )
  }
  let conn = @wt.WtConn::connect(url) catch {
    _ => {
      println("outcome: connect_failed")
      wt_finish(false, "connect failed")
      return
    }
  }
  println("connected: true")
  // The same call `wt_sftp_run` makes, with the same op script the vectors
  // record. Nothing below the transport branches on which scenario this is --
  // that is the property being asserted.
  let outcome = @wtlive.wt_live_sftp(
    conn,
    fixed_x(),
    uname,
    test_auth_key(),
    ops,
    cfg_kh_policy(),
  )
  match outcome {
    @wtlive.WtSftpOutcome::Done(r) => {
      println("outcome: done")
      println("version: " + r.version.to_string())
      println("extensions: " + r.extensions.to_string())
      println("requests_sent: " + r.requests_sent.to_string())
      println("replies_recv: " + r.replies_recv.to_string())
      println("sftp_bytes_in: " + r.sftp_bytes_in.to_string())
      for i = 0; i < r.ops.length(); i = i + 1 {
        wt_print_sftp_op(i, r.ops[i])
      }
    }
    @wtlive.WtSftpOutcome::Failed(e) => {
      println("outcome: failed")
      println("error: " + wt_sftp_error_name(e))
    }
  }
  conn.close()
  wt_finish(true, "done")
}

async fn wt_sftp_run(url : String) -> Unit {
  let user = cfg("user")
  let uname = if user == "" { "hp" } else { user }
  let dir = cfg("sftp")
  let read_path = cfg("sftp_read")
  let missing = cfg("sftp_missing") == "1" || cfg("sftp_missing") == "true"
  // Loop #40 写侧。Config 是 URL 查询参数,所以每个操作自带名字而不是位置。
  let write_path = cfg("sftp_write")
  let write_size = cfg_int("sftp_write_size", 0)
  let mk = cfg("sftp_mkdir")
  let rm = cfg("sftp_remove")
  let rmd = cfg("sftp_rmdir")
  let rn_from = cfg("sftp_rename_from")
  let rn_to = cfg("sftp_rename_to")
  let subsystem = cfg("subsystem")
  let subsys = if subsystem == "" { "sftp" } else { subsystem }
  println("=== Loop #40 SFTP write side vs real sshd ===")
  println("user: " + uname)
  println("subsystem: " + subsys)
  let ops : Array[@sftp.SftpOp] = []
  ops.push(@sftp.SftpOp::Realpath("."))
  if dir != "" {
    ops.push(@sftp.SftpOp::ListDir(dir))
  }
  // 固定顺序,不是命令行顺序:config 是 URL 查询参数,每种操作只有一个值,
  // 没有「谁先出现」可言。顺序本身是有语义的——mkdir 必须在往里面写的
  // write 前面,rename 必须在被改名的文件存在之后。和 `cmd/ssh_live` 的差别
  // 是刻意的,那边是真正的 argv 序列。
  if mk != "" {
    ops.push(@sftp.SftpOp::MakeDir(mk, @sftp.SftpAttrs::none()))
  }
  if write_path != "" {
    ops.push(@sftp.SftpOp::WriteFile(write_path, wt_payload_of(write_size)))
  }
  if rn_from != "" && rn_to != "" {
    ops.push(@sftp.SftpOp::Rename(rn_from, rn_to))
  }
  if read_path != "" {
    ops.push(@sftp.SftpOp::ReadFile(read_path))
  }
  if rm != "" {
    ops.push(@sftp.SftpOp::RemovePath(rm))
  }
  if rmd != "" {
    ops.push(@sftp.SftpOp::RemoveDir(rmd))
  }
  if missing {
    ops.push(@sftp.SftpOp::Stat(
      ".loop39/definitely-not-here-" + "0f3a91c7",
    ))
  }
  let conn = @wt.WtConn::connect(url) catch {
    _ => {
      println("result: FAILED")
      println("error: ConnectFailed")
      wt_finish(false, "connect failed")
      return
    }
  }
  println("transport: connected")
  let outcome = @wtlive.wt_live_sftp(
    conn,
    fixed_x(),
    uname,
    test_auth_key(),
    ops,
    cfg_kh_policy(),
  )
  match outcome {
    @wtlive.WtSftpOutcome::Done(r) => {
      println("result: SFTP_DONE")
      println("version: " + r.version.to_string())
      println("extensions: " + r.extensions.to_string())
      println("requests_sent: " + r.requests_sent.to_string())
      println("replies_recv: " + r.replies_recv.to_string())
      println("sftp_bytes_in: " + r.sftp_bytes_in.to_string())
      println("total_sent_bytes: " + r.total_sent_bytes.to_string())
      println("total_recv_bytes: " + r.total_recv_bytes.to_string())
      for i = 0; i < r.ops.length(); i = i + 1 {
        wt_print_sftp_op(i, r.ops[i])
      }
    }
    @wtlive.WtSftpOutcome::Failed(e) => {
      println("result: SFTP_FAILED")
      println("error: " + wt_sftp_error_name(e))
    }
  }
  conn.close()
  wt_finish(true, "done")
}

fn wt_print_sftp_op(i : Int, op : @sftp.SftpOpResult) -> Unit {
  let tag = "op" + i.to_string()
  match op {
    @sftp.SftpOpResult::RealpathOk(p) => {
      println(tag + ": REALPATH")
      println(tag + "_path: " + @sftp.sftp_ascii(p).length().to_string())
      println(tag + "_hex: " + wt_dump_prefix(@sftp.sftp_ascii(p)))
    }
    @sftp.SftpOpResult::Attrs(a) => {
      println(tag + ": ATTRS")
      println(tag + "_size: " + wt_opt_u64(a.size))
      println(tag + "_uid: " + wt_opt_int(a.uid))
      println(tag + "_gid: " + wt_opt_int(a.gid))
      println(tag + "_perm: " + wt_opt_int(a.permissions))
    }
    @sftp.SftpOpResult::Listing(entries) => {
      println(tag + ": LISTING")
      println(tag + "_count: " + entries.length().to_string())
      for j = 0; j < entries.length(); j = j + 1 {
        println(
          tag + "_entry" + j.to_string() + ": " +
          wt_dump_prefix(@sftp.sftp_ascii(entries[j].0)) + " " +
          entries[j].1.to_string() + " " +
          (if entries[j].2 { "dir" } else { "file" }),
        )
      }
    }
    @sftp.SftpOpResult::Contents(b) => {
      println(tag + ": CONTENTS")
      println(tag + "_len: " + b.length().to_string())
      println(tag + "_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(b)))
      println(tag + "_hex: " + wt_dump_prefix(b))
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
      println(tag + "_msg_hex: " + wt_dump_prefix(@sftp.sftp_ascii(msg)))
    }
  }
}

fn wt_opt_int(v : Int?) -> String {
  match v {
    None => "-"
    Some(x) => x.to_string()
  }
}

fn wt_opt_u64(v : UInt64?) -> String {
  match v {
    None => "-"
    Some(x) => @sftp.sftp_u64_to_int(x).to_string()
  }
}

fn wt_sftp_error_name(e : @wtlive.WtSftpError) -> String {
  match e {
    AuthFailed(a) => "AUTH_FAILED " + auth_error_name(a)
    ChannelFailed(c) => "CHANNEL_FAILED " + wt_exec_error_name(c)
    Protocol(m) => "PROTOCOL " + m
    TooManyPackets => "TooManyPackets"
    Closed => "Closed"
  }
}

async fn main {
  // Loop #52: forget a pin and stop, without connecting. This exists because a
  // store you cannot clear is a store you cannot recover from when a key really
  // does change, and `ssh-keygen -R` has no browser equivalent without one.
  //
  // It is deliberately *only* this: forgetting must not also accept whatever
  // the peer presents next. Doing both in one step is how a "remove this pin"
  // button turns into a silent accept, which is the same fail-open Loop #51
  // just closed.
  if cfg("kh_forget") == "1" || cfg("kh_forget") == "true" {
    let host = cfg_kh_host()
    @khstore.forget(host)
    println("forget: " + host)
    // 必须发完成信号。Worker harness 靠 `__wt_finish` 判定「跑完了」,而每个
    // 模式都自己发——这一处一开始漏了,于是 `kh_forget` 打印了正确的一行然后
    // 静默挂死,门禁只看到一个 timeout 和一段完整 transcript。那种失败读起来像
    // 存储有问题,实际上什么都没发生。
    wt_finish(true, "done")
    return
  }
  let url = cfg("url")
  // The Worker passes `session: 1` for the Loop #33 run. A config lookup
  // rather than argv, because a browser has no argv.
  let want_session = cfg("session") == "1" || cfg("session") == "true"
  // Loop #34: `auth: 1` goes all the way to SSH_MSG_USERAUTH_SUCCESS.
  let want_auth = cfg("auth") == "1" || cfg("auth") == "true"
  // Loop #35: `exec: <command>` runs a remote command and reads back its
  // stdout / stderr / exit-status.
  let exec_cmd = cfg("exec")
  // Loop #36: `shell: <command>` opens a pty, types, optionally resizes, exits.
  // Checked before `exec` so a config carrying both runs the interactive one.
  let shell_cmd = cfg("shell")
  // Loop #46: one fault vector, against a peer that misbehaves on purpose.
  // Checked before the SFTP read/write dispatch, because the two share the
  // `sftp_` prefix and a vector named after its own file would otherwise be
  // indistinguishable from a read request.
  if cfg("sftp_fault") != "" {
    wt_sftp_fault_run(url)
    return
  }
  // Loop #39/40: SFTP read and write side.  Checked after `shell`, which keeps
  // the earlier dispatch order intact.
  if cfg("sftp") != "" || cfg("sftp_read") != "" || cfg("sftp_missing") != "" ||
    cfg("sftp_write") != "" || cfg("sftp_mkdir") != "" ||
    cfg("sftp_remove") != "" || cfg("sftp_rmdir") != "" ||
    cfg("sftp_rename_from") != "" {
    wt_sftp_run(url)
    return
  }
  if shell_cmd != "" {
    let user = cfg("user")
    let uname = if user == "" { "hp" } else { user }
    let cols = cfg_int("cols", 80)
    let rows = cfg_int("rows", 24)
    let resize = cfg_resize()
    println("=== Loop #36 interactive shell in a browser Worker ===")
    println("transport_url: " + url)
    println("user: " + uname)
    println("command: " + shell_cmd)
    println("cols: " + cols.to_string())
    println("rows: " + rows.to_string())
    match resize {
      Some((c, r)) => println("resize: " + c.to_string() + "x" + r.to_string())
      None => println("resize: none")
    }
    let sconn2 = @wt.WtConn::connect(url) catch {
      _ => {
        println("result: FAILED")
        println("error: ConnectFailed")
        wt_finish(false, "connect failed")
        return
      }
    }
    println("transport: connected")
    let soutcome = @wtlive.wt_live_shell(
      sconn2,
      fixed_x(),
      uname,
      test_auth_key(),
      shell_cmd,
      "xterm-256color",
      cols,
      rows,
      resize,
      cfg_kh_policy(),
    )
    match soutcome {
      @wtlive.Done(r) => {
        println("result: SHELL_DONE")
        println("pty_granted: " + wt_yn(r.pty_granted))
        println("resize_sent: " + wt_yn(r.resize_sent))
        println("stdout_len: " + r.stdout.length().to_string())
        println("stdout_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stdout)))
        println("stderr_len: " + r.stderr.length().to_string())
        println("stderr_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stderr)))
        println("exit_status: " + r.exit_status.to_string())
        match r.exit_signal {
          None => println("exit_signal: none")
          Some((n, core)) =>
            println("exit_signal: " + n + " core=" + wt_yn(core))
        }
        println("adjusts_sent: " + r.adjusts_sent.to_string())
        println("total_sent_bytes: " + r.sent_bytes.to_string())
        println("total_recv_bytes: " + r.recv_bytes.to_string())
        let seen = @sshclient.sh_contains_bytes(
          r.stdout,
          @sshclient.sh_ascii(shell_cmd),
        )
        println("marker_seen: " + wt_yn(seen))
        wt_print_bytes(r.stdout)
        wt_print_bytes(r.stderr)
      }
      @wtlive.AuthFailed(e) => {
        println("result: AUTH_FAILED")
        print_auth_rejection(e)
        println("error: " + auth_error_name(e))
        print_pin_hint(e)
      }
      @wtlive.ChannelFailed(e) => {
        println("result: CHANNEL_FAILED")
        println("error: " + wt_exec_error_name(e))
      }
    }
    sconn2.close()
    wt_finish(true, "done")
    return
  }
  if exec_cmd != "" {
    let user = cfg("user")
    let uname = if user == "" { "hp" } else { user }
    println("=== Loop #35 exec in a browser Worker ===")
    println("transport_url: " + url)
    println("user: " + uname)
    println("command: " + exec_cmd)
    let stdin_data = cfg_stdin_bytes()
    println("stdin_bytes: " + stdin_data.length().to_string())
    let envs = cfg_envs()
    for i = 0; i < envs.length(); i = i + 1 {
      println("env: " + envs[i].name + "=" + envs[i].value)
    }
    let econn = @wt.WtConn::connect(url) catch {
      _ => {
        println("result: FAILED")
        println("error: ConnectFailed")
        wt_finish(false, "connect failed")
        return
      }
    }
    println("transport: connected")
    let outcome = @wtlive.wt_live_exec_io(
      econn,
      fixed_x(),
      uname,
      test_auth_key(),
      exec_cmd,
      stdin_data,
      envs,
      cfg_kh_policy(),
    )
    match outcome {
      @wtlive.Done(r) => {
        println("result: EXEC_DONE")
        println("stdout_len: " + r.stdout.length().to_string())
        println("stdout_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stdout)))
        println("stderr_len: " + r.stderr.length().to_string())
        println("stderr_sha256: " + @ecdsa.bytes_to_hex(@sha256.sha256(r.stderr)))
        println("exit_status: " + r.exit_status.to_string())
        println("remote_id: " + r.remote_id.to_string())
        println("adjusts_sent: " + r.adjusts_sent.to_string())
        println("stdin_sent: " + r.stdin_sent.to_string())
        println("stdin_packets: " + r.stdin_packets.to_string())
        println("eof_sent: " + wt_yn(r.eof_sent))
        println("env_sent: " + r.env_sent.to_string())
        println("total_sent_bytes: " + r.sent_bytes.to_string())
        println("total_recv_bytes: " + r.recv_bytes.to_string())
        wt_print_bytes(r.stdout)
        wt_print_bytes(r.stderr)
      }
      @wtlive.AuthFailed(e) => {
        println("result: AUTH_FAILED")
        print_auth_rejection(e)
        println("error: " + auth_error_name(e))
        print_pin_hint(e)
      }
      @wtlive.ChannelFailed(e) => {
        println("result: CHANNEL_FAILED")
        println("error: " + wt_exec_error_name(e))
      }
    }
    econn.close()
    wt_finish(true, "done")
    return
  }
  if want_auth {
    let user = cfg("user")
    let uname = if user == "" { "hp" } else { user }
    println("=== Loop #34 publickey auth in a browser Worker ===")
    println("transport_url: " + url)
    println("user: " + uname)
    let aconn = @wt.WtConn::connect(url) catch {
      _ => {
        println("result: FAILED")
        println("error: ConnectFailed")
        wt_finish(false, "connect failed")
        return
      }
    }
    println("transport: connected")
    match
      @wtlive.wt_live_auth(
        aconn,
        fixed_x(),
        uname,
        test_auth_key(),
        cfg_kh_policy(),
      ) {
      @wtlive.Authenticated(r) => {
        println("result: USERAUTH_SUCCESS")
        cfg_report_tofu(r)
        println("user: " + r.user)
        println("method: " + r.method)
        println("key_type: " + r.key_type)
        // Loop #38: the negotiated host key algorithm, the key type it turned
        // out to be, and the key size.  Mirrors `cmd/ssh_live --auth` exactly,
        // because the point of the comparison is that a browser Web Worker and
        // the native client reach the same host key decision -- and under RFC
        // 8332 the first two of these are *not* the same string for RSA
        // (negotiated `rsa-sha2-512`, blob says `ssh-rsa`).
        println("hostkey_alg: " + r.session.handshake.hostkey_alg)
        println("hostkey_type: " + r.session.handshake.hostkey_type)
        println("hostkey_bits: " + r.session.handshake.hostkey_bits.to_string())
        println("session_id_head: " + r.session.session_id_head)
        println("signed_blob: " + r.signed_blob_hex)
        println("sig_blob: " + r.sig_blob_hex)
        println("request: " + r.request_hex)
        println("handshake_sent_bytes: " + r.session.handshake.sent_bytes.to_string())
        println("handshake_recv_bytes: " + r.session.handshake.recv_bytes.to_string())
        println("total_sent_bytes: " + r.session.sent_bytes.to_string())
        println("total_recv_bytes: " + r.session.recv_bytes.to_string())
      }
      @wtlive.Failed(e) => {
        print_auth_rejection(e)
        if auth_error_name(e) != "AuthRejected" {
          println("result: FAILED")
          println("error: " + auth_error_name(e))
          print_pin_hint(e)
        }
      }
    }
    aconn.close()
    wt_finish(true, "done")
    return
  }
  if want_session {
    println("=== Loop #33 encrypted session in a browser Worker ===")
    println("transport_url: " + url)
    let sconn = @wt.WtConn::connect(url) catch {
      _ => {
        println("result: FAILED")
        println("error: ConnectFailed")
        wt_finish(false, "connect failed")
        return
      }
    }
    println("transport: connected")
    match @wtlive.wt_live_session(sconn, fixed_x(), cfg_kh_policy()) {
      @wtlive.ServiceAccepted(r) => {
        println("result: SERVICE_ACCEPTED")
        println("service: " + r.service_name)
        println("accepted: " + r.accepted_service)
        println("we_need: " + r.we_need.to_string())
        println("cipher_ctos: " + r.handshake.cipher_ctos)
        println("mac_ctos: " + r.handshake.mac_ctos)
        println("key_tag: " + r.key_tag)
        println("session_id_head: " + r.session_id_head)
        println("handshake_sent_bytes: " + r.handshake.sent_bytes.to_string())
        println("handshake_recv_bytes: " + r.handshake.recv_bytes.to_string())
        println("total_sent_bytes: " + r.sent_bytes.to_string())
        println("total_recv_bytes: " + r.recv_bytes.to_string())
      }
      @wtlive.Failed(e) => {
        println("result: FAILED")
        println("error: " + session_error_name(e))
      }
    }
    sconn.close()
    wt_finish(true, "done")
    return
  }
  println("=== Loop #32 SSH transport handshake in a browser Worker ===")
  println("transport_url: " + url)
  let conn = @wt.WtConn::connect(url) catch {
    e => {
      println("result: FAILED")
      println("error: ConnectFailed")
      wt_finish(false, "connect failed")
      return
    }
  }
  println("transport: connected")
  match @wtlive.wt_live_handshake(conn, fixed_x(), cfg_kh_policy()) {
    @wtlive.Established(r) => {
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
    @wtlive.Failed(e) => {
      println("result: FAILED")
      println("error: " + error_name(e))
      // On a signature failure the exchange hash is the whole question, so
      // print it: an independent implementation can recompute H from the same
      // transcript and the two either agree or name the divergence.
      match e {
        @wtlive.SignatureInvalid(h) =>
          println("exchange_hash: " + @ecdsa.bytes_to_hex(h))
        _ => ()
      }
    }
  }
  conn.close()
  wt_finish(true, "done")
}
