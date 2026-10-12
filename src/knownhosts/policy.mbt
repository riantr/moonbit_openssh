///| 一次连接要拿哪些条目去比对、对哪个主机名、比不上怎么办。

///|

///| 这是 Loop #48 加的。`src/kexflow` 里那份规则(`check_host_key_strict`)

///| 只在 kexflow 自己的路径上跑,而两条 live 适配器 (`src/sshclient/live.mbt`

///| 和 `src/wtlive/live.mbt`) 各自实现了握手、根本没走 kexflow —— 所以在

///| 真正的客户端上,主机密钥固定从来没有执行过。签名验证证明的是「对端拥有

///| 它出示的那把钥匙」,不证明「那是我期待的那把钥匙」;后者才是防中间人的

///| 那一半,而 OpenSSH 默认就做(`sshconnect.c` 的 `check_host_key_not_revoked`

///| 之后紧跟 `hostkeys_find` + 比对,不一致就报 HOST_CHANGED 直接退出)。

///|

///| 规则仍住这一份,和 `agrees_with_alg` 同一个道理:两条传输层驱动不各自

///|
/// 抄判定,只问「这把钥匙行不行」。
pub(all) struct KnownHostsPolicy {
  /// 空数组 = 本次不做固定(见 `verify` 返回的 `Skip`)
  entries : Array[KnownHostEntry]
  /// 主机名或 `[host]:port`,和 known_hosts 里写的形式一致
  host_str : String
  /// 0 = SSH 默认端口 22
  port : Int
  /// strict_kex:主机名压根没被固定过也算失败(TOFU 的拒绝侧)
  strict : Bool
}

///|
pub fn KnownHostsPolicy::new(
  entries : Array[KnownHostEntry],
  host_str : String,
  port : Int,
  strict : Bool,
) -> KnownHostsPolicy {
  { entries, host_str, port, strict, }
}

///|
pub fn KnownHostsPolicy::skip() -> KnownHostsPolicy {
  { entries: [], host_str: "", port: 0, strict: false, }
}

///|
/// 从 known_hosts 的**文本**建一份策略。
///
/// 是文本而不是路径,是因为浏览器那一侧根本没有文件:`src/wt` 是 js-only,
/// `cmd/wt_ssh` 的配置是从 Worker 的 postMessage 进来的。两条传输层驱动因此
/// 都调用这一个函数——否则「怎么把 known_hosts 变成条目」会在两边各抄一份,
/// 而这两份正是最容易悄悄漂掉的地方(一段 trim、一个跳注释行的判断)。
pub fn KnownHostsPolicy::from_text(
  content : String,
  host_str : String,
  port : Int,
  strict : Bool,
) -> KnownHostsPolicy {
  { entries: parse_file(content), host_str, port, strict, }
}

///|

///| 判定结果。`Skip` 和 `Accept` 的区别只有一个,但它们必须分开:调用方要

///| 知道自己到底是「比过了并且一致」还是「压根没比」,因为后者是一个策略

///|
/// 决定(而且是一个不安全的那个),值得在诊断里显出来。
pub(all) enum PinVerdict {
  Skip
  Accept
  Mismatch
  Unknown
  InvalidEntry
}

///|

///| 对一把出示的 host key blob 做固定检查。

///|

///| `InvalidEntry` 在 strict 下是 `check_host_key_strict` 把 Unknown 升级来的,

///| 语义上不是「条目坏了」而是「没见过这个主机名」—— 调用方需要能分开这两种

///|
/// 失败,所以这里把 strict 关掉、自己判,把两个状态原样交出去。
pub fn KnownHostsPolicy::verify(
  self : KnownHostsPolicy,
  presented_blob : FixedArray[Byte],
) -> PinVerdict {
  if self.entries.length() == 0 {
    return Skip
  }
  match check_host_key(self.entries, self.host_str, self.port, presented_blob) {
    Ok => Accept
    Mismatch => Mismatch
    Unknown => Unknown
    InvalidEntry => InvalidEntry
  }
}

///|

///| 便捷判断:能不能继续。

///|

///| 和 `verify` 分开是因为**诊断需要分开**:`Unknown` 在非 strict 下是可以

///| 继续的(TOFU),但报告出来必须是「没被固定过」而不是「通过了」,否则一份

///|
/// 「全都验证过了」的日志会撒谎。
pub fn KnownHostsPolicy::allows(
  self : KnownHostsPolicy,
  presented_blob : FixedArray[Byte],
) -> Bool {
  match self.verify(presented_blob) {
    Skip => true
    Accept => true
    Unknown => !self.strict
    Mismatch => false
    InvalidEntry => false
  }
}
