///| 一次连接要拿哪些条目去比对、对哪个主机名、比不上怎么办。

///|
/// 这是 Loop #48 加的。`src/kexflow` 里那份规则(`check_host_key_strict`)
/// 只在 kexflow 自己的路径上跑,而两条 live 适配器(`src/sshclient/live.mbt`
/// 和 `src/wtlive/live.mbt`)各自实现了握手、根本没走 kexflow —— 所以在
/// 真正的客户端上,主机密钥固定从来没有执行过。签名验证证明的是「对端拥有
/// 它出示的那把钥匙」,不证明「那是我期待的那把钥匙」;后者才是防中间人的
/// 那一半,而 OpenSSH 默认就做(`sshconnect.c` 的 `check_host_key_not_revoked`
/// 之后紧跟 `hostkeys_find` + 比对,不一致就报 HOST_CHANGED 直接退出)。
///
/// 规则仍住这一份,和 `agrees_with_alg` 同一个道理:两条传输层驱动不各自
/// 抄判定,只问「这把钥匙行不行」。
pub(all) struct KnownHostsPolicy {
  /// 空数组 = known_hosts 里一条都没有。
  ///
  /// 「本次不做固定」**不**靠这个字段表达,而靠 `strict = false`。把两者
  /// 绑在一起就是 Loop #50 的 bug,见 `decide` 的文档。
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
/// 显式的「不固定」。
///
/// 注意它和 `from_text("", host, 0, false)` 在行为上无法区分:两者都是
/// 「一条都没有 + 非 strict」。这不是缺陷而是要点——「不固定」只有一个意思,
/// 它必须走 `Unknown + 非 strict` 那条路,而不是一条只在特定配置下才生效的
/// 旁路。旁路正是默认不安全的那类形状。
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
/// 比对的结果,不含策略。
///
/// Loop #50 删掉了 `Skip`。它原本表示「entries 是空的,压根没比」,而
/// `Unknown` 表示「比了,没有条目命中这个主机」——这两个在**行为上**必然一致
/// (都没命中),却在 strict 下给出相反的答案。留着它,就是把「忘了配」和
/// 「配了但没匹上」这两种必须区别对待的情况塞进同一个字段;而 Loop #50 的
/// 默认值恰好就死在那个字段上。
///
/// OpenSSH 的 `StrictHostKeyChecking=no` 与 `accept-new` 的差别**不**在这里:
/// 两者的比对结果都是 `Unknown`,区别只在之后写不写回。写回是驱动的事
/// (`cmd/ssh_live` 的 `--kh-tofu`),不是比对结果的属性。
pub(all) enum PinVerdict {
  Accept
  Mismatch
  Unknown
  CertAuthority
  InvalidEntry
}

///|
/// 对一把出示的 host key blob 做固定检查。
///
/// 纯比对:不读 `strict`。空 entries 在这里等于 `Unknown`,由 `check_host_key`
/// 自然给出(它的第 90 行本来就是 `if entries.length() == 0 { return Unknown }`)。
///
/// 此前 `verify` 在这里**提前** `return Skip`,把下面那份 `Unknown` 吞掉了。
/// 那一句就是 Loop #50 默认值不生效的全部原因。
pub fn KnownHostsPolicy::verify(
  self : KnownHostsPolicy,
  presented_blob : FixedArray[Byte],
) -> PinVerdict {
  match check_host_key(self.entries, self.host_str, self.port, presented_blob) {
    Ok => Accept
    Mismatch => Mismatch
    Unknown => Unknown
    CertAuthority => CertAuthority
    InvalidEntry => InvalidEntry
  }
}

///|
/// 失败的原因。「没被固定过」和「钥匙对不上」需要完全不同的处置:前者是
/// 「你还没 pin 这个主机」,后者是「有人在中间」——后者该报警,前者只是
/// 配置还没做。所以判定把原因带出来,而不只给一个 Bool。
pub(all) enum PinFailure {
  Mismatch(String)
  Unknown(String)
  /// Loop #51: 这台主机是用 `@cert-authority` pin 的,而本客户端不验证主机证书。
  ///
  /// 和 `Mismatch` 分开不是为了好看,是因为两者的**处置完全不同**:
  /// `Mismatch` 是「有人在中间」,该报警、该换密钥、该查日志;而这一条是
  /// 「这个客户端没实现证书验证」,该换工具或改配置。把后者报成前者,用户
  /// 照着 `HOST_CHANGED` 的标准流程走就会去加 `--kh-tofu`,而那正好是
  /// Loop #50 刚刚才让需要多敲一个字的选择。
  CertAuthority(String)
  InvalidEntry
}

///|
/// 放行,或者给出拒绝的原因。这是**唯一**的判定入口。
///
/// Loop #50 之前有两条路:`allows`(Bool 版)和两条适配器里各手写一遍的
/// `match`。`allows` 写好了、没有任何调用方,而真正的判定散在两处——改默认值
/// 时只改一处的可能性高得可怕。现在适配器只调它。
///
/// 返回 `Option[PinFailure]` 而不是 `Result`:「能不能继续」是一个**问题**,
/// 而不是一次带值的成功——`Ok(())` 里那个 `()` 没有信息量,只会诱使人再加一个
/// `is_ok()`。拒绝要带原因,放行不需要带任何东西。
///
///|
///
/// **empty entries 在这里是 `Unknown`,不是放行。** 这一条是 Loop #50 真正的
/// 修复点。旧的 `verify` 在 `entries.length() == 0` 时提前返回 `Skip`,而旧的
/// `decide` 把 `Skip` 当作「没问题」——于是「什么都没配」在 strict 下被读成了
/// 「通过了」。`cmd/ssh_live` 的默认因此连改三次都没生效,而 `moon build` 一直
/// 报 "no work to do",让一个没生效的默认值看起来像是构建缓存问题。
///
/// 代价是好的:现在唯一的「不固定」是 `skip()`(strict = false),它经由
/// `Unknown + 非 strict` 拿到同一个放行答案,但走的是**同一段代码**。少一条
/// 只在某种配置下才触发的旁路,就不会有「默认值落在旁路上」这种事。
pub fn KnownHostsPolicy::decide(
  self : KnownHostsPolicy,
  presented_blob : FixedArray[Byte],
) -> Option[PinFailure] {
  match self.verify(presented_blob) {
    Accept => None
    Unknown =>
      if self.strict {
        Some(Unknown(self.host_str))
      } else {
        None
      }
    Mismatch => Some(Mismatch(self.host_str))
    // 没有 strict 的例外:我们不验证证书,所以**任何**模式下都没有可接受的
    // 主机密钥。`--kh-tofu` 也不开这个口子——那会把「用 CA pin 的」悄悄变成
    // 「信任此刻出示的任何东西」,正是 Loop #51 关掉的那个降级。
    CertAuthority => Some(CertAuthority(self.host_str))
    InvalidEntry => Some(InvalidEntry)
  }
}
