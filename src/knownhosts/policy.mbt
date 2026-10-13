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
  /// Unix 秒。**证书路径必须有一个真实时钟**，所以它由调用方注入而不是在这里取。
  ///
  /// 没有它的话，有效期判定就没法做：要么读墙上时间（门禁不可重放，「过期证书
  /// 必须被拒」写出来第二天就永远为真），要么假装过期（那等于关掉证书）。
  /// 默认 0 是**刻意的 fail-closed**：把证书判成 not-yet-valid 而拒绝。
  now : UInt64
}

///|
pub fn KnownHostsPolicy::new(
  entries : Array[KnownHostEntry],
  host_str : String,
  port : Int,
  strict : Bool,
) -> KnownHostsPolicy {
  { entries, host_str, port, strict, now: 0UL, }
}

///|
/// 带显式时钟的构造函数。证书验证必须用真实时间，见 `now` 字段的说明。
pub fn KnownHostsPolicy::at(
  entries : Array[KnownHostEntry],
  host_str : String,
  port : Int,
  strict : Bool,
  now : UInt64,
) -> KnownHostsPolicy {
  { entries, host_str, port, strict, now, }
}

///| 这台主机是否被任何 `@cert-authority` 条目覆盖
///
///| 客户端据此决定要不要在 KEXINIT 里**报出**主机证书算法。规则是「有信任锚
///| 才报」,不是 OpenSSH 的「无条件报、之后再拒」。
///
///| 理由有两条,一条是安全的:我们**永远**只认被 pin 的 CA(见 `CertUntrusted`),
///| 所以在没有 CA 条目时报出证书算法只增加攻击面,对合法连接没有任何好处。
///| 另一条是本仓库特有的:KEXINIT 的算法名列表是要和 OpenSSH/paramiko 抓包
/// 逐字节对比的,无条件加名字会让那几道门禁的基线全部漂掉。
///
///| 这是一个**有意的偏差**,不是遗漏;注释写在这里就是为了下次有人「补全」它时
/// 能先看见。
pub fn KnownHostsPolicy::has_ca_anchor(self : KnownHostsPolicy) -> Bool {
  let (host_only, port_from_str) = split_host_str(self.host_str)
  let port_caller = if self.port == 0 {
    match port_from_str {
      Some(p) => p
      None => 22
    }
  } else {
    self.port
  }
  has_any_ca_entry(self.entries, host_only, port_caller)
}

///|
/// 显式的「不固定」。
///
/// 注意它和 `from_text("", host, 0, false)` 在行为上无法区分:两者都是
/// 「一条都没有 + 非 strict」。这不是缺陷而是要点——「不固定」只有一个意思,
/// 它必须走 `Unknown + 非 strict` 那条路,而不是一条只在特定配置下才生效的
/// 旁路。旁路正是默认不安全的那类形状。
pub fn KnownHostsPolicy::skip() -> KnownHostsPolicy {
  { entries: [], host_str: "", port: 0, strict: false, now: 0UL, }
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
  { entries: parse_file(content), host_str, port, strict, now: 0UL, }
}

///|
/// `from_text` + 显式时钟
pub fn KnownHostsPolicy::from_text_at(
  content : String,
  host_str : String,
  port : Int,
  strict : Bool,
  now : UInt64,
) -> KnownHostsPolicy {
  { entries: parse_file(content), host_str, port, strict, now, }
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
  /// Loop #53: 这台主机的 `@cert-authority` 条目命中了，但证书没过验。
  /// 字符串里是具体理由（`expired` / `principal-mismatch` /
  /// `ca-signature-invalid` / `ca-revoked` ...）。
  ///
  /// Loop #51 时这个变体叫 `CertAuthority` 且不带载荷，含义是「我们不验证主机
  /// 证书」。现在我们验证了，所以它改名为 `CertRejected` 并带上理由——两者对应
  /// 完全不同的处置，必须能一眼分开。
  CertRejected(String)
  /// 出示了证书，但这台主机没有任何 `@cert-authority` 条目
  CertUntrusted(String)
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
  // Loop #53: 出示的是一张证书就走证书路径。这里只**分流**，不做信任判断——
  // 「像不像证书」只是读 blob 的第一个字符串，而真正的判断全在下面。
  if @hostkey.looks_like_cert(presented_blob) {
    return self.verify_cert(presented_blob)
  }
  match check_host_key(self.entries, self.host_str, self.port, presented_blob) {
    Ok => Accept
    Mismatch => Mismatch
    Unknown => Unknown
    CertAuthority => CertRejected("no-certificate-expected")
    InvalidEntry => InvalidEntry
  }
}

///|
/// 证书路径的判定（Loop #53）
///
///| 两条优先级规则在这里落地：
///
///| 1. **直接条目压过 CA 条目。** 这台主机既有 `@cert-authority` 又有一把裸钥匙的
///|    直接 pin，而对端递了张证书过来 —— 报 `Mismatch`，不是 `CertAuthority`。
///|    Loop #51 立这条规则是为了别把「钥匙真换了」洗成「我不支持证书」；证书只是
///|    换了一种出示方式，不该成为绕过它的后门。
///| 2. **证书必须找到自己那把 CA 才可能被认**，见 `CertUntrusted` 的说明。
pub fn KnownHostsPolicy::verify_cert(
  self : KnownHostsPolicy,
  cert_blob : FixedArray[Byte],
) -> PinVerdict {
  let (host_only, port_from_str) = split_host_str(self.host_str)
  let port_caller = if self.port == 0 {
    match port_from_str {
      Some(p) => p
      None => 22
    }
  } else {
    self.port
  }
  // 规则 1：直接 pin 存在时，证书不能顶替它。
  if find_last_direct_match_v2(self.entries, host_only, port_caller) is Some(_) {
    return Mismatch
  }
  match check_host_key_cert(
    self.entries,
    self.host_str,
    self.port,
    cert_blob,
    self.now,
  ) {
    Trusted => Accept
    CaRejected(reason) => CertRejected(reason)
    NoCaEntry => CertUntrusted(self.host_str)
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
  CertAuthority(String, String)
  /// Loop #53: 出示了一张证书，但这台主机**没有**任何 `@cert-authority` 条目。
  ///
  /// 和 `Unknown` 看起来相似（都是「没 pin 过」），但**处置相反**：`Unknown` 在
  /// 非 strict 下会放行，这里在**任何**模式下都拒绝。因为 `Unknown` 的含义是
  /// 「对端出示了一把裸钥匙，而我们没 pin 过它」——此时对端持有的东西就是全部的
  /// 信任来源，宽松模式放行的是「一把没验证过的钥匙」；而证书的内层钥匙是由 CA
  /// 背书的凭证，没有 CA 就没有任何信任来源，和 MITM 没有区别。
  ///
  /// `--kh-tofu` 也不开这个口子：它会把「学一张没被 pin 住的证书」变成事实。
  CertUntrusted(String)
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
    // Loop #53 起这条不再是「我们不验证证书」——我们验证了，而且验不过。
    // 字符串里是具体理由（expired / principal-mismatch / ca-signature-invalid
    // ...），因为这几种的处置完全不同：补一个 CA 条目、重新签一张证书、
    // 查 CA 私钥，各走各的路。
    CertRejected(reason) => Some(CertAuthority(self.host_str, reason))
    // 证书没有任何本地信任锚。没有 strict 的例外，也没有 TOFU 的例外。
    CertUntrusted(host) => Some(CertUntrusted(host))
    InvalidEntry => Some(InvalidEntry)
  }
}
