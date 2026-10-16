///| 把一个出示的 host key blob 渲染成一条 known_hosts 行。

///|

///| Loop #48 收尾。固定检查回答的是「这把钥匙是我预期的吗」,但第一次连接

///| **没有人预期任何东西**——TOFU 的 S 就是 trust on first use:接受,然后记住。

///| 没有写回,「记住」就没有发生,下一次连接仍然是一次全新的、无凭据的接受,

///| 而防重放也就无从谈起。

///|

///| 这里只做**渲染**:把 `(host, key_type, blob)` 变成 OpenSSH 写的那行

///| `host keytype base64(blob)`。写盘不在这里,也不在 `src/` 的任何地方——

///| 这个 moon 版本的 core 没有文件 IO,而 `src/wt` 是 js-only、浏览器里根本没有

///| 文件系统(见 AGENTS.md Loop #48)。所以本包只负责「长什么样」,由驱动决定

///|
/// 「写到哪去」,两条传输层驱动因此拿到的是同一串字节而不是各自的实现。
/// base64 编码。与本包 `b64_decode` 配对,所以「读进来再写出去」得到的是
/// OpenSSH 自己写的那串——标准 base64 带 `=` 补位,`b64_decode` 收得下。
///
/// 补位交给 @base64.encode 而不是这里数:手数补位是那种「多一个 `=` 也能过、
/// 少一个过不了」的错误,而 known_hosts 的解析端未必宽容。
fn base64_encode(blob : FixedArray[Byte]) -> String {
  // 一次喂完整串:`@base64.encode` 自己按 3 字节分组并处理补位(padding 默认
  // 就是 true,也就是 OpenSSH 写的那种带 `=` 的标准 base64)。手工切块既没有
  // 好处,又要自己数补位。
  //
  // 桥是 `Bytes::from_fixedarray`:`@base64.encode` 要 `BytesView`,而本包的条目
  // 里存的是 `FixedArray[Byte]`,两者之间没有隐式转换,而 `FixedArray` 上也没有
  // `to_bytes()` 方法——那是 `String` 才有的。
  @base64.encode(Bytes::from_array(blob))
}

///|
/// `host keytype base64(blob)`,不带换行、不带 marker。
///
/// 给需要自己决定终止符的调用方(`KnownHostEntry::render` 与 `append_line`
/// 各带一次,只有一份字段顺序)。新写的 TOFU 条目永远是普通条目,所以这里没有
/// marker 是对的;要保留一个已有条目的 marker,用 `render`。
pub fn KnownHostEntry::to_line(
  host_field : String,
  key_type : String,
  blob : FixedArray[Byte],
) -> String {
  host_field + " " + key_type + " " + base64_encode(blob)
}

///|
/// 一条 known_hosts 行 = 一个条目,**带结尾换行**。
///
/// 带换行不是格式偏好,而是往返闭合的必要条件:`parse_file` 切出来的每一行都含
/// 它自己的换行符(最后一行除外),所以 `render` 不带换行的话,「读进来再写出去」
/// 两边差一个 `\n`——而那个差会被误读成 key 变了。
///
/// `host_field` 保留原始的 hostname 字段(逗号分隔的模式、否定标记都在里面),
/// 所以拿它渲染回去能得到与源文件逐字一致的行。写回顺手「规范化」掉通配符或
/// 否定标记,比不写回更糟:用户下一次会以为自己在读自己写的东西。
pub fn KnownHostEntry::render(self : KnownHostEntry) -> String {
  // `@revoked` / `@cert-authority` 必须带上。丢掉 `@revoked` 会把一条**吊销**
  // 记录变成一条普通**信任**记录——方向正好相反,而且读回去完全合法,不会有
  // 任何一行说它错了。这是写回最容易造成、也最难发现的一类损坏,所以
  // `render_test.mbt` 里对它有一条专门的断言。
  let marker = match self.marker {
    Marker::None => ""
    Marker::CertAuthority => "@cert-authority "
    Marker::Revoked => "@revoked "
  }
  marker +
  self.host_raw +
  " " +
  self.key_type +
  " " +
  base64_encode(self.key_blob) +
  "\n"
}

///|
/// `existing` 里是不是已经有**逐字相同**的这一行（不含换行比较）。
///
/// Loop #54 把它提出来是因为两个调用点需要同一份判据：`append_line` 走文本，
/// 原生侧的落盘走文件，而两处各写一遍「split + trim + 比较」迟早会有一处忘了
/// 跳过空行和注释——而一份全是注释的 known_hosts 会让第一条真正的 TOFU 记录被
/// 跳过，那正是第一次写回。
///
/// `line` 应当是 `to_line` 的产物（不带换行）。比较前两侧都 `trim`，所以传进来
/// 带不带换行都判得对，但不带换行是这个函数的约定。
pub fn has_line(existing : String, line : String) -> Bool {
  for l in existing.split("\n") {
    if l.trim() == line {
      return true
    }
  }
  false
}

///|
/// 往一段 known_hosts 文本里**追加**一条,末尾补换行。
///
/// 追加而不是覆盖:OpenSSH 的语义是 last-match-wins,新条目加在**后面**才会
/// 覆盖旧的那条,加在前面则会被旧的遮住。一个看起来在工作、实际永远命不中
/// 旧条目的写回,比不写回更难查。
///
/// 已经有完全相同的一行时原样返回原文——重复 TOFU 不该让文件一直增长,也不该
/// 产生噪音。
pub fn append_line(
  existing : String,
  host_field : String,
  key_type : String,
  blob : FixedArray[Byte],
) -> String {
  // 走 `to_line` 而不是另拼一遍:这个顺序就是 OpenSSH 写的顺序,两处各拼一次
  // 迟早有一处少个空格,而少个空格的行**仍然解析得出来**,只是比对永远命中不了。
  let line = KnownHostEntry::to_line(host_field, key_type, blob)
  if has_line(existing, line) {
    return existing
  }
  if existing.length() == 0 {
    return line + "\n"
  }
  if existing[existing.length() - 1] == '\n' {
    existing + line + "\n"
  } else {
    existing + "\n" + line + "\n"
  }
}
