///| Loop #80: the SSH agent protocol.
///

///|
/// `ssh-agent` holds private keys so that the client never has to. The
/// client asks the agent two things, and the protocol is tiny:
///
///   1. "which keys do you have?"  (SSH2_AGENTC_REQUEST_IDENTITIES)
///   2. "sign this for me"         (SSH2_AGENTC_SIGN_REQUEST)
///
/// The agent runs on the same machine as the client, so the transport is
/// local: a unix domain socket on unix, a named pipe on Windows. **The
/// protocol itself does not care** -- it is a sequence of length-prefixed
/// messages, and that is what this package implements. The transport is
/// injected, so the same code talks to a real agent, to a mock agent over
/// TCP, and to a mock agent in a test.
///
/// ## The framing
///
/// Every message, in both directions, is:
///
///     uint32  length          -- the number of bytes that follow
///     byte    type            -- what the message is
///     ...     payload         -- type-specific
///
/// `length` counts the type byte and the payload, but not itself. This is
/// OpenSSH's `ssh_request_reply` (authfd.c) exactly: it writes the length
/// with `POKE_U32(buf, len)` where `len = sshbuf_len(request)`, and the
/// request already contains the type byte.
///
/// ## The messages we use
///
/// From OpenSSH's `authfd.h`:
///
///     SSH2_AGENTC_REQUEST_IDENTITIES  11
///     SSH2_AGENT_IDENTITIES_ANSWER    12
///     SSH2_AGENTC_SIGN_REQUEST        13
///     SSH2_AGENT_SIGN_RESPONSE        14
///     SSH2_AGENT_FAILURE              30
///
/// The payloads, from `authfd.c`:
///
///   * IDENTITIES_ANSWER: `uint32 count`, then `count` times
///     `string key blob` + `string comment` (`deserialise_identity2`).
///   * SIGN_REQUEST: `string key blob` + `string data` + `uint32 flags`
///     (`ssh_agent_sign`). The flags carry the RSA signature algorithm; for
///     every other key type they are zero.
///   * SIGN_RESPONSE: `string signature` -- the **SSH** signature blob, i.e.
///     the same shape the publickey authentication request carries, so it
///     goes into the request unchanged.
///
/// ## Why the agent is worth a whole loop
///
/// It is the only way to use a private key without the client ever seeing
/// it, and the client here is meant to run in a browser eventually. A
/// browser has no local agent, but the *protocol* is the same, and the
/// protocol is what this package implements.
///
/// It is also the first place in this repository where a **length-prefixed
/// message protocol** is spoken over a transport that is not the SSH
/// transport. The SSH framing in `src/bpacket` assumes a cipher and a MAC;
/// the agent framing has neither, and it is a different shape of code.

///|
/// 客户端请求:列出 agent 持有的身份
pub const AGENTC_REQUEST_IDENTITIES : Byte = b'\x0b'

///|
/// agent 的回答:身份列表
pub const AGENT_IDENTITIES_ANSWER : Byte = b'\x0c'

///|
/// 客户端请求:用某把密钥签一段数据
pub const AGENTC_SIGN_REQUEST : Byte = b'\x0d'

///|
/// agent 的回答:签名
pub const AGENT_SIGN_RESPONSE : Byte = b'\x0e'

///|
/// agent 拒绝了
pub const AGENT_FAILURE : Byte = b'\x1e'

///|
/// agent 照办了
///
/// 协议里有两个「成功」:`SSH_AGENT_SUCCESS`(6)是空的成功,
/// `SSH_AGENT_FAILURE`(30)是拒绝。两个都在 `authfd.h` 里,这里记的是
/// 那个空的。
pub const AGENT_SUCCESS : Byte = b'\x06'

///|
/// 客户端请求:加一把密钥
///
/// 载荷是 `string 公钥 blob` + `string 私钥 blob` + `string 注释`。
pub const AGENTC_ADD_IDENTITY : Byte = b'\x11'

///|
/// 客户端请求:删掉一把密钥
///
/// 载荷是 `string 公钥 blob`。
pub const AGENTC_REMOVE_IDENTITY : Byte = b'\x12'

///|
/// 客户端请求:删掉所有密钥
///
/// 没有载荷。
pub const AGENTC_REMOVE_ALL_IDENTITIES : Byte = b'\x13'

///|
/// 客户端请求:删掉所有 RSA 密钥(协议 v1 的那条)
///
/// 这是 1999 年的那条消息,现代的 agent 不理它。**但客户端还是发它**:
/// OpenSSH 的 `ssh-add -D` 对 v1 和 v2 各发一次,只取 v2 的结果
/// (`ssh-add.c`:"attempt to remove both protocol v.1 and v.2 keys"),
/// 因为 agent 可能是被转发的,而转发过来的可能是老实现。
///
/// agent 回答它「成功」就行:它没有 RSA 密钥可删,而「删掉了零把」
/// 也是删掉了。
pub const AGENTC_REMOVE_ALL_RSA_IDENTITIES : Byte = b'\x09'

///|
/// agent 回复的长度上限。
///
/// OpenSSH 的 `MAX_AGENT_REPLY_LEN`(256 KiB)。上限不是可有可无的:回复长度
/// 是对端给的一个 u32,直接拿它去分配内存的话,一个坏掉的 agent 可以让
/// 客户端一次申请 4 GiB。
pub const MAX_REPLY_LEN : Int32 = 256 * 1024

///|
/// 身份条数的上限。
///
/// OpenSSH 的 `MAX_AGENT_IDENTITIES`(2048)。同样的道理:条数也是对端给的,
/// 一个说「我有 40 亿把钥匙」的 agent 不应该让客户端照着它循环。
pub const MAX_IDENTITIES : Int32 = 2048

///|
/// 从载荷里读一个 u32(大端),和 `ag_read_u32` 一样,只是公开了。
///
/// **对外的 agent 也需要读载荷**:请求的载荷完全由对端控制,而服务端
/// 要从里面读出公钥 blob、数据和 flags。这个函数检查越界,`@sshwire`
/// 的那个不检查——所以服务端用的是这个。
pub fn agent_read_u32(b : FixedArray[Byte], off : Int32) -> Int32? {
  ag_read_u32(b, off)
}

///|
/// 从载荷里读一个 SSH string(带长度前缀),返回 `(内容, 下一个偏移)`。
///
/// 越界返回 None。和 `ag_read_string` 一样,只是公开了。
pub fn agent_read_string(
  b : FixedArray[Byte],
  off : Int32,
) -> (FixedArray[Byte], Int32)? {
  ag_read_string(b, off)
}

///|
/// 把一段字节变成字符串(非 ASCII 字节按 latin-1 折算)。
///
/// agent 的注释是给人看的,而它的字节是什么编码取决于写它的人。
/// 这里按 latin-1 折算,所以每一个字节都有一个字符,注释里的每一个
/// 字符也都会回到同一个字节上——往返是不会改内容的。
pub fn agent_bytes_to_string(b : FixedArray[Byte]) -> String {
  ag_string(b)
}

///|
/// agent 的传输。
///
/// 用**闭包结构体**而不是 trait,理由是 MoonBit 的一个硬限制:foreign trait
/// 不能在别的包里为 foreign type 实现(编译器报 4061)。而 agent 通道要能落在
/// 三种载体上——TCP(本轮的 mock agent)、命名管道(Windows 上的真 agent)、
/// 内存(单元测试)——所以它必须是一个**结构**,由调用方把三个闭包包进来。
///
/// 这样还有一个副作用是好的:`src/agent` 仍然是个叶子包,只依赖
/// `src/sshwire`,而 `src/sshclient` 也不会因为它而把 `src/tcp` 拖回来
/// (Loop #64 拆掉的那条依赖箭头)。
pub(all) struct AgentChannel {
  /// 写出一段字节。false 表示连接没了。
  write : (FixedArray[Byte]) -> Bool
  /// 读满 `n` 个字节。None 表示中途断了(或者对端关了)。
  read_exact : (Int32) -> FixedArray[Byte]?
  /// 关掉。重复调用应当是安全的。
  close : () -> Unit
}

///|
/// agent 持有的一把密钥
pub(all) struct AgentIdentity {
  /// 公钥 blob(SSH 的 `string` 形态,不含长度前缀)
  key_blob : FixedArray[Byte]
  /// 注释(agent 自己给这把钥匙起的名字)
  comment : String
}

///|
/// 拼接两个字节数组
fn ag_cat(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
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
/// 读一个 u32(大端)。
///
/// 越界返回 None 而不是越界读:agent 的载荷是对端给的,长度字段也可能
/// 是乱的,而一个越界的读在这个运行时里是 panic,不是错误。
///
/// 用 UInt 中转而不是 Int32:Int32 左移 24 位会溢出,而这里的值是**对端给的**,
/// 一个 0xFFFFFFFF 必须老老实实读成 4294967295,再由上层的上限检查把它
/// 挡掉,而不是在读的时候就变成一个负数。
///
/// 高位为 1 的值直接判为非法:我们接受的三个长度上限(回复 256 KiB、条数
/// 2048、字符串长度)都远小于 2^31,所以「读不出一个正数」和「读出来一个
/// 超出上限的数」在这里是同一件事——都拒绝。
fn ag_read_u32(b : FixedArray[Byte], off : Int32) -> Int32? {
  if off < 0 || off + 4 > b.length() {
    return None
  }
  let v = (b[off].to_uint() << 24) |
    ((b[off + 1].to_uint() << 16) & 0xFF0000U) |
    ((b[off + 2].to_uint() << 8) & 0xFF00U) |
    (b[off + 3].to_uint() & 0xFFU)
  if v > 0x7FFFFFFFU {
    return None
  }
  Some(v.reinterpret_as_int())
}

///|
/// 读一个 SSH string(带长度前缀),返回 `(内容, 下一个偏移)`。
///
/// 与 `@sshwire.read_ssh_string` 的区别只有一个:这个会检查越界。
/// `@sshwire` 那个不检查,而 agent 的载荷完全由对端控制。
fn ag_read_string(
  b : FixedArray[Byte],
  off : Int32,
) -> (FixedArray[Byte], Int32)? {
  let len = match ag_read_u32(b, off) {
    None => return None
    Some(v) => v
  }
  // 长度本身也要查:它是 u32,加到偏移上会溢出 Int32。这里先比「剩余空间」
  // 而不是「off + 4 + len」,就是为了避开这个溢出。
  if len < 0 || len > b.length() - off - 4 {
    return None
  }
  let l = len
  let out : FixedArray[Byte] = FixedArray::make(l, b'\x00')
  for i = 0; i < l; i = i + 1 {
    out[i] = b[off + 4 + i]
  }
  Some((out, off + 4 + l))
}

///|
/// 把一段文本变成 UTF-8 字节。
///
/// **注释是人写的,而且它不是 ASCII。**  OpenSSH 把命令行上的注释按
/// 它本来的字节存下来,而命令行在这台机器上是 UTF-8;所以这里也用
/// UTF-8,两边才对得上。
///
/// `ag_ascii` 取每个字符的低字节,那个捷径对 ASCII 是对的,对别的
/// 编码是**静悄悄地错**——注释会变成一堆乱码,而协议层不会报错。
fn ag_utf8(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}

///|
/// 字节变成 ASCII 文本(非 ASCII 字节按 latin-1 折算)
fn ag_string(b : FixedArray[Byte]) -> String {
  let out = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    out.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  out.to_string()
}

///|
/// 给一条消息加上帧:`u32 长度` + `类型` + `载荷`。
///
/// 长度算的是**类型字节加上载荷**,不包括长度自己——这是 OpenSSH 的
/// `POKE_U32(buf, len)` 里 `len` 的含义(`len = sshbuf_len(request)`,而
/// request 里已经放进了那个类型字节)。
pub fn agent_frame(
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> FixedArray[Byte] {
  let body = ag_cat(FixedArray::from_array([msg_type]), payload)
  let len = body.length()
  ag_cat(
    FixedArray::from_array([
      ((len >> 24) & 0xFF).to_byte(),
      ((len >> 16) & 0xFF).to_byte(),
      ((len >> 8) & 0xFF).to_byte(),
      (len & 0xFF).to_byte(),
    ]),
    body,
  )
}

///|
/// 读一条帧,返回 `(类型, 载荷)`。
///
/// 这是**服务端**要的那一半:`agent_exchange` 是发一条等一条,而一个
/// agent 要先读一条、回答一条、再读一条。客户端和服务端用同一条
/// 帧格式,所以这里也用同一个 `agent_frame` 的逆运算。
///
/// None 表示连接断了、或者长度不合法。**长度是要先查再分配的**:长度
/// 是对端给的一个 u32,一个说「回复有 4 GiB」的对端不应该让 agent
/// 一次申请 4 GiB。
pub fn agent_read_message(chan : AgentChannel) -> (Byte, FixedArray[Byte])? {
  let head = match (chan.read_exact)(4) {
    None => return None
    Some(h) => h
  }
  let len = match ag_read_u32(head, 0) {
    None => return None
    Some(v) => v
  }
  if len > MAX_REPLY_LEN {
    return None
  }
  if len < 1 {
    return None
  }
  let l = len
  let body = match (chan.read_exact)(l) {
    None => return None
    Some(b) => b
  }
  if body.length() < 1 {
    return None
  }
  Some((body[0], ag_slice(body, 1, body.length())))
}

///|
/// 与 agent 交换一条消息:发出去,等一条回复。
///
/// 返回 `(回复类型, 载荷)`。None 表示连接断了、或者回复的长度不合法。
///
/// 回复类型是 `AGENT_FAILURE` 时**不是**错误:那是一个合法的协议回答,
/// 意思是「这个请求 agent 不接」,由调用方决定那是什么意思。
pub fn agent_exchange(
  chan : AgentChannel,
  msg_type : Byte,
  payload : FixedArray[Byte],
) -> (Byte, FixedArray[Byte])? {
  if !(chan.write)(agent_frame(msg_type, payload)) {
    return None
  }
  let head = match (chan.read_exact)(4) {
    None => return None
    Some(h) => h
  }
  let len = match ag_read_u32(head, 0) {
    None => return None
    Some(v) => v
  }
  // 上限先查,再分配。一个坏掉的 agent 说「回复有 4 GiB」的时候,客户端
  // 不应该照着它去申请内存。
  if len > MAX_REPLY_LEN {
    return None
  }
  if len < 1 {
    return None
  }
  let l = len
  let body = match (chan.read_exact)(l) {
    None => return None
    Some(b) => b
  }
  if body.length() < 1 {
    return None
  }
  Some((body[0], ag_slice(body, 1, body.length())))
}

///|
/// 取一段字节的子区间
fn ag_slice(
  b : FixedArray[Byte],
  start : Int32,
  end : Int32,
) -> FixedArray[Byte] {
  let n = if end > b.length() { b.length() } else { end }
  let s = if start > n { n } else { start }
  let out : FixedArray[Byte] = FixedArray::make(n - s, b'\x00')
  for i = 0; i < n - s; i = i + 1 {
    out[i] = b[s + i]
  }
  out
}

///|
/// 解析 IDENTITIES_ANSWER 的载荷。
///
/// 载荷是 `u32 条数` + 每条 `string 公钥 blob` + `string 注释`。
///
/// 条数上限是 2048(OpenSSH 的 `MAX_AGENT_IDENTITIES`):条数也是对端给的,
/// 一个说「我有 40 亿把钥匙」的 agent 不应该让客户端照着它循环。
pub fn agent_parse_identities(
  payload : FixedArray[Byte],
) -> Array[AgentIdentity]? {
  let num = match ag_read_u32(payload, 0) {
    None => return None
    Some(v) => v
  }
  if num > MAX_IDENTITIES {
    return None
  }
  let n = num
  let out : Array[AgentIdentity] = []
  let mut off = 4
  let mut i = 0
  while i < n {
    let (blob, next) = match ag_read_string(payload, off) {
      None => return None
      Some(v) => v
    }
    let (comment, next2) = match ag_read_string(payload, next) {
      None => return None
      Some(v) => v
    }
    out.push({ key_blob: blob, comment: ag_string(comment), })
    off = next2
    i = i + 1
  }
  Some(out)
}

///|
/// 构造 SIGN_REQUEST 的载荷:`string 公钥 blob` + `string 数据` + `u32 flags`。
///
/// flags 是给 RSA 的签名算法用的(SSH_AGENT_RSA_SHA2_256 之类);对别的密钥
/// 类型它是 0,而 0 也是「没有偏好」的意思,所以不传 flags 也能用。
pub fn agent_sign_payload(
  key_blob : FixedArray[Byte],
  data : FixedArray[Byte],
  flags : Int32,
) -> FixedArray[Byte] {
  ag_cat(
    @sshwire.write_ssh_string(key_blob),
    ag_cat(
      @sshwire.write_ssh_string(data),
      FixedArray::from_array([
        ((flags >> 24) & 0xFF).to_byte(),
        ((flags >> 16) & 0xFF).to_byte(),
        ((flags >> 8) & 0xFF).to_byte(),
        (flags & 0xFF).to_byte(),
      ]),
    ),
  )
}

///|
/// 解析 SIGN_RESPONSE 的载荷:`string 签名`。
///
/// 返回的是**SSH 形态**的签名 blob(算法名 + 签名),也就是 publickey 认证
/// 请求里那个 `string signature` 字段要的东西,原样放进去即可。
pub fn agent_parse_signature(payload : FixedArray[Byte]) -> FixedArray[Byte]? {
  let (sig, _) = match ag_read_string(payload, 0) {
    None => return None
    Some(v) => v
  }
  Some(sig)
}

///|
/// 从公钥 blob 里取算法名。
///
/// 所有标准密钥形态的 blob 都以算法名开头(`ssh-rsa`、`ecdsa-sha2-nistp256`、
/// `ssh-ed25519`……),所以第一个 string 就是它。认证请求里那个
/// `string public key algorithm name` 字段要的就是这个。
pub fn agent_key_type(key_blob : FixedArray[Byte]) -> String? {
  let (name, _) = match ag_read_string(key_blob, 0) {
    None => return None
    Some(v) => v
  }
  Some(ag_string(name))
}

///|
/// 向 agent 要一份身份列表。
pub fn agent_list_identities(chan : AgentChannel) -> Array[AgentIdentity]? {
  let (t, payload) = match
    agent_exchange(
      chan,
      AGENTC_REQUEST_IDENTITIES,
      FixedArray::make(0, b'\x00'),
    ) {
    None => return None
    Some(v) => v
  }
  if t == AGENT_FAILURE {
    return None
  }
  if t != AGENT_IDENTITIES_ANSWER {
    return None
  }
  agent_parse_identities(payload)
}

///|
/// 请 agent 用某把密钥签一段数据。
///
/// 返回的是 SSH 形态的签名 blob。
pub fn agent_sign(
  chan : AgentChannel,
  key_blob : FixedArray[Byte],
  data : FixedArray[Byte],
) -> FixedArray[Byte]? {
  let (t, payload) = match
    agent_exchange(
      chan,
      AGENTC_SIGN_REQUEST,
      agent_sign_payload(key_blob, data, 0),
    ) {
    None => return None
    Some(v) => v
  }
  if t == AGENT_FAILURE {
    return None
  }
  if t != AGENT_SIGN_RESPONSE {
    return None
  }
  agent_parse_signature(payload)
}

///|
/// 请 agent 加一把密钥。
///
/// 载荷是 `string 密钥类型名` + `string 公钥` + `string 私钥` +
/// `string 注释`。
///
/// **这里没有外层的长度前缀,而 `REMOVE_IDENTITY` 有。**  这是量出来
/// 的,不是笔误:
///
///   * `ADD_IDENTITY` 的载荷是 135 字节:`00 00 00 0b "ssh-ed25519"`
///     `00 00 00 20 <32 字节公钥>` `00 00 00 40 <64 字节私钥>`
///     `00 00 00 0c probe@loop89`。
///   * `REMOVE_IDENTITY` 的载荷是 55 字节:`00 00 00 33` 后面跟着那
///     51 字节的公钥 blob。
///
/// 原因在 OpenSSH 的源码里:加钥匙走的是 `sshkey_private_serialize`
/// (它写的是类型名、公钥、私钥三个字段),删钥匙走的是 `sshkey_puts`
/// (它写的是 `sshbuf_put_string(blob)`——**多一层长度前缀**)。
///
/// 所以这里的 `key_blob` 是那 51 字节(`string 类型名` + `string 公钥`),
/// 它**原样**就是前两个字段;而 `private_blob` 是 `string 私钥`。
///
/// 返回 false 是**协议意义上的拒绝**,不是连接断了:agent 说「不接」。
/// 这两件事对调用方是不同的——「不接」是 agent 的回答,「断了」是
/// agent 不在了——所以这个函数把两者分开了:`None` 是断了,
/// `Some(false)` 是被拒绝。
pub fn agent_add_identity(
  chan : AgentChannel,
  key_blob : FixedArray[Byte],
  private_blob : FixedArray[Byte],
  comment : String,
) -> Bool? {
  let payload = ag_cat(
    key_blob,
    ag_cat(private_blob, @sshwire.write_ssh_string(ag_utf8(comment))),
  )
  let (t, _) = match agent_exchange(chan, AGENTC_ADD_IDENTITY, payload) {
    None => return None
    Some(v) => v
  }
  Some(t == AGENT_SUCCESS)
}

///|
/// 请 agent 删掉一把密钥。
///
/// 载荷是 `string 公钥 blob`,没有别的。
pub fn agent_remove_identity(
  chan : AgentChannel,
  key_blob : FixedArray[Byte],
) -> Bool? {
  let (t, _) = match
    agent_exchange(
      chan,
      AGENTC_REMOVE_IDENTITY,
      @sshwire.write_ssh_string(key_blob),
    ) {
    None => return None
    Some(v) => v
  }
  Some(t == AGENT_SUCCESS)
}

///|
/// 请 agent 删掉所有密钥。
///
/// **协议 v1 的那条也要发。**  OpenSSH 的 `ssh-add -D` 对 v1 和 v2 各
/// 发一次,只取 v2 的结果,因为 agent 可能是被转发的,而转发过来的
/// 可能是老实现。这一条发过去,老 agent 才真的把它的 RSA 密钥删掉。
///
/// v1 那条的结果**不看**:它对现代的 agent 一定失败(现代 agent 不理
/// 它),而 OpenSSH 也是忽略它的错误的。
pub fn agent_remove_all_identities(chan : AgentChannel) -> Bool? {
  let (t, _) = match
    agent_exchange(
      chan,
      AGENTC_REMOVE_ALL_IDENTITIES,
      FixedArray::make(0, b'\x00'),
    ) {
    None => return None
    Some(v) => v
  }
  // v1 的那条:发出去,结果不看。
  let _ = agent_exchange(
    chan,
    AGENTC_REMOVE_ALL_RSA_IDENTITIES,
    FixedArray::make(0, b'\x00'),
  )
  Some(t == AGENT_SUCCESS)
}

///|
/// 构造一个 identity 列表的**参考**字节串,给 KAT 用。
///
/// 这不是协议的一部分,而是让两套实现能对同一份样例产生同样的字节:
/// 参考实现(Python)按同样的规则拼,我们的实现也按同样的规则拼,两边
/// 比对的是**同一件事的两种写法**。
pub fn agent_reference_identities_payload(
  entries : Array[AgentIdentity],
) -> FixedArray[Byte] {
  let mut out : FixedArray[Byte] = FixedArray::from_array([
    ((entries.length() >> 24) & 0xFF).to_byte(),
    ((entries.length() >> 16) & 0xFF).to_byte(),
    ((entries.length() >> 8) & 0xFF).to_byte(),
    (entries.length() & 0xFF).to_byte(),
  ])
  for i = 0; i < entries.length(); i = i + 1 {
    out = ag_cat(out, @sshwire.write_ssh_string(entries[i].key_blob))
    out = ag_cat(out, @sshwire.write_ssh_string(ag_utf8(entries[i].comment)))
  }
  out
}
