///|
/// Loop #89: the client half of the agent protocol, tested.
///
/// The protocol is **measured, not remembered**: every message type and
/// every payload shape came from running the real `ssh-add` against a
/// stub agent and reading the bytes it sent (`.loop89/probe_add_proto.py`).
///
/// **The asymmetry is the point of most of this file.**  `ADD_IDENTITY`
/// carries the key field by field and has NO outer length prefix;
/// `REMOVE_IDENTITY` carries the blob in ONE string and DOES have one.
/// A client that gets one of them wrong works against a mock agent and
/// fails against a real one -- which is the worst place to find out.
///
/// The channel here is **in memory**: a pair of closures over a buffer.
/// That is the whole reason `AgentChannel` is a struct of closures and
/// not a trait -- the same protocol code has to run over a named pipe, a
/// socket and a buffer.
///
/// These tests run on every target: the protocol is the protocol.

///|
/// 一条被记下来的请求。
///
/// `sent` 是客户端写出去的那些帧。
struct Recorder {
  sent : Array[FixedArray[Byte]]
}

///|
/// 一个在内存里的 agent 通道,它一律回答「成功」。
///
/// 客户端写出去的每一个帧都记下来;服务端回答的是 `u32 1` + 类型字节
/// 6(`AGENT_SUCCESS`)。**读的那一半是从这个回答里取的**,所以这个
/// 通道既是客户端的记录器也是服务端的回答器。
fn recording_channel(rec : Recorder) -> @agent.AgentChannel {
  let mut reply : FixedArray[Byte] = FixedArray::from_array([
    0,
    0,
    0,
    1,
    @agent.AGENT_SUCCESS,
  ])
  let mut pos = 0
  {
    write: fn(d) {
      let out : FixedArray[Byte] = FixedArray::make(d.length(), b'\x00')
      for i = 0; i < d.length(); i = i + 1 {
        out[i] = d[i]
      }
      rec.sent.push(out)
      reply = FixedArray::from_array([0, 0, 0, 1, @agent.AGENT_SUCCESS])
      pos = 0
      true
    },
    read_exact: fn(n) {
      if n <= 0 {
        return Some(FixedArray::make(0, b'\x00'))
      }
      if pos + n > reply.length() {
        return None
      }
      let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
      for i = 0; i < n; i = i + 1 {
        out[i] = reply[pos + i]
      }
      pos = pos + n
      Some(out)
    },
    close: fn() {  },
  }
}

///|
/// 一个只回「拒绝」的通道。
///
/// agent 回 `AGENT_FAILURE` 是一个**合法的回答**,不是连接断了。
fn refusing_channel(rec : Recorder) -> @agent.AgentChannel {
  let mut reply : FixedArray[Byte] = FixedArray::from_array([
    0,
    0,
    0,
    1,
    @agent.AGENT_FAILURE,
  ])
  let mut pos = 0
  {
    write: fn(d) {
      let out : FixedArray[Byte] = FixedArray::make(d.length(), b'\x00')
      for i = 0; i < d.length(); i = i + 1 {
        out[i] = d[i]
      }
      rec.sent.push(out)
      reply = FixedArray::from_array([0, 0, 0, 1, @agent.AGENT_FAILURE])
      pos = 0
      true
    },
    read_exact: fn(n) {
      if n <= 0 {
        return Some(FixedArray::make(0, b'\x00'))
      }
      if pos + n > reply.length() {
        return None
      }
      let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
      for i = 0; i < n; i = i + 1 {
        out[i] = reply[pos + i]
      }
      pos = pos + n
      Some(out)
    },
    close: fn() {  },
  }
}

///|
/// 一个什么也不回答的通道:连接断了。
///
/// 这和「agent 说不接」是不同的两件事,而客户端必须分得清。
fn dead_channel() -> @agent.AgentChannel {
  { write: fn(_d) { false }, read_exact: fn(_n) { None }, close: fn() {  }, }
}

///|
/// 一个公钥 blob:`string "ssh-ed25519"` + `string 32 字节`。
///
/// 51 字节,和真实工具发的一模一样。
fn a_key_blob() -> FixedArray[Byte] {
  let blob : FixedArray[Byte] = FixedArray::make(51, b'\x00')
  let name = "ssh-ed25519"
  blob[3] = 11
  for i = 0; i < 11; i = i + 1 {
    blob[4 + i] = name[i].to_int().to_byte()
  }
  blob[15] = 0
  blob[16] = 0
  blob[17] = 0
  blob[18] = 32
  for i = 0; i < 32; i = i + 1 {
    blob[19 + i] = (i + 1).to_byte()
  }
  blob
}

///|
/// 帧里的长度是**类型字节加上载荷**,不包括长度自己。
///
/// 这是 OpenSSH 的 `POKE_U32(buf, len)`,而 `len = sshbuf_len(request)`,
/// 那个 request 里已经放进了类型字节。
test "the frame length counts the type byte and the payload" {
  let frame = @agent.agent_frame(
    @agent.AGENTC_REQUEST_IDENTITIES,
    FixedArray::make(0, b'\x00'),
  )
  // u32 长度 + 类型字节 + 空载荷。
  assert_eq(frame.length(), 5)
  assert_eq(frame[0], 0)
  assert_eq(frame[1], 0)
  assert_eq(frame[2], 0)
  assert_eq(frame[3], 1)
  assert_eq(frame[4], @agent.AGENTC_REQUEST_IDENTITIES)
}

///|
/// `ADD_IDENTITY` 的载荷**没有外层的长度前缀**。
///
/// 135 字节:`00 00 00 0b "ssh-ed25519"` `00 00 00 20 <32 字节公钥>`
/// `00 00 00 40 <64 字节私钥>` `00 00 00 0c probe@loop89`。
///
/// 这四个字段正好就是那 51 字节公钥 blob 的前两个字段、那 68 字节私钥
/// blob、和注释——**没有一个是再套一层的**。
test "the ADD_IDENTITY payload has no outer length prefix" {
  let rec = Recorder::{ sent: [], }
  let chan = recording_channel(rec)
  let key_blob = a_key_blob()
  // 私钥 blob:`u32 64` + 64 字节。
  let private_blob : FixedArray[Byte] = FixedArray::make(68, b'\x00')
  private_blob[3] = 64
  let ok = @agent.agent_add_identity(
    chan, key_blob, private_blob, "probe@loop89",
  )
  assert_eq(ok, Some(true))
  assert_eq(rec.sent.length(), 1)
  let frame = rec.sent[0]
  // 帧 = u32 长度 + 类型 + 载荷。载荷 = 51 + 68 + 16 = 135。
  assert_eq(frame.length(), 4 + 1 + 135)
  assert_eq(frame[4], @agent.AGENTC_ADD_IDENTITY)
  let payload = slice(frame, 5, frame.length())
  assert_eq(payload.length(), 135)
  // 前 51 字节**就是**公钥 blob 本身,没有再套一层。
  for i = 0; i < 51; i = i + 1 {
    assert_eq(payload[i], key_blob[i])
  }
  // 接下来是私钥 blob(`u32 64` + 64 字节),也**没有**再套一层。
  assert_eq(payload[51], 0)
  assert_eq(payload[52], 0)
  assert_eq(payload[53], 0)
  assert_eq(payload[54], 64)
  // 然后是注释:`u32 12` + 12 字节。
  assert_eq(payload[119], 0)
  assert_eq(payload[120], 0)
  assert_eq(payload[121], 0)
  assert_eq(payload[122], 12)
}

///|
/// `REMOVE_IDENTITY` 的载荷**有一层长度前缀**。
///
/// 55 字节:`00 00 00 33` 后面跟着那 51 字节的公钥 blob。
///
/// **和 ADD 不一样,这就是那个不对称。**
test "the REMOVE_IDENTITY payload has a length prefix" {
  let rec = Recorder::{ sent: [], }
  let chan = recording_channel(rec)
  let ok = @agent.agent_remove_identity(chan, a_key_blob())
  assert_eq(ok, Some(true))
  assert_eq(rec.sent.length(), 1)
  let frame = rec.sent[0]
  // 帧 = u32 长度 + 类型 + 载荷。载荷 = 4 + 51 = 55。
  assert_eq(frame.length(), 4 + 1 + 55)
  assert_eq(frame[4], @agent.AGENTC_REMOVE_IDENTITY)
  let payload = slice(frame, 5, frame.length())
  assert_eq(payload.length(), 55)
  // 那四个字节就是长度前缀:0x33 = 51。
  assert_eq(payload[0], 0)
  assert_eq(payload[1], 0)
  assert_eq(payload[2], 0)
  assert_eq(payload[3], 51)
  // 后面是那 51 字节的 blob 本身。
  let key_blob = a_key_blob()
  for i = 0; i < 51; i = i + 1 {
    assert_eq(payload[4 + i], key_blob[i])
  }
}

///|
/// `REMOVE_ALL_IDENTITIES` 发两条:v2 的那条(19),和 v1 的那条(9)。
///
/// v1 那条的结果**不看**——现代的 agent 不理它,而 OpenSSH 也是忽略
/// 它的错误的。老 agent 才靠它删掉自己的 RSA 密钥。
test "remove-all sends the v2 message and then the v1 one" {
  let rec = Recorder::{ sent: [], }
  let chan = recording_channel(rec)
  let ok = @agent.agent_remove_all_identities(chan)
  assert_eq(ok, Some(true))
  assert_eq(rec.sent.length(), 2)
  assert_eq(rec.sent[0][4], @agent.AGENTC_REMOVE_ALL_IDENTITIES)
  assert_eq(rec.sent[0].length(), 5)
  assert_eq(rec.sent[1][4], @agent.AGENTC_REMOVE_ALL_RSA_IDENTITIES)
  assert_eq(rec.sent[1].length(), 5)
}

///|
/// 「断了」和「agent 说不接」是两件事。
///
/// agent 回 `AGENT_FAILURE` 是一个**合法的回答**,客户端把它翻译成
/// 「agent refused operation」;而连接断了是 agent 不在了,客户端说
/// 「Error connecting to agent」。把它们混成一个,客户端就会在 agent
/// 根本不在的时候说 agent 拒绝了它。
test "a refusal is not a broken connection" {
  let rec = Recorder::{ sent: [], }
  let refused = @agent.agent_add_identity(
    refusing_channel(rec),
    a_key_blob(),
    FixedArray::make(68, b'\x00'),
    "x",
  )
  assert_eq(refused, Some(false))
  // 断了:None。
  let dead = @agent.agent_add_identity(
    dead_channel(),
    a_key_blob(),
    FixedArray::make(68, b'\x00'),
    "x",
  )
  assert_eq(dead, None)
}

///|
/// 一条身份是**两个** string:公钥 blob 和注释。
///
/// 只发一个的话,真实的 `ssh-add` 会说「incomplete message」。
test "an identity is two strings" {
  // u32 条数 = 1,
  // 然后 `string 公钥 blob`(4 + 51),
  // 然后 `string 注释`(4 + 12)。
  let payload : FixedArray[Byte] = FixedArray::make(4 + 55 + 16, b'\x00')
  payload[3] = 1
  // 公钥 blob 的长度前缀。
  payload[7] = 51
  let key_blob = a_key_blob()
  for i = 0; i < 51; i = i + 1 {
    payload[8 + i] = key_blob[i]
  }
  // 注释的长度前缀。
  payload[59] = 0
  payload[60] = 0
  payload[61] = 0
  payload[62] = 12
  // 注释本身。
  let comment = "probe@loop89"
  for i = 0; i < 12; i = i + 1 {
    payload[63 + i] = comment[i].to_int().to_byte()
  }
  let ids = match @agent.agent_parse_identities(payload) {
    None => abort("the payload did not parse")
    Some(v) => v
  }
  assert_eq(ids.length(), 1)
  assert_eq(ids[0].key_blob.length(), 51)
  for i = 0; i < 51; i = i + 1 {
    assert_eq(ids[0].key_blob[i], key_blob[i])
  }
  assert_eq(ids[0].comment, "probe@loop89")
}

///|
/// 少一个 string 就读不下去。
test "an identity with one string does not parse" {
  // u32 条数 = 1,然后**只有**公钥 blob。
  let payload : FixedArray[Byte] = FixedArray::make(4 + 55, b'\x00')
  payload[3] = 1
  payload[7] = 51
  let key_blob = a_key_blob()
  for i = 0; i < 51; i = i + 1 {
    payload[8 + i] = key_blob[i]
  }
  assert_true(@agent.agent_parse_identities(payload) is None)
}

///|
/// 读一个越界的 string 不会 panic。
///
/// agent 的载荷完全由对端控制,而长度字段也可能说是乱的。**一个越界的
/// 读在这个运行时里是 panic,不是错误**——所以这里必须返回 None。
test "a string that runs off the end is refused" {
  let payload : FixedArray[Byte] = FixedArray::from_array([0, 0, 0, 40, 1, 2])
  assert_true(@agent.agent_read_string(payload, 0) is None)
}

///|
/// 字符串的长度是 u32,而且带符号的那一半要挡掉。
///
/// 一个说「这里有 4 GiB」的对端不应该让客户端照着它去申请内存。
test "an absurd length is refused" {
  let payload : FixedArray[Byte] = FixedArray::from_array([
    0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3, 4,
  ])
  assert_true(@agent.agent_read_string(payload, 0) is None)
}

///|
/// 取一段字节的子区间。
fn slice(b : FixedArray[Byte], start : Int32, end : Int32) -> FixedArray[Byte] {
  let n = if end > b.length() { b.length() } else { end }
  let s = if start > n { n } else { start }
  let out : FixedArray[Byte] = FixedArray::make(n - s, b'\x00')
  for i = 0; i < n - s; i = i + 1 {
    out[i] = b[s + i]
  }
  out
}
