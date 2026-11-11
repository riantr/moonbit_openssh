///|
/// Loop #89: what the agent does with a request.
///
/// Every shape here was MEASURED against the real `ssh-add`: the stub
/// agent in `.loop89/probe_add_proto.py` answered the real tool and
/// printed the bytes it sent.
///
/// **A failure is a legal answer.**  `AGENT_FAILURE` means「这个请求
/// agent 不接」,而客户端决定那是什么意思。agent 说成功却没做,是更坏的
/// 失败:客户端会以为事情成了。

///|
/// 处理一条请求,返回 `(回复类型, 载荷)`。
///
/// 不认识的请求类型一律回 `AGENT_FAILURE`:一个 agent 收到看不懂的
/// 消息时回一句「不接」,比回一句「成功」诚实得多。
pub fn agent_server_handle(
  store : AgentStore,
  req_type : Byte,
  payload : FixedArray[Byte],
) -> (Byte, FixedArray[Byte]) {
  if req_type == @agent.AGENTC_REQUEST_IDENTITIES {
    identities_answer(store)
  } else if req_type == @agent.AGENTC_SIGN_REQUEST {
    sign_response(store, payload)
  } else if req_type == @agent.AGENTC_ADD_IDENTITY {
    add_identity(store, payload)
  } else if req_type == @agent.AGENTC_REMOVE_IDENTITY {
    remove_identity(store, payload)
  } else if req_type == @agent.AGENTC_REMOVE_ALL_IDENTITIES {
    remove_all(store)
  } else if req_type == @agent.AGENTC_REMOVE_ALL_RSA_IDENTITIES {
    // 协议 v1 的那条:这个 agent 没有 RSA 密钥,而「删掉了零把」也是
    // 删掉了。**但 v2 的那条已经删过一遍了**,所以这里回成功不会让
    // 客户端以为还有东西留着。
    remove_all(store)
  } else {
    (@agent.AGENT_FAILURE, FixedArray::make(0, b'\x00'))
  }
}

///|
/// `IDENTITIES_ANSWER`:身份列表。
///
/// 载荷是 `u32 条数` + 每条 `string 公钥 blob` + `string 注释`。
///
/// **一条身份是两个 string。**  第一版只发了一个,真实的 `ssh-add`
/// 回了「incomplete message」——它按两个读,少一个就说这条读不下去。
pub fn identities_answer(store : AgentStore) -> (Byte, FixedArray[Byte]) {
  let keys = store.list()
  let mut body : FixedArray[Byte] = u32_bytes(keys.length())
  for k in keys {
    body = cat(body, @sshwire.write_ssh_string(k.key_blob))
    body = cat(body, @sshwire.write_ssh_string(utf8_bytes(k.comment)))
  }
  (@agent.AGENT_IDENTITIES_ANSWER, body)
}

///|
/// `SIGN_RESPONSE`:用某把密钥签一段数据。
///
/// 载荷是 `string 公钥 blob` + `string 数据` + `u32 flags`。
///
/// **公钥和私钥必须是同一对。**  找不到那把钥匙、或者那把钥匙的私钥
/// 和公钥对不上,都是拒绝:签出来的东西客户端验不过,而客户端只会看到
/// 一次神秘的认证失败。
pub fn sign_response(
  store : AgentStore,
  payload : FixedArray[Byte],
) -> (Byte, FixedArray[Byte]) {
  let (key_blob, off) = match @agent.agent_read_string(payload, 0) {
    None => return failure()
    Some(v) => v
  }
  let (data, _) = match @agent.agent_read_string(payload, off) {
    None => return failure()
    Some(v) => v
  }
  let key = match store.find(key_blob) {
    None => return failure()
    Some(k) => k
  }
  if !key_is_consistent(key) {
    return failure()
  }
  let sk = match ed25519_secret_of(key.private_blob) {
    None => return failure()
    Some(v) => v
  }
  let sig = @ed25519.sign(data, sk)
  // SSH 形态的签名:`string "ssh-ed25519"` + `string 64 字节`。
  let mut blob = @sshwire.write_ssh_string(ascii_bytes("ssh-ed25519"))
  blob = cat(blob, @sshwire.write_ssh_string(sig))
  (@agent.AGENT_SIGN_RESPONSE, @sshwire.write_ssh_string(blob))
}

///|
/// `ADD_IDENTITY`:加一把密钥。
///
/// 载荷是 `string 密钥类型名` + `string 公钥` + `string 私钥` +
/// `string 注释`。
///
/// **这里没有外层的长度前缀,而 `REMOVE_IDENTITY` 有。**  实测:
///
///   * `ADD_IDENTITY` 的载荷是 135 字节:`00 00 00 0b "ssh-ed25519"`
///     `00 00 00 20 <32 字节公钥>` `00 00 00 40 <64 字节私钥>`
///     `00 00 00 0c probe@loop89`。
///   * `REMOVE_IDENTITY` 的载荷是 55 字节:`00 00 00 33` 后面跟着那
///     51 字节的公钥 blob。
///
/// 原因在 OpenSSH 的源码里:加钥匙走 `sshkey_private_serialize`(类型名、
/// 公钥、私钥三个字段),删钥匙走 `sshkey_puts`(`sshbuf_put_string(blob)`,
/// **多一层长度前缀**)。
///
/// **加一把对不上的钥匙是拒绝。**  见 `key_is_consistent`。
pub fn add_identity(
  store : AgentStore,
  payload : FixedArray[Byte],
) -> (Byte, FixedArray[Byte]) {
  let (type_name, off) = match @agent.agent_read_string(payload, 0) {
    None => return failure()
    Some(v) => v
  }
  let (pk, off2) = match @agent.agent_read_string(payload, off) {
    None => return failure()
    Some(v) => v
  }
  let (sk, off3) = match @agent.agent_read_string(payload, off2) {
    None => return failure()
    Some(v) => v
  }
  let (comment, _) = match @agent.agent_read_string(payload, off3) {
    None => return failure()
    Some(v) => v
  }
  // 公钥 blob 是 `string 类型名` + `string 公钥`——正好是载荷的头两个
  // 字段,所以它是从那两个字段拼回来的,而不是从载荷里读出来的。
  let key_blob = cat(
    @sshwire.write_ssh_string(type_name),
    @sshwire.write_ssh_string(pk),
  )
  let key = AgentKey::{
    key_blob,
    private_blob: @sshwire.write_ssh_string(sk),
    comment: @agent.agent_bytes_to_string(comment),
  }
  if !key_is_consistent(key) {
    // 这句话是给**看 agent 的人**的:客户端只会看到一句「agent refused
    // operation」,而这一句说的是拒绝的真正理由。
    eprintln(
      "ssh_agent: the key's public half and its private half do not match",
    )
    return failure()
  }
  if !store.add(key) {
    // 已经在里面了。这也是一种「不接」:客户端会说「这个钥匙已经在
    // agent 里了」。
    eprintln("ssh_agent: the key is already in the agent")
    return failure()
  }
  (@agent.AGENT_SUCCESS, FixedArray::make(0, b'\x00'))
}

///|
/// `REMOVE_IDENTITY`:删掉一把密钥。
///
/// 载荷是 `string 公钥 blob`。**删掉一把没有的钥匙是拒绝**,而
/// 客户端会把这句拒绝翻译成「agent 里没有这把钥匙」。
pub fn remove_identity(
  store : AgentStore,
  payload : FixedArray[Byte],
) -> (Byte, FixedArray[Byte]) {
  let (key_blob, _) = match @agent.agent_read_string(payload, 0) {
    None => return failure()
    Some(v) => v
  }
  if !store.remove(key_blob) {
    return failure()
  }
  (@agent.AGENT_SUCCESS, FixedArray::make(0, b'\x00'))
}

///|
/// `REMOVE_ALL_IDENTITIES`:删掉所有密钥。
///
/// 没有载荷。这条**总是成功**:agent 手上有几把钥匙是几把,删完就是零把。
pub fn remove_all(store : AgentStore) -> (Byte, FixedArray[Byte]) {
  store.remove_all()
  (@agent.AGENT_SUCCESS, FixedArray::make(0, b'\x00'))
}

///|
/// 「不接」。
fn failure() -> (Byte, FixedArray[Byte]) {
  (@agent.AGENT_FAILURE, FixedArray::make(0, b'\x00'))
}

///|
/// 一个 u32 的大端字节。
fn u32_bytes(v : Int32) -> FixedArray[Byte] {
  FixedArray::from_array([
    ((v >> 24) & 0xFF).to_byte(),
    ((v >> 16) & 0xFF).to_byte(),
    ((v >> 8) & 0xFF).to_byte(),
    (v & 0xFF).to_byte(),
  ])
}

///|
/// 拼两个字节数组。
fn cat(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
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
/// ASCII 文本的字节。
fn ascii_bytes(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  out
}

///|
/// UTF-8 字节。
///
/// 注释是人写的,可能不是 ASCII,而 agent 的注释字节是什么编码取决于
/// 写它的人。这里用 UTF-8,和 OpenSSH 的命令行编码一致。
fn utf8_bytes(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}
