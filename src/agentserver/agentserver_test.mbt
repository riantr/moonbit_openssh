///|
/// Loop #89: the agent server, tested.
///
/// The vectors here are not hand-made: the **measured** bytes of what
/// the real `ssh-add` sends are the starting point, and the payloads
/// the server builds are checked against the same shapes.
///
/// What the real tool sends (`.loop89/probe_add_proto.py`, a stub
/// agent that prints the bytes):
///
///   * `ADD_IDENTITY`    -- 135 bytes:
///     `00 00 00 0b "ssh-ed25519"` `00 00 00 20 <32 bytes>`
///     `00 00 00 40 <64 bytes>` `00 00 00 0c probe@loop89`
///   * `REMOVE_IDENTITY` -- 55 bytes:
///     `00 00 00 33` followed by the 51-byte public blob
///   * `REQUEST_IDENTITIES` -- no payload
///
/// **The asymmetry between ADD and REMOVE is the point of one of these
/// tests**: ADD has no outer length prefix around the key, REMOVE has
/// one.  A server that reads both the same way gets one of them wrong,
/// and the one it gets wrong is the one that "works" against a mock
/// agent.

///|
/// A fixed seed, so the key is the same on every run and every target.
fn test_seed() -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  let hex = "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9"
  let mut i = 0
  while i < 32 {
    out[i] = hex_byte(hex[2 * i]) * 16 + hex_byte(hex[2 * i + 1])
    i = i + 1
  }
  out
}

///|
/// 一个十六进制数字的值。
fn hex_byte(c : UInt16) -> Byte {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    return (v - 48).to_byte()
  }
  if v >= 97 && v <= 102 {
    return (v - 87).to_byte()
  }
  (v - 65 + 10).to_byte()
}

///|
/// 一把钥匙:公钥 blob、私钥 blob 和注释。
///
/// 私钥 blob 是 `u32 64` + 64 字节,而那 4 个字节**就是**长度前缀——
/// 它是一个 SSH string,不是一个字段。
fn a_key() -> @agentserver.AgentKey {
  let seed = test_seed()
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let blob = private_blob_of(sk)
  @agentserver.AgentKey::{
    key_blob: @keyfile.ed25519_public_blob(pk),
    private_blob: blob,
    comment: "probe@loop89",
  }
}

///|
/// `u32 64` + 64 字节。
fn private_blob_of(sk : FixedArray[Byte]) -> FixedArray[Byte] {
  let blob : FixedArray[Byte] = FixedArray::make(4 + 64, b'\x00')
  blob[3] = 64
  for i = 0; i < 64; i = i + 1 {
    blob[4 + i] = sk[i]
  }
  blob
}

///|
/// 一把**对不上**的钥匙:公钥是 A 的,私钥是 B 的。
///
/// 这是最坏的一种钥匙:客户端拿着公钥 blob 去认领,而 agent 拿着私钥
/// 去签。签名永远验不过,而客户端看到的只是一次神秘的认证失败。
fn a_mismatched_key() -> @agentserver.AgentKey {
  let good = a_key()
  let other_seed : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    other_seed[i] = good.private_blob[4 + i]
  }
  other_seed[0] = (other_seed[0].to_uint() ^ 0x01U).to_byte()
  let (_, sk) = @ed25519.keypair_from_seed(other_seed)
  @agentserver.AgentKey::{
    key_blob: good.key_blob,
    private_blob: private_blob_of(sk),
    comment: "mismatch@loop89",
  }
}

///|
/// `ADD_IDENTITY` 的载荷,按实测的形状拼。
///
/// 注意:**公钥 blob 前面没有再套一层长度前缀**。  那 51 字节本身
/// 就是 `string 类型名` + `string 公钥`,而载荷要的就是这两个字段。
fn add_payload(key : @agentserver.AgentKey) -> FixedArray[Byte] {
  let mut out : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  out = cat(out, key.key_blob)
  out = cat(out, key.private_blob)
  out = cat(out, @sshwire.write_ssh_string(utf8_bytes(key.comment)))
  out
}

///|
/// `REMOVE_IDENTITY` 的载荷,按实测的形状拼。
///
/// **这里有一层长度前缀。**  和 ADD 不一样。
fn remove_payload(key : @agentserver.AgentKey) -> FixedArray[Byte] {
  @sshwire.write_ssh_string(key.key_blob)
}

///|
test "a_key_pair_is_consistent" {
  assert_true(@agentserver.key_is_consistent(a_key()))
  assert_false(@agentserver.key_is_consistent(a_mismatched_key()))
}

///|
test "the_store_adds_finds_and_removes" {
  let store = @agentserver.AgentStore::new()
  assert_eq(store.count(), 0)
  assert_true(store.add(a_key()))
  assert_eq(store.count(), 1)
  assert_true(store.find(a_key().key_blob) is Some(_))
  assert_true(store.remove(a_key().key_blob))
  assert_eq(store.count(), 0)
  assert_false(store.remove(a_key().key_blob))
}

///|
test "the_store_refuses_a_duplicate" {
  let store = @agentserver.AgentStore::new()
  assert_true(store.add(a_key()))
  assert_false(store.add(a_key()))
  assert_eq(store.count(), 1)
}

///|
test "the_store_removes_everything" {
  let store = @agentserver.AgentStore::new()
  assert_true(store.add(a_key()))
  store.remove_all()
  assert_eq(store.count(), 0)
}

///|
test "the_identities_answer_has_two_strings_per_identity" {
  let store = @agentserver.AgentStore::new()
  assert_true(store.add(a_key()))
  let (t, payload) = @agentserver.identities_answer(store)
  assert_eq(t, @agent.AGENT_IDENTITIES_ANSWER)
  // u32 条数
  assert_eq(payload[0], 0)
  assert_eq(payload[1], 0)
  assert_eq(payload[2], 0)
  assert_eq(payload[3], 1)
  // 然后每条身份是**两个** string:公钥 blob 和注释。
  // 只发一个 string 的话,真实的 ssh-add 会说「incomplete message」。
  assert_eq(payload[4], 0)
  assert_eq(payload[5], 0)
  assert_eq(payload[6], 0)
  assert_eq(payload[7], 51)
  // 公钥 blob 的最后一个字段是那 32 字节公钥。
  assert_eq(payload.length(), 4 + 4 + 51 + 4 + 12)
}

///|
test "adding_an_identity_succeeds_and_lands_in_the_store" {
  let store = @agentserver.AgentStore::new()
  let (t, _) = @agentserver.agent_server_handle(
    store,
    @agent.AGENTC_ADD_IDENTITY,
    add_payload(a_key()),
  )
  assert_eq(t, @agent.AGENT_SUCCESS)
  assert_eq(store.count(), 1)
}

///|
test "adding_a_mismatched_key_is_refused" {
  let store = @agentserver.AgentStore::new()
  let (t, _) = @agentserver.agent_server_handle(
    store,
    @agent.AGENTC_ADD_IDENTITY,
    add_payload(a_mismatched_key()),
  )
  assert_eq(t, @agent.AGENT_FAILURE)
  assert_eq(store.count(), 0)
}

///|
test "removing_an_identity_succeeds" {
  let store = @agentserver.AgentStore::new()
  assert_true(store.add(a_key()))
  let (t, _) = @agentserver.agent_server_handle(
    store,
    @agent.AGENTC_REMOVE_IDENTITY,
    remove_payload(a_key()),
  )
  assert_eq(t, @agent.AGENT_SUCCESS)
  assert_eq(store.count(), 0)
}

///|
test "removing_an_identity_the_agent_does_not_have_is_refused" {
  let store = @agentserver.AgentStore::new()
  let (t, _) = @agentserver.agent_server_handle(
    store,
    @agent.AGENTC_REMOVE_IDENTITY,
    remove_payload(a_key()),
  )
  assert_eq(t, @agent.AGENT_FAILURE)
}

///|
test "removing_everything_succeeds_and_empties_the_store" {
  let store = @agentserver.AgentStore::new()
  assert_true(store.add(a_key()))
  let (t, _) = @agentserver.agent_server_handle(
    store,
    @agent.AGENTC_REMOVE_ALL_IDENTITIES,
    FixedArray::make(0, b'\x00'),
  )
  assert_eq(t, @agent.AGENT_SUCCESS)
  assert_eq(store.count(), 0)
}

///|
test "an_unknown_request_is_refused" {
  let store = @agentserver.AgentStore::new()
  let (t, _) = @agentserver.agent_server_handle(
    store,
    b'\x7f',
    FixedArray::make(0, b'\x00'),
  )
  assert_eq(t, @agent.AGENT_FAILURE)
}

///|
test "a_sign_request_is_answered_with_a_signature_that_verifies" {
  let store = @agentserver.AgentStore::new()
  assert_true(store.add(a_key()))
  let data : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  data[0] = 1
  data[1] = 2
  data[2] = 3
  data[3] = 4
  let payload = @agent.agent_sign_payload(a_key().key_blob, data, 0)
  let (t, reply) = @agentserver.agent_server_handle(
    store,
    @agent.AGENTC_SIGN_REQUEST,
    payload,
  )
  assert_eq(t, @agent.AGENT_SIGN_RESPONSE)
  // 回复是 `string 签名`,签名是 `string "ssh-ed25519"` + `string 64 字节`。
  let sig_blob = match @agent.agent_read_string(reply, 0) {
    None => abort("the reply is not a string")
    Some(v) => v.0
  }
  let (name, off) = match @agent.agent_read_string(sig_blob, 0) {
    None => abort("the signature has no algorithm name")
    Some(v) => v
  }
  assert_eq(@agent.agent_bytes_to_string(name), "ssh-ed25519")
  let (sig, _) = match @agent.agent_read_string(sig_blob, off) {
    None => abort("the signature has no bytes")
    Some(v) => v
  }
  assert_eq(sig.length(), 64)
  // 而且这把签名**真的**验得过:公钥 blob 里那 32 字节就是公钥。
  let pk = match @agentserver.ed25519_public_of(a_key().key_blob) {
    None => abort("the key blob has no public key")
    Some(v) => v
  }
  assert_true(@ed25519.verify(sig, data, pk))
}

///|
test "a_sign_request_for_an_unknown_key_is_refused" {
  let store = @agentserver.AgentStore::new()
  let data : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  let payload = @agent.agent_sign_payload(a_key().key_blob, data, 0)
  let (t, _) = @agentserver.agent_server_handle(
    store,
    @agent.AGENTC_SIGN_REQUEST,
    payload,
  )
  assert_eq(t, @agent.AGENT_FAILURE)
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
/// UTF-8 字节。
fn utf8_bytes(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}
