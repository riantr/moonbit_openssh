///|
/// Loop #89: the agent server -- the keys it holds and the answers it
/// gives.
///
/// The rules are here; the driver (`cmd/ssh_agent`) owns the pipe and
/// the loop over connections.

///|
/// agent 持有的一把密钥。
///
/// 三样东西:公钥 blob(客户端拿它去认领这把钥匙)、私钥 blob(agent 拿它
/// 去签名)、注释(人看的名字)。
///
/// **私钥 blob 里是私钥,这是这个结构存在的全部理由。**  所以它永远
/// 不该被打印出来,也不该进任何一份报告。
pub(all) struct AgentKey {
  /// 公钥 blob(SSH 的 `string` 形态,不含长度前缀)
  key_blob : FixedArray[Byte]
  /// 私钥 blob(ed25519 是 `u32 64` + 64 字节)
  private_blob : FixedArray[Byte]
  /// 注释
  comment : String
}

///|
/// agent 持有的密钥。
///
/// 密钥放在内存里,agent 退出就没了。这和 OpenSSH 的 agent 一样
/// (它的密钥在 `SOFTWARE\OpenSSH\Agent\Keys` 这个注册表键下面,
/// 但那也是**这个用户的机器**,不是一张可以随身带的卡)。
pub(all) struct AgentStore {
  mut keys : Array[AgentKey]
}

///|
/// 一个空的 agent。
pub fn AgentStore::new() -> AgentStore {
  { keys: [], }
}

///|
/// 加一把密钥。
///
/// 返回 false 是有意义的:一把**已经在**里的钥匙不算加成功。
/// OpenSSH 的 agent 不接受重复(它的 `process_add_identity` 会在
/// 同一把钥匙已经在里面时拒绝),而客户端会把「拒绝」翻译成
/// 「这个钥匙已经在 agent 里了」。
///
/// 这条规则不写在客户端里,因为**服务端才是知道真相的那一边**。
pub fn AgentStore::add(self : AgentStore, key : AgentKey) -> Bool {
  if self.find(key.key_blob) is Some(_) {
    return false
  }
  self.keys.push(key)
  true
}

///|
/// 按公钥 blob 找一把钥匙。
pub fn AgentStore::find(
  self : AgentStore,
  key_blob : FixedArray[Byte],
) -> AgentKey? {
  for k in self.keys {
    if bytes_equal(k.key_blob, key_blob) {
      return Some(k)
    }
  }
  None
}

///|
/// 删掉一把密钥。删掉了返回 true,本来就没有返回 false。
pub fn AgentStore::remove(
  self : AgentStore,
  key_blob : FixedArray[Byte],
) -> Bool {
  let mut i = 0
  while i < self.keys.length() {
    if bytes_equal(self.keys[i].key_blob, key_blob) {
      let _ = self.keys.remove(i)
      return true
    }
    i = i + 1
  }
  false
}

///|
/// 删掉所有密钥。
pub fn AgentStore::remove_all(self : AgentStore) -> Unit {
  self.keys.clear()
}

///|
/// 现在有几把钥匙。
pub fn AgentStore::count(self : AgentStore) -> Int32 {
  self.keys.length()
}

///|
/// 全部钥匙,按加进去的顺序。
pub fn AgentStore::list(self : AgentStore) -> Array[AgentKey] {
  self.keys
}

///|
/// 两个字节数组一样吗。
fn bytes_equal(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

///|
/// 从公钥 blob 里取出 ed25519 的那 32 字节公钥。
///
/// **这条规则住在 `src/keyfile`**,因为它讲的是密钥文件的形状;这里
/// 只是转过去用,免得两处各拆一遍、拆得不一样。
pub fn ed25519_public_of(key_blob : FixedArray[Byte]) -> FixedArray[Byte]? {
  @keyfile.ed25519_public_of_blob(key_blob)
}

///|
/// 从私钥 blob 里取出 ed25519 的那 64 字节密钥。
///
/// 私钥 blob 的形状是 `u32 64` + 64 字节 = `seed || 公钥`。
/// **那 4 个字节就是长度前缀,不是另一个字段。**  所以它是**一个**
/// SSH string,从偏移 0 读;再从偏移 4 读一次长度,读到的是密钥的
/// 前 4 个字节——那不是一个长度,而是一段密钥。
///
/// 这和 `.pub` 文件里那 32 字节公钥对得上:`keypair_from_seed`
/// 造出来的 sk 就是 `seed || pk`。
pub fn ed25519_secret_of(private_blob : FixedArray[Byte]) -> FixedArray[Byte]? {
  let (sk, _) = match @agent.agent_read_string(private_blob, 0) {
    None => return None
    Some(v) => v
  }
  if sk.length() != 64 {
    return None
  }
  Some(sk)
}

///|
/// 一把密钥自洽吗:私钥 blob 里那 32 字节公钥,和公钥 blob 里那
/// 32 字节是不是同一对。
///
/// **这个检查是签名的前提。**  agent 拿着私钥 blob 里的 seed 去签,
/// 而客户端拿公钥 blob 去验。两者不是同一对的时候,签名永远验不过,
/// 而客户端看到的只是一次神秘的认证失败。**在签名之前发现它**,
/// 比在客户端那边发现它便宜得多,也清楚得多。
///
/// 公钥 blob 和私钥 blob 不是同一对的时候,加进去是拒绝。
pub fn key_is_consistent(key : AgentKey) -> Bool {
  let pk = match ed25519_public_of(key.key_blob) {
    None => return false
    Some(v) => v
  }
  let sk = match ed25519_secret_of(key.private_blob) {
    None => return false
    Some(v) => v
  }
  bytes_equal_from(sk, 32, pk, 0, 32)
}

///|
/// 两段字节的子区间一样吗。
fn bytes_equal_from(
  a : FixedArray[Byte],
  a_off : Int32,
  b : FixedArray[Byte],
  b_off : Int32,
  n : Int32,
) -> Bool {
  if a_off < 0 || b_off < 0 || n < 0 {
    return false
  }
  if a_off + n > a.length() || b_off + n > b.length() {
    return false
  }
  for i = 0; i < n; i = i + 1 {
    if a[a_off + i] != b[b_off + i] {
      return false
    }
  }
  true
}
