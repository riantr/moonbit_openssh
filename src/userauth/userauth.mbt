///| RFC 4252 §7 publickey 认证请求构造(Loop #34)
///
/// Loop #33 把通道加密打通了,但停在 SERVICE_ACCEPT:那之后还没向任何人证明
/// 「我是我」。publickey 是 SSH 里唯一一个**不需要向服务器交付任何秘密**的
/// 认证方式——客户端只持有私钥,签名不外发。对浏览器零依赖的目标来说这是
/// 唯一合理的认证方式:密码认证会把口令处理(存储、清洗、比较)拖进客户端,
/// 而这里一行都不用写。
///
/// 签名的输入(RFC 4252 §7)是一段很具体的字节序列,写错一个字段服务端就会
/// 回 "userauth request ... invalid signature",而且**不会**告诉你错在哪:
///
///     string    session identifier        ← 首次 KEX 的 H,不是会话密钥
///     byte      SSH_MSG_USERAUTH_REQUEST
///     string    user name
///     string    service name ("ssh-connection")
///     string    "publickey"
///     boolean   TRUE
///     string    public key algorithm name
///     string    public key blob
///
/// 两个容易错的地方:
///
///   * **service name 是 `ssh-connection`,不是 `ssh-userauth`**。前者是
///     USERAUTH_REQUEST 里那个字段的固定值,后者是上一条 SERVICE_REQUEST
///     用的名字。两个字符串长得像,含义不同,搞混了服务端会当成未知的
///     service 而拒绝。
///
///   * **签名的输入不含 signature 字段本身**。签名不可能是自己的输入的一部分,
///     所以实际流程是「先把请求拼到签名之前 → 签 → 再把签名追加到末尾」。
///     RFC 4252 §7 的 boolean TRUE 就是在声明「后面跟着签名」。

///|
/// publickey 方法名
pub const AUTH_METHOD_PUBLICKEY : String = "publickey"

///|
/// USERAUTH_REQUEST 里的 service name(RFC 4252 §5)
pub const AUTH_SERVICE_CONNECTION : String = "ssh-connection"

///|
/// SSH boolean TRUE 的 wire 形式(RFC 4251 §5)
pub const SSH_BOOL_TRUE : Byte = b'\x01'

///|
/// SSH boolean FALSE 的 wire 形式(RFC 4251 §5)
pub const SSH_BOOL_FALSE : Byte = b'\x00'

///|
/// ASCII text to bytes.
///
/// 见 `moon.pkg` 的说明:这是为了不把 `src/sshclient`(以及它带来的
/// `src/tcp`)拖进来,才在这里重写一份。
fn ua_ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///|
/// 拼接两个字节数组。
fn ua_concat(a : FixedArray[Byte], b : FixedArray[Byte]) -> FixedArray[Byte] {
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
/// 拼接待签名的字节(RFC 4252 §7)
///
/// `session_id` 是首次密钥交换的 H。**不是**会话密钥 K,也不是 exchange hash
/// 之外的任何东西——传错的话签名照样是"合法"的 ECDSA 签名,只是验不过。
pub fn userauth_signed_blob(
  session_id : FixedArray[Byte],
  user : String,
  service : String,
  key_type : String,
  pubkey_blob : FixedArray[Byte],
) -> FixedArray[Byte] {
  ua_concat(
    @sshwire.write_ssh_string(session_id),
    ua_concat(
      FixedArray::from_array([@sshwire.SSH_MSG_USERAUTH_REQUEST]),
      ua_concat(
        @sshwire.write_ssh_string(ua_ascii(user)),
        ua_concat(
          @sshwire.write_ssh_string(ua_ascii(service)),
          ua_concat(
            @sshwire.write_ssh_string(ua_ascii(AUTH_METHOD_PUBLICKEY)),
            ua_concat(
              FixedArray::from_array([SSH_BOOL_TRUE]),
              ua_concat(
                @sshwire.write_ssh_string(ua_ascii(key_type)),
                @sshwire.write_ssh_string(pubkey_blob),
              ),
            ),
          ),
        ),
      ),
    ),
  )
}

///|
/// 构造 publickey 的**探针**请求(载荷里 boolean 是 FALSE,没有签名字段)
///
/// RFC 4252 §7 允许客户端先发一个「我打算用这把钥匙」的探针:服务端接受这
/// 把公钥就回 `SSH_MSG_USERAUTH_PK_OK`(60),不接受就回 FAILURE。
///
/// 探针的意义有两个:
///
///   * **别为一把服务端根本不认的钥匙去惊动 agent**。真 agent 可能要求用户
///     确认(摸一下指纹),为一个注定被拒的公钥去弹一次确认框是纯粹的骚扰。
///   * **区分「钥匙不对」和「签名不对」**。在服务端看来这两种失败都是同一句
///     FAILURE,只有先探一次才能知道该去找 authorized_keys 还是该去查签名。
///
/// 探针请求和带签名的请求只差两处:boolean 从 TRUE 变成 FALSE,末尾不再接
/// `string signature`。
pub fn userauth_publickey_probe_request(
  user : String,
  service : String,
  key_type : String,
  pubkey_blob : FixedArray[Byte],
) -> FixedArray[Byte] {
  ua_concat(
    @sshwire.write_ssh_string(ua_ascii(user)),
    ua_concat(
      @sshwire.write_ssh_string(ua_ascii(service)),
      ua_concat(
        @sshwire.write_ssh_string(ua_ascii(AUTH_METHOD_PUBLICKEY)),
        ua_concat(
          FixedArray::from_array([SSH_BOOL_FALSE]),
          ua_concat(
            @sshwire.write_ssh_string(ua_ascii(key_type)),
            @sshwire.write_ssh_string(pubkey_blob),
          ),
        ),
      ),
    ),
  )
}

///|
/// 拼接完整的 USERAUTH_REQUEST 载荷(带签名)
///
/// 这就是待签名字节再接上 `string signature`——两者只差最后一段,顺序不能换。
pub fn userauth_publickey_request(
  user : String,
  service : String,
  key_type : String,
  pubkey_blob : FixedArray[Byte],
  sig_blob : FixedArray[Byte],
) -> FixedArray[Byte] {
  ua_concat(
    @sshwire.write_ssh_string(ua_ascii(user)),
    ua_concat(
      @sshwire.write_ssh_string(ua_ascii(service)),
      ua_concat(
        @sshwire.write_ssh_string(ua_ascii(AUTH_METHOD_PUBLICKEY)),
        ua_concat(
          FixedArray::from_array([SSH_BOOL_TRUE]),
          ua_concat(
            @sshwire.write_ssh_string(ua_ascii(key_type)),
            ua_concat(
              @sshwire.write_ssh_string(pubkey_blob),
              @sshwire.write_ssh_string(sig_blob),
            ),
          ),
        ),
      ),
    ),
  )
}

///|
/// 用私钥对 publickey 请求签名,一步得到 `(公钥 blob, 签名 blob, 请求载荷)`
///
/// 返回 None 表示私钥越界或 RFC 6979 的 k 退化——两者都是硬失败,不该换一把
/// 私钥重试。
///
/// 签名 blob 单独返回是因为认证失败在服务端只有一种表现(FAILURE),本地
/// 必须能把它和签名输入一起拿出来给第二实现复核,否则就只能靠猜。
pub fn userauth_publickey_signed_request(
  curve : @ecdsa.Curve,
  d : @bigint.BigNat,
  session_id : FixedArray[Byte],
  user : String,
  service : String,
) -> (FixedArray[Byte], FixedArray[Byte], FixedArray[Byte])? {
  // blob 与签名编码都复用 Loop #30 已有的实现,不另写一份:
  // 客户端签名用的 blob 和服务端读到的 blob 必须逐字节相同,两份实现
  // 只要有一份漂移就会变成一个笼统的 "invalid signature"。
  let q = match curve.public_key(d) {
    None => return None
    Some(p) => p
  }
  let blob = match @ecdsa.encode_pubkey_blob(curve, q) {
    None => return None
    Some(b) => b
  }
  let key_type = curve.ssh_key_type()
  let to_sign = userauth_signed_blob(session_id, user, service, key_type, blob)
  let sig = match @ecdsa.ecdsa_sign(curve, d, to_sign) {
    None => return None
    Some(s) => s
  }
  let sig_blob = @ecdsa.encode_sig_blob(curve, sig)
  Some(
    (
      blob,
      sig_blob,
      userauth_publickey_request(user, service, key_type, blob, sig_blob),
    ),
  )
}
