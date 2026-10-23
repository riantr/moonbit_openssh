///| Loop #82: ssh-keyscan —— 只做 KEX,拿到主机密钥,不认证。
///

///|
/// 一次扫描的结果
pub(all) struct KeyscanReport {
  /// 服务端的版本串(`SSH-2.0-...`)。
  ///
  /// OpenSSH 的 ssh-keyscan 把它印在 stderr 的注释行里(`# host:port SSH-2.0-...`),
  /// 所以它是这个工具**输出的一部分**,不只是调试信息。
  server_ident : String
  /// 协商出的主机密钥算法名(比如 `rsa-sha2-512`)。
  ///
  /// 这是**协商名**,不是 known_hosts 行里写的那个名字——见 `hostkey_type`。
  hostkey_alg : String
  /// 密钥 blob 里的类型名(比如 `ssh-rsa`)。
  ///
  /// known_hosts 行写的是**这个**:OpenSSH 写 known_hosts 用的是密钥自己的类型名
  /// (`sshkey_write`),不是协商出来的名字。RFC 8332 之下这两者本来就不同:
  /// blob 里是 `ssh-rsa`,协商出来的是 `rsa-sha2-512`。写错了,写出来的行
  /// 就和 OpenSSH 写的不一样——而 OpenSSH 自己读这种行也是按 blob 里的名字。
  hostkey_type : String
  /// 主机密钥 blob,原样
  hostkey_blob : FixedArray[Byte]
}

///|
/// 扫描失败的原因
pub(all) enum KeyscanError {
  /// 握手没成(连接断了、协商不出算法、对端不是 SSH-2.0 等等)
  HandshakeFailed(LiveError)
  /// 握手成了,但没拿到主机密钥
  NoHostKey
}

///|
/// 一次扫描的结果
pub(all) enum KeyscanOutcome {
  /// 拿到了主机密钥
  Scanned(KeyscanReport)
  /// 失败
  Failed(KeyscanError)
}

///|
/// 扫一次:只做握手,拿到主机密钥就收工。
///
/// **不认证。** 这是这个工具和普通客户端最要紧的差别。OpenSSH 的 ssh-keyscan
/// 在 KEX 结束、拿到主机密钥的那一刻就断开(`ssh-keyscan.c` 的 `keygrab_ssh2`
/// 里那段注释:「do the key-exchange until an error occurs or until the
/// key_print_wrapper() callback sets c_done」)。它**从不**发
/// SSH_MSG_SERVICE_REQUEST,也**从不**发 SSH_MSG_USERAUTH_REQUEST。
///
/// 这一点不是「少做两步」那么轻:一次认证尝试会把**用户凭据**递出去,而这个
/// 工具的用途恰恰是「在还没决定信不信这台主机之前,先看看它有什么密钥」。
/// 门禁用服务端自己的日志来证这一条:扫描连接在服务端那边一条 userauth 记录
/// 都不该有。
///
/// `hostkey_algs` 是这一次连接要提议的主机密钥算法。ssh-keyscan 对每种类型
/// 开**一条**连接,原因见 `live_proposal_with_hostkey` 的说明:一次握手只
/// 协商出一把主机密钥。
///
/// `kh` 是主机密钥的固定策略。扫描用的是 `KnownHostsPolicy::skip()`——不是
/// 「不检查」,而是「没有条目、且不 strict」,于是走的是**和普通客户端同一段**
/// 判定代码的放行分支(`Unknown` + 非 strict)。另开一条旁路的话,旁路就会
/// 成为「默认值落在旁路上」的那类形状。
pub fn[T : @transport.Transport] live_keyscan(
  conn : T,
  x : @bigint.BigNat,
  kh : @knownhosts.KnownHostsPolicy,
  hostkey_algs : String,
) -> KeyscanOutcome {
  let my = live_proposal_with_hostkey(hostkey_algs)
  // 握手完就收工:没有 SERVICE_REQUEST,没有 USERAUTH_REQUEST。
  let (res, _st) = handshake_to_session_with_proposal(conn, x, kh, my)
  match res {
    Established(rep) => {
      if rep.hostkey_blob.length() == 0 {
        return Failed(KeyscanError::NoHostKey)
      }
      Scanned(KeyscanReport::{
        server_ident: rep.server_ident,
        hostkey_alg: rep.hostkey_alg,
        hostkey_type: rep.hostkey_type,
        hostkey_blob: rep.hostkey_blob,
      })
    }
    Failed(e) => Failed(KeyscanError::HandshakeFailed(e))
  }
}
