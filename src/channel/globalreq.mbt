///| RFC 4254 §7: the connection protocol's *global* requests.
///

///|
/// A channel is one multiplexed stream; a global request is something the
/// client asks the **server** to do that is not a stream at all. The one
/// this client speaks is "tcpip-forward", and it is the first half of
/// `ssh -R` (RFC 4254 §7.1):
///
///     byte           SSH_MSG_GLOBAL_REQUEST
///     string         request name
///     boolean        want reply
///     string         address to bind
///     uint32         port to listen on
///
/// The server answers with SSH_MSG_REQUEST_SUCCESS (81) or
/// SSH_MSG_REQUEST_FAILURE (82).
///
/// ## The reply's payload is not always there, and that is the whole trap
///
/// The success reply carries a u32 -- the port the server allocated -- **but
/// only when the server allocated one**, i.e. only when the client asked for
/// port 0. When the client names a port, the server binds exactly that port
/// and the reply payload is **empty**.
///
/// Measured against a real Win32-OpenSSH 8.0p1 server
/// (host/remote_fwd_capture.py, which drives the server through paramiko and
/// prints the raw bytes):
///
///     client asked for port 0     -> reply payload = 00 00 fb 51   (u32 64337)
///     client asked for port 23456 -> reply payload = (empty)
///
/// OpenSSH's own server code says the same thing: the u32 is put in the reply
/// only `if (allocated_listen_port != 0)`, and `allocated_listen_port` is
/// filled in only when the requested port was 0.
///
/// So a parser that unconditionally reads a u32 from the reply reads past the
/// end of the message when the client asked for a specific port. On a real
/// server that is not a "missing field", it is a malformed packet. The
/// parser here therefore has to accept **both** shapes, and say which one it
/// got.

///|
/// SSH_MSG_GLOBAL_REQUEST(RFC 4253 §7.1)
pub const SSH_MSG_GLOBAL_REQUEST : Byte = b'\x50'

///|
/// SSH_MSG_REQUEST_SUCCESS(RFC 4253 §7.1)
pub const SSH_MSG_REQUEST_SUCCESS : Byte = b'\x51'

///|
/// SSH_MSG_REQUEST_FAILURE(RFC 4253 §7.1)
pub const SSH_MSG_REQUEST_FAILURE : Byte = b'\x52'

///|
/// "tcpip-forward"(RFC 4254 §7.1)——请求服务端在它那边监听一个端口
pub const GLOBAL_REQUEST_TCPIP_FORWARD : String = "tcpip-forward"

///|
/// "cancel-tcpip-forward"(RFC 4254 §7.1)——撤掉上面那条请求
pub const GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD : String = "cancel-tcpip-forward"

///|
/// SSH_MSG_GLOBAL_REQUEST "tcpip-forward" 的载荷(RFC 4254 §7.1)
///
///     string  "tcpip-forward"
///     boolean want reply (TRUE)
///     string  address to bind
///     uint32  port to listen on
///
/// `listen_host` 是**服务端**要绑的地址,不是我们的地址。空串表示「随便哪个
/// 本地地址」——OpenSSH 客户端在 `ssh -R 9000:host:port`(没写绑定地址)时
/// 发的就是空串。
///
/// `listen_port` 为 0 表示「服务端你挑一个」,回包里会带上它挑的那个。
///
/// want_reply 必须是 TRUE:端口是 0 的时候,客户端**只能**从回包里知道服务端
/// 挑了哪个端口;want_reply=FALSE 且端口为 0 的请求,服务端按 RFC 4254 §7.1
/// 直接拒绝(OpenSSH 的 `server_input_global_request` 里那个
/// `(!want_reply && fwd.listen_port == 0)` 条件)。
pub fn tcpip_forward_request_payload(
  listen_host : String,
  listen_port : Int32,
) -> FixedArray[Byte] {
  ch_cat_all([
    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_TCPIP_FORWARD)),
    FixedArray::from_array([b'\x01']),
    @sshwire.write_ssh_string(ch_ascii(listen_host)),
    u32be(listen_port),
  ])
}

///|
/// SSH_MSG_REQUEST_SUCCESS 的载荷:服务端分配的端口
///
/// 返回 None 表示**回包是空的**——服务端没有分配端口,因为客户端自己指定了
/// 端口(见本文件开头的实测)。调用方此时应当用自己请求的端口。
///
/// 返回 None **不表示**「请求被拒了」:被拒是 SSH_MSG_REQUEST_FAILURE,那是
/// 另一个消息号,根本走不到这里。把这两种混在一起的话,「服务端拒绝了转发」
/// 会被报成「服务端没告诉我们端口」,而后者听起来像协议没实现。
pub fn parse_request_success(payload : FixedArray[Byte]) -> Int32? {
  match read_u32_at(payload, 0) {
    None => None
    Some((port, o1)) => if o1 == payload.length() { Some(port) } else { None }
  }
}

///|
/// SSH_MSG_GLOBAL_REQUEST "cancel-tcpip-forward" 的载荷(RFC 4254 §7.1)
///
///     string  "cancel-tcpip-forward"
///     boolean want reply
///     string  address to bind
///     uint32  port to listen on
///
/// ## 三个字段必须和「当初那条请求」对齐,不是和用户的意图对齐
///
/// 1. **want_reply。** OpenSSH 自己的客户端发这条请求时 want_reply 是 **0**
///    ——`channels.c` 里那行 `sshpkt_put_u8(ssh, 0)`,注释就写着
///    `/* want reply */`。服务端只在 want_reply 为真时才回包(`serverloop.c`
///    末尾那个 `if (want_reply)`),所以 want_reply=0 的时候**一个回包都没有**。
///    一个「发完就等回包」的客户端会永远等下去——这条请求最容易踩的坑就是它。
///
/// 2. **address。** 服务端拿这条请求里的地址和当初那条 "tcpip-forward" 请求里
///    的地址**逐字节比较**(`channels.c` 里那句 `strcmp(c->path, host) == 0`)。
///    服务端存的 `c->path` 就是当初请求里那个字符串的原样(`c->path =
///    xstrdup(host)`),所以这里必须回**同一个字符串**——「意思一样」不行,
///    大小写、空格、哪怕一个字节的差别都不行。
///
/// 3. **port。** 服务端比的是 `c->listening_port`,而那是**服务端自己挑的**
///    端口(客户端当初要的是 port=0)。拿 port=0 去取消是取消不掉的:服务端的
///    监听器记着的是它挑的那个端口号。
///
/// 换句话说,这条请求的输入不是「用户想要撤销什么」,而是**当初那次请求的
/// 结果**——服务端答给我们的那个端口号,加上当初发出去的地址。
pub fn cancel_tcpip_forward_request_payload(
  listen_host : String,
  listen_port : Int32,
  want_reply : Bool,
) -> FixedArray[Byte] {
  let want = if want_reply { b'\x01' } else { b'\x00' }
  ch_cat_all([
    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD)),
    FixedArray::from_array([want]),
    @sshwire.write_ssh_string(ch_ascii(listen_host)),
    u32be(listen_port),
  ])
}

///|
/// 绑定地址的归一化,和 OpenSSH 的 `channel_rfwd_bind_host` 一样。
///
/// OpenSSH 的客户端在发 "tcpip-forward" 之前先把绑定地址过一遍这个函数:
/// 空串和 "*" **都**变成空串(空串的意思是「随便哪个本地地址」)。撤销请求
/// 必须用当初请求发出去的那个字符串,所以这个归一化在取消这条路上也得再走
/// 一遍——否则 `ssh -R *:0:host:port` 的撤销会带着 "*" 发出去,而服务端存的是
/// 空串,比不上,撤销静默地不生效。
///
/// OpenSSH 那边 `NULL` 会变成 "localhost";本仓库没有 NULL 可言,空串原样保留。
pub fn rfwd_bind_host(listen_host : String) -> String {
  if listen_host == "*" {
    ""
  } else {
    listen_host
  }
}
