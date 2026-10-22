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
