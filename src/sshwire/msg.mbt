///| SSH message type constants (RFC 4253 §11 + RFC 4252 + RFC 4254)

///|

///| 协议层消息类型字节常量

///|
/// SSH_MSG_SERVICE_REQUEST (RFC 4253 §7.1)
///
/// body 是一个 service name(如 "ssh-userauth")。它通常是 NEWKEYS 之后的
/// 第一个加密消息,所以「服务器回了 SERVICE_ACCEPT」本身就是一次完整的
/// 解密 + hmac-sha2-256 校验通过——不需要再多跑一步就能证明加密会话通了。
pub const SSH_MSG_SERVICE_REQUEST : Byte = b'\x05'

///|
/// SSH_MSG_SERVICE_ACCEPT (RFC 4253 §7.1)
pub const SSH_MSG_SERVICE_ACCEPT : Byte = b'\x06'

///|
/// SSH transport layer (RFC 4253 §11)
pub const SSH_MSG_KEXINIT : Byte = b'\x14'

///|
pub const SSH_MSG_NEWKEYS : Byte = b'\x15'

///|
pub const SSH_MSG_KEX_ECDH_INIT : Byte = b'\x1e'

///|
pub const SSH_MSG_KEX_ECDH_REPLY : Byte = b'\x1f'

///|
/// SSH user authentication (RFC 4252 §5)
pub const SSH_MSG_USERAUTH_REQUEST : Byte = b'\x32'

///|
pub const SSH_MSG_USERAUTH_FAILURE : Byte = b'\x33'

///|
pub const SSH_MSG_USERAUTH_SUCCESS : Byte = b'\x34'

///|
/// 服务端接受了这把公钥(RFC 4252 §7)
///
/// 这是 publickey **探针**请求的回应:客户端先问「我可以用这把钥匙吗」,
/// 服务端回这个就说明钥匙没问题,接下来才轮到签名。
pub const SSH_MSG_USERAUTH_PK_OK : Byte = b'\x3c'

///|
/// SSH connection protocol (RFC 4254 §5)
///
/// **The numbering here was wrong until Loop #94, and the mistake is worth
/// writing down.**
///
/// The table used to read
///
///     CHANNEL_DATA      0x5e
///     CHANNEL_EOF       0x5f     <- wrong
///     CHANNEL_CLOSE     0x60     <- wrong
///     CHANNEL_REQUEST   0x62
///
/// -- that is, it skipped `SSH_MSG_CHANNEL_EXTENDED_DATA` (0x5f) and shifted
/// EOF and CLOSE down by one.  RFC 4254 §5.1 numbers the connection
/// protocol:
///
///     90 CHANNEL_OPEN              0x5a
///     91 CHANNEL_OPEN_CONFIRMATION 0x5b
///     92 CHANNEL_OPEN_FAILURE      0x5c
///     93 CHANNEL_WINDOW_ADJUST     0x5d
///     94 CHANNEL_DATA              0x5e
///     95 CHANNEL_EXTENDED_DATA     0x5f
///     96 CHANNEL_EOF               0x60
///     97 CHANNEL_CLOSE             0x61
///     98 CHANNEL_REQUEST           0x62
///     99 CHANNEL_SUCCESS           0x63
///    100 CHANNEL_FAILURE           0x64
///
/// and the real server agrees, byte for byte: the `sshd` on this machine
/// sends **type 96** for the EOF and **type 97** for the close (measured in
/// `.loop94/bed-real/sshd.log_loop94v`: "send packet: type 96" then
/// "send packet: type 97"), and the real client reads them the same way.
///
/// **Why it stayed wrong for so long:** every test that used these constants
/// also BUILT the packets with them.  `src/sshclient/client.mbt` is a mock
/// server, and it sent its EOF as 0x5f; the test then checked that the
/// packet it received was "an EOF" -- by comparing against the same constant.
/// A mock and the code that checks the mock agree with each other by
/// construction, so the error could not show up there.
///
/// The real client was never affected: `src/channel` does not use this table
/// at all, it uses the literal bytes (0x5e / 0x60 / 0x61), which is why it
/// talks to the real server correctly every day.  That is also the lesson:
/// the table was a SECOND copy of a rule that already existed, and the copy
/// was the one that was wrong.
pub const SSH_MSG_CHANNEL_OPEN : Byte = b'\x5a'

///|
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION : Byte = b'\x5b'

///|
pub const SSH_MSG_CHANNEL_OPEN_FAILURE : Byte = b'\x5c'

///|
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST : Byte = b'\x5d'

///|
pub const SSH_MSG_CHANNEL_DATA : Byte = b'\x5e'

///|
/// SSH_MSG_CHANNEL_EXTENDED_DATA (RFC 4254 §5.2)
///
/// The peer's stderr, and any other "data with a code" stream: the payload
/// is `uint32 recipient || uint32 data_type_code || string data`, and
/// `data_type_code` 1 means stderr.
///
/// This constant did not exist until Loop #94, which is why the server
/// could not report a command's stderr: there was no name for the message
/// that carries it.
pub const SSH_MSG_CHANNEL_EXTENDED_DATA : Byte = b'\x5f'

///|
pub const SSH_MSG_CHANNEL_EOF : Byte = b'\x60'

///|
pub const SSH_MSG_CHANNEL_CLOSE : Byte = b'\x61'

///|
pub const SSH_MSG_CHANNEL_REQUEST : Byte = b'\x62'

///|
pub const SSH_MSG_CHANNEL_SUCCESS : Byte = b'\x63'

///|
pub const SSH_MSG_CHANNEL_FAILURE : Byte = b'\x64'

///|
/// SSH_MSG_GLOBAL_REQUEST (RFC 4254 §7.1)
///
/// A request that is not about any channel: `no-more-sessions@openssh.com`
/// and `hostkeys-00@openssh.com` are the two the real client sends, both
/// with `want_reply = FALSE`, and the real server answers neither.
pub const SSH_MSG_GLOBAL_REQUEST : Byte = b'\x50'

///|
/// SSH_MSG_REQUEST_SUCCESS (RFC 4254 §7.2)
pub const SSH_MSG_REQUEST_SUCCESS : Byte = b'\x51'

///|
/// SSH_MSG_REQUEST_FAILURE (RFC 4254 §7.2)
///
/// The answer to a global request that asked for one and was not honoured.
pub const SSH_MSG_REQUEST_FAILURE : Byte = b'\x52'
