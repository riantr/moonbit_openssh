///| SSH message type constants (RFC 4253 §11 + RFC 4252 + RFC 4254)
///|
///| 协议层消息类型字节常量

///|
/// SSH transport layer (RFC 4253 §11)
pub const SSH_MSG_KEXINIT : Byte = b'\x14'
pub const SSH_MSG_NEWKEYS : Byte = b'\x15'
pub const SSH_MSG_KEX_ECDH_INIT : Byte = b'\x1e'
pub const SSH_MSG_KEX_ECDH_REPLY : Byte = b'\x1f'

///|
/// SSH user authentication (RFC 4252 §5)
pub const SSH_MSG_USERAUTH_REQUEST : Byte = b'\x32'
pub const SSH_MSG_USERAUTH_FAILURE : Byte = b'\x33'
pub const SSH_MSG_USERAUTH_SUCCESS : Byte = b'\x34'

///|
/// SSH connection protocol (RFC 4254 §5)
pub const SSH_MSG_CHANNEL_OPEN : Byte = b'\x5a'
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION : Byte = b'\x5b'
pub const SSH_MSG_CHANNEL_OPEN_FAILURE : Byte = b'\x5c'
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST : Byte = b'\x5d'
pub const SSH_MSG_CHANNEL_DATA : Byte = b'\x5e'
pub const SSH_MSG_CHANNEL_EOF : Byte = b'\x5f'
pub const SSH_MSG_CHANNEL_CLOSE : Byte = b'\x60'
pub const SSH_MSG_CHANNEL_REQUEST : Byte = b'\x62'
pub const SSH_MSG_CHANNEL_SUCCESS : Byte = b'\x63'
pub const SSH_MSG_CHANNEL_FAILURE : Byte = b'\x64'