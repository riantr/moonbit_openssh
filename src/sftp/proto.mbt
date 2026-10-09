///| SFTP v3 constants and the parse cursor
///
/// Values transcribed from `sftp.h:32-96` and `sftp-common.h:29`.

///| We announce and expect version 3 (sftp.h:32 `SSH2_FILEXFER_VERSION`).
pub const SFTP_VERSION : Int = 3

///| Maximum packet either side will send or accept
/// (sftp-common.h:29 `SFTP_MAX_MSG_LENGTH`).
///
/// `get_msg_extended` rejects anything longer *before* allocating for it
/// (sftp-client.c:195), so this is a bound on a length field read off the
/// wire, not on a buffer we already hold. Honouring it is what keeps a hostile
/// or corrupt peer from asking us to reserve 4 GiB.
pub const SFTP_MAX_MSG_LENGTH : Int = 262144

///| Largest READ the server will honour (sftp-server.c:55
/// `SFTP_MAX_READ_LENGTH`), i.e. `SFTP_MAX_MSG_LENGTH - 1024`.
///
/// It clamps rather than errors (sftp-server.c:808-810), so asking for more
/// than this is legal -- it just comes back short. See `sftp_read`.
pub const SFTP_MAX_READ_LENGTH : Int = 261120

// ---- client -> server (sftp.h:34-54) --------------------------------------

pub const FXP_INIT : Int = 1
pub const FXP_OPEN : Int = 3
pub const FXP_CLOSE : Int = 4
pub const FXP_READ : Int = 5
pub const FXP_WRITE : Int = 6
pub const FXP_LSTAT : Int = 7
pub const FXP_FSTAT : Int = 8
pub const FXP_SETSTAT : Int = 9
pub const FXP_FSETSTAT : Int = 10
pub const FXP_OPENDIR : Int = 11
pub const FXP_READDIR : Int = 12
pub const FXP_REMOVE : Int = 13
pub const FXP_MKDIR : Int = 14
pub const FXP_RMDIR : Int = 15
pub const FXP_REALPATH : Int = 16
pub const FXP_STAT : Int = 17
pub const FXP_RENAME : Int = 18
pub const FXP_READLINK : Int = 19
pub const FXP_SYMLINK : Int = 20

// ---- server -> client (sftp.h:56-62) --------------------------------------

pub const FXP_VERSION : Int = 2
pub const FXP_STATUS : Int = 101
pub const FXP_HANDLE : Int = 102
pub const FXP_DATA : Int = 103
pub const FXP_NAME : Int = 104
pub const FXP_ATTRS : Int = 105

// ---- attribute flags (sftp.h:68-72) ---------------------------------------

pub const ATTR_SIZE : Int = 0x00000001
pub const ATTR_UIDGID : Int = 0x00000002
pub const ATTR_PERMISSIONS : Int = 0x00000004
pub const ATTR_ACMODTIME : Int = 0x00000008
pub const ATTR_EXTENDED : Int = 0x80000000

// ---- portable open flags (sftp.h:76-80) ----------------------------------

pub const FXF_READ : Int = 0x00000001
pub const FXF_WRITE : Int = 0x00000002
pub const FXF_APPEND : Int = 0x00000004
pub const FXF_CREAT : Int = 0x00000008
pub const FXF_TRUNC : Int = 0x00000010
pub const FXF_EXCL : Int = 0x00000020

// ---- status codes (sftp.h:87-95) ------------------------------------------

pub const FX_OK : Int = 0
pub const FX_EOF : Int = 1
pub const FX_NO_SUCH_FILE : Int = 2
pub const FX_PERMISSION_DENIED : Int = 3
pub const FX_FAILURE : Int = 4
pub const FX_BAD_MESSAGE : Int = 5
pub const FX_NO_CONNECTION : Int = 6
pub const FX_CONNECTION_LOST : Int = 7
pub const FX_OP_UNSUPPORTED : Int = 8
///| sftp.h:96 `SSH2_FX_MAX` -- anything above this is not a v3 status code.
pub const FX_MAX : Int = 8

// ---------------------------------------------------------------------------
// parse cursor
// ---------------------------------------------------------------------------

///|
/// Why a packet could not be parsed.
///
/// Kept as a closed enum on purpose: SFTP runs *inside* a channel whose bytes
/// have already been authenticated, so the failure modes here are "our own
/// parser is wrong" and "the peer is lying", not "the transport broke". There
/// is no path back to a reconnect here, so the enum exists to make the KAT
/// able to say *which* rule was broken rather than just "None".
pub(all) enum SftpError {
  /// The buffer ended in the middle of a field.
  Truncated
  /// A length field pointed past the end of the buffer.
  BadLength
  /// The declared message type is not one we know how to parse.
  UnknownType(Int)
  /// The packet parsed but did not end where the format says it must.
  TrailingData
  /// A field that the format fixes to a constant had another value.
  Unexpected(Int)
}

///|
/// Offset-based reader over one SFTP packet body.
///
/// Errors are sticky: the first failure latches and every later read returns a
/// zero value. That matches how the C reads (each `sshbuf_get_*` is checked
/// and the function bails), and it means a caller only has to check `err`
/// once at the end rather than after each field.
pub(all) struct SftpCursor {
  buf : FixedArray[Byte]
  mut off : Int
  mut err : SftpError?
}

pub fn SftpCursor::new(buf : FixedArray[Byte]) -> SftpCursor {
  { buf, off: 0, err: None }
}

pub fn SftpCursor::remaining(self : SftpCursor) -> Int {
  self.buf.length() - self.off
}

fn SftpCursor::fail(self : SftpCursor, e : SftpError) -> Unit {
  if self.err is None {
    self.err = Some(e)
  }
}

pub fn SftpCursor::u8(self : SftpCursor) -> Int {
  if self.err is Some(_) {
    return 0
  }
  if self.remaining() < 1 {
    self.fail(Truncated)
    return 0
  }
  let v = self.buf[self.off].to_int()
  self.off = self.off + 1
  v
}

pub fn SftpCursor::u32(self : SftpCursor) -> Int {
  if self.err is Some(_) {
    return 0
  }
  if self.remaining() < 4 {
    self.fail(Truncated)
    return 0
  }
  let v = @sshwire.read_u32(self.buf, self.off).reinterpret_as_int()
  self.off = self.off + 4
  v
}

pub fn SftpCursor::u64(self : SftpCursor) -> UInt64 {
  if self.err is Some(_) {
    return 0
  }
  if self.remaining() < 8 {
    self.fail(Truncated)
    return 0
  }
  let v = @sshwire.read_u64(self.buf, self.off)
  self.off = self.off + 8
  v
}

///|
/// An SSH-style length-prefixed string. Paths, filenames, longnames, handle
/// tokens and extension data are all this shape.
pub fn SftpCursor::string(self : SftpCursor) -> FixedArray[Byte] {
  let empty : FixedArray[Byte] = FixedArray::make(0, b'\x00')
  if self.err is Some(_) {
    return empty
  }
  if self.remaining() < 4 {
    self.fail(Truncated)
    return empty
  }
  let n = @sshwire.read_u32(self.buf, self.off).reinterpret_as_int()
  if n < 0 || n > self.remaining() - 4 {
    // sshbuf_get_string's SSH_ERR_MESSAGE_INCOMPLETE. A length field is the
    // only thing in this format that can name an offset past the end, so it
    // gets its own error rather than sharing Truncated.
    self.fail(BadLength)
    return empty
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = self.buf[self.off + 4 + i]
  }
  self.off = self.off + 4 + n
  out
}

///|
/// The same string as a `String`.
///
/// Paths in this protocol are UTF-8 in practice but the protocol carries
/// bytes, and on Windows a remote path can be anything the server's locale
/// produced. Building the String byte by byte keeps a non-UTF-8 byte from
/// becoming a decode failure that takes the whole session down; the caller
/// that needs bytes still has `SftpCursor::string`.
pub fn SftpCursor::str(self : SftpCursor) -> String {
  let raw = self.string()
  if self.err is Some(_) {
    return ""
  }
  let sb = StringBuilder()
  for i = 0; i < raw.length(); i = i + 1 {
    sb.write_char(Int::unsafe_to_char(raw[i].to_int()))
  }
  sb.to_string()
}

///|
/// Assert the packet ends here.
///
/// Only valid where the format really does fix the end -- `subsystem`'s
/// request payload, or a bare request with no trailing fields. It is *not*
/// valid after attributes, which is what the C's `decode_attrib` also
/// implies by never calling `sshbuf_get_end`.
pub fn SftpCursor::expect_end(self : SftpCursor) -> Unit {
  if self.err is Some(_) {
    return
  }
  if self.remaining() != 0 {
    self.fail(TrailingData)
  }
}

///|
/// `bool` as one byte. OpenSSH sends 0 or 1 and treats anything else as true
/// (`datafellows` in sshbuf.c); we report it rather than guessing.
pub fn SftpCursor::byte_bool(self : SftpCursor) -> Bool {
  self.u8() != 0
}
