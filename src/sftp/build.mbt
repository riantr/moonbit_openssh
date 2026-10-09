///| SFTP v3 request packets
///
/// Every builder returns the **packet body** -- type byte first, no length
/// prefix. Framing happens in one place (`sftp_frame`) so that no builder can
/// produce a packet that disagrees with the reader about where the length
/// goes.
///
/// Request ids start at 1 on purpose. id 0 is not special to the protocol, but
/// a client that starts at 0 and then treats 0 as "unset" in its own pending
/// table will quietly mis-match every response, so the table and the wire are
/// kept in step from the first packet.

///|
/// `uint32 length || body`.
///
/// The length counts the body only, not the four bytes of itself
/// (`send_msg`, sftp-client.c:160-161). Getting this off by four is the
/// classic SFTP framing bug: it still parses locally if the reader is wrong
/// in the same way, and only a real server notices.
pub fn sftp_frame(body : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4 + body.length(), b'\x00')
  let n = @sshwire.write_u32(body.length().reinterpret_as_uint())
  for i = 0; i < 4; i = i + 1 {
    out[i] = n[i]
  }
  for i = 0; i < body.length(); i = i + 1 {
    out[4 + i] = body[i]
  }
  out
}

fn put_type(t : Int) -> FixedArray[Byte] {
  FixedArray::make(1, t.to_byte())
}

fn put_u32i(v : Int) -> FixedArray[Byte] {
  @sshwire.write_u32(v.reinterpret_as_uint())
}

///|
/// SSH2_FXP_INIT -- the first thing a client sends, and the only request with
/// no id (sftp.h:35; `process_init` reads just the version, sftp-server.c:707).
///
/// Sending the version the peer can actually speak is not politeness: the
/// server replies with *its* version plus an extension list sized for that
/// version, so an INIT that understates ours makes the two sides disagree
/// about which extensions are in play.
pub fn sftp_init(version : Int) -> FixedArray[Byte] {
  sftp_cat([put_type(FXP_INIT), put_u32i(version)])
}

///|
/// SSH2_FXP_REALPATH (sftp.h:50).
///
/// Used for "." rather than as a way to escape the chroot: `internal-sftp`
/// confines the session, and REALPATH is how a client *learns* where it
/// landed rather than a way to choose.
pub fn sftp_realpath(id : Int, path : String) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_REALPATH), put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
  ])
}

///|
/// SSH2_FXP_STAT (sftp.h:52) -- follows symlinks, as opposed to LSTAT.
pub fn sftp_stat(id : Int, path : String) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_STAT), put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
  ])
}

///|
/// SSH2_FXP_OPENDIR (sftp.h:45).
pub fn sftp_opendir(id : Int, path : String) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_OPENDIR), put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
  ])
}

///|
/// SSH2_FXP_READDIR (sftp.h:46).
///
/// `handle` is an opaque server-issued token, so it goes back byte for byte.
/// Re-encoding it as text would work until a server issued one containing a
/// NUL or a non-ASCII byte.
pub fn sftp_readdir(id : Int, handle : FixedArray[Byte]) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_READDIR), put_u32i(id),
    @sshwire.write_ssh_string(handle),
  ])
}

///|
/// SSH2_FXP_OPEN (sftp.h:35, `process_open` sftp-server.c:741-743).
///
/// The trailing ATTRS is required by the format even when we have nothing to
/// say -- `process_open` calls `decode_attrib` unconditionally, and reads the
/// mode from it only when the PERMISSIONS bit is set
/// (sftp-server.c:748, defaulting to 0666). An absent block is the
/// four-byte "no flags" encoding, not zero bytes.
pub fn sftp_open(
  id : Int,
  path : String,
  pflags : Int,
  attrs : SftpAttrs,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_OPEN), put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
    put_u32i(pflags),
    attrs.encode(),
  ])
}

///|
/// SSH2_FXP_READ (sftp.h:37, `process_read` sftp-server.c:791-810).
///
/// `offset` is a full-file offset, not a position within the current read.
pub fn sftp_read(
  id : Int,
  handle : FixedArray[Byte],
  offset : UInt64,
  length : Int,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_READ), put_u32i(id),
    @sshwire.write_ssh_string(handle),
    @sshwire.write_u64(offset),
    put_u32i(length),
  ])
}

///|
/// SSH2_FXP_CLOSE (sftp.h:36).
pub fn sftp_close(id : Int, handle : FixedArray[Byte]) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_CLOSE), put_u32i(id),
    @sshwire.write_ssh_string(handle),
  ])
}

///|
/// The READ length to actually ask for.
///
/// The server clamps a too-large request rather than failing it
/// (`sftp-server.c:808-810`: "read change len %u to %u"), so asking for more
/// than `SFTP_MAX_READ_LENGTH` is legal and simply comes back short. Asking
/// for the clamped value ourselves keeps the KAT's byte counts honest and
/// saves a round trip's worth of surprise.
pub fn sftp_read_length(want : Int) -> Int {
  if want > SFTP_MAX_READ_LENGTH {
    return SFTP_MAX_READ_LENGTH
  }
  if want < 1 {
    return 1
  }
  want
}
