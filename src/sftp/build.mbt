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

///|
fn put_type(t : Int32) -> FixedArray[Byte] {
  FixedArray::make(1, t.to_byte())
}

///|
fn put_u32i(v : Int32) -> FixedArray[Byte] {
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
pub fn sftp_init(version : Int32) -> FixedArray[Byte] {
  sftp_cat([put_type(FXP_INIT), put_u32i(version)])
}

///|
/// SSH2_FXP_REALPATH (sftp.h:50).
///
/// Used for "." rather than as a way to escape the chroot: `internal-sftp`
/// confines the session, and REALPATH is how a client *learns* where it
/// landed rather than a way to choose.
pub fn sftp_realpath(id : Int32, path : String) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_REALPATH),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
  ])
}

///|
/// SSH2_FXP_STAT (sftp.h:52) -- follows symlinks, as opposed to LSTAT.
pub fn sftp_stat(id : Int32, path : String) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_STAT),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
  ])
}

///|
/// SSH2_FXP_OPENDIR (sftp.h:45).
pub fn sftp_opendir(id : Int32, path : String) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_OPENDIR),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
  ])
}

///|
/// SSH2_FXP_READDIR (sftp.h:46).
///
/// `handle` is an opaque server-issued token, so it goes back byte for byte.
/// Re-encoding it as text would work until a server issued one containing a
/// NUL or a non-ASCII byte.
pub fn sftp_readdir(id : Int32, handle : FixedArray[Byte]) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_READDIR),
    put_u32i(id),
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
  id : Int32,
  path : String,
  pflags : Int32,
  attrs : SftpAttrs,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_OPEN),
    put_u32i(id),
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
  id : Int32,
  handle : FixedArray[Byte],
  offset : UInt64,
  length : Int32,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_READ),
    put_u32i(id),
    @sshwire.write_ssh_string(handle),
    @sshwire.write_u64(offset),
    put_u32i(length),
  ])
}

///|
/// SSH2_FXP_WRITE (sftp.h:38, `process_write` sftp-server.c:846-856).
///
/// Same offset discipline as READ, and the same reason it is load-bearing:
/// `process_write` does `lseek(fd, off, SEEK_SET)` unless the handle was opened
/// O_APPEND (`:865-866`), so a wrong offset is not a rejected request -- it is
/// bytes written somewhere else in the file.
///
/// There is no clamp on the server side for writes the way there is for reads,
/// but the length still travels inside a `string` in a packet bounded by
/// `SFTP_MAX_MSG_LENGTH`, so `sftp_write_length` keeps one packet's worth of
/// data comfortably under that.
pub fn sftp_write(
  id : Int32,
  handle : FixedArray[Byte],
  offset : UInt64,
  data : FixedArray[Byte],
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_WRITE),
    put_u32i(id),
    @sshwire.write_ssh_string(handle),
    @sshwire.write_u64(offset),
    @sshwire.write_ssh_string(data),
  ])
}

///|
/// SSH2_FXP_SETSTAT (sftp.h:47, `process_setstat` sftp-server.c:979-982).
///
/// Setting nothing is not a no-op request that succeeds quietly: the server
/// still answers, and `decode_attrib` runs over whatever the flags say, so the
/// encoding of "I want to change nothing" is `SftpAttrs::none()` -- four zero
/// bytes -- and it is a complete, legal request.
pub fn sftp_setstat(
  id : Int32,
  path : String,
  attrs : SftpAttrs,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_SETSTAT),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
    attrs.encode(),
  ])
}

///|
/// SSH2_FXP_FSETSTAT (sftp.h:48) -- SETSTAT by handle rather than by path.
pub fn sftp_fsetstat(
  id : Int32,
  handle : FixedArray[Byte],
  attrs : SftpAttrs,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_FSETSTAT),
    put_u32i(id),
    @sshwire.write_ssh_string(handle),
    attrs.encode(),
  ])
}

///|
/// SSH2_FXP_RENAME (sftp.h:52, `process_rename` sftp-server.c:1261-1264).
///
/// Two paths, both length-prefixed strings, and both required: a trailing
/// field the server does not read would not be noticed here, but a missing one
/// is a `fatal_fr`, i.e. the session is torn down rather than answered.
pub fn sftp_rename(
  id : Int32,
  old_path : String,
  new_path : String,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_RENAME),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(old_path)),
    @sshwire.write_ssh_string(sftp_ascii(new_path)),
  ])
}

///|
/// The single-argument filesystem operations.
///
/// They differ only in the message number, and every one of them answers with
/// a STATUS, so they are one function rather than four: a reader looking for
/// "what does REMOVE send" should find the list, not three near-identical
/// bodies that could drift apart in the details.
pub fn sftp_path_only(
  id : Int32,
  typ : Int32,
  path : String,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(typ),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
  ])
}

///|
pub fn sftp_remove(id : Int32, path : String) -> FixedArray[Byte] {
  sftp_path_only(id, FXP_REMOVE, path)
}

///|
pub fn sftp_rmdir(id : Int32, path : String) -> FixedArray[Byte] {
  sftp_path_only(id, FXP_RMDIR, path)
}

///|
/// SSH2_FXP_MKDIR (sftp.h:42, `process_mkdir` sftp-server.c:1196-1199).
///
/// Unlike REMOVE and RMDIR, MKDIR carries attributes after the path -- the
/// mode comes from them when the PERMISSIONS bit is set, and 0777 otherwise
/// (`:1201-1203`). Sending zero bytes there is a parse failure, not a default.
pub fn sftp_mkdir(
  id : Int32,
  path : String,
  attrs : SftpAttrs,
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_MKDIR),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(path)),
    attrs.encode(),
  ])
}

///|
/// SSH2_FXP_EXTENDED (sftp.h:65), and the shape every OpenSSH extension uses:
/// the extension name, then whatever that extension defines.
///
/// `posix-rename@openssh.com` takes two paths and nothing else
/// (`process_extended_posix_rename` sftp-server.c), which is the point of
/// choosing it over FXP_RENAME: the v3 rename is specified to fail if the
/// target exists, while `posix(2)` replaces it. A client that only knows
/// FXP_RENAME cannot overwrite, and one that only knows the extension cannot
/// work against a server that does not advertise it -- so the driver checks
/// what VERSION said.
pub fn sftp_extended(
  id : Int32,
  name : String,
  body : FixedArray[Byte],
) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_EXTENDED),
    put_u32i(id),
    @sshwire.write_ssh_string(sftp_ascii(name)),
    body,
  ])
}

///|
/// `posix-rename@openssh.com`: the two paths, nothing more.
pub fn sftp_posix_rename_body(
  old_path : String,
  new_path : String,
) -> FixedArray[Byte] {
  sftp_cat([
    @sshwire.write_ssh_string(sftp_ascii(old_path)),
    @sshwire.write_ssh_string(sftp_ascii(new_path)),
  ])
}

///|
/// The WRITE chunk size this client asks for.
///
/// There is no server-side clamp for writes, so this is our own choice, and it
/// is worth stating why it is not "as large as possible": a 256 KiB write
/// becomes one SSH packet, which the channel layer then has to split across
/// several CHANNEL_DATA messages and reassemble, so a larger chunk buys
/// nothing and makes the window arithmetic harder to reason about.
pub fn sftp_write_length(want : Int32) -> Int32 {
  if want > 32768 {
    return 32768
  }
  want
}

///|
/// SSH2_FXP_CLOSE (sftp.h:36).
pub fn sftp_close(id : Int32, handle : FixedArray[Byte]) -> FixedArray[Byte] {
  sftp_cat([
    put_type(FXP_CLOSE),
    put_u32i(id),
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
pub fn sftp_read_length(want : Int32) -> Int32 {
  if want > SFTP_MAX_READ_LENGTH {
    return SFTP_MAX_READ_LENGTH
  }
  if want < 1 {
    return 1
  }
  want
}
