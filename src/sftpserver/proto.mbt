///| Loop #92: request parsing and reply building for the SFTP server.
///
/// The type numbers are from `sftp.h` and every one used here has been seen
/// on the wire in `.loop92/probe_out.txt` or the `-l DEBUG3` transcripts in
/// `.loop92/DESIGN.md`.

///|
/// SSH_FXP_INIT -- version only, no id.
pub const FXP_INIT : Int32 = 1

///|
/// SSH_FXP_VERSION
pub const FXP_VERSION : Int32 = 2

///|
/// SSH_FXP_OPEN
pub const FXP_OPEN : Int32 = 3

///|
/// SSH_FXP_CLOSE
pub const FXP_CLOSE : Int32 = 4

///|
/// SSH_FXP_READ
pub const FXP_READ : Int32 = 5

///|
/// SSH_FXP_WRITE
pub const FXP_WRITE : Int32 = 6

///|
/// SSH_FXP_LSTAT
pub const FXP_LSTAT : Int32 = 7

///|
/// SSH_FXP_FSTAT
pub const FXP_FSTAT : Int32 = 8

///|
/// SSH_FXP_SETSTAT
pub const FXP_SETSTAT : Int32 = 9

///|
/// SSH_FXP_FSETSTAT -- the one `scp -p` actually uses.
pub const FXP_FSETSTAT : Int32 = 10

///|
/// SSH_FXP_OPENDIR
pub const FXP_OPENDIR : Int32 = 11

///|
/// SSH_FXP_READDIR
pub const FXP_READDIR : Int32 = 12

///|
/// SSH_FXP_REMOVE
pub const FXP_REMOVE : Int32 = 13

///|
/// SSH_FXP_MKDIR
pub const FXP_MKDIR : Int32 = 14

///|
/// SSH_FXP_RMDIR
pub const FXP_RMDIR : Int32 = 15

///|
/// SSH_FXP_REALPATH
pub const FXP_REALPATH : Int32 = 16

///|
/// SSH_FXP_STAT
pub const FXP_STAT : Int32 = 17

///|
/// SSH_FXP_RENAME
pub const FXP_RENAME : Int32 = 18

///|
/// SSH_FXP_STATUS
pub const FXP_STATUS : Int32 = 101

///|
/// SSH_FXP_HANDLE
pub const FXP_HANDLE : Int32 = 102

///|
/// SSH_FXP_DATA
pub const FXP_DATA : Int32 = 103

///|
/// SSH_FXP_NAME
pub const FXP_NAME : Int32 = 104

///|
/// SSH_FXP_ATTRS
pub const FXP_ATTRS : Int32 = 105

///|
/// The status codes this server can produce.
///
/// Only the codes the real server was RECORDED sending are given their own
/// number here: `0 Success`, `1 End of file`, `2 No such file`,
/// `3 Permission denied`, `4 Failure`, `5 Bad message` and
/// `8 Operation unsupported`.  Code 3 and code 5 were added after
/// `.loop92/probe6.py` and `probe10.py` measured them -- the first four
/// codes were all the earlier note knew, and a server that answered
/// "Failure" where the real one says "Permission denied" would differ in
/// every reply that a client prints the text of.
///
/// Codes 6 and 7 (no connection, connection lost) exist in the protocol
/// and are NOT used: a server that has a connection does not lose it
/// mid-request, and inventing a sentence for them would be a guess.
pub const FX_OK : Int32 = 0

///|
pub const FX_EOF : Int32 = 1

///|
pub const FX_NO_SUCH_FILE : Int32 = 2

///|
pub const FX_PERMISSION_DENIED : Int32 = 3

///|
pub const FX_FAILURE : Int32 = 4

///|
pub const FX_BAD_MESSAGE : Int32 = 5

///|
pub const FX_OP_UNSUPPORTED : Int32 = 8

///|
/// One request, parsed.
///
/// A separate arm per shape rather than a bag of optional fields: the server
/// has to answer each shape differently, and a bag would let a handler read
/// a field its request cannot carry.
pub(all) enum Request {
  /// `u32 version` -- no id, and it is the only request without one
  Init(Int32)
  Open(Int32, String, Int32, @sftp.SftpAttrs)
  Close(Int32, FixedArray[Byte])
  Read(Int32, FixedArray[Byte], UInt64, Int32)
  Write(Int32, FixedArray[Byte], UInt64, FixedArray[Byte])
  Lstat(Int32, String)
  Fstat(Int32, FixedArray[Byte])
  Setstat(Int32, String, @sftp.SftpAttrs)
  Fsetstat(Int32, FixedArray[Byte], @sftp.SftpAttrs)
  Opendir(Int32, String)
  Readdir(Int32, FixedArray[Byte])
  Remove(Int32, String)
  Mkdir(Int32, String, @sftp.SftpAttrs)
  Rmdir(Int32, String)
  Realpath(Int32, String)
  Stat(Int32, String)
  Rename(Int32, String, String)
  /// An extension request: its name, then the fields this package does not
  /// interpret.  Kept opaque on purpose -- answering an extension the
  /// server does not implement with `Failure` is what the real one does.
  Extended(Int32, String, FixedArray[Byte])
  /// A type this server does not know.  It carries no id, because a type
  /// that is not known cannot be assumed to have one: the real server
  /// answered nothing at all to a malformed unknown type (measured), so
  /// there is nothing to reply to.
  Unknown(Int32)
}

///|
/// Read an ATTRS block: flags, then whichever fields the flags name.
///
/// The order is the one the draft fixes and the one the real server's STAT
/// reply was recorded using: size, uid/gid, permissions, atime/mtime.
fn parse_attrs(cur : @sftp.SftpCursor) -> @sftp.SftpAttrs {
  let attrs = @sftp.SftpAttrs::none()
  let flags = cur.u32()
  if (flags & 1) != 0 {
    attrs.size = Some(cur.u64())
  }
  if (flags & 2) != 0 {
    let uid = cur.u32()
    let gid = cur.u32()
    attrs.uid = Some(uid)
    attrs.gid = Some(gid)
  }
  if (flags & 4) != 0 {
    attrs.permissions = Some(cur.u32())
  }
  if (flags & 8) != 0 {
    let atime = cur.u32()
    let mtime = cur.u32()
    attrs.atime = Some(atime)
    attrs.mtime = Some(mtime)
  }
  attrs
}

///|
/// Parse one request body (unframed, type byte first).
///
/// A request whose fields run out mid-way is `Unknown` too: the alternative
/// is a panic on input from the network, and a server that panics on a short
/// packet is a server that can be stopped by one.
pub fn parse_request(body : FixedArray[Byte]) -> Request {
  if body.length() < 1 {
    return Request::Unknown(-1)
  }
  let cur = @sftp.SftpCursor::new(body)
  let t = cur.u8()
  if t == FXP_INIT {
    return Request::Init(cur.u32())
  }
  let id = cur.u32()
  if t == FXP_OPEN {
    let path = cur.str()
    let flags = cur.u32()
    Request::Open(id, path, flags, parse_attrs(cur))
  } else if t == FXP_CLOSE {
    Request::Close(id, cur.string())
  } else if t == FXP_READ {
    let handle = cur.string()
    let offset = cur.u64()
    Request::Read(id, handle, offset, cur.u32())
  } else if t == FXP_WRITE {
    let handle = cur.string()
    let offset = cur.u64()
    Request::Write(id, handle, offset, cur.string())
  } else if t == FXP_LSTAT {
    Request::Lstat(id, cur.str())
  } else if t == FXP_FSTAT {
    Request::Fstat(id, cur.string())
  } else if t == FXP_SETSTAT {
    let path = cur.str()
    Request::Setstat(id, path, parse_attrs(cur))
  } else if t == FXP_FSETSTAT {
    let handle = cur.string()
    Request::Fsetstat(id, handle, parse_attrs(cur))
  } else if t == FXP_OPENDIR {
    Request::Opendir(id, cur.str())
  } else if t == FXP_READDIR {
    Request::Readdir(id, cur.string())
  } else if t == FXP_REMOVE {
    Request::Remove(id, cur.str())
  } else if t == FXP_MKDIR {
    let path = cur.str()
    Request::Mkdir(id, path, parse_attrs(cur))
  } else if t == FXP_RMDIR {
    Request::Rmdir(id, cur.str())
  } else if t == FXP_REALPATH {
    Request::Realpath(id, cur.str())
  } else if t == FXP_STAT {
    Request::Stat(id, cur.str())
  } else if t == FXP_RENAME {
    let from = cur.str()
    Request::Rename(id, from, cur.str())
  } else if t == 200 {
    let name = cur.str()
    // Whatever is left belongs to the extension.
    let rest = FixedArray::make(cur.remaining(), b'\x00')
    for i = 0; i < rest.length(); i = i + 1 {
      rest[i] = cur.u8().to_byte()
    }
    Request::Extended(id, name, rest)
  } else {
    Request::Unknown(t)
  }
}

///|
/// The id of a request, or -1 for the ones that have none.
pub fn Request::id(self : Request) -> Int32 {
  match self {
    Init(_) => -1
    Open(id, _, _, _) => id
    Close(id, _) => id
    Read(id, _, _, _) => id
    Write(id, _, _, _) => id
    Lstat(id, _) => id
    Fstat(id, _) => id
    Setstat(id, _, _) => id
    Fsetstat(id, _, _) => id
    Opendir(id, _) => id
    Readdir(id, _) => id
    Remove(id, _) => id
    Mkdir(id, _, _) => id
    Rmdir(id, _) => id
    Realpath(id, _) => id
    Stat(id, _) => id
    Rename(id, _, _) => id
    Extended(id, _, _) => id
    Unknown(_) => -1
  }
}

///|
/// The VERSION reply body.
///
/// **Six extensions and their values, measured** -- not the eleven
/// `src/sshclient`'s comment remembers from OpenSSH's source, and not the
/// empty values the last three look like when only the NAMES are read:
///
/// ```
/// posix-rename@openssh.com "1"   statvfs@openssh.com  "2"
/// fstatvfs@openssh.com     "2"   hardlink@openssh.com "1"
/// fsync@openssh.com        "1"   lsetstat@openssh.com "1"
/// ```
///
/// Both mistakes were made here and both are invisible in a list of names:
/// the wrong count, and the wrong values, which make this reply 176 bytes
/// instead of the real server's 179.  The test compares all 179 bytes.
pub fn reply_version() -> FixedArray[Byte] {
  @sftp.sftp_cat([
    FixedArray::make(1, FXP_VERSION.to_byte()),
    u32_bytes(3),
    ext_pair("posix-rename@openssh.com", "1"),
    ext_pair("statvfs@openssh.com", "2"),
    ext_pair("fstatvfs@openssh.com", "2"),
    ext_pair("hardlink@openssh.com", "1"),
    ext_pair("fsync@openssh.com", "1"),
    ext_pair("lsetstat@openssh.com", "1"),
  ])
}

///|
/// One extension pair: name as a string, value as a string.
fn ext_pair(name : String, value : String) -> FixedArray[Byte] {
  @sftp.sftp_cat([
    @sshwire.write_ssh_string(@sftp.sftp_ascii(name)),
    @sshwire.write_ssh_string(@sftp.sftp_ascii(value)),
  ])
}

///|
/// The sentence the real server puts in a STATUS reply for a code.
///
/// Measured, and a closed set of seven: a server that invented a longer
/// sentence would still be understood by code that maps the CODE, and
/// would differ for every client that prints the text.
///
/// | code | sentence |
/// |---|---|
/// | 0 | `Success` |
/// | 1 | `End of file` |
/// | 2 | `No such file` |
/// | 3 | `Permission denied` |
/// | 4 | `Failure` |
/// | 5 | `Bad message` |
/// | 8 | `Operation unsupported` |
pub fn status_text(code : Int32) -> String {
  if code == FX_OK {
    "Success"
  } else if code == FX_EOF {
    "End of file"
  } else if code == FX_NO_SUCH_FILE {
    "No such file"
  } else if code == FX_PERMISSION_DENIED {
    "Permission denied"
  } else if code == FX_BAD_MESSAGE {
    "Bad message"
  } else if code == FX_OP_UNSUPPORTED {
    "Operation unsupported"
  } else {
    "Failure"
  }
}

///|
/// A STATUS reply body: type, id, code, message, empty language.
pub fn reply_status(id : Int32, code : Int32) -> FixedArray[Byte] {
  @sftp.sftp_cat([
    FixedArray::make(1, FXP_STATUS.to_byte()),
    u32_bytes(id),
    u32_bytes(code),
    @sshwire.write_ssh_string(@sftp.sftp_ascii(status_text(code))),
    @sshwire.write_ssh_string(@sftp.sftp_ascii("")),
  ])
}

///|
/// A HANDLE reply body.
pub fn reply_handle(id : Int32, handle : FixedArray[Byte]) -> FixedArray[Byte] {
  @sftp.sftp_cat([
    FixedArray::make(1, FXP_HANDLE.to_byte()),
    u32_bytes(id),
    @sshwire.write_ssh_string(handle),
  ])
}

///|
/// A DATA reply body.
pub fn reply_data(id : Int32, data : FixedArray[Byte]) -> FixedArray[Byte] {
  @sftp.sftp_cat([
    FixedArray::make(1, FXP_DATA.to_byte()),
    u32_bytes(id),
    @sshwire.write_ssh_string(data),
  ])
}

///|
/// An ATTRS reply body.
pub fn reply_attrs(id : Int32, attrs : @sftp.SftpAttrs) -> FixedArray[Byte] {
  @sftp.sftp_cat([
    FixedArray::make(1, FXP_ATTRS.to_byte()),
    u32_bytes(id),
    attrs.encode(),
  ])
}

///|
/// One entry of a NAME reply: filename, longname, attrs.
///
/// The `longname` is the `ls -l` line, and the SERVER builds it -- measured
/// on Windows as `-rw-******    1 -        -              13 Nov 11 13:52 a.txt`,
/// with literal asterisks where a unix mode string would be.  It is a
/// parameter here rather than a computed field because the column layout is
/// a formatting decision the caller (which knows the platform) owns.
pub(all) struct NameEntry {
  filename : String
  longname : String
  attrs : @sftp.SftpAttrs
}

///|
/// A NAME reply body: type, id, count, then each entry.
pub fn reply_name(id : Int32, entries : Array[NameEntry]) -> FixedArray[Byte] {
  let parts : Array[FixedArray[Byte]] = [
    FixedArray::make(1, FXP_NAME.to_byte()),
    u32_bytes(id),
    u32_bytes(entries.length()),
  ]
  for i = 0; i < entries.length(); i = i + 1 {
    parts.push(@sshwire.write_ssh_string(@sftp.sftp_ascii(entries[i].filename)))
    parts.push(@sshwire.write_ssh_string(@sftp.sftp_ascii(entries[i].longname)))
    parts.push(entries[i].attrs.encode())
  }
  @sftp.sftp_cat(parts)
}

///|
/// Four bytes, big endian.
fn u32_bytes(v : Int32) -> FixedArray[Byte] {
  @sshwire.write_u32(v.reinterpret_as_uint())
}
