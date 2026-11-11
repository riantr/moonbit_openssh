///| Loop #90: an interactive SFTP client over an abstract byte link.
///
/// ## Why this is separate from `@sftp.SftpSession`
///
/// `src/sftp/session.mbt` is a **scripted** state machine: it is handed
/// the whole list of operations up front and drives them to completion.
/// That is exactly right for a known-answer test and exactly wrong for
/// `scp`, which has to look at an answer before it knows what to ask next
/// (`stat` decides file-versus-directory, a directory listing decides how
/// many children to descend into).
///
/// So this is the other shape: one request, one reply, caller decides.
/// It reuses the same framing, builders and parsers -- there is still only
/// one implementation of the protocol.
///
/// ## The link is two function values, not a trait
///
/// `write` and `read` arrive as closures, which keeps this package free of
/// a generic bound and lets the same driver serve the two transports `scp`
/// needs: a spawned local `sftp-server.exe` (`src/subproc`) for `-D`, and
/// an SSH session channel later. `read` returns an **empty array at end of
/// stream** -- the transports cannot tell a closed pipe from a closed
/// channel and neither can this.

///|
/// What can go wrong.
pub(all) enum DriveError {
  /// the link refused a write, or the peer went away mid-packet
  LinkFailed
  /// the peer said something that is not SFTP
  Protocol(String)
  /// a request was answered with a non-OK STATUS
  Refused(Int32, String)
}

///|
/// The cursor: one id per request, and one reassembly buffer.
pub struct SftpDrive {
  write_fn : (FixedArray[Byte]) -> Bool
  read_fn : () -> FixedArray[Byte]
  inbuf : @sftp.SftpInbuf
  mut next_id : Int32
  mut version : Int32
  mut extensions : Array[String]
}

///|
pub fn SftpDrive::new(
  write_fn : (FixedArray[Byte]) -> Bool,
  read_fn : () -> FixedArray[Byte],
) -> SftpDrive {
  {
    write_fn,
    read_fn,
    inbuf: @sftp.SftpInbuf::new(),
    next_id: 0,
    version: 0,
    extensions: [],
  }
}

///|
/// Send INIT and read VERSION.
///
/// INIT is the one request with no id, so it cannot go through
/// `request`.  Its reply is the only packet that may arrive unsolicited.
pub fn SftpDrive::handshake(self : SftpDrive) -> Result[Unit, DriveError] {
  if !(self.write_fn)(@sftp.sftp_frame(@sftp.sftp_init(3))) {
    return Err(DriveError::LinkFailed)
  }
  match self.read_reply() {
    Err(e) => Err(e)
    Ok(@sftp.Version(v)) => {
      self.version = v.version
      self.extensions = v.ext_names
      Ok(())
    }
    Ok(_) => Err(DriveError::Protocol("first reply was not VERSION"))
  }
}

///|
/// Read one framed packet body, feeding the reassembler until it has one.
fn SftpDrive::read_body(
  self : SftpDrive,
) -> Result[FixedArray[Byte], DriveError] {
  while true {
    match self.inbuf.take() {
      Some(body) => return Ok(body)
      None => ()
    }
    let chunk = (self.read_fn)()
    if chunk.length() == 0 {
      return Err(DriveError::LinkFailed)
    }
    self.inbuf.feed(chunk)
  }
  Err(DriveError::LinkFailed)
}

///|
/// Read one reply and parse it, checking that the id matches the request
/// that is outstanding.
fn SftpDrive::read_reply(
  self : SftpDrive,
) -> Result[@sftp.SftpReply, DriveError] {
  match self.read_body() {
    Err(e) => Err(e)
    Ok(body) =>
      match @sftp.sftp_parse_reply(body) {
        @sftp.Rejected(err) =>
          Err(DriveError::Protocol(@sftp.sftp_error_name(err)))
        @sftp.Parsed(reply) => Ok(reply)
      }
  }
}

///|
/// Send one request body (unframed) and return its reply.
///
/// A reply whose id does not match the request that was just sent is a
/// protocol error rather than something to be reordered or buffered: SFTP
/// answers in any order, but this driver keeps exactly one request
/// outstanding, so a mismatch means the stream is out of step and every
/// later answer would be attributed to the wrong question.
fn SftpDrive::request(
  self : SftpDrive,
  body : FixedArray[Byte],
  id : Int32,
) -> Result[@sftp.SftpReply, DriveError] {
  if !(self.write_fn)(@sftp.sftp_frame(body)) {
    return Err(DriveError::LinkFailed)
  }
  match self.read_reply() {
    Err(e) => Err(e)
    Ok(reply) => {
      let got = @sftp.reply_id(reply)
      // VERSION has no id and is only legal as the first packet.
      match reply {
        @sftp.Version(_) => Ok(reply)
        _ =>
          if got != id {
            Err(DriveError::Protocol("reply id does not match request"))
          } else {
            Ok(reply)
          }
      }
    }
  }
}

///|
fn SftpDrive::take_id(self : SftpDrive) -> Int32 {
  self.next_id = self.next_id + 1
  self.next_id
}

///|
/// A STATUS reply that is not OK becomes `Refused`; OK becomes `Ok(())`.
///
/// `SSH_FXP_OK` is 0 (draft-ietf-secsh-filexfer-01 §4).  Keeping the code
/// and the server's own message is deliberate: `scp`'s sentences quote the
/// reason (`No such file or directory`), and it can only do that if the
/// code survives this far.
fn status_result(reply : @sftp.SftpReply) -> Result[Unit, DriveError] {
  match reply {
    @sftp.Status(st) =>
      if st.code == 0 {
        Ok(())
      } else {
        Err(DriveError::Refused(st.code, bytes_to_text(st.message)))
      }
    _ => Err(DriveError::Protocol("expected STATUS"))
  }
}

///|
pub fn SftpDrive::realpath(
  self : SftpDrive,
  path : String,
) -> Result[String, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_realpath(id, path), id) {
    Err(e) => Err(e)
    Ok(@sftp.Name(n)) =>
      if n.names.length() == 0 {
        Err(DriveError::Protocol("REALPATH returned no name"))
      } else {
        Ok(bytes_to_text(n.names[0].filename))
      }
    Ok(@sftp.Status(_) as st) =>
      match status_result(st) {
        Ok(_) => Err(DriveError::Protocol("REALPATH returned STATUS"))
        Err(e) => Err(e)
      }
    Ok(_) => Err(DriveError::Protocol("REALPATH returned an unexpected reply"))
  }
}

///|
pub fn SftpDrive::stat(
  self : SftpDrive,
  path : String,
) -> Result[@sftp.SftpAttrs, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_stat(id, path), id) {
    Err(e) => Err(e)
    Ok(@sftp.Attrs(a)) => Ok(a.attrs)
    Ok(@sftp.Status(_) as st) =>
      match status_result(st) {
        Ok(_) => Err(DriveError::Protocol("STAT returned OK with no attrs"))
        Err(e) => Err(e)
      }
    Ok(_) => Err(DriveError::Protocol("STAT returned an unexpected reply"))
  }
}

///|
/// `SSH_FXF_READ` / `WRITE` / `CREAT` / `TRUNC` / `EXCL` as the draft
/// numbers them.  Named here so the caller does not paste magic numbers.
pub fn pflag_read() -> Int32 {
  0x01
}

///|
pub fn pflag_write() -> Int32 {
  0x02
}

///|
pub fn pflag_creat() -> Int32 {
  0x08
}

///|
pub fn pflag_trunc() -> Int32 {
  0x10
}

///|
pub fn SftpDrive::open(
  self : SftpDrive,
  path : String,
  pflags : Int32,
) -> Result[FixedArray[Byte], DriveError] {
  let id = self.take_id()
  match
    self.request(@sftp.sftp_open(id, path, pflags, @sftp.SftpAttrs::none()), id) {
    Err(e) => Err(e)
    Ok(@sftp.Handle(h)) => Ok(h.handle)
    Ok(@sftp.Status(_) as st) =>
      match status_result(st) {
        Ok(_) => Err(DriveError::Protocol("OPEN returned OK with no handle"))
        Err(e) => Err(e)
      }
    Ok(_) => Err(DriveError::Protocol("OPEN returned an unexpected reply"))
  }
}

///|
pub fn SftpDrive::read(
  self : SftpDrive,
  handle : FixedArray[Byte],
  offset : UInt64,
  length : Int32,
) -> Result[FixedArray[Byte], DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_read(id, handle, offset, length), id) {
    Err(e) => Err(e)
    Ok(@sftp.Data(d)) => Ok(d.data)
    // End of file arrives as STATUS with code SSH_FX_EOF (1), not as an
    // empty DATA.  Measured against the real `sftp-server.exe`.
    Ok(@sftp.Status(st)) =>
      if st.code == 1 {
        Ok(FixedArray::make(0, b'\x00'))
      } else {
        Err(DriveError::Refused(st.code, bytes_to_text(st.message)))
      }
    Ok(_) => Err(DriveError::Protocol("READ returned an unexpected reply"))
  }
}

///|
pub fn SftpDrive::write(
  self : SftpDrive,
  handle : FixedArray[Byte],
  offset : UInt64,
  data : FixedArray[Byte],
) -> Result[Unit, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_write(id, handle, offset, data), id) {
    Err(e) => Err(e)
    Ok(reply) => status_result(reply)
  }
}

///|
pub fn SftpDrive::close(
  self : SftpDrive,
  handle : FixedArray[Byte],
) -> Result[Unit, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_close(id, handle), id) {
    Err(e) => Err(e)
    Ok(reply) => status_result(reply)
  }
}

///|
pub fn SftpDrive::mkdir(
  self : SftpDrive,
  path : String,
) -> Result[Unit, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_mkdir(id, path, @sftp.SftpAttrs::none()), id) {
    Err(e) => Err(e)
    Ok(reply) => status_result(reply)
  }
}

///|
pub fn SftpDrive::rmdir(
  self : SftpDrive,
  path : String,
) -> Result[Unit, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_rmdir(id, path), id) {
    Err(e) => Err(e)
    Ok(reply) => status_result(reply)
  }
}

///|
pub fn SftpDrive::remove(
  self : SftpDrive,
  path : String,
) -> Result[Unit, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_remove(id, path), id) {
    Err(e) => Err(e)
    Ok(reply) => status_result(reply)
  }
}

///|
pub fn SftpDrive::setstat(
  self : SftpDrive,
  path : String,
  attrs : @sftp.SftpAttrs,
) -> Result[Unit, DriveError] {
  let id = self.take_id()
  match self.request(@sftp.sftp_setstat(id, path, attrs), id) {
    Err(e) => Err(e)
    Ok(reply) => status_result(reply)
  }
}

///|
/// One directory listing, with the `SSH_FX_EOF` terminator already folded
/// away.
pub fn SftpDrive::list_dir(
  self : SftpDrive,
  path : String,
) -> Result[Array[(String, @sftp.SftpAttrs)], DriveError] {
  let open_id = self.take_id()
  let handle = match self.request(@sftp.sftp_opendir(open_id, path), open_id) {
    Err(e) => return Err(e)
    Ok(@sftp.Handle(h)) => h.handle
    Ok(@sftp.Status(_) as st) =>
      return match status_result(st) {
        Ok(_) => Err(DriveError::Protocol("OPENDIR returned OK with no handle"))
        Err(e) => Err(e)
      }
    Ok(_) =>
      return Err(DriveError::Protocol("OPENDIR returned an unexpected reply"))
  }
  let out : Array[(String, @sftp.SftpAttrs)] = []
  let mut done = false
  while !done {
    let id = self.take_id()
    match self.request(@sftp.sftp_readdir(id, handle), id) {
      Err(e) => {
        let _ = self.close(handle)
        return Err(e)
      }
      Ok(@sftp.Name(n)) =>
        for i = 0; i < n.names.length(); i = i + 1 {
          out.push((bytes_to_text(n.names[i].filename), n.names[i].attrs))
        }
      Ok(@sftp.Status(st)) =>
        if st.code == 1 {
          done = true
        } else {
          let _ = self.close(handle)
          return Err(DriveError::Refused(st.code, bytes_to_text(st.message)))
        }
      Ok(_) => {
        let _ = self.close(handle)
        return Err(DriveError::Protocol("READDIR returned an unexpected reply"))
      }
    }
  }
  match self.close(handle) {
    Err(e) => Err(e)
    Ok(_) => Ok(out)
  }
}

///|
/// Whether an ATTRS block describes a directory.
///
/// The permission word carries the POSIX file type in its top four bits;
/// `S_IFDIR` is `0040000`.  Absent permissions mean "not reported", which
/// is answered as `False` rather than guessed at -- a caller that needs to
/// know can `stat` again or treat it as a file and let the copy fail with
/// the server's own reason.
pub fn attrs_is_dir(a : @sftp.SftpAttrs) -> Bool {
  match a.permissions {
    None => false
    Some(p) => (p & 0xF000) == 0x4000
  }
}

///|
/// Bytes as text, latin-1 (SFTP filenames and messages are bytes).
pub fn bytes_to_text(b : FixedArray[Byte]) -> String {
  let out = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    out.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  out.to_string()
}
