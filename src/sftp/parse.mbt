///| SFTP v3 response packets
///
/// Field layouts transcribed from the server that produces them. The two that
/// most often go wrong are VERSION and STATUS, and both are wrong in a way
/// that a self-consistent implementation cannot detect:
///
///   * **VERSION carries an extension list.** `process_init` appends eleven
///     `string name, string value` pairs after the version number
///     (sftp-server.c:716-727), and the real client reads them in a
///     `while (sshbuf_len(msg) > 0)` loop (sftp-client.c:489-497). A parser
///     that calls `expect_end` after the version number works perfectly
///     against a mock and fails on the first byte of a real server's reply.
///   * **STATUS always carries a message and a language tag**, even when the
///     code is OK (`send_status`, sftp-server.c). Stopping after the code
///     leaves the cursor mid-packet and every later field reads garbage.
///
/// Results are a dedicated enum rather than a `(reply?, error?)` tuple,
/// matching `ParseResult` / `VerifyResult` in `src/hostkey` and `SshPacket?` in
/// `src/sshwire`. Beyond consistency it removes a real hazard: with two
/// optionals, "parsed but there was also an error" and "failed" are
/// distinguishable in the type but easy to conflate at a call site, and the
/// KAT needs to assert on *which* failure it was.

///|
/// One entry of a NAME reply: `string filename, string longname, ATTRS`.
pub(all) struct SftpNameEntry {
  filename : FixedArray[Byte]
  longname : FixedArray[Byte]
  attrs : SftpAttrs
}

///|
/// SSH2_FXP_VERSION (sftp.h:57).
///
/// `extensions` is the number of `name/value` pairs that followed, not the
/// number of bytes. We count them rather than keeping them: this client sends
/// no extensions yet, so the pairs are a compatibility fact to record, not
/// data to act on. What matters is that they are *consumed*, so the packet is
/// genuinely understood rather than partially skipped.
pub(all) struct SftpVersionReply {
  version : Int32
  extensions : Int32
  /// The extension names, in the order the server sent them.
  ///
  /// Kept because "the count" and "which names" are different facts and only
  /// the second one is actionable. `posix-rename@openssh.com` is what makes
  /// overwriting a file possible at all -- v3's RENAME is specified to fail
  /// when the target exists -- so a client that recorded only a number could
  /// never tell whether it may overwrite.
  ext_names : Array[String]
}

///|
/// SSH2_FXP_STATUS (sftp.h:58) -- the reply to every request that is not
/// answered with a HANDLE, DATA, NAME or ATTRS.
pub(all) struct SftpStatus {
  id : Int32
  code : Int32
  message : FixedArray[Byte]
  lang : FixedArray[Byte]
}

///|
/// SSH2_FXP_HANDLE (sftp.h:59) -- the answer to OPEN and OPENDIR.
pub(all) struct SftpHandleReply {
  id : Int32
  handle : FixedArray[Byte]
}

///|
/// SSH2_FXP_DATA (sftp.h:60) -- the payload of one READ.
pub(all) struct SftpDataReply {
  id : Int32
  data : FixedArray[Byte]
}

///|
/// SSH2_FXP_ATTRS (sftp.h:62) -- the answer to STAT and LSTAT.
pub(all) struct SftpAttrsReply {
  id : Int32
  attrs : SftpAttrs
}

///|
/// SSH2_FXP_NAME (sftp.h:61) -- the answer to READDIR, REALPATH and READLINK.
pub(all) struct SftpNameReply {
  id : Int32
  names : Array[SftpNameEntry]
}

///|
/// A parsed response, or the reason there is not one.
pub(all) enum SftpParse {
  Parsed(SftpReply)
  Rejected(SftpError)
}

///|
pub(all) enum SftpReply {
  Version(SftpVersionReply)
  Status(SftpStatus)
  Handle(SftpHandleReply)
  Data(SftpDataReply)
  Attrs(SftpAttrsReply)
  Name(SftpNameReply)
}

///|
/// The cursor's sticky error as a result, or `Continue` when it is clean.
///
/// Small helper because the pattern -- read some fields, check the cursor,
/// bail -- appears in all six parsers and getting it subtly different in one
/// of them is exactly the kind of drift a KAT is supposed to catch.
fn checked(e : SftpError?) -> Bool {
  e is Some(_)
}

///|
pub fn sftp_parse_version(body : FixedArray[Byte]) -> SftpParse {
  let c = SftpCursor::new(body)
  let t = c.u8()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  if t != FXP_VERSION {
    return Rejected(SftpError::Unexpected(t))
  }
  let v = c.u32()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  // The extension loop. `while remaining > 0` rather than a known count: the
  // count is not in the packet, so "until the packet ends" is the only correct
  // termination, and a server that sent an odd number of pairs ends up
  // Truncated here rather than silently dropping the last one.
  let mut n = 0
  let names : Array[String] = []
  while c.remaining() > 0 {
    let name = c.string()
    let _value = c.string()
    if checked(c.err) {
      return Rejected(c.err.unwrap())
    }
    names.push(bytes_text_of(name))
    n = n + 1
  }
  Parsed(SftpReply::Version({ version: v, extensions: n, ext_names: names, }))
}

///| 应答里的原始字节按 latin-1 变成文本——扩展名都是 ASCII,而 SFTP 的 string

///|
/// 是字节串,不是「某个编码的字符串」。
fn bytes_text_of(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
pub fn sftp_parse_status(body : FixedArray[Byte]) -> SftpParse {
  let c = SftpCursor::new(body)
  let t = c.u8()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  if t != FXP_STATUS {
    return Rejected(SftpError::Unexpected(t))
  }
  let id = c.u32()
  let code = c.u32()
  let msg = c.string()
  let lang = c.string()
  c.expect_end()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  Parsed(SftpReply::Status({ id, code, message: msg, lang, }))
}

///|
pub fn sftp_parse_handle(body : FixedArray[Byte]) -> SftpParse {
  let c = SftpCursor::new(body)
  let t = c.u8()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  if t != FXP_HANDLE {
    return Rejected(SftpError::Unexpected(t))
  }
  let id = c.u32()
  let h = c.string()
  c.expect_end()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  Parsed(SftpReply::Handle({ id, handle: h, }))
}

///|
pub fn sftp_parse_data(body : FixedArray[Byte]) -> SftpParse {
  let c = SftpCursor::new(body)
  let t = c.u8()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  if t != FXP_DATA {
    return Rejected(SftpError::Unexpected(t))
  }
  let id = c.u32()
  let d = c.string()
  c.expect_end()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  Parsed(SftpReply::Data({ id, data: d, }))
}

///|
pub fn sftp_parse_attrs(body : FixedArray[Byte]) -> SftpParse {
  let c = SftpCursor::new(body)
  let t = c.u8()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  if t != FXP_ATTRS {
    return Rejected(SftpError::Unexpected(t))
  }
  let id = c.u32()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  let a = c.attrs()
  // End-of-packet *is* correct here: ATTRS is the whole reply and nothing
  // follows the attribute block. This is the one response where the rule
  // applies, and it is why `expect_end` lives on the cursor rather than being
  // applied inside `attrs` -- inside NAME, attributes are mid-packet.
  c.expect_end()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  Parsed(SftpReply::Attrs({ id, attrs: a, }))
}

///|
pub fn sftp_parse_name(body : FixedArray[Byte]) -> SftpParse {
  let c = SftpCursor::new(body)
  let t = c.u8()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  if t != FXP_NAME {
    return Rejected(SftpError::Unexpected(t))
  }
  let id = c.u32()
  let count = c.u32()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  // sftp-common.c:138-139 caps a comparable count at 0x100000 before
  // looping. Same guard here: this number arrived on the wire and drives a
  // loop, so it gets bounded before it is trusted.
  if count < 0 || count > 0x100000 {
    return Rejected(SftpError::Unexpected(count))
  }
  let names : Array[SftpNameEntry] = []
  let mut i = 0
  while i < count {
    let fname = c.string()
    let lname = c.string()
    if checked(c.err) {
      return Rejected(c.err.unwrap())
    }
    let a = c.attrs()
    if checked(c.err) {
      return Rejected(c.err.unwrap())
    }
    names.push({ filename: fname, longname: lname, attrs: a, })
    i = i + 1
  }
  // Catches a lying `count`: too few triples and there are leftover bytes, too
  // many and the cursor ran out above.
  c.expect_end()
  if checked(c.err) {
    return Rejected(c.err.unwrap())
  }
  Parsed(SftpReply::Name({ id, names, }))
}

///|
/// Parse a packet body of any type we understand.
///
/// Dispatching in one place is what keeps the type constants honest: a builder
/// added without a matching arm here means the KAT cannot see that reply type
/// at all, rather than failing loudly.
pub fn sftp_parse_reply(body : FixedArray[Byte]) -> SftpParse {
  if body.length() < 1 {
    return Rejected(SftpError::Truncated)
  }
  match body[0].to_int() {
    FXP_VERSION => sftp_parse_version(body)
    FXP_STATUS => sftp_parse_status(body)
    FXP_HANDLE => sftp_parse_handle(body)
    FXP_DATA => sftp_parse_data(body)
    FXP_ATTRS => sftp_parse_attrs(body)
    FXP_NAME => sftp_parse_name(body)
    other => Rejected(SftpError::UnknownType(other))
  }
}

///|
/// The request id a reply answers, or -1 for VERSION (which has none).
///
/// Matching on this is what keeps a reply to an abandoned request from being
/// attributed to the request we are actually waiting for.
pub fn reply_id(r : SftpReply) -> Int32 {
  match r {
    SftpReply::Version(_) => -1
    SftpReply::Status(s) => s.id
    SftpReply::Handle(s) => s.id
    SftpReply::Data(s) => s.id
    SftpReply::Attrs(s) => s.id
    SftpReply::Name(s) => s.id
  }
}

///|
/// The name of a parsed reply's type.
pub fn reply_kind(r : SftpReply) -> String {
  match r {
    SftpReply::Version(_) => "Version"
    SftpReply::Status(_) => "Status"
    SftpReply::Handle(_) => "Handle"
    SftpReply::Data(_) => "Data"
    SftpReply::Attrs(_) => "Attrs"
    SftpReply::Name(_) => "Name"
  }
}

///|
/// The name of an `SftpError`, for the KAT. The payload-carrying variants
/// report their name only; a case that needs to pin the value carries it in
/// the vector.
pub fn sftp_error_name(e : SftpError) -> String {
  match e {
    SftpError::Truncated => "Truncated"
    SftpError::BadLength => "BadLength"
    SftpError::UnknownType(_) => "UnknownType"
    SftpError::TrailingData => "TrailingData"
    SftpError::Unexpected(_) => "Unexpected"
  }
}

///|
/// The name of a parse result, for the KAT and for the CLI's report.
pub fn sftp_reply_kind(p : SftpParse) -> String {
  match p {
    Rejected(e) => "Rejected(" + sftp_error_name(e) + ")"
    Parsed(r) => reply_kind(r)
  }
}
