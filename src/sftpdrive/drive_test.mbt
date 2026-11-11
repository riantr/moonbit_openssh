///| Loop #90: the interactive driver, against a scripted peer.
///
/// The peer here is a fake: it holds a queue of reply bodies and answers
/// whatever the driver sends with the next one.  That is enough to pin the
/// four behaviours that a real `sftp-server.exe` would otherwise be the
/// only witness to -- framing, id matching, `SSH_FX_EOF` on READ, and the
/// permission bits that decide directory-versus-file.
///
/// The frames are built by hand rather than with a builder, because SFTP
/// has no *reply* builders: replies are what a server writes, and this
/// package only ever writes requests.

///|
struct FakeServer {
  replies : Array[FixedArray[Byte]]
  requests : Array[FixedArray[Byte]]
  mut index : Int32
}

///|
fn u32(v : Int32) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  out[0] = ((v >> 24) & 0xFF).to_byte()
  out[1] = ((v >> 16) & 0xFF).to_byte()
  out[2] = ((v >> 8) & 0xFF).to_byte()
  out[3] = (v & 0xFF).to_byte()
  out
}

///|
fn sftp_string(s : FixedArray[Byte]) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(4 + s.length(), b'\x00')
  let n = u32(s.length())
  for i = 0; i < 4; i = i + 1 {
    out[i] = n[i]
  }
  for i = 0; i < s.length(); i = i + 1 {
    out[4 + i] = s[i]
  }
  out
}

///|
fn cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut at = 0
  for i = 0; i < parts.length(); i = i + 1 {
    for j = 0; j < parts[i].length(); j = j + 1 {
      out[at + j] = parts[i][j]
    }
    at = at + parts[i].length()
  }
  out
}

///|
fn empty_bytes() -> FixedArray[Byte] {
  FixedArray::make(0, b'\x00')
}

///|
fn ascii(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = s[i].to_byte()
  }
  out
}

///|
/// Add the `u32 length` prefix.
///
/// The driver's reassembler (`@sftp.SftpInbuf`) hands back the body *after*
/// the prefix, so the bytes a link returns have to be framed.  Leaving this
/// out made every request in this file fail as "the peer is not speaking
/// SFTP" -- which is exactly what it looked like, from the driver's side.
fn framed(body : FixedArray[Byte]) -> FixedArray[Byte] {
  cat([u32(body.length()), body])
}

///|
fn version_reply(v : Int32) -> FixedArray[Byte] {
  // type VERSION(2), version -- and NOTHING else when there are no
  // extensions.
  //
  // This cost a debugging round: `@sftp.sftp_parse_version` reads the
  // extension list until the packet ends (`while c.remaining() > 0`),
  // because the count is not in the packet.  Writing a `u32(0)` count here
  // made the parser read that zero as a string length and then run out of
  // bytes -- reported as `Protocol(Truncated)`.
  framed(cat([FixedArray::make(1, 2), u32(v)]))
}

///|
fn status_reply(id : Int32, code : Int32, msg : String) -> FixedArray[Byte] {
  // type STATUS(101), id, code, message, lang
  framed(
    cat([
      FixedArray::make(1, 101),
      u32(id),
      u32(code),
      sftp_string(ascii(msg)),
      sftp_string(empty_bytes()),
    ]),
  )
}

///|
fn attrs_reply(id : Int32, permissions : Int32) -> FixedArray[Byte] {
  // type ATTRS(105), id, flags(PERMISSIONS=4), permissions
  framed(cat([FixedArray::make(1, 105), u32(id), u32(4), u32(permissions)]))
}

///|
fn make_drive(s : FakeServer) -> @sftpdrive.SftpDrive {
  @sftpdrive.SftpDrive::new(
    fn(bytes) {
      s.requests.push(bytes)
      true
    },
    fn() {
      if s.index >= s.replies.length() {
        return empty_bytes()
      }
      let r = s.replies[s.index]
      s.index = s.index + 1
      r
    },
  )
}

///|
fn describe(e : @sftpdrive.DriveError) -> String {
  match e {
    @sftpdrive.LinkFailed => "LinkFailed"
    @sftpdrive.Protocol(why) => "Protocol(" + why + ")"
    @sftpdrive.Refused(code, msg) =>
      "Refused(" + code.to_string() + ", " + msg + ")"
  }
}

///|
test "handshake reads VERSION and keeps the version" {
  let s : FakeServer = { replies: [], requests: [], index: 0, }
  s.replies.push(version_reply(3))
  let d = make_drive(s)
  match d.handshake() {
    Err(e) => fail("handshake should succeed, got " + describe(e))
    Ok(_) => {
      assert_eq(d.version, 3)
      // One request went out, and it is INIT framed: length prefix then
      // type 1 then version 3.
      assert_eq(s.requests.length(), 1)
      let sent = s.requests[0]
      assert_eq(sent.length(), 9)
      assert_eq(sent[0].to_int(), 0)
      assert_eq(sent[3].to_int(), 5)
      assert_eq(sent[4].to_int(), 1)
      assert_eq(sent[8].to_int(), 3)
    }
  }
}

///|
test "READ answering STATUS code 1 is end of file, not a failure" {
  let s : FakeServer = { replies: [], requests: [], index: 0, }
  s.replies.push(version_reply(3))
  // No OPEN here: this asks READ directly with a made-up handle, so the
  // READ is id 1 and the next reply must belong to id 1.
  s.replies.push(status_reply(1, 1, "End of file"))
  let d = make_drive(s)
  let _ = d.handshake()
  let offset : UInt64 = 0
  match d.read(ascii("h"), offset, 64) {
    Err(_) => fail("EOF must not be an error")
    Ok(data) => assert_eq(data.length(), 0)
  }
}

///|
test "the permission bits decide directory versus file" {
  // 0x41ED is a directory with 0755; 0x81A4 is a regular file with 0644.
  let s : FakeServer = { replies: [], requests: [], index: 0, }
  s.replies.push(version_reply(3))
  s.replies.push(attrs_reply(1, 0x41ED))
  let d = make_drive(s)
  let _ = d.handshake()
  match d.stat("srv") {
    Err(_) => fail("stat should succeed")
    Ok(a) => assert_true(@sftpdrive.attrs_is_dir(a))
  }
  let s2 : FakeServer = { replies: [], requests: [], index: 0, }
  s2.replies.push(version_reply(3))
  s2.replies.push(attrs_reply(1, 0x81A4))
  let d2 = make_drive(s2)
  let _ = d2.handshake()
  match d2.stat("a.txt") {
    Err(_) => fail("stat should succeed")
    Ok(a) => assert_false(@sftpdrive.attrs_is_dir(a))
  }
}

///|
test "a reply carrying the wrong id is a protocol error, not a buffered one" {
  let s : FakeServer = { replies: [], requests: [], index: 0, }
  s.replies.push(version_reply(3))
  // The driver will send STAT with id 1 and get an ATTRS for id 99.
  s.replies.push(attrs_reply(99, 0x81A4))
  let d = make_drive(s)
  let _ = d.handshake()
  match d.stat("a.txt") {
    Ok(_) => fail("a mismatched id must not be accepted")
    Err(@sftpdrive.Protocol(_)) => ()
    Err(_) => fail("expected a protocol error")
  }
}

///|
test "a REFUSED status keeps the server's own reason" {
  let s : FakeServer = { replies: [], requests: [], index: 0, }
  s.replies.push(version_reply(3))
  s.replies.push(status_reply(1, 2, "No such file"))
  let d = make_drive(s)
  let _ = d.handshake()
  match d.stat("nope") {
    Ok(_) => fail("a refusal must not be Ok")
    Err(@sftpdrive.Refused(code, msg)) => {
      assert_eq(code, 2)
      assert_eq(msg, "No such file")
    }
    Err(_) => fail("expected Refused")
  }
}

///|
test "a closed link is a link failure, not an empty file" {
  let s : FakeServer = { replies: [], requests: [], index: 0, }
  // No replies at all: the reader answers end-of-stream immediately.
  let d = make_drive(s)
  match d.handshake() {
    Err(@sftpdrive.LinkFailed) => ()
    Err(_) => fail("expected LinkFailed")
    Ok(_) => fail("handshake cannot succeed with no reply")
  }
}
