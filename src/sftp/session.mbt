///| The SFTP session, as a transport-free state machine
///
/// This exists so that the two transports do not each own a copy of the
/// protocol. Both `src/sshclient` and `src/wtlive` drive a *socket*, and
/// everything above the socket -- which request goes out next, which reply id
/// we are waiting for, when a READDIR is finished, how the READ offset
/// accumulates -- is identical between them and identical between the native
/// client and the browser Worker. So it lives here, once.
///
/// The driver contract is deliberately tiny:
///
///     let s = SftpSession::new(ops)     // queues INIT
///     loop:
///       for each framed packet in s.take_out():  put it on the channel
///       s.pump()                               // drain + advance
///       s.feed(channel_data_payload)           // for each inbound CHANNEL_DATA
///     until s.done() or s.failed()
///
/// `take_out` before the first `pump` is what puts INIT on the wire, so the
/// caller never has to know that INIT carries no request id.
///
/// Results are only complete once an operation *and* its CLOSE have finished,
/// so `results()` never returns a half-filled directory.

///|
/// One scripted operation.
pub(all) enum SftpOp {
  /// REALPATH -- where the session actually landed
  Realpath(String)
  /// STAT on a path
  Stat(String)
  /// OPENDIR + READDIR until the server says EOF, then CLOSE
  ListDir(String)
  /// OPEN + READ until EOF, then CLOSE; returns the bytes
  ReadFile(String)
  /// OPEN for writing, WRITE the whole payload in chunks, then CLOSE.
  ///
  /// The chunk size is ours to choose and is deliberately not "as large as
  /// possible": one packet has to survive the channel's window and
  /// max_packet splitting either way, and a smaller chunk makes the offset
  /// arithmetic visible in the byte transcript instead of hidden inside one
  /// enormous frame.
  WriteFile(String, FixedArray[Byte])
  /// SETSTAT on a path -- size, permissions and/or times, whichever the
  /// attributes carry.
  SetAttrs(String, SftpAttrs)
  /// The single-path operations that all answer with a STATUS.
  MakeDir(String, SftpAttrs)
  RemovePath(String)
  RemoveDir(String)
  /// RENAME. Prefers `posix-rename@openssh.com` when the server advertised it
  /// in VERSION, because v3's RENAME is specified to fail when the target
  /// already exists and that makes "overwrite" impossible without an
  /// extension. A server that did not advertise it gets the v3 form, and
  /// reports the refusal as a refusal rather than silently doing nothing.
  Rename(String, String)
}

///|
/// What one operation produced.
///
/// A failure carries the SFTP status code rather than becoming a transport
/// error, because "no such file" is a *successful* SFTP exchange: the request
/// went out, the server answered, and the answer was `SSH2_FX_NO_SUCH_FILE`.
/// Reporting that as a protocol failure would make a routine negative test look
/// like a broken client.
pub(all) enum SftpOpResult {
  RealpathOk(String)
  Attrs(SftpAttrs)
  /// (filename, size, is_dir) -- size is -1 when not reported or too big for Int
  Listing(Array[(String, Int32, Bool)])
  Contents(FixedArray[Byte])
  /// SFTP status code, and its message
  Failed(Int32, String)
  /// A mutating operation that the server accepted: how many bytes it wrote,
  /// or 0 for the ones with nothing to report.
  ///
  /// Separate from `Failed` for the same reason the read side is: a STATUS
  /// with a non-zero code is an answer, not a broken exchange.
  Wrote(Int32)
  Changed
}

///|
const PH_VERSION : Int32 = 0

///|
const PH_RUNNING : Int32 = 1

///|
const PH_DONE : Int32 = 2

///|
const PH_FAILED : Int32 = 3

///|
/// 一个子步骤:某个请求已经在等它的应答
enum Step {
  WantVersion
  WantRealpath(Int32)
  WantStat(Int32)
  WantOpenDir(Int32)
  WantReadDir(Int32)
  WantOpenFile(Int32)
  WantRead(Int32)
  WantClose(Int32)
  WantOpenWrite(Int32)
  WantWrite(Int32)
  /// SETSTAT / MKDIR / REMOVE / RMDIR: one request, one STATUS, no handle.
  WantSimple(Int32)
}

///|
/// An SFTP session in progress.
pub(all) struct SftpSession {
  mut inbuf : SftpInbuf
  mut outq : Array[FixedArray[Byte]]
  mut ops : Array[SftpOp]
  mut results : Array[SftpOpResult]
  mut op_index : Int32
  mut next_id : Int32
  mut step : Step
  mut phase : Int32
  /// handle held by the operation in progress (operations are serial)
  mut handle : FixedArray[Byte]
  mut offset : UInt64
  mut chunks : Array[FixedArray[Byte]]
  /// entries gathered by the current ListDir
  mut listing : Array[(String, Int32, Bool)]
  /// set when the current ListDir failed part way
  mut listing_failed : SftpOpResult?
  /// the Contents the current ReadFile assembled
  mut contents : SftpOpResult?
  /// the payload the current WriteFile still has to send
  mut pending_write : FixedArray[Byte]
  /// how many bytes of it the server has accepted so far, which is also the
  /// offset of the next WRITE
  mut written : Int32
  /// the extension names the server listed in VERSION, in the order it sent
  /// them. Kept as names rather than as a count: the count is already
  /// reported, and a client that decides behaviour from a number has to know
  /// which number means which thing.
  mut ext_names : Array[String]
  mut version : Int32
  mut extensions : Int32
  mut requests_sent : Int32
  mut replies_recv : Int32
  mut sftp_bytes_in : Int32
  mut failure : String?
}

///|
/// A new session, with INIT already queued.
pub fn SftpSession::new(ops : Array[SftpOp]) -> SftpSession {
  let s = {
    inbuf: SftpInbuf::new(),
    outq: [],
    ops,
    results: [],
    op_index: 0,
    // id 0 is not special to the protocol, but a table starting at 0
    // conflates "nothing sent yet" with "the first request".
    next_id: 1,
    step: Step::WantVersion,
    phase: PH_VERSION,
    handle: FixedArray::make(0, b'\x00'),
    offset: 0,
    chunks: [],
    listing: [],
    listing_failed: None,
    contents: None,
    pending_write: FixedArray::make(0, b'\x00'),
    written: 0,
    ext_names: [],
    version: 0,
    extensions: 0,
    requests_sent: 0,
    replies_recv: 0,
    sftp_bytes_in: 0,
    failure: None,
  }
  s.outq.push(sftp_frame(sftp_init(SFTP_VERSION)))
  s.requests_sent = s.requests_sent + 1
  s
}

///|
/// 取走排队中的请求(已带长度前缀)
pub fn SftpSession::take_out(self : SftpSession) -> Array[FixedArray[Byte]] {
  let out = self.outq
  self.outq = []
  out
}

///|
pub fn SftpSession::done(self : SftpSession) -> Bool {
  self.phase == PH_DONE
}

///|
pub fn SftpSession::failed(self : SftpSession) -> Bool {
  self.phase == PH_FAILED
}

///|
pub fn SftpSession::failure_reason(self : SftpSession) -> String {
  match self.failure {
    Some(s) => s
    None => ""
  }
}

///|
pub fn SftpSession::results_of(self : SftpSession) -> Array[SftpOpResult] {
  self.results
}

///|
pub fn SftpSession::version_of(self : SftpSession) -> Int32 {
  self.version
}

///|
pub fn SftpSession::extensions_of(self : SftpSession) -> Int32 {
  self.extensions
}

///|
pub fn SftpSession::requests_sent_count(self : SftpSession) -> Int32 {
  self.requests_sent
}

///|
pub fn SftpSession::replies_recv_count(self : SftpSession) -> Int32 {
  self.replies_recv
}

///|
pub fn SftpSession::bytes_in_count(self : SftpSession) -> Int32 {
  self.sftp_bytes_in
}

///|
/// Absorb the payload of one inbound CHANNEL_DATA.
///
/// Nothing is parsed here. CHANNEL_DATA boundaries and SFTP packet boundaries
/// are unrelated, and conflating them is the bug this whole file exists to
/// prevent.
pub fn SftpSession::feed(self : SftpSession, chunk : FixedArray[Byte]) -> Unit {
  self.inbuf.feed(chunk)
}

///|
/// Drain buffered packets and advance.
///
/// Call it after every `feed`, and also whenever the driver is about to block
/// on a read: a reply may already be sitting in the buffer while the socket has
/// nothing left, and stopping there is how a client ends up waiting forever for
/// a packet it has already received.
pub fn SftpSession::pump(self : SftpSession) -> Unit {
  let packets = self.inbuf.drain()
  // A latched stream failure has to end the session, not just stop handing out
  // packets.  It is checked *after* the drain as well as before it, because
  // `drain` is where an over-long length is discovered
  // (`SFTP_MAX_MSG_LENGTH`, sftp-client.c:195 rejects before reserving for it).
  // Otherwise a peer that claims a length we refuse leaves the driver waiting
  // for a reply that is never coming, and the symptom is a hang rather than a
  // refusal.
  match self.inbuf.failure() {
    Some(e) => {
      self.phase = PH_FAILED
      self.failure = Some("framing: " + sftp_error_name(e))
      return
    }
    None => ()
  }
  for i = 0; i < packets.length(); i = i + 1 {
    self.replies_recv = self.replies_recv + 1
    self.sftp_bytes_in = self.sftp_bytes_in + packets[i].length()
    match sftp_parse_reply(packets[i]) {
      Rejected(e) => {
        // A reply we cannot parse is fatal for the session: we no longer know
        // where in the exchange we are, and carrying on would attribute a
        // later reply to the wrong request.
        self.phase = PH_FAILED
        self.failure = Some("unparsable reply: " + sftp_error_name(e))
        return
      }
      Parsed(r) => self.on_reply(r)
    }
  }
}

///|
/// Attribute one parsed reply to the step waiting for it.
///
/// A reply whose id is not the one we want is dropped rather than treated as
/// fatal: v3 has no unsolicited replies, but a reply to a request we already
/// abandoned is harmless, and killing the session over it would turn a benign
/// race into an outage. Being strict about the id is also what keeps two
/// operations from stealing each other's replies.
fn SftpSession::on_reply(self : SftpSession, r : SftpReply) -> Unit {
  match self.step {
    WantVersion =>
      match r {
        Version(v) => {
          self.version = v.version
          self.extensions = v.extensions
          // Keep the names, not just the count: which extensions exist is the
          // only part that can be acted on, and `Rename` below decides between
          // the v3 message and the extension by looking at this.
          self.ext_names = v.ext_names
          self.phase = PH_RUNNING
          self.begin_op()
        }
        // Anything before VERSION is ignored, which is what the real client
        // does -- it waits for VERSION specifically (sftp-client.c:474-484).
        _ => ()
      }
    WantRealpath(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Name(nm) =>
          if nm.names.length() < 1 {
            // REALPATH always answers with exactly one name. Zero entries is
            // not "an empty path" -- it means the reply is not the shape we
            // asked for, and reporting it as a path would hide that.
            self.results.push(Failed(-1, "realpath returned no name"))
          } else {
            self.results.push(RealpathOk(bytes_text(nm.names[0].filename)))
          }
        Status(st) => self.results.push(Failed(st.code, bytes_text(st.message)))
        _ => self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
      }
      self.next_op()
    }
    WantStat(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Attrs(a) => self.results.push(Attrs(a.attrs))
        Status(st) => self.results.push(Failed(st.code, bytes_text(st.message)))
        _ => self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
      }
      self.next_op()
    }
    WantOpenDir(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Handle(h) => {
          self.handle = h.handle
          self.listing = []
          self.listing_failed = None
          self.send_readdir()
        }
        Status(st) => {
          self.results.push(Failed(st.code, bytes_text(st.message)))
          self.next_op()
        }
        _ => {
          self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
          self.next_op()
        }
      }
    }
    WantReadDir(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Name(nm) => {
          for i = 0; i < nm.names.length(); i = i + 1 {
            let e = nm.names[i]
            self.listing.push(
              (
                bytes_text(e.filename),
                sftp_u64_to_int_of(e.attrs),
                is_dir_perm(e.attrs),
              ),
            )
          }
          self.send_readdir()
        }
        Status(st) => {
          // EOF is how a directory ends. Any other status is the answer
          // itself -- an error the caller has to see, not a silent empty list.
          if st.code != FX_EOF && st.code != FX_OK {
            self.listing_failed = Some(Failed(st.code, bytes_text(st.message)))
          }
          self.flush_listing()
          self.send_close()
        }
        _ => {
          self.listing_failed = Some(Failed(-1, "unexpected " + reply_kind(r)))
          self.flush_listing()
          self.send_close()
        }
      }
    }
    WantOpenFile(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Handle(h) => {
          self.handle = h.handle
          self.offset = 0
          self.chunks = []
          self.contents = None
          self.send_read()
        }
        Status(st) => {
          self.results.push(Failed(st.code, bytes_text(st.message)))
          self.next_op()
        }
        _ => {
          self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
          self.next_op()
        }
      }
    }
    WantRead(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Data(d) => {
          self.chunks.push(d.data)
          // The offset is over the **whole file**, so it must accumulate.
          // Reset it each round and every read returns the head of the file,
          // while the total length still looks plausible -- the worst kind of
          // bug to find.
          self.offset = self.offset + d.data.length().to_uint64()
          // A short chunk is NOT end of file: the server may return less than
          // asked. Treating a short read as EOF truncates every file larger
          // than one read. Only STATUS(EOF) ends it.
          if d.data.length() == 0 {
            self.contents = Some(Contents(sftp_cat(self.chunks)))
            self.send_close()
          } else {
            self.send_read()
          }
        }
        Status(st) => {
          if st.code == FX_EOF {
            self.contents = Some(Contents(sftp_cat(self.chunks)))
          } else {
            self.results.push(Failed(st.code, bytes_text(st.message)))
            self.contents = None
          }
          self.send_close()
        }
        _ => {
          self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
          self.contents = None
          self.send_close()
        }
      }
    }
    WantClose(id) => {
      if reply_id(r) != id {
        return
      }
      self.flush_contents()
      self.next_op()
    }
    WantOpenWrite(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Handle(h) => {
          self.handle = h.handle
          self.written = 0
          self.send_write()
        }
        Status(st) => {
          self.results.push(Failed(st.code, bytes_text(st.message)))
          self.pending_write = FixedArray::make(0, b'\x00')
          self.next_op()
        }
        _ => {
          self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
          self.pending_write = FixedArray::make(0, b'\x00')
          self.next_op()
        }
      }
    }
    WantWrite(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Status(st) =>
          if st.code == FX_OK {
            self.send_write()
          } else {
            self.results.push(Failed(st.code, bytes_text(st.message)))
            // Still close the handle: the OPEN succeeded, so the server is
            // holding a descriptor, and leaving it open leaks it until the
            // channel goes away.
            self.send_close()
          }
        _ => {
          self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
          self.send_close()
        }
      }
    }
    WantSimple(id) => {
      if reply_id(r) != id {
        return
      }
      match r {
        Status(st) => {
          if st.code == FX_OK {
            self.results.push(Changed)
          } else {
            self.results.push(Failed(st.code, bytes_text(st.message)))
          }
          self.next_op()
        }
        // An EXTENDED reply answers with its own message type when the
        // extension defines a payload. None of the extensions used here do,
        // so anything else is genuinely unexpected rather than merely
        // unrecognised -- and silently accepting it would let an operation
        // report success for a reply that proved nothing.
        _ => {
          self.results.push(Failed(-1, "unexpected " + reply_kind(r)))
          self.next_op()
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// driving the script
// ---------------------------------------------------------------------------

///|
fn SftpSession::take_id(self : SftpSession) -> Int32 {
  let id = self.next_id
  self.next_id = id + 1
  id
}

///|
fn SftpSession::queue(self : SftpSession, body : FixedArray[Byte]) -> Unit {
  self.outq.push(sftp_frame(body))
  self.requests_sent = self.requests_sent + 1
}

///|
fn SftpSession::begin_op(self : SftpSession) -> Unit {
  if self.op_index >= self.ops.length() {
    self.phase = PH_DONE
    return
  }
  match self.ops[self.op_index] {
    SftpOp::Realpath(p) => {
      let id = self.take_id()
      self.step = WantRealpath(id)
      self.queue(sftp_realpath(id, p))
    }
    SftpOp::Stat(p) => {
      let id = self.take_id()
      self.step = WantStat(id)
      self.queue(sftp_stat(id, p))
    }
    SftpOp::ListDir(p) => {
      let id = self.take_id()
      self.step = WantOpenDir(id)
      self.queue(sftp_opendir(id, p))
    }
    SftpOp::ReadFile(p) => {
      let id = self.take_id()
      self.step = WantOpenFile(id)
      self.queue(sftp_open(id, p, FXF_READ, SftpAttrs::none()))
    }
    SftpOp::WriteFile(p, data) => {
      let id = self.take_id()
      self.step = WantOpenWrite(id)
      // The payload is stashed **before** the OPEN is queued, even though
      // `queue` only appends to a buffer and nothing reads it yet.  The HANDLE
      // that comes back sends the first WRITE, and that path reads
      // `pending_write`; assigning after the queue works today by accident and
      // breaks the day `queue` grows a flush.
      self.pending_write = data
      self.written = 0
      // TRUNC + CREAT so the result is the payload and not the payload appended
      // to whatever was there. Both bits are required: CREAT alone leaves an
      // existing file's contents in front of what we write.
      self.queue(
        sftp_open(id, p, FXF_WRITE | FXF_CREAT | FXF_TRUNC, SftpAttrs::none()),
      )
    }
    SftpOp::SetAttrs(p, attrs) => {
      let id = self.take_id()
      self.step = WantSimple(id)
      self.queue(sftp_setstat(id, p, attrs))
    }
    SftpOp::MakeDir(p, attrs) => {
      let id = self.take_id()
      self.step = WantSimple(id)
      self.queue(sftp_mkdir(id, p, attrs))
    }
    SftpOp::RemovePath(p) => {
      let id = self.take_id()
      self.step = WantSimple(id)
      self.queue(sftp_remove(id, p))
    }
    SftpOp::RemoveDir(p) => {
      let id = self.take_id()
      self.step = WantSimple(id)
      self.queue(sftp_rmdir(id, p))
    }
    SftpOp::Rename(from, to) => {
      let id = self.take_id()
      self.step = WantSimple(id)
      if self.has_extension(EXT_POSIX_RENAME) {
        self.queue(
          sftp_extended(id, EXT_POSIX_RENAME, sftp_posix_rename_body(from, to)),
        )
      } else {
        self.queue(sftp_rename(id, from, to))
      }
    }
  }
}

///|
fn SftpSession::next_op(self : SftpSession) -> Unit {
  self.op_index = self.op_index + 1
  self.begin_op()
}

///|
fn SftpSession::send_readdir(self : SftpSession) -> Unit {
  let id = self.take_id()
  self.step = WantReadDir(id)
  self.queue(sftp_readdir(id, self.handle))
}

///|
fn SftpSession::send_read(self : SftpSession) -> Unit {
  let id = self.take_id()
  self.step = WantRead(id)
  self.queue(sftp_read(id, self.handle, self.offset, sftp_read_length(32768)))
}

///|
fn SftpSession::send_close(self : SftpSession) -> Unit {
  let id = self.take_id()
  self.step = WantClose(id)
  self.queue(sftp_close(id, self.handle))
}

///|
/// 发出下一块 WRITE,或者在整份数据写完后收尾。
///
/// 三件事都是 load-bearing,而且三件都和 offset 有关:
///
///  1. `written` is a **file** offset, not "bytes still to send". The server
///     does `lseek(fd, off, SEEK_SET)` before every write
///     (`process_write`, sftp-server.c:865-866), so sending the same offset
///     twice overwrites instead of appends, and the file ends up with a
///     correct-looking length and wrong contents.
///  2. An empty payload is sent as **zero** WRITE requests, not one empty
///     one. A client that sends an empty WRITE gets STATUS(OK) for a write of
///     nothing, which looks identical to having written the file -- and then
///     TRUNC has already destroyed the old contents, so "create an empty
///     file" and "write a file" become indistinguishable at the wire.
///  3. A write that fails still closes the handle, because the OPEN
///     succeeded and the server is holding a descriptor.
///
/// `written` is advanced as each WRITE is **queued**, not when it is
/// acknowledged. It is therefore "bytes handed to the channel so far", which
/// is the same number as the offset of the next WRITE -- and the number a
/// partial write would have to resume from. Waiting for the STATUS to advance
/// it looks more cautious and is not: it re-sends the same chunk at the same
/// offset forever, because nothing else moves it.
fn SftpSession::send_write(self : SftpSession) -> Unit {
  if self.written >= self.pending_write.length() {
    self.results.push(Wrote(self.written))
    self.pending_write = FixedArray::make(0, b'\x00')
    self.send_close()
    return
  }
  let id = self.take_id()
  self.step = WantWrite(id)
  let want = sftp_write_length(32768)
  let left = self.pending_write.length() - self.written
  let n = if left < want { left } else { want }
  let chunk : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    chunk[i] = self.pending_write[self.written + i]
  }
  self.queue(sftp_write(id, self.handle, self.written.to_uint64(), chunk))
  self.written = self.written + n
}

///|
/// 版本协商里服务器报过的扩展名里有没有它。
///
/// 名字比对而不是「扩展数量 >= N」:数量是服务器的属性,和「哪些名字」没有
/// 映射关系,用数量去推断能力,等于把两个不同的事实当成一个。
pub fn SftpSession::has_extension(self : SftpSession, name : String) -> Bool {
  for i = 0; i < self.ext_names.length(); i = i + 1 {
    if self.ext_names[i] == name {
      return true
    }
  }
  false
}

///|
/// 版本协商里服务器报过的扩展名,原序。
pub fn SftpSession::extension_names(self : SftpSession) -> Array[String] {
  self.ext_names
}

// ---------------------------------------------------------------------------
// assembling one operation's result
// ---------------------------------------------------------------------------

///|
/// 把攒到的目录条目作为**一条**结果落定
fn SftpSession::flush_listing(self : SftpSession) -> Unit {
  match self.listing_failed {
    Some(v) => self.results.push(v)
    None => self.results.push(Listing(self.listing))
  }
  self.listing = []
  self.listing_failed = None
}

///|
fn SftpSession::flush_contents(self : SftpSession) -> Unit {
  match self.contents {
    Some(v) => self.results.push(v)
    None => ()
  }
  self.contents = None
}

///| S_IFMT / S_IFDIR: a directory is 0x4000 in the permission bits. The server

///| may not report permissions at all, so an absent field means "not known"

///|
/// and we say file rather than guess.
fn is_dir_perm(a : SftpAttrs) -> Bool {
  match a.permissions {
    Some(p) => (p & 0xF000) == 0x4000
    None => false
  }
}

///|
fn bytes_text(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  sb.to_string()
}

///|
fn sftp_u64_to_int_of(a : SftpAttrs) -> Int32 {
  match a.size {
    Some(v) => sftp_u64_to_int(v)
    None => -1
  }
}
