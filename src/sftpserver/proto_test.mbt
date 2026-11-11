///| Loop #92: the server's two inverse halves, pinned to measured bytes.
///
/// Two kinds of assertion here, and the difference matters:
///
///   * **Reply builders** are compared against what the REAL
///     `sftp-server.exe` sent, byte for byte (`.loop92/probe_out.txt`).  A
///     reply that "looks right" but differs by three bytes is a reply the
///     client will mis-read, and this is the only way to know.
///   * **Request parsing** is checked by round-tripping bodies built by
///     `src/sftp`'s own builders, which Loop #90 already gated against the
///     real server.  A server that cannot parse its own client's requests
///     would fail there and is caught here, cheaply, on all four targets.

///|
/// Bytes as lowercase hex, for comparing against the recorded transcripts.
fn sh(a : FixedArray[Byte]) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < a.length(); i = i + 1 {
    let v = a[i].to_int()
    sb.write_string(digits.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(digits.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}

///|
/// The VERSION reply is the real server's 179 bytes, exactly.
///
/// This is the check that caught both mistakes in `reply_version`: the count
/// (six, not eleven) and the values (the last three are "1", not empty).
/// Comparing the NAMES would have passed with a body three bytes short.
test "the_version_reply_is_the_real_servers_179_bytes" {
  let want = "0200000003" +
    "00000018706f7369782d72656e616d65406f70656e7373682e636f6d0000000131" +
    "0000001373746174766673406f70656e7373682e636f6d0000000132" +
    "000000146673746174766673406f70656e7373682e636f6d0000000132" +
    "00000014686172646c696e6b406f70656e7373682e636f6d0000000131" +
    "000000116673796e63406f70656e7373682e636f6d0000000131" +
    "000000146c73657473746174406f70656e7373682e636f6d0000000131"
  let got = @sftpserver.reply_version()
  assert_eq(got.length(), 179)
  assert_eq(sh(got), want)
}

///|
/// The four STATUS replies are the real server's bytes, messages included.
///
/// The ids are the ones the probe used, so these are the exact replies from
/// `.loop92/probe_out.txt`, not re-derived ones.
test "the_status_replies_are_the_real_servers_bytes" {
  // id 3 -> No such file
  assert_eq(
    sh(@sftpserver.reply_status(3, @sftpserver.FX_NO_SUCH_FILE)),
    "6500000003000000020000000c4e6f20737563682066696c6500000000",
  )
  // id 7 -> End of file
  assert_eq(
    sh(@sftpserver.reply_status(7, @sftpserver.FX_EOF)),
    "6500000007000000010000000b456e64206f662066696c6500000000",
  )
  // id 8 -> Success
  assert_eq(
    sh(@sftpserver.reply_status(8, @sftpserver.FX_OK)),
    "650000000800000000000000075375636365737300000000",
  )
  // id 15 -> Failure (the real server's answer to mkdir on an existing dir)
  assert_eq(
    sh(@sftpserver.reply_status(15, @sftpserver.FX_FAILURE)),
    "650000000f00000004000000074661696c75726500000000",
  )
}

///|
/// A HANDLE reply is the real server's four-byte handle.
test "the_handle_reply_is_the_real_servers_bytes" {
  let handle : FixedArray[Byte] = FixedArray::from_array([
    0x00, 0x00, 0x00, 0x00,
  ])
  assert_eq(
    sh(@sftpserver.reply_handle(4, handle)),
    "66000000040000000400000000",
  )
}

///|
/// A DATA reply is the real server's bytes for the same payload.
test "the_data_reply_is_the_real_servers_bytes" {
  let payload = @sftp.sftp_ascii("hello loop92\n")
  assert_eq(
    sh(@sftpserver.reply_data(11, payload)),
    "670000000b0000000d68656c6c6f206c6f6f7039320a",
  )
}

///|
/// Every request shape this server accepts parses back to what the client
/// built.
///
/// The bodies come from `src/sftp`'s builders, so this also asserts that the
/// two halves of the protocol agree on the field order -- a server that read
/// `path` and `flags` in the wrong order would fail here rather than at the
/// far end of a network.
test "every_request_shape_parses_back" {
  let attrs = @sftp.SftpAttrs::none()
  match @sftpserver.parse_request(@sftp.sftp_stat(7, "/tmp/x")) {
    Stat(id, path) => {
      assert_eq(id, 7)
      assert_eq(path, "/tmp/x")
    }
    _ => abort("STAT did not parse as Stat")
  }
  match @sftpserver.parse_request(@sftp.sftp_realpath(8, ".")) {
    Realpath(id, path) => {
      assert_eq(id, 8)
      assert_eq(path, ".")
    }
    _ => abort("REALPATH did not parse as Realpath")
  }
  match @sftpserver.parse_request(@sftp.sftp_opendir(9, "dir")) {
    Opendir(id, path) => {
      assert_eq(id, 9)
      assert_eq(path, "dir")
    }
    _ => abort("OPENDIR did not parse as Opendir")
  }
  match @sftpserver.parse_request(@sftp.sftp_mkdir(10, "made", attrs)) {
    Mkdir(id, path, _) => {
      assert_eq(id, 10)
      assert_eq(path, "made")
    }
    _ => abort("MKDIR did not parse as Mkdir")
  }
  match @sftpserver.parse_request(@sftp.sftp_remove(11, "gone")) {
    Remove(id, path) => {
      assert_eq(id, 11)
      assert_eq(path, "gone")
    }
    _ => abort("REMOVE did not parse as Remove")
  }
  match @sftpserver.parse_request(@sftp.sftp_rmdir(12, "dir")) {
    Rmdir(id, path) => {
      assert_eq(id, 12)
      assert_eq(path, "dir")
    }
    _ => abort("RMDIR did not parse as Rmdir")
  }
  // The recursive-upload sequence's readdir on a handle: the handle is opaque
  // bytes and must come back byte for byte.
  let handle : FixedArray[Byte] = FixedArray::from_array([
    0x00, 0x00, 0x00, 0x01,
  ])
  match @sftpserver.parse_request(@sftp.sftp_readdir(13, handle)) {
    Readdir(id, got) => {
      assert_eq(id, 13)
      assert_eq(sh(got), "00000001")
    }
    _ => abort("READDIR did not parse as Readdir")
  }
  match @sftpserver.parse_request(@sftp.sftp_close(14, handle)) {
    Close(id, got) => {
      assert_eq(id, 14)
      assert_eq(sh(got), "00000001")
    }
    _ => abort("CLOSE did not parse as Close")
  }
}

///|
/// OPEN carries its flags and its ATTRS, in that order, and both survive.
///
/// The flags value `10` is the one the real client was recorded sending for
/// an upload (WRITE|CREATE), so this also pins the reading of that field.
test "open_carries_flags_and_attributes" {
  match
    @sftpserver.parse_request(
      @sftp.sftp_open(4, "up.txt", 10, @sftp.SftpAttrs::none()),
    ) {
    Open(id, path, flags, _) => {
      assert_eq(id, 4)
      assert_eq(path, "up.txt")
      assert_eq(flags, 10)
    }
    _ => abort("OPEN did not parse as Open")
  }
}

///|
/// READ and WRITE carry an offset and a length or a payload.
///
/// The offsets are 64-bit on the wire and the real client starts at 0; a
/// reader that took only the low half would work until a file got large,
/// which is the worst kind of bug to find later.
test "read_and_write_carry_the_offset" {
  let handle : FixedArray[Byte] = FixedArray::from_array([
    0x00, 0x00, 0x00, 0x00,
  ])
  match @sftpserver.parse_request(@sftp.sftp_read(5, handle, 0UL, 64)) {
    Read(id, got, offset, len) => {
      assert_eq(id, 5)
      assert_eq(sh(got), "00000000")
      assert_eq(offset, 0UL)
      assert_eq(len, 64)
    }
    _ => abort("READ did not parse as Read")
  }
  let payload = @sftp.sftp_ascii("hello")
  match @sftpserver.parse_request(@sftp.sftp_write(6, handle, 27UL, payload)) {
    Write(id, got, offset, data) => {
      assert_eq(id, 6)
      assert_eq(sh(got), "00000000")
      assert_eq(offset, 27UL)
      assert_eq(sh(data), sh(payload))
    }
    _ => abort("WRITE did not parse as Write")
  }
}

///|
/// INIT is the one request with no id, and it parses to its version.
test "init_has_no_id_and_carries_the_version" {
  let body = @sftp.sftp_init(3)
  match @sftpserver.parse_request(body) {
    Init(v) => assert_eq(v, 3)
    _ => abort("INIT did not parse as Init")
  }
  // And the server must not invent an id for it.
  assert_eq(@sftpserver.parse_request(body).id(), -1)
}

///|
/// A truncated or unknown request is reported, not obeyed and not panicked
/// on.
///
/// A server that panics on a short packet is a server one packet can stop,
/// and the real server's behaviour on an unknown type was measured as
/// "no reply at all" -- so this must be a value the caller can choose to
/// ignore rather than a crash.
test "an_unknown_or_truncated_request_is_not_a_panic" {
  match @sftpserver.parse_request(FixedArray::make(0, b'\x00')) {
    Unknown(_) => ()
    _ => abort("an empty body was not reported as unknown")
  }
  // Type 99 with an id, which this server does not implement.
  let body : FixedArray[Byte] = FixedArray::from_array([
    99, 0x00, 0x00, 0x00, 0x05,
  ])
  match @sftpserver.parse_request(body) {
    Unknown(t) => assert_eq(t, 99)
    _ => abort("type 99 was not reported as unknown")
  }
  // A STAT whose path string runs past the end of the packet.
  let short : FixedArray[Byte] = FixedArray::from_array([
    17, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20,
  ])
  let _ = @sftpserver.parse_request(short)
}
