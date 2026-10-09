///| SFTP v3 attributes
///
/// The order of the optional fields is fixed by the draft and is *not* the
/// order of the flag bits. Transcribed from `decode_attrib`
/// (sftp-common.c:104-146):
///
///     uint32   flags
///     uint64   size          if flags & ATTR_SIZE        (0x00000001)
///     uint32   uid           if flags & ATTR_UIDGID      (0x00000002)
///     uint32   gid           }
///     uint32   permissions   if flags & ATTR_PERMISSIONS (0x00000004)
///     uint32   atime         if flags & ATTR_ACMODTIME   (0x00000008)
///     uint32   mtime         }
///     uint32   count         if flags & ATTR_EXTENDED    (0x80000000)
///     count x (string type, string data)
///
/// Two things that are easy to get wrong and that the KAT pins:
///
///   * a field the flags do not select is **absent**, not zero. Reading
///     unconditionally and then ignoring the result happens to work when the
///     peer always sets every bit, and then fails on the first peer that
///     doesn't -- which is most of them.
///   * `decode_attrib` never calls `sshbuf_get_end`. Attributes appear
///     *mid-packet* (OPEN carries one after the path and flags; every entry of
///     a NAME reply carries one), so anything after the attributes belongs to
///     the enclosing packet, not to the attributes. See `SftpCursor::expect_end`
///     for where demanding end-of-packet is actually correct.

///|
/// A decoded ATTRS block. Absent fields are `None`, not zero, so a caller can
/// tell "size is 0" from "size was not reported".
pub(all) struct SftpAttrs {
  mut size : UInt64?
  mut uid : Int?
  mut gid : Int?
  mut permissions : Int?
  mut atime : Int?
  mut mtime : Int?
  /// count of vendor extension pairs, in the order they appeared
  mut ext_count : Int
}

///|
/// Flags with nothing selected -- what a client sends in an OPEN when it has
/// no opinion, and what the draft's "no attributes" encoding looks like.
pub fn SftpAttrs::none() -> SftpAttrs {
  { size: None, uid: None, gid: None, permissions: None,
    atime: None, mtime: None, ext_count: 0 }
}

///|
/// Read an ATTRS block starting at the cursor.
///
/// Sticky errors are the caller's to check: `SftpCursor` latches the first
/// failure, so this returns a zero-valued `SftpAttrs` and the cursor carries
/// the reason.
pub fn SftpCursor::attrs(self : SftpCursor) -> SftpAttrs {
  let flags = self.u32()
  if self.err is Some(_) {
    return SftpAttrs::none()
  }
  let out = SftpAttrs::none()
  if (flags & ATTR_SIZE) != 0 {
    out.size = Some(self.u64())
  }
  if self.err is Some(_) {
    return out
  }
  if (flags & ATTR_UIDGID) != 0 {
    out.uid = Some(self.u32())
    out.gid = Some(self.u32())
  }
  if self.err is Some(_) {
    return out
  }
  if (flags & ATTR_PERMISSIONS) != 0 {
    out.permissions = Some(self.u32())
  }
  if self.err is Some(_) {
    return out
  }
  if (flags & ATTR_ACMODTIME) != 0 {
    out.atime = Some(self.u32())
    out.mtime = Some(self.u32())
  }
  if self.err is Some(_) {
    return out
  }
  if (flags & ATTR_EXTENDED) != 0 {
    let count = self.u32()
    // sftp-common.c:138-139 caps this before looping, so a corrupt count
    // cannot turn into a multi-million iteration loop.
    if count < 0 || count > 0x100000 {
      self.fail(Unexpected(count))
      return out
    }
    out.ext_count = count
    let mut i = 0
    while i < count {
      let _ty = self.string()
      let _data = self.string()
      if self.err is Some(_) {
        return out
      }
      i = i + 1
    }
  }
  out
}

///|
/// Encode an ATTRS block, in the same fixed order `decode_attrib` reads.
///
/// Only the fields that are `Some` are emitted, and the flag bits are derived
/// from that -- so an encoder cannot advertise a bit whose field it forgot to
/// write, which is the mirror-image version of the bug above.
pub fn SftpAttrs::encode(self : SftpAttrs) -> FixedArray[Byte] {
  let mut flags = 0
  if self.size is Some(_) { flags = flags | ATTR_SIZE }
  if self.uid is Some(_) { flags = flags | ATTR_UIDGID }
  if self.permissions is Some(_) { flags = flags | ATTR_PERMISSIONS }
  if self.atime is Some(_) { flags = flags | ATTR_ACMODTIME }
  // Vendor extensions are not produced by this client yet; if ext_count is
  // nonzero on an encode we deliberately drop them rather than write a flag
  // bit with no pairs behind it.
  let out : Array[FixedArray[Byte]] = []
  out.push(@sshwire.write_u32(flags.reinterpret_as_uint()))
  match self.size {
    Some(v) => out.push(@sshwire.write_u64(v))
    None => ()
  }
  if self.uid is Some(_) {
    out.push(@sshwire.write_u32(self.uid.unwrap().reinterpret_as_uint()))
    out.push(@sshwire.write_u32(self.gid.unwrap().reinterpret_as_uint()))
  }
  match self.permissions {
    Some(v) => out.push(@sshwire.write_u32(v.reinterpret_as_uint()))
    None => ()
  }
  if self.atime is Some(_) {
    out.push(@sshwire.write_u32(self.atime.unwrap().reinterpret_as_uint()))
    out.push(@sshwire.write_u32(self.mtime.unwrap().reinterpret_as_uint()))
  }
  sftp_cat(out)
}

///|
/// Concatenate a list of byte arrays.
pub fn sftp_cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut n = 0
  for i = 0; i < parts.length(); i = i + 1 {
    n = n + parts[i].length()
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
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
/// `u64` -> `Int`, or -1 when it does not fit.
///
/// File sizes arrive as `u64` (the ATTRS layout mandates it) but every caller
/// here wants a count to print or compare. Narrowing silently is the wrong
/// default: `reinterpret_as_int` on a 64-bit value is not a thing, and a
/// hand-rolled truncation would turn a 5 GiB file into a negative size that
/// reads like a parse failure. -1 already means "size not reported", so it
/// doubles as "size reported but unrepresentable" and neither is mistaken for
/// a real count.
pub fn sftp_u64_to_int(v : UInt64) -> Int {
  // `UInt64` has no `reinterpret_as_uint` -- only `UInt` does -- so the
  // narrowing goes through `Int`, and the signedness has to be checked before
  // the narrowing rather than after it.
  if v > 0x7FFFFFFFUL {
    return -1
  }
  v.to_int()
}

///|
/// ASCII bytes of a `String`.
pub fn sftp_ascii(s : String) -> FixedArray[Byte] {  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  out
}
