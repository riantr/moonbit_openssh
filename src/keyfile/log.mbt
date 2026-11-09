///|
/// Loop #87: the escaping OpenSSH puts on the messages it prints.
///
/// OpenSSH does not print an error message as it is.  Every message goes
/// through `do_log` (log.c:337), which runs it through
/// `strnvis(..., LOG_STDERR_VIS)` before it reaches the terminal, and
/// `LOG_STDERR_VIS` is `VIS_SAFE|VIS_OCTAL` (log.c:69).
///
/// The visible effect on Windows is that every backslash in a path comes
/// out doubled:
///
/// ```
/// ssh-keygen: E:\\src\\key: No such file or directory
/// ```
///
/// That is not a bug in OpenSSH and it is not decoration.  It is what
/// makes a message safe to print when the message contains a control
/// character, and it is the reason a path in an error message cannot be
/// mistaken for the end of the message.
///
/// **The rules, from `vis` (openbsd-compat/vis.c:64):**
///
///   * a backslash becomes two backslashes;
///   * a printable ASCII character is left alone -- including `#`, `*`,
///     `?` and `[`, which `vis` would otherwise treat as glob
///     characters;
///   * a space, a tab, a newline, a backspace, a bell and a carriage
///     return are left alone (`VIS_SAFE` keeps them, and so do the three
///     flags that are not set);
///   * anything else becomes a backslash and three octal digits.
///
/// The last rule includes every byte above 0x7F, because `vis` works on
/// bytes in the C locale and those are not printable there.  A path with
/// a non-ASCII character in it is therefore escaped byte by byte, and
/// this function does the same: it works on the UTF-8 BYTES of the text,
/// not on its characters.  Working on the characters would be wrong in a
/// way that is easy to miss: the character `é` is one character and two
/// bytes, and OpenSSH escapes two bytes.
///
/// **Measured against the real tool.**  The `ssh-keygen` in
/// `C:\Windows\System32\OpenSSH` prints this for a file that is not
/// there:
///
/// ```
/// ssh-keygen: E:\\src\\moon\\nope: No such file or directory
/// ```
///
/// and the two backslashes in that line are two backslashes and not one,
/// which the transcript of a `repr()` cannot show on its own -- `repr()`
/// doubles them too.  The gate for this loop compares the bytes, not the
/// transcript of the bytes.

///|
/// Escape a message the way OpenSSH escapes a message.
///
/// The message is escaped as a whole, so a path inside it comes out
/// escaped too.  That is the point: OpenSSH escapes the whole message
/// (log.c:399 runs `strnvis` over `msgbuf`, which already holds the
/// path), and a message that is escaped in parts is not the same
/// message.
pub fn escape_log_text(text : String) -> String {
  let bytes = utf8_bytes(text)
  let out = StringBuilder()
  for i = 0; i < bytes.length(); i = i + 1 {
    let value = bytes[i].to_int()
    if value == 0x5C {
      // The backslash itself.
      out.write_string("\\\\")
    } else if value >= 0x20 && value <= 0x7E {
      out.write_char(Int32::unsafe_to_char(value))
    } else if value == 0x09 ||
      value == 0x0A ||
      value == 0x08 ||
      value == 0x07 ||
      value == 0x0D {
      // The whitespace and the three control characters that `VIS_SAFE`
      // keeps as they are.
      out.write_char(Int32::unsafe_to_char(value))
    } else {
      out.write_char('\\')
      out.write_string(octal3(value))
    }
  }
  out.to_string()
}

///|
/// Three octal digits for a byte.
///
/// `vis` writes the octal escape with exactly three digits, and the
/// width matters: `vis` writes `\0` for a NUL and `\000` for a byte
/// whose value happens to be zero in the low three digits, and a reader
/// that cannot tell the two apart cannot read the message back.
fn octal3(value : Int32) -> String {
  let text = value.to_string(radix=8)
  if text.length() == 1 {
    "00" + text
  } else if text.length() == 2 {
    "0" + text
  } else {
    text
  }
}
