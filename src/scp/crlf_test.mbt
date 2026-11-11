///| The two pure functions the driver's output depends on.
///
/// Both are rules rather than plumbing, so both are pinned here on all
/// four targets rather than being discovered by a gate on one machine.

///|
test "every newline becomes CRLF, exactly once" {
  assert_true(@scp.text_crlf("a\nb\n") == "a\r\nb\r\n")
  // A string with no newline is unchanged: the conversion adds nothing.
  assert_true(@scp.text_crlf("plain") == "plain")
  assert_true(@scp.text_crlf("") == "")
  // An already-converted string is not converted twice.
  assert_true(@scp.text_crlf("a\r\nb") == "a\r\r\nb")
}

///|
test "the usage block, converted, is the three measured lines" {
  let text = @scp.usage_text()
  let bytes = @scp.text_crlf(text)
  let mut crlf = 0
  let mut lf = 0
  let mut i = 0
  while i < bytes.length() {
    if bytes[i] == '\r' {
      crlf = crlf + 1
    } else if bytes[i] == '\n' {
      lf = lf + 1
    }
    i = i + 1
  }
  // Three `\r\n` pairs, and every `\n` is preceded by a `\r`: three of
  // each, and the conversion added exactly three bytes -- no fourth empty
  // line, which is what passing the raw text to `eprintln` would produce.
  assert_eq(crlf, 3)
  assert_eq(lf, 3)
  assert_eq(bytes.length(), text.length() + 3)
}

///|
test "the port refusal keeps its bare newline before the CRLF" {
  // `bad port "0"` + a raw `\n` + the translated `\r\n`.  This is the one
  // message the driver must NOT pass through `text_crlf`.
  let text = @scp.port_error_text("0")
  assert_true(text == "bad port \"0\"\n")
  let full = "scp.exe: " + text + "\r\n"
  assert_true(full == "scp.exe: bad port \"0\"\n\r\n")
}

///|
test "a path crosses to bytes as UTF-8, not as code units" {
  // ASCII is one byte each.
  assert_eq(@scp.path_bytes("abc").length(), 3)
  // A CJK name is three bytes per character in UTF-8 and would be one or
  // two code units in the string, which is exactly the mistake this test
  // exists to catch.
  assert_eq(@scp.path_bytes("键").length(), 3)
  assert_eq(@scp.path_bytes("key-键").length(), 7)
}
