///|
/// Loop #85: the textual half of a private key file.
///
/// The binary blob becomes a file with three parts:
///
/// ```
/// -----BEGIN OPENSSH PRIVATE KEY-----
/// <base64, wrapped at 70 columns>
/// -----END OPENSSH PRIVATE KEY-----
/// ```
///
/// **The wrapping is 70 columns and it is not optional.**  OpenSSH's
/// writer (`sshbuf_dtob64` with `wrap=1`, sshbuf-misc.c:145) breaks the
/// line after every 70 characters, and a reader that expects that will
/// still read a single long line -- but the file will not look like
/// anything OpenSSH wrote, and `diff` against a reference file will be
/// useless.
///
/// **The padding is present.**  The core package's `@base64.encode`
/// produces the padded form, which is what a private key file uses.
/// (The `authorized_keys` line uses the *unpadded* form -- that is a
/// different file and a different rule, and `src/knownhosts` is the one
/// that deals with it.)

///|
/// The line a private key file starts with.
pub const MARK_BEGIN : String = "-----BEGIN OPENSSH PRIVATE KEY-----\n"

///|
/// The line a private key file ends with.
pub const MARK_END : String = "-----END OPENSSH PRIVATE KEY-----\n"

///|
/// How many base64 characters go on one line.
///
/// OpenSSH's `sshbuf_dtob64` breaks the line "if `i % 70 == 69`", so the
/// lines are 70 characters each (sshbuf-misc.c:149).
pub const LINE_WIDTH : Int32 = 70

///|
/// Wrap a base64 string into lines of at most `width` characters.
///
/// Every line ends with a newline, including the last one, because the
/// file ends with a newline and OpenSSH writes one.
///
/// The input is assumed to be ASCII, which base64 is.
fn wrap_lines(b64 : String, width : Int32) -> String {
  let sb = StringBuilder()
  let n = b64.length()
  let mut at = 0
  while at < n {
    let end = if at + width < n { at + width } else { n }
    sb.write_string(b64.unsafe_substring(start=at, end~))
    sb.write_char('\n')
    at = end
  }
  sb.to_string()
}

///|
/// The text of a private key file, from the binary blob.
///
/// This is the whole file: the two markers and the base64 in between.
/// There is no trailing newline beyond the one that ends the last base64
/// line, because `MARK_END` supplies its own.
pub fn encode_pem(blob : FixedArray[Byte]) -> String {
  let b64 = @base64.encode(Bytes::from_array(blob))
  MARK_BEGIN + wrap_lines(b64, LINE_WIDTH) + MARK_END
}

///|
/// The base64 body of a private key file, as its lines.
///
/// The lines are the file's shape: OpenSSH wraps the base64 at 70
/// columns, and every line ends with a newline.  The lines are returned
/// as an array of strings because a test has to be able to count them
/// and measure them, and `String::split` returns an iterator that
/// cannot be indexed.
pub fn body_after_marker(text : String) -> Array[String] {
  let out : Array[String] = []
  let begin = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
  let end = "-----END OPENSSH PRIVATE KEY-----\n"
  if !text.has_prefix(begin) || !text.has_suffix(end) {
    return out
  }
  let body = text.unsafe_substring(
    start=begin.length(),
    end=text.length() - end.length(),
  )
  let mut at = 0
  while at < body.length() {
    let mut stop = at
    while stop < body.length() && body[stop] != '\n' {
      stop = stop + 1
    }
    out.push(body.unsafe_substring(start=at, end=stop))
    at = stop + 1
  }
  out
}

///|
/// The text of a `.pub` file: the authorized_keys line for this key.
///
/// ```
/// ssh-ed25519 <base64 of the public blob> <comment>
/// ```
///
/// The base64 here is **unpadded**, unlike the private key file's.  That
/// is not an inconsistency: OpenSSH writes the `authorized_keys` line
/// with `b64_ntop` and the padding stripped, and the private key file
/// with `b64_ntop` and the padding kept.  `src/knownhosts` already
/// handles the unpadded form on the way in.
///
/// The comment may be empty, in which case the line has no trailing
/// space either.
pub fn encode_public_line(pk : FixedArray[Byte], comment : String) -> String {
  let blob = ed25519_public_blob(pk)
  let padded = @base64.encode(Bytes::from_array(blob))
  let b64 = strip_padding(padded)
  if comment == "" {
    KEY_TYPE + " " + b64 + "\n"
  } else {
    KEY_TYPE + " " + b64 + " " + comment + "\n"
  }
}

///|
/// Remove the `=` padding from a base64 string.
///
/// The padding is one or two `=` at the very end.  OpenSSH's
/// `sshbuf_dtourlb64` does the same thing (sshbuf-misc.c:222) for the
/// `authorized_keys` line.
fn strip_padding(b64 : String) -> String {
  let n = b64.length()
  let mut end = n
  while end > 0 && b64[end - 1] == '=' {
    end = end - 1
  }
  if end == n {
    b64
  } else {
    b64.unsafe_substring(start=0, end~)
  }
}
