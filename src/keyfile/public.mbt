///|
/// Loop #87: reading a PUBLIC key line.
///
/// `src/keyfile` could write a `.pub` file (Loop #85) and could read a
/// private key file (Loop #85, encrypted form in Loop #86), but it could
/// not read a `.pub` file.  That is the file `ssh-keygen -l` is usually
/// pointed at, and the file an `authorized_keys` line is made of.
///
/// The line is the one OpenSSH writes (`sshkey_format_text`,
/// sshkey.c:1416):
///
/// ```
/// ssh-ed25519 <base64 of the public blob> [comment]
/// ```
///
/// **The base64 here is unpadded.**  That is not an inconsistency with the
/// private key file, which is padded: the private file uses `b64_ntop` with
/// the padding kept, and this line uses `sshbuf_dtourlb64`, which strips
/// it (sshbuf-misc.c:222).  `src/knownhosts` already deals with the
/// unpadded form on the way in.
///
/// **A line with no comment gets the FILE NAME as its comment.**  That is
/// OpenSSH's rule and it is not an obvious one: `authfile.c:238` does
/// `strdup(*cp ? cp : filename)`.  Measured with the real tool:
///
/// ```
/// $ ssh-keygen -l -f .../nocomment
/// 256 SHA256:nlg0lNK... E:\...\nocomment.pub (ED25519)
/// ```
///
/// The path is there because the `.pub` file beside the private key has no
/// comment of its own, so the file name stands in for one.  Reproducing
/// this is not pedantry: it is the difference between a tool whose output
/// can be compared byte for byte with OpenSSH's and one that cannot.
///
/// **But that rule is the rule for a `.pub` FILE, and it is not the rule
/// for a `.pub` LINE.**  OpenSSH has two of them, in two different places,
/// and they disagree:
///
///   * `sshkey_try_load_public` (authfile.c:238) reads a `.pub` FILE and
///     gives a line with no comment the FILE's name.
///   * `do_fingerprint` (ssh-keygen.c:989) reads a line and gives a line
///     with no comment NOTHING -- and the fingerprint line then says `no
///     comment`.
///
/// So `ssh-keygen -l -f key` and `ssh-keygen -l -f key.pub` can print
/// two different things for the same key, and they do.  Which one is
/// which is the CALLER's business, and this package only reports the
/// FACT: the comment that is in the line, or nothing.

///|
///
/// The bit count `ssh-keygen -l` prints for an ed25519 key.
///
/// OpenSSH's `sshkey_size()` returns the implementation's `keybits` when
/// the type has no size function of its own, and ed25519's is 256
/// (ssh-ed25519.c).  Measured: `256 SHA256:... comment (ED25519)`.
pub const ED25519_BITS : Int32 = 256

///|
/// The name OpenSSH prints in parentheses after a fingerprint.
///
/// `sshkey_type()` returns the implementation's **shortname**, which for
/// ed25519 is "ED25519" -- not the ssh name "ssh-ed25519" that appears
/// in the key line itself (sshkey.c:194, ssh-ed25519.c:314).  The two names
/// are different strings in OpenSSH and confusing them changes the output
/// of every fingerprint line.
pub const ED25519_SHORT_NAME : String = "ED25519"

///|
/// What came of reading a public key line.
///
/// A public key line has its own vocabulary, and it is NOT the private
/// reader's: `Parsed` is about private key files, and every one of its
/// answers is about one.  A public line has three of the same four -- a
/// key, not a key at all, a key this reader does not have -- and none of
/// the fourth, because a public line is never enciphered and so is never
/// "opened with the wrong passphrase".
pub(all) enum PublicParsed {
  /// The line was read and it is an ed25519 public key: the 32-byte
  /// public half, and the comment.
  ///
  /// The comment is `None` when the line has none.  It is NOT the same
  /// thing as an empty comment, and the difference is visible in
  /// OpenSSH's output: `None` is printed as `no comment`, and an empty
  /// comment leaves two spaces in the line where `no comment` leaves
  /// one.  Which of the two applies is the CALLER's business -- OpenSSH
  /// has two different rules, in two different places, and they disagree.
  Ed25519(FixedArray[Byte], String?)
  /// The line is not a key line at all.
  Malformed(String)
  /// The line is a key line for another key type.
  Unsupported(String)
}

///|
/// Parse a public key line -- the line of a `.pub` file.
///
/// The answers are the same four the private key reader gives: a line
/// that is not a key line is `Malformed`, a line for another key type is
/// `Unsupported`, and an ed25519 key is `Ed25519` -- the public half and
/// the comment.
///
/// **The whole file is scanned, not just its first line.**  OpenSSH's
/// `sshkey_try_load_public` (authfile.c:229) reads the file line by line
/// and keeps going until it finds a key, so a file whose first line is a
/// comment and whose second is the key is a file with a key in it.  The
/// scan here stops at the first ED25519 key, which is the only kind this
/// repository has; a file with an ed25519 key AND another kind of key in
/// it is a file OpenSSH would read the other kind from, and this one
/// does not.
pub fn parse_public_line(text : String) -> PublicParsed {
  let mut other : PublicParsed? = None
  let n = text.length()
  let mut at = 0
  while at <= n {
    let mut stop = at
    while stop < n && text[stop] != '\n' {
      stop = stop + 1
    }
    let raw = text[at:stop].to_owned()
    let line = trim_blanks(trim_cr(raw))
    if line.length() > 0 && line[0] != '#' {
      match parse_one_public_line(line) {
        Ed25519(pk, comment) => return PublicParsed::Ed25519(pk, comment)
        Unsupported(why) =>
          if other is None {
            other = Some(PublicParsed::Unsupported(why))
          }
        Malformed(_) => ()
      }
    }
    if stop >= n {
      break
    }
    at = stop + 1
  }
  match other {
    Some(u) => u
    None => PublicParsed::Malformed("the file has no public key line in it")
  }
}

///|
/// The fingerprint line, in the form `ssh-keygen -l` prints it.
///
/// That is:
///
/// ```
/// <bits> <fingerprint> <comment> (<type>)
/// ```
///
/// **The comment is `None` or it is a string, and the difference between
/// the two is a space.**  A comment that is not there at all is printed
/// as the word `no comment`, and a comment that is there but empty is
/// printed as nothing -- which leaves TWO spaces in the line where `no
/// comment` leaves one.  The two are different strings in OpenSSH too:
/// `fingerprint_one_key` (ssh-keygen.c:873) prints `comment ? comment
/// : "no comment"`, and an empty comment IS a comment.
///
/// Measured with the real tool:
///
/// ```
/// 256 SHA256:IBt2EsgRd8d0wDn0Q7KhefjdHxaSAq605T+ngf4eqik no comment (ED25519)
/// 256 SHA256:IBt2EsgRd8d0wDn0Q7KhefjdHxaSAq605T+ngf4eqik  (ED25519)
/// ```
///
/// The first line is a key file whose comment is empty and whose `.pub`
/// file is missing; the second is the same key with the `.pub` file
/// there.  One space and two, and the difference is a fact about the
/// FILE rather than about the key.
pub fn fingerprint_line(fingerprint : String, comment : String?) -> String {
  let text = match comment {
    None => "no comment"
    Some(s) => s
  }
  ED25519_BITS.to_string() +
  " " +
  fingerprint +
  " " +
  text +
  " (" +
  ED25519_SHORT_NAME +
  ")"
}

///|
/// The SHA-256 fingerprint of a public key blob, in the form
/// `ssh-keygen -l` prints it.
///
/// That is `SHA256:` followed by the base64 of the SHA-256 of the public
/// key blob, with the padding stripped.  OpenSSH's `fingerprint_b64`
/// (sshkey.c:1031) does exactly this, and the blob is the one in the
/// `.pub` line -- the key type as a string, then the key as a string.
///
/// `src/hostkey` computes fingerprints over host key blobs too, and this
/// is the same computation over the same blob -- but `src/hostkey` is
/// above this package in the dependency graph, so it is repeated here
/// rather than inverted.
pub fn fingerprint_of_blob(blob : FixedArray[Byte]) -> String {
  let digest = @sha256.sha256(blob)
  let padded = @base64.encode(Bytes::from_array(digest))
  "SHA256:" + strip_padding(padded)
}

///|
/// A line without its trailing carriage return.
///
/// A file written on Windows has CRLF line endings, and the carriage
/// return would otherwise become part of the comment.
fn trim_cr(line : String) -> String {
  let n = line.length()
  if n > 0 && line[n - 1] == '\r' {
    line[0:n - 1].to_owned()
  } else {
    line
  }
}

///|
/// A line without its leading spaces and tabs.
fn trim_blanks(line : String) -> String {
  let n = line.length()
  let mut at = 0
  while at < n && (line[at] == ' ' || line[at] == '\t') {
    at = at + 1
  }
  if at == 0 {
    line
  } else {
    line[at:n].to_owned()
  }
}

///|
/// Parse one key line: the type, the base64 blob, and the comment.
///
/// **A line whose first word is not a key type is read again with that
/// word skipped.**  OpenSSH's `do_fingerprint` (ssh-keygen.c:962) tries
/// the line as a key, and when that fails it treats the first word as a
/// host name or as options and tries again -- that is how a
/// `known_hosts` line ("host ssh-ed25519 AAAA...") and an
/// `authorized_keys` line with options are read.
///
/// Only ONE word is skipped.  A second one would be a guess, and a guess
/// that finds a key in the wrong place is worse than a refusal: it would
/// print a fingerprint for a key the file never claimed to hold.
fn parse_one_public_line(line : String) -> PublicParsed {
  parse_line_at(line, true)
}

///|
/// Parse one key line, with the answer to "may the first word be
/// something that is not a key type".
fn parse_line_at(line : String, may_skip : Bool) -> PublicParsed {
  let at = end_of_word(line, 0)
  if at == 0 {
    return PublicParsed::Malformed("the line has no key type in it")
  }
  let ktype = line[0:at].to_owned()
  if ktype == KEY_TYPE {
    return parse_key_body(line, at)
  }
  // The first word is not the ed25519 type.  It may still be a word in
  // FRONT of the key -- a host name in a `known_hosts` line, or options
  // in an `authorized_keys` line -- and the way to tell the two apart
  // is to look at the NEXT word: if that one is the ed25519 type, then
  // the first word is in front of the key and the key starts after it.
  //
  // Looking at the next word is what keeps this from being a guess.  A
  // line whose first word is `ssh-rsa` is a line for another key type,
  // and skipping its first word would find a base64 blob where the type
  // should be and report THAT as the key type.
  if may_skip {
    let rest = skip_blanks(line, at)
    if rest < line.length() {
      let next = end_of_word(line, rest)
      if next > rest && line[rest:next].to_owned() == KEY_TYPE {
        return parse_key_body(line, next)
      }
    }
  }
  PublicParsed::Unsupported("the key type is " + ktype + ", not ed25519")
}

///|
/// The key part of a line: the base64 blob and the comment.
///
/// `type_end` is where the key type ends, which the caller has already
/// checked to be the ed25519 type.
fn parse_key_body(line : String, type_end : Int32) -> PublicParsed {
  let blob_start = skip_blanks(line, type_end)
  if blob_start >= line.length() {
    return PublicParsed::Malformed("the line has no key in it")
  }
  let blob_end = end_of_word(line, blob_start)
  let b64 = line[blob_start:blob_end].to_owned()
  let comment_start = skip_blanks(line, blob_end)
  let comment = if comment_start >= line.length() {
    ""
  } else {
    line[comment_start:line.length()].to_owned()
  }
  let view : StringView = b64
  let raw = @base64.decode(view, ignore_whitespace=false) catch {
    _ => return PublicParsed::Malformed("the key is not base64")
  }
  let blob : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    blob[i] = raw[i]
  }
  match ed25519_pk_from_blob(blob) {
    None => PublicParsed::Malformed("the key blob is not an ed25519 public key")
    Some(pk) => {
      // The FACT, not the rule: the comment as it is in the line, or
      // nothing.  OpenSSH has two rules for an absent comment and they
      // disagree -- see the note on `PublicParsed`.
      let c : String? = if comment == "" { None } else { Some(comment) }
      PublicParsed::Ed25519(pk, c)
    }
  }
}

///|
/// The index of the first character at or after `at` that is not a space
/// or a tab.
fn skip_blanks(line : String, at : Int32) -> Int32 {
  let n = line.length()
  let mut i = at
  while i < n && (line[i] == ' ' || line[i] == '\t') {
    i = i + 1
  }
  i
}

///|
/// The index of the first blank at or after `at` -- the END of the word
/// that starts there.
///
/// This is the other half of `skip_blanks`, and the two are not
/// interchangeable: `skip_blanks` finds where a word STARTS and
/// `end_of_word` finds where it ENDS, and a base64 blob read with the
/// wrong one of the two is an empty string.
fn end_of_word(line : String, at : Int32) -> Int32 {
  let n = line.length()
  let mut i = at
  while i < n && line[i] != ' ' && line[i] != '\t' {
    i = i + 1
  }
  i
}

///|
/// The 32-byte public key inside a public key blob.
///
/// The blob is the key type as a string, then the key as a string, so its
/// length is fixed: 4 + 11 + 4 + 32 = 51 bytes.  The lengths are checked
/// rather than assumed, because a blob that is the right size but the
/// wrong shape is a blob that some other tool wrote, and this reader has
/// to say so instead of reading past the end.
fn ed25519_pk_from_blob(blob : FixedArray[Byte]) -> FixedArray[Byte]? {
  if blob.length() != 4 + 11 + 4 + 32 {
    return None
  }
  let want = utf8_bytes(KEY_TYPE)
  for i = 0; i < 11; i = i + 1 {
    if blob[4 + i] != want[i] {
      return None
    }
  }
  if blob[15] != b'\x00' ||
    blob[16] != b'\x00' ||
    blob[17] != b'\x00' ||
    blob[18] != 32U.to_byte() {
    return None
  }
  let pk : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    pk[i] = blob[19 + i]
  }
  Some(pk)
}

///|
/// The public key of a private key file, and its comment if it can be read.
///
/// The comment is `None` when the file's private block is enciphered: the
/// comment lives in that block, so there is nothing to read without the
/// passphrase, and OpenSSH prints `no comment` for it.  An empty comment
/// is a DIFFERENT thing -- it is a comment that is empty, and OpenSSH
/// prints that as an empty string, which leaves two spaces in the line
/// where `no comment` leaves one.
///
/// The public key is available either way, because the public blob of an
/// `openssh-key-v1` file is stored in the clear.  That is why
/// `ssh-keygen -l` prints the fingerprint of an encrypted key without
/// asking for anything.
pub fn public_of_private_file(text : String) -> (FixedArray[Byte], String?)? {
  let body = match strip_markers(text) {
    None => return None
    Some(b) => b
  }
  let view : StringView = body
  let raw = @base64.decode(view, ignore_whitespace=true) catch {
    _ => return None
  }
  let b : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    b[i] = raw[i]
  }
  let mg = magic()
  if b.length() < mg.length() {
    return None
  }
  for i = 0; i < mg.length(); i = i + 1 {
    if b[i] != mg[i] {
      return None
    }
  }
  let mut at = mg.length()
  let cipher = match read_string(b, at) {
    None => return None
    Some((c, a1)) => {
      at = a1
      c
    }
  }
  let kdf = match read_string(b, at) {
    None => return None
    Some((k, a2)) => {
      at = a2
      k
    }
  }
  // The KDF options, which are in the clear even for an encrypted file.
  at = match read_bytes(b, at) {
    None => return None
    Some((_opts, a3)) => a3
  }
  let count = match read_key_count(b, at) {
    None => return None
    Some((c, a4)) => {
      at = a4
      c
    }
  }
  if count != 1U {
    return None
  }
  let pubblob = match read_bytes(b, at) {
    None => return None
    Some((p, _a5)) => p
  }
  let pk = match ed25519_pk_from_blob(pubblob) {
    None => return None
    Some(k) => k
  }
  if cipher == CIPHER_NONE && kdf == CIPHER_NONE {
    // The private block is in the clear, so the comment is in there too.
    match parse_private_file(text) {
      Ed25519(_, comment) => Some((pk, Some(comment)))
      _ => Some((pk, None))
    }
  } else {
    // The comment is in the enciphered block.  There is nothing to read
    // without the passphrase, and OpenSSH prints "no comment" for it.
    Some((pk, None))
  }
}

///|
/// Whether a private key file's private block is enciphered.
///
/// The answer is a fact about the FILE, and the driver needs it to say the
/// right thing: "this key is encrypted, give the passphrase" is right for
/// an encrypted file and wrong for a file this reader cannot open for some
/// other reason.
///
/// The cipher name and the KDF name are in the clear part of the file, so
/// this works without the passphrase.
pub fn private_file_is_encrypted(text : String) -> Bool {
  let body = match strip_markers(text) {
    None => return false
    Some(b) => b
  }
  let view : StringView = body
  let raw = @base64.decode(view, ignore_whitespace=true) catch {
    _ => return false
  }
  let b : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    b[i] = raw[i]
  }
  let mg = magic()
  if b.length() < mg.length() {
    return false
  }
  for i = 0; i < mg.length(); i = i + 1 {
    if b[i] != mg[i] {
      return false
    }
  }
  let mut at = mg.length()
  let cipher = match read_string(b, at) {
    None => return false
    Some((c, a1)) => {
      at = a1
      c
    }
  }
  let kdf = match read_string(b, at) {
    None => return false
    Some((k, _a2)) => k
  }
  !(cipher == CIPHER_NONE && kdf == CIPHER_NONE)
}
