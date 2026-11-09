///|
/// cmd/ssh_keygen -- Loop #85: make a key pair and write it down.
///
///   The client could USE a key and could not MAKE one.  There was no
///   `ssh-keygen` here, and no code in this repository that could write a
///   private key file at all.
///
///   This driver is the whole of `ssh-keygen` for the one key type that
///   works: ed25519.
///
///   The options are OpenSSH's, and only the ones that mean something here:
///
///     -f <path>    where to write the private key (the `.pub` goes next
///                  to it, with `.pub` appended)
///     -t <type>    the key type; only `ed25519` is supported
///     -C <comment> the comment to put in both files
///     -N <pass>    the passphrase; the empty one means no passphrase
///     -a <rounds>  how many KDF rounds to use when there is one
///     -q           quiet: do not print the fingerprint lines
///
///   **Loop #87 added reading.**  Before it, this driver could only MAKE a
///   key.  Now it can also READ one:
///
///     -l           print the fingerprint of the key file
///     -y           print the public key of the key file
///     -P <pass>    the passphrase of an encrypted key file
///     -E <hash>    the fingerprint hash; only `sha256` is supported
///
///   **Loop #86 changed the passphrase.**  Before it, `-N` with a
///   non-empty value was REFUSED, because there was no `bcrypt_pbkdf`
///   here and a tool that accepts `-N secret` and writes an UNENCRYPTED
///   key would be a way to lose a secret quietly.  Now there is a KDF,
///   so the passphrase is honoured: the key file is enciphered with
///   AES-256-CTR under a key derived from the passphrase, and OpenSSH
///   reads it back.
///
///   The private key file is written with the owner's permissions only.
///   On Windows there are no POSIX permission bits to set, so the mode is
///   whatever the filesystem gives a file it just created -- but the file
///   is still created with the *exclusive* mode, so on a POSIX system it
///   is not readable by anyone else.
async fn main {
  let args = @env.args()
  let mut path = ""
  let mut key_type = "ed25519"
  let mut comment = ""
  let mut passphrase = ""
  let mut rounds = @keyfile.DEFAULT_ROUNDS
  let mut quiet = false
  let mut want_fingerprint = false
  let mut want_public = false
  let mut read_passphrase = ""
  let mut digest = "sha256"
  let mut i = 1
  while i < args.length() {
    let a = args[i]
    if a == "-f" && i + 1 < args.length() {
      i = i + 1
      path = args[i]
    } else if a == "-t" && i + 1 < args.length() {
      i = i + 1
      key_type = args[i]
    } else if a == "-C" && i + 1 < args.length() {
      i = i + 1
      comment = args[i]
    } else if a == "-N" && i + 1 < args.length() {
      i = i + 1
      passphrase = args[i]
    } else if a == "-a" && i + 1 < args.length() {
      i = i + 1
      rounds = parse_rounds(args[i])
    } else if a == "-P" && i + 1 < args.length() {
      i = i + 1
      read_passphrase = args[i]
    } else if a == "-E" && i + 1 < args.length() {
      i = i + 1
      digest = args[i]
    } else if a == "-l" {
      want_fingerprint = true
    } else if a == "-y" {
      want_public = true
    } else if a == "-q" {
      quiet = true
    } else {
      println("ssh_keygen: unknown argument: " + a)
      return
    }
    i = i + 1
  }
  // The digest algorithm is checked BEFORE anything is done, the way
  // OpenSSH checks it: it reads the option and refuses one it does not
  // know there and then (ssh-keygen.c:3361), before it opens a file.
  //
  // **An algorithm OpenSSH knows and this repository does not is NOT the
  // same thing as an algorithm neither of them knows.**  `md5` is one
  // OpenSSH has and this repository has not, so the honest answer is
  // that this tool cannot print that fingerprint -- not that the
  // algorithm is invalid.  An algorithm neither of them knows gets
  // OpenSSH's own words, byte for byte.
  if digest != "sha256" {
    if digest == "md5" || digest == "sha384" || digest == "sha512" {
      fail("ssh_keygen: only -E sha256 is supported, not " + digest)
    } else {
      fail("Invalid hash algorithm \"" + digest + "\"")
    }
  }
  if want_fingerprint || want_public {
    read_mode(path, want_fingerprint, read_passphrase)
    return
  }
  if path == "" {
    println("ssh_keygen: -f <path> is required")
    return
  }
  if key_type != "ed25519" {
    println("ssh_keygen: only -t ed25519 is supported, not " + key_type)
    return
  }
  if rounds < 1 {
    println("ssh_keygen: -a <rounds> must be at least 1")
    return
  }
  if rounds > @keyfile.MAX_ROUNDS {
    println(
      "ssh_keygen: -a <rounds> must not be more than " +
      @keyfile.MAX_ROUNDS.to_string(),
    )
    return
  }
  let pair = @keyfile.generate_ed25519()
  // The check word is four random bytes, read as a big-endian word.
  // OpenSSH's writer uses `arc4random()` for it; the point of it is that
  // the two copies in the file are equal, and the point of it being
  // random is that two key files do not look alike.
  let check_bytes = random_check_bytes()
  let check = check_word(check_bytes)
  let priv_text = if passphrase == "" {
    @keyfile.private_file_text(pair, comment, check)
  } else {
    // The salt is random too, and it goes into the file so that the
    // reader can derive the same key.  Sixteen bytes, from the same
    // source as the seed.
    let salt = @keyfile.random_salt()
    let text = @keyfile.private_file_text_encrypted(
      pair, comment, check, passphrase, salt, rounds,
    )
    if text == "" {
      // The KDF refused the passphrase -- an empty one is the only
      // thing it refuses, and this branch is here so that a failure is
      // a sentence and not a file that claims to be encrypted and is
      // not.
      println("ssh_keygen: the passphrase could not be used")
      return
    }
    text
  }
  let pub_text = @keyfile.public_file_text(pair, comment)
  let priv_path = path
  let pub_path = path + ".pub"
  let w1 = write_private(priv_path, priv_text)
  if w1 != "" {
    println("ssh_keygen: cannot write " + priv_path + ": " + w1)
    return
  }
  // The file is written; now it has to be made private.  A key file that
  // other users can read is not a key file, and OpenSSH refuses to use
  // one -- so a failure here is a failure of the whole command, not a
  // warning to print and carry on.
  if @keyperm.protect(priv_path) != 0 {
    println(
      "ssh_keygen: cannot restrict " +
      priv_path +
      " to its owner; the key is readable by other users",
    )
    return
  }
  let w2 = write_public(pub_path, pub_text)
  if w2 != "" {
    println("ssh_keygen: cannot write " + pub_path + ": " + w2)
    return
  }
  if !quiet {
    println("Your identification has been saved in " + priv_path)
    println("Your public key has been saved in " + pub_path)
    let fp = @keyfile.fingerprint_text(pair)
    println("The key fingerprint is:\n" + fp + " " + comment)
  }
}

///|
/// Fail the way OpenSSH's `ssh-keygen` fails.
///
/// OpenSSH puts its errors on **stderr** and exits with **255**.  Both
/// matter, and neither is decoration:
///
///   * a script that reads the tool's output has to be able to tell the
///     key from the complaint about the key, and stdout and stderr are
///     two different pipes for exactly that reason;
///   * a script that checks the status has to be able to tell "it
///     failed" from "it worked", and a tool that fails with 0 is a tool
///     whose failure a script cannot see.
///
/// **The status is set with `@env.exit`.**  `abort` would raise a failure
/// instead, and the status that comes out of that is the runtime's, not
/// this program's; `@env.exit(255)` is the one that sets it to 255.
///
/// The message is escaped before it gets here -- see
/// `@keyfile.escape_log_text` -- because OpenSSH escapes every message
/// it prints, and a message that is printed the way OpenSSH prints it
/// has to be escaped the way OpenSSH escapes it.
fn fail(message : String) -> Unit {
  eprintln(message)
  @env.exit(255)
}

///|
/// The number of KDF rounds, from the `-a` option.
///
/// OpenSSH's `ssh-keygen` takes the number as a decimal number and
/// refuses anything that is not one.  A number that is not a number at
/// all is a refusal here too, and so is a number below one -- the KDF
/// has nothing to do with no rounds.
///
/// **The number is capped as it is read.**  A count of thirty digits
/// does not fit in an `Int32`, and an `Int32` that wraps around lands
/// on a small number that looks perfectly legal -- so a request for
/// two billion rounds could arrive as twenty-four and be written into
/// the file as twenty-four.  Stopping at the cap turns every too-big
///
/// number into the one refusal, which is the honest answer.
fn parse_rounds(text : String) -> Int32 {
  let mut n = 0
  let mut seen = false
  for i = 0; i < text.length(); i = i + 1 {
    let c = text[i]
    if c < '0' || c > '9' {
      return 0
    }
    seen = true
    if n > @keyfile.MAX_ROUNDS {
      return @keyfile.MAX_ROUNDS + 1
    }
    n = n * 10 + (c.to_int() - '0'.to_int())
  }
  if !seen {
    return 0
  }
  n
}

///|
/// Four random bytes for the check word.
///
/// The check word is a random word that is written twice into the private
/// block, so that a reader can tell whether the file was decrypted with
/// the passphrase it thinks it was.
///
/// It comes from `src/rng`, the same source as the seed.
fn random_check_bytes() -> FixedArray[Byte] {
  @keyfile.random_check_bytes()
}

///|
/// Four bytes as a big-endian word.
fn check_word(b : FixedArray[Byte]) -> UInt32 {
  ((b[0].to_uint() << 24) & 0xFF000000U) |
  ((b[1].to_uint() << 16) & 0x00FF0000U) |
  ((b[2].to_uint() << 8) & 0x0000FF00U) |
  (b[3].to_uint() & 0x000000FFU)
}

///|
/// Write the private key file.
///
/// The mode is the owner's own, and nothing else.  `@fs.write_file`
/// takes a `CreateMode`, and `CreateNew` is the one that will NOT write
/// over a file that is already there -- so a key that already exists is
/// never silently replaced.
///
/// (On Windows the mode has no effect, because there are no POSIX
/// permission bits there.  It is still the right thing to ask for, and
/// on a POSIX system it is what makes the file private.)
///
/// The empty string means success and anything else is the reason it
/// failed.  A `Result` would say the same thing, but `async fn main`
/// cannot raise, and an error type in the signature of `main` would mean
/// the driver exits with a stack trace instead of a sentence.
async fn write_private(path : String, text : String) -> String {
  try {
    @fs.write_file(path, text, create_mode=@fs.CreateMode::CreateNew)
    ""
  } catch {
    e => e.to_string()
  }
}

///|
/// Write the `.pub` file.
///
/// The public key is not a secret, so it is written the ordinary way --
/// overwriting whatever was there, which is what OpenSSH does.
async fn write_public(path : String, text : String) -> String {
  try {
    @fs.write_file(path, text)
    ""
  } catch {
    e => e.to_string()
  }
}

///|
/// Loop #87: reading a key file instead of writing one.
///
/// `-l` prints the fingerprint and `-y` prints the public key, and both
/// follow OpenSSH's rules rather than a convenient subset of them.  The
/// rules that are easy to get wrong:
///
///   * `-l` on a PRIVATE key file asks for the PUBLIC key first: the
///     `.pub` file beside it decides the fingerprint and the comment, and
///     the passphrase is never needed.  A `.pub` file that is missing or
///     unreadable leaves the private file to decide, and then the comment
///     is the one in the private block -- which for an ENCRYPTED file
///     cannot be read at all, so OpenSSH prints `no comment`.
///
///   * `-l` on a PUBLIC key file takes the comment from the line, and a
///     line with no comment of its own is given the file's name.
///
///   * `-y` always opens the PRIVATE file, so it needs the passphrase for
///     an encrypted one, and it prints the comment from the private block
///     -- which is empty rather than `no comment` when the key has no
///     comment.
///
/// `no comment` and an empty comment are DIFFERENT strings and the
/// difference is visible: the first leaves one space in the line, the
/// second leaves two.
///
/// **The errors go to stderr and the exit status is 255**, the way
/// OpenSSH's do.
async fn read_mode(
  path : String,
  want_fingerprint : Bool,
  read_passphrase : String,
) -> Unit {
  if path == "" {
    fail("ssh_keygen: -f <path> is required")
  } else {
    let text = read_text(path)
    match text {
      None =>
        // OpenSSH's two messages are not the same message.  The
        // fingerprint path opens the file itself and says
        // `ssh-keygen: <path>: ...` (ssh-keygen.c:931); the public path
        // asks for the file and says `<path>: ...`
        // (ssh-keygen.c:785).  One has the program name in it and the
        // other does not, and the reason is in the source: one format
        // string names the program and the other does not.
        if want_fingerprint {
          fail("ssh-keygen: " + escaped(path) + ": No such file or directory")
        } else {
          fail(escaped(path) + ": No such file or directory")
        }
      Some(t) =>
        if want_fingerprint {
          print_fingerprint(path, t)
        } else {
          print_public(path, t, read_passphrase)
        }
    }
  }
}

///|
/// A path, escaped the way OpenSSH escapes a path in a message.
///
/// OpenSSH runs every message through `strnvis` before it prints it
/// (log.c:399), so a path in an error message has its backslashes
/// doubled.  That is not decoration: it is what keeps a control
/// character in a path from reaching the terminal, and it is why the
/// message can be compared with OpenSSH's byte for byte.
fn escaped(path : String) -> String {
  @keyfile.escape_log_text(path)
}

///|
/// Read a file, if it can be read.
async fn read_text(path : String) -> String? {
  if !@fs.exists(path) {
    return None
  }
  let data = @fs.read_file(path) catch { _ => return None }
  Some(data.text())
}

///|
/// Print the fingerprint line: `<bits> <fingerprint> <comment> (<type>)`.
async fn print_fingerprint(path : String, text : String) -> Unit {
  match fingerprint_of(path, text) {
    None =>
      // Two different messages, because OpenSSH has two different
      // places that can fail here.  A file whose first line does not
      // hold "PRIVATE KEY" is read as a public key file, and a public
      // key file that holds no key is "not a public key file"
      // (ssh-keygen.c:1003).  A file that does hold "PRIVATE KEY" is
      // read as a private key file, and one that cannot be read is "not
      // a key file" (ssh-keygen.c:897).
      if is_private_key_file(text) {
        fail(escaped(path) + " is not a key file.")
      } else {
        fail(escaped(path) + " is not a public key file.")
      }
    Some((fp, comment)) => println(@keyfile.fingerprint_line(fp, comment))
  }
}

///|
/// The fingerprint of the key in a file, and the comment that goes with it.
///
/// The comment is `None` when there is none to read, which is a different
/// thing from an empty one.  `None` is printed as `no comment` and an
/// empty comment leaves two spaces in the line.
async fn fingerprint_of(path : String, text : String) -> (String, String?)? {
  if is_private_key_file(text) {
    // A private key file.  OpenSSH asks for the public key first
    // (authfile.c:269), and a `.pub` file beside the key decides the
    // fingerprint AND the comment when it can be read.
    let pub_text = read_text(path + ".pub")
    match pub_text {
      Some(pt) =>
        match @keyfile.parse_public_line(pt) {
          Ed25519(pk, comment) => {
            // The rule of `sshkey_try_load_public` (authfile.c:238): a
            // public key FILE whose line has no comment of its own is
            // given the file's name.  This is the rule that puts the
            // `.pub` PATH where a comment would be.
            let c = match comment {
              None => path + ".pub"
              Some(s) => s
            }
            Some((fingerprint_of_pk(pk), Some(c)))
          }
          _ => private_fingerprint(text)
        }
      None => private_fingerprint(text)
    }
  } else {
    match @keyfile.parse_public_line(text) {
      Ed25519(pk, comment) => {
        // The rule of `do_fingerprint` (ssh-keygen.c:989-993): the
        // comment is what follows the key, and there is NONE if it is
        // empty or starts with '#'.  This is a different rule from the
        // one above, and it is the reason `-l -f key.pub` prints
        // `no comment` where `-l -f key` prints the `.pub` path.
        let c = match comment {
          None => None
          Some(s) => if s.has_prefix("#") { None } else { Some(s) }
        }
        Some((fingerprint_of_pk(pk), c))
      }
      _ => None
    }
  }
}

///|
/// The fingerprint of a private key file, and its comment if it can be read.
fn private_fingerprint(text : String) -> (String, String?)? {
  match @keyfile.public_of_private_file(text) {
    None => None
    Some((pk, comment)) => Some((fingerprint_of_pk(pk), comment))
  }
}

///|
/// The fingerprint of a public key.
fn fingerprint_of_pk(pk : FixedArray[Byte]) -> String {
  @keyfile.fingerprint_of_blob(@keyfile.ed25519_public_blob(pk))
}

///|
/// Whether a file is a private key file.
///
/// OpenSSH's test is on the FIRST line and is a substring test: it looks
/// for "PRIVATE KEY" in the first line of the file (ssh-keygen.c:950).
/// A file whose marker is further down is not a private key file to
/// OpenSSH, and this driver agrees with it.
fn is_private_key_file(text : String) -> Bool {
  let n = text.length()
  let mut stop = 0
  while stop < n && text[stop] != '\n' {
    stop = stop + 1
  }
  let first = text[0:stop].to_owned()
  first.contains("PRIVATE KEY")
}

///|
/// Print the public key of a private key file.
///
/// OpenSSH's `do_print_public` loads the PRIVATE file (ssh-keygen.c:785)
/// and writes the public key with `sshkey_write`, which is the same line
/// the `.pub` file holds: the key type, the base64 of the public blob,
/// and the comment -- with no trailing space when the comment is empty.
///
/// The line is printed, not the file text: the newline comes from the
/// print, so a line that already had one would end with two.
fn print_public(path : String, text : String, read_passphrase : String) -> Unit {
  match @keyfile.parse_private_file(text) {
    Ed25519(pair, comment) => println(@keyfile.public_line_text(pair, comment))
    Unsupported(why) =>
      if read_passphrase == "" {
        if @keyfile.private_file_is_encrypted(text) {
          // OpenSSH would ask for the passphrase on the terminal
          // (ssh-keygen.c:311).  There is no terminal here, and a tool
          // that waits for one that is not coming is a tool that hangs.
          fail(
            "ssh_keygen: " +
            escaped(path) +
            " is an encrypted private key; give the passphrase with -P",
          )
        } else {
          fail("Load key \"" + escaped(path) + "\": " + why)
        }
      } else {
        match
          @keyfile.parse_private_file_with_passphrase(text, read_passphrase) {
          Ed25519(pair, comment) =>
            println(@keyfile.public_line_text(pair, comment))
          WrongPassphrase(_) =>
            fail(
              "Load key \"" +
              escaped(path) +
              "\": incorrect passphrase supplied to decrypt private key",
            )
          Malformed(why) => fail("Load key \"" + escaped(path) + "\": " + why)
          Unsupported(why) => fail("Load key \"" + escaped(path) + "\": " + why)
        }
      }
    Malformed(why) => fail("Load key \"" + escaped(path) + "\": " + why)
    WrongPassphrase(why) => fail("Load key \"" + escaped(path) + "\": " + why)
  }
}
