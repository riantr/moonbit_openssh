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
  // Loop #88: the two rewrites, and the three "was this option given
  // at all" flags.
  //
  // **The flags are not the same as an empty value.**  `-N ""` asks for
  // an EMPTY passphrase -- which takes the passphrase OFF a key -- and
  // no `-N` at all asks OpenSSH a question it asks on the terminal.
  // Those two are very different, and a tool that cannot tell them
  // apart either hangs or silently removes a passphrase.
  let mut change_passphrase = false
  let mut change_comment = false
  let mut have_new_passphrase = false
  let mut have_new_comment = false
  let mut have_read_passphrase = false
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
      have_new_comment = true
    } else if a == "-N" && i + 1 < args.length() {
      i = i + 1
      passphrase = args[i]
      have_new_passphrase = true
    } else if a == "-a" && i + 1 < args.length() {
      i = i + 1
      rounds = parse_rounds(args[i])
    } else if a == "-P" && i + 1 < args.length() {
      i = i + 1
      read_passphrase = args[i]
      have_read_passphrase = true
    } else if a == "-E" && i + 1 < args.length() {
      i = i + 1
      digest = args[i]
    } else if a == "-p" {
      change_passphrase = true
    } else if a == "-c" {
      change_comment = true
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
  // Loop #88: the two rewrites.
  //
  // `-p` and `-c` are the only options that change a key file that is
  // already there, and they are checked BEFORE the digest: `-E` is
  // about fingerprints, and a fingerprint is not what `-p` produces.
  // (OpenSSH checks the digest inside `do_fingerprint`, which does not
  // run for a rewrite at all, so `-p -E md5` is a rewrite for OpenSSH
  // and not a refusal.)
  //
  // **Only one of them at a time.**  OpenSSH says so and exits with 1
  // (ssh-keygen.c:3656):
  //
  //     Can only have one of -p and -c.
  //
  // OpenSSH then prints its whole usage text, and that text is not
  // printed here: it is OpenSSH's, it changes from one release to the
  // next, and a tool that prints another tool's usage text is a tool
  // that lies about what it can do.  The sentence carries the meaning,
  // so the sentence is what this prints.
  if change_passphrase && change_comment {
    eprintln("Can only have one of -p and -c.")
    @env.exit(1)
  }
  if change_passphrase || change_comment {
    rewrite_mode(RewriteRequest::{
      path,
      old_passphrase: read_passphrase,
      have_old_passphrase: have_read_passphrase,
      new_passphrase: passphrase,
      have_new_passphrase,
      new_comment: comment,
      have_new_comment,
      rounds,
      change_passphrase,
    })
    return
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
  let check = @keyfile.random_check_word()
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
///
/// **The work is done by `fail_with`.**  There is one place that
/// prints and one place that exits, and a second copy of those two
/// lines is a second place for them to drift apart in.
fn fail(message : String) -> Unit {
  fail_with(message)
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
    // Loop #91: `-y` prints the public half of any key this reader can
    // open, and the line is built from the file's own point -- no private
    // scalar is needed and nothing is written.  Measured against
    // `ssh-keygen -y -f <p256 key>` byte for byte.
    Ecdsa(pair, comment) =>
      println(@keyfile.ecdsa_public_line_text(pair, comment))
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
          Ecdsa(pair, comment) =>
            println(@keyfile.ecdsa_public_line_text(pair, comment))
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

///|
/// Loop #88: what a rewrite was asked to do.
///
/// The options of a run are its arguments; this is the subset of them
/// that the rewrite path needs, gathered in one place so that the
/// function that does the rewriting takes one argument instead of
/// eight.
struct RewriteRequest {
  path : String
  /// The passphrase the file is OPENED with: `-P`.
  old_passphrase : String
  have_old_passphrase : Bool
  /// The passphrase the file is SAVED with.
  ///
  /// For `-p` it is the NEW passphrase (`-N`).  For `-c` it is the one
  /// the file was opened with -- changing the comment does not change
  /// the passphrase -- and `-N` is only the CURRENT passphrase when
  /// there is no `-P`.
  new_passphrase : String
  have_new_passphrase : Bool
  /// The comment the file is SAVED with: `-C`.
  new_comment : String
  have_new_comment : Bool
  rounds : Int32
  /// True for `-p`, false for `-c`.
  change_passphrase : Bool
}

///|
/// Rewrite a private key file: `-p` (a new passphrase) or `-c` (a new
/// comment).
///
/// **The rules, all of them measured against the real tool.**  The
/// scripts that measured them are `.loop88/probe_truth.py`,
/// `.loop88/probe_more.py` and `.loop88/probe_three.py`, and the byte
/// comparison in `.loop88/compare_keygen88.py` is what holds the two
/// tools to them.
///
///   * `-p` prints `Key has comment '<comment>'` BEFORE it writes
///     anything, and `Your identification has been saved with the new
///     passphrase.` after.
///   * `-c` prints `Old comment: <comment>`, and then one of
///     `Comment '<new>' applied`, `Comment removed` (the new comment is
///     empty) or `No change to comment` (the comment is already the one
///     that was asked for -- and then NOTHING is written).
///   * an EMPTY comment still prints: `Key has comment ''` and
///     `Old comment: ` with a space and nothing after it.
///   * `-p` does NOT touch the `.pub` file; `-c` rewrites it with the
///     new comment, and writes it even when it was not there before.
///   * changing the comment does NOT change the passphrase: an
///     encrypted key is still encrypted with the same passphrase
///     afterwards.
///   * an empty new passphrase takes the passphrase OFF the key: the
///     file comes out unencrypted.
///   * the EMPTY passphrase is tried FIRST, so `-p -P whatever` on a
///     key with no passphrase works and the `-P` is never looked at.
///
/// **The two failure messages are different messages.**  `-p` says
/// `Failed to load key <path>: <why>` and `-c` says `Cannot load
/// private key "<path>": <why>`.  The reason is in the source: one
/// format string and the other (ssh-keygen.c:1397 and
/// ssh-keygen.c:1515).
///
/// **A file that is not there says so without the program name in
/// front of it**: `<path>: No such file or directory`.
///
/// **Nothing here asks a question.**  OpenSSH asks for the old
/// passphrase, for the new one and for the new comment on the
/// TERMINAL -- and with no terminal it does not fail, it BLOCKS.
/// Measured: `ssh-keygen -p -P "" -f key` with an empty stdin did not
/// return in 120 seconds.  A tool that waits for an answer that is not
/// coming is a tool that hangs, so this one refuses and says what is
/// missing.
async fn rewrite_mode(req : RewriteRequest) -> Unit {
  let path = req.path
  if path == "" {
    fail("ssh_keygen: -f <path> is required")
    return
  }
  // OpenSSH stats the file before it opens it (ssh-keygen.c:1379), and
  // the message for a file that is not there has the file's name in it
  // and NO program name in front of it:
  // `fatal("%s: %s", identity_file, strerror(errno))`.
  if !@fs.exists(path) {
    fail(escaped(path) + ": No such file or directory")
    return
  }
  let text = match read_text(path) {
    None => fail_with(escaped(path) + ": cannot be read")
    Some(t) => t
  }
  // The passphrase that OPENS the file.
  //
  // OpenSSH tries the EMPTY passphrase first (ssh-keygen.c:1382), and
  // only asks for the old one when the empty one is refused.  That is
  // why `-p -P whatever` works on a key with no passphrase: the empty
  // one opens it and the `-P` is never looked at.
  let encrypted = @keyfile.private_file_is_encrypted(text)
  let mut opening = ""
  if encrypted {
    if req.have_old_passphrase {
      opening = req.old_passphrase
    } else if !req.change_passphrase && req.have_new_passphrase {
      // For `-c`, the CURRENT passphrase is `-P`, or `-N` when there
      // is no `-P` (ssh-keygen.c:1506).  That is OpenSSH's order, and
      // it is a quirk worth naming: `-N` means "the new passphrase" in
      // `-p` and "the current passphrase" in `-c`.
      opening = req.new_passphrase
    } else {
      // OpenSSH would ask for it on the terminal
      // (ssh-keygen.c:1388).  There is no terminal here, and a tool
      // that waits for an answer that is not coming is a tool that
      // hangs.
      fail(
        "ssh_keygen: " +
        escaped(path) +
        " is an encrypted private key; give the passphrase with -P",
      )
      return
    }
  }
  let loaded = if encrypted {
    @keyfile.parse_private_file_with_passphrase(text, opening)
  } else {
    @keyfile.parse_private_file(text)
  }
  let (pair, comment) = match loaded {
    Ed25519(pair, comment) => (pair, comment)
    // Loop #91: `-y` reads an ECDSA key, but a rewrite (`-c`, `-p`) has
    // to write one back, and this writer still writes ed25519 only.  The
    // refusal is here rather than deeper because this is the last point
    // where the file is known to be good and the operation known to be
    // unimplemented; failing here cannot leave a half-written file.
    Ecdsa(_, _) =>
      fail_with(
        load_failure(
          req, path, "this tool rewrites ed25519 keys, and this is an ECDSA key",
        ),
      )
    // OpenSSH's word for a wrong passphrase.  It is the same word in
    // both modes, and it is not this repository's wording: a reader
    // that says "the passphrase is wrong" is a reader that knows
    // something the caller does not.
    WrongPassphrase(_) =>
      fail_with(
        load_failure(
          req, path, "incorrect passphrase supplied to decrypt private key",
        ),
      )
    // OpenSSH's word for a file that is not a key file at all.
    Malformed(_) => fail_with(load_failure(req, path, "invalid format"))
    Unsupported(reason) => fail_with(load_failure(req, path, reason))
  }
  if req.change_passphrase {
    // OpenSSH prints the comment it read BEFORE it writes anything
    // (ssh-keygen.c:1400).  The comment of a key with no comment is an
    // EMPTY comment and not an absent one, so the line reads
    // `Key has comment ''`.
    println("Key has comment '" + comment + "'")
    if !req.have_new_passphrase {
      // OpenSSH asks for the new passphrase twice
      // (ssh-keygen.c:1407).  There is no terminal here, and an
      // unanswered question is a hang.
      fail("ssh_keygen: give the new passphrase with -N")
      return
    }
    let text = @keyfile.private_file_text_with_passphrase(
      pair,
      comment,
      req.new_passphrase,
      req.rounds,
    )
    if text == "" {
      // The KDF refused the arguments.  There is then no file to
      // write, and a file that claims to be encrypted and is not is
      // worse than no file at all.
      fail("ssh_keygen: the passphrase could not be used")
      return
    }
    if !save_private(path, text) {
      return
    }
    println("Your identification has been saved with the new passphrase.")
    return
  }
  // -c
  //
  // OpenSSH prints the comment it read (ssh-keygen.c:1529).  The
  // comment of a key with no comment is an EMPTY comment and not an
  // absent one, so the line is `Old comment: ` with a space and
  // nothing after it.
  println("Old comment: " + comment)
  if !req.have_new_comment {
    // OpenSSH asks for the new comment on the terminal
    // (ssh-keygen.c:1536).  There is no terminal here.
    fail("ssh_keygen: give the new comment with -C")
    return
  }
  if @keyfile.comment_is_unchanged(comment, req.new_comment) {
    // The comment is already the one that was asked for, so OpenSSH
    // says so and writes NOTHING (ssh-keygen.c:1545).  Writing the
    // file anyway would change the salt and the check word: a NEW
    // file with the same contents.
    println("No change to comment")
    return
  }
  // The passphrase the file is SAVED with is the one it was OPENED
  // with: changing the comment does not change the passphrase
  // (ssh-keygen.c:1554).
  let text = @keyfile.private_file_text_with_passphrase(
    pair,
    req.new_comment,
    opening,
    req.rounds,
  )
  if text == "" {
    fail("ssh_keygen: the passphrase could not be used")
    return
  }
  if !save_private(path, text) {
    return
  }
  // The `.pub` file is rewritten too, with the new comment
  // (ssh-keygen.c:1568).  OpenSSH writes it even when it was not there
  // before.
  let w = write_public(
    path + ".pub",
    @keyfile.public_file_text(pair, req.new_comment),
  )
  if w != "" {
    fail("ssh_keygen: cannot write " + escaped(path) + ".pub: " + w)
    return
  }
  if req.new_comment != "" {
    println("Comment '" + req.new_comment + "' applied")
  } else {
    println("Comment removed")
  }
}

///|
/// The message for a file that could not be opened.
///
/// **The two modes have DIFFERENT messages, and the difference is in
/// OpenSSH's source.**  `-p` says `Failed to load key %s`
/// (ssh-keygen.c:1397) and `-c` says `Cannot load private key "%s"`
/// (ssh-keygen.c:1515).  One has no quotes around the path and the
/// other has them, and the path in both is escaped the way OpenSSH
/// escapes a path in a message.
fn load_failure(req : RewriteRequest, path : String, why : String) -> String {
  if req.change_passphrase {
    "Failed to load key " + escaped(path) + ": " + why
  } else {
    "Cannot load private key \"" + escaped(path) + "\": " + why
  }
}

///|
/// Write a rewritten private key file, and make it private again.
///
/// **The write is IN PLACE**, the way OpenSSH does it:
/// `sshbuf_write_file` opens the file with O_TRUNC and writes over
/// it.  A rewrite that wrote to a temporary file and renamed it would
/// be a different operation -- and one that changes the file's inode,
/// which a program holding the old one open would not notice.
///
/// **The file is made private again afterwards.**  OpenSSH does not do
/// that: it writes with `umask(077)`, which only affects a file that
/// is CREATED, so a file that was already there keeps the mode it
/// had.  This repository is stricter on purpose -- see the note in
/// `src/keyperm` -- and a key file that other users can read is not a
/// key file.
///
/// The answer is whether it worked.  A failure has already been
/// reported by the time this returns, and the caller has to stop.
async fn save_private(path : String, text : String) -> Bool {
  let w = rewrite_private(path, text)
  if w != "" {
    fail("ssh_keygen: cannot write " + escaped(path) + ": " + w)
    return false
  }
  if @keyperm.protect(path) != 0 {
    fail(
      "ssh_keygen: cannot restrict " +
      escaped(path) +
      " to its owner; the key is readable by other users",
    )
    return false
  }
  true
}

///|
/// Write a private key file over whatever is there.
///
/// This is the rewrite path, and it is DIFFERENT from the make path on
/// purpose.  The make path uses `CreateNew`, so that running the tool
/// twice cannot destroy a key that is already there.  The rewrite path
/// is the one place where overwriting IS the job: OpenSSH writes the
/// file it is rewriting in place, and a rewrite that refused to
/// overwrite would refuse to do the one thing it is for.
///
/// The empty string means success and anything else is the reason it
/// failed.
async fn rewrite_private(path : String, text : String) -> String {
  try {
    @fs.write_file(path, text, create_mode=@fs.CreateMode::CreateOrTruncate)
    ""
  } catch {
    e => e.to_string()
  }
}

///|
/// Fail, where a value of another type is expected.
///
/// `@env.exit` returns whatever type the caller asks for, so this can
/// stand in for a value in a place where the value is not a `Unit` --
/// a match arm that has to produce a pair, say.  The program never
/// gets there: `exit` does not come back.
///
/// **This is the one place that prints and the one place that exits.**
/// `fail` is the same thing for the places where a `Unit` is what is
/// wanted, and there is no second copy of these two lines.
fn[T] fail_with(message : String) -> T {
  eprintln(message)
  @env.exit(255)
}
