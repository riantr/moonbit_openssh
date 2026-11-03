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
    } else if a == "-q" {
      quiet = true
    } else {
      println("ssh_keygen: unknown argument: " + a)
      return
    }
    i = i + 1
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
/// block, so that a reader can tell whether the file was encrypted with
/// the passphrase it thinks it was.
///
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
