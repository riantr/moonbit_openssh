///|
/// Loop #87: reading a public key line, and the lines OpenSSH prints
/// about one.
///
/// The vectors here are not hand-made.  The key is the one the rest of
/// this package's tests use -- a fixed seed, so the key is fixed -- and
/// the fingerprint was computed independently (SHA-256 over the public
/// blob, base64 without the padding) and then CHECKED AGAINST THE REAL
/// TOOL:
///
/// ```
/// $ ssh-keygen -l -f k.pub
/// 256 SHA256:VvxuUNEw8QPYQxk4kv+N/5t0DKHxwyE4iYP0soz3a34 e2e@loop87 (ED25519)
/// ```
///
/// So the fingerprint in this file is OpenSSH's fingerprint, and not
/// this repository's opinion about what OpenSSH's fingerprint is.

///|
/// The public key line of the test key, with its comment.
const PUB_LINE : String = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAqytvIbKMOIgGvsKbdoqs+uITDNb9/apuW5WIjFezCN e2e@loop87"

///|
/// The public key half of the test key.
const PUB_HEX : String = "0ab2b6f21b28c388806bec29b768aacfae2130cd6fdfdaa6e5b95888c57b308d"

///|
/// The fingerprint of the test key, as OpenSSH prints it.
const PUB_FINGERPRINT : String = "SHA256:VvxuUNEw8QPYQxk4kv+N/5t0DKHxwyE4iYP0soz3a34"

///|
/// A public key line gives the key and the comment.
test "a_public_key_line_gives_the_key_and_the_comment" {
  match @keyfile.parse_public_line(PUB_LINE) {
    Ed25519(pk, comment) => {
      assert_eq(hex_of(pk), PUB_HEX)
      match comment {
        None => abort("the comment of the line was lost")
        Some(c) => assert_eq(c, "e2e@loop87")
      }
    }
    Malformed(why) => abort("the line did not parse: " + why)
    Unsupported(why) => abort("the line was not supported: " + why)
  }
}

///|
/// A line with no comment gives NO comment -- and that is not the same
/// thing as an empty comment.
///
/// OpenSSH's `sshkey_try_load_public` (authfile.c:238) gives a `.pub`
/// FILE whose line has no comment the file's name, and its
/// `do_fingerprint` (ssh-keygen.c:989) gives a line with no comment
/// nothing at all.  The two rules disagree, so the parser reports the
/// FACT and the caller applies the rule it wants.
test "a_public_key_line_with_no_comment_gives_none" {
  let line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAqytvIbKMOIgGvsKbdoqs+uITDNb9/apuW5WIjFezCN"
  match @keyfile.parse_public_line(line) {
    Ed25519(pk, comment) => {
      assert_eq(hex_of(pk), PUB_HEX)
      match comment {
        None => ()
        Some(c) => abort("a line with no comment gave the comment " + c)
      }
    }
    Malformed(why) => abort("the line did not parse: " + why)
    Unsupported(why) => abort("the line was not supported: " + why)
  }
}

///|
/// The comment is the FACT, not the rule.
///
/// A comment that starts with '#' is a comment all the same, and the
/// parser says so.  Whether OpenSSH prints it or prints `no comment` is
/// OpenSSH's business and depends on which of its two rules applies,
/// and the rule is NOT this package's to apply: the two disagree.
test "a_comment_that_starts_with_a_hash_is_still_a_comment" {
  let line = PUB_LINE + " #a hash comment"
  match @keyfile.parse_public_line(line) {
    Ed25519(_, comment) =>
      match comment {
        None => abort("the comment was thrown away")
        Some(c) => assert_eq(c, "e2e@loop87 #a hash comment")
      }
    Malformed(why) => abort("the line did not parse: " + why)
    Unsupported(why) => abort("the line was not supported: " + why)
  }
}

///|
/// A file is scanned until a key is found.
///
/// OpenSSH's `sshkey_try_load_public` (authfile.c:229) reads line by
/// line and keeps going, so a file whose first line is a comment is a
/// file with a key in it.
test "a_public_key_file_is_scanned_until_a_key_is_found" {
  let text = "# a comment\n\n" + PUB_LINE + "\n"
  match @keyfile.parse_public_line(text) {
    Ed25519(pk, _) => assert_eq(hex_of(pk), PUB_HEX)
    Malformed(why) => abort("the file did not parse: " + why)
    Unsupported(why) => abort("the file was not supported: " + why)
  }
}

///|
/// A `known_hosts` line is read after the host name.
///
/// OpenSSH's `do_fingerprint` (ssh-keygen.c:962) tries the line as a
/// key, and when that fails it treats the first word as a host name and
/// tries again.  Only ONE word is skipped: skipping two would be a
/// guess, and a guess that finds a key in the wrong place is worse than
/// a refusal.
test "a_known_hosts_line_is_read_after_the_host_name" {
  let text = "example.com " + PUB_LINE + "\n"
  match @keyfile.parse_public_line(text) {
    Ed25519(pk, comment) => {
      assert_eq(hex_of(pk), PUB_HEX)
      match comment {
        None => abort("the comment of the line was lost")
        Some(c) => assert_eq(c, "e2e@loop87")
      }
    }
    Malformed(why) => abort("the line did not parse: " + why)
    Unsupported(why) => abort("the line was not supported: " + why)
  }
}

///|
/// Two words in front of the key are not read.
///
/// This is the other side of the rule above: a line that says
/// "something else ssh-ed25519 AAAA..." is refused rather than read,
/// because reading it would mean guessing where the key starts.
test "two_words_in_front_of_the_key_are_not_read" {
  let text = "example.com port 22 " + PUB_LINE + "\n"
  match @keyfile.parse_public_line(text) {
    Ed25519(_, _) => abort("a key was found in the wrong place")
    Malformed(_) => ()
    Unsupported(_) => ()
  }
}

///|
/// A line for another key type is unsupported, not malformed.
test "a_line_for_another_key_type_is_unsupported" {
  let text = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ example\n"
  match @keyfile.parse_public_line(text) {
    Ed25519(_, _) => abort("a key of another type was accepted")
    Malformed(why) => abort("it was reported as malformed instead: " + why)
    Unsupported(why) => assert_true(why.contains("ssh-rsa"))
  }
}

///|
/// A file with no ed25519 key in it is not read.
///
/// The answer is `Unsupported` and not `Malformed`, and the difference
/// is worth stating: this reader knows ONE key type, so a line whose key
/// type is not that one is a line it cannot read, and it cannot tell
/// "a key of another type" from "not a key at all" without a table of
/// the other types.  OpenSSH prints the same thing for both -- "is not a
/// public key file." -- so the difference does not reach the output.
test "a_public_key_file_with_no_key_in_it_is_not_read" {
  match @keyfile.parse_public_line("this is not a key\n") {
    Ed25519(_, _) => abort("a file with no key in it was accepted")
    Malformed(why) => abort("it was reported as malformed instead: " + why)
    Unsupported(why) => assert_true(why.contains("not ed25519"))
  }
}

///|
/// The fingerprint of a public blob is the SHA-256 of it.
///
/// Checked against the real tool: `ssh-keygen -l -f k.pub` prints
/// `256 SHA256:VvxuUNEw8QPYQxk4kv+N/5t0DKHxwyE4iYP0soz3a34`.
test "the_fingerprint_of_a_public_blob_is_the_sha256_of_it" {
  let pk = hex_bytes(PUB_HEX)
  assert_eq(
    @keyfile.fingerprint_of_blob(@keyfile.ed25519_public_blob(pk)),
    PUB_FINGERPRINT,
  )
}

///|
/// `no comment` and an empty comment leave a different number of spaces.
test "the_fingerprint_line_leaves_one_space_for_no_comment_and_two_for_an_empty_one" {
  assert_eq(
    @keyfile.fingerprint_line(PUB_FINGERPRINT, None),
    "256 " + PUB_FINGERPRINT + " no comment (ED25519)",
  )
  assert_eq(
    @keyfile.fingerprint_line(PUB_FINGERPRINT, Some("")),
    "256 " + PUB_FINGERPRINT + "  (ED25519)",
  )
  assert_eq(
    @keyfile.fingerprint_line(PUB_FINGERPRINT, Some("e2e@loop87")),
    "256 " + PUB_FINGERPRINT + " e2e@loop87 (ED25519)",
  )
}

///|
/// The public key LINE has no newline of its own.
///
/// The file has one, and the printed line gets one from the print.  A
/// line that had one already would end with two.
test "the_public_key_line_has_no_trailing_newline" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let line = @keyfile.public_line_text(pair, "e2e@loop87")
  assert_eq(
    line,
    "ssh-ed25519 " +
    "AAAAC3NzaC1lZDI1NTE5AAAAIAqytvIbKMOIgGvsKbdoqs+uITDNb9/apuW5WIjFezCN" +
    " e2e@loop87",
  )
  // And the file text is the same line with a newline on the end.
  assert_eq(@keyfile.public_file_text(pair, "e2e@loop87"), line + "\n")
}

///|
/// An empty comment leaves no trailing space on the line.
test "a_public_key_line_with_an_empty_comment_has_no_trailing_space" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let line = @keyfile.public_line_text(pair, "")
  assert_eq(
    line,
    "ssh-ed25519 " +
    "AAAAC3NzaC1lZDI1NTE5AAAAIAqytvIbKMOIgGvsKbdoqs+uITDNb9/apuW5WIjFezCN",
  )
}

///|
/// An encrypted private key gives its public key and NO comment.
///
/// The public blob of an `openssh-key-v1` file is in the clear, so
/// `ssh-keygen -l` prints the fingerprint of an encrypted key without
/// asking for anything.  The COMMENT is in the enciphered block, so it
/// cannot be read, and OpenSSH prints `no comment` for it.
test "an_encrypted_private_key_gives_the_key_but_not_the_comment" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let salt = hex_bytes("000102030405060708090a0b0c0d0e0f")
  let text = @keyfile.private_file_text_encrypted(
    pair, "e2e@loop87", 0x6983577DU, "correct horse", salt, 4,
  )
  assert_true(@keyfile.private_file_is_encrypted(text))
  match @keyfile.public_of_private_file(text) {
    None => abort("the public key could not be read from the encrypted file")
    Some((pk, comment)) => {
      assert_eq(hex_of(pk), PUB_HEX)
      match comment {
        None => ()
        Some(c) => abort("the comment of an encrypted key was read: " + c)
      }
    }
  }
}

///|
/// A private key in the clear gives its comment as well.
test "a_private_key_in_the_clear_gives_its_comment" {
  let seed = hex_bytes(
    "19ef1c43f6ca37ea207b091fa6683f111a8d15a05d4483012ef8c846f0e374e9",
  )
  let pair = @keyfile.derive_ed25519(seed)
  let text = @keyfile.private_file_text(pair, "e2e@loop87", 0x6983577DU)
  assert_false(@keyfile.private_file_is_encrypted(text))
  match @keyfile.public_of_private_file(text) {
    None => abort("the public key could not be read from the file")
    Some((pk, comment)) => {
      assert_eq(hex_of(pk), PUB_HEX)
      match comment {
        None => abort("the comment was lost")
        Some(c) => assert_eq(c, "e2e@loop87")
      }
    }
  }
}

///|
/// The log escaping doubles the backslashes.
///
/// OpenSSH runs every message through `strnvis` with `VIS_SAFE|VIS_OCTAL`
/// (log.c:69), and a backslash comes out doubled.  This is what the
/// real tool prints for a file that is not there:
///
/// ```
/// ssh-keygen: E:\\src\\moon\\nope: No such file or directory
/// ```
///
/// machine-path-exempt: the path in the two lines below is a VECTOR for the
/// escaping -- the example OpenSSH prints -- and not a path this code reads.
test "the_log_escaping_doubles_the_backslashes" {
  assert_eq(
    @keyfile.escape_log_text("E:\\src\\moon\\nope"),
    "E:\\\\src\\\\moon\\\\nope",
  )
  // And a string with no backslash in it is left alone.
  assert_eq(
    @keyfile.escape_log_text("No such file or directory"),
    "No such file or directory",
  )
}

///|
/// The log escaping keeps the characters that are safe to print.
test "the_log_escaping_keeps_the_printable_characters" {
  assert_eq(@keyfile.escape_log_text("a b\tc\nd"), "a b\tc\nd")
  // The glob characters are printable and stay as they are.
  assert_eq(@keyfile.escape_log_text("#*?[]"), "#*?[]")
}

///|
/// The log escaping writes the control characters in octal.
///
/// `vis` writes three octal digits, always: a NUL is `\000` and not
/// `\0`, because a reader that cannot tell the two apart cannot read the
/// message back.
test "the_log_escaping_writes_the_control_characters_in_octal" {
  assert_eq(@keyfile.escape_log_text("\u{01}"), "\\001")
  assert_eq(@keyfile.escape_log_text("\u{1F}"), "\\037")
  assert_eq(@keyfile.escape_log_text("\u{7F}"), "\\177")
}

///|
/// The log escaping works on BYTES, not on characters.
///
/// `vis` runs on a C string, so a character outside ASCII is more than
/// one byte and each byte is escaped on its own.  Working on the
/// characters would produce a different message.
test "the_log_escaping_works_on_bytes_and_not_on_characters" {
  // The Latin-1 letter e-acute is two bytes in UTF-8: 0xC3 0xA9.
  assert_eq(@keyfile.escape_log_text("\u{00E9}"), "\\303\\251")
}
