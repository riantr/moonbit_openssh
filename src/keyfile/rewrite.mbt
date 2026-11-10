///|
/// Loop #88: rewriting a private key file.
///
/// Loop #85 made this repository able to WRITE a key file, Loop #86
/// gave the file a passphrase, and Loop #87 made it able to READ one.
/// What was left was the middle of the story: a key file that can be
/// read but not written again is a key file that can be created once
/// and then never changed -- and changing a key file is what
/// `ssh-keygen -p` (a new passphrase) and `ssh-keygen -c` (a new
/// comment) are for.
///
/// This file holds the one thing a rewrite needs that the make path
/// does not: **a file that is written again from a key that was read
/// out of an older file**.
///
/// **An empty passphrase means an UNENCRYPTED file.**  That is
/// OpenSSH's rule and not this repository's invention: in
/// `sshkey_private_to_blob2` (sshkey.c:2850) a passphrase that is
/// absent or empty makes the cipher `none` and the KDF `none`, and the
/// private block is then stored in the clear.
///
/// It is the rule that makes `ssh-keygen -p -N ""` a way to take the
/// passphrase OFF a key.  Measured with the real tool: a key written
/// with a passphrase, rewritten with an empty one, opens afterwards with
/// no passphrase at all -- and the tool says
/// `Your identification has been saved with the new passphrase.` about
/// it, which is OpenSSH's wording and not a promise that there IS a new
/// passphrase.
///
/// **The salt and the check word are drawn fresh, every time.**  That is
/// what OpenSSH does -- `arc4random_buf(salt, SALT_LEN)` and
/// `check = arc4random()` in `sshkey_private_to_blob2` -- and it is
/// not a detail.  A rewrite that kept the old salt would keep the old
/// passphrase's key material alive: the same salt and the same
/// passphrase derive the same key, so a file that kept its salt is a
/// file whose old passphrase is still worth something.
///
/// **The round count is the DEFAULT unless the caller says otherwise.**
/// OpenSSH's `ssh-keygen` has ONE global `rounds`, which is 0 unless
/// `-a` was given, and `sshkey_private_to_blob2` turns a 0 into
/// `DEFAULT_ROUNDS` (24).  So a rewrite does NOT keep the round count
/// the old file had: it uses the default, and a file written with
/// `-a 100` comes back with 24 rounds after a `-p`.
///
/// (That is OpenSSH's behaviour, and it is a mildly surprising one.
/// It is reproduced here rather than improved, because the point of
/// this package is to be the same file format, not a nicer one.)

///|
///
/// The text of a private key file that holds this key, under this
/// comment, with this passphrase.
///
/// **An empty passphrase writes an UNENCRYPTED file** and a non-empty
/// one writes an encrypted file.  See the note at the top of this file
/// for why that is OpenSSH's rule and not a choice made here.
///
/// **The salt and the check word are drawn here**, so the caller cannot
/// accidentally write a file that reuses the salt of an older one.
///
/// **An empty string means the file could not be built.**  That happens
/// when the KDF refuses the arguments -- an empty passphrase with the
/// encrypted path, or a round count outside the cap -- and it is
/// returned as an empty string rather than as a file, so that a caller
/// cannot write a file that claims to be encrypted and is not.
///
/// `rounds` of zero or less means the default, which is what OpenSSH
/// does with a `rounds` it was not given.
pub fn private_file_text_with_passphrase(
  pair : Ed25519KeyPair,
  comment : String,
  passphrase : String,
  rounds : Int32,
) -> String {
  let check = random_check_word()
  if passphrase == "" {
    // The unencrypted file.  The "none" cipher's block size is 8, and
    // the padding is the same 1, 2, 3, ... either way.
    return private_file_text(pair, comment, check)
  }
  let n = if rounds < 1 { DEFAULT_ROUNDS } else { rounds }
  private_file_text_encrypted(
    pair,
    comment,
    check,
    passphrase,
    random_salt(),
    n,
  )
}

///|
/// Whether a comment change is a change at all.
///
/// OpenSSH compares the comment it read with the comment it was asked
/// for, and when they are the same it says `No change to comment` and
/// writes NOTHING (ssh-keygen.c:1545).
///
/// **The comparison is of the comment, and the comment of a key with no
/// comment is an EMPTY comment, not an absent one.**  So `-c -C ""` on
/// a key that has no comment is NOT a change: the two are equal, and
/// the file is left alone.  Measured with the real tool:
///
/// ```
/// $ ssh-keygen -c -C "" -f key-with-no-comment
/// Old comment:
/// No change to comment
/// ```
///
/// The comparison is a plain string comparison, and that is the whole
/// of OpenSSH's rule: `strcmp(comment, new_comment) == 0`.
pub fn comment_is_unchanged(old_comment : String, new_comment : String) -> Bool {
  old_comment == new_comment
}
