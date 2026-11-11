///|
/// Loop #88: rewriting a private key file -- the comment rule.
///
/// This file holds the one part of a rewrite that needs no entropy
/// source: what counts as a change to the comment.  The rest of the
/// rewrite tests -- the ones that check the salt and the check word are
/// drawn afresh -- are in `rewrite_rng_test.mbt`, because drawing needs
/// a source the `wasm` targets do not have.
///
/// It used to hold three helpers (`test_seed`, `blob_of` and `index_of`)
/// that only that other file used.  They are over there now: `moon
/// check` reports an unused value per FILE while resolving names per
/// PACKAGE, so a helper defined here and called only there was reported
/// unused -- measured with the real compiler at HEAD, where `moon check
/// --deny-warn src/keyfile` failed on exactly those two names and nothing
/// else.  One file's helpers living in that file keeps a false positive
/// from being mistaken for dead code.

///|
/// A comment change is a change only when the comment differs.
///
/// OpenSSH compares the comment it read with the comment it was asked
/// for, and when they are the same it says `No change to comment` and
/// writes NOTHING (ssh-keygen.c:1545).
///
/// **The comment of a key with no comment is an EMPTY comment, not an
/// absent one.**  So `-c -C ""` on a key that has no comment is NOT a
/// change: the two are equal.  Measured with the real tool:
///
/// ```
/// Old comment:
/// No change to comment
/// ```
test "a_comment_change_is_a_change_only_when_the_comment_differs" {
  assert_true(@keyfile.comment_is_unchanged("old@loop88", "old@loop88"))
  assert_false(@keyfile.comment_is_unchanged("old@loop88", "new@loop88"))
  assert_false(@keyfile.comment_is_unchanged("old@loop88", ""))
  // And the empty comment against the empty comment.
  assert_true(@keyfile.comment_is_unchanged("", ""))
}
