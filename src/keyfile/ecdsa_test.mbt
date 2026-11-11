///|
/// Loop #91: reading an ECDSA private key file.
///
/// ## The vectors are real
///
/// Every byte below came out of a real `ssh-keygen -t ecdsa` run, and
/// every expected public line is what the real `ssh-keygen -y` printed
/// for the same file.  Nothing here is remembered from a document.
///
/// The four files are chosen to cover the three things that are easy to
/// get wrong, which is why there are four and not one:
///
/// | file | curve | point | `d` as written | padding |
/// |------|-------|-------|----------------|---------|
/// | k256 | P-256 | 65 | 32 bytes | `01 02` |
/// | k384 | P-384 | 97 | **49** bytes, leading `00` | `01..05` |
/// | k521 | P-521 | 133 | **66** bytes, leading `01` | none |
/// | k0 | P-256 | 65 | **33** bytes, leading `00` | `01` |
///
/// Three of those four columns are traps:
///
/// 1. **`d` is an `mpint`, not a fixed-width integer.**  A scalar whose
///    top bit is set is written with a leading `00` and is one byte
///    longer (k384, k0).  A reader that truncates to 32 bytes gets a
///    different key and no error -- which is why k0 is here: it is the
///    P-256 case, the one everybody writes the fixed width for.
/// 2. **P-521's `d` is genuinely 66 bytes.**  Its top byte is `01`,
///    which is a real bit of the number and not a sign byte, so the
///    "strip a leading zero" rule must not fire on it.  A reader that
///    assumes the width is `point_width / 2` gets 66 and then has to
///    explain why P-521 alone is different.
/// 3. **P-521's padding is empty.**  Its block happens to be a whole
///    number of 8-byte words already, so `(8 - used % 8) % 8` is 0 and
///    the padding is nothing at all.  A reader that insists on at least
///    one padding byte rejects every fifth P-521 key.
///
/// The public line is the strongest single assertion available: it is
/// curve + point + comment + base64 + newline, compared against what
/// `ssh-keygen -y` actually printed.

///|
/// The `hex_bytes` of the other test files, under a name of this file's
/// own.
///
/// Test files in this package are compiled together but the unused-value
/// analysis is per file, so a helper defined in one file and used only in
/// another is reported unused (measured at HEAD with the real compiler).
/// Keeping this file's helpers in this file keeps that false positive out
/// of the way.
fn ecdsa_hex_bytes(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length() / 2, b'\x00')
  for i = 0; i < s.length() / 2; i = i + 1 {
    let hi = ecdsa_nibble(s[i * 2])
    let lo = ecdsa_nibble(s[i * 2 + 1])
    out[i] = (hi * 16 + lo).to_byte()
  }
  out
}

///|
/// One hex digit as a number.
fn ecdsa_nibble(c : UInt16) -> Int32 {
  if c >= '0' && c <= '9' {
    (c - '0').to_int()
  } else if c >= 'a' && c <= 'f' {
    (c - 'a').to_int() + 10
  } else {
    (c - 'A').to_int() + 10
  }
}

///|
/// A byte array as lowercase hex.
fn ecdsa_hex_of(b : FixedArray[Byte]) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_string(digits.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(digits.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}

///|
/// The bytes of a private key file, with the markers and line breaks
/// taken off.
fn ecdsa_blob_of(text : String) -> FixedArray[Byte] {
  let begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
  let end = "-----END OPENSSH PRIVATE KEY-----"
  let b = ecdsa_index_of(text, begin)
  let e = ecdsa_index_of(text, end)
  if b < 0 || e < 0 {
    abort("the file has no markers in it")
  }
  let view : StringView = text[b + begin.length():e]
  let raw = @base64.decode(view, ignore_whitespace=true) catch {
    _ => abort("the body of the file does not decode")
  }
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}

///|
/// The index of `needle` in `hay`, or -1.
fn ecdsa_index_of(hay : String, needle : String) -> Int32 {
  let n = hay.length()
  let m = needle.length()
  if m == 0 || m > n {
    return -1
  }
  let mut at = 0
  while at + m <= n {
    let mut same = true
    let mut j = 0
    while j < m {
      if hay[at + j] != needle[j] {
        same = false
        break
      }
      j = j + 1
    }
    if same {
      return at
    }
    at = at + 1
  }
  -1
}

///|
/// The file with a run of bytes replaced, written back as a key file.
///
/// The patch is applied to the decoded bytes and the whole file is
/// re-marked, so a test can damage exactly one field and leave the rest
/// of the file -- the lengths, the envelope, the base64 -- untouched.
/// A run rather than a byte, because the curve name is eight bytes and a
/// test that renamed it one byte at a time would be testing the patcher.
fn ecdsa_patched(text : String, at : Int32, hex : String) -> String {
  let b = ecdsa_blob_of(text)
  let v = ecdsa_hex_bytes(hex)
  for i = 0; i < v.length(); i = i + 1 {
    b[at + i] = v[i]
  }
  @keyfile.encode_pem(b)
}

///|
/// The public line `ssh-keygen -y` printed for `.loop91/k256`.
///
/// Measured, not composed: this is the tool's output, and the point of
/// the test is that this repository's output is the same bytes.
const ECDSA_LINE_256 : String = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFBijCc+YTJLDMcdt8y6wSLL8b9kOoSomSKe1qervLTRYKp4hXQ2QxHw7bD8QAlvFAAq9I0P/4/KGWDUOYJk/dc= loop91"

///|
/// The base64 body of `.loop91/k256`, no passphrase.
const ECDSA_BODY_256 : String = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRQYownPmEySwzHHbfMusEiy/G/ZDqEqJkintanq7y00WCqeIV0NkMR8O2w/EAJbxQAKvSND/+Pyhlg1DmCZP3XAAAAoKdEDoGnRA6BAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFBijCc+YTJLDMcdt8y6wSLL8b9kOoSomSKe1qervLTRYKp4hXQ2QxHw7bD8QAlvFAAq9I0P/4/KGWDUOYJk/dcAAAAgMuQSl3OYtDIB2sYsxCPYb2/Hpy/JM8r/fCv7XE2AmroAAAAGbG9vcDkxAQI="

///|
/// The public line `ssh-keygen -y` printed for `.loop91/k384`.
const ECDSA_LINE_384 : String = "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBLgIfttkAsFzjwn2UlR4TPbAsThqS+fapgAquCFxNAIQb+RjrvCNWK1Cji3P+QP5wVIyS6aMiUvw3WXV95b25rwiprh3KCWKOXnD7embvQ0VEHDeE+wuCDaTui5q6/Ibqg== loop91p384"

///|
/// The base64 body of `.loop91/k384`, no passphrase.
const ECDSA_BODY_384 : String = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAiAAAABNlY2RzYS1zaGEyLW5pc3RwMzg0AAAACG5pc3RwMzg0AAAAYQS4CH7bZALBc48J9lJUeEz2wLE4akvn2qYAKrghcTQCEG/kY67wjVitQo4tz/kD+cFSMkumjIlL8N1l1feW9ua8Iqa4dyglijl5w+3pm70NFRBw3hPsLgg2k7ouauvyG6oAAADYBj6+mgY+vpoAAAATZWNkc2Etc2hhMi1uaXN0cDM4NAAAAAhuaXN0cDM4NAAAAGEEuAh+22QCwXOPCfZSVHhM9sCxOGpL59qmACq4IXE0AhBv5GOu8I1YrUKOLc/5A/nBUjJLpoyJS/DdZdX3lvbmvCKmuHcoJYo5ecPt6Zu9DRUQcN4T7C4INpO6Lmrr8huqAAAAMQDpUWNAkj01x/t8vg2WQmUwPimicpiNJ2+LSUENVNepp23oc7sIYfs6RYWIn/jsXugAAAAKbG9vcDkxcDM4NAECAwQF"

///|
/// The public line `ssh-keygen -y` printed for `.loop91/k521`.
const ECDSA_LINE_521 : String = "ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAG/YM+2su64DRskysO8mBiaHd84/q+z34urjQ93jnoVJdfxX+AYMU8WKZp0cCKsTj3ZW9H9dMTwFu/JcWwNhYVfPwHapwJDDfO/5+M3Ljd5+9VvEoy1ehb+jyHGYCoVZQspli4kGxHY+vu0q9+UJt17kTSaJK6HpjMj4dJYzC7nAt30fA== loop91p521"

///|
/// The base64 body of `.loop91/k521`, no passphrase.
const ECDSA_BODY_521 : String = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAArAAAABNlY2RzYS1zaGEyLW5pc3RwNTIxAAAACG5pc3RwNTIxAAAAhQQBv2DPtrLuuA0bJMrDvJgYmh3fOP6vs9+Lq40Pd456FSXX8V/gGDFPFimadHAirE492VvR/XTE8BbvyXFsDYWFXz8B2qcCQw3zv+fjNy43efvVbxKMtXoW/o8hxmAqFWULKZYuJBsR2Pr7tKvflCbde5E0miSuh6YzI+HSWMwu5wLd9HwAAAEIrV+Aoa1fgKEAAAATZWNkc2Etc2hhMi1uaXN0cDUyMQAAAAhuaXN0cDUyMQAAAIUEAb9gz7ay7rgNGyTKw7yYGJod3zj+r7Pfi6uND3eOehUl1/Ff4BgxTxYpmnRwIqxOPdlb0f10xPAW78lxbA2FhV8/AdqnAkMN87/n4zcuN3n71W8SjLV6Fv6PIcZgKhVlCymWLiQbEdj6+7Sr35Qm3XuRNJokroemMyPh0ljMLucC3fR8AAAAQgGTQ/BF7nggxRHX+1mEKiirIPOmHEpJaCXh+FEao6OUo/M/CnqZPqoUbAtSmPUtfQMR4GWsmo7RArJAfSkyedDgGAAAAApsb29wOTFwNTIx"

///|
/// The public line `ssh-keygen -y` printed for `.loop91/mpint/k0`, whose
/// scalar has its top bit set.
const ECDSA_LINE_MPINT : String = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCBh1grBTCDW8LR39eijItVkRRHxQzYIa3wxhCtA8UfMtmn+KL1B+vx98lcaj5HyOlq2d31cbNkbWA64X2PLS5Q= mpint0"

///|
/// The base64 body of `.loop91/mpint/k0`, no passphrase.
const ECDSA_BODY_MPINT : String = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQgYdYKwUwg1vC0d/XooyLVZEUR8UM2CGt8MYQrQPFHzLZp/ii9Qfr8ffJXGo+R8jpatnd9XGzZG1gOuF9jy0uUAAAAoN0kF4XdJBeFAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCBh1grBTCDW8LR39eijItVkRRHxQzYIa3wxhCtA8UfMtmn+KL1B+vx98lcaj5HyOlq2d31cbNkbWA64X2PLS5QAAAAhALWURWzxkdc2nwD8S4poWEkP7lr2gU2663d4xAuG03BlAAAABm1waW50MAE="

///|
/// The file text of a body, marked up the way `ssh-keygen` writes it.
fn ecdsa_file(body : String) -> String {
  "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
  body +
  "\n-----END OPENSSH PRIVATE KEY-----\n"
}

///|
/// A real P-256 key file reads, and its public line is the one the real
/// `ssh-keygen -y` printed.
///
/// The scalar is asserted byte for byte.  It is the one field this
/// package did not have before, and it is the field a signature is made
/// from: a reader that returns the right point and the wrong scalar
/// returns a key that authenticates as nobody.
test "the_p256_file_reads_and_its_line_is_the_one_openssh_prints" {
  let text = ecdsa_file(ECDSA_BODY_256)
  match @keyfile.parse_private_file(text) {
    Ecdsa(pair, comment) => {
      assert_eq(pair.curve, "nistp256")
      assert_eq(comment, "loop91")
      // 65 = 04 || X(32) || Y(32).
      assert_eq(pair.point.length(), 65)
      assert_eq(pair.point[0].to_int(), 4)
      assert_eq(
        ecdsa_hex_of(pair.point),
        "0450628c273e61324b0cc71db7ccbac122cbf1bf643a84a899229ed6a7abbcb4d160aa788574364311f0edb0fc40096f14002af48d0fff8fca1960d4398264fdd7",
      )
      assert_eq(
        ecdsa_hex_of(pair.scalar),
        "32e412977398b43201dac62cc423d86f6fc7a72fc933caff7c2bfb5c4d809aba",
      )
      assert_eq(@keyfile.ecdsa_public_line_text(pair, comment), ECDSA_LINE_256)
    }
    Malformed(why) => abort("a real P-256 file was refused: " + why)
    Unsupported(why) => abort("a real P-256 file was unsupported: " + why)
    WrongPassphrase(why) =>
      abort("a real P-256 file wanted a passphrase: " + why)
    Ed25519(_, _) => abort("a P-256 file was read as an ed25519 key")
  }
}

///|
/// A real P-384 and a real P-521 file read too, at their own widths.
///
/// This is the test that catches a reader with one width for all three
/// curves.  P-384's point is 97 bytes and P-521's is 133 -- 521 bits is
/// 66 bytes with seven bits of the last byte unused, and a reader that
/// rounds it to 64 rejects every P-521 key as malformed.
///
/// P-521's `d` is 66 bytes, and its first byte is `01`.  That `01` is a
/// real bit of a 521-bit number, not an `mpint` sign byte, so the
/// "strip a leading zero" rule must not touch it -- and `assert_eq` on
/// the length says whether it did.
test "the_p384_and_p521_files_read_at_their_own_widths" {
  match @keyfile.parse_private_file(ecdsa_file(ECDSA_BODY_384)) {
    Ecdsa(pair, comment) => {
      assert_eq(pair.curve, "nistp384")
      assert_eq(comment, "loop91p384")
      assert_eq(pair.point.length(), 97)
      assert_eq(pair.point[0].to_int(), 4)
      assert_eq(pair.scalar.length(), 48)
      assert_eq(
        ecdsa_hex_of(pair.scalar),
        "e9516340923d35c7fb7cbe0d964265303e29a272988d276f8b49410d54d7a9a76de873bb0861fb3a4585889ff8ec5ee8",
      )
      assert_eq(@keyfile.ecdsa_public_line_text(pair, comment), ECDSA_LINE_384)
    }
    Malformed(why) => abort("a real P-384 file was refused: " + why)
    Unsupported(why) => abort("a real P-384 file was unsupported: " + why)
    WrongPassphrase(why) =>
      abort("a real P-384 file wanted a passphrase: " + why)
    Ed25519(_, _) => abort("a P-384 file was read as an ed25519 key")
  }
  match @keyfile.parse_private_file(ecdsa_file(ECDSA_BODY_521)) {
    Ecdsa(pair, comment) => {
      assert_eq(pair.curve, "nistp521")
      assert_eq(comment, "loop91p521")
      assert_eq(pair.point.length(), 133)
      assert_eq(pair.point[0].to_int(), 4)
      // 66, and the leading 01 kept: a 521-bit scalar's top byte is a
      // bit of the number.
      assert_eq(pair.scalar.length(), 66)
      assert_eq(pair.scalar[0].to_int(), 1)
      assert_eq(@keyfile.ecdsa_public_line_text(pair, comment), ECDSA_LINE_521)
    }
    Malformed(why) => abort("a real P-521 file was refused: " + why)
    Unsupported(why) => abort("a real P-521 file was unsupported: " + why)
    WrongPassphrase(why) =>
      abort("a real P-521 file wanted a passphrase: " + why)
    Ed25519(_, _) => abort("a P-521 file was read as an ed25519 key")
  }
}

///|
/// A P-256 scalar whose top bit is set keeps all 32 of its bytes.
///
/// The file writes it as 33 bytes with a leading `00`, because an
/// `mpint`'s top bit is a sign bit.  A reader that takes the first 32
/// bytes of the field gets `00 || 31 bytes` -- a different number, a
/// different key, and no error anywhere.  This is the fixture that
/// catches it, and the public line is the proof: it is built from the
/// point, so the line would still match, which is why the scalar itself
/// is asserted here.
test "a_scalar_whose_top_bit_is_set_keeps_all_of_its_bytes" {
  // The field as written is 33 bytes; the scalar that comes out is 32.
  let raw = ecdsa_blob_of(ecdsa_file(ECDSA_BODY_MPINT))
  assert_eq(raw.length(), 311)
  match @keyfile.parse_private_file(ecdsa_file(ECDSA_BODY_MPINT)) {
    Ecdsa(pair, comment) => {
      assert_eq(comment, "mpint0")
      assert_eq(pair.scalar.length(), 32)
      assert_eq(
        ecdsa_hex_of(pair.scalar),
        "b594456cf191d7369f00fc4b8a6858490fee5af6814dbaeb7778c40b86d37065",
      )
      assert_eq(
        @keyfile.ecdsa_public_line_text(pair, comment),
        ECDSA_LINE_MPINT,
      )
    }
    Malformed(why) => abort("a real mpint file was refused: " + why)
    Unsupported(why) => abort("a real mpint file was unsupported: " + why)
    WrongPassphrase(why) =>
      abort("a real mpint file wanted a passphrase: " + why)
    Ed25519(_, _) => abort("a P-256 file was read as an ed25519 key")
  }
}

// The offsets the patch tests below use, measured once.
//
// For the P-256 fixture the file is 311 bytes:
//
// ```
//  0  15  magic
// 15   8  cipher    ("none")
// 23   8  KDF       ("none")
// 31   4  KDF options (empty)
// 35   4  number of keys
// 39 108  public blob (4 length + 104)
// 147 164 private block (4 length + 160)
// ```
//
// so the private block's data starts at 151, and inside it:
//
// ```
//  0   8  the two check words
//  8  23  key type   ("ecdsa-sha2-nistp256")
// 31  12  curve      ("nistp256")
// 43  69  point      (04 || X || Y)
// 112 36  scalar d
// 148 10  comment    ("loop91")
// 158  2  padding    (01 02)
// ```
//
// The offsets are written as numbers rather than computed from those
// numbers, because a computed offset would agree with a wrong layout.

///|
/// A point that is not an uncompressed point is refused.
///
/// `0x02` is a legitimate SEC1 compressed point; OpenSSH's private file
/// format never writes one, so refusing it is a statement about this
/// file format and not about ECDSA.
test "a_point_that_is_not_uncompressed_is_refused" {
  // 151 + 47: the point's own first byte, which is 04 in the real file.
  let text = ecdsa_patched(ecdsa_file(ECDSA_BODY_256), 198, "02")
  match @keyfile.parse_private_file(text) {
    Malformed(why) => assert_true(why.contains("uncompressed"))
    Ed25519(_, _) => abort("a damaged P-256 file was read as ed25519")
    Ecdsa(_, _) => abort("a compressed point was accepted")
    Unsupported(why) =>
      abort("a compressed point was called unsupported: " + why)
    WrongPassphrase(why) =>
      abort("a compressed point wanted a passphrase: " + why)
  }
}

///|
/// A key type that disagrees with its own curve field is refused.
///
/// `nistp256`, `nistp384` and `nistp521` are the **same length**, so a
/// reader that compares lengths instead of strings cannot tell them
/// apart.  This is the test that says so: the file still says
/// `ecdsa-sha2-nistp256` in its type string while its curve field now
/// says `nistp384`, and the two disagree.
test "a_curve_that_disagrees_with_the_key_type_is_refused" {
  // 151 + 35: the curve name, rewritten to another curve of the same
  // eight bytes.
  let text = ecdsa_patched(ecdsa_file(ECDSA_BODY_256), 186, "6e69737470333834")
  match @keyfile.parse_private_file(text) {
    Malformed(why) => assert_true(why.contains("the curve field says"))
    Ed25519(_, _) => abort("a damaged P-256 file was read as ed25519")
    Ecdsa(_, _) => abort("a type and a curve that disagree were accepted")
    Unsupported(why) => abort("it was called unsupported instead: " + why)
    WrongPassphrase(why) => abort("it wanted a passphrase: " + why)
  }
}

///|
/// A curve that is not one of the three says so, and says which.
///
/// `Unsupported` rather than `Malformed`: the file is a key file, this
/// reader simply does not have that curve.  The same distinction the
/// package already makes for key types.
test "a_curve_that_is_not_one_of_the_three_is_unsupported" {
  let text = ecdsa_patched(ecdsa_file(ECDSA_BODY_256), 186, "6e6973746b313633")
  match @keyfile.parse_private_file(text) {
    Unsupported(why) => assert_true(why.contains("nistk163"))
    Ed25519(_, _) => abort("an unknown curve was read as ed25519")
    Ecdsa(_, _) => abort("an unknown curve was accepted")
    Malformed(why) => abort("an unknown curve was called malformed: " + why)
    WrongPassphrase(why) =>
      abort("an unknown curve wanted a passphrase: " + why)
  }
}

///|
/// Padding that is not `01 02 03 ...` is refused, and the refusal does
/// not blame a passphrase.
///
/// This is the one place where copying OpenSSH's sentence would be
/// actively misleading.  OpenSSH uses a padding mismatch to detect a
/// wrong passphrase, because with a passphrase a mismatch is the
/// expected result of a wrong one.  With no passphrase there is no
/// passphrase to blame, and a reader that said "incorrect passphrase"
/// would send a user looking for a password that does not exist.
test "padding_that_is_wrong_is_refused_without_blaming_a_passphrase" {
  // 151 + 158: the first padding byte, 01 in the real file.
  let text = ecdsa_patched(ecdsa_file(ECDSA_BODY_256), 309, "09")
  match @keyfile.parse_private_file(text) {
    Malformed(why) => {
      assert_true(why.contains("padding"))
      assert_false(why.contains("passphrase"))
    }
    Ed25519(_, _) => abort("a damaged P-256 file was read as ed25519")
    Ecdsa(_, _) => abort("wrong padding was accepted")
    Unsupported(why) => abort("wrong padding was called unsupported: " + why)
    WrongPassphrase(why) =>
      abort("wrong padding was blamed on a passphrase: " + why)
  }
}

///|
/// An envelope that disagrees with the private half is refused.
///
/// The file carries the public key twice: once as the envelope's blob
/// and once as the point inside the private block.  A file where the two
/// disagree is a file whose copy is damaged, and OpenSSH checks the same
/// thing (`sshkey.c:3214`).
test "an_envelope_that_disagrees_with_the_private_half_is_refused" {
  // 43 + 39: the envelope's own copy of the point's first byte.
  let text = ecdsa_patched(ecdsa_file(ECDSA_BODY_256), 82, "05")
  match @keyfile.parse_private_file(text) {
    Malformed(why) =>
      assert_true(why.contains("does not match the private half"))
    Ed25519(_, _) => abort("a damaged P-256 file was read as ed25519")
    Ecdsa(_, _) => abort("an envelope that disagrees was accepted")
    Unsupported(why) => abort("it was called unsupported instead: " + why)
    WrongPassphrase(why) => abort("it wanted a passphrase: " + why)
  }
}

///|
/// A field length that does not fit its field is refused, not obeyed.
///
/// The scalar's length is a four-byte word in front of the scalar, and
/// the reader takes it from the file.  A length that is one byte too
/// large makes every field after it start one byte late, and the reader
/// must end up refusing rather than reading past the end of the block.
test "a_length_that_does_not_fit_its_field_is_refused" {
  // 151 + 112: the scalar's length prefix, 32 written as 33.
  let text = ecdsa_patched(ecdsa_file(ECDSA_BODY_256), 263, "00000021")
  match @keyfile.parse_private_file(text) {
    Malformed(_) => ()
    Ed25519(_, _) => abort("a damaged P-256 file was read as ed25519")
    Ecdsa(_, _) => abort("a scalar one byte too long was accepted")
    Unsupported(why) => abort("it was called unsupported instead: " + why)
    WrongPassphrase(why) => abort("it wanted a passphrase: " + why)
  }
}

///|
/// The three helpers that decide a width agree with a real file.
///
/// P-521 is the case worth pinning: 521 bits is 66 bytes, and its point
/// is 133.  A `point_width / 2` that rounded down to 32 would give 64
/// and 129.
test "the_curve_widths_are_the_measured_ones" {
  assert_eq(@keyfile.ecdsa_point_width("nistp256"), 65)
  assert_eq(@keyfile.ecdsa_point_width("nistp384"), 97)
  assert_eq(@keyfile.ecdsa_point_width("nistp521"), 133)
  // The largest the scalar may be, the leading mpint zero included.
  assert_eq(@keyfile.ecdsa_scalar_max("nistp256"), 33)
  assert_eq(@keyfile.ecdsa_scalar_max("nistp384"), 49)
  assert_eq(@keyfile.ecdsa_scalar_max("nistp521"), 67)
  // And the three names are the same length, which is why they have to
  // be compared as strings.
  assert_eq("nistp256".length(), "nistp384".length())
  assert_eq("nistp384".length(), "nistp521".length())
  assert_true(@keyfile.ecdsa_is_curve("nistp256"))
  assert_false(@keyfile.ecdsa_is_curve("nistk163"))
  assert_true(@keyfile.ecdsa_is_key_type("ecdsa-sha2-nistp521"))
  assert_false(@keyfile.ecdsa_is_key_type("ssh-ed25519"))
}
