///| ECDSA private keys, as OpenSSH stores them (Loop #91).
///
/// ## Why this exists
///
/// `src/keyfile` could read and write exactly one kind of key: ed25519.
/// Everything else came back `Unsupported`, which was honest but meant a
/// real client could not be pointed at the key most Windows installs
/// actually have -- and `scp -i <key>` needs one.
///
/// ## The layout, measured rather than remembered
///
/// Decoded from real `ssh-keygen -t ecdsa -b 256` output
/// (`.loop91/DESIGN.md` has the walker).  The private block is:
///
/// ```
/// u32    checkint1
/// u32    checkint2        equal to checkint1
/// string key type         "ecdsa-sha2-nistp256"
/// string curve id         "nistp256"          <-- ed25519 has no such field
/// string Q                04 <X> <Y>
/// string d                the scalar, an mpint
/// string comment
/// bytes  padding          01 02 03 ...
/// ```
///
/// and the public blob in the same file is exactly
/// `string type || string curve id || string Q` -- 104 bytes for P-256.
///
/// ## The three ways to get this wrong
///
/// 1. **Copying the ed25519 shape.**  ed25519's block is
///    `type || pk || sk || comment`; ECDSA's carries the curve id as its
///    own string first.  A reader that copies the shape reads
///    `nistp256`(8) as the point and the point(65) as the scalar.  Both
///    lengths look plausible, so nothing fails until a signature is wrong.
/// 2. **Treating `d` as fixed-width.**  It is an `mpint`: a scalar whose
///    high bit is set carries a leading `00` and is one byte longer.
///    Truncating to 32 bytes silently yields a different key.
/// 3. **Ignoring the padding.**  It is `01 02 03 ...`, and a mismatch is
///    how a decrypting reader detects a wrong passphrase.  With no
///    passphrase a mismatch can only mean corruption, so this reader says
///    so with its own sentence instead of blaming a passphrase nobody
///    typed.
///
/// ## What is NOT here
///
/// No signature.  Producing an ECDSA signature from this scalar is
/// `src/ecdsa`'s job and it already takes a scalar
/// (`@ecdsa.ecdsa_sign(curve, d, ...)`); this file only gets the scalar
/// out of the file.  No PEM/SEC1 reading either: OpenSSH's own format is
/// what `ssh-keygen` writes here, and a second container format would be
/// a second parser with no caller.

///|
/// One ECDSA key, as the file carries it.
///
/// `scalar` has its `mpint` leading zero stripped, so its length is the
/// curve's own width (32 for P-256) in the ordinary case and one byte more
/// never.  `point` keeps its `0x04` prefix: it is the wire form, and the
/// signature code wants the wire form.
pub(all) struct EcdsaKeyPair {
  /// `nistp256`, `nistp384` or `nistp521`
  curve : String
  /// `04 || X || Y`
  point : FixedArray[Byte]
  /// the private scalar, big-endian, no leading zero
  scalar : FixedArray[Byte]
}

///|
/// The key type string for a curve: `ecdsa-sha2-` + the curve id.
///
/// Measured: the three names are the **same length**, so a reader that
/// compares lengths instead of strings cannot tell the curves apart --
/// which is why `ecdsa_curve_width` below switches on the string.
pub fn ecdsa_key_type(curve : String) -> String {
  "ecdsa-sha2-" + curve
}

///|
/// Whether a key-type string is one of the three ECDSA types.
pub fn ecdsa_is_key_type(ktype : String) -> Bool {
  ktype == "ecdsa-sha2-nistp256" ||
  ktype == "ecdsa-sha2-nistp384" ||
  ktype == "ecdsa-sha2-nistp521"
}

///|
/// Whether a string is one of the three curve identifiers.
pub fn ecdsa_is_curve(curve : String) -> Bool {
  curve == "nistp256" || curve == "nistp384" || curve == "nistp521"
}

///|
/// The width of the uncompressed point, `04 || X || Y`, per curve.
///
/// 65 / 97 / 133: `1 + 2 * ceil(bits / 8)` for 256 / 384 / 521.  P-521 is
/// the odd one -- 521 bits is 66 bytes with the top seven bits unused, and
/// a reader that assumes 64 would reject every 521 key as malformed.
pub fn ecdsa_point_width(curve : String) -> Int32 {
  if curve == "nistp384" {
    97
  } else if curve == "nistp521" {
    133
  } else {
    65
  }
}

///|
/// The largest the `mpint` scalar may be, leading zero included.
///
/// One more than the curve's byte width: P-256's `d` is 32 bytes, or 33
/// when bit 255 is set and the `mpint` encoding needs the `00` prefix.
pub fn ecdsa_scalar_max(curve : String) -> Int32 {
  ecdsa_point_width(curve) / 2 + 1
}

///|
/// The wire form of the public half: `string type || string curve || string Q`.
///
/// This is what the private file's public blob holds, byte for byte, and
/// what `ssh-keygen -y` prints after base64-decoding its second field.
pub fn ecdsa_public_blob(pair : EcdsaKeyPair) -> FixedArray[Byte] {
  cat([
    @sshwire.write_ssh_string(utf8_bytes(ecdsa_key_type(pair.curve))),
    @sshwire.write_ssh_string(utf8_bytes(pair.curve)),
    @sshwire.write_ssh_string(pair.point),
  ])
}

///|
/// The `authorized_keys` line for this key -- what `ssh-keygen -y`
/// prints.
///
/// **The line has no trailing newline.**  It is the printed form, not
/// the file form, exactly like `public_line_text`: the newline comes
/// from the print, and a line that already carried one would end with
/// two.  Measured against the real tool, which is what caught it --
/// `encode_public_line_of` returns the FILE form and does end with a
/// newline, so this trims the one it added rather than building the
/// line a second time.
///
/// The measured target for the gate: `ssh-keygen -y -f <file>` prints
/// exactly this line, comment included, for a key that has one.
pub fn ecdsa_public_line_text(pair : EcdsaKeyPair, comment : String) -> String {
  let text = encode_public_line_of(
    ecdsa_key_type(pair.curve),
    ecdsa_public_blob(pair),
    comment,
  )
  text[0:text.length() - 1].to_owned()
}

///|
/// The private half of the block, starting just past the key type.
///
/// `ktype` and `at` come from `parse_block`, which has already read the
/// two check words and the type string.  Everything from here is ECDSA's
/// own: curve id, point, scalar, comment, padding.
fn parse_ecdsa_fields(
  block : FixedArray[Byte],
  at : Int32,
  ktype : String,
) -> Parsed {
  match read_string(block, at) {
    None => Parsed::Malformed("the ECDSA curve name is missing")
    Some((curve, a1)) =>
      if !ecdsa_is_curve(curve) {
        Parsed::Unsupported(
          "the ECDSA curve is " + curve + ", which is not one of the three",
        )
      } else if ecdsa_key_type(curve) != ktype {
        // A file whose type says p256 and whose curve field says p384 is
        // not a file this reader should guess about.
        Parsed::Malformed(
          "the key type says " + ktype + " but the curve field says " + curve,
        )
      } else {
        match read_bytes(block, a1) {
          None => Parsed::Malformed("the ECDSA public point is missing")
          Some((point, a2)) =>
            if point.length() != ecdsa_point_width(curve) {
              Parsed::Malformed(
                "the ECDSA point is " +
                point.length().to_string() +
                " bytes, not " +
                ecdsa_point_width(curve).to_string(),
              )
            } else if point[0] != b'\x04' {
              // 0x04 is "uncompressed".  A compressed point (0x02/0x03)
              // is a legitimate SEC1 encoding that OpenSSH does not write
              // here, so refusing it is a statement about this file
              // format and not about ECDSA.
              Parsed::Malformed("the ECDSA point is not an uncompressed point")
            } else {
              match read_bytes(block, a2) {
                None => Parsed::Malformed("the ECDSA private scalar is missing")
                Some((raw_d, a3)) => {
                  let d = strip_mpint_zero(raw_d)
                  if d.length() > ecdsa_scalar_max(curve) ||
                    d.length() == 0 ||
                    d.length() < ecdsa_scalar_max(curve) - 1 {
                    Parsed::Malformed(
                      "the ECDSA scalar is " +
                      d.length().to_string() +
                      " bytes, which is not a " +
                      curve +
                      " scalar",
                    )
                  } else {
                    match read_string(block, a3) {
                      None => Parsed::Malformed("the ECDSA comment is missing")
                      Some((comment, a4)) =>
                        match check_padding(block, a4) {
                          Some(why) => Parsed::Malformed(why)
                          None =>
                            Parsed::Ecdsa({ curve, point, scalar: d, }, comment)
                        }
                    }
                  }
                }
              }
            }
        }
      }
  }
}

///|
/// An `mpint`'s leading zero, removed.
///
/// One zero at most: a second would mean the value is not minimally
/// encoded, which OpenSSH never writes and which this reader therefore
/// does not accept as a different number.
fn strip_mpint_zero(raw : FixedArray[Byte]) -> FixedArray[Byte] {
  let n = raw.length()
  if n >= 2 && raw[0] == b'\x00' {
    let out = FixedArray::make(n - 1, b'\x00')
    for i = 0; i < n - 1; i = i + 1 {
      out[i] = raw[i + 1]
    }
    out
  } else {
    raw
  }
}

///|
/// The padding after the comment: `01 02 03 ...`, up to the block size.
///
/// `None` means the padding is what it should be.  The block size here is
/// 8, which is both the cipher-"none" block size and what every caller of
/// this reader deals in; an encrypted block is decrypted before it gets
/// here, so the same arithmetic applies.
///
/// **The failure sentence matters.**  With no passphrase a wrong padding
/// cannot mean a wrong passphrase, so it must not say so -- it is the one
/// place where a reader that copies OpenSSH's message would send a user
/// looking for a password that does not exist.
fn check_padding(block : FixedArray[Byte], at : Int32) -> String? {
  let used = at
  let n = block.length()
  if n < used {
    return Some("the private block ends before its padding")
  }
  let want = (8 - used % 8) % 8
  if n - used != want {
    return Some(
      "the private block has " +
      (n - used).to_string() +
      " bytes of padding, not " +
      want.to_string(),
    )
  }
  let mut i = 0
  while i < want {
    if block[used + i].to_int() != i + 1 {
      return Some("the private block padding is not 1, 2, 3, ...")
    }
    i = i + 1
  }
  None
}

///|
/// Whether the file's own public blob agrees with its private half.
///
/// The same idea as `check_envelope` for ed25519: the file carries the
/// public key twice, once as a blob and once (implicitly) as a point in
/// the private block, and a file where the two disagree is a file whose
/// copy is damaged.  Comparing them costs one `ecdsa_public_blob` call and
/// turns "the copy is subtly wrong" into a refusal.
pub fn check_ecdsa_envelope(
  pubblob : FixedArray[Byte],
  pair : EcdsaKeyPair,
) -> String? {
  let want = ecdsa_public_blob(pair)
  if pubblob.length() != want.length() {
    return Some(
      "the public blob is " +
      pubblob.length().to_string() +
      " bytes and the private half implies " +
      want.length().to_string(),
    )
  }
  let mut i = 0
  while i < want.length() {
    if pubblob[i] != want[i] {
      return Some("the public blob does not match the private half")
    }
    i = i + 1
  }
  None
}
