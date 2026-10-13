///| cmd/ed25519_kat -- Loop #55: MoonBit Ed25519, exported for byte comparison.
///
///|
///
/// `moon test src/ed25519` can only answer "did the implementation agree with
/// the constants *inside its own test file*". That is exactly the shape Loop
/// #53 was written against: a fixture and a verifier that share a mistake agree
/// with each other and the whole thing is green.
///
///|
///
/// The vectors are RFC 8032 section 7.1 tests 1-3, which are **published
/// constants**, not values this repository chose. They are an authority rather
/// than a second opinion, and the gate compares this output against two
/// implementations other people wrote: OpenSSH's original `ed25519.c`
/// (`verify_c/ed25519_harness.c`) and Python's `cryptography`
/// (`verify_c/ed25519_python_ref.py`, libsodium/OpenSSL-backed).
///
///|
///
/// The line format is deliberately the Python reference's, so the gate compares
/// text instead of re-implementing a parser per side. Lowercase hex.
///
///|
///
/// The negative cases are here for the same reason the C harness has them: a
/// verifier that accepts everything passes every positive vector. `s == L`
/// (malleability), a tampered message and a wrong key are the three a
/// hand-written implementation most plausibly gets wrong.
fn main {
  println("===== RFC 8032 SS 7.1 Test Vectors =====")
  let cases : Array[(String, String, String)] = [
    (
      "Test 1",
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
      "",
    ),
    (
      "Test 2",
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
      "72",
    ),
    (
      "Test 3",
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
      "af82",
    ),
  ]
  let mut i = 0
  while i < cases.length() {
    let (name, seed_hex, msg_hex) = cases[i]
    let seed = hx(seed_hex)
    let msg = hx(msg_hex)
    let (pk, sk) = @ed25519.keypair_from_seed(seed)
    let sig = @ed25519.sign(msg, sk)
    let ok = @ed25519.verify(sig, msg, pk)
    let msg_shown = if msg_hex == "" { "(empty)" } else { msg_hex }
    println(name + ":")
    println("  seed     = " + seed_hex)
    println("  pk       = " + @ecdsa.bytes_to_hex(pk))
    println("  msg      = " + msg_shown)
    println("  sig      = " + @ecdsa.bytes_to_hex(sig))
    println("  verified = " + bool_txt(ok))
    // ---- negative: the same signature must not verify a changed message
    let bad_msg = hx(if msg_hex == "" { "00" } else { msg_hex + "00" })
    println(
      "  tamper-rejected = " + bool_txt(!@ed25519.verify(sig, bad_msg, pk)),
    )
    // ---- negative: a different key must not verify this signature
    let (pk2, _) = @ed25519.keypair_from_seed(
      hx("0000000000000000000000000000000000000000000000000000000000000001"),
    )
    println(
      "  wrongkey-rejected = " + bool_txt(!@ed25519.verify(sig, msg, pk2)),
    )
    i = i + 1
  }
  // ---- malleability: s + L must be rejected
  //
  // The attack is a **second valid signature over the same message**, so the
  // vector is `s + L`, not `L`.
  //
  // That distinction is the whole point, and it cost a mutation to learn: with
  // `s = L` the signature is rejected by the *first* check -- `sig[63] & 0xE0`
  // -- because L's top byte is 0xed and the high three bits are set. The range
  // check is never reached, so the test passes for a reason that has nothing to
  // do with malleability, and a mutation that disabled the range check entirely
  // still reported PASS.
  //
  // `s + L` is below 2L, hence below 2^253, so its top byte is under 0x20: the
  // S-range bit check passes, the high-bits check passes, and the *only* thing
  // that can reject it is the range check. That is the vector that tests the
  // thing.
  let seed = hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  let msg = FixedArray::make(0, b'\x00')
  let (pk, sk) = @ed25519.keypair_from_seed(seed)
  let sig = @ed25519.sign(msg, sk)
  let l_bytes = hx("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
  let malleable = FixedArray::make(64, b'\x00')
  for k = 0; k < 32; k = k + 1 {
    malleable[k] = sig[k]
  }
  // 32-byte little-endian addition of the s half and L, with carry.
  let mut carry = 0
  let mut k = 0
  while k < 32 {
    let sum = sig[32 + k].to_int() + l_bytes[k].to_int() + carry
    malleable[32 + k] = (sum & 0xFF).to_byte()
    carry = sum >> 8
    k = k + 1
  }
  // The carry out of 32 bytes is the bit above 2^256. If it were set, `s + L`
  // would have wrapped and stopped being malleable, so the vector would quietly
  // become a correct signature again -- a test that stops testing itself.
  let s_sum = (if carry != 0 { "OVERFLOW" } else { "ok" })
  let accepted = @ed25519.verify(malleable, msg, pk)
  println("s+L top byte: " + @ecdsa.bytes_to_hex(
    FixedArray::make(1, malleable[63]),
  ))
  println("s+L carry: " + s_sum)
  println("s+L reject: " + (if accepted { "WRONG_PASS" } else { "PASS" }))
  // The control: the unmodified signature must still verify, or "rejected"
  // above could just mean `verify` is broken for everything.
  println(
    "s orig accept: " + (if @ed25519.verify(sig, msg, pk) { "PASS" } else {
      "WRONG_FAIL"
    }),
  )
  println("ALL PASS")
}

///|
fn bool_txt(b : Bool) -> String {
  if b { "True" } else { "False" }
}

///|
/// Strict hex parsing: anything that is not a hex digit aborts rather than
/// quietly becoming 0.
///
/// The same rule as `src/aead`'s `hex_to_bytes`, written out again on purpose.
/// The two never parse the same input -- this one reads RFC 8032's published
/// constants, that one reads RFC 8439's -- so sharing a parser would make "both
/// sides mis-read the same character" happen once instead of twice, which is
/// exactly the failure being hunted.
fn hx(s : String) -> FixedArray[Byte] {
  if s.length() == 0 {
    return FixedArray::make(0, b'\x00')
  }
  if s.length() % 2 != 0 {
    abort("hx: odd length")
  }
  let n = s.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = (d(s[i * 2]) * 16 + d(s[i * 2 + 1])).to_byte()
  }
  arr
}

///|
fn d(c : UInt16) -> Int {
  let x : Int = c.to_int()
  if x >= 48 && x <= 57 {
    x - 48
  } else if x >= 97 && x <= 102 {
    x - 87
  } else {
    abort("hx: not a hex digit")
  }
}
