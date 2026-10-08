///| Loop #30 G4: ECDSA (P-256 / P-384) + RFC 6979 byte-exact KAT
///|
///| Checks, per curve:
///|   * RFC 6979 deterministic nonce matches the reference
///|   * d*G equals the recorded public key
///|   * signing with d reproduces the recorded (r, s)
///|   * the recorded signature verifies, and a fresh sign does too
///|   * negative vectors are all rejected
///|   * SSH wire blobs match the reference encoding byte for byte
///|   * unreduced Montgomery operands are reduced before CIOS

///| Render a rejection verdict. The argument is "the malformed input was
///| correctly rejected", so a false here means the parser accepted garbage.
fn rej(correctly_rejected : Bool) -> String {
  if correctly_rejected { "CORRECT_FAIL" } else { "WRONG_PASS" }
}

///| Hex of an optional blob.
fn opt_hex(o : FixedArray[Byte]?) -> String {
  match o {
    Some(b) => @ecdsa.bytes_to_hex(b)
    None => "NONE"
  }
}

///| Build a public key blob from raw parts, for the negative cases.
fn build_pk(alg : String, cname : String, q : FixedArray[Byte]) -> FixedArray[Byte] {
  @ecdsa.cat(
    @ecdsa.cat(
      @ecdsa.put_string(@ecdsa.str_bytes(alg)),
      @ecdsa.put_string(@ecdsa.str_bytes(cname))),
    @ecdsa.put_string(q))
}

///| Build a signature blob from raw r/s byte strings, for the negative cases.
///
/// 布局必须和 `encode_sig_blob` 一致 —— `string alg` + `string( mpint r ‖ mpint s )`。
/// 少包外面那层 string 的话,每一条负例都会在**解析层**就失败,于是
/// "is None" 恒真:测试看起来全绿,实际什么都没测。Loop #34 修
/// `encode_sig_blob` 时正是被这一点挡了一下,所以这里显式写死正确布局,
/// 并在下面单独用一条正例(`_wire_sig` 往返)守住它。
fn build_sig(alg : String, rb : FixedArray[Byte], sb : FixedArray[Byte]) -> FixedArray[Byte] {
  @ecdsa.cat(
    @ecdsa.put_string(@ecdsa.str_bytes(alg)),
    @ecdsa.put_string(
      @ecdsa.cat(@ecdsa.put_string(rb), @ecdsa.put_string(sb)),
    ),
  )
}

fn run_curve(name : String, c : @ecdsa.Curve) -> Unit {
  let alg = c.hash_alg()
  let msg = @ecdsa.kat_msg()
  let badmsg = @ecdsa.kat_bad_msg()
  let fs = @ecdsa.Curve::field_bytes(c)
  println("--- " + name + " (" + c.bits.to_string() + "-bit) ---")
  // generator is on the curve
  println(name + "_G_on_curve: " + @ecdsa.Curve::on_curve(c, c.generator()).to_string())
  for i in 0..=2 {
    let di = @ecdsa.load_kat_priv(name, i)
    let qx = @ecdsa.load_kat_Qx(name, i)
    let qy = @ecdsa.load_kat_Qy(name, i)
    let kref = @ecdsa.load_kat_k(name, i)
    let rref = @ecdsa.load_kat_r(name, i)
    let sref = @ecdsa.load_kat_s(name, i)
    let q = @ecdsa.Point::new(qx, qy)
    // 1. public key = d*G
    let derived = @ecdsa.Curve::mul(c, di, c.generator())
    let q_match = @bigint.BigNat::cmp(derived.x, qx) == 0 &&
                 @bigint.BigNat::cmp(derived.y, qy) == 0
    println(name + "_v" + i.to_string() + "_pubkey: " + q_match.to_string())
    // 2. RFC 6979 nonce
    let h1 = c.hash_message(msg)
    let k = @ecdsa.rfc6979_nonce(alg, c.n, c.bits, di, h1)
    let k_match = @bigint.BigNat::cmp(k, kref) == 0
    println(name + "_v" + i.to_string() + "_rfc6979_k: " + k_match.to_string())
    // 3. sign and compare (r, s)
    match @ecdsa.ecdsa_sign(c, di, msg) {
      Some(sig) => {
        let rs = @bigint.BigNat::cmp(sig.r, rref) == 0
        let ss = @bigint.BigNat::cmp(sig.s, sref) == 0
        println(name + "_v" + i.to_string() + "_sign_match: " + (rs && ss).to_string())
        // 4. verify our own fresh signature
        println(name + "_v" + i.to_string() + "_verify: " +
          @ecdsa.ecdsa_verify(c, q, sig, msg).to_string())
        // 5. verify the reference signature too
        let ref_sig = @ecdsa.Signature::new(rref, sref)
        println(name + "_v" + i.to_string() + "_verify_ref: " +
          @ecdsa.ecdsa_verify(c, q, ref_sig, msg).to_string())
        // 6. wrong message must be rejected
        println(name + "_v" + i.to_string() + "_wrong_msg: " +
          (if @ecdsa.ecdsa_verify(c, q, sig, badmsg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())
      }
      None => println(name + "_v" + i.to_string() + "_sign_match: SIGN_FAILED")
    }
  }
  // negative vectors, all derived from vector 0
  let d0 = @ecdsa.load_kat_priv(name, 0)
  let qx0 = @ecdsa.load_kat_Qx(name, 0)
  let qy0 = @ecdsa.load_kat_Qy(name, 0)
  let q0 = @ecdsa.Point::new(qx0, qy0)
  let r0 = @ecdsa.load_kat_r(name, 0)
  let s0 = @ecdsa.load_kat_s(name, 0)
  let sref0 = s0
  let bad_r = @ecdsa.Signature::new(@ecdsa.load_kat_bad_r(name), sref0)
  let zero_r = @ecdsa.Signature::new(@ecdsa.load_kat_zero_r(name), sref0)
  let zero_s = @ecdsa.Signature::new(r0, @ecdsa.load_kat_zero_s(name))
  let big_s = @ecdsa.Signature::new(r0, @ecdsa.load_kat_big_s(name))
  println(name + "_neg_bad_r: " +
    (if @ecdsa.ecdsa_verify(c, q0, bad_r, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())
  println(name + "_neg_zero_r: " +
    (if @ecdsa.ecdsa_verify(c, q0, zero_r, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())
  println(name + "_neg_zero_s: " +
    (if @ecdsa.ecdsa_verify(c, q0, zero_s, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())
  println(name + "_neg_big_s: " +
    (if @ecdsa.ecdsa_verify(c, q0, big_s, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())

  // ================= point arithmetic invariants =================
  // dbl-2001-b / add-2007-bl are easy to get subtly wrong in a way that
  // still returns a point, so pin the ladder against repeated addition,
  // against the group order, and against reference coordinates.
  let g = c.generator()
  let two = @bigint.BigNat::from_uint64(2UL)
  let g2 = @ecdsa.Curve::mul(c, two, g)
  println(name + "_2G_x: " + @bigint.BigNat::to_hex(g2.x))
  println(name + "_2G_on_curve: " + @ecdsa.Curve::on_curve(c, g2).to_string())
  let g3 = @ecdsa.Curve::mul(c, @bigint.BigNat::from_uint64(3UL), g)
  println(name + "_3G_x: " + @bigint.BigNat::to_hex(g3.x))
  println(name + "_3G_on_curve: " + @ecdsa.Curve::on_curve(c, g3).to_string())
  println(name + "_nG_is_inf: " +
    @ecdsa.Curve::mul(c, c.n, g).inf.to_string())
  let mut acc = @ecdsa.Point::infinity()
  let mut ladder_ok = true
  let mut i = 1
  while i <= 5 {
    acc = @ecdsa.Curve::point_add(c, acc, g)
    let via_mul = @ecdsa.Curve::mul(c, @bigint.BigNat::from_uint64(i.to_uint64()), g)
    if @bigint.BigNat::cmp(acc.x, via_mul.x) != 0 ||
       @bigint.BigNat::cmp(acc.y, via_mul.y) != 0 {
      ladder_ok = false
    }
    i = i + 1
  }
  println(name + "_ladder_matches_add: " + ladder_ok.to_string())

  // ================= unreduced-operand regression =================
  // Montgomery CIOS requires both operands < n, but the ECDSA signing
  // equation is k^-1 * (e + r*d), and e + r*d routinely exceeds n.
  // r*d is deliberately left unreduced here to reproduce exactly the input
  // that used to make mod_mul_auto return a wrong s.
  let kinv = @bigint.BigNat::mod_pow_auto(
    @ecdsa.load_kat_k(name, 0),
    @bigint.BigNat::sub(c.n, @bigint.BigNat::from_uint64(2UL)),
    c.n)
  println(name + "_kinv: " + @bigint.BigNat::to_hex(kinv))
  let e0 = @ecdsa.bits2int(c.hash_message(msg), c.bits)
  let rd_full = @bigint.BigNat::mul(r0, d0)
  let tsum = @bigint.BigNat::add(@bigint.BigNat::mod(e0, c.n), rd_full)
  println(name + "_unreduced_ge_n: " +
    (@bigint.BigNat::cmp(tsum, c.n) >= 0).to_string())
  let unreduced = @bigint.BigNat::mod_mul_auto(kinv, tsum, c.n)
  let schoolbook = @bigint.BigNat::mod_mul(kinv, tsum, c.n)
  println(name + "_unreduced_mul: " + @bigint.BigNat::to_hex(unreduced))
  println(name + "_unreduced_match: " +
    (if @bigint.BigNat::cmp(unreduced, schoolbook) == 0 { "MATCH" } else { "MISMATCH" }).to_string())

  // ================= SSH wire encoding =================
  // mpint bodies, compared against an independent Python implementation
  println(name + "_mpint_r: " + @ecdsa.bytes_to_hex(@ecdsa.mpint_body(r0)))
  println(name + "_mpint_s: " + @ecdsa.bytes_to_hex(@ecdsa.mpint_body(s0)))
  println(name + "_mpint_r_len: " + @ecdsa.mpint_body(r0).length().to_string())
  let pk_blob = @ecdsa.encode_pubkey_blob(c, q0)
  println(name + "_wire_pk: " + opt_hex(pk_blob))
  let pk_rt = match pk_blob {
    None => false
    Some(b) =>
      match @ecdsa.decode_pubkey_blob(b) {
        None => false
        Some((c2, q2)) =>
          c2.bits == c.bits &&
          @bigint.BigNat::cmp(q2.x, qx0) == 0 &&
          @bigint.BigNat::cmp(q2.y, qy0) == 0
      }
  }
  println(name + "_wire_pk_roundtrip: " + pk_rt.to_string())
  let sb = @ecdsa.encode_sig_blob(c, @ecdsa.Signature::new(r0, s0))
  println(name + "_wire_sig: " + @ecdsa.bytes_to_hex(sb))
  let sig_rt = match @ecdsa.decode_sig_blob(c, sb) {
    None => false
    Some(sg) => @ecdsa.ecdsa_verify(c, q0, sg, msg)
  }
  println(name + "_wire_sig_verify: " + sig_rt.to_string())

  // RFC 4251 mpint: a full-width r whose top bit is set must arrive with a
  // 0x00 sign pad (33 bytes). The same 32 bytes without the pad is a
  // negative mpint and has to be rejected, even though the value is a
  // perfectly good positive P-256 r.
  let rf = @ecdsa.bignat_to_fixed_be(r0, fs)
  let sf = @ecdsa.bignat_to_fixed_be(s0, fs)
  let fixed_rej = match (rf, sf) {
    (Some(rb), Some(sbb)) =>
      @ecdsa.decode_sig_blob(
        c, build_sig(c.ssh_name(), rb, sbb)) is None
    _ => false
  }
  println(name + "_wire_fixed_rejected: " + rej(fixed_rej))

  // ...while a short value with the high bit clear is a legal mpint and
  // must survive the parse layer (it then fails verification, which is a
  // different check).
  let shortr : FixedArray[Byte] = FixedArray::from_array([0x01, 0x02, 0x03, 0x04])
  let smp = @ecdsa.mpint_body(s0)
  let short_ok =
    match @ecdsa.decode_sig_blob(
      c, build_sig(c.ssh_name(), shortr, smp)) {
      None => false
      Some(sg) =>
        @bigint.BigNat::cmp(sg.r, @bigint.BigNat::from_bytes_be(shortr)) == 0
    }
  println(name + "_wire_short_mpint: " + short_ok.to_string())

  // ---- wire negative cases ----
  let qenc = @ecdsa.encode_point(c, q0)
  let neg_trailing = match pk_blob {
    None => false
    Some(b) => @ecdsa.decode_pubkey_blob(
      @ecdsa.cat(b, FixedArray::from_array([b'\x00']))) is None
  }
  println(name + "_wire_neg_trailing: " + rej(neg_trailing))
  let neg_badalg = match qenc {
    None => false
    Some(qb) => @ecdsa.decode_pubkey_blob(
      build_pk("ecdsa-sha2-nistp999", c.curve_name(), qb)) is None
  }
  println(name + "_wire_neg_badalg: " + rej(neg_badalg))
  let neg_badcurve = match qenc {
    None => false
    Some(qb) => @ecdsa.decode_pubkey_blob(
      build_pk(c.ssh_name(), "nistp999", qb)) is None
  }
  println(name + "_wire_neg_badcurve: " + rej(neg_badcurve))
  // Q with y bumped by one: right length, wrong curve equation
  let neg_badpoint = match (qenc, @ecdsa.bignat_to_fixed_be(
    @bigint.BigNat::mod(@bigint.BigNat::add(qy0, @bigint.BigNat::from_uint64(1UL)), c.p), fs)) {
    (Some(qb), Some(yb)) => {
      let bad : FixedArray[Byte] = FixedArray::make(1 + 2 * fs, b'\x00')
      bad[0] = b'\x04'
      for i = 0; i < fs; i = i + 1 {
        bad[1 + i] = qb[1 + i]
        bad[1 + fs + i] = yb[i]
      }
      @ecdsa.decode_pubkey_blob(
        build_pk(c.ssh_name(), c.curve_name(), bad)) is None
    }
    _ => false
  }
  println(name + "_wire_neg_badpoint: " + rej(neg_badpoint))
  // compressed point marker 0x02 is not accepted
  let neg_compressed = match qenc {
    None => false
    Some(qb) => {
      let comp : FixedArray[Byte] = FixedArray::make(1 + 2 * fs, b'\x00')
      comp[0] = b'\x02'
      for i = 0; i < 2 * fs; i = i + 1 { comp[1 + i] = qb[1 + i] }
      @ecdsa.decode_pubkey_blob(
        build_pk(c.ssh_name(), c.curve_name(), comp)) is None
    }
  }
  println(name + "_wire_neg_compressed: " + rej(neg_compressed))
  // r one byte too long with a non-zero lead byte is a negative mpint
  let rneg : FixedArray[Byte] = FixedArray::make(fs + 1, b'\x01')
  let neg_negmpint = match sf {
    None => false
    Some(sbb) => @ecdsa.decode_sig_blob(
      c, build_sig(c.ssh_name(), rneg, sbb)) is None
  }
  println(name + "_wire_neg_negmpint: " + rej(neg_negmpint))
  // trailing byte after a signature blob
  let neg_sigtrail = @ecdsa.decode_sig_blob(
    c, @ecdsa.cat(sb, FixedArray::from_array([b'\x00']))) is None
  println(name + "_wire_neg_sigtrail: " + rej(neg_sigtrail))
  // wrong algorithm name in the signature blob
  let neg_wrongalg = match (rf, sf) {
    (Some(rb), Some(sbb)) => @ecdsa.decode_sig_blob(
      c, build_sig("ssh-rsa", rb, sbb)) is None
    _ => false
  }
  println(name + "_wire_neg_wrongalg: " + rej(neg_wrongalg))
  // an all-zero r decodes fine at this layer but must fail verification
  let zerobytes : FixedArray[Byte] = FixedArray::make(fs, b'\x00')
  let neg_zeror = match sf {
    None => false
    Some(sbb) =>
      match @ecdsa.decode_sig_blob(
        c, build_sig(c.ssh_name(), zerobytes, sbb)) {
        None => true
        Some(sg) => !@ecdsa.ecdsa_verify(c, q0, sg, msg)
      }
  }
  println(name + "_wire_neg_zeror: " + rej(neg_zeror))
}

fn main {
  run_curve("p256", @ecdsa.Curve::p256())
  run_curve("p384", @ecdsa.Curve::p384())
}
