"""Generate the Loop #30 ECDSA KAT data, driver, and expected-output file.

Three things are produced, all from Python arbitrary-precision reference
arithmetic so nothing is hand-transcribed:

  1. src/ecdsa/kat_data.mbt        raw vector bytes (d, Q, r, s, k)
  2. cmd/ecdsa_test/main.mbt       the typed test driver
  3. scripts/ecdsa_kat_expected.txt  expected driver output, line for line

The driver also exercises the SSH wire encoding (RFC 5656 public key blob and
OpenSSH signature blob). The expected hex for those blobs is computed here
from an independent implementation of OpenSSH's sshbuf_put_bignum2 rule, so the
MoonBit encoder is checked against a second reading of the C code rather than
against itself.

Run:  python scripts/gen_ecdsa_driver.py
"""
import hashlib
import hmac as hmac_mod

# ---------------------------------------------------------------- helpers
def mb_bytes(name, raw, indent="  "):
    body = []
    for i in range(0, len(raw), 12):
        chunk = raw[i:i + 12]
        body.append(indent + "  " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
    return (f"{indent}let {name} : FixedArray[Byte] = FixedArray::from_array([\n"
            + "\n".join(body) + f"\n{indent}])")


P256 = dict(
    name="p256", bits=256, hash="sha256", size=32,
    ssh="ecdsa-sha2-nistp256", curve="nistp256",
    p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
)
P384 = dict(
    name="p384", bits=384, hash="sha384", size=48,
    ssh="ecdsa-sha2-nistp384", curve="nistp384",
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    b=0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    gx=0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    gy=0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
    n=0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
)
CURVES = [P256, P384]


def inv(a, m):
    return pow(a, -1, m)


def pt_add(P, Q, c):
    if P is None:
        return Q
    if Q is None:
        return P
    p = c["p"]
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 - 3) * inv(2 * y1, p) % p
    else:
        lam = (y2 - y1) * inv(x2 - x1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def pt_mul(k, P, c):
    R = None
    while k:
        if k & 1:
            R = pt_add(R, P, c)
        P = pt_add(P, P, c)
        k >>= 1
    return R


def bits2int(b, qlen):
    x = int.from_bytes(b, "big")
    l = len(b) * 8
    if l > qlen:
        x >>= (l - qlen)
    return x


def bits2octets(b, c):
    qlen = c["bits"]
    z1 = bits2int(b, qlen)
    z2 = z1 - c["n"]
    if z2 < 0:
        z2 = z1
    return z2.to_bytes((qlen + 7) // 8, "big")


def rfc6979_k(c, priv, hashfunc, msg_hash):
    hlen = hashfunc().digest_size
    qlen = c["bits"]
    rolen = (qlen + 7) // 8
    h1 = msg_hash
    bh = bits2octets(h1, c)
    bx_oct = priv.to_bytes(rolen, "big")
    V = b"\x01" * hlen
    K = b"\x00" * hlen
    K = hmac_mod.new(K, V + b"\x00" + bx_oct + bh, hashfunc).digest()
    V = hmac_mod.new(K, V, hashfunc).digest()
    K = hmac_mod.new(K, V + b"\x01" + bx_oct + bh, hashfunc).digest()
    V = hmac_mod.new(K, V, hashfunc).digest()
    while True:
        T = b""
        while len(T) * 8 < qlen:
            V = hmac_mod.new(K, V, hashfunc).digest()
            T += V
        k = bits2int(T, qlen)
        if 1 <= k < c["n"]:
            return k
        K = hmac_mod.new(K, V + b"\x00", hashfunc).digest()
        V = hmac_mod.new(K, V, hashfunc).digest()


def sign(c, priv, msg, hashfunc):
    h = hashfunc(msg).digest()
    n = c["n"]
    k = rfc6979_k(c, priv, hashfunc, h)
    R = pt_mul(k, (c["gx"], c["gy"]), c)
    r = R[0] % n
    e = bits2int(h, c["bits"])
    s = (inv(k, n) * ((e % n) + r * priv)) % n
    return r, s, k


# ---------------------------------------------------------------- SSH wire
# Independent re-implementation of OpenSSH's sshbuf_put_bignum2
# (sshbuf-getput-crypto.c:130-150) and sshbuf_put_string / sshbuf_put_ec.
def ssh_string(b):
    return len(b).to_bytes(4, "big") + b


def put_bignum2(v):
    """RFC 4251 mpint body: minimal big-endian, 0x00 prepended if MSB set."""
    raw = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if len(raw) == 0:
        return b""
    if raw[0] & 0x80:
        return b"\x00" + raw
    return raw


def put_ec(x, y, size):
    return ssh_string(b"\x04" + x.to_bytes(size, "big") + y.to_bytes(size, "big"))


def pubkey_blob(c, Q):
    return (ssh_string(c["ssh"].encode()) + ssh_string(c["curve"].encode())
            + put_ec(Q[0], Q[1], c["size"]))


def sig_blob(c, r, s):
    # RFC 5656 3.1.1: the signature field is a `string` holding the blob, and
    # the blob itself is `mpint r` + `mpint s`. This used to emit the two mpints
    # directly after the algorithm name, with no outer length -- so the expected
    # file described a byte string that no RFC 4251 parser can read: a consumer
    # would read r's length as the blob length and then run off the end. The
    # MoonBit side always emitted the outer length and was right.
    inner = ssh_string(put_bignum2(r)) + ssh_string(put_bignum2(s))
    return ssh_string(c["ssh"].encode()) + ssh_string(inner)


# ---------------------------------------------------------------- data file
data = []
w = data.append
w('///| ECDSA / RFC 6979 KAT vector data (Loop #30 G4)')
w('///|')
w('///| AUTO-GENERATED by scripts/gen_ecdsa_driver.py -- do not hand-edit.')
w('///| Values come from Python arbitrary-precision reference arithmetic.')
w('')
w('///| RFC 6979 test message used by every vector below.')
w('let data_msg : FixedArray[Byte] = FixedArray::from_array([')
w('  0x73, 0x61, 0x6D, 0x70, 0x6C, 0x65,')
w('])')
w('')
w('///| Tampered message: one byte differs from `kat_msg`.')
w('let data_bad_msg : FixedArray[Byte] = FixedArray::from_array([')
w('  0x73, 0x61, 0x6D, 0x70, 0x6C, 0x66,')
w('])')
w('')

expected = []
MSG = b"sample"
for c in CURVES:
    size = c["size"]
    hashfn = getattr(hashlib, c["hash"])
    nm = c["name"]
    for idx in range(3):
        seed = f"{nm}-key-{idx}".encode()
        priv = bits2int(hashlib.sha512(seed).digest(), c["bits"]) % (c["n"] - 1) + 1
        Q = pt_mul(priv, (c["gx"], c["gy"]), c)
        r, s, k = sign(c, priv, MSG, hashfn)
        w('')
        w(f'// {nm} vector {idx}')
        w(mb_bytes(f'{nm}_d{idx}', priv.to_bytes(size, "big")))
        w(mb_bytes(f'{nm}_Qx{idx}', Q[0].to_bytes(size, "big")))
        w(mb_bytes(f'{nm}_Qy{idx}', Q[1].to_bytes(size, "big")))
        w(mb_bytes(f'{nm}_r{idx}', r.to_bytes(size, "big")))
        w(mb_bytes(f'{nm}_s{idx}', s.to_bytes(size, "big")))
        w(mb_bytes(f'{nm}_k{idx}', k.to_bytes(size, "big")))
        expected.append((f'{nm}_v{idx}_k', k))
        expected.append((f'{nm}_v{idx}_r', r))
        expected.append((f'{nm}_v{idx}_s', s))
        expected.append((f'{nm}_v{idx}_Qx', Q[0]))
        expected.append((f'{nm}_v{idx}_Qy', Q[1]))
    # negative vectors based on vector 0
    seed = f"{nm}-key-0".encode()
    priv0 = bits2int(hashlib.sha512(seed).digest(), c["bits"]) % (c["n"] - 1) + 1
    Q0 = pt_mul(priv0, (c["gx"], c["gy"]), c)
    r0, s0, k0 = sign(c, priv0, MSG, hashfn)
    w('')
    w(f'// {nm} negative vectors (derived from vector 0)')
    w(mb_bytes(f'{nm}_bad_r', ((r0 + 1) % c["n"]).to_bytes(size, "big")))
    w(mb_bytes(f'{nm}_zero_r', (0).to_bytes(size, "big")))
    w(mb_bytes(f'{nm}_zero_s', (0).to_bytes(size, "big")))
    w(mb_bytes(f'{nm}_big_s', c["n"].to_bytes(size, "big")))

    # ---- wire-format expectations (computed independently of MoonBit) ----
    expected.append((f'{nm}_mpint_r', put_bignum2(r0).hex().upper()))
    expected.append((f'{nm}_mpint_s', put_bignum2(s0).hex().upper()))
    expected.append((f'{nm}_mpint_r_len', str(len(put_bignum2(r0)))))
    expected.append((f'{nm}_wire_pk', pubkey_blob(c, Q0).hex().upper()))
    expected.append((f'{nm}_wire_sig', sig_blob(c, r0, s0).hex().upper()))
    # ---- point arithmetic invariants (independent of the KAT vectors) ----
    # dbl/add in Jacobian coordinates are easy to get subtly wrong in a way
    # that still returns a point, so pin the ladder against repeated affine
    # addition and against the group order.
    G = (c["gx"], c["gy"])
    G2 = pt_mul(2, G, c)
    G3 = pt_mul(3, G, c)
    # Curve coordinates are fixed width by definition. `format(v, "X")` is not:
    # it drops leading zeros, so a P-384 x-coordinate whose top nibble happens
    # to be 0 came out 95 hex characters wide instead of 96 and no longer
    # described a 48-byte value. The MoonBit side pads to the curve size, which
    # is the correct behaviour.
    width = c["size"] * 2
    expected.append((f'{nm}_2G_x', format(G2[0], "0%dx" % width).upper()))
    expected.append((f'{nm}_3G_x', format(G3[0], "0%dx" % width).upper()))
    expected.append((f'{nm}_nG_is_inf', pt_mul(c["n"], G, c) is None))
    # k^-1 * (e + r*d) with an unreduced second operand must still equal s.
    h = hashfn(MSG).digest()
    e = bits2int(h, c["bits"])
    expected.append((f'{nm}_kinv', inv(k0, c["n"])))
    expected.append((f'{nm}_unreduced_ge_n', (e % c["n"] + r0 * priv0) >= c["n"]))
    expected.append((f'{nm}_unreduced_mul', s0))

with open('src/ecdsa/kat_data.mbt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(data) + '\n')

# ---------------------------------------------------------------- driver
drv = []
v = drv.append
v('///| Loop #30 G4: ECDSA (P-256 / P-384) + RFC 6979 byte-exact KAT')
v('///|')
v('///| Checks, per curve:')
v('///|   * RFC 6979 deterministic nonce matches the reference')
v('///|   * d*G equals the recorded public key')
v('///|   * signing with d reproduces the recorded (r, s)')
v('///|   * the recorded signature verifies, and a fresh sign does too')
v('///|   * negative vectors are all rejected')
v('///|   * SSH wire blobs match the reference encoding byte for byte')
v('///|   * unreduced Montgomery operands are reduced before CIOS')
v('')
v('///| Render a rejection verdict. The argument is "the malformed input was')
v('///| correctly rejected", so a false here means the parser accepted garbage.')
v('fn rej(correctly_rejected : Bool) -> String {')
v('  if correctly_rejected { "CORRECT_FAIL" } else { "WRONG_PASS" }')
v('}')
v('')
v('///| Hex of an optional blob.')
v('fn opt_hex(o : FixedArray[Byte]?) -> String {')
v('  match o {')
v('    Some(b) => @ecdsa.bytes_to_hex(b)')
v('    None => "NONE"')
v('  }')
v('}')
v('')
v('///| Build a public key blob from raw parts, for the negative cases.')
v('fn build_pk(alg : String, cname : String, q : FixedArray[Byte]) -> FixedArray[Byte] {')
v('  @ecdsa.cat(')
v('    @ecdsa.cat(')
v('      @ecdsa.put_string(@ecdsa.str_bytes(alg)),')
v('      @ecdsa.put_string(@ecdsa.str_bytes(cname))),')
v('    @ecdsa.put_string(q))')
v('}')
v('')
v('///| Build a signature blob from raw r/s byte strings, for the negative cases.')
v('///')
v('/// \u5e03\u5c40\u5fc5\u987b\u548c `encode_sig_blob` \u4e00\u81f4 \u2014\u2014 `string alg` + `string( mpint r \u2016 mpint s )`\u3002')
v('/// \u5c11\u5305\u5916\u9762\u90a3\u5c42 string \u7684\u8bdd,\u6bcf\u4e00\u6761\u8d1f\u4f8b\u90fd\u4f1a\u5728**\u89e3\u6790\u5c42**\u5c31\u5931\u8d25,\u4e8e\u662f')
v('/// "is None" \u6052\u771f:\u6d4b\u8bd5\u770b\u8d77\u6765\u5168\u7eff,\u5b9e\u9645\u4ec0\u4e48\u90fd\u6ca1\u6d4b\u3002Loop #34 \u4fee')
v('/// `encode_sig_blob` \u65f6\u6b63\u662f\u88ab\u8fd9\u4e00\u70b9\u6321\u4e86\u4e00\u4e0b,\u6240\u4ee5\u8fd9\u91cc\u663e\u5f0f\u5199\u6b7b\u6b63\u786e\u5e03\u5c40,')
v('/// \u5e76\u5728\u4e0b\u9762\u5355\u72ec\u7528\u4e00\u6761\u6b63\u4f8b(`_wire_sig` \u5f80\u8fd4)\u5b88\u4f4f\u5b83\u3002')
v('fn build_sig(alg : String, rb : FixedArray[Byte], sb : FixedArray[Byte]) -> FixedArray[Byte] {')
v('  @ecdsa.cat(')
v('    @ecdsa.put_string(@ecdsa.str_bytes(alg)),')
v('    @ecdsa.put_string(')
v('      @ecdsa.cat(@ecdsa.put_string(rb), @ecdsa.put_string(sb)),')
v('    ),')
v('  )')
v('}')
v('')
v('fn run_curve(name : String, c : @ecdsa.Curve) -> Unit {')
v('  let alg = c.hash_alg()')
v('  let msg = @ecdsa.kat_msg()')
v('  let badmsg = @ecdsa.kat_bad_msg()')
v('  let fs = @ecdsa.Curve::field_bytes(c)')
v('  println("--- " + name + " (" + c.bits.to_string() + "-bit) ---")')
v('  // generator is on the curve')
v('  println(name + "_G_on_curve: " + @ecdsa.Curve::on_curve(c, c.generator()).to_string())')
v('  for i in 0..=2 {')
v('    let di = @ecdsa.load_kat_priv(name, i)')
v('    let qx = @ecdsa.load_kat_Qx(name, i)')
v('    let qy = @ecdsa.load_kat_Qy(name, i)')
v('    let kref = @ecdsa.load_kat_k(name, i)')
v('    let rref = @ecdsa.load_kat_r(name, i)')
v('    let sref = @ecdsa.load_kat_s(name, i)')
v('    let q = @ecdsa.Point::new(qx, qy)')
v('    // 1. public key = d*G')
v('    let derived = @ecdsa.Curve::mul(c, di, c.generator())')
v('    let q_match = @bigint.BigNat::cmp(derived.x, qx) == 0 &&')
v('                 @bigint.BigNat::cmp(derived.y, qy) == 0')
v('    println(name + "_v" + i.to_string() + "_pubkey: " + q_match.to_string())')
v('    // 2. RFC 6979 nonce')
v('    let h1 = c.hash_message(msg)')
v('    let k = @ecdsa.rfc6979_nonce(alg, c.n, c.bits, di, h1)')
v('    let k_match = @bigint.BigNat::cmp(k, kref) == 0')
v('    println(name + "_v" + i.to_string() + "_rfc6979_k: " + k_match.to_string())')
v('    // 3. sign and compare (r, s)')
v('    match @ecdsa.ecdsa_sign(c, di, msg) {')
v('      Some(sig) => {')
v('        let rs = @bigint.BigNat::cmp(sig.r, rref) == 0')
v('        let ss = @bigint.BigNat::cmp(sig.s, sref) == 0')
v('        println(name + "_v" + i.to_string() + "_sign_match: " + (rs && ss).to_string())')
v('        // 4. verify our own fresh signature')
v('        println(name + "_v" + i.to_string() + "_verify: " +')
v('          @ecdsa.ecdsa_verify(c, q, sig, msg).to_string())')
v('        // 5. verify the reference signature too')
v('        let ref_sig = @ecdsa.Signature::new(rref, sref)')
v('        println(name + "_v" + i.to_string() + "_verify_ref: " +')
v('          @ecdsa.ecdsa_verify(c, q, ref_sig, msg).to_string())')
v('        // 6. wrong message must be rejected')
v('        println(name + "_v" + i.to_string() + "_wrong_msg: " +')
v('          (if @ecdsa.ecdsa_verify(c, q, sig, badmsg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())')
v('      }')
v('      None => println(name + "_v" + i.to_string() + "_sign_match: SIGN_FAILED")')
v('    }')
v('  }')
v('  // negative vectors, all derived from vector 0')
v('  let d0 = @ecdsa.load_kat_priv(name, 0)')
v('  let qx0 = @ecdsa.load_kat_Qx(name, 0)')
v('  let qy0 = @ecdsa.load_kat_Qy(name, 0)')
v('  let q0 = @ecdsa.Point::new(qx0, qy0)')
v('  let r0 = @ecdsa.load_kat_r(name, 0)')
v('  let s0 = @ecdsa.load_kat_s(name, 0)')
v('  let sref0 = s0')
v('  let bad_r = @ecdsa.Signature::new(@ecdsa.load_kat_bad_r(name), sref0)')
v('  let zero_r = @ecdsa.Signature::new(@ecdsa.load_kat_zero_r(name), sref0)')
v('  let zero_s = @ecdsa.Signature::new(r0, @ecdsa.load_kat_zero_s(name))')
v('  let big_s = @ecdsa.Signature::new(r0, @ecdsa.load_kat_big_s(name))')
v('  println(name + "_neg_bad_r: " +')
v('    (if @ecdsa.ecdsa_verify(c, q0, bad_r, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())')
v('  println(name + "_neg_zero_r: " +')
v('    (if @ecdsa.ecdsa_verify(c, q0, zero_r, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())')
v('  println(name + "_neg_zero_s: " +')
v('    (if @ecdsa.ecdsa_verify(c, q0, zero_s, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())')
v('  println(name + "_neg_big_s: " +')
v('    (if @ecdsa.ecdsa_verify(c, q0, big_s, msg) { "WRONG_PASS" } else { "CORRECT_FAIL" }).to_string())')
v('')
v('  // ================= point arithmetic invariants =================')
v('  // dbl-2001-b / add-2007-bl are easy to get subtly wrong in a way that')
v('  // still returns a point, so pin the ladder against repeated addition,')
v('  // against the group order, and against reference coordinates.')
v('  let g = c.generator()')
v('  let two = @bigint.BigNat::from_uint64(2UL)')
v('  let g2 = @ecdsa.Curve::mul(c, two, g)')
v('  println(name + "_2G_x: " + @bigint.BigNat::to_hex(g2.x))')
v('  println(name + "_2G_on_curve: " + @ecdsa.Curve::on_curve(c, g2).to_string())')
v('  let g3 = @ecdsa.Curve::mul(c, @bigint.BigNat::from_uint64(3UL), g)')
v('  println(name + "_3G_x: " + @bigint.BigNat::to_hex(g3.x))')
v('  println(name + "_3G_on_curve: " + @ecdsa.Curve::on_curve(c, g3).to_string())')
v('  println(name + "_nG_is_inf: " +')
v('    @ecdsa.Curve::mul(c, c.n, g).inf.to_string())')
v('  let mut acc = @ecdsa.Point::infinity()')
v('  let mut ladder_ok = true')
v('  let mut i = 1')
v('  while i <= 5 {')
v('    acc = @ecdsa.Curve::point_add(c, acc, g)')
v('    let via_mul = @ecdsa.Curve::mul(c, @bigint.BigNat::from_uint64(i.to_uint64()), g)')
v('    if @bigint.BigNat::cmp(acc.x, via_mul.x) != 0 ||')
v('       @bigint.BigNat::cmp(acc.y, via_mul.y) != 0 {')
v('      ladder_ok = false')
v('    }')
v('    i = i + 1')
v('  }')
v('  println(name + "_ladder_matches_add: " + ladder_ok.to_string())')
v('')
v('  // ================= unreduced-operand regression =================')
v('  // Montgomery CIOS requires both operands < n, but the ECDSA signing')
v('  // equation is k^-1 * (e + r*d), and e + r*d routinely exceeds n.')
v('  // r*d is deliberately left unreduced here to reproduce exactly the input')
v('  // that used to make mod_mul_auto return a wrong s.')
v('  let kinv = @bigint.BigNat::mod_pow_auto(')
v('    @ecdsa.load_kat_k(name, 0),')
v('    @bigint.BigNat::sub(c.n, @bigint.BigNat::from_uint64(2UL)),')
v('    c.n)')
v('  println(name + "_kinv: " + @bigint.BigNat::to_hex(kinv))')
v('  let e0 = @ecdsa.bits2int(c.hash_message(msg), c.bits)')
v('  let rd_full = @bigint.BigNat::mul(r0, d0)')
v('  let tsum = @bigint.BigNat::add(@bigint.BigNat::mod(e0, c.n), rd_full)')
v('  println(name + "_unreduced_ge_n: " +')
v('    (@bigint.BigNat::cmp(tsum, c.n) >= 0).to_string())')
v('  let unreduced = @bigint.BigNat::mod_mul_auto(kinv, tsum, c.n)')
v('  let schoolbook = @bigint.BigNat::mod_mul(kinv, tsum, c.n)')
v('  println(name + "_unreduced_mul: " + @bigint.BigNat::to_hex(unreduced))')
v('  println(name + "_unreduced_match: " +')
v('    (if @bigint.BigNat::cmp(unreduced, schoolbook) == 0 { "MATCH" } else { "MISMATCH" }).to_string())')
v('')
v('  // ================= SSH wire encoding =================')
v('  // mpint bodies, compared against an independent Python implementation')
v('  println(name + "_mpint_r: " + @ecdsa.bytes_to_hex(@ecdsa.mpint_body(r0)))')
v('  println(name + "_mpint_s: " + @ecdsa.bytes_to_hex(@ecdsa.mpint_body(s0)))')
v('  println(name + "_mpint_r_len: " + @ecdsa.mpint_body(r0).length().to_string())')
v('  let pk_blob = @ecdsa.encode_pubkey_blob(c, q0)')
v('  println(name + "_wire_pk: " + opt_hex(pk_blob))')
v('  let pk_rt = match pk_blob {')
v('    None => false')
v('    Some(b) =>')
v('      match @ecdsa.decode_pubkey_blob(b) {')
v('        None => false')
v('        Some((c2, q2)) =>')
v('          c2.bits == c.bits &&')
v('          @bigint.BigNat::cmp(q2.x, qx0) == 0 &&')
v('          @bigint.BigNat::cmp(q2.y, qy0) == 0')
v('      }')
v('  }')
v('  println(name + "_wire_pk_roundtrip: " + pk_rt.to_string())')
v('  let sb = @ecdsa.encode_sig_blob(c, @ecdsa.Signature::new(r0, s0))')
v('  println(name + "_wire_sig: " + @ecdsa.bytes_to_hex(sb))')
v('  let sig_rt = match @ecdsa.decode_sig_blob(c, sb) {')
v('    None => false')
v('    Some(sg) => @ecdsa.ecdsa_verify(c, q0, sg, msg)')
v('  }')
v('  println(name + "_wire_sig_verify: " + sig_rt.to_string())')
v('')
v('  // RFC 4251 mpint: a full-width r whose top bit is set must arrive with a')
v('  // 0x00 sign pad (33 bytes). The same 32 bytes without the pad is a')
v('  // negative mpint and has to be rejected, even though the value is a')
v('  // perfectly good positive P-256 r.')
v('  let rf = @ecdsa.bignat_to_fixed_be(r0, fs)')
v('  let sf = @ecdsa.bignat_to_fixed_be(s0, fs)')
v('  let fixed_rej = match (rf, sf) {')
v('    (Some(rb), Some(sbb)) =>')
v('      @ecdsa.decode_sig_blob(')
v('        c, build_sig(c.ssh_name(), rb, sbb)) is None')
v('    _ => false')
v('  }')
v('  println(name + "_wire_fixed_rejected: " + rej(fixed_rej))')
v('')
v('  // ...while a short value with the high bit clear is a legal mpint and')
v('  // must survive the parse layer (it then fails verification, which is a')
v('  // different check).')
v('  let shortr : FixedArray[Byte] = FixedArray::from_array([0x01, 0x02, 0x03, 0x04])')
v('  let smp = @ecdsa.mpint_body(s0)')
v('  let short_ok =')
v('    match @ecdsa.decode_sig_blob(')
v('      c, build_sig(c.ssh_name(), shortr, smp)) {')
v('      None => false')
v('      Some(sg) =>')
v('        @bigint.BigNat::cmp(sg.r, @bigint.BigNat::from_bytes_be(shortr)) == 0')
v('    }')
v('  println(name + "_wire_short_mpint: " + short_ok.to_string())')
v('')
v('  // ---- wire negative cases ----')
v('  let qenc = @ecdsa.encode_point(c, q0)')
v('  let neg_trailing = match pk_blob {')
v('    None => false')
v('    Some(b) => @ecdsa.decode_pubkey_blob(')
v('      @ecdsa.cat(b, FixedArray::from_array([b\'\\x00\']))) is None')
v('  }')
v('  println(name + "_wire_neg_trailing: " + rej(neg_trailing))')
v('  let neg_badalg = match qenc {')
v('    None => false')
v('    Some(qb) => @ecdsa.decode_pubkey_blob(')
v('      build_pk("ecdsa-sha2-nistp999", c.curve_name(), qb)) is None')
v('  }')
v('  println(name + "_wire_neg_badalg: " + rej(neg_badalg))')
v('  let neg_badcurve = match qenc {')
v('    None => false')
v('    Some(qb) => @ecdsa.decode_pubkey_blob(')
v('      build_pk(c.ssh_name(), "nistp999", qb)) is None')
v('  }')
v('  println(name + "_wire_neg_badcurve: " + rej(neg_badcurve))')
v('  // Q with y bumped by one: right length, wrong curve equation')
v('  let neg_badpoint = match (qenc, @ecdsa.bignat_to_fixed_be(')
v('    @bigint.BigNat::mod(@bigint.BigNat::add(qy0, @bigint.BigNat::from_uint64(1UL)), c.p), fs)) {')
v('    (Some(qb), Some(yb)) => {')
v('      let bad : FixedArray[Byte] = FixedArray::make(1 + 2 * fs, b\'\\x00\')')
v('      bad[0] = b\'\\x04\'')
v('      for i = 0; i < fs; i = i + 1 {')
v('        bad[1 + i] = qb[1 + i]')
v('        bad[1 + fs + i] = yb[i]')
v('      }')
v('      @ecdsa.decode_pubkey_blob(')
v('        build_pk(c.ssh_name(), c.curve_name(), bad)) is None')
v('    }')
v('    _ => false')
v('  }')
v('  println(name + "_wire_neg_badpoint: " + rej(neg_badpoint))')
v('  // compressed point marker 0x02 is not accepted')
v('  let neg_compressed = match qenc {')
v('    None => false')
v('    Some(qb) => {')
v('      let comp : FixedArray[Byte] = FixedArray::make(1 + 2 * fs, b\'\\x00\')')
v('      comp[0] = b\'\\x02\'')
v('      for i = 0; i < 2 * fs; i = i + 1 { comp[1 + i] = qb[1 + i] }')
v('      @ecdsa.decode_pubkey_blob(')
v('        build_pk(c.ssh_name(), c.curve_name(), comp)) is None')
v('    }')
v('  }')
v('  println(name + "_wire_neg_compressed: " + rej(neg_compressed))')
v('  // r one byte too long with a non-zero lead byte is a negative mpint')
v('  let rneg : FixedArray[Byte] = FixedArray::make(fs + 1, b\'\\x01\')')
v('  let neg_negmpint = match sf {')
v('    None => false')
v('    Some(sbb) => @ecdsa.decode_sig_blob(')
v('      c, build_sig(c.ssh_name(), rneg, sbb)) is None')
v('  }')
v('  println(name + "_wire_neg_negmpint: " + rej(neg_negmpint))')
v('  // trailing byte after a signature blob')
v('  let neg_sigtrail = @ecdsa.decode_sig_blob(')
v('    c, @ecdsa.cat(sb, FixedArray::from_array([b\'\\x00\']))) is None')
v('  println(name + "_wire_neg_sigtrail: " + rej(neg_sigtrail))')
v('  // wrong algorithm name in the signature blob')
v('  let neg_wrongalg = match (rf, sf) {')
v('    (Some(rb), Some(sbb)) => @ecdsa.decode_sig_blob(')
v('      c, build_sig("ssh-rsa", rb, sbb)) is None')
v('    _ => false')
v('  }')
v('  println(name + "_wire_neg_wrongalg: " + rej(neg_wrongalg))')
v('  // an all-zero r decodes fine at this layer but must fail verification')
v('  let zerobytes : FixedArray[Byte] = FixedArray::make(fs, b\'\\x00\')')
v('  let neg_zeror = match sf {')
v('    None => false')
v('    Some(sbb) =>')
v('      match @ecdsa.decode_sig_blob(')
v('        c, build_sig(c.ssh_name(), zerobytes, sbb)) {')
v('        None => true')
v('        Some(sg) => !@ecdsa.ecdsa_verify(c, q0, sg, msg)')
v('      }')
v('  }')
v('  println(name + "_wire_neg_zeror: " + rej(neg_zeror))')
v('}')
v('')
v('fn main {')
v('  run_curve("p256", @ecdsa.Curve::p256())')
v('  run_curve("p384", @ecdsa.Curve::p384())')
v('}')

with open('cmd/ecdsa_test/main.mbt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(drv) + '\n')


def render(val):
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, int):
        return format(val, "X")
    return str(val)


# The expected file must mirror the driver's output line for line, in order.
# Hex values are predicted from Python; the booleans and verdict strings are
# the contract the MoonBit side has to satisfy.
val = {k: render(x) for k, x in expected}
lines = []
for c in CURVES:
    nm = c["name"]
    lines.append((None, f'--- {nm} ({c["bits"]}-bit) ---'))
    lines.append((None, f'{nm}_G_on_curve: true'))
    for idx in range(3):
        lines.append((None, f'{nm}_v{idx}_pubkey: true'))
        lines.append((None, f'{nm}_v{idx}_rfc6979_k: true'))
        lines.append((None, f'{nm}_v{idx}_sign_match: true'))
        lines.append((None, f'{nm}_v{idx}_verify: true'))
        lines.append((None, f'{nm}_v{idx}_verify_ref: true'))
        lines.append((None, f'{nm}_v{idx}_wrong_msg: CORRECT_FAIL'))
    for suffix in ("bad_r", "zero_r", "zero_s", "big_s"):
        lines.append((None, f'{nm}_neg_{suffix}: CORRECT_FAIL'))
    lines.append((f'{nm}_2G_x', None))
    lines.append((None, f'{nm}_2G_on_curve: true'))
    lines.append((f'{nm}_3G_x', None))
    lines.append((None, f'{nm}_3G_on_curve: true'))
    lines.append((f'{nm}_nG_is_inf', None))
    lines.append((None, f'{nm}_ladder_matches_add: true'))
    lines.append((f'{nm}_kinv', None))
    lines.append((f'{nm}_unreduced_ge_n', None))
    lines.append((f'{nm}_unreduced_mul', None))
    lines.append((None, f'{nm}_unreduced_match: MATCH'))
    lines.append((f'{nm}_mpint_r', None))
    lines.append((f'{nm}_mpint_s', None))
    lines.append((f'{nm}_mpint_r_len', None))
    lines.append((f'{nm}_wire_pk', None))
    lines.append((None, f'{nm}_wire_pk_roundtrip: true'))
    lines.append((f'{nm}_wire_sig', None))
    lines.append((None, f'{nm}_wire_sig_verify: true'))
    lines.append((None, f'{nm}_wire_fixed_rejected: CORRECT_FAIL'))
    lines.append((None, f'{nm}_wire_short_mpint: true'))
    for suffix in ("trailing", "badalg", "badcurve", "badpoint",
                   "compressed", "negmpint", "sigtrail", "wrongalg", "zeror"):
        lines.append((None, f'{nm}_wire_neg_{suffix}: CORRECT_FAIL'))

with open('scripts/ecdsa_kat_expected.txt', 'w', encoding='utf-8') as f:
    for key, literal in lines:
        if literal is not None:
            f.write(literal + '\n')
        else:
            f.write(f'{key}: {val[key]}\n')

print("wrote src/ecdsa/kat_data.mbt, cmd/ecdsa_test/main.mbt, scripts/ecdsa_kat_expected.txt")
