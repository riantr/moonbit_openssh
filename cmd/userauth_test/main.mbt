///| Loop #34 byte-exact verification (cmd/userauth_test)
///
/// Checks the RFC 4252 section 7 publickey path end to end, offline:
///
///     private key d
///       -> public point Q = d*G        (against RFC 6979 A.2.5)
///       -> SSH pubkey blob            (against paramiko-independent Python)
///       -> signed blob                (RFC 4252 section 7 layout)
///       -> ECDSA signature            (RFC 6979 deterministic)
///       -> USERAUTH_REQUEST payload
///
/// Every expected value comes from `host/ecdsa_auth_oracle.py`, which itself
/// refuses to emit unless its point derivation reproduces the public point
/// RFC 6979 A.2.5 publishes, and signs with an RFC 6979 deterministic nonce.
/// So a matching signature here is not "some valid signature" -- it is the
/// only correct one, which is what makes this checkable at all.
///
/// The signed blob and the request payload are **rebuilt** from the session id
/// rather than compared against stored blobs, so the RFC 4252 section 7 field
/// order is what is under test.

///| hex 字符串 -> 字节(MoonBit 的 String 下标返回 UInt16,不是 Char)
fn hex_nibble(c : UInt16) -> Int {
  let n = c.to_int()
  if n >= 48 && n <= 57 {
    return n - 48
  }
  if n >= 97 && n <= 102 {
    return n - 87
  }
  abort("hex_to_bytes: bad digit")
}

fn hex_to_bytes(s : String) -> FixedArray[Byte] {
  let n = s.length() / 2
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut i = 0
  while i < n {
    let hi = hex_nibble(s[i * 2])
    let lo = hex_nibble(s[i * 2 + 1])
    out[i] = ((hi << 4) | lo).to_byte()
    i = i + 1
  }
  out
}

fn bytes_equal(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut i = 0
  while i < a.length() {
    if a[i].to_int() != b[i].to_int() {
      return false
    }
    i = i + 1
  }
  true
}

fn pf(ok : Bool) -> String {
  if ok {
    "PASS"
  } else {
    "FAIL"
  }
}

///| mpint 是否需要前导 0x00(RFC 4251 §5)
///
/// r / s 是约 256 位宽,一半的取值最高位是 1,必须补一个 0x00 才不会
/// 被读成负数。向量集刻意覆盖了这条路径——漏掉它的签名在宽松解析器下
/// **仍然验得过**,所以单条向量根本发现不了。
///| 这个 mpint 是否**已经**被补了前导 0x00
///
/// r / s 是 256 位整数,定长编码就是 32 字节;只有最高位为 1 时才需要多一个
/// 0x00,变成 33 字节。判断依据是长度,不是首字节——补过之后首字节恰恰是
/// 0x00,拿「首字节有没有置高位」去测永远得到 false(第一版就是这么错的,
/// 6 个用例全部报成「没有覆盖」,而 Python 侧明确报了 4 个)。
fn mpint_pad(v : FixedArray[Byte]) -> Bool {
  v.length() == 33
}

///| 签名 blob 里 r 或 s 是否有任意一个需要前导 0x00
///
/// blob 布局是 `string key_type || string( mpint r || mpint s )`
/// (RFC 5656 §3.1.2 + ssh-ecdsa.c:431-432),外面还有一层 string 包装。
/// 必须先剥掉这层再取 r / s——按三个平级字段去读会整体错位 4 字节,
/// 解析直接失败,覆盖度会被误报成 0,恰好在出问题的那条路径上失去报警。
fn mpint_pair_padded(sig_blob : FixedArray[Byte]) -> Bool {
  match @ecdsa.read_string(sig_blob, 0) {
    None => false
    Some((_, off1)) =>
      match @ecdsa.read_string(sig_blob, off1) {
        None => false
        Some((inner, off2)) => {
          if off2 != sig_blob.length() {
            return false
          }
          match @ecdsa.read_string(inner, 0) {
            None => false
            Some((r, ro)) =>
              match @ecdsa.read_string(inner, ro) {
                None => false
                Some((s, so)) => {
                  if so != inner.length() {
                    return false
                  }
                  mpint_pad(r) || mpint_pad(s)
                }
              }
          }
        }
      }
  }
}

fn main {
  let d = @bigint.BigNat::from_bytes_be(hex_to_bytes(KAT_D_HEX))
  let c = @ecdsa.Curve::p256()

  // ---- 1. 公钥点:Q = d*G,对照 RFC 6979 A.2.5 公布的 (Ux, Uy) ----
  let q = match c.public_key(d) {
    None => {
      println("userauth_pubkey_point: FAIL")
      return
    }
    Some(p) => p
  }
  let ux = @bigint.BigNat::to_bytes_be(q.x())
  let uy = @bigint.BigNat::to_bytes_be(q.y())
  // BigNat 的最短大端表示可能短于 32 字节(前导零被省掉),而 RFC 向量是
  // 定长 32 字节,所以比较时统一左补零。
  let ux32 = pad_left(ux, 32)
  let uy32 = pad_left(uy, 32)
  let point_ok = bytes_equal(ux32, hex_to_bytes(KAT_UX_HEX)) &&
    bytes_equal(uy32, hex_to_bytes(KAT_UY_HEX))
  println("userauth_pubkey_point: " + pf(point_ok))
  println("userauth_ux: " + to_hex(ux32))
  println("userauth_uy: " + to_hex(uy32))

  // ---- 2. 公钥 blob(复用 Loop #30 的 encode_pubkey_blob)----
  let q = match c.public_key(d) {
    None => {
      println("userauth_pubkey_blob: FAIL")
      return
    }
    Some(p) => p
  }
  let blob = match @ecdsa.encode_pubkey_blob(c, q) {
    None => {
      println("userauth_pubkey_blob: FAIL")
      return
    }
    Some(b) => b
  }
  // RFC 5656 §3.1:第三个字段是**一个** SEC1 八位组串 0x04||X||Y,不是两个
  // 坐标字段。这里断言它的形状,因为「写成两个 string」是这类 key 最常见
  // 的构造错误,而服务端只回一句 curve mismatch。
  let shape_ok = blob.length() == 4 + 19 + 4 + 8 + 4 + 65
  println("userauth_pubkey_blob: " + pf(shape_ok))
  println("userauth_pubkey_blob_len: " + blob.length().to_string())

  let mut all_ok = point_ok
  let mut pad_seen = 0
  for k in auth_cases() {
    let sid = hex_to_bytes(k.session_id_hex)
    let to_sign = @userauth.userauth_signed_blob(
      sid,
      KAT_USER,
      KAT_SERVICE,
      KAT_KEY_TYPE,
      blob,
    )
    let sig = match @ecdsa.ecdsa_sign(c, d, to_sign) {
      None => {
        all_ok = false
        println("userauth_case_" + k.name + ": FAIL")
        continue
      }
      Some(s) => s
    }
    let sig_blob = @ecdsa.encode_sig_blob(c, sig)
    let payload = @userauth.userauth_publickey_request(
      KAT_USER,
      KAT_SERVICE,
      KAT_KEY_TYPE,
      blob,
      sig_blob,
    )
    let sb_ok = bytes_equal(to_sign, hex_to_bytes(k.signed_blob_hex))
    let sig_ok = bytes_equal(sig_blob, hex_to_bytes(k.sig_blob_hex))
    let req_ok = bytes_equal(payload, hex_to_bytes(k.request_payload_hex))
    // sig_blob 的第一个字节是 key_type 的长度前缀(0x00),直接对它做
    // mpint_pad 永远是 false——必须先把 r / s 两个 mpint 取出来。
    if mpint_pair_padded(sig_blob) {
      pad_seen = pad_seen + 1
    }
    if !sb_ok || !sig_ok || !req_ok {
      all_ok = false
    }
    println("userauth_case_" + k.name + ": " + pf(sb_ok && sig_ok && req_ok))
    println("  signed " + to_hex(to_sign))
    println("  sig    " + to_hex(sig_blob))
    println("  req    " + to_hex(payload))
  }
  println("userauth_cases_all: " + pf(all_ok))

  // mpint 覆盖:如果一个都没命中,向量集退化成「只测了不需要补零的路径」。
  println("userauth_mpint_pad_cases: " + pad_seen.to_string())

  // ---- 3. 私钥越界必须被拒绝,而不是悄悄归约 ----
  let zero = @bigint.BigNat::from_uint64(0UL)
  let out_of_range_ok = c.public_key(zero) is None &&
    c.public_key(c.order()) is None
  println("userauth_reject_bad_key: " + pf(out_of_range_ok))

  // d = n-1 是合法私钥,必须被接受(确认上一步不是靠"全都拒绝"蒙混过关)
  let n_minus_1 = @bigint.BigNat::sub(
    c.order(),
    @bigint.BigNat::from_uint64(1UL),
  )
  println(
    "userauth_accept_n_minus_1: " +
    pf(c.public_key(n_minus_1) is Some(_)),
  )

  // ---- 4. RFC 6979 A.2.5 已公布向量 ----
  //
  // 这一段是 Loop #34 真正的发现点:Loop #30 的 ecdsa_test 也检查了 RFC 6979
  // 的 k / r / s,但那批常量是自己生成的(kat_data.mbt 里没有 RFC 6979 A.2.5
  // 公布的任何数值),等于拿实现自己校验实现——bits2int 取错位、bits2octets
  // 漏了 mod order、hlen 用错,这类系统性错误全部照样通过。
  //
  // 这里直接用 RFC 6979 A.2.5 自己公布的消息与结果,那才是第三方意见。
  let sample = hex_to_bytes("73616d706c65")
  let h1 = c.hash_message(sample)
  let knonce = @ecdsa.rfc6979_nonce(c.hash_alg(), c.order(), 256, d, h1)
  let sample_sig = match @ecdsa.ecdsa_sign(c, d, sample) {
    None => {
      println("rfc6979_a25: FAIL")
      return
    }
    Some(v) => v
  }
  println("rfc6979_k: " + to_hex(pad_left(@bigint.BigNat::to_bytes_be(knonce), 32)))
  println(
    "rfc6979_r: " + to_hex(pad_left(@bigint.BigNat::to_bytes_be(sample_sig.r()), 32)),
  )
  println(
    "rfc6979_s: " + to_hex(pad_left(@bigint.BigNat::to_bytes_be(sample_sig.s()), 32)),
  )
  // RFC 6979 A.2.5 published values for NIST P-256, SHA-256, msg = "sample"
  let a25_k = "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60"
  let a25_r = "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716"
  let a25_s = "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"
  let k_ok = to_hex(pad_left(@bigint.BigNat::to_bytes_be(knonce), 32)) == a25_k
  let r_ok = to_hex(pad_left(@bigint.BigNat::to_bytes_be(sample_sig.r()), 32)) == a25_r
  let s_ok = to_hex(pad_left(@bigint.BigNat::to_bytes_be(sample_sig.s()), 32)) == a25_s
  println("rfc6979_a25_k: " + pf(k_ok))
  println("rfc6979_a25_r: " + pf(r_ok))
  println("rfc6979_a25_s: " + pf(s_ok))
  println("rfc6979_a25: " + pf(k_ok && r_ok && s_ok))
}

///| 左补零到 n 字节
fn pad_left(b : FixedArray[Byte], n : Int) -> FixedArray[Byte] {
  if b.length() >= n {
    return b
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let off = n - b.length()
  for i = 0; i < b.length(); i = i + 1 {
    out[off + i] = b[i]
  }
  out
}

fn byte_to_hex(b : Byte) -> String {
  let hex_chars : String = "0123456789abcdef"
  let hi = b.to_int() / 16
  let lo = b.to_int() % 16
  hex_chars.unsafe_substring(start=hi, end=hi + 1) +
  hex_chars.unsafe_substring(start=lo, end=lo + 1)
}

fn to_hex(b : FixedArray[Byte]) -> String {
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    sb.write_string(byte_to_hex(b[i]))
  }
  sb.to_string()
}
