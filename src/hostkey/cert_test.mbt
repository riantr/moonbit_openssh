///| Loop #53 主机证书测试
///
///| 固定件全部由 `host/cert_gen_fixture.py` 从真实的 `ssh-keygen -s` 证书生成，
///| 证书字段顺序、`signed_data` 切片长度、`SSH_CERT_TYPE_*` 常量都对着字节核过，
///| 且与 `ssh-keygen -L` 的输出交叉验证（见 cert.mbt 顶部）。
///
///| 时钟一律显式传入，不读墙上时间——否则「过期证书必须被拒」这条断言在写出来的
///| 第二天就永远为真了，等于没有。

///|
fn cert_b64(s : String) -> FixedArray[Byte] {
  let view : StringView = s
  let res = try { @base64.decode(view, ignore_whitespace=false) } catch {
    _ => Bytes::new(0)
  }
  let arr : FixedArray[Byte] = FixedArray::make(res.length(), b'\x00')
  for i = 0; i < res.length(); i = i + 1 {
    arr[i] = res[i]
  }
  arr
}

///|
/// GOOD_CERT 的有效期正中（由 ssh-keygen -V -1d:+1d 生成，落在固定件窗口内）
/// GOOD_CERT 的有效期正中（由生成脚本算出的窗口中点，不手写时间戳）
const NOW_MID : UInt64 = (GOOD_CERT_VALID_AFTER + GOOD_CERT_VALID_BEFORE) / 2UL

///|
fn cert_ok(v : CertVerdict) -> Bool {
  v is Trusted(_)
}

///
/// 期望「证书可信」，失败时把**具体理由**打出来。理由比行号有用得多：同一个
/// test 里「被拒」可以是换 CA、过期、principal 不对、验签失败，处置完全不同。
fn cert_expect_trusted(v : CertVerdict) -> Unit {
  if !cert_ok(v) {
    abort("expected trusted, got: " + cert_reason(v))
  }
}

///|
fn cert_reason(v : CertVerdict) -> String {
  match v {
    Trusted(_) => "trusted"
    Rejected(f) =>
      match f {
        Malformed => "malformed"
        CaNotPinned => "ca-not-pinned"
        CaSignatureInvalid => "ca-sig-invalid"
        NotHostCertificate => "not-host"
        NotYetValid => "not-yet-valid"
        Expired => "expired"
        PrincipalMismatch => "principal-mismatch"
        UnsupportedCriticalOption => "critical-option"
        InnerKeyUnsupported => "inner-key-unsupported"
      }
  }
}

///|
/// 从 blob 偏移 off 起把一个字节翻转，用来制造「结构仍合法但内容被改过」的证书
fn cert_flip(blob : FixedArray[Byte], off : Int) -> FixedArray[Byte] {
  let out = FixedArray::make(blob.length(), b'\x00')
  for i = 0; i < blob.length(); i = i + 1 {
    out[i] = blob[i]
  }
  out[off] = (out[off].to_int() ^ 0xFF).to_byte()
  out
}

///|
fn cert_truncate(blob : FixedArray[Byte], n : Int) -> FixedArray[Byte] {
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = blob[i]
  }
  out
}

///|
fn cert_parse_or_die(b : FixedArray[Byte]) -> HostCert {
  match HostCert::from_blob(b) {
    Rejected(_) => panic()
    Parsed(c) => c
  }
}

// ---------------------------------------------------------------------------
// 解析
// ---------------------------------------------------------------------------

test "cert_parse_good" {
  let c = cert_parse_or_die(cert_b64(GOOD_CERT))
  assert_eq(c.cert_type_name, "ssh-ed25519-cert-v01@openssh.com")
  assert_eq(c.key_type_name, "ssh-ed25519")
  assert_eq(c.cert_type, SSH_CERT_TYPE_HOST)
  assert_eq(c.key_id, "host.example.com")  // CA-assigned key id, NOT the principal
  assert_eq(c.principals.length(), 1)
  assert_eq(c.principals[0], "127.0.0.1")
  assert_eq(c.serial, 0UL)
  assert_eq(c.valid_after, GOOD_CERT_VALID_AFTER)
  assert_eq(c.valid_before, GOOD_CERT_VALID_BEFORE)
  assert_eq(c.critical_options.length(), 0)
  assert_eq(c.extensions.length(), 0)
  assert_eq(c.reserved.length(), 0)
  assert_eq(c.nonce.length(), 32)
  assert_eq(c.inner_key.length(), 32)
  // 这条是整个解析器的核心断言：切片短一字节或多一字节，下面的 CA 验签都会失败。
  assert_eq(c.signed_data.length(), GOOD_CERT_SIGNED_LEN)
}

test "cert_inner_key_round_trips" {
  let cert = cert_parse_or_die(cert_b64(GOOD_CERT))
  let key = match HostKey::from_blob(cert.inner_key_blob) {
    Rejected(_) => panic()
    Parsed(k) => k
  }
  match key {
    Ed25519Key(pk) => {
      assert_eq(pk.length(), 32)
      for i = 0; i < 32; i = i + 1 {
        assert_eq(pk[i], cert.inner_key[i])
      }
    }
    _ => panic()
  }
}

test "cert_names_its_signer" {
  let cert = cert_parse_or_die(cert_b64(GOOD_CERT))
  let ca = cert_b64(CA_PUB)
  assert_eq(cert.sig_key.length(), ca.length())
  for i = 0; i < ca.length(); i = i + 1 {
    assert_eq(cert.sig_key[i], ca[i])
  }
}

test "cert_signed_data_is_the_prefix" {
  let blob = cert_b64(GOOD_CERT)
  let cert = cert_parse_or_die(blob)
  let n = cert.signed_data.length()
  assert_eq(n, GOOD_CERT_SIGNED_LEN)
  for i = 0; i < n; i = i + 1 {
    assert_eq(cert.signed_data[i], blob[i])
  }
}

test "cert_type_name_helpers" {
  assert_true(is_cert_type_name("ssh-ed25519-cert-v01@openssh.com"))
  assert_true(!is_cert_type_name("ssh-ed25519"))
  assert_eq(
    plain_type_of_cert("ssh-ed25519-cert-v01@openssh.com"),
    "ssh-ed25519",
  )
  assert_eq(plain_type_of_cert("ssh-rsa-cert-v01@openssh.com"), "ssh-rsa")
  assert_true(looks_like_cert(cert_b64(GOOD_CERT)))
  assert_true(!looks_like_cert(cert_b64(HOST_PUB)))
}

test "cert_structural_failures" {
  let blob = cert_b64(GOOD_CERT)
  match HostCert::from_blob(cert_truncate(blob, blob.length() - 20)) {
    Rejected(Malformed) => ()
    _ => panic()
  }
  let long = FixedArray::make(blob.length() + 1, b'\x00')
  for i = 0; i < blob.length(); i = i + 1 {
    long[i] = blob[i]
  }
  match HostCert::from_blob(long) {
    Rejected(TrailingData) => ()
    _ => panic()
  }
  match HostCert::from_blob(cert_b64(HOST_PUB)) {
    Rejected(NotACertificate(name)) => assert_eq(name, "ssh-ed25519")
    _ => panic()
  }
}

test "cert_principals_are_a_blob_of_strings" {
  let c = cert_parse_or_die(cert_b64(NON_HOST_PRINCIPAL_CERT))
  assert_eq(c.principals.length(), 2)
  assert_eq(c.principals[0], "alice")
  assert_eq(c.principals[1], "bob")
  // 空字段 → 空列表。这半边可测；「空列表 = 对所有 principal 有效」那半边需要
  // 一张 ssh-keygen 签不出来的证书（它拒绝空 principal 名：Empty principal name），
  // 是已知缺口，见 AGENTS.md。
  match parse_principals(FixedArray::make(0, b'\x00')) {
    Some(ps) => assert_eq(ps.length(), 0)
    None => panic()
  }
}

// ---------------------------------------------------------------------------
// 验证
// ---------------------------------------------------------------------------

test "cert_verifies_with_pinned_ca" {
  let v = verify_host_cert(
    cert_b64(GOOD_CERT),
    cert_b64(CA_PUB),
    "127.0.0.1",
    NOW_MID,
  )
  cert_expect_trusted(v)
}

test "cert_signed_data_tamper_is_caught" {
  // 翻的是 nonce（blob 偏移 0x28），结构仍然完全合法——只改内容不改布局。
  // 若把检查顺序改成「先看语义字段后验签」，这条仍然会红，所以它同时也在钉顺序。
  let v = verify_host_cert(
    cert_flip(cert_b64(GOOD_CERT), 0x28),
    cert_b64(CA_PUB),
    "127.0.0.1",
    NOW_MID,
  )
  assert_eq(cert_reason(v), "ca-sig-invalid")
}

test "cert_signature_tamper_is_caught" {
  let blob = cert_b64(GOOD_CERT)
  let v = verify_host_cert(
    cert_flip(blob, blob.length() - 1),
    cert_b64(CA_PUB),
    "127.0.0.1",
    NOW_MID,
  )
  assert_eq(cert_reason(v), "ca-sig-invalid")
}

test "cert_wrong_ca_is_ca_not_pinned" {
  // 这两种区分不是洁癖：前者是「这台主机的 CA 不在你 pin 的名单里」，后者是
  // 「有人在中间乱改」。处置完全不同。
  let cert = cert_b64(ROGUE_CA_CERT)
  let v = verify_host_cert(cert, cert_b64(CA_PUB), "127.0.0.1", NOW_MID)
  assert_eq(cert_reason(v), "ca-not-pinned")
  // 同一张证书配上它自己的 CA 就该过——否则上面那条可能只是「这张证书坏了」
  let v2 = verify_host_cert(
    cert,
    cert_b64(ROGUE_CA_PUB),
    "127.0.0.1",
    NOW_MID,
  )
  cert_expect_trusted(v2)
}

test "cert_ca_anchor_is_exactly_the_pinned_one" {
  // CA 信任锚的语义是「这张证书由**这一把** CA 签的」，两个方向都要成立：
  //
  //   rogue 证书 + 真的 CA   -> 不认（ca-not-pinned）
  //   rogue 证书 + rogue CA  -> 认，而且这是**正确**的
  //
  // 第二条容易被写成「任何不是 ca.pub 的证书都必须被拒」，那是把 CA 信任锚
  // 退化成了「只认一把写死的钥匙」——每台主机换一把 CA 就得改代码。
  let cert = cert_b64(ROGUE_CA_CERT)
  let wrong = verify_host_cert(cert, cert_b64(CA_PUB), "127.0.0.1", NOW_MID)
  assert_eq(cert_reason(wrong), "ca-not-pinned")
  let right = verify_host_cert(
    cert,
    cert_b64(ROGUE_CA_PUB),
    "127.0.0.1",
    NOW_MID,
  )
  cert_expect_trusted(right)
}

test "user_certificate_is_not_a_host_certificate" {
  // 这是本轮最贵的一条常量：SSH_CERT_TYPE_USER=1 / HOST=2。若写反，一张发给
  // alice 的用户证书就会被当成主机证书。这里连 principal 都传成证书自己声称的
  // alice，这样只剩类型检查挡着它——写反常量时这条断言是唯一会红的。
  let c = cert_parse_or_die(cert_b64(USER_CERT))
  assert_eq(c.cert_type, SSH_CERT_TYPE_USER)
  assert_eq(SSH_CERT_TYPE_USER, 1)
  assert_eq(SSH_CERT_TYPE_HOST, 2)
  assert_eq(c.principals[0], "alice")
  let v = verify_host_cert(cert_b64(USER_CERT), cert_b64(CA_PUB), "alice", NOW_MID)
  assert_eq(cert_reason(v), "not-host")
}

test "cert_validity_window" {
  let cert = cert_b64(EXPIRED_CERT)
  let ca = cert_b64(CA_PUB)
  let c = cert_parse_or_die(cert)
  // 窗口内 → 信任（证明这条不是无脑拒）
  let inside = (c.valid_after + c.valid_before) / 2UL
  let v_ok = verify_host_cert(cert, ca, "127.0.0.1", inside)
  cert_expect_trusted(v_ok)
  let v_expired = verify_host_cert(cert, ca, "127.0.0.1", c.valid_before + 1UL)
  assert_eq(cert_reason(v_expired), "expired")
  let v_early = verify_host_cert(cert, ca, "127.0.0.1", c.valid_after - 1UL)
  assert_eq(cert_reason(v_early), "not-yet-valid")
  // 好证书用两个远离窗口的时间各判一次——两个方向都要区分得开。探针由常量
  // 推出而不是写死日期：写死的日期在固定件重新签发之后会悄悄落进窗口内部，
  // 于是这条断言变成「窗口内应当通过」，看起来仍然绿，但什么也没断言到。
  // 两个方向必须分开：混成一个「不在窗口内就拒绝」会掩盖这个区别。
  let v_past = verify_host_cert(
    cert_b64(GOOD_CERT),
    ca,
    "127.0.0.1",
    GOOD_CERT_VALID_AFTER - 1UL,
  )
  assert_eq(cert_reason(v_past), "not-yet-valid")
  let v_future = verify_host_cert(
    cert_b64(GOOD_CERT),
    ca,
    "127.0.0.1",
    GOOD_CERT_VALID_BEFORE + 1UL,
  )
  assert_eq(cert_reason(v_future), "expired")
}

test "cert_principal_mismatch" {
  let cert = cert_b64(OTHER_PRINCIPAL_CERT)
  let ca = cert_b64(CA_PUB)
  let v = verify_host_cert(cert, ca, "127.0.0.1", NOW_MID)
  assert_eq(cert_reason(v), "principal-mismatch")
  let v2 = verify_host_cert(cert, ca, "other.example.com", NOW_MID)
  cert_expect_trusted(v2)
  let v3 = verify_host_cert(
    cert_b64(NON_HOST_PRINCIPAL_CERT),
    ca,
    "127.0.0.1",
    NOW_MID,
  )
  assert_eq(cert_reason(v3), "principal-mismatch")
}

test "cert_principal_comparison_is_exact" {
  let v = verify_host_cert(
    cert_b64(GOOD_CERT),
    cert_b64(CA_PUB),
    "host.example.com.evil.test",
    NOW_MID,
  )
  assert_eq(cert_reason(v), "principal-mismatch")
  let v2 = verify_host_cert(
    cert_b64(GOOD_CERT),
    cert_b64(CA_PUB),
    "127.0.0.11",
    NOW_MID,
  )
  assert_eq(cert_reason(v2), "principal-mismatch")
  // known_hosts 支持 *.example.com 通配，principal 不支持——两者规则不同是有意的
  let v3 = verify_host_cert(
    cert_b64(GOOD_CERT),
    cert_b64(CA_PUB),
    "*.example.com",
    NOW_MID,
  )
  assert_eq(cert_reason(v3), "principal-mismatch")
}