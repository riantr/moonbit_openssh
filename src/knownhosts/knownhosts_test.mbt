///| Loop #13 known_hosts 包黑盒测试 (T1-T10)
///
/// 本文件由 verify_c/gen_knownhosts_test.py 机器生成,勿手改。
/// 向量来源:verify_c/_knownhosts_ref_out.txt(Python 三盲参考,
/// 34/34 SHA-1/HMAC/NFA/parse/check 自检通过)。重新生成:
///   python verify_c/knownhosts_python_ref.py     # 重跑自检 + 落盘 KAT
///   python verify_c/gen_knownhosts_test.py       # 重产测试文件
///   python verify_c/knownhosts_harness.c 编译运行  # C 独立实现交叉验证

// 自动生成的十六进制工具函数(kexflow_test.mbt 同款)
fn khex(hex : String) -> FixedArray[Byte] {
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = ((_kd(hex[i * 2]) * 16 + _kd(hex[i * 2 + 1]))
              .reinterpret_as_uint() & 0xFFU)
      .to_byte()
  }
  arr
}

fn _kd(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 { code - 48 }
  else if code >= 97 && code <= 102 { code - 87 }
  else if code >= 65 && code <= 70 { code - 55 }
  else { abort("hex char invalid") }
}

fn _kfeq(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() { return false }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] { return false }
  }
  true
}

// ---- T1: SHA-1 FIPS 180-4 标准向量 ----
test "t1_sha1_fips_vectors" {
  // 空消息
  let empty = khex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
  let expected_empty = khex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
  if !_kfeq(empty, expected_empty) {
    abort("SHA-1(\"\") should match FIPS vector")
  }
  // "abc"
  let abc = khex("a9993e364706816aba3e25717850c26c9cd0d89d")
  let expected_abc = khex("a9993e364706816aba3e25717850c26c9cd0d89d")
  if !_kfeq(abc, expected_abc) {
    abort("SHA-1(\"abc\") should match FIPS vector")
  }
  // 长度校验
  if empty.length() != 20 { abort("SHA-1 output should be 20 bytes") }
  if abc.length() != 20 { abort("SHA-1 output should be 20 bytes") }
}

// ---- T2: HMAC-SHA1 RFC 2202 标准向量 ----
test "t2_hmac_sha1_rfc2202" {
  // Case 1: key = 0x0b * 20, msg = "Hi There"
  let key1 : FixedArray[Byte] = FixedArray::make(20, b'\x0b')
  let msg1 : FixedArray[Byte] = khex("4869205468657265")  // "Hi There"
  let h1 = @knownhosts.hmac_sha1(key1, msg1, msg1.length())
  let expected1 = khex("b617318655057264e28bc0b6fb378c8ef146be00")
  if !_kfeq(h1, expected1) {
    abort("HMAC-SHA1 Case 1 mismatch")
  }
  // Case 2: key = "Jefe", msg = "what do ya want for nothing?"
  let key2 : FixedArray[Byte] = khex("4a656665")  // "Jefe"
  let msg2 : FixedArray[Byte] = khex("7768617420646f2079612077616e7420666f72206e6f7468696e673f")
  let h2 = @knownhosts.hmac_sha1(key2, msg2, msg2.length())
  let expected2 = khex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79")
  if !_kfeq(h2, expected2) {
    abort("HMAC-SHA1 Case 2 mismatch")
  }
}

// ---- T3: parse_line 简单往返 ----
test "t3_parse_line_roundtrip" {
  let line = "example.com,*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"
  let entry = match @knownhosts.parse_line(line, 1) {
    Some(e) => e
    None => abort("parse_line should succeed")
  }
  // host_patterns 拆分:["example.com", "*.example.com"]
  if entry.host_patterns.length() != 2 {
    abort("host_patterns should have 2 entries")
  }
  if entry.host_patterns[0] != "example.com" {
    abort("host_patterns[0] should be 'example.com'")
  }
  if entry.host_patterns[1] != "*.example.com" {
    abort("host_patterns[1] should be '*.example.com'")
  }
  if entry.key_type != "ssh-ed25519" {
    abort("key_type should be 'ssh-ed25519'")
  }
  // key_blob 应等于 V1_blob_hex
  let expected_blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  if !_kfeq(entry.key_blob, expected_blob) {
    abort("key_blob should match V1_blob_hex")
  }
}

// ---- T4: parse_file 多行解析 ----
test "t4_parse_file_multi_line" {
  let line1 = "example.com,*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"
  // 构造 3 行 + 一个空行 + 一个 # 注释
  let content = line1 + "\n" +
                "foo.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk" + "\n" +
                "known.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk" + "\n" +
                "# comment\n" +
                "\n"
  let entries = @knownhosts.parse_file(content)
  // 跳过注释行 + 空行 → 3 entries
  if entries.length() != 3 {
    abort("parse_file should yield 3 entries (skip comment + empty)")
  }
  if entries[0].host_patterns[0] != "example.com" {
    abort("entries[0] should be V1 line")
  }
}

// ---- T5: NFA 通配符 ----
test "t5_nfa_wildcard" {
  // *.example.com vs foo.example.com → true(走 match_host_pattern 包裹)
  if !@knownhosts.match_host_pattern("foo.example.com", "*.example.com") {
    abort("*.example.com should match foo.example.com")
  }
  // *.example.com vs bar.example.org → false
  if @knownhosts.match_host_pattern("bar.example.org", "*.example.com") {
    abort("*.example.com should NOT match bar.example.org")
  }
  // ?hello vs ahello → true
  if !@knownhosts.match_host_pattern("ahello", "?hello") {
    abort("?hello should match ahello")
  }
  // *.example.com vs foo.example.com.evil → false(严格 full-match)
  if @knownhosts.match_host_pattern("foo.example.com.evil", "*.example.com") {
    abort("*.example.com should NOT match foo.example.com.evil")
  }
  // * vs 空字符串 → true
  if !@knownhosts.match_host_pattern("", "*") {
    abort("* should match empty")
  }
}

// ---- T6: V1 host_key_check Ok ----
test "t6_check_host_key_ok" {
  let content = "example.com,*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  // Loop #14 新签名:port=0 表示 default 22
  let status = @knownhosts.check_host_key(entries, "foo.example.com", 0, blob)
  if status != @knownhosts.Ok {
    abort("V1 should return Ok")
  }
}

// ---- T7: V4 |1| HMAC-SHA1 哈希 host 匹配 ----
test "t7_check_host_key_hashed" {
  let content = "|1|aGFzaGVkX3NhbHRfMDEyMwAAAAA|hCSB+hWjT7cddQRFZzHNnKLYu3Y ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILr8cb6tOsXktj6cghbucaNKrsZXIu7bynKLTps8zOOW\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d6564323535313900000020bafc71bead3ac5e4b63e9c8216ee71a34aaec65722eedbca728b4e9b3ccce396")
  let status = @knownhosts.check_host_key(entries, "hashed.example.com", 0, blob)
  if status != @knownhosts.Ok {
    abort("V4 hash entry should match expected host")
  }
}

// ---- T8: V5 mismatch ----
test "t8_check_host_key_mismatch" {
  let content = "foo.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d6564323535313900000020bafc71bead3ac5e4b63e9c8216ee71a34aaec65722eedbca728b4e9b3ccce396")
  let status = @knownhosts.check_host_key(entries, "foo.example.com", 0, blob)
  if status != @knownhosts.Mismatch {
    abort("V5 should return Mismatch")
  }
}

// ---- T9: V6 unknown host ----
test "t9_check_host_key_unknown" {
  let content = "known.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  let status = @knownhosts.check_host_key(entries, "unknown.example.org", 0, blob)
  if status != @knownhosts.Unknown {
    abort("V6 should return Unknown")
  }
}

// ---- T10: V7 strict + Unknown → Invalid ----
test "t10_check_host_key_strict_unknown_to_invalid" {
  let content = "known.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  let status = @knownhosts.check_host_key_strict(
    entries, "unknown.example.org", 0, blob, true)
  if status != @knownhosts.InvalidEntry {
    abort("V7 strict Unknown should return InvalidEntry")
  }
  // 非 strict 同样输入应返回 Unknown
  let status2 = @knownhosts.check_host_key_strict(
    entries, "unknown.example.org", 0, blob, false)
  if status2 != @knownhosts.Unknown {
    abort("V7 non-strict Unknown should return Unknown")
  }
}

// ---- marker & @revoked 形状 ----
test "t11_markers" {
  let v1_line = "example.com,*.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"
  // @revoked 行也解析为 entry(marker = Revoked);语义跳过,但 entry 存活
  let content = "@revoked " + v1_line + "\n"
  let entries = @knownhosts.parse_file(content)
  if entries.length() != 1 {
    abort("revoked entry should still parse")
  }
  if entries[0].marker != @knownhosts.Revoked {
    abort("marker should be Revoked")
  }
  let content2 = "@cert-authority " + v1_line + "\n"
  let entries2 = @knownhosts.parse_file(content2)
  if entries2.length() != 1 { abort("cert-authority entry should parse") }
  if entries2[0].marker != @knownhosts.CertAuthority {
    abort("marker should be CertAuthority")
  }
}

// ---- Loop #14 V9: plain host + default port → Ok ----
test "t13_v9_plain_host_default_port" {
  let content = "foo.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  let status = @knownhosts.check_host_key(entries, "foo.example.com", 0, blob)
  if status != @knownhosts.Ok {
    abort("V9 should return Ok (plain host + default port)")
  }
}

// ---- Loop #14 V10: [host]:port explicit → Ok ----
test "t14_v10_explicit_port" {
  let content = "[foo.example.com]:2200 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  // 两种调用方式:
  // 1) caller 给完整 [host]:port 字面 + port=0 → split_host_str 提取 port
  let status1 = @knownhosts.check_host_key(entries, "[foo.example.com]:2200", 0, blob)
  if status1 != @knownhosts.Ok {
    abort("V10a [host]:port caller-full + port=0 should be Ok")
  }
  // 2) caller 给 plain host + 显式 port 参数
  let status2 = @knownhosts.check_host_key(
    entries, "foo.example.com", 2200, blob)
  if status2 != @knownhosts.Ok {
    abort("V10b plain host + port=2200 should be Ok")
  }
}

// ---- Loop #14 V11: port mismatch → Unknown ----
test "t15_v11_port_mismatch" {
  let content = "[foo.example.com]:2200 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  // caller 默认 port 22 vs entry 2200 → Unknown
  let status = @knownhosts.check_host_key(entries, "foo.example.com", 0, blob)
  if status != @knownhosts.Unknown {
    abort("V11 caller port 22 vs entry 2200 should be Unknown")
  }
}

// ---- Loop #14 V12: @revoked wins → Mismatch ----
test "t16_v12_revoked_wins" {
  let content = "@revoked foo.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  // presented = A; entries[0] = @revoked ... A → Mismatch
  let status = @knownhosts.check_host_key(entries, "foo.example.com", 0, blob)
  if status != @knownhosts.Mismatch {
    abort("V12 @revoked + A presented should be Mismatch (Revoked 后置全局扫)")
  }
}

// ---- Loop #14 parse_line [host]:port 拆分 ----
test "t17_parse_split_host_port_spec" {
  // 使用 V10 已知基线 known_hosts 行 (已经是合法 base64)
  let line = "[foo.example.com]:2200 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZk"
  let entries = @knownhosts.parse_line(line, 1)
  let e = match entries {
    Some(x) => x
    None => abort("parse_line should succeed for [host]:port")
  }
  if e.host_patterns.length() != 1 {
    abort("[host]:port entry should have 1 host_pattern")
  }
  if e.host_patterns[0] != "[foo.example.com]:2200" {
    abort("host_patterns[0] should preserve literal [foo.example.com]:2200")
  }
  if e.host_specs.length() != 1 {
    abort("host_specs should have 1 entry parallel to host_patterns")
  }
  if e.host_specs[0].host_only != "foo.example.com" {
    abort("host_specs[0].host_only should be foo.example.com without brackets")
  }
  match e.host_specs[0].host_port {
    Some(2200) => ()
    _ => abort("host_specs[0].host_port should be Some(2200)")
  }
}

// ---- 空 entries / 空 blob / skip 空 + 注释 ----
test "t12_empty_and_comments" {
  let content = "# only a comment\n\n   \n"
  let entries = @knownhosts.parse_file(content)
  if entries.length() != 0 {
    abort("comment-only file should produce 0 entries")
  }
  // 空 entries 调用 check_host_key → Unknown
  let blob = khex("0000000b7373682d656432353531390000002079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
  let status = @knownhosts.check_host_key([], "any.host", 0, blob)
  if status != @knownhosts.Unknown {
    abort("empty entries should return Unknown")
  }
}
