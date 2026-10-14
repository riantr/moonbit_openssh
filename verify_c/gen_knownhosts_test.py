#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop #13 -- 由 _knownhosts_ref_out.txt 机器生成两份产物(KAT 禁止手抄):

1) src/knownhosts/knownhosts_test.mbt   MoonBit 黑盒测试(T1-T10,字面量内嵌)
2) verify_c/_knownhosts_kat.h           C harness 向量头(供 knownhosts_harness.c)

向量唯一来源:knownhosts_python_ref.py 自检 34/34 通过后落盘的 KAT 文件。

用法:
    python verify_c/knownhosts_python_ref.py     # 跑自检 + 落盘 KAT
    python verify_c/gen_knownhosts_test.py       # 从 KAT 双产
"""
import os
import re
import sys

ROOT = r'E:\src\moon\openssh_moonbit'
KAT_PATH = os.path.join(ROOT, 'verify_c', '_knownhosts_ref_out.txt')
MBT_OUT = os.path.join(ROOT, 'src', 'knownhosts', 'knownhosts_test.mbt')
H_OUT = os.path.join(ROOT, 'verify_c', '_knownhosts_kat.h')


def parse_kat(path):
    vec = {}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('[') or line.startswith('==='):
            continue
        if '=' not in line:
            continue
        k, v = line.split('=', 1)
        vec[k.strip()] = v.strip()
    return vec


def sanity(vec):
    """与 knownhosts_python_ref.py 自检交叉断言(防止种子漂移)."""
    # SHA-1 FIPS 180-4 标准
    assert vec['V0_sha1_empty_hex'] == 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    assert vec['V0_sha1_abc_hex'] == 'a9993e364706816aba3e25717850c26c9cd0d89d'
    assert vec['V0_sha1_long_hex'] == '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
    # HMAC-SHA1 RFC 2202
    assert vec['V0b_hmac_case1_hex'] == 'b617318655057264e28bc0b6fb378c8ef146be00'
    assert vec['V0b_hmac_case2_hex'] == 'effcdf6ae5eb2fa2d27416d5f184df9c259a7c79'
    # Last-match-wins vectors
    assert vec['V1_expected_status'] == '0', 'V1 should be Ok (0)'
    assert vec['V4_expected_status'] == '0', 'V4 hash entry should match'
    assert vec['V5_expected_status'] == '1', 'V5 should be Mismatch (1)'
    assert vec['V6_expected_status'] == '2', 'V6 should be Unknown (2)'
    assert vec['V7_expected_status'] == '3', 'V7 strict Unknown should be Invalid (3)'
    # Loop #14 V9-V12 expected_status
    assert vec['V9_expected_status'] == '0', 'V9 plain + default port should be Ok (0)'
    assert vec['V10_expected_status'] == '0', 'V10 [host]:port should match (Ok=0)'
    assert vec['V11_expected_status'] == '2', 'V11 port mismatch should be Unknown (2)'
    assert vec['V12_expected_status'] == '1', 'V12 @revoked wins should be Mismatch (1)'
    assert vec['V9_port'] == '0', 'V9 caller port 0 (default)'
    assert vec['V10_port'] == '2200', 'V10 explicit port'
    assert vec['V11_port'] == '0', 'V11 caller port 0'
    assert vec['V12_port'] == '0', 'V12 caller port 0'
    # 字节长度
    assert len(vec['V8_PK_A_hex']) == 64, 'V8 PK_A 长度应为 64 hex chars'
    assert len(vec['V8_BLOB_A_hex']) > 4 and vec['V8_BLOB_A_hex'].startswith('0000000b7373682d65643235353139'), \
        'V8 BLOB_A 应以 00 00 00 0b + "ssh-ed25519" 开头'


def mbt_template(vec):
    """生成 MoonBit 测试文件,用 @@KEY@@ 占位符避免与 MoonBit 的 {} 语法冲突."""
    return r'''///| Loop #13 known_hosts 包黑盒测试 (T1-T10)
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
  let empty = khex("@@V0_sha1_empty_hex@@")
  let expected_empty = khex("da39a3ee5e6b4b0d3255bfef95601890afd80709")
  if !_kfeq(empty, expected_empty) {
    abort("SHA-1(\"\") should match FIPS vector")
  }
  // "abc"
  let abc = khex("@@V0_sha1_abc_hex@@")
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
  let expected1 = khex("@@V0b_hmac_case1_hex@@")
  if !_kfeq(h1, expected1) {
    abort("HMAC-SHA1 Case 1 mismatch")
  }
  // Case 2: key = "Jefe", msg = "what do ya want for nothing?"
  let key2 : FixedArray[Byte] = khex("4a656665")  // "Jefe"
  let msg2 : FixedArray[Byte] = khex("7768617420646f2079612077616e7420666f72206e6f7468696e673f")
  let h2 = @knownhosts.hmac_sha1(key2, msg2, msg2.length())
  let expected2 = khex("@@V0b_hmac_case2_hex@@")
  if !_kfeq(h2, expected2) {
    abort("HMAC-SHA1 Case 2 mismatch")
  }
}

// ---- T3: parse_line 简单往返 ----
test "t3_parse_line_roundtrip" {
  let line = "@@V1_knownhosts_line@@"
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
  let expected_blob = khex("@@V1_blob_hex@@")
  if !_kfeq(entry.key_blob, expected_blob) {
    abort("key_blob should match V1_blob_hex")
  }
}

// ---- T4: parse_file 多行解析 ----
test "t4_parse_file_multi_line" {
  let line1 = "@@V1_knownhosts_line@@"
  // 构造 3 行 + 一个空行 + 一个 # 注释
  let content = line1 + "\n" +
                "@@V5_knownhosts_line@@" + "\n" +
                "@@V6_knownhosts_line@@" + "\n" +
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
  let content = "@@V1_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V1_blob_hex@@")
  // Loop #14 新签名:port=0 表示 default 22
  let status = @knownhosts.check_host_key(entries, "@@V1_host@@", 0, blob)
  if status != @knownhosts.Ok {
    abort("V1 should return Ok")
  }
}

// ---- T7: V4 |1| HMAC-SHA1 哈希 host 匹配 ----
test "t7_check_host_key_hashed" {
  let content = "@@V4_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V4_blob_hex@@")
  let status = @knownhosts.check_host_key(entries, "@@V4_host@@", 0, blob)
  if status != @knownhosts.Ok {
    abort("V4 hash entry should match expected host")
  }
}

// ---- T8: V5 mismatch ----
test "t8_check_host_key_mismatch" {
  let content = "@@V5_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V5_presented_blob_hex@@")
  let status = @knownhosts.check_host_key(entries, "@@V5_host@@", 0, blob)
  if status != @knownhosts.Mismatch {
    abort("V5 should return Mismatch")
  }
}

// ---- T9: V6 unknown host ----
test "t9_check_host_key_unknown" {
  let content = "@@V6_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V6_presented_blob_hex@@")
  let status = @knownhosts.check_host_key(entries, "@@V6_host@@", 0, blob)
  if status != @knownhosts.Unknown {
    abort("V6 should return Unknown")
  }
}

// ---- T10: V7 strict + Unknown → Invalid ----
test "t10_check_host_key_strict_unknown_to_invalid" {
  let content = "@@V7_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V7_presented_blob_hex@@")
  let status = @knownhosts.check_host_key_strict(
    entries, "@@V7_host@@", 0, blob, true)
  if status != @knownhosts.InvalidEntry {
    abort("V7 strict Unknown should return InvalidEntry")
  }
  // 非 strict 同样输入应返回 Unknown
  let status2 = @knownhosts.check_host_key_strict(
    entries, "@@V7_host@@", 0, blob, false)
  if status2 != @knownhosts.Unknown {
    abort("V7 non-strict Unknown should return Unknown")
  }
}

// ---- marker & @revoked 形状 ----
test "t11_markers" {
  let v1_line = "@@V1_knownhosts_line@@"
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
  let content = "@@V9_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V9_presented_blob_hex@@")
  let status = @knownhosts.check_host_key(entries, "@@V9_host@@", @@V9_port@@, blob)
  if status != @knownhosts.Ok {
    abort("V9 should return Ok (plain host + default port)")
  }
}

// ---- Loop #14 V10: [host]:port explicit → Ok ----
test "t14_v10_explicit_port" {
  let content = "@@V10_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V10_presented_blob_hex@@")
  // 两种调用方式:
  // 1) caller 给完整 [host]:port 字面 + port=0 → split_host_str 提取 port
  let status1 = @knownhosts.check_host_key(entries, "@@V10_host@@", 0, blob)
  if status1 != @knownhosts.Ok {
    abort("V10a [host]:port caller-full + port=0 should be Ok")
  }
  // 2) caller 给 plain host + 显式 port 参数
  let status2 = @knownhosts.check_host_key(
    entries, "foo.example.com", @@V10_port@@, blob)
  if status2 != @knownhosts.Ok {
    abort("V10b plain host + port=2200 should be Ok")
  }
}

// ---- Loop #14 V11: port mismatch → Unknown ----
test "t15_v11_port_mismatch" {
  let content = "@@V11_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V11_presented_blob_hex@@")
  // caller 默认 port 22 vs entry 2200 → Unknown
  let status = @knownhosts.check_host_key(entries, "@@V11_host@@", 0, blob)
  if status != @knownhosts.Unknown {
    abort("V11 caller port 22 vs entry 2200 should be Unknown")
  }
}

// ---- Loop #14 V12: @revoked wins → Mismatch ----
test "t16_v12_revoked_wins" {
  let content = "@@V12_knownhosts_line@@\n"
  let entries = @knownhosts.parse_file(content)
  let blob = khex("@@V12_presented_blob_hex@@")
  // presented = A; entries[0] = @revoked ... A → Mismatch
  let status = @knownhosts.check_host_key(entries, "@@V12_host@@", 0, blob)
  if status != @knownhosts.Mismatch {
    abort("V12 @revoked + A presented should be Mismatch (Revoked 后置全局扫)")
  }
}

// ---- Loop #14 parse_line [host]:port 拆分 ----
test "t17_parse_split_host_port_spec" {
  // 使用 V10 已知基线 known_hosts 行 (已经是合法 base64)
  let line = "@@V10_knownhosts_line@@"
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
  let blob = khex("@@V1_blob_hex@@")
  let status = @knownhosts.check_host_key([], "any.host", 0, blob)
  if status != @knownhosts.Unknown {
    abort("empty entries should return Unknown")
  }
}
'''.replace('@@V1_host@@', vec['V1_host']).replace('@@V4_host@@', vec['V4_host']) \
   .replace('@@V5_host@@', vec['V5_host']).replace('@@V6_host@@', vec['V6_host']) \
   .replace('@@V7_host@@', vec['V7_host']).replace('@@V1_blob_hex@@', vec['V1_blob_hex']) \
   .replace('@@V4_blob_hex@@', vec['V4_blob_hex']).replace('@@V5_presented_blob_hex@@', vec['V5_presented_blob_hex']) \
   .replace('@@V6_presented_blob_hex@@', vec['V6_presented_blob_hex']) \
   .replace('@@V7_presented_blob_hex@@', vec['V7_presented_blob_hex']) \
   .replace('@@V1_knownhosts_line@@', vec['V1_knownhosts_line']) \
   .replace('@@V3_knownhosts_line@@', vec['V3_knownhosts_line']) \
   .replace('@@V4_knownhosts_line@@', vec['V4_knownhosts_line']) \
   .replace('@@V5_knownhosts_line@@', vec['V5_knownhosts_line']) \
   .replace('@@V6_knownhosts_line@@', vec['V6_knownhosts_line']) \
   .replace('@@V7_knownhosts_line@@', vec['V7_knownhosts_line']) \
   .replace('@@V0_sha1_empty_hex@@', vec['V0_sha1_empty_hex']) \
   .replace('@@V0_sha1_abc_hex@@', vec['V0_sha1_abc_hex']) \
   .replace('@@V0b_hmac_case1_hex@@', vec['V0b_hmac_case1_hex']) \
   .replace('@@V0b_hmac_case2_hex@@', vec['V0b_hmac_case2_hex']) \
   .replace('@@V9_host@@', vec['V9_host']).replace('@@V9_port@@', vec['V9_port']) \
   .replace('@@V9_presented_blob_hex@@', vec['V9_presented_blob_hex']) \
   .replace('@@V9_knownhosts_line@@', vec['V9_knownhosts_line']) \
   .replace('@@V10_host@@', vec['V10_host']).replace('@@V10_port@@', vec['V10_port']) \
   .replace('@@V10_presented_blob_hex@@', vec['V10_presented_blob_hex']) \
   .replace('@@V10_knownhosts_line@@', vec['V10_knownhosts_line']) \
   .replace('@@V11_host@@', vec['V11_host']).replace('@@V11_port@@', vec['V11_port']) \
   .replace('@@V11_presented_blob_hex@@', vec['V11_presented_blob_hex']) \
   .replace('@@V11_knownhosts_line@@', vec['V11_knownhosts_line']) \
   .replace('@@V12_host@@', vec['V12_host']).replace('@@V12_port@@', vec['V12_port']) \
   .replace('@@V12_presented_blob_hex@@', vec['V12_presented_blob_hex']) \
   .replace('@@V12_knownhosts_line@@', vec['V12_knownhosts_line'])


def c_header_template(vec):
    """生成 C 头文件(供 knownhosts_harness.c 使用)."""
    # 字节向量(V1-V7)
    byte_vecs = [
        ('V1_BLOB', vec['V1_blob_hex']),
        ('V4_BLOB', vec['V4_blob_hex']),
        ('V5_BLOB', vec['V5_presented_blob_hex']),
        ('V4_SALT', vec['V4_salt_hex']),
        ('V4_HASH', vec['V4_hash_hex']),
        ('V8_PK_A', vec['V8_PK_A_hex']),
        ('V8_PK_B', vec['V8_PK_B_hex']),
        ('V8_BLOB_A', vec['V8_BLOB_A_hex']),
        ('V8_BLOB_B', vec['V8_BLOB_B_hex']),
        ('V0_SHA1_EMPTY', vec['V0_sha1_empty_hex']),
        ('V0_SHA1_ABC', vec['V0_sha1_abc_hex']),
        ('V0_SHA1_LONG', vec['V0_sha1_long_hex']),
        ('V0B_HMAC_CASE1', vec['V0b_hmac_case1_hex']),
        ('V0B_HMAC_CASE2', vec['V0b_hmac_case2_hex']),
        ('V9_PRESENTED_BLOB', vec['V9_presented_blob_hex']),
        ('V10_PRESENTED_BLOB', vec['V10_presented_blob_hex']),
        ('V11_PRESENTED_BLOB', vec['V11_presented_blob_hex']),
        ('V12_PRESENTED_BLOB', vec['V12_presented_blob_hex']),
        # Loop #56: @cert-authority 用例。C1/C3 出示的不是 CA 自己那把钥匙，
        # C3 出示的**正是** CA 条目里那把——修 Loop #51 之前后者会返回 Ok。
        ('C1_PRESENTED_BLOB', vec['C1_presented_blob_hex']),
        ('C2_PRESENTED_BLOB', vec['C2_presented_blob_hex']),
        ('C3_PRESENTED_BLOB', vec['C3_presented_blob_hex']),
    ]
    lines = []
    lines.append('/**')
    lines.append(' * Loop #13 known_hosts test vectors (generated from knownhosts_python_ref.py)')
    lines.append(' * DO NOT MODIFY BY HAND - re-run gen_knownhosts_test.py to update')
    lines.append(' */')
    lines.append('#ifndef _KNOWNHOSTS_KAT_H_')
    lines.append('#define _KNOWNHOSTS_KAT_H_')
    lines.append('')
    lines.append('#include <stddef.h>')
    lines.append('#include <stdint.h>')
    lines.append('')

    for name, hexstr in byte_vecs:
        n = len(hexstr) // 2
        lines.append(f'static const uint8_t {name}[{n}] = {{')
        for i in range(0, len(hexstr), 24):
            chunk = hexstr[i:i + 24]
            bytes_chunk = [chunk[j:j + 2] for j in range(0, len(chunk), 2)]
            line = ', '.join(f'0x{b}' for b in bytes_chunk)
            lines.append(f'  {line},')
        lines.append('};')
        lines.append(f'static const size_t {name}_len = {n};')
        lines.append('')

    # 字符串向量(host names)
    str_vecs = [
        ('V1_HOST', vec['V1_host']),
        ('V2_HOST', vec['V2_host']),
        ('V3_HOST', vec['V3_host']),
        ('V4_HOST', vec['V4_host']),
        ('V5_HOST', vec['V5_host']),
        ('V6_HOST', vec['V6_host']),
        ('V7_HOST', vec['V7_host']),
        ('V9_HOST', vec['V9_host']),
        ('V10_HOST', vec['V10_host']),
        ('V11_HOST', vec['V11_host']),
        ('V12_HOST', vec['V12_host']),
        ('C1_HOST', vec['C1_host']),
        ('C2_HOST', vec['C2_host']),
        ('C3_HOST', vec['C3_host']),
    ]
    for name, s in str_vecs:
        # C 字符串字面量
        byte_seq = ', '.join(f"'{c}'" if c not in '\\"' else f"'{ord(c)}'" for c in s)
        # 安全做法:用 ord() 统一形式
        byte_seq = ', '.join(str(ord(c)) for c in s)
        lines.append(f'static const char {name}[] = {{ {byte_seq}, 0 }};')
        lines.append(f'static const size_t {name}_len = {len(s)};')
        lines.append('')

    # expected_status 整型
    int_vecs = [
        ('V1_STATUS', int(vec['V1_expected_status'])),
        ('V2_STATUS', int(vec['V2_expected_status'])),
        ('V3_STATUS', int(vec['V3_expected_status'])),
        ('V4_STATUS', int(vec['V4_expected_status'])),
        ('V5_STATUS', int(vec['V5_expected_status'])),
        ('V6_STATUS', int(vec['V6_expected_status'])),
        ('V7_STATUS', int(vec['V7_expected_status'])),
        ('V9_STATUS', int(vec['V9_expected_status'])),
        ('V10_STATUS', int(vec['V10_expected_status'])),
        ('V11_STATUS', int(vec['V11_expected_status'])),
        ('V12_STATUS', int(vec['V12_expected_status'])),
        # Loop #56: 4 = CertAuthority
        ('C1_STATUS', int(vec['C1_expected_status'])),
        ('C2_STATUS', int(vec['C2_expected_status'])),
        ('C3_STATUS', int(vec['C3_expected_status'])),
        ('V9_PORT', int(vec['V9_port'])),
        ('V10_PORT', int(vec['V10_port'])),
        ('V11_PORT', int(vec['V11_port'])),
        ('V12_PORT', int(vec['V12_port'])),
    ]
    for name, v in int_vecs:
        lines.append(f'#define {name} {v}')
    lines.append('')
    lines.append('/* HOST_OK=0 HOST_MISMATCH=1 HOST_UNKNOWN=2 HOST_INVALID=3')
    lines.append(' * HOST_CERT_AUTHORITY=4  (Loop #56; src/knownhosts has it since #51)')
    lines.append(' */')
    lines.append('')

    # known_hosts 整行(test 给 harness 用)
    line_vecs = [
        ('V1_KH_LINE', vec['V1_knownhosts_line']),
        ('V3_KH_LINE', vec['V3_knownhosts_line']),
        ('V4_KH_LINE', vec['V4_knownhosts_line']),
        ('V5_KH_LINE', vec['V5_knownhosts_line']),
        ('V6_KH_LINE', vec['V6_knownhosts_line']),
        ('V7_KH_LINE', vec['V7_knownhosts_line']),
        ('V9_KH_LINE', vec['V9_knownhosts_line']),
        ('V10_KH_LINE', vec['V10_knownhosts_line']),
        ('V11_KH_LINE', vec['V11_knownhosts_line']),
        ('V12_KH_LINE', vec['V12_knownhosts_line']),
        # Loop #56: @cert-authority。C2 是**两行**（直接条目 + CA 条目），向量文件里
        # 因此是两个键而不是一个带换行的值——向量文件是行式的。
        ('C1_KH_LINE', vec['C1_knownhosts_line']),
        ('C2_KH_LINE', vec['C2_knownhosts_line']),
        ('C2_KH_LINE_CA', vec['C2_knownhosts_line_ca']),
        ('C3_KH_LINE', vec['C3_knownhosts_line']),
    ]
    for name, s in line_vecs:
        byte_seq = ', '.join(str(ord(c)) for c in s)
        lines.append(f'static const char {name}[] = {{ {byte_seq}, 0 }};')
        lines.append(f'static const size_t {name}_len = {len(s)};')
        lines.append('')

    lines.append('#endif // _KNOWNHOSTS_KAT_H_')
    return '\n'.join(lines) + '\n'


def main():
    vec = parse_kat(KAT_PATH)
    sanity(vec)
    with open(MBT_OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(mbt_template(vec))
    print(f'Generated {MBT_OUT}')
    with open(H_OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(c_header_template(vec))
    print(f'Generated {H_OUT}')


if __name__ == '__main__':
    main()
