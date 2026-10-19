#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop #11 -- 由 _hostkey_ref_out.txt 机器生成两份产物(KAT 禁止手抄):

1) src/hostkey/hostkey_test.mbt   MoonBit 黑盒测试(T1-T9,字面量内嵌)
2) verify_c/_hostkey_kat.h        C harness 向量头

向量唯一来源:hostkey_python_ref.py 自检 6/6 后落盘的 KAT 文件。
seed 公式与参考脚本一致,并与模块常量交叉断言。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hostkey_python_ref as ref  # noqa: E402  (import 副作用受 __main__ 保护)

# Loop #71: this was ROOT = r'E:\src\moon\openssh_moonbit'. A runner checks
# out to D:\a\..., so the generator wrote its KAT header to a path that is not
# there and reported nothing about it. Derived from __file__.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KAT_PATH = os.path.join(ROOT, 'verify_c', '_hostkey_ref_out.txt')


def parse_kat(path):
    """解析 KAT 文本为扁平 dict。

    支持两种行:`k=v ...`(全局键,V1/V2/V3/V6)与
    `name: k=v k=v ...`(名字空间键,V4/V5,存为 name.k)。
    """
    vec = {}
    for line in open(path, encoding='utf-8'):
        line = line.rstrip('\n')
        if not line.strip() or line.lstrip().startswith('#') or (
                line.startswith('[') and line.endswith(']')):
            continue
        eq = line.find('=')
        colon = line.find(':')
        if colon != -1 and (eq == -1 or colon < eq):
            head, rest = line[:colon], line[colon + 1:]
            for tok in rest.strip().split(' '):
                if '=' in tok:
                    k, v = tok.split('=', 1)
                    vec[head + '.' + k] = v
        else:
            for tok in line.strip().split(' '):
                if '=' in tok:
                    k, v = tok.split('=', 1)
                    vec[k] = v
    return vec


def sanity(vec):
    assert vec['pk_hex'] == ref.PK_A.hex(), 'V1 pk 与参考模块不一致'
    assert vec['blob_hex'] == ref.BLOB_A.hex(), 'V1 blob 不一致'
    assert vec['rs_hex'] == ref.SIG_A.hex(), 'V2 rs 不一致'
    assert vec['fp_text'] == ref.fingerprint_text(ref.BLOB_A), 'V1 fp 不一致'
    assert vec['blob_b_hex'] == ref.BLOB_B.hex(), 'V6 blob_b 不一致'
    assert vec['rsa_ok.e_hex'] == ref.E_65537.hex() == '010001'
    assert int(vec['rsa_ok.nbits']) == 2048
    assert vec['rsa_1024.expect'] == 'Parsed'
    assert vec['rsa_short.expect'] == 'RsaModulusTooShort'
    assert vec['rsa_negative.expect'] == 'BigNumNegative'
    assert vec['rsa_overlong.expect'] == 'BigNumTooLarge'
    assert vec['rsa_2049zero.expect'] == 'RsaModulusTooShort'
    # wire 布局锚点:header(4+11) + len(4) + body
    assert len(vec['pk_hex']) == 64
    assert len(vec['blob_hex']) == 102          # 51 字节
    assert len(vec['blob_b_hex']) == 102
    assert vec['blob_b_hex'][38:] != vec['pk_hex'], 'A/B 公钥不应相同'
    assert len(vec['sigblob_hex']) == 166       # 83 字节
    assert len(vec['rs_hex']) == 128            # 64 字节
    assert vec['sig_b_over_main_hex'][38:] == ref.SK_B.sign(ref.MSG_MAIN).hex()


def mbt_template(vec, seed_a, seed_b):
    tpl = r'''///| Loop #11 hostkey 黑盒测试(T1-T9)
///
/// 本文件由 verify_c/gen_hostkey_test.py 机器生成,勿手改。
/// 向量来源:verify_c/_hostkey_ref_out.txt(Python 三盲参考,
/// cryptography 库交叉自检 6/6 通过)。重新生成:
///   python verify_c/gen_hostkey_test.py

///|
/// 严格 16 进制转字节
fn hk_hex(hex : String) -> FixedArray[Byte] {
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = ((hk_digit(hex[i * 2]) * 16 + hk_digit(hex[i * 2 + 1]))
              .reinterpret_as_uint() & 0xFFU)
      .to_byte()
  }
  arr
}

///|
fn hk_digit(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("hk_digit: invalid hex char")
  }
}

///|
fn hk_eq(
  actual : FixedArray[Byte],
  expected : FixedArray[Byte],
  label : String,
) -> Unit {
  if actual.length() != expected.length() {
    abort("\{label}: len \{actual.length()} != \{expected.length()}")
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if actual[i] != expected[i] {
      abort("\{label}: byte \{i} mismatch")
    }
  }
}

///|
fn hk_err_name(e : KeyError) -> String {
  match e {
    InvalidFormat => "InvalidFormat"
    UnsupportedType => "UnsupportedType"
    CertNotAllowed => "CertNotAllowed"
    TypeMismatch => "TypeMismatch"
    TrailingData => "TrailingData"
    BigNumNegative => "BigNumNegative"
    BigNumTooLarge => "BigNumTooLarge"
    RsaModulusTooShort => "RsaModulusTooShort"
    SignatureInvalid => "SignatureInvalid"
    InvalidArgument => "InvalidArgument"
    RsaVerifyUnavailable => "RsaVerifyUnavailable"
  }
}

///|
fn hk_parse_name(res : ParseResult) -> String {
  match res {
    Parsed(Ed25519Key(_)) => "Parsed(ed25519)"
    Parsed(RsaKey(_, _)) => "Parsed(rsa)"
    Rejected(e) => hk_err_name(e)
  }
}

///|
fn hk_verify_name(res : VerifyResult) -> String {
  match res {
    Accepted => "Accepted"
    Rejected(e) => hk_err_name(e)
  }
}

///|
fn hk_check_parse(blob : FixedArray[Byte], want : String, label : String) -> Unit {
  let got = hk_parse_name(HostKey::from_blob(blob))
  if got != want {
    abort("\{label}: got \{got}, want \{want}")
  }
}

///|
fn hk_check_verify(res : VerifyResult, want : String, label : String) -> Unit {
  let got = hk_verify_name(res)
  if got != want {
    abort("\{label}: got \{got}, want \{want}")
  }
}

///|
fn hk_ed25519_key(blob_hex : String, label : String) -> HostKey {
  match HostKey::from_blob(hk_hex(blob_hex)) {
    Parsed(Ed25519Key(pk)) => Ed25519Key(pk)
    other => abort("\{label}: unexpected \{hk_parse_name(other)}")
  }
}

///|
fn hk_u32(v : Int) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(4, b'\x00')
  let u : UInt = v.reinterpret_as_uint()
  a[0] = ((u >> 24) & 0xFFU).to_byte()
  a[1] = ((u >> 16) & 0xFFU).to_byte()
  a[2] = ((u >> 8) & 0xFFU).to_byte()
  a[3] = (u & 0xFFU).to_byte()
  a
}

///|
fn hk_cat(parts : Array[FixedArray[Byte]]) -> FixedArray[Byte] {
  let mut total = 0
  for p in parts {
    total = total + p.length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i = 0; i < p.length(); i = i + 1 {
      out[off + i] = p[i]
    }
    off = off + p.length()
  }
  out
}

///| RFC 4251 string 组包
fn hk_wstr(b : FixedArray[Byte]) -> FixedArray[Byte] {
  hk_cat([hk_u32(b.length()), b])
}

///| ASCII 转 bytes(测试常量专用)
fn hk_ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///| 确定性填充:i & 0xFF
fn hk_seq(n : Int) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = (i & 0xFF).to_byte()
  }
  a
}

///| trim 后大端 bit length(本地副本,镜像包内私有实现)
fn hk_bitlen(b : FixedArray[Byte]) -> Int {
  let n = b.length()
  if n == 0 {
    return 0
  }
  let mut bits = 0
  let mut v = b[0].to_int()
  while v > 0 {
    bits = bits + 1
    v = v >> 1
  }
  (n - 1) * 8 + bits
}

///| T1:密钥 A blob 解析 + SHA256 指纹文本
test "t1_parse_ed25519_key_a" {
  let blob = hk_hex("@BLOB_A@")
  match HostKey::from_blob(blob) {
    Parsed(Ed25519Key(pk)) => hk_eq(pk, hk_hex("@PK_A@"), "t1 pk")
    other => abort("t1: unexpected \{hk_parse_name(other)}")
  }
  let fp = fingerprint_text(blob)
  if fp != "@FP_A@" {
    abort("t1: fingerprint \{fp}")
  }
}

///| T2:Loop #7 ed25519 与 cryptography 的确定性交叉锚点
/// (RFC 8032:同 seed 必得同 pk/签名)
test "t2_loop7_seed_crosscheck" {
  let (pk_a, sk_a) = keypair_from_seed(hk_hex("@SEED_A@"))
  hk_eq(pk_a, hk_hex("@PK_A@"), "t2 pk_a")
  hk_eq(sign(hk_hex("@MSG_MAIN@"), sk_a), hk_hex("@SIG_A@"), "t2 sig_a")
  let (pk_b, sk_b) = keypair_from_seed(hk_hex("@SEED_B@"))
  hk_eq(pk_b, hk_hex("@PK_B@"), "t2 pk_b")
  hk_eq(sign(hk_hex("@MSG_MAIN@"), sk_b), hk_hex("@RS_B_MAIN@"), "t2 sig_b")
}

///| T3:合法签名验证通过
test "t3_verify_accept" {
  let key = hk_ed25519_key("@BLOB_A@", "t3")
  let res = key.verify(hk_hex("@MSG_MAIN@"), hk_hex("@SIGBLOB_A@"))
  hk_check_verify(res, "Accepted", "t3")
  if !(res is Accepted) || !is_verified(res) {
    abort("t3: is_verified inconsistent")
  }
}

///| T4:篡改矩阵 —— 消息翻转/R 块翻转/换签名人,全部 SignatureInvalid
test "t4_tamper_matrix" {
  let key = hk_ed25519_key("@BLOB_A@", "t4")
  let msg = hk_hex("@MSG_MAIN@")
  hk_check_verify(
    key.verify(hk_hex("@MSG_FLIP@"), hk_hex("@SIGBLOB_A@")),
    "SignatureInvalid",
    "t4 msg_flip",
  )
  hk_check_verify(
    key.verify(msg, hk_hex("@SIGBLOB_RSFLIP@")),
    "SignatureInvalid",
    "t4 rs_flip",
  )
  hk_check_verify(
    key.verify(msg, hk_hex("@SIGBLOB_WRONGKEY@")),
    "SignatureInvalid",
    "t4 wrongkey",
  )
}

///| T5:畸形 blob 矩阵(V4 全部 10 例)
test "t5_malformed_blob_matrix" {
  let cases : Array[(String, String)] = [
    // empty:空输入
    ("", "InvalidFormat"),
    // truncated:pk 截短 3 字节
    ("@TRUNCATED@", "InvalidFormat"),
    // nul_in_name:ktype 中部含 NUL(get_cstring 拒)
    ("@NUL_IN_NAME@", "InvalidFormat"),
    // unknown_type:未知名
    ("@UNKNOWN_TYPE@", "UnsupportedType"),
    // cert_name:!allow_cert 路径显式分类
    ("@CERT_NAME@", "CertNotAllowed"),
    // ecdsa_name:仅名字无后续字段
    ("@ECDSA_NAME@", "UnsupportedType"),
    // sk_name:硬件代理名不支持
    ("@SK_NAME@", "UnsupportedType"),
    // pk31:pk 长度 31
    ("@PK31@", "InvalidFormat"),
    // pk33:pk 长度 33
    ("@PK33@", "InvalidFormat"),
    // trailing:良构 blob 后带 2 字节残余
    ("@TRAILING@", "TrailingData"),
  ]
  for i = 0; i < cases.length(); i = i + 1 {
    hk_check_parse(hk_hex(cases[i].0), cases[i].1, "t5[\{i}]")
  }
}

///| T6:RSA 解析矩阵(V5)。rsa_ok 同时锁定 e 先 n 后的读序:
/// 若实现反序,首块 0xC7 前缀会触发 BigNumNegative / 模长检查错位。
test "t6_rsa_parse_matrix" {
  match HostKey::from_blob(hk_hex("@RSA_OK@")) {
    Parsed(RsaKey(e, n)) => {
      hk_eq(e, hk_hex("010001"), "t6 e")
      hk_eq(n, hk_hex("@N2048@"), "t6 n(trim 后)")
      if hk_bitlen(n) != 2048 {
        abort("t6: nbits \{hk_bitlen(n)} != 2048")
      }
    }
    other => abort("t6: unexpected \{hk_parse_name(other)}")
  }
  hk_check_parse(hk_hex("@RSA_1024@"), "Parsed(rsa)", "t6 rsa1024")
  hk_check_parse(hk_hex("@RSA_SHORT@"), "RsaModulusTooShort", "t6 short")
  hk_check_parse(hk_hex("@RSA_NEG@"), "BigNumNegative", "t6 negative")
  hk_check_parse(hk_hex("@RSA_OVERLONG@"), "BigNumTooLarge", "t6 overlong")
  // 2049 字节全零:过长度门,trim 后空 → 0 bits < 1024 → TooShort
  hk_check_parse(hk_hex("@RSA_2049ZERO@"), "RsaModulusTooShort", "t6 zero2049")
}

///| T7:sshkey_verify 前置检查(先于算法分派)
test "t7_verify_preconditions" {
  let key = hk_ed25519_key("@BLOB_A@", "t7")
  let msg = hk_hex("@MSG_MAIN@")
  // siglen == 0
  hk_check_verify(key.verify(msg, hk_hex("")), "InvalidArgument", "t7 empty sig")
  // msg 超上限(>1<<20)
  let big : FixedArray[Byte] = FixedArray::make(MAX_SIGN_DATA_SIZE + 1, b'\x41')
  hk_check_verify(
    key.verify(big, hk_hex("@SIGBLOB_A@")),
    "InvalidArgument",
    "t7 oversized msg",
  )
  // 边界:恰等于上限 → 过前置,进密码学验证必败
  let edge : FixedArray[Byte] = FixedArray::make(MAX_SIGN_DATA_SIZE, b'\x42')
  hk_check_verify(
    key.verify(edge, hk_hex("@SIGBLOB_A@")),
    "SignatureInvalid",
    "t7 boundary msg",
  )
}

///| T8:sig blob 结构错误分类学(ssh-ed25519.c:232-300 精确顺序)
test "t8_sig_structure_errors" {
  let key = hk_ed25519_key("@BLOB_A@", "t8")
  let msg = hk_hex("@MSG_MAIN@")
  // alg ≠ ssh-ed25519(C 先比 alg,后查尾巴)
  let mismatch = hk_cat([hk_wstr(hk_ascii("ssh-rsa")), hk_wstr(hk_seq(64))])
  hk_check_verify(key.verify(msg, mismatch), "TypeMismatch", "t8 alg mismatch")
  // 错 alg 且带尾部残余:alg 判定优先于 trailing —— 顺序锁
  let mismatch_trail = hk_cat([
    hk_wstr(hk_ascii("ssh-rsa")),
    hk_wstr(hk_seq(64)),
    hk_hex("dead"),
  ])
  hk_check_verify(
    key.verify(msg, mismatch_trail),
    "TypeMismatch",
    "t8 alg-before-trailing",
  )
  // rs > 64(无残余,走到长度检查)
  let long65 = hk_cat([hk_wstr(hk_ascii("ssh-ed25519")), hk_wstr(hk_seq(65))])
  hk_check_verify(key.verify(msg, long65), "InvalidFormat", "t8 rs65")
  // rs < 64:C 放行进 open 必败 → 等价捷径直接 SignatureInvalid
  let short63 = hk_cat([hk_wstr(hk_ascii("ssh-ed25519")), hk_wstr(hk_seq(63))])
  hk_check_verify(key.verify(msg, short63), "SignatureInvalid", "t8 rs63")
  // 正确 alg + 尾部残余 → TrailingData(ssh-ed25519.c:252-255)
  let trail = hk_cat([hk_hex("@SIGBLOB_A@"), hk_hex("dead")])
  hk_check_verify(key.verify(msg, trail), "TrailingData", "t8 trailing")
  // RSA 密钥收到形态合法的 sig:密码学验证范围外 → 显式 Unavailable
  let rk = match HostKey::from_blob(hk_hex("@RSA_OK@")) {
    Parsed(k) => k
    other => abort("t8: rsa parse \{hk_parse_name(other)}")
  }
  hk_check_verify(
    rk.verify(msg, hk_hex("@SIGBLOB_A@")),
    "RsaVerifyUnavailable",
    "t8 rsa unavailable",
  )
}

///| T9:密钥 B 往返 + 指纹形态
test "t9_key_b_roundtrip" {
  let blob_b = hk_hex("@BLOB_B@")
  match HostKey::from_blob(blob_b) {
    Parsed(Ed25519Key(pk)) => hk_eq(pk, hk_hex("@PK_B@"), "t9 pk")
    other => abort("t9: unexpected \{hk_parse_name(other)}")
  }
  let fp = fingerprint_text(blob_b)
  if fp != "@FP_B@" {
    abort("t9: fingerprint \{fp}")
  }
  // "SHA256:" + 43 字符 base64 nopad(32 字节摘要恒定)
  if fp.length() != 50 || !fp.has_prefix("SHA256:") {
    abort("t9: fingerprint form")
  }
  let key_b = hk_ed25519_key("@BLOB_B@", "t9")
  hk_check_verify(
    key_b.verify(hk_hex("@MSG_MAIN@"), hk_hex("@SIG_B_OVER_MAIN@")),
    "Accepted",
    "t9 accept",
  )
}
'''
    rep = {
        '@BLOB_A@': vec['blob_hex'],
        '@PK_A@': vec['pk_hex'],
        '@FP_A@': vec['fp_text'],
        '@MSG_MAIN@': vec['msg_hex'],
        '@SIGBLOB_A@': vec['sigblob_hex'],
        '@SIG_A@': vec['rs_hex'],
        '@MSG_FLIP@': vec['msg_flip_hex'],
        '@SIGBLOB_RSFLIP@': vec['rs_flip_hex'],
        '@SIGBLOB_WRONGKEY@': vec['wrongkey_hex'],
        '@TRUNCATED@': vec['truncated.hex'],
        '@NUL_IN_NAME@': vec['nul_in_name.hex'],
        '@UNKNOWN_TYPE@': vec['unknown_type.hex'],
        '@CERT_NAME@': vec['cert_name.hex'],
        '@ECDSA_NAME@': vec['ecdsa_name.hex'],
        '@SK_NAME@': vec['sk_name.hex'],
        '@PK31@': vec['pk31.hex'],
        '@PK33@': vec['pk33.hex'],
        '@TRAILING@': vec['trailing.hex'],
        '@RSA_OK@': vec['rsa_ok.hex'],
        '@N2048@': ref.N_2048.hex(),
        '@RSA_1024@': vec['rsa_1024.hex'],
        '@RSA_SHORT@': vec['rsa_short.hex'],
        '@RSA_NEG@': vec['rsa_negative.hex'],
        '@RSA_OVERLONG@': vec['rsa_overlong.hex'],
        '@RSA_2049ZERO@': vec['rsa_2049zero.hex'],
        '@BLOB_B@': vec['blob_b_hex'],
        '@PK_B@': vec['blob_b_hex'][38:],
        '@FP_B@': vec['fp_b_text'],
        '@SIG_B_OVER_MAIN@': vec['sig_b_over_main_hex'],
        '@RS_B_MAIN@': vec['sig_b_over_main_hex'][38:],
        '@SEED_A@': seed_a,
        '@SEED_B@': seed_b,
    }
    out = tpl
    for k, v in rep.items():
        out = out.replace(k, v)
    leftover = re.findall(r'@\w+@', out)
    assert not leftover, f'unreplaced placeholders: {leftover}'
    return out


def c_header(vec, seed_a, seed_b):
    L = []
    L.append('/* generated by verify_c/gen_hostkey_test.py -- do not edit.')
    L.append(' * vectors: verify_c/_hostkey_ref_out.txt (python triple-blind)')
    L.append(' */')
    L.append('#ifndef HOSTKEY_KAT_H')
    L.append('#define HOSTKEY_KAT_H')
    L.append('')
    scalars = [
        ('HK_SEED_A', seed_a),
        ('HK_SEED_B', seed_b),
        ('HK_PK_A', vec['pk_hex']),
        ('HK_PK_B', vec['blob_b_hex'][38:]),
        ('HK_MSG_MAIN', vec['msg_hex']),
        ('HK_MSG_FLIP', vec['msg_flip_hex']),
        ('HK_SIG_A', vec['rs_hex']),
        ('HK_RS_B_MAIN', vec['sig_b_over_main_hex'][38:]),
        ('HK_SIGBLOB_A', vec['sigblob_hex']),
        ('HK_SIGBLOB_RSFLIP', vec['rs_flip_hex']),
        ('HK_SIGBLOB_WRONGKEY', vec['wrongkey_hex']),
        ('HK_BLOB_A', vec['blob_hex']),
        ('HK_BLOB_B', vec['blob_b_hex']),
        ('HK_SIG_B_OVER_MAIN', vec['sig_b_over_main_hex']),
        ('HK_RSA_OK', vec['rsa_ok.hex']),
        ('HK_FP_A', None),  # 文本特殊处理
        ('HK_FP_B', None),
        ('HK_RSA_E', vec['rsa_ok.e_hex']),
        ('HK_N2048', ref.N_2048.hex()),
    ]
    for name, hx in scalars:
        if name == 'HK_FP_A':
            L.append(f'#define {name} "{vec["fp_text"]}"')
        elif name == 'HK_FP_B':
            L.append(f'#define {name} "{vec["fp_b_text"]}"')
        else:
            L.append(f'#define {name} "{hx}"')
    L.append('')
    L.append('struct hk_blob_case { const char *name; const char *hex; const char *expect; };')
    L.append('static const struct hk_blob_case HK_BLOB_CASES[] = {')
    for nm in ['empty', 'truncated', 'nul_in_name', 'unknown_type', 'cert_name',
               'ecdsa_name', 'sk_name', 'pk31', 'pk33', 'trailing']:
        L.append(f'    {{ "{nm}", "{vec[nm + ".hex"]}", "{vec[nm + ".expect"]}" }},')
    L.append('};')
    L.append('')
    L.append('static const struct hk_blob_case HK_RSA_CASES[] = {')
    for nm in ['rsa_ok', 'rsa_1024', 'rsa_short', 'rsa_negative',
               'rsa_overlong', 'rsa_2049zero']:
        exp = 'Parsed' if nm == 'rsa_ok' else vec[nm + '.expect']
        L.append(f'    {{ "{nm}", "{vec[nm + ".hex"]}", "{exp}" }},')
    L.append('};')
    L.append('')
    L.append('#endif /* HOSTKEY_KAT_H */')
    return '\n'.join(L) + '\n'


def main():
    vec = parse_kat(KAT_PATH)
    sanity(vec)
    seed_a = ref.SEED_A.hex()
    seed_b = ref.SEED_B.hex()

    mbt = mbt_template(vec, seed_a, seed_b)
    mbt_path = os.path.join(ROOT, 'src', 'hostkey', 'hostkey_test.mbt')
    with open(mbt_path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(mbt)

    hdr = c_header(vec, seed_a, seed_b)
    hdr_path = os.path.join(ROOT, 'verify_c', '_hostkey_kat.h')
    with open(hdr_path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(hdr)

    print(f'written: {mbt_path} ({len(mbt)} bytes)')
    print(f'written: {hdr_path} ({len(hdr)} bytes)')


if __name__ == '__main__':
    main()
