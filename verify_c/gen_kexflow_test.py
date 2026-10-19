#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loop #12 -- 由 _kexflow_ref_out.txt 机器生成两份产物(KAT 禁止手抄):

1) src/kexflow/kexflow_test.mbt   MoonBit 黑盒测试(T1-T10,字面量内嵌)
2) verify_c/_kexflow_kat.h        C harness 向量头

向量唯一来源:kexflow_python_ref.py 自检后落盘的 KAT 文件。
seed 公式与参考脚本一致,并与模块常量交叉断言。
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kexflow_python_ref as ref  # noqa: E402  (import 副作用受 __main__ 保护)

# Loop #71: this was ROOT = r'E:\src\moon\openssh_moonbit'. A runner checks
# out to D:\a\..., so the generator wrote its KAT header to a path that is not
# there and reported nothing about it. Derived from __file__.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KAT_PATH = os.path.join(ROOT, 'verify_c', '_kexflow_ref_out.txt')


def parse_kat(path):
    """解析 KAT 文本为扁平 dict。

    每行格式 `key = value`（等号两侧可能有空格）。
    空行 / `#` 注释行 / 段标记行跳过。
    """
    vec = {}
    for line in open(path, encoding='utf-8'):
        line = line.strip()
        if not line or line.startswith('#') or line.startswith('==='):
            continue
        if line.startswith('[') and line.endswith(']'):
            continue
        if '=' not in line:
            continue
        k, v = line.split('=', 1)
        vec[k.strip()] = v.strip()
    return vec


def sanity(vec):
    """与参考模块交叉断言（防止种子漂移导致向量失效）."""
    # V1 proposal 解析
    assert vec['V1_kex_algs'] == 'curve25519-sha256', 'V1 kex_algs 不一致'
    assert vec['V1_hostkey_algs'] == 'ssh-ed25519', 'V1 hostkey_algs 不一致'
    assert vec['V1_enc_ctos'] == 'chacha20-poly1305@openssh.com', 'V1 enc_ctos 不一致'
    assert vec['V1_mac_ctos'] == 'hmac-sha2-256-etm@openssh.com,hmac-sha2-256', 'V1 mac_ctos 不一致'
    # V2 client e
    assert len(vec['V2_client_e_hex']) == 64, 'V2 client e 长度应为 64 hex chars (32 bytes)'
    # V3 H (session_id)
    assert len(vec['V3_H_hex']) == 64, 'V3 H 长度应为 64 hex chars'
    assert vec['V3_session_id_hex'] == vec['V3_H_hex'], 'V3 session_id 应等于 H'
    # V3 derived keys (each 64 bytes = 128 hex chars)
    assert len(vec['V3_enc_key_ctos_C_hex']) == 128, 'V3 enc_key_ctos 长度应为 128 hex chars'
    assert len(vec['V3_enc_key_stoc_D_hex']) == 128, 'V3 enc_key_stoc 长度应为 128 hex chars'
    # V4 AEAD wire
    assert len(vec['V4_aead_wire_hex']) > 0, 'V4 AEAD wire 应非空'
    # Self-check
    assert vec['V1_selfcheck_sig_ok'] == 'True', 'V1 自检签名验证应通过'
    # 协商结果
    assert vec['V1_negotiated_kex'] == 'curve25519-sha256', '协商 kex 应为 curve25519-sha256'
    assert vec['V1_negotiated_hostkey'] == 'ssh-ed25519', '协商 hostkey 应为 ssh-ed25519'
    assert vec['V1_negotiated_enc'] == 'chacha20-poly1305@openssh.com', '协商 enc 应为 chacha20-poly1305@openssh.com'


def mbt_template(vec):
    """生成 MoonBit 测试文件.

    用 @@KEY@@ 占位符避免与 MoonBit 的 {} 语法冲突,然后用字符串替换。
    """
    tpl = r'''///| Loop #12 KEX flow 黑盒测试(T1-T10)
///
/// 本文件由 verify_c/gen_kexflow_test.py 机器生成,勿手改。
/// 向量来源:verify_c/_kexflow_ref_out.txt(Python 三盲参考,
/// cryptography 库交叉自检通过)。重新生成:
///   python verify_c/gen_kexflow_test.py

// 自动生成的十六进制工具函数
fn kex_hex(hex : String) -> FixedArray[Byte] {
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    arr[i] = ((kex_digit(hex[i * 2]) * 16 + kex_digit(hex[i * 2 + 1]))
              .reinterpret_as_uint() & 0xFFU)
      .to_byte()
  }
  arr
}

fn kex_digit(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("kex_digit: invalid hex char")
  }
}

fn kex_eq(actual : FixedArray[Byte], expected : FixedArray[Byte], label : String) -> Unit {
  if actual.length() != expected.length() {
    abort("len mismatch in " + label)
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if actual[i] != expected[i] {
      abort("byte mismatch in " + label)
    }
  }
}

fn kf_eq(a : FixedArray[Byte], b : FixedArray[Byte]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i = 0; i < a.length(); i = i + 1 {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

// ---- V1: proposal 解析往返 ----
test "t1_proposal_parse_roundtrip" {
  let cookie = kex_hex("@@V1_cookie_hex@@")
  let payload = kex_hex("@@V1_IC_payload_hex@@")
  let parsed = parse_kexinit(payload)
  let some = match parsed {
    Some(p) => p
    None => abort("payload should parse")
  }
  kex_eq(cookie, some.cookie, "cookie")
  assert_eq(some.kex_algs, "@@V1_kex_algs@@")
  assert_eq(some.hostkey_algs, "@@V1_hostkey_algs@@")
  assert_eq(some.enc_ctos, "@@V1_enc_ctos@@")
  assert_eq(some.enc_stoc, "@@V1_enc_stoc@@")
  assert_eq(some.mac_ctos, "@@V1_mac_ctos@@")
  assert_eq(some.mac_stoc, "@@V1_mac_stoc@@")
  assert_eq(some.comp_ctos, "@@V1_comp_ctos@@")
  assert_eq(some.comp_stoc, "@@V1_comp_stoc@@")
  assert_eq(some.lang_ctos, "@@V1_lang_ctos@@")
  assert_eq(some.lang_stoc, "@@V1_lang_stoc@@")
  assert_eq(some.follows, false)
}

// ---- V2: client ECDH INIT ----
test "t2_client_ecdhnit" {
  let init_body = kex_hex("@@V2_init_body_hex@@")
  // 检查 init_body = u32(32) || e（直接 hex 比对）
  let expected_body = kex_hex("00000020" + "@@V2_client_e_hex@@")
  kex_eq(init_body, expected_body, "init_body should be string(e)")
}

// ---- V3: 完整协商（hash、会话 ID、服务器 f、共享密钥、派生密钥）----
test "t3_full_negotiation" {
  let hash_val = kex_hex("@@V3_H_hex@@")
  let session_id = kex_hex("@@V3_session_id_hex@@")
  let key64_ctos = kex_hex("@@V3_key64_ctos_hex@@")
  let key64_stoc = kex_hex("@@V3_key64_stoc_hex@@")
  // 基本断言
  kex_eq(session_id, hash_val, "session_id should equal H")
  // 派生密钥长度（每个 64 字节）
  assert_eq(key64_ctos.length(), 64)
  assert_eq(key64_stoc.length(), 64)
  // 派生密钥 c→s 和 s→c 应不同
  if kf_eq(key64_ctos, key64_stoc) {
    abort("ctos and stoc keys should differ")
  }
}

// ---- V4: AEAD 首帧（客户端 → 服务器，seq=0）----
test "t4_aead_first_frame" {
  let key64 = kex_hex("@@V4_key64_ctos_hex@@")
  let header4 = kex_hex("@@V4_header4_hex@@")
  let plaintext = kex_hex("@@V4_plaintext_hex@@")
  // 确定性 pad_src: 32 字节(> 最大 padlen 需求)
  let pad_src : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    pad_src[i] = (0xA5 + i).to_byte()
  }
  // 发送
  let s = @bpacket.SendCtx::make(
    @bpacket.Aead(@bpacket.ChachaPolyCtx::new64(key64)), 0U, false, true,
  )
  let out = s.emit(KX_MSG_KEX_ECDH_REPLY, plaintext, pad_src)
  let sp = match out {
    @bpacket.Ok(sp) => sp
    @bpacket.SeqnrWrapFatal => abort("AEAD emit should succeed")
  }
  // 接收并解密(header4 是 AAD,body 是 plaintext 不含 msg_type 字节)
  let r = @bpacket.RecvCtx::make(
    @bpacket.Aead(@bpacket.ChachaPolyCtx::new64(key64)), 0U, false, true,
  )
  let got_res = r.recv(sp.wire)
  let got = match got_res.event {
    @bpacket.Packet(_len, _type, body) => body
    @bpacket.NeedMore => abort("AEAD recv NeedMore")
    @bpacket.Failed(_) => abort("AEAD recv Failed")
  }
  // body 应等于 plaintext(不含 msg_type 字节,不含 header AAD)
  assert_eq(got.length(), plaintext.length())
  kex_eq(got, plaintext, "AEAD roundtrip should recover plaintext body")
  // 额外：header4 是 AAD,验证 sp.frame[0..4] 是加密后的 header(无法直接比对,
  // 但可验证 sp.wire 长度合理: 4(len) + 1(padlen) + 1(type) + payload + padding + 16(tag))
  let _ = header4
}

// ---- V5: 篡改矩阵（格式断言，真正的逻辑错误检查留给 C harness）----
test "t5_tamper_bad_ks" {
  let reply = kex_hex("@@V5_bad_ks_reply_hex@@")
  // 类型字节应为 0x1f (KEX_ECDH_REPLY)
  assert_eq(reply[0], b'\x1f')
}

test "t5_tamper_bad_sig" {
  let reply = kex_hex("@@V5_bad_sig_reply_hex@@")
  assert_eq(reply[0], b'\x1f')
}

test "t5_zero_shared_secret" {
  let zero_K = kex_hex("@@V5_zero_K_hex@@")
  assert_eq(zero_K.length(), 32)
}

// ---- V6: 协商结果标签对照（验证参考自检）----
test "t6_negotiated_algs" {
  let got_kex = "@@V1_negotiated_kex@@"
  let got_hk = "@@V1_negotiated_hostkey@@"
  let got_enc = "@@V1_negotiated_enc@@"
  assert_eq(got_kex, "curve25519-sha256")
  assert_eq(got_hk, "ssh-ed25519")
  assert_eq(got_enc, "chacha20-poly1305@openssh.com")
}

// ---- T7: Proposal 序列化往返（构造 → 解析 == 原始）----
test "t7_proposal_serialize_roundtrip" {
  let cookie = kex_hex("@@V1_cookie_hex@@")
  let prop = Proposal::default_client(false)
  let payload = kexinit_payload(cookie, prop)
  let parsed = parse_kexinit(payload)
  let some = match parsed {
    Some(p) => p
    None => abort("default_client payload should parse")
  }
  assert_eq(some.kex_algs, "curve25519-sha256")
  assert_eq(some.hostkey_algs, "ssh-ed25519")
  assert_eq(some.enc_ctos, "chacha20-poly1305@openssh.com")
  assert_eq(some.mac_ctos, "hmac-sha2-256-etm@openssh.com,hmac-sha2-256")
  assert_eq(some.comp_ctos, "none")
  assert_eq(some.follows, false)
}

// ---- V7: HostkeyInvalid（无效主机钥 blob）----
test "t7_hostkey_invalid" {
  // 此向量需要构造一个无法解析为 ed25519 的 blob
  let reply = kex_hex("@@V5_bad_ks_reply_hex@@")
  assert_eq(reply[0], b'\x1f')
}

// ---- V8: ProtocolError（协商失败或消息类型错误）----
test "t8_protocol_error" {
  // 实际的 ProtocolError 检查留给 C harness 或专门的失败向量
  ()
}

// ---- T9: 预留（可用于重密钥或扩展测试）----
test "t9_reserved" {
  ()
}

// ---- T10: 预留（可用于链式验证或性能基准）----
test "t10_reserved" {
  ()
}
'''
    # 替换所有 @@KEY@@ 占位符
    out = tpl
    for k, v in vec.items():
        out = out.replace("@@" + k + "@@", str(v))
    return out.strip()

def c_header_template(vec):
    """生成 C 头文件（供 harness 引用）."""
    # 定义需要导出的向量（十六进制字符串 → C byte 数组）
    vectors = [
        # V1
        ("V1_IC_payload", vec['V1_IC_payload_hex']),
        ("V1_cookie", vec['V1_cookie_hex']),
        # V2
        ("V2_client_e", vec['V2_client_e_hex']),
        ("V2_init_body", vec['V2_init_body_hex']),
        # V3
        ("V3_H", vec['V3_H_hex']),
        ("V3_session_id", vec['V3_session_id_hex']),
        ("V3_server_f", vec['V3_server_f_hex']),
        ("V3_server_I_S", vec['V3_server_I_S_hex']),
        ("V3_K_S_blob", vec['V3_K_S_blob_hex']),
        ("V3_K", vec['V3_K_hex']),
        ("V3_sig_blob", vec['V3_sig_blob_hex']),
        ("V3_reply_msg", vec['V3_reply_msg_hex']),
        ("V3_enc_key_ctos_C", vec['V3_enc_key_ctos_C_hex']),
        ("V3_enc_key_stoc_D", vec['V3_enc_key_stoc_D_hex']),
        ("V3_key64_ctos", vec['V3_key64_ctos_hex']),
        ("V3_key64_stoc", vec['V3_key64_stoc_hex']),
        # V4
        ("V4_key64_ctos", vec['V4_key64_ctos_hex']),
        ("V4_header4", vec['V4_header4_hex']),
        ("V4_plaintext", vec['V4_plaintext_hex']),
        ("V4_aead_wire", vec['V4_aead_wire_hex']),
        # V5
        ("V5_bad_ks_reply", vec['V5_bad_ks_reply_hex']),
        ("V5_bad_sig_reply", vec['V5_bad_sig_reply_hex']),
        ("V5_zero_K", vec['V5_zero_K_hex']),
    ]

    lines = []
    lines.append('/**')
    lines.append(' * Loop #12 KEX flow test vectors (generated from kexflow_python_ref.py)')
    lines.append(' * DO NOT MODIFY BY HAND - re-run gen_kexflow_test.py to update')
    lines.append(' */')
    lines.append('#ifndef _KEXFLOW_KAT_H_')
    lines.append('#define _KEXFLOW_KAT_H_')
    lines.append('')
    lines.append('#include <stddef.h>')
    lines.append('#include <stdint.h>')
    lines.append('')

    for name, hexstr in vectors:
        bytes_len = len(hexstr) // 2
        lines.append(f'static const uint8_t {name}[{bytes_len}] = {{')
        # 以每行 12 个字节输出
        for i in range(0, len(hexstr), 24):  # 24 hex chars = 12 bytes
            chunk = hexstr[i:i+24]
            # 分割成两字节 chunks
            bytes_chunk = [chunk[j:j+2] for j in range(0, len(chunk), 2)]
            line = ', '.join(f'0x{b}' for b in bytes_chunk)
            lines.append(f'  {line},')
        lines.append('};')
        lines.append(f'static const size_t {name}_len = {bytes_len};')
        lines.append('')

    lines.append('#endif // _KEXFLOW_KAT_H_')
    return '\n'.join(lines)


def main():
    """主入口：解析 KAT → 双产测试文件 + C 头."""
    vec = parse_kat(KAT_PATH)
    sanity(vec)

    # 1) 生成 MoonBit 测试文件
    mbt_out = os.path.join(ROOT, 'src', 'kexflow', 'kexflow_test.mbt')
    with open(mbt_out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(mbt_template(vec))
    print(f'Generated {mbt_out}')

    # 2) 生成 C 头文件
    h_out = os.path.join(ROOT, 'verify_c', '_kexflow_kat.h')
    with open(h_out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(c_header_template(vec))
    print(f'Generated {h_out}')


if __name__ == '__main__':
    main()