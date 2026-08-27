///| KEX c25519 黑盒测试(公开 API + 三盲期望值)

///| 期望值由 verify_c/kex_c25519_python_ref.py 生成(cryptography 交叉自检)

///|
/// 严格 16 进制字符串转 FixedArray[Byte](非法字符 abort)
fn hex_to_bytes(hex : String) -> FixedArray[Byte] {
  if hex.length() % 2 != 0 {
    abort("hex_to_bytes: odd length")
  }
  let n = hex.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hxd(hex[i * 2])
    let lo = hxd(hex[i * 2 + 1])
    arr[i] = ((hi * 16 + lo).reinterpret_as_uint() & 0xFFU).to_byte()
  }
  arr
}

///|
fn hxd(c : UInt16) -> Int {
  let code : Int = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else if code >= 65 && code <= 70 {
    code - 55
  } else {
    abort("hxd: invalid character")
  }
}

///|
fn assert_eq_bytes(
  actual : FixedArray[Byte],
  expected : FixedArray[Byte],
  label : String,
) -> Unit {
  if actual.length() != expected.length() {
    abort("\{label}: length \{actual.length()} != \{expected.length()}")
  }
  for i = 0; i < expected.length(); i = i + 1 {
    if actual[i] != expected[i] {
      abort("\{label}: byte \{i} mismatch")
    }
  }
}

///|
/// RFC 7748 §6.1 标量对
fn alice_sk() -> FixedArray[Byte] {
  hex_to_bytes(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
  )
}

///|
fn alice_pk() -> FixedArray[Byte] {
  hex_to_bytes(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )
}

///|
fn bob_pk() -> FixedArray[Byte] {
  hex_to_bytes(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
  )
}

///|
/// Section B 端到端输入(Python 参考 _kex_ref_out.txt)
fn b_inputs() -> ExchangeInputs {
  ExchangeInputs::make(
    hex_to_bytes("5353482d322e302d4d6f6f6e426974506f72745f312e300d0a"),
    hex_to_bytes("5353482d322e302d4f70656e5353485f31302e300d0a"),
    hex_to_bytes(
      "00000004637572766532353531392d736861323536000000157373682d656432353531392c7373682d7273610000004163686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733132382d637472",
    ),
    hex_to_bytes(
      "00000004637572766532353531392d736861323536000000157373682d656432353531392c7373682d7273610000004163686163686132302d706f6c7931333035406f70656e7373682e636f6d2c6165733235362d67636d406f70656e7373682e636f6d",
    ),
  )
}

// ================= X25519 与共享密钥 =================

///|
test "keygen_rfc7748_alice" {
  assert_eq_bytes(c25519_keygen(alice_sk()), alice_pk(), "keygen alice")
}

///|
test "shared_key_raw_agreement" {
  // Alice(sk) × Bob(pk) == Bob(sk) × Alice(pk)(对称性)
  let bob_sk = hex_to_bytes(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
  )
  let ss1 = c25519_shared_key_raw(alice_sk(), bob_pk()).unwrap()
  let ss2 = c25519_shared_key_raw(bob_sk, alice_pk()).unwrap()
  assert_eq_bytes(
    ss1,
    hex_to_bytes(
      "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ),
    "rfc7748 shared secret",
  )
  assert_eq_bytes(ss2, ss1, "agreement symmetry")
}

///|
test "shared_key_mpint_both_branches" {
  // 无前置分支(首字节 0x4a)
  let m1 = c25519_shared_key_mpint(alice_sk(), bob_pk()).unwrap()
  assert_eq_bytes(
    m1,
    hex_to_bytes(
      "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
    ),
    "mpint no-prepend",
  )
  // 前置分支(A2.sk_bob × alice_pk → ss 首字节 0xb7)
  let sk_bob2 = hex_to_bytes(
    "fdab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e06b",
  )
  let m2 = c25519_shared_key_mpint(sk_bob2, alice_pk()).unwrap()
  assert_eq_bytes(
    m2,
    hex_to_bytes(
      "0000002100b7157392fe559875efb25f56dc0258aa44e6cfa47be51df654884d61281c7815",
    ),
    "mpint prepend",
  )
}

///|
test "shared_key_zero_rejected" {
  // 全零公钥 → 共享密钥全零 → 拒绝(kexc25519.c 的 KEY_INVALID_EC_VALUE 路径)
  let zero : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  assert_eq(c25519_shared_key_raw(alice_sk(), zero), None)
  assert_eq(c25519_shared_key_mpint(alice_sk(), zero), None)
}

// ================= 交换哈希与 KDF =================

///|
test "kex_gen_hash_e2e" {
  let ks_blob = hex_to_bytes(
    "0000000b7373682d656432353531390000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  )
  let ss_mpint = hex_to_bytes(
    "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  let h = kex_gen_hash(b_inputs(), ks_blob, alice_pk(), bob_pk(), ss_mpint)
  assert_eq_bytes(
    h,
    hex_to_bytes(
      "2cbabe0febe8e8901baa07bc2a1bfae779932a12e92251c797b42f8785222d5f",
    ),
    "exchange hash H",
  )
}

///|
test "kex_gen_hash_field_sensitivity" {
  // I_C 差一比特 → H 必须不同(防止漏掉任何输入字段)
  let ks_blob = hex_to_bytes(
    "0000000b7373682d656432353531390000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
  )
  let ss_mpint = hex_to_bytes(
    "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  let ic = b_inputs().client_kexinit
  let last = ic.length() - 1
  ic[last] = ic[last] ^ b'\x01'
  let inputs_mut = ExchangeInputs::make(
    b_inputs().client_version,
    b_inputs().server_version,
    ic,
    b_inputs().server_kexinit,
  )
  let h1 = kex_gen_hash(b_inputs(), ks_blob, alice_pk(), bob_pk(), ss_mpint)
  let h2 = kex_gen_hash(inputs_mut, ks_blob, alice_pk(), bob_pk(), ss_mpint)
  let mut same = true
  for i = 0; i < 32; i = i + 1 {
    if h1[i] != h2[i] {
      same = false
    }
  }
  assert_eq(same, false)
}

///|
test "derive_keys_all_six" {
  let h = hex_to_bytes(
    "2cbabe0febe8e8901baa07bc2a1bfae779932a12e92251c797b42f8785222d5f",
  )
  let ss_mpint = hex_to_bytes(
    "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  let keys = derive_keys(h, ss_mpint, 64)
  assert_eq_bytes(keys.session_id, h, "session_id == first H")
  assert_eq_bytes(
    keys.iv_ctos,
    hex_to_bytes(
      "e3b3ec44845eabe125809002d6d9c97695aa2a0727d326265f57f8ebc448e9351e83ec95ce3aba9d57db03116fcc8466c9de12469b4a63f6dab7947f1e8f210e",
    ),
    "iv_ctos",
  )
  assert_eq_bytes(
    keys.iv_stoc,
    hex_to_bytes(
      "a0900763971dbed63c8409e446b774b78ed422ac128c6b4f4d83b860376ee9003bb638f0a9e7bfcdbe29ef581ca782c5e0d7edb4037ed0cd7c2192017ac5c473",
    ),
    "iv_stoc",
  )
  assert_eq_bytes(
    keys.enc_key_ctos,
    hex_to_bytes(
      "306e3f27a5d2601f9e5e8b25f5430da89710adfcf60231030acf5649b4133eb48fb59a7cec1e5013fcdf709008d75f0adfd3fde907d90702568b12462c0684ce",
    ),
    "enc_ctos",
  )
  assert_eq_bytes(
    keys.enc_key_stoc,
    hex_to_bytes(
      "2748b2185860c78fa428ff1153bb3c5d04b661132674f109e19a6d7a569904b01927634b0c9ec1d271e3dffbbe106423357cc69ea4168a3da1fe4773c82e209a",
    ),
    "enc_stoc",
  )
  assert_eq_bytes(
    keys.mac_key_ctos,
    hex_to_bytes(
      "b958e89cdb4089b2267e4989f35f949686264d996b3688052d1ce71be052a6736cd57fe5a0b6a6249ae1d7783a1d5ad8c4310a1d996bb5298ef66161f2805909",
    ),
    "mac_ctos",
  )
  assert_eq_bytes(
    keys.mac_key_stoc,
    hex_to_bytes(
      "8b3e553e26346f53b4fde0fe71f7df4a02857eaca29634d04d3d40a24c3df714d3ecf1646dea250346f1d2ed53e6d4bbb735d856f32016ddd28756ccc226825d",
    ),
    "mac_stoc",
  )
}

///|
test "derive_single_chain_expansion" {
  // we_need=33 触发第二块扩展(Kn 公式无 session_id)
  let h = hex_to_bytes(
    "2cbabe0febe8e8901baa07bc2a1bfae779932a12e92251c797b42f8785222d5f",
  )
  let ss_mpint = hex_to_bytes(
    "000000204a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
  // 前 32 字节必须与 we_need=32 时完全一致(前缀稳定性)
  let k32 = derive_single(b'A', 32, h, ss_mpint, h)
  let k33 = derive_single(b'A', 33, h, ss_mpint, h)
  for i = 0; i < 32; i = i + 1 {
    assert_eq(k33[i], k32[i])
  }
  assert_eq(k33.length(), 33)
}

// ================= REPLY 解析与签名形态 =================

///|
test "parse_reply_valid" {
  let reply = hex_to_bytes(
    "000000330000000b7373682d656432353531390000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000020de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f000000530000000b7373682d6564323535313900000040bdd8ae79ed073b1ec000b840f60792c85410c48070d3b7f4f90b8bd9971614da953fa569e5b05626bdca280e1775d9085ee354dbd927d7e876fc1fc5939eae0f",
  )
  match parse_reply(reply) {
    Some(r) => {
      assert_eq_bytes(
        r.hostkey_blob,
        hex_to_bytes(
          "0000000b7373682d656432353531390000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8",
        ),
        "K_S",
      )
      assert_eq_bytes(r.server_pub, bob_pk(), "Q_S == f")
      assert_eq(r.sig_blob.length(), 83) // 11+4 + 64+4
    }
    None => abort("parse_reply should succeed")
  }
}

///|
test "parse_reply_truncated_and_trailing" {
  // 截断:去掉最后两个字节
  let reply = hex_to_bytes(
    "000000330000000b7373682d656432353531390000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b800000020de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f000000530000000b7373682d6564323535313900000040bdd8ae79ed073b1ec000b840f60792c85410c48070d3b7f4f90b8bd9971614da953fa569e5b05626bdca280e1775d9085ee354dbd927d7e876fc1fc5939eae0f",
  )
  let short : FixedArray[Byte] = FixedArray::make(reply.length() - 2, b'\x00')
  for i = 0; i < short.length(); i = i + 1 {
    short[i] = reply[i]
  }
  assert_eq(parse_reply(short) is None, true)
  // 尾随垃圾:追加一个字节
  let trailing : FixedArray[Byte] = FixedArray::make(
    reply.length() + 1,
    b'\x00',
  )
  for i = 0; i < reply.length(); i = i + 1 {
    trailing[i] = reply[i]
  }
  trailing[reply.length()] = b'\xff'
  assert_eq(parse_reply(trailing) is None, true)
  // Q_S 非 32 字节(C: sshbuf_len(server_blob)!=CURVE25519_SIZE → SIGNATURE_INVALID)
  let wrong_len_blob = hex_to_bytes("00000002aabb")
  // 构造 string(KS=empty) ‖ string(QS=aabb) ‖ string(sig=empty)
  let crafted = KxBuf::new()
  crafted.put_string(FixedArray::make(0, b'\x00'))
  crafted.put_string(wrong_len_blob)
  crafted.put_string(FixedArray::make(0, b'\x00'))
  assert_eq(parse_reply(crafted.to_bytes()) is None, true)
}

///|
test "parse_sig_ed25519" {
  let sig_blob = hex_to_bytes(
    "0000000b7373682d6564323535313900000040bdd8ae79ed073b1ec000b840f60792c85410c48070d3b7f4f90b8bd9971614da953fa569e5b05626bdca280e1775d9085ee354dbd927d7e876fc1fc5939eae0f",
  )
  match parse_sig(sig_blob) {
    Some(s) => {
      assert_eq(sig_is_ed25519(s), true)
      assert_eq_bytes(
        s.rs,
        hex_to_bytes(
          "bdd8ae79ed073b1ec000b840f60792c85410c48070d3b7f4f90b8bd9971614da953fa569e5b05626bdca280e1775d9085ee354dbd927d7e876fc1fc5939eae0f",
        ),
        "rs bytes",
      )
    }
    None => abort("parse_sig should succeed")
  }
}

///|
test "parse_sig_bad_forms" {
  let sig_blob = hex_to_bytes(
    "0000000b7373682d6564323535313900000040bdd8ae79ed073b1ec000b840f60792c85410c48070d3b7f4f90b8bd9971614da953fa569e5b05626bdca280e1775d9085ee354dbd927d7e876fc1fc5939eae0f",
  )
  // rs 截断为 63B(python C.bad_reply 内嵌的坏签名)
  let bad_rs_blob = hex_to_bytes(
    "0000000b7373682d656432353531390000003fbdd8ae79ed073b1ec000b840f60792c85410c48070d3b7f4f90b8bd9971614da953fa569e5b05626bdca280e1775d9085ee354dbd927d7e876fc1fc5939eae",
  )
  match parse_sig(bad_rs_blob) {
    Some(_) => abort("63-byte rs must be rejected")
    None => assert_eq(true, true)
  }
  // 错误算法名
  let rsa_blob = KxBuf::new()
  rsa_blob.put_string(hex_to_bytes("7373682d727361")) // "ssh-rsa"
  rsa_blob.put_string(hex_to_bytes("010203"))
  match parse_sig(rsa_blob.to_bytes()) {
    Some(s) => {
      // 形态合法(rs 3B? 不——非 ed25519 要求 64B,应被拒)
      let _ = s
      abort("non-64B rs with other alg must be rejected by shape check")
    }
    None => assert_eq(true, true)
  }
  let _ = sig_blob
}
