///| Loop #11 hostkey 黑盒测试(T1-T9)
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
    arr[i] = ((hk_digit(hex[i * 2]) * 16 + hk_digit(hex[i * 2 + 1])).reinterpret_as_uint() &
    0xFFU).to_byte()
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
    KeyBitsMismatch => "KeyBitsMismatch"
    SignatureInvalid => "SignatureInvalid"
    InvalidArgument => "InvalidArgument"
    EcCurveMismatch => "EcCurveMismatch"
    KeyInvalidEcValue => "KeyInvalidEcValue"
    RsaVerifyUnavailable => "RsaVerifyUnavailable"
  }
}

///|
fn hk_parse_name(res : ParseResult) -> String {
  match res {
    Parsed(Ed25519Key(_)) => "Parsed(ed25519)"
    Parsed(RsaKey(_, _)) => "Parsed(rsa)"
    Parsed(EcdsaKey(bits, _)) => if bits == 256 {
      "Parsed(ecdsa-p256)"
    } else {
      "Parsed(ecdsa-p384)"
    }
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
fn hk_check_parse(
  blob : FixedArray[Byte],
  want : String,
  label : String,
) -> Unit {
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

///|
/// RFC 4251 string 组包
fn hk_wstr(b : FixedArray[Byte]) -> FixedArray[Byte] {
  hk_cat([hk_u32(b.length()), b])
}

///|
/// ASCII 转 bytes(测试常量专用)
fn hk_ascii(s : String) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    a[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  a
}

///|
/// 确定性填充:i & 0xFF
fn hk_seq(n : Int) -> FixedArray[Byte] {
  let a : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    a[i] = (i & 0xFF).to_byte()
  }
  a
}

///|
/// trim 后大端 bit length(本地副本,镜像包内私有实现)
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

///|
/// T1:密钥 A blob 解析 + SHA256 指纹文本
test "t1_parse_ed25519_key_a" {
  let blob = hk_hex(
    "0000000b7373682d6564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
  )
  match HostKey::from_blob(blob) {
    Parsed(Ed25519Key(pk)) =>
      hk_eq(
        pk,
        hk_hex(
          "ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
        ),
        "t1 pk",
      )
    other => abort("t1: unexpected \{hk_parse_name(other)}")
  }
  let fp = fingerprint_text(blob)
  if fp != "SHA256:JX5PbRhflNv0JVcf8P8IVbqwcOZH9GOVafQPvzd6fq4" {
    abort("t1: fingerprint \{fp}")
  }
}

///|
/// T2:Loop #7 ed25519 与 cryptography 的确定性交叉锚点
/// (RFC 8032:同 seed 必得同 pk/签名)
test "t2_loop7_seed_crosscheck" {
  let (pk_a, sk_a) = keypair_from_seed(
    hk_hex("112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f20"),
  )
  hk_eq(
    pk_a,
    hk_hex("ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d"),
    "t2 pk_a",
  )
  hk_eq(
    sign(
      hk_hex(
        "4d6f6f6e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
      ),
      sk_a,
    ),
    hk_hex(
      "6e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0624ea4b47cfde201070628fbb0f",
    ),
    "t2 sig_a",
  )
  let (pk_b, sk_b) = keypair_from_seed(
    hk_hex("a7aaadb0b3b6b9bcbfc2c5c8cbced1d4d7dadde0e3e6e9eceff2f5f8fbfe0104"),
  )
  hk_eq(
    pk_b,
    hk_hex("27ca11763a2d91b23f6426d83031e6bc51eed538566c90cbf82fe3f9e2525230"),
    "t2 pk_b",
  )
  hk_eq(
    sign(
      hk_hex(
        "4d6f6f6e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
      ),
      sk_b,
    ),
    hk_hex(
      "47bc142f44f7f757717ed9ef3663a4ec98168cab7337f8853aac9e9447a61551c219a430964416dcb96e54247d5c8f4c31708d9428d0b8b5d319e45412f5cf0a",
    ),
    "t2 sig_b",
  )
}

///|
/// T3:合法签名验证通过
test "t3_verify_accept" {
  let key = hk_ed25519_key(
    "0000000b7373682d6564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
    "t3",
  )
  let res = key.verify(
    hk_hex(
      "4d6f6f6e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
    ),
    hk_hex(
      "0000000b7373682d65643235353139000000406e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0624ea4b47cfde201070628fbb0f",
    ),
  )
  hk_check_verify(res, "Accepted", "t3")
  if !(res is Accepted) || !is_verified(res) {
    abort("t3: is_verified inconsistent")
  }
}

///|
/// T4:篡改矩阵 —— 消息翻转/R 块翻转/换签名人,全部 SignatureInvalid
test "t4_tamper_matrix" {
  let key = hk_ed25519_key(
    "0000000b7373682d6564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
    "t4",
  )
  let msg = hk_hex(
    "4d6f6f6e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
  )
  hk_check_verify(
    key.verify(
      hk_hex(
        "4d6f6f2e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
      ),
      hk_hex(
        "0000000b7373682d65643235353139000000406e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0624ea4b47cfde201070628fbb0f",
      ),
    ),
    "SignatureInvalid",
    "t4 msg_flip",
  )
  hk_check_verify(
    key.verify(
      msg,
      hk_hex(
        "0000000b7373682d65643235353139000000406e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0724ea4b47cfde201070628fbb0f",
      ),
    ),
    "SignatureInvalid",
    "t4 rs_flip",
  )
  hk_check_verify(
    key.verify(
      msg,
      hk_hex(
        "0000000b7373682d656432353531390000004047bc142f44f7f757717ed9ef3663a4ec98168cab7337f8853aac9e9447a61551c219a430964416dcb96e54247d5c8f4c31708d9428d0b8b5d319e45412f5cf0a",
      ),
    ),
    "SignatureInvalid",
    "t4 wrongkey",
  )
}

///|
/// T5:畸形 blob 矩阵(V4 全部 10 例)
test "t5_malformed_blob_matrix" {
  let cases : Array[(String, String)] = [
    // empty:空输入
    ("", "InvalidFormat"),
    // truncated:pk 截短 3 字节
    (
      "0000000b7373682d6564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd74",
      "InvalidFormat",
    ),
    // nul_in_name:ktype 中部含 NUL(get_cstring 拒)
    (
      "0000000c7373682d006564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
      "InvalidFormat",
    ),
    // unknown_type:未知名
    (
      "0000000b666f6f2d6261722d62617a00000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
      "UnsupportedType",
    ),
    // cert_name:!allow_cert 路径显式分类
    (
      "000000207373682d656432353531392d636572742d763031406f70656e7373682e636f6d00000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
      "CertNotAllowed",
    ),
    // ecdsa_name:仅名字无后续字段。
    // 期望 InvalidFormat 而不是 UnsupportedType —— 这一条以前写错了,
    // 而且它一直「红着」没人碰。sshkey.c:2031-2046 的顺序是:
    //   impl = sshkey_impl_from_type(type) == NULL → KEY_TYPE_UNKNOWN
    //   然后才进 impl->deserialize_public(读曲线名 + 点)
    // `ecdsa-sha2-nistp256` 是一个**已知**类型,impl 查找会通过,所以缺字段
    // 是格式错误。把它写成 UnsupportedType,等于断言「合法的 ECDSA 类型名
    // 查不到实现」,和 C 的顺序正相反。
    ("0000001365636473612d736861322d6e69737470323536", "InvalidFormat"),
    // sk_name:硬件代理名不支持
    (
      "0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d00000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
      "UnsupportedType",
    ),
    // pk31:pk 长度 31
    (
      "0000000b7373682d656432353531390000001fffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c27",
      "InvalidFormat",
    ),
    // pk33:pk 长度 33
    (
      "0000000b7373682d6564323535313900000021ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d01",
      "InvalidFormat",
    ),
    // trailing:良构 blob 后带 2 字节残余
    (
      "0000000b7373682d6564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278ddead",
      "TrailingData",
    ),
  ]
  for i = 0; i < cases.length(); i = i + 1 {
    hk_check_parse(hk_hex(cases[i].0), cases[i].1, "t5[\{i}]")
  }
}

///|
/// T6:RSA 解析矩阵(V5)。rsa_ok 同时锁定 e 先 n 后的读序:
/// 若实现反序,首块 0xC7 前缀会触发 BigNumNegative / 模长检查错位。
test "t6_rsa_parse_matrix" {
  match
    HostKey::from_blob(
      hk_hex(
        "000000077373682d727361000000030100010000010100c72d9f20d0fe16f4cff2f8958e4daa6dab9580c7fbfeb41cde96221d5d35c97f0822028a92857e612891010f966ee05519e73b3602d8fb3f0f558a97899a55ca1db703547bf872f0b015769e441f50771325f030eca9eb70ebc53ad1961db8b8ba845ad5036d2c795e180f9b0f7834a891e6570e3188bc87697fea26fdd42a22d720be65a3fde2d42a30845d7092c2c28cc327274a8ea55c811b52eb35d7e3e16d24e95dd3c0cdd90df58d3bde85339bfb541ad3aed3e0c82c312a79b7401bcc742791130acd2561fe01e190d169c00dd731e66ad56fa4a162582a29fa2509bbe2c370e1c03d2343f6e93ab1c2569fef17f14544387929c11a290952779fe786",
      ),
    ) {
    Parsed(RsaKey(e, n)) => {
      hk_eq(e, hk_hex("010001"), "t6 e")
      hk_eq(
        n,
        hk_hex(
          "c72d9f20d0fe16f4cff2f8958e4daa6dab9580c7fbfeb41cde96221d5d35c97f0822028a92857e612891010f966ee05519e73b3602d8fb3f0f558a97899a55ca1db703547bf872f0b015769e441f50771325f030eca9eb70ebc53ad1961db8b8ba845ad5036d2c795e180f9b0f7834a891e6570e3188bc87697fea26fdd42a22d720be65a3fde2d42a30845d7092c2c28cc327274a8ea55c811b52eb35d7e3e16d24e95dd3c0cdd90df58d3bde85339bfb541ad3aed3e0c82c312a79b7401bcc742791130acd2561fe01e190d169c00dd731e66ad56fa4a162582a29fa2509bbe2c370e1c03d2343f6e93ab1c2569fef17f14544387929c11a290952779fe786",
        ),
        "t6 n(trim 后)",
      )
      if hk_bitlen(n) != 2048 {
        abort("t6: nbits \{hk_bitlen(n)} != 2048")
      }
    }
    other => abort("t6: unexpected \{hk_parse_name(other)}")
  }
  hk_check_parse(
    hk_hex(
      "000000077373682d727361000000030100010000008100bf5e8e283883ef52b98b6e35f337ae03d7c4f0978df83166ebefff24b4a31f36903ce0dacf1d3d18deabb66885dbeb20e682fda4365ca44c38d910137eab81055f11a567b7e0b5a361564efa759e10e84223f8560a957e8280bc6eaf02ff868c96b3d464a625ce0b7c662e847bd99473237dd946c2fb3421fb6f0f8df8f6a7e1",
    ),
    "Parsed(rsa)",
    "t6 rsa1024",
  )
  hk_check_parse(
    hk_hex(
      "000000077373682d727361000000030100010000007f5e8e283883ef52b98b6e35f337ae03d7c4f0978df83166ebefff24b4a31f36903ce0dacf1d3d18deabb66885dbeb20e682fda4365ca44c38d910137eab81055f11a567b7e0b5a361564efa759e10e84223f8560a957e8280bc6eaf02ff868c96b3d464a625ce0b7c662e847bd99473237dd946c2fb3421fb6f0f8df8f6a7e1",
    ),
    "RsaModulusTooShort",
    "t6 short",
  )
  hk_check_parse(
    hk_hex(
      "000000077373682d72736100000003010001000000c980cac21000f26439fcc00b55c47aa3405437a125d808ba88c3e5680faf591e13f7ed46ea1656fff2be5e975eb892cac07eb1b85a9acfa824bd4c7f9d9e79fe529803be2f0227ed894e94c6e7e11fd294b429e0e5afd0c54ac0d8d417be581c10012464b7bdfee754237bd0c836b774126db8519e0ea3ca5245a1a056068f30a5a9686f583e72a5adb52becdaaff268942276435eafdf6f92c3be1b306fb5f26a08e616eb7e1ce0eb7dbc54f4456a65714a7aeefb8b1d6d63b2487d7ff0631ab597b7934974944e66f2",
    ),
    "BigNumNegative",
    "t6 negative",
  )
  hk_check_parse(
    hk_hex(
      "000000077373682d727361000000030100010000080200907d309f09c8afa324e4d55821b19903f360681ff3adb0f847dc2b0a1175ec1957bf2a0db5fdcf93c46bc07449f6ebb31ebf1269e04e59615e969073bcad41a16b4879f3c9f85712972656a71ecf5a7121007b2981119515b3a18c6ee2555f73e34ff449dc709d99b44e6de83af43eb5145c7d546eadbc8d5e35f5f419249f06d80e7308881ffba0341bdf30331deff6110befe43edc26407889a5fbfad458d362bcce2763bbc89d2fc58376a101c5ac2e45aad18a542ca719d7737e1c1ce2519890dd9f05fd5c0bbc8431b21e5a195084428412e9ce24385955387318b395f893c47967089e0f5ff490c2dd40de42592a3a579ff402686e4f3dcad28653ca416b8e797802543a13ef210cef9f4798403965fa7143a94fbf15c50393feb2d7a43727b5c98cd8339fc46fe9dfd54b737cc9fb457f6e7931a3c026bab01789169711c805523de2547a8cb230a578a42b85f13410c20c2b67926b99c71e6a91de950ea7410cae2af41c5f22b93a210819d4cb483331b67747062c5402d78f80871349fd42ef77686cfe54f65c95673094e16d6e87c404152b741c9043d31d0f6a8cd802def1305412978568f2afe3d4f423efe0e3748dbd6a5652856308adf6dd75d4eeef0d70a6406007ae517f2dac91126ad41f39ea265c24e76b3971d7ed3a4855f94c38d0164cd0f50253fddd70c327f684130ab30a5a54f37a9c0332acd87d725bce6ce75b9060659acf228ad8e3d9ab2697df7f20ba618eea67b957eb0f8b444c4ba14e2f638770b09ee6cd9c47a1a0f384b1e720d6c0cff36f88de6237eae3049dce9d491ebd2e7a963f3e7449f6ee24b07783c105eccfcc8d6a5fc9a91366ba9aeb6c60177bb631912874184050adeff52aebbd9f5aa6af9a5771d8bb7de6a81cf1522ea838210d6596083f8528f48d2ac1b6cafd846bd36d46ad46c7a17b05fbd7e869286d8746ec8392a36ef5dc3628347da175e2376fde2faacd24f63c080d96c6caef91ff14fee7a9fb55307d22c57cd7fb61eb22bdc50b01232af442eb2c25830a551da2af71b9e6fe9151ef89db905d8e181743f3fbd14a023214a5e42e7db8dfb388884f1ef1e1667ace49a34169a713f2dfb34a577a1d2092ce7d2ced95fd025f4bc82cde8831e96821a4a8cffe4d4247ba8afbb0fd1137a498e1fc4065ea2bb3dc7b7e88766f40b3c217d05d48e6d36f21df3ce052bffdbfedea8a00e6161206b6b97cf4b13324b428bb52c33e0b7ec38bcb46bf72bf2b3b42af0f030f1a6fb04f9960fb34154bc1cba868dad954fb9a7066512355a879711249c323d98dfa0a1f346173f4ac6e3424f648791058024c49c895e6f113a0b7d2d0de373b086b6a9fa2b636eb914565abbc2c78dbb04b318e084ade41985667fc5c98172e237a2a46fb991b115b88aad6134aaf33f48ea1b63fa8e53bce54d80804299ba976dea18c5640fa5da3ef5c1f13dcf60fbb82f53984e7d2d74e52626de1c99ca5985127eacce4abc70132d4fed31826689ee18490f03f7e0db0075da30bb0f019228a15d875be06480d0969ea6c3716353562a6329be8bfd68b2d2223991671fdac40c1cd6804e4d75e2c735cf6729d6f18bcb3979d196f2a787b0864a432f64acd2d8541beef1c6d8d524acb88ff960ddea903390d0c65000fa966df443e57f71e07b8ad8eb78601323547af3b17d60720dfee8d04f87950e86e960b90706dfd3787b288f294fa8ce48bc08127f236567517cd0d9a1483139a84f060a1020e53af66cb4b00be50053c0e0fb863c88ff2760af730e6995c40bea1ca578f2a14f21f5a5c6dd06d6164d2748bcd08d1b8d2bb6ec46f01c0dad0eb7f7e68722256d11f1cbb667cd904a23d778c372e4489eedcfc8c4103bfd7babbd462096120ace8466442af1a3a10b617cd6b6eed5bda3e706ca81f04cf2af6c459d0b5755dee302dea48c0c3c76099f52f7eeb5c4d84bc10766e801b29ab7d9ec720e1c511f5a06c66250f8ebac94272561f2694525d5d54d238dd60033347e3d4a8086b7497319b903217944a24aa24f8a596aca13f1bd3385daded96984b2939c29f7cbfaeda5120c54dedae4ac8a4ce68b3be7401ee26603568d81ab48108aec4201327119427ce382cb12012948990c1f6e0017bcce50119873ac75ee21aeb080346e79956b451e229f7d654076df606d62a8185b0a7d55f812bd56e65f5a8e5bf2e361c1991631bbed809e819e6b891ccb62df88f059361cfc27bbd02329db4cce34c74d356bb3c636bf2a7c18c8eb94f9a3bab6497f276e818f321b26881cba37c61787f9b109b8ecac767f7f82fd6d7eee47624f5acf6454474746d300e84bb12ac0013f71c92ba0bc102b4c25540ddcc6031c9b677395d60358d2a22fb368dbd67e4870395785d46184fef82b74fd84ae7b44b730d98a8827044e1d600399094c9fcd45734a5ef950426a0cf0c5c4180b1d7a1c3246a9fc25b718be3d4e53cb10921f18ab271e80ebd60c0430ebe9088f673c33f7507ba3a30ed1fe231920a296029d635c535c1c97bd3477373cd3b78ee5faa7fb8c76f00258e966acd99721707ee7cf02647f2e076592cfaf5e1bc69d1734d1ba502392c742ee7156151ea913448db538d01f269e6c9676e4a538b72d787a5aaf5108dd853a40a78a612edb0200deaf5b2ba397d02fbf1682b791fad3874a9c55e4ae51afbc8f82e5234f08b0416a16f4dca403304c7c17f50adf02f2b1051049807b90ba473a9cd1e0f6e3c163cf958168a7ea42306cf4c72467713ea3596fe5d9f80c2867b14eec2fcdcd98f56e949c5506ce8968e1567479c2c6fabba704c646ab259d9ba3129f651b47aa73c6ada12768117973988688807855ca877d68665c0c8e5d507f91672686e38",
    ),
    "BigNumTooLarge",
    "t6 overlong",
  )
  // 2049 字节全零:过长度门,trim 后空 → 0 bits < 1024 → TooShort
  hk_check_parse(
    hk_hex(
      "000000077373682d7273610000000301000100000801000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ),
    "RsaModulusTooShort",
    "t6 zero2049",
  )
}

///|
/// T7:sshkey_verify 前置检查(先于算法分派)
test "t7_verify_preconditions" {
  let key = hk_ed25519_key(
    "0000000b7373682d6564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
    "t7",
  )
  let msg = hk_hex(
    "4d6f6f6e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
  )
  // siglen == 0
  hk_check_verify(
    key.verify(msg, hk_hex("")),
    "InvalidArgument",
    "t7 empty sig",
  )
  // msg 超上限(>1<<20)
  let big : FixedArray[Byte] = FixedArray::make(MAX_SIGN_DATA_SIZE + 1, b'\x41')
  hk_check_verify(
    key.verify(
      big,
      hk_hex(
        "0000000b7373682d65643235353139000000406e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0624ea4b47cfde201070628fbb0f",
      ),
    ),
    "InvalidArgument",
    "t7 oversized msg",
  )
  // 边界:恰等于上限 → 过前置,进密码学验证必败
  let edge : FixedArray[Byte] = FixedArray::make(MAX_SIGN_DATA_SIZE, b'\x42')
  hk_check_verify(
    key.verify(
      edge,
      hk_hex(
        "0000000b7373682d65643235353139000000406e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0624ea4b47cfde201070628fbb0f",
      ),
    ),
    "SignatureInvalid",
    "t7 boundary msg",
  )
}

///|
/// T8:sig blob 结构错误分类学(ssh-ed25519.c:232-300 精确顺序)
test "t8_sig_structure_errors" {
  let key = hk_ed25519_key(
    "0000000b7373682d6564323535313900000020ffb3b57c2f8bd3bb1fc072037fbf02d1a091c3a9ff80d23715ff5acd743c278d",
    "t8",
  )
  let msg = hk_hex(
    "4d6f6f6e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
  )
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
  let trail = hk_cat([
    hk_hex(
      "0000000b7373682d65643235353139000000406e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0624ea4b47cfde201070628fbb0f",
    ),
    hk_hex("dead"),
  ])
  hk_check_verify(key.verify(msg, trail), "TrailingData", "t8 trailing")
  // RSA 密钥收到形态合法的 sig:密码学验证范围外 → 显式 Unavailable
  let rk = match
    HostKey::from_blob(
      hk_hex(
        "000000077373682d727361000000030100010000010100c72d9f20d0fe16f4cff2f8958e4daa6dab9580c7fbfeb41cde96221d5d35c97f0822028a92857e612891010f966ee05519e73b3602d8fb3f0f558a97899a55ca1db703547bf872f0b015769e441f50771325f030eca9eb70ebc53ad1961db8b8ba845ad5036d2c795e180f9b0f7834a891e6570e3188bc87697fea26fdd42a22d720be65a3fde2d42a30845d7092c2c28cc327274a8ea55c811b52eb35d7e3e16d24e95dd3c0cdd90df58d3bde85339bfb541ad3aed3e0c82c312a79b7401bcc742791130acd2561fe01e190d169c00dd731e66ad56fa4a162582a29fa2509bbe2c370e1c03d2343f6e93ab1c2569fef17f14544387929c11a290952779fe786",
      ),
    ) {
    Parsed(k) => k
    other => abort("t8: rsa parse \{hk_parse_name(other)}")
  }
  hk_check_verify(
    rk.verify(
      msg,
      hk_hex(
        "0000000b7373682d65643235353139000000406e0ff66da9fea6cd50226a87c8f7d29b4a1bd27004a41be1dc4f30b73d88bd477dc99f05cdc6d9e9be268f2ef2415fe283df0624ea4b47cfde201070628fbb0f",
      ),
    ),
    "RsaVerifyUnavailable",
    "t8 rsa unavailable",
  )
}

///|
/// T9:密钥 B 往返 + 指纹形态
test "t9_key_b_roundtrip" {
  let blob_b = hk_hex(
    "0000000b7373682d656432353531390000002027ca11763a2d91b23f6426d83031e6bc51eed538566c90cbf82fe3f9e2525230",
  )
  match HostKey::from_blob(blob_b) {
    Parsed(Ed25519Key(pk)) =>
      hk_eq(
        pk,
        hk_hex(
          "27ca11763a2d91b23f6426d83031e6bc51eed538566c90cbf82fe3f9e2525230",
        ),
        "t9 pk",
      )
    other => abort("t9: unexpected \{hk_parse_name(other)}")
  }
  let fp = fingerprint_text(blob_b)
  if fp != "SHA256:A6ELrt9LQi77fouexEwyX5hg0fn2ZBZMeAVP1FISXKA" {
    abort("t9: fingerprint \{fp}")
  }
  // "SHA256:" + 43 字符 base64 nopad(32 字节摘要恒定)
  if fp.length() != 50 || !fp.has_prefix("SHA256:") {
    abort("t9: fingerprint form")
  }
  let key_b = hk_ed25519_key(
    "0000000b7373682d656432353531390000002027ca11763a2d91b23f6426d83031e6bc51eed538566c90cbf82fe3f9e2525230",
    "t9",
  )
  hk_check_verify(
    key_b.verify(
      hk_hex(
        "4d6f6f6e426974204c6f6f702023313120686f73746b657920766572696669636174696f6e2070726f6265",
      ),
      hk_hex(
        "0000000b7373682d656432353531390000004047bc142f44f7f757717ed9ef3663a4ec98168cab7337f8853aac9e9447a61551c219a430964416dcb96e54247d5c8f4c31708d9428d0b8b5d319e45412f5cf0a",
      ),
    ),
    "Accepted",
    "t9 accept",
  )
}
