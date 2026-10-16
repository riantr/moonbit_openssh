///| cmd/hostkey_test -- Loop #38 RFC 8332 主机密钥算法

///|

///| 只依赖 `src/hostkey` 和 `src/rsa`,两者都不碰 `@tcp`,所以四个后端都能跑。

///| 和 Loop #34/#35 拆出 `src/userauth` / `src/channel` 是同一个理由。

///|

///| 对着三份彼此独立的来源核对:

///|

///|   1. **真 OpenSSH** —— `real_*` 向量是 OpenSSH 8.0p1 sshd 真的发上线上的字节,

///|      覆盖的是它真的算出来的 exchange hash。这几条没法辩。

///|   2. **paramiko 5.0** —— 其余 blob 由一个真 SSH 库拼,布局是它的意见不是我们的。

///|   3. **ssh-rsa.c** —— 每个期望结果都按行号从 C 的判定顺序重新推导一遍。

///|

///| 第 3 类里最要紧的是 `ssh-rsa.c:526-535`:签名名和协商名**各自解析成摘要之后

///| 必须相等**,不是两个字符串相等。照 ed25519 的模板写成「签名名 == 密钥类型」的话,

///| 每一条 RFC 8332 签名都会被拒掉,而且报 TypeMismatch —— 指向一个看起来完全正常

///| 的名字。`rsa_sig512_negotiated256` / `rsa_sig256_negotiated512` 两条就是钉这个。

///|

///| 名字有三层,向量里刻意把它们拆开:`real_rsa_sha2_512` 的 key blob 自称

///| `ssh-rsa`,协商名是 `rsa-sha2-512`,签名 blob 里写的也是 `rsa-sha2-512`。

///| 三者两两不同是正常的,只有第三个必须等于第二个。

///|

///| `err` 按**变体名**比对而不是构造序号:枚举若新增变体,序号比对会静默错位继续

///|
/// 通过,名字比对则必须写全分支、编译不过。

// ---------------------------------------------------------------------------
// hex / byte helpers
// ---------------------------------------------------------------------------

fn hex_nibble(c : UInt16) -> Int32 {
  let n = c.to_int()
  if n >= 48 && n <= 57 {
    return n - 48
  }
  if n >= 97 && n <= 102 {
    return n - 87
  }
  abort("hex_to_bytes: bad digit")
}

///|
fn hex_to_bytes(s : String) -> FixedArray[Byte] {
  let n = s.length() / 2
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s[i * 2])
    let lo = hex_nibble(s[i * 2 + 1])
    out[i] = ((hi << 4) | lo).to_byte()
  }
  out
}

///|
fn pf(ok : Bool) -> String {
  if ok {
    "PASS"
  } else {
    "FAIL"
  }
}

// ---------------------------------------------------------------------------
// error names <-> variants
// ---------------------------------------------------------------------------

///|
/// 名字到变体的映射**故意写全 14 个分支**。少写一个 MoonBit 会报 non-exhaustive,
/// 那正是想要的:枚举新增变体时 KAT 应该编译不过,而不是悄悄把序号对错一位继续绿。
fn key_error_of(name : String) -> @hostkey.KeyError {
  match name {
    "InvalidFormat" => @hostkey.InvalidFormat
    "UnsupportedType" => @hostkey.UnsupportedType
    "CertNotAllowed" => @hostkey.CertNotAllowed
    "TypeMismatch" => @hostkey.TypeMismatch
    "TrailingData" => @hostkey.TrailingData
    "BigNumNegative" => @hostkey.BigNumNegative
    "BigNumTooLarge" => @hostkey.BigNumTooLarge
    "RsaModulusTooShort" => @hostkey.RsaModulusTooShort
    "KeyBitsMismatch" => @hostkey.KeyBitsMismatch
    "SignatureInvalid" => @hostkey.SignatureInvalid
    "InvalidArgument" => @hostkey.InvalidArgument
    "EcCurveMismatch" => @hostkey.EcCurveMismatch
    "KeyInvalidEcValue" => @hostkey.KeyInvalidEcValue
    "RsaVerifyUnavailable" => @hostkey.RsaVerifyUnavailable
    _ => abort("unknown KeyError name: " + name)
  }
}

///|
fn key_error_name(e : @hostkey.KeyError) -> String {
  match e {
    @hostkey.InvalidFormat => "InvalidFormat"
    @hostkey.UnsupportedType => "UnsupportedType"
    @hostkey.CertNotAllowed => "CertNotAllowed"
    @hostkey.TypeMismatch => "TypeMismatch"
    @hostkey.TrailingData => "TrailingData"
    @hostkey.BigNumNegative => "BigNumNegative"
    @hostkey.BigNumTooLarge => "BigNumTooLarge"
    @hostkey.RsaModulusTooShort => "RsaModulusTooShort"
    @hostkey.KeyBitsMismatch => "KeyBitsMismatch"
    @hostkey.SignatureInvalid => "SignatureInvalid"
    @hostkey.InvalidArgument => "InvalidArgument"
    @hostkey.EcCurveMismatch => "EcCurveMismatch"
    @hostkey.KeyInvalidEcValue => "KeyInvalidEcValue"
    @hostkey.RsaVerifyUnavailable => "RsaVerifyUnavailable"
  }
}

///|
fn verify_name(r : @hostkey.VerifyResult) -> String {
  match r {
    @hostkey.Accepted => "Accepted"
    @hostkey.Rejected(e) => key_error_name(e)
  }
}

// ---------------------------------------------------------------------------
// chk_key_blobs -- parse + describe
// ---------------------------------------------------------------------------

///|
fn chk_key_blobs(fails : Array[String]) -> Unit {
  for i = 0; i < kat_key_cases.length(); i = i + 1 {
    let c = kat_key_cases[i]
    let blob = hex_to_bytes(c.blob_hex)
    let r = @hostkey.HostKey::from_blob(blob)
    if c.expect_parsed {
      match r {
        @hostkey.Parsed(k) => {
          let (tn, bits) = @hostkey.HostKey::describe(k)
          if tn != c.type_name || bits != c.bits {
            fails.push(
              c.name +
              ": describe -> " +
              tn +
              "/" +
              bits.to_string() +
              " want " +
              c.type_name +
              "/" +
              c.bits.to_string(),
            )
          }
        }
        @hostkey.Rejected(e) =>
          fails.push(c.name + ": parsed as Rejected(" + key_error_name(e) + ")")
      }
    } else {
      match r {
        @hostkey.Parsed(_) =>
          fails.push(c.name + ": parsed but should be Rejected")
        @hostkey.Rejected(e) =>
          if key_error_name(e) != c.err {
            fails.push(
              c.name + ": Rejected(" + key_error_name(e) + ") want " + c.err,
            )
          }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// chk_sig_verify -- the whole point of the loop
// ---------------------------------------------------------------------------

///|
fn chk_sig_verify(fails : Array[String]) -> Unit {
  for i = 0; i < kat_sig_cases.length(); i = i + 1 {
    let c = kat_sig_cases[i]
    let key_blob = hex_to_bytes(c.key_blob_hex)
    let msg = hex_to_bytes(c.msg_hex)
    let sig = hex_to_bytes(c.sig_hex)
    let key = match @hostkey.HostKey::from_blob(key_blob) {
      @hostkey.Parsed(k) => k
      @hostkey.Rejected(e) => {
        fails.push(c.name + ": key blob unparsable: " + key_error_name(e))
        continue
      }
    }
    let want = if c.expect_accepted { "Accepted" } else { c.err }
    let got = @hostkey.HostKey::verify_with_alg(key, msg, sig, c.alg)
    if verify_name(got) != want {
      fails.push(
        c.name + " [" + c.alg + "]: " + verify_name(got) + " want " + want,
      )
    }
  }
}

// ---------------------------------------------------------------------------
// chk_pkcs1_shapes -- RFC 8017 §9.2, no RSA maths involved
// ---------------------------------------------------------------------------

///|
fn chk_pkcs1_shapes(fails : Array[String]) -> Unit {
  for i = 0; i < kat_pkcs1_cases.length(); i = i + 1 {
    let c = kat_pkcs1_cases[i]
    let em = hex_to_bytes(c.em_hex)
    let msg = hex_to_bytes(c.msg_hex)
    match @rsa.rsa_digest_info_prefix(c.digest) {
      None => {
        fails.push(
          c.name + ": no DigestInfo prefix for digest " + c.digest.to_string(),
        )
        continue
      }
      Some(prefix) =>
        match @rsa.rsa_digest(msg, c.digest) {
          None => {
            fails.push(c.name + ": no digest for id " + c.digest.to_string())
            continue
          }
          Some(hash) => {
            let ok = @rsa.rsa_parse_pkcs1_prefix(em, prefix, hash)
            if ok != c.expect_ok {
              fails.push(
                c.name + ": parse -> " + pf(ok) + " want " + pf(c.expect_ok),
              )
            }
          }
        }
    }
  }
}

// ---------------------------------------------------------------------------
// chk_digest_tables -- ssh-rsa.c:328-359
// ---------------------------------------------------------------------------

///|
/// 两个名字表。`ssh_rsa_hash_id_from_keyname` 在 C 里还接受
/// `ssh-rsa-cert-v01@openssh.com`(证书路径),我们没有证书支持,这一格返回 None。
/// 这是**主动的**差异而不是遗漏,写在这里是为了让它可见:哪天接了证书支持,这一格
/// 会红,提醒把 C 那份函数表补上。
fn chk_digest_tables(fails : Array[String]) -> Unit {
  let known : Array[(String, Int32)] = [
    ("rsa-sha2-256", @rsa.RSA_DIGEST_SHA256),
    ("rsa-sha2-512", @rsa.RSA_DIGEST_SHA512),
  ]
  let unknown : Array[String] = [
    // SHA-1 时代的主机密钥签名名。映射到本项目没有的 SHA-1,所以是 None,
    // 而客户端干脆不报它(见 LIVE_HOSTKEY_ALGS 的注释)
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256", "RSA-SHA2-512", "rsa-sha2-512 ",
    "",
  ]
  let cert : Array[String] = ["ssh-rsa-cert-v01@openssh.com"]
  for i = 0; i < known.length(); i = i + 1 {
    let (name, want) = known[i]
    let a = @hostkey.rsa_digest_of_sigtype(name)
    let b = @hostkey.rsa_digest_of_keyname(name)
    if a != Some(want) {
      fails.push("sigtype " + name + " -> " + pf(a == Some(want)))
    }
    if b != Some(want) {
      fails.push("keyname " + name + " -> " + pf(b == Some(want)))
    }
  }
  for i = 0; i < unknown.length(); i = i + 1 {
    let name = unknown[i]
    if @hostkey.rsa_digest_of_sigtype(name) != None {
      fails.push("sigtype " + name + " should not resolve")
    }
    if @hostkey.rsa_digest_of_keyname(name) != None {
      fails.push("keyname " + name + " should not resolve")
    }
  }
  for i = 0; i < cert.length(); i = i + 1 {
    // deliberate divergence, see above
    if @hostkey.rsa_digest_of_keyname(cert[i]) != None {
      fails.push("cert " + cert[i] + ": no cert support yet, expected None")
    }
  }
}

// ---------------------------------------------------------------------------
// chk_agreement -- `agrees_with_alg`, the rule both drivers share
// ---------------------------------------------------------------------------

///|
/// RSA 的配对规则和 ed25519 / ECDSA 的**结构上就不一样**:后两者名字由密钥类型
/// 唯一决定,RSA 的不是(SSH-RSA 是 SHA-1 时代的名字,协商名却带摘要)。两条驱动
/// 原来各抄了一份,Loop #38 把规则收回 `src/hostkey`。
fn chk_agreement(fails : Array[String]) -> Unit {
  // 64 bytes with the top bit set == a 512-bit modulus.  describe reports
  // n.length() * 8, so this has to be exactly 64 bytes or the bit count in
  // the assertion below is measuring the test vector, not the code.
  let rsa = @hostkey.RsaKey(
    hex_to_bytes("010001"),
    hex_to_bytes("c0ffee" + String::repeat("00", 60) + "03"),
  )
  let ed = @hostkey.Ed25519Key(FixedArray::make(32, b'\x00'))
  let pairs : Array[(String, String, Bool)] = [
    ("rsa/ssh-rsa", "ssh-rsa", false),
    ("rsa/rsa-sha2-256", "rsa-sha2-256", true),
    ("rsa/rsa-sha2-512", "rsa-sha2-512", true),
    ("rsa/ssh-ed25519", "ssh-ed25519", false),
    ("rsa/ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256", false),
    ("ed/ssh-ed25519", "ssh-ed25519", true),
    ("ed/rsa-sha2-512", "rsa-sha2-512", false),
    ("ed/ssh-rsa", "ssh-rsa", false),
  ]
  for i = 0; i < pairs.length(); i = i + 1 {
    let (label, alg, want) = pairs[i]
    let k = if label.has_prefix("rsa") { rsa } else { ed }
    let got = @hostkey.HostKey::agrees_with_alg(k, alg)
    if got != want {
      fails.push("agree " + label + " -> " + pf(got) + " want " + pf(want))
    }
  }
  // describe 报的是**密钥自己**的名字,RFC 8332 下它和协商名不同
  let (tn, bits) = @hostkey.HostKey::describe(rsa)
  if tn != "ssh-rsa" || bits != 512 {
    fails.push(
      "describe rsa -> " + tn + "/" + bits.to_string() + " want ssh-rsa/512",
    )
  }
  let (tn2, bits2) = @hostkey.HostKey::describe(ed)
  if tn2 != "ssh-ed25519" || bits2 != 256 {
    fails.push(
      "describe ed -> " +
      tn2 +
      "/" +
      bits2.to_string() +
      " want ssh-ed25519/256",
    )
  }
}

// ---------------------------------------------------------------------------
// coverage -- a KAT that silently lost its hard cases is worse than none
// ---------------------------------------------------------------------------

///|
fn chk_coverage(fails : Array[String]) -> Unit {
  // Every error name a vector mentions has to resolve to a real variant.
  // `key_error_of` is an exhaustive match with no catch-all, so a name that
  // does not exist aborts here -- a loud failure on a typo in the generated
  // file, rather than a confusing "Rejected(X) want Y" on some later case.
  for i = 0; i < kat_sig_cases.length(); i = i + 1 {
    let c = kat_sig_cases[i]
    if !c.expect_accepted && key_error_name(key_error_of(c.err)) != c.err {
      fails.push(c.name + ": error name does not round-trip: " + c.err)
    }
  }
  for i = 0; i < kat_key_cases.length(); i = i + 1 {
    let c = kat_key_cases[i]
    if !c.expect_parsed && key_error_name(key_error_of(c.err)) != c.err {
      fails.push(c.name + ": error name does not round-trip: " + c.err)
    }
  }

  let real = kat_sig_cases.filter(c => c.name.has_prefix("real_"))
  let accepted = kat_sig_cases.filter(c => c.expect_accepted)
  let rejected = kat_sig_cases.filter(c => !c.expect_accepted)
  // every one of the three algorithms the client advertises has to have a
  // vector that a real server produced, or the loop proved nothing about it
  let algs = ["ssh-ed25519", "rsa-sha2-256", "rsa-sha2-512"]
  for i = 0; i < algs.length(); i = i + 1 {
    let a = algs[i]
    let n = real.filter(c => c.alg == a).length()
    if n != 1 {
      fails.push("real capture for " + a + ": " + n.to_string() + " (want 1)")
    }
  }
  if real.length() != kat_real_capture_count {
    fails.push(
      "real capture count " +
      real.length().to_string() +
      " != declared " +
      kat_real_capture_count.to_string(),
    )
  }
  // the negative half has to be more than one flavour, or a single wrong
  // early-return passes everything.  `RsaModulusTooShort` is counted against
  // the *key* vectors: OpenSSH enforces the floor while deserialising the key,
  // so a short modulus never reaches the verify path at all.
  let sig_errs = [
    "SignatureInvalid", "TypeMismatch", "InvalidFormat", "TrailingData", "KeyBitsMismatch",
  ]
  for i = 0; i < sig_errs.length(); i = i + 1 {
    let e = sig_errs[i]
    if rejected.filter(c => c.err == e).length() == 0 {
      fails.push("no signature vector expects " + e)
    }
  }
  if kat_key_cases.filter(c => c.err == "RsaModulusTooShort").length() == 0 {
    fails.push("no key vector expects RsaModulusTooShort")
  }
  println("hostkey_real_captures: " + real.length().to_string())
  println("hostkey_accepted_cases: " + accepted.length().to_string())
  println("hostkey_rejected_cases: " + rejected.length().to_string())
  println("hostkey_pkcs1_cases: " + kat_pkcs1_cases.length().to_string())
}

///|
fn main {
  let fails : Array[String] = []
  chk_key_blobs(fails)
  println("chk_key_blobs: " + pf(fails.length() == 0))
  let before = fails.length()
  chk_sig_verify(fails)
  println("chk_sig_verify: " + pf(fails.length() == before))
  let b2 = fails.length()
  chk_pkcs1_shapes(fails)
  println("chk_pkcs1_shapes: " + pf(fails.length() == b2))
  let b3 = fails.length()
  chk_digest_tables(fails)
  println("chk_digest_tables: " + pf(fails.length() == b3))
  let b4 = fails.length()
  chk_agreement(fails)
  println("chk_agreement: " + pf(fails.length() == b4))
  let b5 = fails.length()
  chk_coverage(fails)
  println("chk_coverage: " + pf(fails.length() == b5))
  for i = 0; i < fails.length(); i = i + 1 {
    println("  hostkey_fail: " + fails[i])
  }
  println("hostkey_cases: " + kat_sig_cases.length().to_string())
}
