/// Loop #50: 固定判定的三态,以及默认必须落在拒绝那一侧。
///
/// 这些断言看起来琐碎,尤其是第一个。它们的全部理由是: Loop #50 把默认值从
/// 「放行」改成「拒绝」之后,改了三遍都没生效,因为 `verify` 在 `entries` 为空
/// 时提前返回了一个被 `decide` 当作「没问题」的状态。一个**永远不会被执行的
/// 分支**不会让任何 e2e 门禁变红——门禁要连上一个真的对端,而对端根本不关心
/// 我们改没改默认值。所以这条规则的正确回归网是单元测试,不是端到端。
///
/// 端到端的部分在 `host/verify_loop50.mjs`。
///
/// base64 常量是**真实的 SSH wire blob**,不是占位串:`parse_base64_blob` 解不出
/// 东西时测试会 abort,而那读起来像「规则坏了」,其实只是夹具不是钥匙。
/// Loop #43 的 `hex_to_bytes` 是同一种教训。

/// 一条 ed25519 wire blob,恰好 51 字节(不是 3 的倍数,base64 带 `=`)。
const PIN_ED25519_B64 : String =
  "AAAAC3NzaC1lZDI1NTE5AAAAKwAAAAAAAAAAAAAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

/// 另一把真的钥匙,用来构造「钉住的和出示的不是同一把」。
const PIN_RSA_B64 : String = "AAAAB3NzaC1yc2EAAAALAQABAAECAwQFBgc="

fn blob_of(b64 : String) -> FixedArray[Byte] {
  match @knownhosts.parse_base64_blob(b64) {
    Some(v) => v
    None => abort("the test constant must parse as base64")
  }
}

/// `decide` 的结果压成一个字符串,好让断言能一次看清是哪个态。
///
/// 直接 `assert_eq` 一个 `Option[PinFailure]` 做不到,因为它没有 `Eq`——而为了
/// 断言去给一个只在测试里比较的类型派生 `Eq`,是在生产代码上为一个测试加约束。
/// 压成字符串顺带让失败信息能直接说清是哪一态。
fn decide_as(p : @knownhosts.KnownHostsPolicy, blob : FixedArray[Byte]) -> String {
  match p.decide(blob) {
    None => "allow"
    Some(f) =>
      match f {
        Mismatch(h) => "mismatch:" + h
        Unknown(h) => "unknown:" + h
        CertAuthority(h, reason) => "certauthority:" + h + "/" + reason
        CertUntrusted(h) => "certuntrusted:" + h
        InvalidEntry => "invalid"
      }
  }
}

// ---------------------------------------------------------------------------
// 真正修掉的那个 bug
// ---------------------------------------------------------------------------

test "strict_with_no_entries_refuses" {
  // 这一条就是 Loop #50 的回归测试。空的 known_hosts 在 strict 下是
  // 「这个主机没被固定过」,因此拒绝;它此前被读成「没东西可比,放行」。
  let p = @knownhosts.KnownHostsPolicy::from_text("", "h.example", 0, true)
  assert_eq(p.entries.length(), 0)
  assert_eq(decide_as(p, blob_of(PIN_ED25519_B64)), "unknown:h.example")
}

test "empty_text_is_not_the_same_as_skip" {
  // 两个策略在字段上只差一个 `strict`,而答案相反。这正是把它们绑在一起会
  // 出事的理由:任何「有没有配置」的特殊路径都长这个样子,然后在默认值上生效。
  let strict = @knownhosts.KnownHostsPolicy::from_text("", "h.example", 0, true)
  let loose = @knownhosts.KnownHostsPolicy::from_text("", "h.example", 0, false)
  let skip = @knownhosts.KnownHostsPolicy::skip()
  let blob = blob_of(PIN_ED25519_B64)
  assert_eq(decide_as(strict, blob), "unknown:h.example")
  assert_eq(decide_as(loose, blob), "allow")
  assert_eq(decide_as(skip, blob), "allow")
}

test "skip_needs_no_entries_and_no_host" {
  // skip() 在任何一把钥匙、任何主机名下都放行——它是「不固定」,不是「没匹上」。
  let skip = @knownhosts.KnownHostsPolicy::skip()
  assert_eq(decide_as(skip, blob_of(PIN_ED25519_B64)), "allow")
  assert_eq(decide_as(skip, blob_of(PIN_RSA_B64)), "allow")
  assert_eq(decide_as(skip, FixedArray::from_array([b'x'])), "allow")
}

// ---------------------------------------------------------------------------
// 三态
// ---------------------------------------------------------------------------

test "a_matching_pin_allows" {
  let line = "h.example ssh-ed25519 " + PIN_ED25519_B64
  let p = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, true)
  assert_eq(p.entries.length(), 1)
  assert_eq(decide_as(p, blob_of(PIN_ED25519_B64)), "allow")
}

test "a_mismatching_pin_refuses_in_both_modes" {
  // **TOFU 不赦免 mismatch。** accept-new 只对「没被固定过」放行;一旦某个条目
  // 命中了主机名而钥匙对不上,那是有人在中间,任何模式下都必须拒。
  //
  // 这一条值得单独断言,因为「非 strict 就放行」是一个极其自然、也极其致命的
  // 写法——它和 OpenSSH 的 accept-new 只差一个分支。
  let line = "h.example ssh-ed25519 " + PIN_ED25519_B64
  let other = blob_of(PIN_RSA_B64)
  let strict = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, true)
  let tofu = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, false)
  assert_eq(decide_as(strict, other), "mismatch:h.example")
  assert_eq(decide_as(tofu, other), "mismatch:h.example")
}

test "unknown_is_a_refusal_only_under_strict" {
  let line = "other.example ssh-ed25519 " + PIN_ED25519_B64
  let blob = blob_of(PIN_ED25519_B64)
  let strict = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, true)
  let tofu = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, false)
  assert_eq(decide_as(strict, blob), "unknown:h.example")
  assert_eq(decide_as(tofu, blob), "allow")
}

test "a_revoked_entry_refuses_under_too" {
  // 吊销走的是另一条路(全局扫,不要求主机名命中),所以它必须和 accept-new
  // 无关。一条被吊销的钥匙在 TOFU 模式下被接受,等于吊销功能不存在。
  let line = "@revoked anywhere.example ssh-ed25519 " + PIN_ED25519_B64
  let tofu = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, false)
  assert_eq(decide_as(tofu, blob_of(PIN_ED25519_B64)), "mismatch:h.example")
}

// ---------------------------------------------------------------------------
// 端口
// ---------------------------------------------------------------------------

test "an_entry_on_another_port_does_not_pin_this_one" {
  // `[host]:2222` 钉住的是 2222 端口上的 h.example,连 2222 时它必须匹上;
  // 连 2223 时它必须**不**匹上。
  //
  // 值得断言的是后一半。端口写错的后果如果落成 Match,一次配置错误会看起来像
  // 安全通过——而它是这整层里最容易写错、也最难在事后看出来的一处。
  let line = "[h.example]:2222 ssh-ed25519 " + PIN_ED25519_B64
  let blob = blob_of(PIN_ED25519_B64)
  let right = @knownhosts.KnownHostsPolicy::from_text(line, "[h.example]:2222", 0, true)
  assert_eq(decide_as(right, blob), "allow")
  let right_split = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 2222, true)
  assert_eq(decide_as(right_split, blob), "allow")
  let wrong = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 2223, true)
  assert_eq(decide_as(wrong, blob), "unknown:h.example")
}

// ---------------------------------------------------------------------------
// Loop #51: `@cert-authority` 不是一把主机密钥的 pin
// ---------------------------------------------------------------------------

test "a_cert_authority_entry_is_never_a_direct_pin" {
  // **这一条就是 Loop #51 的回归测试。**
  //
  // `@cert-authority h.example <BLOB>` 说的是「只有出示这张 CA 签的证书才信任」,
  // 不是「这台主机的密钥就是 BLOB」。此前它被当成普通条目比对相等,而
  // **相等即放行**——实测对端出示这把 key 时客户端会认证并把凭据发出去。
  //
  // 构造方式刻意选了「blob 完全相同」:只有这种情况下 fail-open 才会发生,所以
  // 只有这种情况能证明洞被堵上了。
  let blob = blob_of(PIN_ED25519_B64)
  let line = "@cert-authority h.example ssh-ed25519 " + PIN_ED25519_B64
  let strict = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, true)
  assert_eq(
    decide_as(strict, blob),
    "certauthority:h.example/no-certificate-expected",
  )
}

test "a_cert_authority_entry_does_not_escape_under_tofu" {
  // **accept-new 也不能把它变成信任。**
  //
  // 这一点值得单独断言,因为 `--kh-tofu` 的字面意思就是「接受没见过的」,
  // 而「用 CA pin 的主机」看起来就很像「没见过的」。但放行它等于把 Loop #51
  // 关掉的降级原样装回来,而且是从一个看起来正当的开关进来的。
  let blob = blob_of(PIN_ED25519_B64)
  let line = "@cert-authority h.example ssh-ed25519 " + PIN_ED25519_B64
  let tofu = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, false)
  assert_eq(
    decide_as(tofu, blob),
    "certauthority:h.example/no-certificate-expected",
  )
}

test "a_cert_authority_entry_for_another_host_is_still_unknown" {
  // CA 命中必须真的按主机名算。通配 CA 条目很常见(`@cert-authority
  // *.internal.example`),所以「命中」这个条件要真的起作用,否则一个覆盖
  // 半张网段的 CA 会把无关主机也变成 `CertAuthority`,而那个状态会让人
  // 去找根本不存在的证书问题。
  let blob = blob_of(PIN_ED25519_B64)
  let line = "@cert-authority other.example ssh-ed25519 " + PIN_ED25519_B64
  let p = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, true)
  assert_eq(decide_as(p, blob), "unknown:h.example")
}

test "a_direct_entry_wins_over_a_cert_authority_entry" {
  // 同一主机既有直接条目又有 CA 条目时,拿直接条目说话。
  //
  // 顺序反过来会怎样:如果 CA 条目压过直接条目,那么一次**真实**的钥匙更换
  // 会被报成「用 CA pin 的、我不支持」,也就是把一个真指控洗成一条
  // 无害的说明——比反过来更糟。
  let blob = blob_of(PIN_ED25519_B64)
  let other = blob_of(PIN_RSA_B64)
  // 直接条目在**前**面,CA 条目在后面:后者不能用 last-match-wins 盖掉前者。
  let ca_then_direct = "@cert-authority h.example ssh-ed25519 " + PIN_ED25519_B64 +
    "\nh.example ssh-ed25519 " + PIN_ED25519_B64
  let direct_then_ca = "h.example ssh-ed25519 " + PIN_ED25519_B64 +
    "\n@cert-authority h.example ssh-ed25519 " + PIN_RSA_B64
  let a = @knownhosts.KnownHostsPolicy::from_text(ca_then_direct, "h.example", 0, true)
  let b = @knownhosts.KnownHostsPolicy::from_text(direct_then_ca, "h.example", 0, true)
  assert_eq(decide_as(a, blob), "allow")
  // 直接条目仍在,出示的却是别的钥匙 → 真指控,不能被 CA 条目洗掉。
  assert_eq(decide_as(b, other), "mismatch:h.example")
}

test "a_revoked_key_still_wins_over_a_cert_authority_entry" {
  // 吊销是全表扫,不看主机名,所以它必须排在所有事之前。
  // 一条「既被 @revoked 又被 @cert-authority 引用」的 key,报 CertAuthority
  // 会把一条明确的吊销记录说成一个功能缺失。
  let blob = blob_of(PIN_ED25519_B64)
  let line = "@cert-authority h.example ssh-ed25519 " + PIN_ED25519_B64 +
    "\n@revoked anywhere.example ssh-ed25519 " + PIN_ED25519_B64
  let p = @knownhosts.KnownHostsPolicy::from_text(line, "h.example", 0, true)
  assert_eq(decide_as(p, blob), "mismatch:h.example")
}

test "a_wildcard_cert_authority_entry_covers_the_host" {
  // 通配 CA 条目是 CA pin 的常见写法,必须真的匹配。这条与
  // `a_cert_authority_entry_for_another_host_is_still_unknown` 成对:一个证明
  // 该命中,一个证明不该命中。
  let blob = blob_of(PIN_ED25519_B64)
  let line = "@cert-authority *.example.com ssh-ed25519 " + PIN_ED25519_B64
  let p = @knownhosts.KnownHostsPolicy::from_text(line, "h.example.com", 0, true)
  assert_eq(
    decide_as(p, blob),
    "certauthority:h.example.com/no-certificate-expected",
  )
}

// ---------------------------------------------------------------------------
// Loop #53: `@cert-authority` 变成一个真正能用的信任锚
// ---------------------------------------------------------------------------
//
// 固定件来自 src/hostkey/cert_fixture.mbt（真实 ssh-keygen 证书），生成过程见
// host/cert_gen_fixture.py。

/// GOOD_CERT 的有效期正中
const CERT_NOW : UInt64 = (@hostkey.GOOD_CERT_VALID_AFTER +
  @hostkey.GOOD_CERT_VALID_BEFORE) / 2UL

/// 一行「这台主机由这把 CA 担保」的 known_hosts
fn ca_line(host : String, ca_b64 : String) -> String {
  "@cert-authority " + host + " ssh-ed25519 " + ca_b64
}

/// 带时钟的策略
fn policy_for(
  line : String,
  host : String,
  strict : Bool,
  now : UInt64,
) -> @knownhosts.KnownHostsPolicy {
  @knownhosts.KnownHostsPolicy::from_text_at(line, host, 0, strict, now)
}

test "a_valid_host_certificate_is_accepted" {
  // 这一条是 Loop #53 的正例：Loop #51 时同一个场景报的是「我不支持证书」。
  let p = policy_for(
    ca_line("127.0.0.1", @hostkey.CA_PUB),
    "127.0.0.1",
    true,
    CERT_NOW,
  )
  assert_eq(decide_as(p, blob_of(@hostkey.GOOD_CERT)), "allow")
}

test "a_certificate_only_behaves_like_this_when_strict_is_off" {
  // 非 strict 下，**没有 CA 条目**时证书仍然被拒。这条与 `Unknown` 的宽松放行
  // 正好相反，必须单独钉住：宽松模式放行的是「一把没验证过的裸钥匙」，而
  // 一张没有本地信任锚的证书没有任何东西为它背书。
  let p = policy_for(
    ca_line("other.example", @hostkey.CA_PUB),
    "127.0.0.1",
    false,
    CERT_NOW,
  )
  assert_eq(
    decide_as(p, blob_of(@hostkey.GOOD_CERT)),
    "certuntrusted:127.0.0.1",
  )
  let tofu = policy_for(
    ca_line("other.example", @hostkey.CA_PUB),
    "127.0.0.1",
    true,
    CERT_NOW,
  )
  assert_eq(
    decide_as(tofu, blob_of(@hostkey.GOOD_CERT)),
    "certuntrusted:127.0.0.1",
  )
}

test "a_certificate_from_an_unpinned_ca_is_untrusted" {
  // 证书指名 rogue CA，而本机 pin 的是另一把 CA。这不是验签失败——rogue 证书
  // 本身签名是好的——而是「这台主机没有你这个信任锚」。
  let p = policy_for(
    ca_line("127.0.0.1", @hostkey.CA_PUB),
    "127.0.0.1",
    true,
    CERT_NOW,
  )
  assert_eq(
    decide_as(p, blob_of(@hostkey.ROGUE_CA_CERT)),
    "certuntrusted:127.0.0.1",
  )
}

test "an_expired_certificate_names_the_reason" {
  // 理由要能一眼看出该干什么：补 CA 条目 / 重签证书 / 查 CA 私钥是三条不同的路。
  let p = policy_for(
    ca_line("127.0.0.1", @hostkey.CA_PUB),
    "127.0.0.1",
    true,
    (@hostkey.GOOD_CERT_VALID_BEFORE + 1UL),
  )
  assert_eq(
    decide_as(p, blob_of(@hostkey.EXPIRED_CERT)),
    "certauthority:127.0.0.1/expired",
  )
}

test "a_certificate_for_another_principal_names_the_reason" {
  let p = policy_for(
    ca_line("127.0.0.1", @hostkey.CA_PUB),
    "127.0.0.1",
    true,
    CERT_NOW,
  )
  assert_eq(
    decide_as(p, blob_of(@hostkey.OTHER_PRINCIPAL_CERT)),
    "certauthority:127.0.0.1/principal-mismatch",
  )
}

test "a_user_certificate_is_not_a_host_identity" {
  let p = policy_for(
    ca_line("alice", @hostkey.CA_PUB),
    "alice",
    true,
    CERT_NOW,
  )
  assert_eq(
    decide_as(p, blob_of(@hostkey.USER_CERT)),
    "certauthority:alice/not-a-host-certificate",
  )
}

test "a_revoked_ca_stops_cutting_certificates" {
  // 吊销检查的对象是**签发者**：CA 进了 @revoked，它签的一切证书就都不再可信。
  let line = ca_line("127.0.0.1", @hostkey.CA_PUB) +
    "\n@revoked * ssh-ed25519 " + @hostkey.CA_PUB
  let p = policy_for(line, "127.0.0.1", true, CERT_NOW)
  assert_eq(
    decide_as(p, blob_of(@hostkey.GOOD_CERT)),
    "certauthority:127.0.0.1/ca-revoked",
  )
}

test "a_direct_pin_outranks_a_ca_entry_even_for_certificates" {
  // Loop #51 立过一条规则：直接条目压过 CA 条目，否则真换钥会被洗成
  // 「不支持证书」。Loop #53 必须让这条规则对证书一样成立——证书只是换了一种
  // 出示方式，不该成为绕过它的后门。
  let line = "h.example ssh-ed25519 " + PIN_ED25519_B64 + "\n" +
    ca_line("h.example", @hostkey.CA_PUB)
  let p = policy_for(line, "h.example", true, CERT_NOW)
  assert_eq(decide_as(p, blob_of(@hostkey.GOOD_CERT)), "mismatch:h.example")
}

test "a_certificate_is_not_learned_by_tofu" {
  // `--kh-tofu` 会学一张没有信任锚的证书，那等于把「信任此刻出示的任何东西」
  // 换了个说法重新装回来——Loop #51 关掉的正是这个降级。
  let p = policy_for("", "127.0.0.1", false, CERT_NOW)
  assert_eq(
    decide_as(p, blob_of(@hostkey.GOOD_CERT)),
    "certuntrusted:127.0.0.1",
  )
}

test "the_clock_is_injected_not_read" {
  // 同一张证书、同一份 known_hosts，只有 now 不同。门禁要能反复跑「过期必须被
  // 拒」，所以时钟必须由调用方给；这条同时证明 `now` 真的参与了判定。
  let line = ca_line("127.0.0.1", @hostkey.CA_PUB)
  let inside = policy_for(line, "127.0.0.1", true, CERT_NOW)
  assert_eq(decide_as(inside, blob_of(@hostkey.GOOD_CERT)), "allow")
  let after = policy_for(line, "127.0.0.1", true, (@hostkey.GOOD_CERT_VALID_BEFORE + 1UL))
  assert_eq(
    decide_as(after, blob_of(@hostkey.GOOD_CERT)),
    "certauthority:127.0.0.1/expired",
  )
  let before = policy_for(line, "127.0.0.1", true, (@hostkey.GOOD_CERT_VALID_AFTER - 1UL))
  assert_eq(
    decide_as(before, blob_of(@hostkey.GOOD_CERT)),
    "certauthority:127.0.0.1/not-yet-valid",
  )
}

test "a_default_clock_refuses_instead_of_expiring_silently" {
  // `now = 0`（没注入时钟）必须 fail-closed 成 not-yet-valid，而不是「不检查
  // 有效期就放行」。把默认值选成宽松那一边，等于给「忘了传时钟」写了一个
  // 默认放行的后门。
  let line = ca_line("127.0.0.1", @hostkey.CA_PUB)
  let p = @knownhosts.KnownHostsPolicy::from_text(
    line,
    "127.0.0.1",
    0,
    true,
  )
  assert_eq(
    decide_as(p, blob_of(@hostkey.GOOD_CERT)),
    "certauthority:127.0.0.1/not-yet-valid",
  )
}
