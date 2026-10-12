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
