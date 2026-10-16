///| Loop #49: known_hosts 的往返性质。

///|

///| 写回的唯一安全性质是**读进来再写出去逐字不变**。不是「功能上等价」,是

///| 逐字:一次 TOFU 写回如果顺手把通配符或否定标记改写了,那份文件就变得和用户

///| 写的不是一回事,而那比不写回更糟——用户下一次会以为自己在读自己写的东西。

///|

///| 这些是纯单元测试,因为往返不依赖任何对端;端到端的写回在

///| `host/verify_loop49.mjs`。

///|

///|
/// base64 常量是**真实的 SSH wire blob**,不是占位串:`parse_line` 会把 key
/// 字段解成 key blob,一串编造的 base64 解析出来是 0 条,而一个断言
/// `0 != 1` 的失败读起来像「渲染坏了」,其实只是夹具不是钥匙。这正是
/// Loop #43 的 `hex_to_bytes` 那条教训的同一种:夹具错了,现象却指向规则。
const ED25519_B64 : String = "AAAAC3NzaC1lZDI1NTE5AAAAKwAAAAAAAAAAAAAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="

///|
/// 一条 ed25519 wire blob 恰好 51 字节,不是 3 的倍数,所以 base64 带一个 `=`。
/// 这是**故意的**:补位是写回最容易写错的一环(`AAAA` 这样的 4 字节输入永远
/// 凑巧看不出问题),而 OpenSSH 写出来的就是带 `=` 的标准 base64。
const RSA_B64 : String = "AAAAB3NzaC1yc2EAAAALAQABAAECAwQFBgc="

///|
test "render_round_trip_is_byte_identical" {
  let line = "foo.example.com ssh-ed25519 " + ED25519_B64
  let entries = @knownhosts.parse_file("# a comment line\n" + line + "\n")
  assert_eq(entries.length(), 1)
  assert_eq(entries[0].render(), line + "\n")
}

///|
test "render_keeps_wildcards_and_negation" {
  // 这两样是最容易在写回时被「规范化」掉的,而它们正是用户的本意。
  let line = "*.example.com,!bar.example.com ssh-rsa " + RSA_B64
  let entries = @knownhosts.parse_file(line + "\n")
  assert_eq(entries.length(), 1)
  assert_eq(entries[0].render(), line + "\n")
}

///|
test "render_keeps_a_marker" {
  // @revoked 前缀如果被丢掉,一条吊销记录会静默变成一条普通信任记录——方向
  // 正好相反,比不写回更危险。
  let line = "@revoked evil.example.com ssh-ed25519 " + ED25519_B64
  let entries = @knownhosts.parse_file(line + "\n")
  assert_eq(entries.length(), 1)
  assert_eq(entries[0].render(), line + "\n")
}

///|
test "append_adds_a_trailing_newline" {
  // `abc` 是 3 字节,base64 无补位;挑一个恰好 3 的倍数,是为了让这里的断言
  // 只测「换行处理」而不掺「补位」。
  let got = @knownhosts.append_line(
    "foo.example.com ssh-ed25519 " + ED25519_B64 + "\n",
    "bar.example.com",
    "ssh-ed25519",
    FixedArray::from_array([b'a', b'b', b'c']),
  )
  assert_eq(
    got,
    "foo.example.com ssh-ed25519 " +
    ED25519_B64 +
    "\nbar.example.com ssh-ed25519 YWJj\n",
  )
}

///|
test "append_is_idempotent" {
  let blob = match @knownhosts.parse_base64_blob("QUJDRA==") {
    Some(v) => v
    None => abort("the test constant must parse as base64")
  }
  let once = @knownhosts.append_line(
    "h ecdsa-sha2-nistp256 AAAA", "h", "ecdsa-sha2-nistp256", blob,
  )
  let twice = @knownhosts.append_line(once, "h", "ecdsa-sha2-nistp256", blob)
  assert_eq(twice, once)
}

///|
test "append_does_not_duplicate_when_the_file_has_comments" {
  // 一份全是注释的 known_hosts 仍然要能接住第一条真正的记录;如果去重时把
  // 「已经有」判成「文件非空」,第一次写回就会被跳过,而那正是最该发生的一次。
  // 4 字节输入 -> `QUJDRA==`,补位在这里是被断言的一部分。
  let got = @knownhosts.append_line(
    "# nothing pinned yet\n",
    "h",
    "ssh-ed25519",
    FixedArray::from_array([b'A', b'B', b'C', b'D']),
  )
  assert_eq(got, "# nothing pinned yet\nh ssh-ed25519 QUJDRA==\n")
}

///|
test "appended_line_parses_back_to_the_same_blob" {
  // 写回去的东西必须能被自己读回来——不然下一次连接比对的就不是刚才接受的那把。
  let blob = match @knownhosts.parse_base64_blob(ED25519_B64) {
    Some(v) => v
    None => abort("the test constant must parse as base64")
  }
  let line = @knownhosts.append_line("", "h.example", "ssh-ed25519", blob)
  let entries = @knownhosts.parse_file(line)
  assert_eq(entries.length(), 1)
  assert_eq(entries[0].host_raw, "h.example")
  assert_eq(entries[0].key_type, "ssh-ed25519")
  assert_eq(entries[0].key_blob, blob)
}
