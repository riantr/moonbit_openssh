///| cmd/knownhosts_kat -- Loop #56: MoonBit's side of the known_hosts KAT.
///
///|
///
/// The chain for this component is older than any gate:
///
/// ```
///   knownhosts_python_ref.py   self-checks against hashlib / hmac,
///                               writes _knownhosts_ref_out.txt
///         |
///         v
///   gen_knownhosts_test.py     sanity-checks against FIPS 180-4 and RFC 2202,
///                               then emits BOTH knownhosts_test.mbt (MoonBit)
///                               and _knownhosts_kat.h (C)
/// ```
///
/// All three sides came out of one source, and nothing ran any of it.
/// `verify_loop56` runs the chain and checks the committed generated files still
/// match what it produces -- the drift nobody was watching for.
///
///
/// This program exists because "MoonBit's tests passed" is not a cross-check. The
/// generated test asserts against vectors the generator wrote from a file Python
/// wrote, so a mistake anywhere in that chain is invisible to it. Printing the
/// *decisions* lets the gate compare verdicts -- `Ok`, `Mismatch`, `Unknown`,
/// `Invalid` -- against the C harness and against Python, which is where a
/// disagreement about what a pinning rule *means* would show up rather than a
/// disagreement about arithmetic.
///
///|
///
/// **The case table below is not uniform, and that is the point.** The vector
/// file spells some cases with their own keys and leaves others to reuse V1's --
/// `V2` is a wildcard match *of V1's line*, `V3`/`V6`/`V7` present `V1_BLOB`, and
/// `V7` is the strict path. An earlier version of this file derived every key name
/// as `<id>_knownhosts_line` / `<id>_presented_blob_hex` and so silently fed an
/// empty entry list into four cases; they "passed" as `Unknown`, which is a real
/// verdict, just not the verdict anyone was looking at. Every row here mirrors a
/// block in `verify_c/knownhosts_harness.c` and says which one.
///
/// `assert_full_coverage` is the guard against that whole class of mistake
/// recurring: any vector carrying an `_expected_status` must be claimed by some
/// row, or this program aborts instead of quietly skipping it.
///
///|
///
/// The verdict encoding is the vector file's, not one invented here:
/// `0 = Ok, 1 = Mismatch, 2 = Unknown, 3 = Invalid`, and `4` for the certificate
/// case that Loop #53 added and this vector set predates.
async fn main {
  let path = argv(1)
  let text = try {
    let data = @fs.read_file(path)
    data.text()
  } catch {
    _ => abort("cannot read the vector file: " + path)
  }
  let kv = pairs(text)
  assert_full_coverage(kv)
  // ---- the primitives, against the constants the vector file pins
  //
  // `sanity()` in gen_knownhosts_test.py pins these to FIPS 180-4 and RFC 2202,
  // so printing them means the third implementation is compared on the
  // primitives too, not only on the pinning decisions. Row names match the C
  // harness's V0a-V0e so the gate can line them up.
  println("V0a_sha1_empty_hex = " + hex(@knownhosts.sha1(b(""), 0)))
  println("V0b_sha1_abc_hex = " + hex(@knownhosts.sha1(b("abc"), 3)))
  // 56 bytes: the RFC 3174 multi-block vector, which is what actually exercises
  // the block loop rather than just the padding path.
  println(
    "V0c_sha1_long_hex = " +
    hex(@knownhosts.sha1(b("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), 56)),
  )
  println("V0d_hmac_case1_hex = " + hex(@knownhosts.hmac_sha1(fill(20, b'\x0b'), b("Hi There"), 8)))
  println(
    "V0e_hmac_case2_hex = " +
    hex(@knownhosts.hmac_sha1(b("Jefe"), b("what do ya want for nothing?"), 28)),
  )
  // V4a: HMAC-SHA1 over the salt and host, checked against the hash the vector
  // file carries. This is the same primitive V4's match depends on, so a drift
  // in it would otherwise only show as a mysterious "no match".
  println(
    "V4a_hmac_hex = " +
    hex(@knownhosts.hmac_sha1(hx(kv_get(kv, "V4_salt_hex")), b(kv_get(kv, "V4_host")), kv_get(kv, "V4_host").length())),
  )
  // ---- the pinning decisions
  for i = 0; i < cases.length(); i = i + 1 {
    let (id, line_key, blob_key, host_key, port_key, strict, extra_key) = cases[i]
    let mut content = val(kv, line_key) + "\n"
    if extra_key != "" {
      content = content + val(kv, extra_key) + "\n"
    }
    let entries = @knownhosts.parse_file(content)
    let status = @knownhosts.check_host_key_strict(
      entries,
      val(kv, host_key),
      parse_int(val(kv, port_key)),
      hx(val(kv, blob_key)),
      strict,
    )
    let base = base_id(id)
    let code = status_code(status)
    println(id + "_got_status = " + code)
    // `expected_status` 只在 base id 自己那行（或子案的 a 行）打一次：V10a 与 V10b
    // 共用一个被钉住的值，打两次就是重复键，而门禁的解析器**故意**拒绝重复键。
    // 反过来也不发 `V10_got_status`——门禁要的是两个子案各自对上那一个期望值，
    // 同键两行会让"最后一个赢"变成子案顺序的函数。
    //
    // 不发 `V7_strict_got_status`：V7 本来就是 strict 案，`_strict` 那行是它自己的
    // 重复，只是前缀不同骗过了解析器。
    if !ends_with(id, "b") {
      println(base + "_expected_status = " + kv_get(kv, base + "_expected_status"))
    }
  }
  // ---- V8: markers, which is not a check_host_key verdict at all
  //
  // The C harness asserts these four (V8a-V8d) by parsing `@revoked <V1 line>`
  // and `@cert-authority <V1 line>`. Same construction here.
  let v1_line = kv_get(kv, "V1_knownhosts_line")
  println("V8a_revoked_parsed = " + marker_parsed("@revoked " + v1_line))
  println("V8b_revoked_marker = " + marker_of("@revoked " + v1_line))
  println("V8c_certauth_parsed = " + marker_parsed("@cert-authority " + v1_line))
  println("V8d_certauth_marker = " + marker_of("@cert-authority " + v1_line))
  // C's harness checks empty entries inline (knownhosts_harness.c:673) against a
  // literal 2 rather than a vector key, so this row has no vector-file source
  // either. Named E1 so it cannot be confused with Loop #14's V9, which is a
  // different test that happens to share the number.
  println(
    "E1_empty_entries_got_status = " +
    status_code(@knownhosts.check_host_key([], "any.host", 0, hx(kv_get(kv, "V1_blob_hex")))),
  )
  println("ALL PASS")
}

///|
/// 用例表，逐行对应 `verify_c/knownhosts_harness.c` 里的一个 block。
///
/// `(id, line_key, blob_key, host_key, port_key, strict)`
///
/// `key:X` 从向量文件取，`lit:X` 是字面量。host 只有 V10b 是字面量——它就是
/// C 那边 harness.c:698 那个 `check_host_key_v2(..., "foo.example.com", V10_PORT, ...)`。
///
///| 刻意**不用** `<id>_*` 拼键名。向量文件里 V2 没有自己的行（它复用 V1 的），
///| V3/V6/V7 用的公钥是 `V1_blob_hex` 而不是自己的 `V*_blob_hex`。按 id 拼会喂进
///| 空条目表，然后被判成 `Unknown`——一个真判定，但不是这里要看的那个。
let cases : Array[(String, String, String, String, String, Bool, String)] = [
  // harness.c:583-591  V1 single host match
  ("V1", "key:V1_knownhosts_line", "key:V1_blob_hex", "key:V1_host", "lit:0", false, ""),
  // harness.c:592-602  V2 wildcard host —— 复用 V1 的行和 blob
  ("V2", "key:V1_knownhosts_line", "key:V1_blob_hex", "key:V2_host", "lit:0", false, ""),
  // harness.c:603-612  V3 `!` 前缀不影响其它匹配
  ("V3", "key:V3_knownhosts_line", "key:V1_blob_hex", "key:V3_host", "lit:0", false, ""),
  // harness.c:613-623  V4 `|1|` HMAC-SHA1 哈希主机
  ("V4", "key:V4_knownhosts_line", "key:V4_blob_hex", "key:V4_host", "lit:0", false, ""),
  // harness.c:624-633  V5 命中主机但公钥不同
  ("V5", "key:V5_knownhosts_line", "key:V5_presented_blob_hex", "key:V5_host", "lit:0", false, ""),
  // harness.c:634-643  V6 未知主机
  ("V6", "key:V6_knownhosts_line", "key:V1_blob_hex", "key:V6_host", "lit:0", false, ""),
  // harness.c:644-653  V7 strict：Unknown 升级成 Invalid
  ("V7", "key:V7_knownhosts_line", "key:V1_blob_hex", "key:V7_host", "lit:0", true, ""),
  // harness.c:677-687  V9 明文主机 + 默认端口
  ("V9", "key:V9_knownhosts_line", "key:V9_presented_blob_hex", "key:V9_host", "key:V9_port", false, ""),
  // harness.c:688-700  V10 `[host]:port` 两种写法各来一次
  ("V10a", "key:V10_knownhosts_line", "key:V10_presented_blob_hex", "key:V10_host", "lit:0", false, ""),
  ("V10b", "key:V10_knownhosts_line", "key:V10_presented_blob_hex", "lit:foo.example.com", "key:V10_port", false, ""),
  // harness.c:702-712  V11 端口不符
  ("V11", "key:V11_knownhosts_line", "key:V11_presented_blob_hex", "key:V11_host", "key:V11_port", false, ""),
  // harness.c:713-723  V12 `@revoked` 命中
  ("V12", "key:V12_knownhosts_line", "key:V12_presented_blob_hex", "key:V12_host", "key:V12_port", false, ""),
  // Loop #56 @cert-authority. C1: CA covers the host and there is no direct entry.
  ("C1", "key:C1_knownhosts_line", "key:C1_presented_blob_hex", "key:C1_host", "key:C1_port", false, ""),
  // C2: a direct entry and a CA entry for the same host; the direct one speaks.
  ("C2", "key:C2_knownhosts_line", "key:C2_presented_blob_hex", "key:C2_host", "key:C2_port", false, "key:C2_knownhosts_line_ca"),
  // C3: presenting the CA entry's OWN key. This one carries the loop -- before
  // Loop #51 it came back Ok, i.e. fail-open.
  ("C3", "key:C3_knownhosts_line", "key:C3_presented_blob_hex", "key:C3_host", "key:C3_port", false, ""),
]

///|
/// 向量文件里任何带 `_expected_status` 的向量都必须被用例表认领。
///
/// 少一行不会报错——它只是不跑。这是 Loop #56 里发射器最初的四类假判定里最安静
/// 的一类，所以在这里变成一次硬失败：新增向量忘了加用例，比用例写错更早暴露。
fn assert_full_coverage(kv : Array[String]) -> Unit {
  let mut i = 0
  while i + 1 < kv.length() {
    let key = kv[i]
    if ends_with(key, SUFFIX_STATUS) {
      let id = slice(key, 0, key.length() - SUFFIX_STATUS.length())
      if id != "V" && !claimed(id) {
        abort("vector " + id + " has an _expected_status but no row in the case table")
      }
    }
    i = i + 2
  }
}

///|
/// 长度 16。写成常量是因为上一版把它写成 15：截出来的是 `V1_`，覆盖检查于是对着一个
/// 永远匹配不上的 id 报「V1 没有用例行」——错得很像对，很难一眼看出是长度问题。
const SUFFIX_STATUS = "_expected_status"

///|
fn claimed(id : String) -> Bool {
  let mut i = 0
  while i < cases.length() {
    if cases[i].0 == id || base_id(cases[i].0) == id {
      return true
    }
    i = i + 1
  }
  false
}

///|
/// `V10a` / `V10b` 去掉子案后缀，回到向量文件里的 `V10`
fn base_id(id : String) -> String {
  if ends_with(id, "a") || ends_with(id, "b") {
    slice(id, 0, id.length() - 1)
  } else {
    id
  }
}

///|
/// `key:X` 取向量文件的值，`lit:X` 用字面量
fn val(kv : Array[String], spec : String) -> String {
  let body = slice(spec, 4, spec.length())
  if starts_with(spec, "key:") {
    kv_get(kv, body)
  } else if starts_with(spec, "lit:") {
    body
  } else {
    abort("bad spec, want key: or lit: -> " + spec)
  }
}

///|
fn status_code(s : @knownhosts.HostStatus) -> String {
  match s {
    Ok => "0"
    Mismatch => "1"
    Unknown => "2"
    InvalidEntry => "3"
    CertAuthority => "4"
  }
}

///|
fn marker_parsed(line : String) -> String {
  if @knownhosts.parse_file(line + "\n").length() == 1 { "1" } else { "0" }
}

///|
fn marker_of(line : String) -> String {
  let es = @knownhosts.parse_file(line + "\n")
  if es.length() != 1 {
    return "none"
  }
  match es[0].marker {
    None => "none"
    CertAuthority => "cert-authority"
    Revoked => "revoked"
  }
}

///|
/// `key = value` 解析成**两两相邻**的扁平数组：`out[2i]` 是键，`out[2i+1]` 是值。
///
/// 刻意做成扁平而不是一个 map：键里已经带了 `V1_host` 这样的前缀，不会冲突，
/// 而线性查找在这个规模上不贵，少一个类型就少一处能写错。**缺失的键返回空串**——
/// 那会让判定落到「不匹配」，而缺向量时本来就该那样响。
fn pairs(text : String) -> Array[String] {
  let out : Array[String] = []
  let mut i = 0
  let n = text.length()
  while i < n {
    let mut line = ""
    let start = i
    while i < n && text[i] != 10 {
      i = i + 1
    }
    line = slice(text, start, i)
    i = i + 1
    let t = trim(line)
    if t == "" || at(t, 0) == 35 || at(t, 0) == 91 || at(t, 0) == 61 {
      continue
    }
    match index_of_eq(t) {
      None => ()
      Some(eq) => {
        out.push(trim(slice(t, 0, eq)))
        out.push(trim(slice(t, eq + 1, t.length())))
      }
    }
  }
  out
}

///|
fn kv_get(kv : Array[String], key : String) -> String {
  let mut i = 0
  while i + 1 < kv.length() {
    if kv[i] == key {
      return kv[i + 1]
    }
    i = i + 2
  }
  ""
}

///|
/// 第一个 `=` 的下标
fn index_of_eq(s : String) -> Int? {
  let mut i = 0
  while i < s.length() {
    if at(s, i) == 61 {
      return Some(i)
    }
    i = i + 1
  }
  None
}

///|
/// 字符码；越界返回 0（调用点只比较 ASCII，不会走到）
fn at(s : String, i : Int) -> Int {
  if i >= 0 && i < s.length() {
    s[i].to_int()
  } else {
    0
  }
}

///|
fn starts_with(s : String, prefix : String) -> Bool {
  if prefix.length() > s.length() {
    return false
  }
  let mut i = 0
  while i < prefix.length() {
    if at(s, i) != at(prefix, i) {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn ends_with(s : String, suffix : String) -> Bool {
  if suffix.length() > s.length() {
    return false
  }
  let off = s.length() - suffix.length()
  let mut i = 0
  while i < suffix.length() {
    if at(s, off + i) != at(suffix, i) {
      return false
    }
    i = i + 1
  }
  true
}

///|
fn slice(s : String, from : Int, to : Int) -> String {
  let b = StringBuilder()
  let mut i = from
  let hi = if to > s.length() { s.length() } else { to }
  while i < hi {
    b.write_char(Int::unsafe_to_char(s[i].to_int()))
    i = i + 1
  }
  b.to_string()
}

///|
fn is_space(c : Int) -> Bool {
  c == 32 || c == 9 || c == 13
}

///|
fn trim(s : String) -> String {
  let mut a = 0
  let mut b = s.length()
  while a < b && is_space(at(s, a)) {
    a = a + 1
  }
  while b > a && is_space(at(s, b - 1)) {
    b = b - 1
  }
  slice(s, a, b)
}

///|
fn parse_int(s : String) -> Int {
  let mut acc = 0
  let mut i = 0
  while i < s.length() {
    let c = at(s, i)
    if c >= 48 && c <= 57 {
      acc = acc * 10 + (c - 48)
    }
    i = i + 1
  }
  acc
}

///|
/// 字符串按字节取（调用点全是 ASCII）
fn b(s : String) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  let mut i = 0
  while i < s.length() {
    arr[i] = at(s, i).to_byte()
    i = i + 1
  }
  arr
}

///|
fn fill(n : Int, v : Byte) -> FixedArray[Byte] {
  let arr : FixedArray[Byte] = FixedArray::make(n, v)
  let mut i = 0
  while i < n {
    arr[i] = v
    i = i + 1
  }
  arr
}

///|
fn hx(s : String) -> FixedArray[Byte] {
  if s.length() == 0 {
    return FixedArray::make(0, b'\x00')
  }
  let n = s.length() / 2
  let arr : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut i = 0
  while i < n {
    arr[i] = (hd(at(s, i * 2)) * 16 + hd(at(s, i * 2 + 1))).to_byte()
    i = i + 1
  }
  arr
}

///|
fn hex(a : FixedArray[Byte]) -> String {
  let b = StringBuilder()
  let mut i = 0
  while i < a.length() {
    b.write_char(hexdigit(Int::unsafe_to_char(a[i].to_int() >> 4)))
    b.write_char(hexdigit(Int::unsafe_to_char(a[i].to_int() & 15)))
    i = i + 1
  }
  b.to_string()
}

///|
fn hexdigit(c : Char) -> Char {
  let n = c.to_int()
  if n < 10 { Int::unsafe_to_char(48 + n) } else { Int::unsafe_to_char(87 + n) }
}

///|
fn hd(c : Int) -> Int {
  if c >= 48 && c <= 57 {
    c - 48
  } else if c >= 97 && c <= 102 {
    c - 87
  } else {
    abort("hx: not a hex digit")
  }
}

///|
fn argv(i : Int) -> String {
  let a = @env.args()
  if i < a.length() {
    a[i]
  } else {
    abort("usage: knownhosts_kat <vector-file>")
  }
}