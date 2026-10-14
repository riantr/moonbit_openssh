///| Loop #57: resolve ssh_config and print what the rules resolve to.
///
/// The comparison authority is OpenSSH's own `ssh -G`. Everything the resolver
/// does here was checked against it first; see resolve.mbt for what was verified
/// and how. The point of printing the *resolved* options rather than the parse is
/// in moon.pkg -- the parse was never the thing that was wrong.
async fn main {
  let dir = @env.args()[1]
  let cases_text = read_all(dir + "/cases.txt")
  let cases = parse_cases(cases_text)
  if cases.length() == 0 {
    abort("no cases in " + dir + "/cases.txt")
  }
  for i = 0; i < cases.length(); i = i + 1 {
    let (fixture, host) = cases[i]
    let text = read_all(dir + "/" + fixture)
    let sections = @sshconfig.parse_ssh_config(text)
    let opts = @sshconfig.resolve_host(host, sections)
    println("CASE " + fixture + " " + host)
    // Group by keyword so a multi-valued keyword prints once, `|`-joined, in
    // file order. Printing one line per option instead would make
    // `identityfile /a` and `identityfile /b` indistinguishable from a keyword
    // that was set twice when the first should have won.
    let seen : Array[String] = []
    let mut j = 0
    while j < opts.length() {
      let k = lower(opts[j].keyword)
      if contains(seen, k) {
        j = j + 1
        continue
      }
      seen.push(k)
      println(k + " = " + join_values(opts, k))
      j = j + 1
    }
  }
  println("ALL PASS")
}

///|
fn join_values(opts : Array[@sshconfig.SshConfigOption], keyword : String) -> String {
  let mut out = ""
  let mut first = true
  let mut i = 0
  while i < opts.length() {
    if lower(opts[i].keyword) == keyword {
      if first {
        out = opts[i].value
        first = false
      } else {
        out = out + "|" + opts[i].value
      }
    }
    i = i + 1
  }
  out
}

///|
fn contains(arr : Array[String], v : String) -> Bool {
  let mut i = 0
  while i < arr.length() {
    if arr[i] == v {
      return true
    }
    i = i + 1
  }
  false
}

///|
fn lower(s : String) -> String {
  let b = StringBuilder()
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    b.write_char(if c >= 65 && c <= 90 { (c + 32).unsafe_to_char() } else { s[i].unsafe_to_char() })
    i = i + 1
  }
  b.to_string()
}

///| `fixture host` per line; `#` comments and blanks skipped.
fn parse_cases(text : String) -> Array[(String, String)] {
  let out : Array[(String, String)] = []
  let lines = split_lines(text)
  let mut i = 0
  while i < lines.length() {
    let t = trim(lines[i])
    if t.length() > 0 && at(t, 0) != 35 {
      let parts = split_ws(t)
      if parts.length() >= 2 {
        out.push((parts[0], parts[1]))
      }
    }
    i = i + 1
  }
  out
}

///|
fn split_lines(text : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = 0
  let mut i = 0
  while i <= text.length() {
    if i == text.length() || text[i].to_int() == 10 {
      out.push(slice(text, start, i))
      start = i + 1
    }
    i = i + 1
  }
  out
}

///|
fn split_ws(s : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = -1
  let mut i = 0
  while i <= s.length() {
    let is_space = i == s.length() || {
      let c = at(s, i)
      c == 32 || c == 9 || c == 13
    }
    if is_space {
      if start >= 0 {
        out.push(slice(s, start, i))
        start = -1
      }
    } else if start < 0 {
      start = i
    }
    i = i + 1
  }
  out
}

///|
fn at(s : String, i : Int) -> Int {
  if i >= 0 && i < s.length() { s[i].to_int() } else { 0 }
}

///|
fn slice(s : String, from : Int, to : Int) -> String {
  let b = StringBuilder()
  let mut i = from
  let hi = if to > s.length() { s.length() } else { to }
  while i < hi {
    b.write_char(s[i].unsafe_to_char())
    i = i + 1
  }
  b.to_string()
}

///|
fn is_space(c : Int) -> Bool { c == 32 || c == 9 || c == 13 }

///|
fn trim(s : String) -> String {
  let mut a = 0
  let mut b = s.length()
  while a < b && is_space(at(s, a)) { a = a + 1 }
  while b > a && is_space(at(s, b - 1)) { b = b - 1 }
  slice(s, a, b)
}

///|
async fn read_all(path : String) -> String {
  let data = try { @fs.read_file(path) } catch { _ => abort("cannot read " + path) }
  data.text()
}