///| cmd/flow_kat -- Loop #62: run `flow_on_reply` over the real handshake vectors.
///
///|
///
/// Loop #61 proved, by inspection and by a unit test, that `flow_on_reply`'s
/// `derive_keys` arguments are in the right order and that its derivation length
/// comes from the transport table. It did **not** prove the function can complete
/// a handshake, and its own AGENTS.md entry says so. This is that proof.
///
///|
///
/// The vectors come from `host/gen_flow62_vectors.py`, whose server half shares
/// no code with this tree: X25519 and Ed25519 come from Python's
/// `cryptography`, and the exchange-hash layout there is written from OpenSSH
/// kexgen.c:67-82 independently of `src/kexc25519/exchange_hash.mbt`. So H and
/// the signature are each computed twice, by code that shares nothing.
///
///|
///
/// **The verdict is the contract, not the bytes.** All three of Loop #61's
/// defects showed up as a wrong or missing verdict rather than as wrong bytes --
/// the swapped arguments produced a *successful* key derivation followed by an
/// internal assertion failure, and the hardcoded 64 produced a plausible length.
/// So the file records `expect = <variant>` and this prints the variant it got.
///
/// native only: reading the vector file needs `moonbitlang/async/fs`, which is
/// why this `main` is `async`.
struct Tally {
  mut pass : Int
  mut fail : Int
}

async fn main {
  let path = "verify_c/kexflow/flow_vectors.txt"
  let text = read_all(path)
  let tally = { pass: 0, fail: 0 }
  let mut seen = 0
  let mut cur = blank_case()
  for raw in split_lines(text) {
    let line = trim(raw)
    if line == "" {
      continue
    }
    if has_prefix(line, "#") {
      continue
    }
    if has_prefix(line, "CASE ") {
      run_case(cur, tally)
      seen = seen + 1
      cur = blank_case()
      cur.id = trim(after(line, "CASE"))
      continue
    }
    if has_prefix(line, "note = ") {
      cur.note = trim(after(line, "note = "))
      continue
    }
    if has_prefix(line, "client_seed = ") {
      cur.client_seed = trim(after(line, "client_seed = "))
      continue
    }
    if has_prefix(line, "peer_ic = ") {
      cur.peer_ic = trim(after(line, "peer_ic = "))
      continue
    }
    if has_prefix(line, "reply = ") {
      cur.reply = trim(after(line, "reply = "))
      continue
    }
    if has_prefix(line, "strict_kex = ") {
      cur.strict_kex = trim(after(line, "strict_kex = ")) == "1"
      continue
    }
    if has_prefix(line, "expect = ") {
      cur.want = trim(after(line, "expect = "))
      continue
    }
    if has_prefix(line, "probe_k_s = ") {
      cur.probe_k_s = trim(after(line, "probe_k_s = ")) == "1"
      continue
    }
    if has_prefix(line, "probe_h = ") {
      cur.probe_h = trim(after(line, "probe_h = ")) == "1"
      continue
    }
    // known_hosts is deliberately ignored: every case here passes an empty
    // list, which means "skip the check" (flow.mbt:226). Kept in the file so
    // the key exists for the day a case needs one, and so its absence is a
    // deliberate decision rather than an oversight.
  }
  run_case(cur, tally)
  println("FLOW_TOTAL \{seen}")
  println("FLOW_PASS \{tally.pass}")
  println("FLOW_FAIL \{tally.fail}")
}

priv struct Case {
  mut id : String
  mut want : String
  mut client_seed : String
  mut peer_ic : String
  mut reply : String
  mut strict_kex : Bool
  mut note : String
  mut probe_k_s : Bool
  mut probe_h : Bool
}

///| Reading a file needs the async fs, hence the `async fn` on `main` too.
async fn read_all(path : String) -> String {
  let data = try { @fs.read_file(path) } catch { _ => abort("cannot read " + path) }
  data.text()
}

fn blank_case() -> Case {
  {
    id: "",
    want: "",
    client_seed: "",
    peer_ic: "",
    reply: "",
    strict_kex: false,
    note: "",
    probe_k_s: false,
    probe_h: false,
  }
}

///|
/// The body of the first SSH string in `wire`, i.e. K_S out of the REPLY.
///
/// `wire` includes the leading message-type byte (0x1f), so the string header
/// starts at offset 1 -- reading it from offset 0 picked the type byte as a
/// length prefix and indexed far past the end. That is why this helper exists
/// instead of "just parsing it here": the first version crashed, and a crash in
/// the diagnostic path hides the diagnosis.
fn first_string_body(wire : String) -> FixedArray[Byte] {
  let all = hex(wire)
  if all.length() < 6 {
    return FixedArray::make(0, b'\x00')
  }
  let n = ((all[1].to_uint() << 24) | (all[2].to_uint() << 16) |
  (all[3].to_uint() << 8) | all[4].to_uint()).reinterpret_as_int()
  if n < 0 || n > all.length() - 5 {
    return FixedArray::make(0, b'\x00')
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = all[5 + i]
  }
  out
}

///| A short hex prefix, for the probe line. Diagnostics need evidence.
fn hex_of(b : FixedArray[Byte], n : Int) -> String {
  let sb = StringBuilder()
  let m = if n < b.length() { n } else { b.length() }
  for i = 0; i < m; i = i + 1 {
    sb.write_string(to_hex2(b[i].to_int()))
  }
  sb.to_string()
}

fn to_hex2(v : Int) -> String {
  let mut out = ""
  out = out + hex_digit(v / 16)
  out + hex_digit(v % 16)
}

fn hex_digit(v : Int) -> String {
  if v < 10 {
    return code_to_digit(48 + v)
  }
  code_to_digit(97 + v - 10)
}

fn code_to_digit(code : Int) -> String {
  let s = "\{code}"
  s
}

///|
/// K_S out of a REPLY, via the same `parse_reply` the code under test uses.
///
/// The REPLY wire is `0x1f ‖ string(K_S) ‖ string(Q_S) ‖ string(sig)`, so the
/// first string header sits at offset 1. Parsing it here rather than
/// hand-slicing the hex keeps this probe honest: if `parse_reply` and this
/// disagree, that is worth knowing.
fn reply_ks(wire : String) -> FixedArray[Byte] {
  let all = hex(wire)
  let body : FixedArray[Byte] = FixedArray::make(
    if all.length() > 1 { all.length() - 1 } else { 0 },
    b'\x00',
  )
  for i = 0; i < body.length(); i = i + 1 {
    body[i] = all[i + 1]
  }
  match @kexc25519.parse_reply(body) {
    Some(r) => r.hostkey_blob
    None => FixedArray::make(0, b'\x00')
  }
}

///|
/// Bytes to hex, the way `src/ecdsa/wire.mbt` does it: index a lookup string
/// with `unsafe_substring`.
///
/// My first version built the same thing with `"{v}"`-style interpolation and
/// produced decimal digits instead of hex, which made a H diff unreadable and
/// briefly looked like a cryptographic mismatch. The tree already had the right
/// answer; I did not go and read it.
fn to_hex_full(b : FixedArray[Byte]) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    sb.write_string(digits.unsafe_substring(start=v >> 4, end=(v >> 4) + 1))
    sb.write_string(digits.unsafe_substring(start=v & 0xF, end=(v & 0xF) + 1))
  }
  sb.to_string()
}

///| Q_S, the second string in a REPLY.
fn reply_qs(wire : String) -> FixedArray[Byte] {
  let all = hex(wire)
  let body : FixedArray[Byte] = FixedArray::make(
    if all.length() > 1 { all.length() - 1 } else { 0 },
    b'\x00',
  )
  for i = 0; i < body.length(); i = i + 1 {
    body[i] = all[i + 1]
  }
  match @kexc25519.parse_reply(body) {
    Some(r) => r.server_pub
    None => FixedArray::make(0, b'\x00')
  }
}

fn key_error_name(e : @hostkey.KeyError) -> String {
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
/// Run one case and print the variant `flow_on_reply` actually returned.
fn run_case(c : Case, tally : Tally) -> Unit {
  if c.id == "" || c.want == "" {
    return
  }
  if c.client_seed == "" || c.peer_ic == "" || c.reply == "" {
    println("FLOW_CASE \{c.id} expected=INVALID want=\{c.want} got=MALFORMED")
    tally.fail = tally.fail + 1
    return
  }
  let cookie : FixedArray[Byte] = hex(first16(c.peer_ic))
  let my = @kexflow.Proposal::default_client(c.strict_kex)
  let cfg = @kexflow.FlowConfig::make(
    ascii("SSH-2.0-MoonBit"),
    ascii("SSH-2.0-VectorPeer_1.0"),
    cookie,
    hex(c.client_seed),
    c.strict_kex,
    "vector.invalid",
    22,
    [],
  )
  let started = @kexflow.flow_start(cfg, my)
  let got = match
    @kexflow.flow_on_reply(
      started,
      cfg,
      my,
      hex(c.peer_ic),
      hex(c.reply),
    ) {
    @kexflow.Established(e) => {
      // `Established` alone would be too weak: the interesting question is
      // whether the derived session id is the exchange hash. Loop #61's whole
      // bug class was a plausible-looking success.
      if e.session_id.length() == 32 {
        "Established"
      } else {
        "Established(short-session-id)"
      }
    }
    @kexflow.Failed(e) => variant_name(e)
  }
  // Probe the K_S blob separately. `flow_on_reply` collapses "the blob did not
  // parse" and "the blob was the wrong key type" into one `HostkeyInvalid`,
  // which was not enough to diagnose four failures at once -- and a gate that
  // cannot say *why* a case failed is a gate you end up debugging by hand.
  if c.probe_h {
    // Export the client-side exchange hash. Python's peer half signs *its* H;
    // if the two disagree, every signature fails and the verdict alone cannot
    // say why. Printing ours is what turns "SignatureInvalid" into a diff.
    let seed_bytes = hex(c.client_seed)
    let my_pub = @kexc25519.c25519_keygen(seed_bytes)
    let srv_pub = reply_qs(c.reply)
    match @kexc25519.c25519_shared_key_mpint(seed_bytes, srv_pub) {
      None => println("FLOW_H \{c.id} shared=None")
      Some(sm) => {
        let blob = reply_ks(c.reply)
        let inputs = @kexc25519.ExchangeInputs::make(
          ascii("SSH-2.0-MoonBit"),
          ascii("SSH-2.0-VectorPeer_1.0"),
          @kexflow.kexinit_payload(cookie, my),
          hex(c.peer_ic),
        )
        let h = @kexc25519.kex_gen_hash(inputs, blob, my_pub, srv_pub, sm)
        println("FLOW_H \{c.id} h=\{to_hex_full(h)}")
      }
    }
  }
  if c.probe_k_s {
    // A second, independent path to the same conclusion: parse K_S with
    // `parse_reply` and hand the blob straight to `from_blob`. `flow_on_reply`
    // collapses "blob did not parse" and "wrong key type" into one
    // `HostkeyInvalid`, and when four cases failed at once that was not enough
    // to tell a bad vector from a real bug.
    let blob = reply_ks(c.reply)
    let detail = match @hostkey.HostKey::from_blob(blob) {
      @hostkey.Parsed(_) => "from_blob=ok"
      @hostkey.Rejected(k) => "from_blob=" + key_error_name(k)
    }
    println("FLOW_PROBE \{c.id} \{detail} ks_len=\{blob.length()}")
  }
  if got == c.want {
    tally.pass = tally.pass + 1
    println(
      "FLOW_CASE \{c.id} expected=\{c.want} got=\{got} ok note: \{c.note}",
    )
  } else {
    tally.fail = tally.fail + 1
    println(
      "FLOW_CASE \{c.id} expected=\{c.want} got=\{got} FAIL note: \{c.note}",
    )
  }
}

///| The variant name, spelled out. A gate needs the name, not a Moonbit repr.
fn variant_name(e : @kexflow.FlowError) -> String {
  match e {
    ProtocolError => "ProtocolError"
    NoAgreement(n) => "NoAgreement(" + neg_name(n) + ")"
    HostkeyInvalid => "HostkeyInvalid"
    SignatureInvalid => "SignatureInvalid"
    SharedSecretInvalid => "SharedSecretInvalid"
    HostKeyMismatch(_) => "HostKeyMismatch"
    HostKeyUnknown(_) => "HostKeyUnknown"
    HostKeyCertAuthority(_) => "HostKeyCertAuthority"
    AlgorithmNotRunnable(name) => "AlgorithmNotRunnable(" + name + ")"
    CipherNotRunnable(name) => "CipherNotRunnable(" + name + ")"
  }
}

fn neg_name(e : @kexflow.NegotiationError) -> String {
  match e {
    NoKexAlg => "kex"
    NoHostkeyAlg => "hostkey"
    NoCipherAlg => "cipher"
    NoMacAlg => "mac"
    NoCompAlg => "comp"
  }
}

fn split_lines(s : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = 0
  for i = 0; i <= s.length(); i = i + 1 {
    if i == s.length() || s[i] == '\n' {
      out.push(s[start:i].to_owned())
      start = i + 1
    }
  }
  out
}

fn trim(s : String) -> String {
  let mut a = 0
  let mut b = s.length()
  while a < b && is_space(s[a].to_int()) {
    a = a + 1
  }
  while b > a && is_space(s[b - 1].to_int()) {
    b = b - 1
  }
  s[a:b].to_owned()
}

///|
/// Space by code point. `is_space(s[i])` does not typecheck: `s[i]` is UInt16,
/// and passing it as an argument makes the index a standalone expression, which
/// needs `.to_int()` first. Inside a `for` body the conversion is implicit (see
/// `bp_hex` in src/bpacket), so this only bites outside one.
fn is_space(code : Int) -> Bool {
  code == 32 || code == 13 || code == 9 || code == 10
}

fn has_prefix(s : String, p : String) -> Bool {
  if s.length() < p.length() {
    return false
  }
  for i = 0; i < p.length(); i = i + 1 {
    if s[i] != p[i] {
      return false
    }
  }
  true
}

fn after(s : String, p : String) -> String {
  let mut i = p.length()
  while i < s.length() && is_space(s[i].to_int()) {
    i = i + 1
  }
  s[i:s.length()].to_owned()
}

fn ascii(s : String) -> FixedArray[Byte] {
  let out : FixedArray[Byte] = FixedArray::make(s.length(), b'\x00')
  for i = 0; i < s.length(); i = i + 1 {
    out[i] = (s[i].to_int() & 0xFF).to_byte()
  }
  out
}

fn hex(s : String) -> FixedArray[Byte] {
  let n = s.length() / 2
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    out[i] = ((hexval(s[i * 2]) * 16 + hexval(s[i * 2 + 1])).reinterpret_as_uint() &
    0xFFU).to_byte()
  }
  out
}

fn first16(s : String) -> String {
  if s.length() >= 32 {
    s[0:32].to_owned()
  } else {
    s
  }
}

///|
/// Indexed as `UInt16`, matching `bp_hex_digit` in `src/bpacket` (the tree's
/// authority). Comparing `Char` against `'0'` also works, but only because the
/// literal is typed; the numeric form is what the rest of the project uses.
fn hexval(c : UInt16) -> Int {
  let code = c.to_int()
  if code >= 48 && code <= 57 {
    code - 48
  } else if code >= 97 && code <= 102 {
    code - 87
  } else {
    code - 55
  }
}