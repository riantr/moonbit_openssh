///| Loop #93: the user authentication, in the SERVER role.
///
/// `src/userauth` builds the requests.  This file reads them, decides
/// whether to accept, and checks the signature.
///
/// ## What the server actually has to do
///
/// RFC 4252 §7's `publickey` method is a two-step dance:
///
///   1. the client sends a **probe** -- the key it wants to use, with the
///      boolean FALSE and no signature.  The server answers
///      `SSH_MSG_USERAUTH_PK_OK` if it recognises the key, or
///      `SSH_MSG_USERAUTH_FAILURE` if it does not;
///   2. the client sends the same request with the boolean TRUE and the
///      signature appended.  The server checks the signature over the
///      session identifier and the request fields, and answers
///      `SSH_MSG_USERAUTH_SUCCESS` or `SSH_MSG_USERAUTH_FAILURE`.
///
/// Both steps end in the same failure message, which is deliberate on the
/// peer's side: a server that says "that key is fine but your signature is
/// wrong" tells an attacker exactly which half to attack.
///
/// ## The signature's input, and why it is rebuilt rather than parsed
///
/// The client signs (RFC 4252 §7):
///
///     string    session identifier
///     byte      SSH_MSG_USERAUTH_REQUEST
///     string    user name
///     string    service name
///     string    "publickey"
///     boolean   TRUE
///     string    public key algorithm name
///     string    public key blob
///
/// The server does not have these bytes: what arrives is the signature
/// AFTER them.  So the server REBUILDS them and verifies the signature
/// against the rebuild.  That is why the rebuild lives in `src/userauth` --
/// the one implementation, used by the client to sign and by the server to
/// verify, so the two cannot drift apart.  A second copy here would be a
/// server that accepts keys the client did not sign for, and the symptom
/// would be a bare "Permission denied" with nothing to point at.
///
/// ## The session identifier is H, not K
///
/// The first field is the exchange hash of the key exchange -- the session
/// identifier -- and NOT the shared secret.  It is the thing both ends
/// computed and neither end transmitted.

///|
/// One key from an `authorized_keys` file.
pub(all) struct AuthorizedKey {
  /// The key type, e.g. `ssh-ed25519`.
  alg : String
  /// The SSH key blob: `string(type) || string(key bytes)`.
  blob : FixedArray[Byte]
}

///|
/// A `SSH_MSG_USERAUTH_REQUEST`, read off the wire.
pub(all) struct UserauthRequest {
  /// The user name the client claims.
  user : String
  /// The service name; `ssh-connection` for this method.
  service : String
  /// The method name; `publickey` for this one.
  method_name : String
  /// Whether the request carries a signature.
  has_signature : Bool
  /// The public key algorithm name (publickey only).
  alg : String
  /// The public key blob (publickey only).
  key_blob : FixedArray[Byte]
  /// The signature blob (publickey only, and only when `has_signature`).
  sig_blob : FixedArray[Byte]?
}

///|
/// Parse an `authorized_keys` file.
///
/// The format is one key per line:
///
///     ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... an optional comment
///
/// with three things that are easy to forget and all of which appear in
/// real files:
///
///   * lines starting with `#` are comments, and blank lines are allowed;
///   * a line may carry OPTIONS before the key type
///     (`command="...",no-pty ssh-ed25519 AAAA...`), so the key type is
///     the first token that LOOKS like a key type and not simply the first
///     token;
///   * a line whose base64 does not decode is skipped, not fatal -- one
///     broken line in a file of fifty keys must not lock the user out of
///     the other forty-nine.
///
/// The options themselves are not interpreted.  This server does not honour
/// `command=` or `no-pty`, and a key that carries options it will not
/// enforce is a key whose restrictions are silently dropped -- so a line
/// with options is REFUSED rather than accepted without them.
pub fn parse_authorized_keys(text : String) -> Array[AuthorizedKey] {
  let out : Array[AuthorizedKey] = []
  for raw in split_lines(text) {
    let line = raw.trim().to_owned()
    if line.is_empty() || line.has_prefix("#") {
      continue
    }
    let tokens = split_ws(line)
    if tokens.length() < 2 {
      continue
    }
    // Find the key type: the first token that names one.  A token before it
    // is an option list, and a key with options is a key this server would
    // have to honour to be worth accepting.
    let mut type_at = -1
    let mut i = 0
    while i < tokens.length() {
      if looks_like_key_type(tokens[i]) {
        type_at = i
        break
      }
      i = i + 1
    }
    if type_at < 0 {
      continue
    }
    if type_at > 0 {
      // Options are present and this server does not implement them.
      continue
    }
    if type_at + 1 >= tokens.length() {
      continue
    }
    match decode_key_blob(tokens[type_at + 1]) {
      None => continue
      Some(blob) => out.push({ alg: tokens[type_at], blob, })
    }
  }
  out
}

///|
/// Does this token name a key type?
fn looks_like_key_type(tok : String) -> Bool {
  tok.has_prefix("ssh-") ||
  tok.has_prefix("ecdsa-") ||
  tok.has_prefix("sk-") ||
  tok.has_prefix("rsa-")
}

///|
/// Decode the base64 of an `authorized_keys` line into an SSH key blob.
///
/// The blob's own structure is NOT checked here: it is checked when the
/// key is used, by `src/hostkey`, which is where the knowledge of what a
/// well-formed key blob is lives.
fn decode_key_blob(b64 : String) -> FixedArray[Byte]? {
  let view : StringView = b64
  let decoded = @base64.decode(view, ignore_whitespace=false) catch {
    _ => return None
  }
  let arr : FixedArray[Byte] = FixedArray::make(decoded.length(), b'\x00')
  for i = 0; i < decoded.length(); i = i + 1 {
    arr[i] = decoded[i]
  }
  Some(arr)
}

///|
/// Split a text into lines, on either CR LF or a bare LF.
fn split_lines(text : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = 0
  let mut i = 0
  while i < text.length() {
    if text[i] == '\n' {
      let mut end = i
      if end > start && text[end - 1] == '\r' {
        end = end - 1
      }
      out.push(text[start:end].to_owned())
      start = i + 1
    }
    i = i + 1
  }
  if start < text.length() {
    out.push(text[start:text.length()].to_owned())
  }
  out
}

///|
/// Split a line into whitespace-separated tokens.
fn split_ws(line : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = -1
  let mut i = 0
  while i < line.length() {
    let c = line[i]
    if c == ' ' || c == '\t' {
      if start >= 0 {
        out.push(line[start:i].to_owned())
        start = -1
      }
    } else if start < 0 {
      start = i
    }
    i = i + 1
  }
  if start >= 0 {
    out.push(line[start:line.length()].to_owned())
  }
  out
}

///|
/// Parse a `SSH_MSG_USERAUTH_REQUEST` payload.
///
/// Returns `None` when the payload is not a well-formed request.  Trailing
/// bytes are a failure and not something to ignore: a request with extra
/// bytes after the signature is a request whose fields this server has not
/// checked, and accepting it would mean accepting fields it does not read.
pub fn parse_userauth_request(payload : FixedArray[Byte]) -> UserauthRequest? {
  let (user_b, off1) = match sd_read_string(payload, 0) {
    None => return None
    Some(v) => v
  }
  let (service_b, off2) = match sd_read_string(payload, off1) {
    None => return None
    Some(v) => v
  }
  let (method_b, off3) = match sd_read_string(payload, off2) {
    None => return None
    Some(v) => v
  }
  let user = sd_bytes_to_string(user_b)
  let service = sd_bytes_to_string(service_b)
  let method_name = sd_bytes_to_string(method_b)
  if method_name != @userauth.AUTH_METHOD_PUBLICKEY {
    // A method this server does not implement: the fields after the method
    // name are the method's own, and there are none to read.
    if off3 != payload.length() {
      return None
    }
    return Some({
      user,
      service,
      method_name,
      has_signature: false,
      alg: "",
      key_blob: FixedArray::make(0, b'\x00'),
      sig_blob: None,
    })
  }
  // publickey: boolean, algorithm name, key blob, and maybe a signature.
  let flag = match sd_read_u8(payload, off3) {
    None => return None
    Some(v) => v
  }
  if flag != @userauth.SSH_BOOL_TRUE && flag != @userauth.SSH_BOOL_FALSE {
    return None
  }
  let has_signature = flag == @userauth.SSH_BOOL_TRUE
  let (alg_b, off4) = match sd_read_string(payload, off3 + 1) {
    None => return None
    Some(v) => v
  }
  let (key_blob, off5) = match sd_read_string(payload, off4) {
    None => return None
    Some(v) => v
  }
  let sig_blob = if has_signature {
    match sd_read_string(payload, off5) {
      None => return None
      Some((s, off6)) => {
        if off6 != payload.length() {
          return None
        }
        Some(s)
      }
    }
  } else {
    if off5 != payload.length() {
      return None
    }
    None
  }
  Some({
    user,
    service,
    method_name,
    has_signature,
    alg: sd_bytes_to_string(alg_b),
    key_blob,
    sig_blob,
  })
}

///|
/// Is this key blob on the authorized list?
///
/// ONE implementation of the rule, called from BOTH places that ask it: the
/// probe (`key_is_authorized`) and the signed request (`verify_publickey`).
///
/// They used to have their own comparisons, and that was a hole in the GATE
/// as well as in the code.  The real client always sends the probe first, so
/// removing either comparison ALONE changed nothing the client could see --
/// the other one still refused the key.  A rule written twice is a rule that
/// can be broken in a way nobody notices, and the mutation suite is exactly
/// the place where that shows up.
fn key_authorized(
  blob : FixedArray[Byte],
  authorized : Array[AuthorizedKey],
) -> Bool {
  for k in authorized {
    if k.blob == blob {
      return true
    }
  }
  false
}

///|
/// Check a `publickey` request against the authorized keys.
///
/// The order of the two questions matters, and it is the order OpenSSH
/// uses:
///
///   1. **Is this key authorized?**  A key that is not in the file is
///      refused without the signature being looked at.  Checking the
///      signature first would be wasted work on every unauthorized key, and
///      it would turn "you do not have access" into "your signature is
///      bad", which is a different and misleading answer.
///   2. **Is the signature good?**  The signed bytes are rebuilt from the
///      session identifier and the request's own fields.
///
/// The comparison of the key is on the BLOB, not on the algorithm name: the
/// blob carries the type inside it, so a name that disagrees with the blob
/// is a request whose fields do not agree with each other.
pub fn verify_publickey(
  req : UserauthRequest,
  session_id : FixedArray[Byte],
  authorized : Array[AuthorizedKey],
) -> Bool {
  if !req.has_signature {
    return false
  }
  let sig_blob = match req.sig_blob {
    None => return false
    Some(v) => v
  }
  // 1. is the key authorized?
  if !key_authorized(req.key_blob, authorized) {
    return false
  }
  // 2. is the signature good?
  let key = match @hostkey.HostKey::from_blob(req.key_blob) {
    @hostkey.Parsed(k) => k
    _ => return false
  }
  let to_sign = @userauth.userauth_signed_blob(
    session_id,
    req.user,
    req.service,
    req.alg,
    req.key_blob,
  )
  match @hostkey.HostKey::verify_with_alg(key, to_sign, sig_blob, req.alg) {
    @hostkey.Accepted => true
    _ => false
  }
}

///|
/// Is this key in the authorized list?
///
/// The probe step asks exactly this question, and answering it with the
/// blob comparison (rather than with the signature) is what lets a client
/// skip the signature entirely when the answer is no.
pub fn key_is_authorized(
  req : UserauthRequest,
  authorized : Array[AuthorizedKey],
) -> Bool {
  key_authorized(req.key_blob, authorized)
}
