///| Loop #61: the kex and host key axes, which Loop #60 declared out of scope.
///
///|
///
/// Loop #60 enforced "a client proposal may only name algorithms the transport
/// can run" over cipher and MAC, and said in as many words that kex and hostkey
/// were left out. This file closes that gap.
///
///|
///
/// **What was actually there, checked before anything was written.** The gap
/// was not known to contain a defect. Hand-checked first:
///
///   * kex -- `curve25519-sha256` (`src/kexc25519`) and
///     `diffie-hellman-group14-sha256` (`src/kexdh`, group 14 only). Both are
///     real; `kexdh/group14.mbt` exposes `group14_prime` and nothing else, so
///     there is exactly one DH group this client speaks.
///   * hostkey -- `ssh-ed25519`, `ecdsa-sha2-nistp256`,
///     `ecdsa-sha2-nistp384`, `rsa-sha2-256`, `rsa-sha2-512`. `HostKey::verify`
///     implements ed25519 and ECDSA, and `verify_with_alg` adds the RSA path
///     (Loop #38) precisely because RFC 8332 means the negotiated name is not
///     the blob's type string. All five are backed.
///
/// So the finding of this loop is **not** "the lists were wrong". It is that
/// they were right by accident and by hand, which is the condition Loop #60 was
/// about. The host key names are now derived from `HostKey::agrees_with_alg`'s
/// own tables instead of being written down twice.
///
///|
///
/// **Why kex runnability lives here.** `src/bpacket` owns cipher and MAC
/// because those are the packet layer's. kex is owned by neither `kexc25519`
/// nor `kexdh` in a way that either could enumerate both, and this package
/// already depends on `kexc25519` and `hostkey` and is the package that owns
/// proposals. So the table sits with the thing that has to answer the question.
fn runnable_kex_names_table() -> Array[String] {
  ["curve25519-sha256", "diffie-hellman-group14-sha256"]
}

///|
/// The KEX algorithms this client can execute end to end.
///
/// `diffie-hellman-group14-sha256` is here because `src/kexdh` implements
/// RFC 3526 group 14 and `sshclient::live` drives it. The other seven names in
/// OpenSSH's default table are not, and saying so here is cheaper than having
/// a reader assume the list is an oversight -- `curve25519-sha256@libssh.org`,
/// the other `ecdh-sha2-nistp*` curves, group 16, and group-exchange all have
/// no implementation anywhere in this tree.
pub fn runnable_kex_names() -> Array[String] {
  runnable_kex_names_table()
}

///| Is this a KEX algorithm this client can execute?
pub fn is_runnable_kex(alg : String) -> Bool {
  runnable_kex_names_table().contains(alg)
}

///|
/// Is this a KEX **marker** rather than an algorithm?
///
/// `kex-strict-c-v00@openssh.com` rides in the kex list but is not a key
/// exchange: OpenSSH appends it in `kex_proposal_populate_entries` purely to
/// signal rfc8308 strict-KEX support, and `match_list` can never select it. The
/// authority agrees -- `ssh -Q kex` lists twelve algorithms and this is not one
/// of them.
///
/// The first version of this checker had no such rule and reported
/// `default_client/strict=true` as over-promising. That was a false positive
/// with a real cost: the fix anyone would reach for under pressure is to delete
/// the marker and turn off strict KEX, trading a security property for a green
/// gate. "Is there an implementation" and "is this an algorithm" are two
/// different questions and conflating them makes the invariant hostile.
pub fn is_pseudo_kex_alg(alg : String) -> Bool {
  alg == "kex-strict-c-v00@openssh.com"
}

///|
/// Is this an OpenSSH host **certificate** algorithm name?
///
/// A separate category, not a subset of the plain ones -- `ssh -Q key-plain`
/// and `ssh -Q key-cert` are two disjoint lists, and that is the whole reason.
/// `src/hostkey` parses and validates certificate structure (Loop #53), but
/// `flow_on_reply` and `live.mbt` deliberately do **not** accept a certificate
/// as a host key: `KnownHostsPolicy::has_ca_anchor` reports
/// `HostKeyCertUntrusted` instead.
///
/// So a certificate name is gated by **policy**, not by implementation, and it
/// is reported rather than called a violation. Calling it a violation would
/// mean `live_proposal_with_certs(true)` -- which exists precisely to let a
/// client ask, under a CA anchor -- could not be written at all.
pub fn is_cert_hostkey_alg(alg : String) -> Bool {
  alg.has_suffix("-cert-v01@openssh.com")
}

///|
/// A host key name this client cannot verify as a plain key.
///
/// Certificate names are excluded, and their exclusion is reported separately
/// by `policy_gated_hostkey_names` rather than swallowed here.
pub fn is_runnable_hostkey(alg : String) -> Bool {
  if is_cert_hostkey_alg(alg) {
    return false
  }
  @hostkey.is_verifiable_alg(alg)
}

///| The certificate names in `hostkey_list`, in order.
pub fn policy_gated_hostkey_names(hostkey_list : String) -> Array[String] {
  let out : Array[String] = []
  for name in split_alg_list(hostkey_list) {
    if is_cert_hostkey_alg(name) {
      out.push(name)
    }
  }
  out
}

///| The host key algorithm names this client can verify (see `src/hostkey`).
pub fn runnable_hostkey_names() -> Array[String] {
  @hostkey.verifiable_alg_names()
}

///|
/// The first KEX name in `kex_list` with no implementation, or `None`.
pub fn first_unrunnable_kex(kex_list : String) -> String? {
  for name in split_alg_list(kex_list) {
    if is_pseudo_kex_alg(name) {
      continue
    }
    if !is_runnable_kex(name) {
      return Some(name)
    }
  }
  None
}

///|
/// The first host key name in `hostkey_list` this client cannot verify.
///
/// The name is reported unadorned. Deciding whether an unverified name is a
/// security event or merely a capability gap belongs to the caller, because
/// the two live in different places: `negotiate` is the wrong place (a peer
/// may legitimately offer names we lack) and the report is the right one.
pub fn first_unrunnable_hostkey(hostkey_list : String) -> String? {
  for name in split_alg_list(hostkey_list) {
    // A certificate name is policy-gated, not unimplemented -- see
    // `is_cert_hostkey_alg`. Reporting it here would say `live_proposal_with_certs`
    // over-promises, which is the opposite of what Loop #53 decided.
    if is_cert_hostkey_alg(name) {
      continue
    }
    if !is_runnable_hostkey(name) {
      return Some(name)
    }
  }
  None
}

///|
/// Split a comma-separated proposal list. Same shape as the helper in
/// `src/bpacket`, duplicated because neither package may depend on the other
/// for a string split -- and a four-line loop is a better duplication than an
/// import cycle.
fn split_alg_list(list : String) -> Array[String] {
  let out : Array[String] = []
  let mut start = 0
  for i = 0; i <= list.length(); i = i + 1 {
    if i == list.length() || list[i] == ',' {
      if i > start {
        out.push(list[start:i].to_owned())
      }
      start = i + 1
    }
  }
  out
}

///|
/// The Loop #60 invariant, extended to all four name-lists that decide whether
/// a handshake can actually complete.
///
/// Returns the first offending name prefixed by its category, so the report can
/// say *which* list is over-promising. Cipher and MAC go through `src/bpacket`,
/// which owns them; kex and hostkey are answered here.
pub fn check_proposal_runnable(p : Proposal) -> String? {
  match @bpacket.check_runnable(p.enc_ctos, p.mac_ctos) {
    Some(bad) => return Some(bad)
    None => ()
  }
  match @bpacket.check_runnable(p.enc_stoc, p.mac_stoc) {
    Some(bad) => return Some(bad)
    None => ()
  }
  match first_unrunnable_kex(p.kex_algs) {
    Some(bad) => return Some("kex:" + bad)
    None => ()
  }
  match first_unrunnable_hostkey(p.hostkey_algs) {
    Some(bad) => return Some("hostkey:" + bad)
    None => ()
  }
  None
}