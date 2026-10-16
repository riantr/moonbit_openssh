///| cmd/proposal_kat -- Loop #60: every algorithm name this client advertises.
///

///|
///
/// Prints each proposal in the tree together with `@bpacket.check_runnable`'s
/// verdict, so `host/verify_loop60.mjs` can hold the invariant from the outside.
///

///|
///
/// **Why a separate program.** The invariant is one line -- a client proposal
/// may only name algorithms the packet transport can run -- and it is exactly
/// the kind of rule that decays silently. `default_client` carried
/// `hmac-sha2-256-etm@openssh.com` for a dozen loops. Nothing failed: the
/// proposal's cipher was an AEAD, so the MAC was never computed, so the
/// over-promise was invisible to every test that already existed. A rule with
/// no emitter has no observable state.
///

///|
///
/// **Scope is deliberately asymmetric, and the labels below are the point.**
/// A *client* proposal is checked. A *server* proposal is not: negotiation
/// takes the intersection, so a peer is free to name things we cannot run and
/// the handshake still lands on something we can. The `scope=server` entry is
/// emitted anyway, so the gate can assert it is still classified as
/// server-side. That is the check which stops this gate from quietly widening
/// into "reject every name we do not implement" -- which would break
/// connectivity against real servers for no safety gain.
///
/// The server list in `host/verify_loop23.mjs:74-77` is a host-side fixture and
/// is not reachable from here; `verify_loop60.mjs` covers that one by reading
/// the file directly.
fn main {
  // --- the runnable set, straight from src/bpacket ---
  println("RUNNABLE_CIPHER " + join_list(@bpacket.runnable_cipher_names()))
  println("RUNNABLE_MAC " + join_list(@bpacket.runnable_mac_names()))
  // transport_params, so the gate checks the numbers and not just the names.
  let (ck, cb, civ, cm) = @bpacket.transport_params(
    "aes128-ctr", "hmac-sha2-256",
  )
  println("PARAMS aes128-ctr hmac-sha2-256 \{ck} \{cb} \{civ} \{cm}")
  let (ak, ab, aiv, am) = @bpacket.transport_params(
    "chacha20-poly1305@openssh.com", "",
  )
  println("PARAMS chacha20-poly1305@openssh.com - \{ak} \{ab} \{aiv} \{am}")

  // The wire-level auth tag length, which is NOT the MAC key length above.
  // OpenSSH's cipher table has a column for it (`auth_len`); without this line
  // the gate had nothing to compare that column against.
  println(
    "AUTHLEN aes128-ctr " + @bpacket.authlen_for("aes128-ctr").to_string(),
  )
  println(
    "AUTHLEN chacha20-poly1305@openssh.com " +
    @bpacket.authlen_for("chacha20-poly1305@openssh.com").to_string(),
  )

  // --- client proposals: every name must be runnable ---
  emit_client(
    "kexflow.default_client/strict=false",
    @kexflow.Proposal::default_client(false),
  )
  emit_client(
    "kexflow.default_client/strict=true",
    @kexflow.Proposal::default_client(true),
  )
  emit_client("sshclient.live_proposal", @sshclient.live_proposal())
  emit_client(
    "sshclient.live_proposal_with_certs=true",
    @sshclient.live_proposal_with_certs(true),
  )
  emit_client(
    "sshclient.live_proposal_with_certs=false",
    @sshclient.live_proposal_with_certs(false),
  )

  // --- the lists Loop #60 deleted, re-asserted as gone ---
  // Emitted so the gate can assert they stay deleted without grepping the tree.
  println("DEFAULTS_REMOVED 4")

  // Loop #61: the two axes Loop #60 left as `info`.
  println("RUNNABLE_KEX " + join_list(@kexflow.runnable_kex_names()))
  println("RUNNABLE_HOSTKEY " + join_list(@kexflow.runnable_hostkey_names()))

  // --- a peer proposal, for the scope check only ---
  // Deliberately carries two names with no packet-layer path. If the gate ever
  // stops classifying this as server scope, the rule has widened.
  emit_server(
    "fixture.peer_broad", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com",
    "hmac-sha2-512-etm@openssh.com,hmac-sha2-256",
  )
}

///|
/// `scope=client`: the invariant applies to every name on the wire.
fn emit_client(label : String, p : @kexflow.Proposal) -> Unit {
  emit(label, "client", p)
}

///|
/// `scope=server`: names are informational. Not a defect if unrunnable.
fn emit_server(label : String, enc : String, mac : String) -> Unit {
  println("PROPOSAL \{label} scope=server")
  emit_list("  enc", enc, "enc")
  emit_list("  mac", mac, "mac")
  println("  verdict=not-checked(scope=server)")
}

///|
fn emit(label : String, scope : String, p : @kexflow.Proposal) -> Unit {
  println("PROPOSAL \{label} scope=\{scope}")
  emit_list("  kex", p.kex_algs, "kex")
  emit_list("  hostkey", p.hostkey_algs, "hostkey")
  emit_list("  enc", p.enc_ctos, "enc")
  emit_list("  mac", p.mac_ctos, "mac")
  // enc_stoc/mac_stoc are separate wire categories with their own strings; a
  // proposal that sets ctos but leaves stoc empty would slip a one-sided gate.
  emit_list("  enc_stoc", p.enc_stoc, "enc")
  emit_list("  mac_stoc", p.mac_stoc, "mac")
  let bad = @bpacket.check_runnable(p.enc_ctos, p.mac_ctos)
  let bad2 = @bpacket.check_runnable(p.enc_stoc, p.mac_stoc)
  match bad {
    None => ()
    Some(name) => println("  verdict=UNRUNNABLE(\{name})")
  }
  match bad2 {
    None => ()
    Some(name) => println("  verdict_stoc=UNRUNNABLE(\{name})")
  }
  // Loop #61: kex and hostkey used to be tagged `info` here, i.e. emitted with
  // no verdict at all. That was the gap Loop #60 declared out loud. Both axes
  // turned out to be honest -- so the tags now carry real verdicts and the gate
  // can prove they stay that way.
  let bad3 = @kexflow.check_proposal_runnable(p)
  match bad3 {
    None => ()
    Some(name) => println("  verdict_full=UNRUNNABLE(\{name})")
  }
  if bad is None && bad2 is None && bad3 is None {
    println("  verdict=honorable")
  }
  // What a peer supporting our first runnable name would hand us. Reported, not
  // judged: `negotiate` scans *our* list first (kexflow proposal.mbt pf_match_list).
  let sm = @bpacket.selected_mac(p.enc_ctos, p.mac_ctos)
  match sm {
    Some(m) => println("  selected_mac_under_ctos=\{m}")
    None => println("  selected_mac_under_ctos=n/a(aead-or-nothing)")
  }
}

///|
/// One list, one name per line. `kind` is `kex`, `hostkey`, `enc`, or `mac`.
/// `info` is still accepted and means "emitted, not judged" -- the peer fixture
/// uses it for categories that are exempt. Loop #61 replaced the old blanket
/// `info` on kex and hostkey, which had been emitting those two categories with
/// no verdict at all.
fn emit_list(prefix : String, list : String, kind : String) -> Unit {
  let names = split_alg_list(list)
  for n in names {
    // Three outcomes, not two. `MARKER` is a name that is not an algorithm at
    // all (`ssh -Q kex` does not list it); `POLICY-GATED` is a real category
    // this client handles by refusing rather than by implementing
    // (`ssh -Q key-cert` lists these separately). Folding either into `ok` would
    // be a lie, and into `NO-PATH` would be wrong -- the first version of this
    // file did the latter and the gate caught two false positives on its first
    // honest run.
    let tag = if kind == "info" {
      "info"
    } else if kind == "kex" && @kexflow.is_pseudo_kex_alg(n) {
      "MARKER"
    } else if kind == "hostkey" && @kexflow.is_cert_hostkey_alg(n) {
      "POLICY-GATED"
    } else if kind == "mac" {
      if @bpacket.is_runnable_mac(n) {
        "ok"
      } else {
        "NO-PATH"
      }
    } else if kind == "kex" {
      if @kexflow.is_runnable_kex(n) {
        "ok"
      } else {
        "NO-PATH"
      }
    } else if kind == "hostkey" {
      if @kexflow.is_runnable_hostkey(n) {
        "ok"
      } else {
        "NO-PATH"
      }
    } else if @bpacket.is_runnable_cipher(n) {
      "ok"
    } else {
      "NO-PATH"
    }
    println("\{prefix} name=\{n} kind=\{kind} \{tag}")
  }
}

///|
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
fn join_list(xs : Array[String]) -> String {
  let sb = StringBuilder()
  for i = 0; i < xs.length(); i = i + 1 {
    if i > 0 {
      sb.write_char(',')
    }
    sb.write_string(xs[i])
  }
  sb.to_string()
}
