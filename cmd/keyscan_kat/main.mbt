///| cmd/keyscan_kat -- Loop #82: the known_hosts line rules, byte for byte.
///

///|
/// Prints the formatting rules `ssh-keyscan` depends on, one case per line:
///
///     HOSTFIELD <label> <host> <port> <field>
///     LOWER     <label> <output>
///     KEYFIELD  <label> <host> <port> <field>
///
/// HOSTFIELD and LOWER are the two rules; KEYFIELD is the two composed, the
/// way the tool itself uses them.
///
/// The expected lines come from `host/gen_keyscan_vectors.py`, which implements
/// OpenSSH's `put_host_port` and `lowercase` in Python -- an implementation
/// that shares no code with this repository.
///
/// ## Why these need pinning at all
///
/// The end-to-end test already compares this client's whole output against the
/// real `ssh-keyscan`, byte for byte. That covers the **non-standard port**
/// shape, because the test server listens on a high port. Two rules it cannot
/// reach:
///
///   * the **default port** shape (a bare host name, no brackets) -- that
///     would need a server on port 22, which is a privileged port and not
///     something a gate may bind;
///   * the **lowercasing** -- that needs a host name with upper-case letters
///     that still resolves to the test server, and on this machine `LOCALHOST`
///     resolves to `::1` first, where the server is not listening. Both the
///     real tool and this one fail there, identically, which is a fine
///     property to have and a useless one to test.
///
/// So the two rules are pinned here instead, where they can be stated as
/// cases. A rule that is only ever exercised through one shape is a rule whose
/// other shape has never been looked at.
///

///|
fn main {
  // ---- HOSTFIELD: the hosts field of a known_hosts line ----
  // H1/H2 are the default-port shapes (a bare host name); H3/H4/H5 are the
  // bracketed shape a non-standard port needs.
  emit_host_field("H1", "127.0.0.1", 0)
  emit_host_field("H2", "127.0.0.1", 22)
  emit_host_field("H3", "127.0.0.1", 2222)
  emit_host_field("H4", "example.com", 2222)
  // H5 is an IPv6 literal: the brackets are what keeps the port from being
  // read as part of the address.
  emit_host_field("H5", "::1", 2222)
  // ---- LOWER: OpenSSH's `lowercase` ----
  // L3 is the whole field (host *and* port) lowercased, which is what
  // ssh-keyscan does -- it lowercases the hostport, not just the host.
  emit_lower("L1", "Example.COM")
  emit_lower("L2", "127.0.0.1:2222")
  emit_lower("L3", "[Example.COM]:2222")
  // ---- KEYFIELD: the two rules composed, the way the tool uses them ----
  // The driver calls `keyscan_host_field`, which is `lowercase` applied to
  // `put_host_port`.  These three are the composition the driver actually
  // performs, stated as cases so the composition itself is pinned -- not just
  // each half of it.
  //
  // K1 is the bracketed shape with upper-case letters (the one the
  // end-to-end test cannot reach: the only host this client can connect to is
  // a numeric IPv4 literal, which has no letters to fold).  K2 is the
  // default-port shape, K3 the zero-port shape.
  emit_key_field("K1", "Example.COM", 2222)
  emit_key_field("K2", "Example.COM", 22)
  emit_key_field("K3", "127.0.0.1", 0)
}

///|
/// One hosts field, one line.
fn emit_host_field(label : String, host : String, port : Int32) -> Unit {
  println(
    "HOSTFIELD " +
    label +
    " " +
    host +
    " " +
    port.to_string() +
    " " +
    @knownhosts.host_field(host, port),
  )
}

///|
/// One lowercased string, one line.
fn emit_lower(label : String, text : String) -> Unit {
  println("LOWER " + label + " " + @knownhosts.lowercase_ascii(text))
}

///|
/// One hosts field as the tool writes it: `put_host_port` then `lowercase`.
fn emit_key_field(label : String, host : String, port : Int32) -> Unit {
  println(
    "KEYFIELD " +
    label +
    " " +
    host +
    " " +
    port.to_string() +
    " " +
    @knownhosts.keyscan_host_field(host, port),
  )
}
