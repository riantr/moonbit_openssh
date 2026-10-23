///| cmd/cancel_fwd_kat -- Loop #81: the "cancel-tcpip-forward" request, byte for byte.
///

///|
/// Prints the exact bytes this client puts on the wire when it cancels a
/// remote port forward, one line per case:
///
///     REQ  <label> <hex>   -- the "tcpip-forward" GLOBAL_REQUEST payload
///     CANC <label> <hex>   -- the "cancel-tcpip-forward" GLOBAL_REQUEST payload
///     HOST <label> <host>  -- the bind address after normalisation
///
/// The expected lines come from `host/gen_cancel_fwd_vectors.py`, which builds
/// them with **paramiko's own encoder** -- an implementation that shares no
/// code with this repository. Comparing our encoder with our encoder would
/// prove nothing.
///
/// ## Why the REQ lines are here too
///
/// A cancel is only meaningful **relative to the request it cancels**: the
/// server matches the address byte for byte and the port exactly, so a cancel
/// that is internally well-formed but points at the wrong address or the wrong
/// port is a correct-looking packet that silently does nothing.
///
/// So the gate does not only compare each payload against paramiko's; it also
/// checks that the tail of the cancel (address + port) is **the same bytes**
/// as the tail of the request it cancels. That relation is the whole point of
/// the request, and it is invisible if the two payloads are only compared
/// against a third party.
///

///|
fn main {
  // ---- REQ: the "tcpip-forward" request ----
  // R1 asks for port 0 (the server allocates one and says so in the reply);
  // R2 names an address; R3 is the pair that C4 cancels.
  emit_req("R1", "", 0)
  emit_req("R2", "127.0.0.1", 0)
  emit_req("R3", "127.0.0.1", 64337)
  // ---- CANC: the "cancel-tcpip-forward" request ----
  // C1 is the shape OpenSSH's own client sends: want_reply = 0, and the
  // server therefore answers with **nothing at all**.
  emit_cancel("C1", "", 0, false)
  emit_cancel("C2", "", 0, true)
  // C3/C4 cancel the forward R3 asked for -- same address, same port.
  emit_cancel("C3", "127.0.0.1", 64337, false)
  emit_cancel("C4", "127.0.0.1", 64337, true)
  // C5 is a named address and a named port, for the general shape.
  emit_cancel("C5", "localhost", 23456, true)
  // ---- HOST: the bind address after normalisation ----
  // "*" and "" both mean "any local address" and both go out as the empty
  // string; OpenSSH's `channel_rfwd_bind_host` does exactly this.
  emit_host("H1", "")
  emit_host("H2", "*")
  emit_host("H3", "127.0.0.1")
}

///|
/// One request, one line.
fn emit_req(label : String, listen_host : String, listen_port : Int32) -> Unit {
  let payload = @channel.tcpip_forward_request_payload(listen_host, listen_port)
  println("REQ " + label + " " + @ecdsa.bytes_to_hex(payload))
}

///|
/// One cancel, one line.
fn emit_cancel(
  label : String,
  listen_host : String,
  listen_port : Int32,
  want_reply : Bool,
) -> Unit {
  let payload = @channel.cancel_tcpip_forward_request_payload(
    listen_host, listen_port, want_reply,
  )
  println("CANC " + label + " " + @ecdsa.bytes_to_hex(payload))
}

///|
/// One normalisation, one line.
fn emit_host(label : String, listen_host : String) -> Unit {
  println("HOST " + label + " " + @channel.rfwd_bind_host(listen_host))
}
