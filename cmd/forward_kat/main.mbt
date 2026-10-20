///| cmd/forward_kat -- Loop #76: the direct-tcpip CHANNEL_OPEN, byte for byte.
///

///|

///|
/// Prints the exact payload bytes this client puts on the wire for a
/// "direct-tcpip" channel open, one line per case:
///
///     OPEN <label> <hex>
///
/// The expected bytes come from `host/gen_forward_vectors.py`, which builds
/// them with **paramiko's own encoder** (`paramiko.message.Message`) -- an
/// implementation that has nothing to do with this repository. That is the
/// point of this program: a wire format is a contract with other
/// implementations, and "our encoder agrees with our encoder" proves
/// nothing.
///
/// Why the bytes need pinning at all, when the real server already accepts
/// them: the server accepts a direct-tcpip open whose *destination* it read
/// correctly, but it is tolerant about the rest -- an originator it does not
/// understand, for instance. A layout that is right in the fields the server
/// uses and wrong in the ones it ignores would pass every end-to-end test and
/// still be a wrong wire format. Pinning the whole payload is what catches
/// that.
///

///|

///|
/// The four cases are chosen to cover the layout's edges, not to be pretty:
///
///   C1  the shape this client actually sends (a loopback destination)
///   C2  a different sender id, a small window, and the largest port
///   C3  a destination that is an IPv6 literal, and a zero port
///   C4  a long destination name, to move the string length prefix
///
/// C3 exists because an IPv6 literal contains colons, and a parser that
/// splits the destination on ':' would take "::1" apart. That is a parser
/// bug, not a wire-format bug -- but the bytes of a wrong split are exactly
/// what this program pins, so it is worth having.
fn main {
  emit("C1", 0, 2097152, 32768, "127.0.0.1", 24000, "127.0.0.1", 0)
  emit("C2", 7, 64, 32, "example.com", 65535, "10.0.0.1", 12345)
  emit("C3", 0, 2097152, 32768, "::1", 0, "127.0.0.1", 0)
  emit(
    "C4", 3, 4096, 8192, "a-very-long-destination-name.example.com", 443, "192.0.2.1",
    65534,
  )
}

///|
/// One case, one line. The label is part of the line so a mismatch names
/// the case instead of just "line 3 differs".
fn emit(
  label : String,
  sender : Int32,
  window : Int32,
  max_packet : Int32,
  dest_host : String,
  dest_port : Int32,
  originator_ip : String,
  originator_port : Int32,
) -> Unit {
  let payload = @channel.channel_open_direct_tcpip_payload(
    sender, window, max_packet, dest_host, dest_port, originator_ip, originator_port,
  )
  println("OPEN " + label + " " + @ecdsa.bytes_to_hex(payload))
}
