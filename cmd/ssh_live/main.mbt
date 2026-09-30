///| cmd/ssh_live -- Loop #31 real handshake against a live OpenSSH server

///|

///|   Usage: ssh_live <port>   (default 22222)
///

///|   Every field printed here came off a real socket. `result: ESTABLISHED`

///|   means an OpenSSH 8.0p1 server accepted our KEXINIT, we computed the same

///|   exchange hash it did, and it signed that hash with an ECDSA P-256 host key

///|   that our own verifier accepted.

///|
/// DH private exponent. A production client draws this from the CSPRNG and
/// never reuses it; fixing it here keeps the byte transcript reproducible so a
/// diff against the paramiko capture is meaningful. The value is well above
/// 2^ so it is not a toy magnitude for a 2048-bit group.
fn fixed_x() -> @bigint.BigNat {
  let bytes : FixedArray[Byte] = FixedArray::from_array([
    0x5A, 0x17, 0xC3, 0x9E, 0x44, 0xB2, 0x6D, 0xF1, 0x08, 0xA7, 0x35, 0xCC, 0x91,
    0x2E, 0x60, 0xD3, 0x74, 0x18, 0x9F, 0xE2, 0x50, 0xB7, 0xC6, 0x3D, 0x81, 0x0A,
    0xF5, 0x29, 0x64, 0xC8, 0x7B, 0x1E,
  ])
  @bigint.BigNat::from_bytes_be(bytes)
}

///|
fn live_error_name(e : @sshclient.LiveError) -> String {
  match e {
    ConnectFailed => "ConnectFailed"
    NoServerIdent => "NoServerIdent"
    KexinitSendFailed => "KexinitSendFailed"
    NoPeerKexinit => "NoPeerKexinit"
    KexinitParseFailed => "KexinitParseFailed"
    NoAgreement(_) => "NoAgreement"
    EcdhInitSendFailed => "EcdhInitSendFailed"
    NoEcdhReply => "NoEcdhReply"
    EcdhReplyMalformed => "EcdhReplyMalformed"
    HostkeyInvalid => "HostkeyInvalid"
    SignatureInvalid(h) => "SignatureInvalid"
    NewkeysSendFailed => "NewkeysSendFailed"
    NoNewkeys => "NoNewkeys"
  }
}

///|
/// Decimal string to Int, or `fallback` if it is not a bare 1-5 digit number.
/// Kept local rather than reaching for a parser from the standard library,
/// whose surface differs across MoonBit releases and this driver only ever
/// needs a port number. `fallback = 0` means "not a port", which lets the
/// caller scan argv without a separate validity flag.
fn parse_port(s : String, fallback : Int) -> Int {
  let n = s.length()
  if n == 0 || n > 5 {
    return fallback
  }
  let mut acc = 0
  let mut i = 0
  while i < n {
    let c = s[i].to_int()
    if c < 48 || c > 57 {
      return fallback
    }
    acc = acc * 10 + (c - 48)
    i = i + 1
  }
  acc
}

///|
/// Pick the port out of argv, whatever the backend's argv looks like.
///
/// The native backend passes [exe_path, ...user]. The js backend passes
/// process.argv, so argv[1] is the script path rather than a user argument,
/// and blindly indexing argv[1] silently falls back to the default port
/// instead of honouring what the caller asked for. Scanning for the first
/// argument that actually parses as a port is backend-agnostic and cannot
/// pick up a path component by accident -- a path segment is not all digits.
fn find_port(argv : Array[String]) -> Int {
  let mut i = 1
  while i < argv.length() {
    match parse_port(argv[i], 0) {
      0 => ()
      p => return p
    }
    i = i + 1
  }
  22222
}

///|
fn main {
  let argv = @env.args()
  let port = find_port(argv)
  println("=== Loop #31 live SSH handshake vs real sshd ===")
  println("port: " + port.to_string())
  match @tcp.TcpConn::connect("127.0.0.1", port) {
    None => {
      println("result: CONNECT_FAILED")
      return
    }
    Some(conn) => {
      let outcome = @sshclient.live_handshake(conn, fixed_x())
      conn.close()
      match outcome {
        @sshclient.Established(r) => {
          println("result: ESTABLISHED")
          println("server_ident: " + r.server_ident)
          println("client_ident: " + r.client_ident)
          println("kex_alg: " + r.kex_alg)
          println("hostkey_alg: " + r.hostkey_alg)
          println("hostkey_type: " + r.hostkey_type)
          println("hostkey_bits: " + r.hostkey_bits.to_string())
          println("cipher_ctos: " + r.cipher_ctos)
          println("cipher_stoc: " + r.cipher_stoc)
          println("mac_ctos: " + r.mac_ctos)
          println("mac_stoc: " + r.mac_stoc)
          println("hostkey_blob_hex: " + @ecdsa.bytes_to_hex(r.hostkey_blob))
          println("exchange_hash: " + @ecdsa.bytes_to_hex(r.exchange_hash))
          println("shared_secret_head: " + r.shared_secret_head)
          println("sent_bytes: " + r.sent_bytes.to_string())
          println("recv_bytes: " + r.recv_bytes.to_string())
        }
        @sshclient.Failed(e) => {
          println("result: FAILED")
          println("error: " + live_error_name(e))
          // On a signature failure the exchange hash is the whole question, so
          // print it: an independent implementation can recompute H from the
          // same transcript and the two either agree or name the divergence.
          match e {
            @sshclient.SignatureInvalid(h) =>
              println("exchange_hash: " + @ecdsa.bytes_to_hex(h))
            _ => ()
          }
        }
      }
    }
  }
}
