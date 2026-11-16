///| cmd/sshd -- Loop #93: the SSH server, driven over a TCP socket.
///
/// The rules live in `src/sshd`; this program listens, accepts, hands the
/// connection to the state machine, and prints what happened.  It decides
/// nothing about SSH.
///
/// ## Usage
///
///     cmd/sshd --host-key FILE --authorized-keys FILE [--port N] [--host H]
///              [--ident STR] [--accept-timeout-ms N]
///
/// `--port 0` means "pick one", and the port that was picked is printed to
/// STDERR as `listen_port: N` before the program waits.  It goes to stderr
/// because stdout is block-buffered when it is a pipe: the caller has to
/// know the port BEFORE it can connect, and a buffered line is only
/// flushed when the process exits -- which is never, because the process is
/// waiting for a connection only the caller can make.  That is a deadlock
/// with a plausible-looking cause, and `cmd/listen_kat` says the same
/// thing about the same trap.
///
/// The host key is an OpenSSH private key file (`openssh-key-v1`), read
/// with `src/keyfile` -- the same format the real `sshd` reads and the
/// same parser `cmd/ssh_keygen` writes.  The server does not invent a key
/// type of its own.
///
/// ## What it prints
///
/// The report goes to stdout, one `key: value` per line, so a gate can read
/// it without parsing prose:
///
///     client_ident: SSH-2.0-OpenSSH_for_Windows_9.5
///     kex_alg: diffie-hellman-group14-sha256
///     hostkey_alg: ssh-ed25519
///     cipher_ctos: aes128-ctr
///     cipher_stoc: aes128-ctr
///     authenticated: 1
///     user: hp
///     session_id: <hex>
///
/// The exit status is 0 when the peer authenticated and 1 when it did not,
/// so a gate can branch on it without reading the report at all.

///|
async fn main {
  let args = @env.args()
  let mut port = 0
  let mut host = "127.0.0.1"
  let mut host_key_path = ""
  let mut authorized_path = ""
  let mut ident = "SSH-2.0-MoonBit_sshd_0.1"
  let mut accept_timeout = 30000
  let mut i = 1
  while i < args.length() {
    let a = args[i]
    if a == "--port" && i + 1 < args.length() {
      port = parse_int(args[i + 1], 0)
      i = i + 2
    } else if a == "--host" && i + 1 < args.length() {
      host = args[i + 1]
      i = i + 2
    } else if a == "--host-key" && i + 1 < args.length() {
      host_key_path = args[i + 1]
      i = i + 2
    } else if a == "--authorized-keys" && i + 1 < args.length() {
      authorized_path = args[i + 1]
      i = i + 2
    } else if a == "--ident" && i + 1 < args.length() {
      ident = args[i + 1]
      i = i + 2
    } else if a == "--accept-timeout-ms" && i + 1 < args.length() {
      accept_timeout = parse_int(args[i + 1], 30000)
      i = i + 2
    } else {
      eprintln("unknown argument: " + a)
      @env.exit(2)
    }
  }
  if host_key_path == "" || authorized_path == "" {
    eprintln("usage: sshd --host-key FILE --authorized-keys FILE [--port N]")
    @env.exit(2)
  }
  // ---- the host key ----
  let host_key_text = match read_text(host_key_path) {
    None => {
      eprintln("cannot read the host key file: " + host_key_path)
      @env.exit(2)
    }
    Some(t) => t
  }
  let seed = match @keyfile.parse_private_file(host_key_text) {
    @keyfile.Parsed::Ed25519(pair, _) => pair.seed
    @keyfile.Parsed::Ecdsa(_, _) => {
      eprintln("the host key is an ECDSA key; this server speaks ssh-ed25519")
      @env.exit(2)
    }
    @keyfile.Parsed::Malformed(why) => {
      eprintln("the host key file is malformed: " + why)
      @env.exit(2)
    }
    @keyfile.Parsed::Unsupported(why) => {
      eprintln("the host key file is not supported: " + why)
      @env.exit(2)
    }
    @keyfile.Parsed::WrongPassphrase(_) => {
      eprintln("the host key file is encrypted; this server reads plain keys")
      @env.exit(2)
    }
  }
  // ---- the authorized keys ----
  let authorized_text = match read_text(authorized_path) {
    None => {
      eprintln("cannot read the authorized keys file: " + authorized_path)
      @env.exit(2)
    }
    Some(t) => t
  }
  // ---- listen ----
  let listener = match @tcp.TcpListener::listen(host, port) {
    None => {
      eprintln("listen failed on " + host + ":" + port.to_string())
      @env.exit(1)
    }
    Some(l) => l
  }
  let bound = listener.port()
  eprintln("listen_port: " + bound.to_string())
  // ---- one connection ----
  match listener.accept(accept_timeout) {
    @tcp.Timeout => {
      eprintln("accept timed out")
      listener.close()
      @env.exit(1)
    }
    @tcp.Failed(code) => {
      eprintln("accept failed: " + code.to_string())
      listener.close()
      @env.exit(1)
    }
    @tcp.Accepted(conn, ip, peer_port) => {
      eprintln("peer: " + ip + ":" + peer_port.to_string())
      let cfg = @sshdsrv.ServerConfig::make(ident, seed, authorized_text)
      match @sshdsrv.serve(conn, cfg) {
        Err(e) => {
          eprintln("server_error: " + @sshdsrv.sd_server_error_label(e))
          conn.close()
          listener.close()
          @env.exit(1)
        }
        Ok(report) => {
          println("client_ident: " + report.client_ident)
          println("kex_alg: " + report.kex_alg)
          println("hostkey_alg: " + report.hostkey_alg)
          println("cipher_ctos: " + report.cipher_ctos)
          println("cipher_stoc: " + report.cipher_stoc)
          println(
            "authenticated: " + (if report.authenticated { "1" } else { "0" }),
          )
          println("user: " + report.user)
          println("session_id: " + @sshdsrv.sd_hex(report.session_id))
          conn.close()
          listener.close()
          if report.authenticated {
            @env.exit(0)
          }
          @env.exit(1)
        }
      }
    }
  }
}

///|
/// Read a file as text, or `None` when it cannot be read.
///
/// A missing file and an unreadable file are the same answer here -- the
/// server cannot start without it -- but the CALLER says which path it was,
/// so the message names the file rather than the errno.
async fn read_text(path : String) -> String? {
  try {
    let data = @fs.read_file(path)
    Some(data.text())
  } catch {
    _ => None
  }
}

///|
/// A decimal integer, or `fallback`.
fn parse_int(s : String, fallback : Int32) -> Int32 {
  if s.length() == 0 {
    return fallback
  }
  let mut n = 0
  let mut i = 0
  while i < s.length() {
    let c = s[i].to_int()
    if c < 48 || c > 57 {
      return fallback
    }
    n = n * 10 + (c - 48)
    i = i + 1
  }
  n
}
