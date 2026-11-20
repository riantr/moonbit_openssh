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
/// Run a command the way the real OpenSSH server runs one.
///
/// The real server's own DEBUG3 log says what it does:
///
/// ```
///   spawn_argv[0]: "c:\windows\system32\cmd.exe" /c "cmd /c echo hello"
/// ```
///
/// -- the login shell is `cmd.exe`, and the command string is ONE argument,
/// wrapped in quotes.  The quotes are not decoration: cmd.exe's rule for
/// the argument of `/c` is "strip the leading quote, remove the LAST quote
/// character on the command line", so `cmd /c "cmd /c echo hello"` echoes
/// `hello"` -- with a trailing quote -- and the client receives that quote.
///
/// The two streams are separated by the PIPES and not by redirections on the
/// command line.  With `> out 2> err` appended, the last quote on the line
/// is the one closing "err", the whole tail becomes the command, and `echo`
/// prints it.  Measured, in `.loop94/cmdline_probe.py`.
///
/// ## Why the image is the bare name
///
/// This used to be `C:\Windows\System32\cmd.exe` spelled out, and
/// `verify_loop71.mjs` failed it -- correctly: that is a claim about one
/// machine's layout.  `src/subproc` passes `lpApplicationName = NULL`, so
/// Win32 resolves the first token of the command line through the same
/// search path the shell uses, and `cmd.exe` is found there.
///
/// Measured three ways before choosing (`.loop94/comspec_probe.py`): a bare
/// `cmd.exe`, `%ComSpec%`, and `%SystemRoot%\System32\cmd.exe` all run and
/// all produce the SAME bytes, including the trailing quote.  The bare name
/// is the one that asserts nothing about where the shell lives.
fn run_command(command : String) -> @sshdsrv.CommandResult {
  let image = "cmd.exe"
  let args = "/c \"" + command + "\""
  match @subproc.proc_capture(image, args, COMMAND_TIMEOUT_MS) {
    None =>
      @sshdsrv.CommandResult::make(
        FixedArray::make(0, b'\x00'),
        FixedArray::make(0, b'\x00'),
        -1,
      )
    Some(c) => {
      if c.truncated {
        eprintln("command output was longer than the capture limit and was cut")
      }
      @sshdsrv.CommandResult::make(c.stdout, c.stderr, c.code)
    }
  }
}

///|
/// How long a command may run before the server stops waiting for it.
const COMMAND_TIMEOUT_MS : Int32 = 120000

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
      let runner = @sshdsrv.CommandRunner::make(run_command)
      // The SFTP subsystem's rules live in `src/sftpserver`; the filesystem
      // and the clock they need are native-only work, so they are supplied
      // here.  This driver is the only place that knows they exist.
      let provider = @sshdsrv.SftpProvider::make(
        @sftpserver.real_server_fs(),
        @sftpserver.real_server_clock(),
      )
      // The port forward's provider, the same way: the rules are in
      // `src/sshd/forward.mbt` and the sockets are here.
      let forward = make_forward_provider(conn)
      match @sshdsrv.serve(conn, cfg, runner, Some(provider), Some(forward)) {
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
          println("command: " + report.command)
          println("exit_status: " + report.exit_status.to_string())
          println("stdout_bytes: " + report.stdout_bytes.to_string())
          println("stderr_bytes: " + report.stderr_bytes.to_string())
          // What the SFTP subsystem produced.  Zero for a command, and the
          // number of reply bytes and answered requests for the `sftp`
          // subsystem -- which is the part of the report a gate can check
          // against the client's own.
          println("sftp_bytes: " + report.sftp_bytes.to_string())
          println("sftp_requests: " + report.sftp_requests.to_string())
          // What the port forward carried.  Zero for a command, and the
          // number of bytes relayed plus the number of channels served when
          // the peer asked for a forward -- the part of the report a gate
          // can check against the client's own.
          println("forward_bytes: " + report.forward_bytes.to_string())
          println("forward_targets: " + report.forward_targets.to_string())
          // Only 1 when the server READ the peer's CHANNEL_CLOSE before it
          // closed the connection.  Closing while that answer is in flight
          // is what turns the close into a TCP RESET, which discards what
          // the peer has not read yet -- so this line is how the drain
          // stays observable, and a gate that removes the drain sees this
          // line go to 0.
          println(
            "peer_closed: " + (if report.peer_closed { "1" } else { "0" }),
          )
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
/// How long the server may take to reach a port forward's target.
///
///   The real server makes the connection asynchronously and answers the
///   channel when it is done, so a target that never answers holds the
///   channel open rather than the whole server.  This driver connects
///   synchronously, so the budget is what keeps one unreachable target from
///   holding up the connection that asked for it.
const FORWARD_CONNECT_TIMEOUT_MS : Int32 = 10000

///|
/// Build the port forward's provider.
///
///   The rules are `src/sshd/forward.mbt`; the sockets are here, because
///   they are native-only work.  The same split `CommandRunner` and
///   `SftpProvider` have.
///
///   The `wait_fn` is the interesting one: a forward has to watch the SSH
///   connection AND the target connection at the same time, and the only
///   honest way to do that is one wait over both sockets.  Waiting for the
///   SSH connection alone loses the answer coming back from the target;
///   waiting for the target alone never sees the request.  Both are
///   deadlocks.
fn make_forward_provider(
  ssh_conn : @tcp.TcpConn,
) -> @sshdsrv.ForwardProvider[@tcp.TcpConn] {
  let ssh_handle = ssh_conn.raw_handle()
  @sshdsrv.ForwardProvider::make(
    fn(host : String, port : Int32) {
      let report = @tcp.TcpConn::connect_with_timeout(
        host,
        port,
        FORWARD_CONNECT_TIMEOUT_MS,
      )
      report.conn
    },
    fn(conn : @tcp.TcpConn, n : Int32) { conn.recv_some(n) },
    fn(conn : @tcp.TcpConn, data : FixedArray[Byte]) { conn.send(data) },
    fn(conn : @tcp.TcpConn) { ignore(conn.shutdown_write()) },
    fn(conn : @tcp.TcpConn) { conn.close() },
    fn(conn : @tcp.TcpConn, timeout_ms : Int32) {
      @tcp.wait_readable_pair(ssh_handle, conn.raw_handle(), timeout_ms)
    },
  )
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
