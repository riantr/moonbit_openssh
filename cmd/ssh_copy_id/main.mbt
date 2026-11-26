///| cmd/ssh_copy_id -- Loop #103: install a public key on a remote account.
///
///     ssh-copy-id [-h|-?|-f|-n|-s|-x] [-i [identity_file]] [-t target_path]
///                  [-F ssh_config] [[-o ssh_option] ...] [-p port]
///                  [user@]hostname
///
/// ## What this driver is allowed to do
///
/// Translate.  The option table, the sentences, the remote command and the
/// order of the steps are in `src/sshcopyid`; this file reads `argv`, turns
/// the local disk and the network into the function values the rules ask
/// for, and writes the rules' bytes.
///
/// ## The output is written raw, and that is deliberate
///
/// Upstream's `ssh-copy-id` is a `/bin/sh` script, so its lines end with
/// **LF**.  `println` and `eprintln` would end them with CRLF on Windows
/// (`eprintln` text-translates the whole string), and the tool would then
/// differ from the script it replaces by a byte on every line.  So the
/// bytes go out through a raw file descriptor, unchanged.
///
/// ## The two gaps, both said out loud
///
///   * `-s` (install over sftp) is refused with a sentence of our own.
///     Upstream can do it; this build has no sftp install path.
///   * The host key is checked against `~/.ssh/known_hosts` when that file
///     is there, and accepted without a check when it is not.  Upstream
///     asks the user; this build cannot ask, because its stdin carries the
///     key.

///|
fn main {
  let argv = @env.args()
  let prog = if argv.length() > 0 { argv[0] } else { "ssh-copy-id" }
  let fs = @scplib.real_local_fs()
  let probe = fn(path : String) -> Bool { mentions_ssh(fs, path) }
  match @sshcopyid.parse_args(argv, probe) {
    Err(e) => {
      let (lines, _) = @sshcopyid.copy_id_arg_error(prog, e)
      @scplib.write_stderr(join_lines(lines))
      @env.exit(1)
    }
    Ok(o) => run(prog, o, fs)
  }
}

///|
/// Run the rules and write what they said.
fn run(
  prog : String,
  o : @sshcopyid.CopyIdOptions,
  fs : @scplib.LocalFs,
) -> Unit {
  let io : @sshcopyid.CopyIdIo = {
    home: home_dir(),
    exec_fn: fn(priv_path : String, command : String, stdin : FixedArray[Byte]) {
      run_remote(o, priv_path, command, stdin)
    },
    auth_fn: fn(priv_path : String) { probe_auth(o, priv_path) },
    read_fn: fn(path : String) { (fs.read_fn)(path) },
    list_fn: fn(path : String) { (fs.list_fn)(path) },
    stat_fn: fn(path : String) { stat_of(fs, path) },
    reason_fn: fn() { (fs.reason_fn)() },
  }
  let result = @sshcopyid.run_copy_id(prog, o, io)
  // Upstream writes its INFO and ERROR lines while the work happens and
  // its closing block at the end, so stderr comes first here too.
  @scplib.write_stderr(join_lines(result.stderr_lines))
  @scplib.write_stdout(join_lines(result.stdout_lines))
  @env.exit(result.status)
}

///|
/// The lines, each with a newline, unchanged.
fn join_lines(lines : Array[String]) -> String {
  let out = StringBuilder()
  for i in 0..<lines.length() {
    out.write_string(lines[i])
    out.write_string("\n")
  }
  out.to_string()
}

///|
/// The local home directory.
///
/// `HOME` first (a POSIX shell's word), then `USERPROFILE` (the Windows
/// one).  This build does not read the account name out of the registry,
/// so the environment is the only place the home can come from.
fn home_dir() -> String {
  match @env.get_env_var("HOME") {
    Some(v) => if v != "" { v } else { env_or_empty("USERPROFILE") }
    None => env_or_empty("USERPROFILE")
  }
}

///|
/// The login name, when the target did not carry one.
///
/// Upstream's `ssh` defaults to the local login name.  `USER` and
/// `USERNAME` are the two names the two platforms use.
fn local_user() -> String {
  match @env.get_env_var("USER") {
    Some(v) => if v != "" { v } else { env_or_empty("USERNAME") }
    None => env_or_empty("USERNAME")
  }
}

///|
/// One environment variable, or the empty string.
fn env_or_empty(name : String) -> String {
  match @env.get_env_var(name) {
    Some(v) => v
    None => ""
  }
}

///|
/// Whether a file is readable and mentions `ssh`.
///
/// Upstream's test for the "Missing hostname" case is
/// `[ -r "$nextarg" ] && grep -iq ssh "$nextarg"`.
fn mentions_ssh(fs : @scplib.LocalFs, path : String) -> Bool {
  let bytes = match (fs.read_fn)(path) {
    None => return false
    Some(b) => b
  }
  let text = @utf8.decode_lossy(Bytes::from_array(bytes)).to_lower()
  text.contains("ssh")
}

///|
/// A local path's facts, in the shape the rules want.
fn stat_of(fs : @scplib.LocalFs, path : String) -> @sshcopyid.CopyIdStat? {
  match (fs.stat_fn)(path) {
    None => None
    Some(st) =>
      Some({
        is_file: !st.is_dir,
        is_dir: st.is_dir,
        size: st.size,
        mtime: st.mtime,
      })
  }
}

///|
/// The scalar and curve of the identity file, or the sentence that says
/// why there is none.
///
/// The same wording `cmd/scp` uses, because it is the same refusal: this
/// client signs ECDSA keys only.
fn identity_of(
  fs : @scplib.LocalFs,
  path : String,
) -> Result[(@bigint.BigNat, @ecdsa.Curve), String] {
  let bytes = match (fs.read_fn)(path) {
    None => return Err("failed to open " + path)
    Some(b) => b
  }
  let text = @utf8.decode_lossy(Bytes::from_array(bytes))
  match @keyfile.parse_private_file(text) {
    Ecdsa(pair, _) =>
      if pair.curve == "nistp256" {
        Ok((@bigint.BigNat::from_bytes_be(pair.scalar), @ecdsa.Curve::p256()))
      } else if pair.curve == "nistp384" {
        Ok((@bigint.BigNat::from_bytes_be(pair.scalar), @ecdsa.Curve::p384()))
      } else {
        Err(
          "the key " +
          path +
          " is a " +
          pair.curve +
          " key, and this build signs nistp256 and nistp384 only",
        )
      }
    Ed25519(_, _) =>
      Err("the key " + path + " is ed25519, and this build signs ECDSA keys only")
    Unsupported(why) => Err(path + ": " + why)
    Malformed(why) => Err(path + ": " + why)
    WrongPassphrase(why) => Err(path + ": " + why)
  }
}

///|
/// The host key policy.
///
/// The `known_hosts` file is used when it is there, and an unknown host is
/// accepted (the non-strict branch) rather than refused: upstream would
/// ask, and this build cannot ask, because its stdin is carrying the key.
///
/// Two ssh options are honoured, because without them the tool cannot be
/// pointed at a server whose host key is not the one in the local file:
/// `UserKnownHostsFile=` and `StrictHostKeyChecking=`.  Upstream passes
/// every `-o` straight to `ssh`; this build honours the two it can and
/// ignores the rest, which is said out loud in the README.
fn known_hosts_policy(
  fs : @scplib.LocalFs,
  o : @sshcopyid.CopyIdOptions,
) -> @knownhosts.KnownHostsPolicy {
  let path = match ssh_option(o, "UserKnownHostsFile") {
    Some(p) => p
    None => home_dir() + "/.ssh/known_hosts"
  }
  let strict = match ssh_option(o, "StrictHostKeyChecking") {
    Some(v) => v == "yes"
    None => false
  }
  let bytes = match (fs.read_fn)(path) {
    None => return @knownhosts.KnownHostsPolicy::skip()
    Some(b) => b
  }
  let text = @utf8.decode_lossy(Bytes::from_array(bytes))
  @knownhosts.KnownHostsPolicy::from_text(text, o.host, o.port, strict)
}

///|
/// One ssh option's value, the last one winning, as `ssh` does.
fn ssh_option(o : @sshcopyid.CopyIdOptions, name : String) -> String? {
  @sshcopyid.ssh_option(o, name)
}

///|
/// The port to connect to: `-p`, unless an `-o Port=` says otherwise.
fn effective_port(o : @sshcopyid.CopyIdOptions) -> Int32 {
  match ssh_option(o, "Port") {
    Some(v) => {
      let mut value = 0
      let mut any = false
      let mut i = 0
      while i < v.length() {
        let c = v[i]
        if c < '0' || c > '9' {
          return o.port
        }
        value = value * 10 + (c.to_int() - '0'.to_int())
        any = true
        i = i + 1
      }
      if any {
        value
      } else {
        o.port
      }
    }
    None => o.port
  }
}

///|
/// The identities to try, in order.
///
/// **The identity being installed is usually not one of them.**  Upstream
/// connects with the user's *default* identities -- the key being
/// installed is not in the server's `authorized_keys` yet, so it cannot
/// be the one that opens the connection.  Trying it first costs one
/// refused authentication and buys the case where it *is* already
/// installed; after that come the default identities, in the order the
/// directory lists them.
fn identity_candidates(
  fs : @scplib.LocalFs,
  priv_path : String,
) -> Array[String] {
  let out : Array[String] = []
  out.push(priv_path)
  let dir = home_dir() + "/.ssh"
  let names = match (fs.list_fn)(dir) {
    None => return out
    Some(v) => v
  }
  for i in 0..<names.length() {
    let name = names[i]
    if @sshcopyid.has_prefix(name, "id") &&
      @sshcopyid.has_suffix(name, ".pub") &&
      !@sshcopyid.has_suffix(name, "-cert.pub") {
      let pub_path = dir + "/" + name
      let priv_key = @sshcopyid.substring_of(
        pub_path,
        0,
        pub_path.length() - 4,
      )
      let readable = match (fs.read_fn)(priv_key) {
        None => false
        Some(_) => true
      }
      if readable {
        out.push(priv_key)
      }
    }
  }
  out
}

///|
/// Run one remote command.
fn run_remote(
  o : @sshcopyid.CopyIdOptions,
  priv_path : String,
  command : String,
  stdin : FixedArray[Byte],
) -> @sshcopyid.CopyIdExec {
  let fs = @scplib.real_local_fs()
  let candidates = identity_candidates(fs, priv_path)
  let mut last = @sshcopyid.CopyIdExec::Failed(
    "no identity was accepted by the server",
  )
  for i in 0..<candidates.length() {
    match try_remote(o, fs, candidates[i], command, stdin) {
      Ok(outcome) => return outcome
      Err(why) => last = @sshcopyid.CopyIdExec::Failed(why)
    }
  }
  last
}

///|
/// One attempt with one identity.
///
/// The difference between the two failures matters: a refused identity
/// means "try the next one", while a channel that broke after the
/// authentication means "this connection is the answer".
fn try_remote(
  o : @sshcopyid.CopyIdOptions,
  fs : @scplib.LocalFs,
  priv_path : String,
  command : String,
  stdin : FixedArray[Byte],
) -> Result[@sshcopyid.CopyIdExec, String] {
  let (d, curve) = match identity_of(fs, priv_path) {
    Err(why) => return Err(why)
    Ok(v) => v
  }
  let user = if o.user != "" { o.user } else { local_user() }
  let port = effective_port(o)
  let conn = match @tcp.TcpConn::connect(o.host, port) {
    None =>
      return Err(
        "ssh: connect to host " +
        o.host +
        " port " +
        port.to_string() +
        ": Connection refused",
      )
    Some(c) => c
  }
  let outcome = @sshclient.live_exec_io_curve(
    conn,
    @sshclient.random_dh_priv(),
    user,
    d,
    curve,
    command,
    stdin,
    [],
    known_hosts_policy(fs, o),
  )
  conn.close()
  match outcome {
    @sshclient.Done(r) =>
      Ok(
        @sshcopyid.CopyIdExec::Done(
          bytes_to_text(r.stdout),
          bytes_to_text(r.stderr),
          r.exit_status,
        ),
      )
    @sshclient.AuthFailed(e) => Err(auth_error_text(e))
    @sshclient.ChannelFailed(_) =>
      Ok(
        @sshcopyid.CopyIdExec::Failed(
          "the channel failed before the command ran",
        ),
      )
  }
}

///|
/// Try to log in with the identity, and say what the server said.
///
/// The three answers are kept apart on purpose: "the server refused this
/// key" is the answer that means "the key is not installed yet", and it
/// must not be confused with "the connection broke".
fn probe_auth(
  o : @sshcopyid.CopyIdOptions,
  priv_path : String,
) -> @sshcopyid.CopyIdAuth {
  let fs = @scplib.real_local_fs()
  let (d, curve) = match identity_of(fs, priv_path) {
    Err(why) => return @sshcopyid.CopyIdAuth::Failed(why)
    Ok(v) => v
  }
  let user = if o.user != "" { o.user } else { local_user() }
  let port = effective_port(o)
  let conn = match @tcp.TcpConn::connect(o.host, port) {
    None =>
      return @sshcopyid.CopyIdAuth::Failed(
        "ssh: connect to host " +
        o.host +
        " port " +
        port.to_string() +
        ": Connection refused",
      )
    Some(c) => c
  }
  let outcome = @sshclient.live_auth_curve(
    conn,
    @sshclient.random_dh_priv(),
    user,
    d,
    curve,
    known_hosts_policy(fs, o),
  )
  conn.close()
  match outcome {
    @sshclient.Authenticated(_) => @sshcopyid.CopyIdAuth::Accepted
    @sshclient.Failed(e) =>
      match e {
        @sshclient.AuthError::AuthRejected(reason, _, _) =>
          @sshcopyid.CopyIdAuth::Rejected(reason)
        _ => @sshcopyid.CopyIdAuth::Failed(auth_error_text(e))
      }
  }
}

///|
/// The sentence for an authentication failure, in the shape `ssh` uses.
fn auth_error_text(e : @sshclient.AuthError) -> String {
  match e {
    @sshclient.AuthError::AuthRejected(reason, _, _) =>
      "Permission denied (" + reason + ")."
    @sshclient.AuthError::Transport(se) => session_error_text(se)
    @sshclient.AuthError::SignFailed => "the key could not be used to sign"
    @sshclient.AuthError::NoAuthReply => "the server did not answer"
    @sshclient.AuthError::BadPacket(_) => "the server sent a packet that made no sense"
  }
}

///|
/// The sentence for a session failure.
///
/// The handshake's own label is carried, because "the connection failed"
/// and "the host key is not the one we pinned" are different answers and
/// only the second one tells the user what to do.
fn session_error_text(e : @sshclient.SessionError) -> String {
  match e {
    @sshclient.SessionError::HandshakeFailed(live) =>
      "the handshake failed: " + @sshclient.live_error_label(live)
    @sshclient.SessionError::NoServiceAccept =>
      "the server did not accept the session service"
    @sshclient.SessionError::UnexpectedService(s) =>
      "the server accepted a different service: " + s
    @sshclient.SessionError::BadPacket(s) =>
      "the server sent a packet that made no sense: " + s
  }
}

///|
/// Bytes as text.
fn bytes_to_text(bytes : FixedArray[Byte]) -> String {
  @utf8.decode_lossy(Bytes::from_array(bytes))
}
