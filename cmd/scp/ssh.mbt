///| Loop #91: the SSH leg for `scp`.
///
/// ## What changes and what does not
///
/// Nothing above this file changes.  The copy engine, the destination
/// naming, the four directions and every sentence `scp` prints are
/// Loop #90's, measured against the real tool; the only difference is where
/// the bytes come from.  Loop #90 reached a local `sftp-server.exe` through
/// `src/subproc`; this reaches a host's own SFTP subsystem through
/// `src/sshclient`'s interactive link.  Both hand `@sftpdrive.SftpDrive`
/// the same two closures, which is why the reuse is real rather than
/// aspirational.
///
/// ## The one thing that had to be built first
///
/// A real `scp` signs with a private key **file**, and `src/keyfile` could
/// read only ed25519.  Loop #91 added the ECDSA reader (`ecdsa.mbt`), so
/// this file can now do what a user does: read the file `-i` names, take
/// the scalar out of it, and let `src/sshclient` sign.
///
/// ## The three sentences this adds
///
/// Everything else here produces Loop #90's text.  These three are ours,
/// and each says why rather than guessing:
///
///   * no `-i` at all -- this build will not look in `~/.ssh`, and a
///     client that silently picked a key would be lying about which one;
///   * an ed25519 key file -- the reader exists but the client's
///     publickey request signs ECDSA only;
///   * a P-521 key file -- `src/ecdsa` implements P-256 and P-384, so the
///     key is readable and not usable, which is a different answer from
///     "this is not a key file".

///|
/// Where to connect, once the specs have been read.
struct RemoteTarget {
  host : String
  user : String
  port : Int32
}

///|
/// The scalar and curve of the identity file, or the sentence that says why
/// there is none.
fn identity_of(
  o : @scp.ScpOptions,
  fs : @scp.LocalFs,
) -> Result[(@bigint.BigNat, @ecdsa.Curve), String] {
  if o.identity_files.length() == 0 {
    return Err(
      "remote copies need -i <key file>, and this build does not read ~/.ssh",
    )
  }
  // The FIRST -i, like the real tool: it tries them in order and stops at
  // the first the server accepts.  One key is all this leg can try, so
  // anything after the first is not merely unused -- it would be a promise
  // the code does not keep.
  let path = o.identity_files[0]
  let bytes = match (fs.read_fn)(path) {
    None => return Err((fs.reason_fn)() + " " + path)
    Some(b) => b
  }
  let text = @sftpdrive.bytes_to_text(bytes)
  match @keyfile.parse_private_file(text) {
    Ecdsa(pair, _comment) =>
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
      Err(
        "the key " + path + " is ed25519, and this build signs ECDSA keys only",
      )
    Unsupported(why) => Err(path + ": " + why)
    Malformed(why) => Err(path + ": " + why)
    WrongPassphrase(why) => Err(path + ": " + why)
  }
}

///|
/// The remote end of a run.
///
/// **The login name is not guessed.**  Real `scp` defaults to the local
/// login name, and this build cannot read it: `@env` exposes argv, `env`
/// and `time`, and reaching for `USERNAME` from MoonBit drags in
/// `__moonbit_fs_unstable` -- which is the same reason `cmd/ssh_live` takes
/// `--user` from its caller instead of looking (`main.mbt:289-292` there).
///
/// So an empty user is a refusal with a sentence, not a guess.  Connecting
/// as the wrong account fails with "Permission denied", which reads like a
/// key problem and is not one.
fn target_of_spec(
  o : @scp.ScpOptions,
  user_given : String?,
  host : String,
) -> Result[RemoteTarget, String] {
  let user = match user_given {
    Some(u) => u
    None =>
      return Err(
        "remote copies need user@host, and this build does not read the local login name",
      )
  }
  if user == "" {
    return Err(
      "remote copies need user@host, and this build does not read the local login name",
    )
  }
  Ok({ host, user, port: if o.port_given { o.port } else { 22 }, })
}

///|
/// Run the whole copy against a host: connect, sign, open the subsystem,
/// hand the drive to Loop #90's engine, and close.
///
/// A failure before the drive exists is reported against the host, which
/// is what the real tool names in `ssh`'s own message.  A failure after it
/// is inside `run_copy` and is reported exactly as Loop #90 reports it --
/// there is no second set of sentences for the remote case.
fn run_remote(
  prog : String,
  o : @scp.ScpOptions,
  fs : @scp.LocalFs,
  report : @scp.ScpReport,
  user_given : String?,
  host : String,
) -> Unit {
  let (d, curve) = match identity_of(o, fs) {
    Err(why) => {
      report.push(@scp.ScpError::Perror(host, why))
      finish(prog, report)
      return
    }
    Ok(v) => v
  }
  let t = match target_of_spec(o, user_given, host) {
    Err(why) => {
      report.push(@scp.ScpError::Perror(host, why))
      finish(prog, report)
      return
    }
    Ok(v) => v
  }
  let conn = match @tcp.TcpConn::connect(t.host, t.port) {
    None => {
      report.push(@scp.ScpError::Perror(t.host, "Connection refused"))
      finish(prog, report)
      return
    }
    Some(c) => c
  }
  let x = @sshclient.random_dh_priv()
  let link = match
    @sshclient.live_sftp_link_curve(
      conn,
      x,
      t.user,
      d,
      curve,
      "sftp",
      @knownhosts.KnownHostsPolicy::skip(),
    ) {
    Err(e) => {
      report.push(@scp.ScpError::Perror(t.host, link_error_text(e)))
      conn.close()
      finish(prog, report)
      return
    }
    Ok(l) => l
  }
  let drive = @sftpdrive.SftpDrive::new(
    fn(data : FixedArray[Byte]) -> Bool { link.write(data) },
    fn() -> FixedArray[Byte] { link.read() },
  )
  match drive.handshake() {
    Err(_) => {
      report.push(@scp.ScpError::Perror(t.host, "no SFTP handshake"))
      conn.close()
      finish(prog, report)
      return
    }
    Ok(_) => ()
  }
  @scp.run_copy(o, fs, Some(drive), report)
  conn.close()
  finish(prog, report)
}

///|
/// The sentence for a link failure.
fn link_error_text(e : @sshclient.SftpLinkError) -> String {
  match e {
    @sshclient.SftpLinkError::AuthFailed(_) => "Permission denied (publickey)"
    @sshclient.SftpLinkError::ChannelFailed(_) =>
      "the SFTP subsystem did not start"
    @sshclient.SftpLinkError::NoSession => "the session was not established"
  }
}
