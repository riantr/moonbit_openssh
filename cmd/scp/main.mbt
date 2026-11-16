///| cmd/scp -- Loop #90: copy files over SFTP, and copy them locally.
///
///     scp [-r] [-p] [-q] [-v] [-P port] [-D sftp_server_path] src ... dst
///
/// ## What this driver is allowed to do
///
/// Nothing but translate.  The option table, the remote-versus-local
/// split, the destination naming, the four copy directions and every
/// sentence the tool prints are in `src/scp`; this file parses `argv`,
/// builds the two ends (`real_local_fs` and, when something is remote,
/// an `SftpDrive` over a spawned `sftp-server.exe`), calls `run_copy`,
/// and writes the report's bytes.
///
/// ## The one deliberate gap: the SSH leg
///
/// Real `scp` reaches a host over SSH.  This build does not: `-D` (speak
/// SFTP to a program on this machine) is implemented, and a remote spec
/// **without** `-D` is refused with a sentence of our own rather than a
/// silent failure.  `.loop90/DESIGN.md` section 6 says why -- real `scp`
/// needs a private key *file*, `src/keyfile` reads ed25519 only, and the
/// repository's test ECDSA key exists as a scalar in code, not as a file.
/// That is a `src/keyfile` capability, not a `scp` change, so it waits for
/// its own loop instead of being faked here.
///
/// ## Why the output goes through `write_stderr` and not `eprintln`
///
/// `eprintln` text-translates the whole string (`"A\nB"` becomes
/// `A\r\nB\r\n`), which cannot express the one message whose embedded
/// newline stays bare -- the `-P` refusal, measured as
/// `bad port "0"\n\r\n`.  So the bytes are built here and written
/// unchanged; `text_crlf` does the conversion the C runtime would, once,
/// and the port message is the single documented exception.

///|
/// `argv0: ` plus the sentence, or the sentence alone for the `perror`
/// group.  Every measured line is `<argv0>: <words>` except that group.
fn add_line(out : StringBuilder, prog : String, e : @scplib.ScpError) -> Unit {
  if @scplib.needs_argv0_prefix(e) {
    out.write_string(prog + ": ")
  }
  out.write_string(@scplib.text_crlf(@scplib.scp_error_text(e) + "\n"))
}

///|
fn main {
  let argv = @env.args()
  let prog = if argv.length() > 0 { argv[0] } else { "scp" }
  let args : Array[String] = []
  for i = 1; i < argv.length(); i = i + 1 {
    args.push(argv[i])
  }
  match @scplib.parse_args(args) {
    @scplib.ParsedArgs::Refused(e) => {
      // getopt's sentence, then the usage block, then 1.
      @scplib.write_stderr(
        @scplib.text_crlf(
          prog + ": " + @scplib.arg_error_text(e) + "\n" + @scplib.usage_text(),
        ),
      )
      @env.exit(1)
    }
    @scplib.ParsedArgs::ProtocolV1 => {
      @scplib.write_stderr(
        @scplib.text_crlf(
          prog + ": " + @scplib.unsupported_protocol_v1_text() + "\n",
        ),
      )
      @env.exit(255)
    }
    @scplib.ParsedArgs::BadPort(v) => {
      // The one message with a bare `\n`: the tool writes the text raw
      // and only the trailing newline is translated.
      @scplib.write_stderr(prog + ": " + @scplib.port_error_text(v) + "\r\n")
      @env.exit(255)
    }
    @scplib.ParsedArgs::NeedUsage => {
      @scplib.write_stderr(@scplib.text_crlf(@scplib.usage_text()))
      @env.exit(1)
    }
    @scplib.ParsedArgs::Options(o) => run(prog, o)
  }
}

///|
fn run(prog : String, o : @scplib.ScpOptions) -> Unit {
  let fs = @scplib.real_local_fs()
  let report = @scplib.ScpReport::new()
  let sources = @scplib.sources_of(o)
  let target = @scplib.target_of(o)
  let mut needs_remote = !@scplib.is_local(target)
  let hosts : Array[String] = []
  // Loop #91: the login name comes from the first remote spec, the same
  // one the connection is made to.  `user@host:path` is the only place
  // `scp` can learn it.
  let mut remote_user : String? = None
  for i = 0; i < sources.length(); i = i + 1 {
    match @scplib.split_spec(sources[i]) {
      @scplib.Spec::Local(_) => ()
      @scplib.Spec::Remote(user, host, _) => {
        needs_remote = true
        hosts.push(host)
        if remote_user is None {
          remote_user = user
        }
      }
    }
  }
  match @scplib.split_spec(target) {
    @scplib.Spec::Local(_) => ()
    @scplib.Spec::Remote(user, host, _) => {
      hosts.push(host)
      if remote_user is None {
        remote_user = user
      }
    }
  }
  if needs_remote {
    // One connection can only serve one host; `-3` and multi-host runs are
    // refused by name rather than by guessing which one to dial.
    let mut different = false
    for i = 1; i < hosts.length(); i = i + 1 {
      if hosts[i] != hosts[0] {
        different = true
      }
    }
    if different {
      report.push(
        @scplib.ScpError::Perror(hosts[0], "one connection, one host"),
      )
      finish(prog, report)
      return
    }
    if o.sftp_server_path == "" {
      // Loop #91: the SSH leg.  Same engine, same sentences, different
      // byte link -- see `ssh.mbt` for why nothing above it changed.
      run_remote(prog, o, fs, report, remote_user, hosts[0])
      return
    }
    match spawn_drive(o.sftp_server_path) {
      Err(why) => {
        report.push(@scplib.ScpError::Perror(o.sftp_server_path, why))
        finish(prog, report)
      }
      Ok(proc) => {
        let drive = drive_over(proc)
        match drive.handshake() {
          Err(_) => {
            report.push(
              @scplib.ScpError::Perror(o.sftp_server_path, "no SFTP handshake"),
            )
            proc.close()
            finish(prog, report)
          }
          Ok(_) => {
            @scplib.run_copy(o, fs, Some(drive), report)
            proc.close_stdin()
            let _ = proc.wait()
            proc.close()
            finish(prog, report)
          }
        }
      }
    }
  } else {
    // Both ends are on this machine: no drive, no process.
    @scplib.run_copy(o, fs, None, report)
    finish(prog, report)
  }
}

///|
fn spawn_drive(path : String) -> Result[@subproc.Proc, String] {
  match @subproc.proc_spawn(path, "") {
    Some(p) => Ok(p)
    None => Err("cannot start the SFTP server")
  }
}

///|
/// An interactive SFTP client over the child's stdin and stdout.
///
/// A short read is not a shortcut for "nothing there": `read_some`
/// returns what arrived, and the drive's reassembler decides when a
/// packet is complete.  A closed stdout returns an empty array, which the
/// drive reads as a link failure.
fn drive_over(proc : @subproc.Proc) -> @sftpdrive.SftpDrive {
  let write_fn = fn(data : FixedArray[Byte]) -> Bool { proc.write(data) >= 0 }
  let read_fn = fn() -> FixedArray[Byte] { proc.read_some(16384) }
  @sftpdrive.SftpDrive::new(write_fn, read_fn)
}

///|
fn finish(prog : String, report : @scplib.ScpReport) -> Unit {
  let out = StringBuilder()
  for i = 0; i < report.lines.length(); i = i + 1 {
    add_line(out, prog, report.lines[i])
  }
  @scplib.write_stderr(out.to_string())
  @env.exit(@scplib.scp_exit_code(report.exit()))
}
