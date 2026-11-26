///| Loop #103: the order of the steps.
///
/// This is upstream's order, and the order is load-bearing:
///
///   1. find the key(s) to install and say where they came from,
///   2. (unless `-f`) try to log in with them, and if that works they are
///      already installed -- upstream says so and stops,
///   3. say how many keys remain,
///   4. (unless `-n`) install them,
///   5. say how many were added.
///
/// ## The one thing this file does that upstream does not
///
/// Step 4 is followed by a **check**: the tool authenticates with the key
/// it just installed.  Upstream does not check -- it counts the keys it
/// wrote and reports them, which is why upstream can exit 0 and print
/// "Number of key(s) added: 1" on a Windows server where the key was never
/// written (measured).
///
/// The check is not allowed to be a guess in either direction:
///
///   * the server **accepted** the key -- the install took effect,
///   * the server **refused** it -- the key is not in the file the server
///     reads, so the tool says so and exits 1 instead of claiming success,
///   * the check itself **failed** -- nothing is known, and the tool says
///     that too, but the install itself did succeed, so the status stays 0.
pub fn run_copy_id(
  prog : String,
  o : CopyIdOptions,
  io : CopyIdIo,
) -> CopyIdResult {
  let r = CopyIdResult::new()
  if o.use_sftp {
    // Upstream's `-s` installs over the sftp subsystem instead of running a
    // remote command.  This build has no sftp install path, and pretending
    // otherwise would be the same kind of lie this loop exists to remove.
    push_text(r, prog, CopyIdText::SftpNotSupported)
    r.status = 1
    return r
  }
  // ---- 1. the keys to install -------------------------------------------
  let source = match resolve_source(o, io) {
    Err(why) => {
      push_text(r, prog, why)
      r.status = 1
      return r
    }
    Ok(v) => v
  }
  match source {
    Source::None => {
      // Upstream prints the "Source of key(s)" line with an empty source
      // and then refuses.
      r.stderr_lines.push(info_source(prog, ""))
      push_text(r, prog, CopyIdText::NoIdentities)
      r.status = 1
      return r
    }
    Source::Found(pub_path, priv_path) => {
      r.stderr_lines.push(info_source(prog, pub_path))
      let bytes = match (io.read_fn)(pub_path) {
        None => {
          push_text(
            r,
            prog,
            CopyIdText::CannotOpen(pub_path, (io.reason_fn)(), None),
          )
          r.status = 1
          return r
        }
        Some(b) => b
      }
      let text = bytes_to_text(bytes)
      let keys = strip_trailing_newlines(text)
      if keys == "" {
        push_text(r, prog, CopyIdText::NoIdentities)
        r.status = 1
        return r
      }
      // ---- 2. is the key already there? ---------------------------------
      if !o.force {
        r.stderr_lines.push(info_filtering(prog))
        match (io.auth_fn)(priv_path) {
          CopyIdAuth::Accepted => {
            push_text(r, prog, CopyIdText::AllSkipped)
            r.status = 0
            return r
          }
          CopyIdAuth::Rejected(_) => ()
          CopyIdAuth::Failed(why) => {
            push_text(r, prog, CopyIdText::Filter(why))
            r.status = 1
            return r
          }
        }
      }
      let count = count_lines(keys)
      // ---- 3. how many are left ------------------------------------------
      r.stderr_lines.push(info_remaining(prog, count))
      // ---- 4. the dry run stops here --------------------------------------
      if o.dry_run {
        let (lines, _) = copy_id_text(prog, CopyIdText::WouldAdd(keys))
        for i in 0..<lines.length() {
          r.stdout_lines.push(lines[i])
        }
        r.status = 0
        return r
      }
      // ---- 5. install ----------------------------------------------------
      let probe = match (io.exec_fn)(priv_path, os_probe_command(), empty_bytes()) {
        CopyIdExec::Failed(why) => {
          push_text(r, prog, CopyIdText::Filter(why))
          r.status = 1
          return r
        }
        CopyIdExec::Done(out, _, _) => out
      }
      let command = if probe_says_windows(probe) {
        install_command_windows(o.target_path)
      } else {
        install_command_posix(o.target_path)
      }
      let stdin = utf8_bytes_of(keys + "\n")
      match (io.exec_fn)(priv_path, command, stdin) {
        CopyIdExec::Failed(why) => {
          push_text(r, prog, CopyIdText::Filter(why))
          r.status = 1
          return r
        }
        CopyIdExec::Done(_, err, status) => {
          if status != 0 {
            let why = if err != "" { err } else { "the remote command failed" }
            push_text(r, prog, CopyIdText::Filter(why))
            r.status = 1
            return r
          }
        }
      }
      // ---- 6. did the key take effect? -----------------------------------
      match (io.auth_fn)(priv_path) {
        CopyIdAuth::Accepted => ()
        CopyIdAuth::Rejected(_) => {
          push_text(
            r,
            prog,
            CopyIdText::NotAccepted(
              "; the server still refuses it, so the remote AuthorizedKeysFile is probably not the file that was written.",
            ),
          )
          r.status = 1
          return r
        }
        CopyIdAuth::Failed(_) => {
          // The install itself worked; what failed is the check.  Saying so
          // is enough -- the status stays 0 because nothing here says the
          // install did not happen.
          push_text(
            r,
            prog,
            CopyIdText::NotAccepted(
              "; the check could not be run, so the server's answer is unknown.",
            ),
          )
        }
      }
      // ---- 7. the closing block ------------------------------------------
      // Upstream computes `PRIV_ID_FILE` only when `-f` was **not** given
      // (`[ "$FORCED" ] || PRIV_ID_FILE=...`), so in force mode the hint
      // says `-i` with no path after it.  That is upstream's shape and it
      // is kept.
      let hint = closing_hint(o, if o.force { "" } else { priv_path })
      let (lines, _) = copy_id_text(prog, CopyIdText::Added(count, hint))
      for i in 0..<lines.length() {
        r.stdout_lines.push(lines[i])
      }
      r.status = 0
      r
    }
  }
}

///|
/// Where the keys come from.
pub(all) enum Source {
  /// there is no key file at all.
  None
  /// the public key file and the private key path that goes with it.
  Found(String, String)
}

///|
/// The key file to install, and the private key path that goes with it.
///
/// Upstream's rules, in upstream's order:
///
///   * `-i key` means the file `key.pub`, and `-i key.pub` means that file,
///   * without `-i` it is the newest `~/.ssh/id*.pub`, skipping the
///     `-cert.pub` ones (upstream: `ls -dt ... | grep -v -- '-cert.pub$' |
///     head -n 1`),
///   * the private key path is `dirname(pub) + "/" + basename(pub)`, and
///     upstream checks that **both** files can be opened unless `-f` was
///     given.
fn resolve_source(
  o : CopyIdOptions,
  io : CopyIdIo,
) -> Result[Source, CopyIdText] {
  match o.identity {
    Some(given) => {
      if given == "" {
        return Err(CopyIdText::NoIdentityFile)
      }
      let pub_path = if has_suffix(given, ".pub") {
        given
      } else {
        given + ".pub"
      }
      let priv_path = private_path_of(pub_path)
      if !o.force {
        let pub_ok = match (io.read_fn)(pub_path) {
          None => false
          Some(_) => true
        }
        if !pub_ok {
          return Err(
            CopyIdText::CannotOpen(pub_path, (io.reason_fn)(), None),
          )
        }
        let priv_ok = match (io.read_fn)(priv_path) {
          None => false
          Some(_) => true
        }
        if !priv_ok {
          return Err(
            CopyIdText::CannotOpen(
              priv_path,
              (io.reason_fn)(),
              Some(pub_path),
            ),
          )
        }
      }
      Ok(Source::Found(pub_path, priv_path))
    }
    None => {
      match default_pub_id_file(io) {
        None => Ok(Source::None)
        Some(pub_path) => {
          let priv_path = private_path_of(pub_path)
          Ok(Source::Found(pub_path, priv_path))
        }
      }
    }
  }
}

///|
/// The newest `~/.ssh/id*.pub`, skipping the `-cert.pub` ones.
///
/// Upstream's `ls -dt` sorts by modification time, newest first, and its
/// `grep -v -- '-cert.pub$'` drops the certificate files.  A tie is broken
/// by name, descending, which is what `ls -t` does when the times are the
/// same.
fn default_pub_id_file(io : CopyIdIo) -> String? {
  let dir = io.home + "/.ssh"
  let names = match (io.list_fn)(dir) {
    None => return None
    Some(v) => v
  }
  let mut best = ""
  let mut best_mtime = -1L
  let mut i = 0
  while i < names.length() {
    let name = names[i]
    if has_prefix(name, "id") && has_suffix(name, ".pub") &&
      !has_suffix(name, "-cert.pub") {
      let path = dir + "/" + name
      let mtime = match (io.stat_fn)(path) {
        None => 0L
        Some(st) => st.mtime
      }
      if mtime > best_mtime || (mtime == best_mtime && string_less(name, best)) {
        best_mtime = mtime
        best = path
      }
    }
    i = i + 1
  }
  if best == "" {
    None
  } else {
    Some(best)
  }
}

///|
/// Whether `a` sorts before `b`, byte by byte.
///
/// `ls -t` sorts the files it lists by time and, for equal times, by name;
/// the name order is what `head -n 1` then picks from.
fn string_less(a : String, b : String) -> Bool {
  let n = a.length()
  let m = b.length()
  let mut i = 0
  while i < n && i < m {
    let x = a[i].to_int()
    let y = b[i].to_int()
    if x != y {
      return x < y
    }
    i = i + 1
  }
  n < m
}

///|
/// Push a sentence's lines into the result, on the stream it belongs to.
fn push_text(
  r : CopyIdResult,
  prog : String,
  t : CopyIdText,
) -> Unit {
  let (lines, to_stderr) = copy_id_text(prog, t)
  for i in 0..<lines.length() {
    if to_stderr {
      r.stderr_lines.push(lines[i])
    } else {
      r.stdout_lines.push(lines[i])
    }
  }
}

///|
/// The lines of a text, the way `wc -l` counts them.
///
/// Upstream counts the keys with `printf '%s\n' "$NEW_IDS" | wc -l`, so a
/// single key is one line and a trailing newline does not add a line: the
/// text that reaches `wc -l` has been through a command substitution
/// (which strips the trailing newlines) and then through a `printf` that
/// puts exactly one back.
///
/// So the count is "the number of newlines, plus one for the last line
/// that has no newline of its own" -- and a text with no newline at all is
/// **one** line, not zero.  Counting the newlines alone would report "0
/// key(s) remain" for a file with one key in it.
fn count_lines(text : String) -> Int32 {
  let n = text.length()
  if n == 0 {
    return 0
  }
  let mut count = 0
  let mut i = 0
  while i < n {
    if text[i] == '\n' {
      count = count + 1
    }
    i = i + 1
  }
  if text[n - 1] == '\n' {
    count
  } else {
    count + 1
  }
}

///|
/// The trailing newlines, gone.
///
/// A command substitution (`$(cat file)`) strips trailing newlines and
/// nothing else, so a file that ends with CRLF keeps its carriage return --
/// and upstream then adds one newline back.  Stripping `\r` as well would
/// quietly change the bytes on the far side.
fn strip_trailing_newlines(text : String) -> String {
  let n = text.length()
  let mut end = n
  while end > 0 && text[end - 1] == '\n' {
    end = end - 1
  }
  substring_of(text, 0, end)
}

///|
/// Bytes as text, with anything that is not valid UTF-8 replaced.
fn bytes_to_text(bytes : FixedArray[Byte]) -> String {
  @utf8.decode_lossy(Bytes::from_array(bytes))
}

///|
/// Nothing at all, for a command that reads no stdin.
fn empty_bytes() -> FixedArray[Byte] {
  FixedArray::make(0, b'\x00')
}
