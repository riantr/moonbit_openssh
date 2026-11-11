///| Which of the four copies a run performs, and what happens first.
///
/// ## The four directions
///
/// `scp` decides per source, not per run:
///
///     local  -> remote   upload
///     remote -> local    download
///     local  -> local    a plain copy (the real tool hands this to cmd;
///                        see `DESIGN.md` section 2 and `local_copy`)
///     remote -> remote   both ends on the same server (`-D`, or `-3`)
///
/// ## The pre-flight, which is measured and asymmetric
///
/// With **more than one source** the target has to be a directory, and
/// the two sides answer differently:
///
/// * a **local** target that is missing or is a file is refused through
///   `perror` -- `<target>: No such file or directory`, **no** `argv[0]`
///   prefix, exit 1, and **nothing is copied** (round 7 scenario 27);
/// * a **remote** target is **created** when it is missing (round 8
///   scenario 29), and a refusal to create it is `fatal` at 255 (round 8
///   scenario 30).
///
/// That asymmetry is the single most surprising thing in this file: the
/// same command line creates a directory on one side and refuses on the
/// other.
///
/// ## What is not implemented
///
/// `-d` (the target must be a directory) is parsed and ignored: it was
/// never measured in this loop, so there is no sentence to print.  `-3`
/// and a run whose sources name *different* hosts are refused by the
/// driver, which can only hold one connection.

///|
/// Everything one source needs to know about the run.
priv struct RunContext {
  target : String
  target_is_local : Bool
  /// the target's path half, for the messages that strip the host
  target_path : String
  multi : Bool
  recursive : Bool
  preserve : Bool
}

///|
/// Copy every source into the target, printing through `report`.
///
/// `drive` is `None` only when no side of the run is remote; a run that
/// needs it and does not have it reports a link failure rather than
/// pretending to copy.
pub fn run_copy(
  o : ScpOptions,
  fs : LocalFs,
  drive : @sftpdrive.SftpDrive?,
  report : ScpReport,
) -> Unit {
  let sources = sources_of(o)
  let target = target_of(o)
  let ctx : RunContext = {
    target,
    target_is_local: is_local(target),
    target_path: path_of(target),
    multi: sources.length() > 1,
    recursive: o.recursive,
    preserve: o.preserve,
  }
  let eng = match drive {
    Some(d) => Some(CopyEngine::new(fs, d))
    None => None
  }
  if !preflight(ctx, fs, eng, report) {
    return
  }
  for i = 0; i < sources.length(); i = i + 1 {
    if report.fatal {
      return
    }
    copy_one(ctx, fs, eng, sources[i], report)
  }
}

///|
/// The check that runs before any byte moves.  `False` means "stop, the
/// report already says why".
fn preflight(
  ctx : RunContext,
  fs : LocalFs,
  eng : CopyEngine?,
  report : ScpReport,
) -> Bool {
  if !ctx.multi {
    return true
  }
  if ctx.target_is_local {
    match (fs.stat_fn)(ctx.target) {
      None => {
        report.push(Perror(ctx.target, (fs.reason_fn)()))
        false
      }
      Some(st) =>
        if st.is_dir {
          true
        } else {
          report.push(Perror(ctx.target, reason_not_a_directory()))
          false
        }
    }
  } else {
    match eng {
      None => {
        report.push(Perror(ctx.target, "Connection lost"))
        false
      }
      Some(e) =>
        if e.remote_is_dir(ctx.target_path) {
          true
        } else {
          match e.ensure_remote_dir(ctx.target_path) {
            Ok(_) => true
            Err(why) => {
              report.push(RemoteMkdir(ctx.target_path, why))
              false
            }
          }
        }
    }
  }
}

///|
/// One source, in whichever direction it goes.
fn copy_one(
  ctx : RunContext,
  fs : LocalFs,
  eng : CopyEngine?,
  src : String,
  report : ScpReport,
) -> Unit {
  let src_is_local = is_local(src)
  if src_is_local && ctx.target_is_local {
    copy_one_local(ctx, fs, src, report)
  } else if src_is_local {
    copy_one_upload(ctx, fs, eng, src, report)
  } else {
    match eng {
      None => report.push(Perror(src, "Connection lost"))
      Some(e) =>
        if ctx.target_is_local {
          copy_one_download(ctx, fs, e, src, report)
        } else {
          copy_one_remote(ctx, e, src, report)
        }
    }
  }
}

///|
fn copy_one_local(
  ctx : RunContext,
  fs : LocalFs,
  src : String,
  report : ScpReport,
) -> Unit {
  let st = match (fs.stat_fn)(src) {
    Some(s) => s
    None => {
      report.push(StatLocal(src, (fs.reason_fn)()))
      return
    }
  }
  if st.is_dir && !ctx.recursive {
    report.push(NotARegularFile(src))
    return
  }
  let target_is_dir = match (fs.stat_fn)(ctx.target) {
    Some(s) => s.is_dir
    None => false
  }
  let dest = dest_for(
    basename_of(src),
    ctx.target,
    st.is_dir,
    target_is_dir,
    ctx.multi,
  )
  if st.is_dir {
    local_copy_tree(fs, src, dest, ctx.preserve, report)
  } else {
    local_copy(fs, src, dest, ctx.preserve, report)
  }
}

///|
fn copy_one_upload(
  ctx : RunContext,
  fs : LocalFs,
  eng : CopyEngine?,
  src : String,
  report : ScpReport,
) -> Unit {
  let st = match (fs.stat_fn)(src) {
    Some(s) => s
    None => {
      report.push(StatLocal(src, (fs.reason_fn)()))
      return
    }
  }
  if st.is_dir && !ctx.recursive {
    // Measured: two lines -- the refusal, then the failed-to-upload that
    // names the target as written (round 5 scenario 8).
    report.push(NotARegularFile(src))
    report.push(TransferFailed(direction_upload(), src, ctx.target_path))
    return
  }
  match eng {
    None => report.push(Perror(ctx.target, "Connection lost"))
    Some(e) => {
      let dest = dest_for(
        basename_of(src),
        ctx.target_path,
        st.is_dir,
        e.remote_is_dir(ctx.target_path),
        ctx.multi,
      )
      if st.is_dir {
        e.upload_tree(src, dest, ctx.preserve, report)
      } else {
        e.upload_file(src, dest, ctx.preserve, report)
      }
    }
  }
}

///|
fn copy_one_download(
  ctx : RunContext,
  fs : LocalFs,
  e : CopyEngine,
  src : String,
  report : ScpReport,
) -> Unit {
  let rpath = path_of(src)
  let attrs = match e.drive.stat(rpath) {
    Ok(a) => a
    Err(err) => {
      report.push(RemotePath(rpath, drive_reason(err)))
      return
    }
  }
  let is_dir = @sftpdrive.attrs_is_dir(attrs)
  if is_dir && !ctx.recursive {
    report.push(RemoteNotRegular(rpath))
    return
  }
  let target_is_dir = match (fs.stat_fn)(ctx.target) {
    Some(s) => s.is_dir
    None => false
  }
  let dest = dest_for(
    basename_of(rpath),
    ctx.target,
    is_dir,
    target_is_dir,
    ctx.multi,
  )
  if is_dir {
    e.download_tree(rpath, dest, ctx.preserve, report)
  } else {
    // `inside_walk` is false: a top-level failure prints one line, not two.
    e.download_file(rpath, rpath, dest, ctx.preserve, false, report)
  }
}

///|
fn copy_one_remote(
  ctx : RunContext,
  e : CopyEngine,
  src : String,
  report : ScpReport,
) -> Unit {
  let from = path_of(src)
  let attrs = match e.drive.stat(from) {
    Ok(a) => a
    Err(err) => {
      report.push(RemotePath(from, drive_reason(err)))
      return
    }
  }
  let is_dir = @sftpdrive.attrs_is_dir(attrs)
  if is_dir && !ctx.recursive {
    report.push(RemoteNotRegular(from))
    return
  }
  let dest = dest_for(
    basename_of(from),
    ctx.target_path,
    is_dir,
    e.remote_is_dir(ctx.target_path),
    ctx.multi,
  )
  if is_dir {
    e.copy_remote_tree(from, dest, ctx.preserve, report)
  } else {
    e.copy_remote(from, dest, ctx.preserve, report)
  }
}
