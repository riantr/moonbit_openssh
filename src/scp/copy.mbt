///| Which destination does a source go to, and when is it refused?
///
/// The rules below are the table measured in `.loop90/DESIGN.md` section
/// 4, and they are not the obvious ones.  Driving the real `scp` through a
/// local `sftp-server.exe` showed that a **directory source does not get
/// its own name appended** to a destination that is not already a
/// directory:
///
///     scp -r local/t host:srv/upload
///     -> srv/upload/x.txt, srv/upload/sub/y.txt
///
/// while a **file** source copied to a directory does:
///
///     scp local/s1.txt local/s2.txt host:srv/d
///     -> srv/d/s1.txt, srv/d/s2.txt
///
/// Getting that backwards produces `srv/upload/t/x.txt`, which is the
/// classic `cp -r` mistake and is invisible in a test that only checks
/// that the bytes arrived.

///|
/// One source's fate.
pub(all) enum CopyStep {
  /// transfer a local path to a remote path
  Upload(String, String)
  /// a directory given without `-r`: refused, exit 1
  /// (`local "<path>" is not a regular file`)
  RefuseNotRegular(String)
  /// the local source is not there: fatal, exit 255
  /// (`stat local "<path>": No such file or directory`)
  RefuseMissing(String)
}

///|
/// Where a source lands, given what the two sides said about themselves.
///
/// This is the table from the measured rounds, in one place, because all
/// three copy paths (upload, download, local-to-local) obey it and only
/// the *direction* differs:
///
/// | source | target is a directory | destination |
/// |---|---|---|
/// | file | yes (or there are several sources) | `target/basename` |
/// | file | no | `target` |
/// | directory | yes | `target/basename` |
/// | directory | no | `target` |
///
/// The third row is the one that was wrong in the obvious implementation:
/// `-r local/t host:srv/upload` with `upload` absent puts **t's contents**
/// in `upload/` (round 5 scenario 3), and with `upload` present puts them
/// in `upload/t/` (round 7 scenario 28).  Both were measured.
pub fn dest_for(
  source_basename : String,
  target : String,
  source_is_dir : Bool,
  target_is_dir : Bool,
  multi : Bool,
) -> String {
  if source_is_dir {
    if target_is_dir {
      remote_join(target, source_basename)
    } else {
      target
    }
  } else if target_is_dir || multi {
    remote_join(target, source_basename)
  } else {
    target
  }
}

///|
/// Decide one source.
///
/// `target_is_dir` is what the *server* said about the target (a `stat`
/// on the remote path), not what the command line looks like: `scp
/// a.txt host:srv` and `scp a.txt host:srv/` are the same command line
/// shape and different answers.
///
/// `multi` is "there is more than one source", which forces the target to
/// be treated as a directory even before it is `stat`ed -- the real tool
/// does that check itself and answers `<target>: Not a directory` when it
/// is not.
pub fn plan_one(
  source : String,
  target : String,
  source_exists : Bool,
  source_is_dir : Bool,
  target_is_dir : Bool,
  multi : Bool,
  recursive : Bool,
) -> CopyStep {
  if !source_exists {
    return CopyStep::RefuseMissing(source)
  }
  if source_is_dir && !recursive {
    return CopyStep::RefuseNotRegular(source)
  }
  CopyStep::Upload(
    source,
    dest_for(basename_of(source), target, source_is_dir, target_is_dir, multi),
  )
}
