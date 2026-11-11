///| The destination-naming table, pinned.
///
/// Every expectation below is a row from `.loop90/DESIGN.md` section 4 --
/// what the real `scp` actually did against a local `sftp-server.exe`.
/// The two rows that matter most are a directory landing on a
/// non-directory (no name appended) and a file landing on a directory
/// (name appended), because getting them the same way round is the classic
/// `cp -r` mistake.

///|
fn show(step : @scp.CopyStep) -> String {
  match step {
    @scp.Upload(src, dest) => "Upload(" + src + " -> " + dest + ")"
    @scp.RefuseNotRegular(s) => "RefuseNotRegular(" + s + ")"
    @scp.RefuseMissing(s) => "RefuseMissing(" + s + ")"
  }
}

///|
test "a single file copied to a name keeps that name" {
  // measured: `scp local/a.txt host:srv/out.txt` -> srv/out.txt
  let step = @scp.plan_one(
    "local/a.txt", "srv/out.txt", true, false, false, false, false,
  )
  assert_eq(show(step), "Upload(local/a.txt -> srv/out.txt)")
}

///|
test "a single file copied into a directory takes its basename" {
  // measured: `scp local/s1.txt host:srv/d` with d existing -> srv/d/s1.txt
  let step = @scp.plan_one(
    "local/s1.txt", "srv/d", true, false, true, false, false,
  )
  assert_eq(show(step), "Upload(local/s1.txt -> srv/d/s1.txt)")
}

///|
test "a directory copied to a name does NOT get its own name appended" {
  // measured: `scp -r local/t host:srv/upload` -> upload/x.txt,
  // upload/sub/y.txt -- not upload/t/x.txt.
  let step = @scp.plan_one(
    "local/t", "srv/upload", true, true, false, false, true,
  )
  assert_eq(show(step), "Upload(local/t -> srv/upload)")
}

///|
test "a directory copied INTO a directory does get its name appended" {
  let step = @scp.plan_one("local/t", "srv/d", true, true, true, false, true)
  assert_eq(show(step), "Upload(local/t -> srv/d/t)")
}

///|
test "a directory without -r is refused as not a regular file" {
  // measured: exit 1, `local "local/d" is not a regular file`
  let step = @scp.plan_one("local/d", "srv/x", true, true, false, false, false)
  assert_eq(show(step), "RefuseNotRegular(local/d)")
}

///|
test "a missing local source is its own refusal" {
  // measured: exit 255, `stat local "..." : No such file or directory`
  let step = @scp.plan_one(
    "local/nope.txt", "srv/x", false, false, false, false, false,
  )
  assert_eq(show(step), "RefuseMissing(local/nope.txt)")
}

///|
test "several sources force the target to be a directory" {
  // measured: `scp local/s1.txt local/s2.txt host:srv/d` -> d/s1.txt, d/s2.txt
  let step = @scp.plan_one(
    "local/s1.txt", "srv/d", true, false, false, true, false,
  )
  assert_eq(show(step), "Upload(local/s1.txt -> srv/d/s1.txt)")
}

///|
test "a missing source is reported before the -r rule can fire" {
  // Ordering matters: the real tool `stat`s first, so a path that is both
  // absent and "a directory without -r" is the 255 case, not the 1 case.
  let step = @scp.plan_one(
    "local/gone", "srv/x", false, true, false, false, false,
  )
  assert_eq(show(step), "RefuseMissing(local/gone)")
}
