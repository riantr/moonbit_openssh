///| The measured failure sentences, pinned.
///
/// Each expected string below is copied out of `.loop90/round5.json`,
/// which is what the real `scp.exe` wrote while copying through a local
/// `sftp-server.exe`.  The gate normalises `argv[0]`, so what is pinned
/// here is the part after the `scp.exe: ` prefix -- and one constructor
/// deliberately has no prefix at all.
///
/// Statuses are compared as **numbers** rather than as the enum: adding
/// `derive(Eq)` to a public type costs two `implicit_impl_as_method`
/// deprecation warnings, and `--deny-warn` turns those into errors.  The
/// number is also the thing that is actually measured.

///|
test "the upload failures speak the measured sentences" {
  // A local source that is not there: fatal, and the message names the
  // side that was examined.
  let e = @scp.StatLocal("local/nope.txt", @scp.reason_no_such_file())
  assert_eq(
    @scp.scp_error_text(e),
    "stat local \"local/nope.txt\": No such file or directory",
  )
  assert_true(@scp.needs_argv0_prefix(e))
  assert_eq(@scp.scp_exit_code(@scp.scp_error_exit(e)), 255)

  // A directory as a source without -r: two lines in the real output.
  let d = @scp.NotARegularFile("local/d")
  assert_eq(@scp.scp_error_text(d), "local \"local/d\" is not a regular file")
  assert_true(@scp.needs_argv0_prefix(d))
  assert_eq(@scp.scp_exit_code(@scp.scp_error_exit(d)), 1)

  let f = @scp.TransferFailed(@scp.direction_upload(), "local/d", "srv/x")
  assert_eq(@scp.scp_error_text(f), "failed to upload file local/d to srv/x")
  assert_eq(@scp.scp_exit_code(@scp.scp_error_exit(f)), 1)

  // A remote target that cannot be opened.
  let o = @scp.DestOpen("srv/nodir/out.txt", @scp.reason_no_such_file())
  assert_eq(
    @scp.scp_error_text(o),
    "dest open \"srv/nodir/out.txt\": No such file or directory",
  )
  assert_eq(@scp.scp_exit_code(@scp.scp_error_exit(o)), 1)
}

///|
test "a missing remote source names the path without the host" {
  // Measured: `scp h:srv/nope.txt out.txt` prints `srv/nope.txt: ...`.
  // The host half is not in the sentence, which is why this constructor
  // takes the path and not the spec.
  let e = @scp.RemotePath("srv/nope.txt", @scp.reason_no_such_file())
  assert_eq(@scp.scp_error_text(e), "srv/nope.txt: No such file or directory")
  assert_true(@scp.needs_argv0_prefix(e))
  assert_eq(@scp.scp_exit_code(@scp.scp_error_exit(e)), 1)
}

///|
test "the perror group has no argv0 prefix and exits 1" {
  // The three-or-more-positionals check: the target must be a directory.
  // Two measured outcomes, and the difference between them is the
  // operating system's own strerror text.
  let missing = @scp.Perror("nodir", @scp.reason_no_such_file())
  assert_eq(@scp.scp_error_text(missing), "nodir: No such file or directory")
  assert_false(@scp.needs_argv0_prefix(missing))
  assert_eq(@scp.scp_exit_code(@scp.scp_error_exit(missing)), 1)

  let notdir = @scp.Perror("a.txt", @scp.reason_not_a_directory())
  assert_eq(@scp.scp_error_text(notdir), "a.txt: Not a directory")
  assert_false(@scp.needs_argv0_prefix(notdir))
}

///|
test "every non-perror error is prefixed, and nothing else is" {
  // A guard rather than a restatement: if a future constructor is added
  // and lands on the wrong side of the prefix rule, this fails.
  let prefixed = [
    @scp.StatLocal("p", "why"),
    @scp.NotARegularFile("p"),
    @scp.RemotePath("p", "why"),
    @scp.DestOpen("p", "why"),
    @scp.TransferFailed("upload", "a", "b"),
  ]
  for i = 0; i < prefixed.length(); i = i + 1 {
    assert_true(@scp.needs_argv0_prefix(prefixed[i]))
  }
  assert_false(@scp.needs_argv0_prefix(@scp.Perror("p", "why")))
}

///|
test "only the missing-local-source case is fatal" {
  // 255 versus 1 is the distinction the real tool makes, and it is the
  // one a reimplementation is most likely to flatten.
  assert_eq(@scp.scp_exit_code(@scp.Ok), 0)
  assert_eq(@scp.scp_exit_code(@scp.Failure), 1)
  assert_eq(@scp.scp_exit_code(@scp.Fatal), 255)
  assert_eq(
    @scp.scp_exit_code(@scp.scp_error_exit(@scp.StatLocal("p", "why"))),
    255,
  )
  assert_eq(
    @scp.scp_exit_code(@scp.scp_error_exit(@scp.NotARegularFile("p"))),
    1,
  )
  assert_eq(
    @scp.scp_exit_code(@scp.scp_error_exit(@scp.RemotePath("p", "why"))),
    1,
  )
  assert_eq(
    @scp.scp_exit_code(@scp.scp_error_exit(@scp.DestOpen("p", "why"))),
    1,
  )
  assert_eq(
    @scp.scp_exit_code(
      @scp.scp_error_exit(@scp.TransferFailed("upload", "a", "b")),
    ),
    1,
  )
  assert_eq(@scp.scp_exit_code(@scp.scp_error_exit(@scp.Perror("p", "why"))), 1)
}
