///|
/// Loop #89: the targets that cannot make a named pipe.
///
/// **A stub that pretends to have a pipe is worse than a stub that says
/// it does not.**  A client that got a handle it could not use would fail
/// later, in the middle of a request, with a message about the AGENT
/// rather than about the PLATFORM -- and the platform is the thing that
/// is actually wrong.
///
/// So on these targets every operation fails, and this test says so.  It
/// is a test about the stub refusing, and it runs on the targets where
/// the stub is the whole story.
///
/// These tests are compiled only on js, wasm and wasm-gc.  The native
/// target has the real thing, and it is tested in `agentpipe_test.mbt`.

///|
/// 建不出来。
test "the stub cannot create a pipe" {
  assert_true(
    @agentpipe.agent_pipe_server_create("\\\\.\\pipe\\openssh-stub-test")
    is None,
  )
}

///|
/// 连不上——因为根本没有管道。
test "the stub cannot connect to a pipe" {
  assert_true(
    @agentpipe.agent_pipe_connect("\\\\.\\pipe\\openssh-stub-test") is None,
  )
}
