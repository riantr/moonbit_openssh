///|
/// Loop #89: the targets that cannot make a named pipe.
///
/// A named pipe is a Windows thing.  The js and wasm targets have no
/// way to make one, and **a stub that pretends to have one is worse
/// than a stub that says it does not**: a client that got a handle it
/// could not use would fail later, in the middle of a request, with a
/// message about the agent rather than about the platform.
///
/// So every operation here fails, and the driver that reaches it says
/// which platform it is on.  The package still type-checks everywhere,
/// which is the point of having this file at all.

///|
fn agent_pipe_server_create_raw(_name : String) -> Int64 {
  -1L
}

///|
fn agent_pipe_connect_raw(_name : String) -> Int64 {
  -1L
}

///|
fn agent_pipe_accept_raw(_h : Int64) -> Int32 {
  -1
}

///|
fn agent_pipe_read_raw(_h : Int64, _buf : Bytes, _n : Int32) -> Int64 {
  -1L
}

///|
fn agent_pipe_write_raw(
  _h : Int64,
  _buf : Bytes,
  _off : Int32,
  _n : Int32,
) -> Int64 {
  -1L
}

///|
fn agent_pipe_close_raw(_h : Int64) -> Int32 {
  -1
}
