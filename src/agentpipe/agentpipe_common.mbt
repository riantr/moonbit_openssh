///|
/// Loop #89: the transport the SSH agent runs on.
///
/// The agent protocol is length-prefixed and unencrypted, so it can run
/// over anything that carries bytes.  On this platform the transport
/// is not a choice: the installed `ssh-add` refuses a TCP address
/// without even connecting --
///
///     $ SSH_AUTH_SOCK=127.0.0.1:1234 ssh-add -l
///     Error connecting to agent: No such file or directory
///
/// -- and its binary carries the literal string
/// `SSH_AUTH_SOCK=\\.\\pipe\\openssh-ssh-agent`.  The real client
/// therefore talks to a NAMED PIPE, and an agent that the real client
/// can use has to be one.
///
/// **A named pipe is not a stream socket.**  One handle serves one
/// client at a time, and the next client has to wait for the pipe to
/// be disconnected first.  So the server side is
///
///     create -> accept -> (read/write)* -> close
///
/// and `accept` disconnects the previous client before it waits for
/// the next one.  The Windows OpenSSH agent spawns a worker per client;
/// this one serves one client at a time, which is enough for the tools
/// that talk to it: `ssh-add` sends its request, reads the reply and
/// closes.
///
/// **This package is native only.**  A named pipe is a Windows thing,
/// and the js and wasm targets have no way to make one.  They are not
/// left with a stub that pretends: every operation there fails, and
/// the driver says so.

///|
/// One end of a named pipe.
///
/// The handle is the Windows HANDLE, which is pointer-sized, so it
/// travels as a 64-bit integer.  `closed` is what keeps a second
/// close from being a second `CloseHandle` on a handle that is gone.
pub struct AgentPipe {
  handle : Int64
  mut closed : Bool
}

///|
/// The handle value that means "no pipe".
///
/// The C side returns -1 for a failure, and 0 is a legal HANDLE on
/// Windows (the standard input), so 0 cannot be the failure value.
const NO_PIPE : Int64 = -1L

///|
/// Create the server end of a named pipe.
///
/// The name is a full pipe path, `\\.\pipe\<something>`.  None is
/// asserted to exist: the caller decides, and a name that is already
/// taken fails here rather than in the middle of a request.
///
/// Returns None when the pipe could not be created.
pub fn agent_pipe_server_create(name : String) -> AgentPipe? {
  let h = agent_pipe_server_create_raw(name)
  if h == NO_PIPE {
    return None
  }
  Some(AgentPipe::{ handle: h, closed: false, })
}

///|
/// Wait for a client to connect.
///
/// Returns false when the wait failed.  The previous client is
/// disconnected first: a pipe handle that is still connected cannot
/// take another one.
pub fn agent_pipe_server_accept(pipe : AgentPipe) -> Bool {
  if pipe.closed {
    return false
  }
  agent_pipe_accept_raw(pipe.handle) == 0
}

///|
/// Connect to a named pipe as a client.
///
/// Returns None when there is no such pipe -- which is the ordinary
/// "there is no agent running" answer, and the one the real `ssh-add`
/// turns into `Error connecting to agent: No such file or directory`.
pub fn agent_pipe_connect(name : String) -> AgentPipe? {
  let h = agent_pipe_connect_raw(name)
  if h == NO_PIPE {
    return None
  }
  Some(AgentPipe::{ handle: h, closed: false, })
}

///|
/// Write a whole buffer.
///
/// A short write is not a failure: the loop goes round again with the
/// rest.  A pipe that is gone is a failure.
pub fn AgentPipe::write(self : AgentPipe, data : FixedArray[Byte]) -> Bool {
  if self.closed {
    return false
  }
  let total = data.length()
  if total == 0 {
    return true
  }
  let view = Bytes::from_array(data)
  let mut off = 0
  while off < total {
    let n = agent_pipe_write_raw(self.handle, view, off, total - off)
    if n <= 0L {
      return false
    }
    off = off + n.to_int()
  }
  true
}

///|
/// Read up to `n` bytes.  An empty array is the end of the pipe.
pub fn AgentPipe::read_some(self : AgentPipe, n : Int32) -> FixedArray[Byte] {
  if self.closed || n <= 0 {
    return FixedArray::make(0, b'\x00')
  }
  let buf = Bytes::from_array(FixedArray::make(n, b'\x00'))
  let got = agent_pipe_read_raw(self.handle, buf, n)
  let k = if got <= 0L { 0 } else { got.to_int() }
  let out : FixedArray[Byte] = FixedArray::make(k, b'\x00')
  for i = 0; i < k; i = i + 1 {
    out[i] = buf[i]
  }
  out
}

///|
/// Read exactly `n` bytes.
///
/// None means the pipe ended in the middle, or broke.  That is
/// different from a short read, and the difference is the difference
/// between "the agent answered" and "the agent went away".
pub fn AgentPipe::read_exact(self : AgentPipe, n : Int32) -> FixedArray[Byte]? {
  if self.closed || n < 0 {
    return None
  }
  let out : FixedArray[Byte] = FixedArray::make(n, b'\x00')
  let mut got = 0
  while got < n {
    let chunk = self.read_some(n - got)
    if chunk.length() == 0 {
      return None
    }
    for i = 0; i < chunk.length(); i = i + 1 {
      out[got + i] = chunk[i]
    }
    got = got + chunk.length()
  }
  Some(out)
}

///|
/// Close the pipe.  Closing twice is not an error.
pub fn AgentPipe::close(self : AgentPipe) -> Unit {
  if !self.closed {
    self.closed = true
    ignore(agent_pipe_close_raw(self.handle))
  }
}
