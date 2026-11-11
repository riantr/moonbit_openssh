///| Loop #90: run a child process with its stdin and stdout on pipes.
///
/// ## Why this package exists
///
/// `scp -D <path>` is a testing hook built into the real tool.  Instead of
/// connecting to a host it runs the named program and speaks SFTP over
/// that program's stdin and stdout.  Measured on this machine
/// (`.loop90/DESIGN.md` section 3), that works with a path containing a
/// space and needs no network, no sshd and no key material -- which makes
/// it the cheapest honest comparison available for `scp`, and an
/// implementation that wants to be measured that way has to be able to do
/// the same thing.
///
/// ## The shape
///
///     spawn -> (write | read)* -> close_stdin -> wait -> close
///
/// `read` blocks.  That is deliberate: the SFTP driver above it has just
/// asked a question and is waiting for the answer, so a non-blocking read
/// would only move the polling loop somewhere less informed.
///
/// ## This package is native only
///
/// Starting a process with redirected stdio is a Windows thing here (the
/// C file uses `CreateProcessW` and anonymous pipes).  The js and wasm
/// targets are not given a stub that pretends: every operation fails, and
/// the message says why.
///
/// ## Handles are `Int64`
///
/// The C side returns a pointer to its own state, which is pointer-sized.
/// Truncating it to `Int32` would corrupt every handle above 2^31 -- the
/// same trap `src/agentpipe` documents for `HANDLE`.

///|
/// A child process plus the two pipes.
pub struct Proc {
  handle : Int64
  mut closed : Bool
}

///|
/// The handle value that means "nothing was started".
///
/// The C side returns -1 on failure.  `0` cannot be the failure value: it
/// is a legal HANDLE on Windows (the standard input).
const NO_PROC : Int64 = -1L

///|
/// Start `image` with `args`, its stdin and stdout on pipes.
///
/// `image` is a path to an executable and may contain spaces -- the C side
/// passes it as `lpApplicationName` and quotes it inside the command line,
/// which is what makes an unquoted
/// `C:\Program Files\OpenSSH-Win64\sftp-server.exe` work, exactly as the
/// real `scp -D` does.
///
/// `args` is appended verbatim; pass `""` for none.
///
/// The child's **stderr is inherited**.  That is not laziness: a local
/// `sftp-server.exe` reports a configuration problem there and nowhere
/// else, and swallowing it would turn "the server refused to start" into
/// "the protocol hung", which is the failure mode with the worst
/// diagnosis cost.
pub fn proc_spawn(image : String, args : String) -> Proc? {
  let image_bytes = utf8_bytes(image)
  let arg_bytes = utf8_bytes(args)
  let image_view = Bytes::from_array(image_bytes)
  let arg_view = Bytes::from_array(arg_bytes)
  let h = subproc_spawn_raw(
    image_view,
    image_bytes.length(),
    arg_view,
    arg_bytes.length(),
  )
  if h == NO_PROC {
    None
  } else {
    Some({ handle: h, closed: false, })
  }
}

///|
/// Write a whole buffer.  Returns the number of bytes written, or -1.
///
/// A short write is retried in C rather than here, because the C side is
/// the one that has the `WriteFile` return value; a caller that saw a
/// partial count would have to know how much of whose buffer to re-send.
pub fn Proc::write(self : Proc, data : FixedArray[Byte]) -> Int32 {
  if self.closed || data.length() == 0 {
    return 0
  }
  let view = Bytes::from_array(data)
  let n = subproc_write_raw(self.handle, view, 0, data.length())
  if n < 0L {
    -1
  } else {
    n.to_int()
  }
}

///|
/// Read up to `n` bytes.  An empty array is the end of the child's
/// output, or a broken pipe -- the two are the same answer here, because
/// a child that has been reaped cannot be asked which it was.
pub fn Proc::read_some(self : Proc, n : Int32) -> FixedArray[Byte] {
  if self.closed || n <= 0 {
    return FixedArray::make(0, b'\x00')
  }
  let buf = Bytes::from_array(FixedArray::make(n, b'\x00'))
  let got = subproc_read_raw(self.handle, buf, n)
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
/// None means the child's output ended in the middle of what was asked
/// for.  That is different from a short read, and the difference is the
/// difference between "the server answered" and "the server went away".
pub fn Proc::read_exact(self : Proc, n : Int32) -> FixedArray[Byte]? {
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
/// Close the writing end, so the child sees end of input.
///
/// For `scp -D` this is how a copy session is ended politely: the SFTP
/// driver stops writing, the server reads EOF, and it exits with a status
/// that `wait` can report.  Killing instead would work too and would throw
/// away the status.
pub fn Proc::close_stdin(self : Proc) -> Unit {
  if self.closed {
    return
  }
  let _ = subproc_close_stdin_raw(self.handle)
}

///|
/// Wait for the child and return its exit status, or -1.
pub fn Proc::wait(self : Proc) -> Int32 {
  if self.closed {
    return -1
  }
  subproc_wait_raw(self.handle)
}

///|
/// Terminate the child.
pub fn Proc::kill(self : Proc) -> Unit {
  if self.closed {
    return
  }
  subproc_kill_raw(self.handle)
}

///|
/// Release every handle.  Does not wait; the caller decides whether the
/// exit status mattered.
pub fn Proc::close(self : Proc) -> Unit {
  if self.closed {
    return
  }
  self.closed = true
  subproc_close_raw(self.handle)
}

///|
/// The image as UTF-8 bytes.
///
/// Bytes rather than a `String`: a MoonBit String carries no terminator
/// and the C side widens with `MultiByteToWideChar(CP_UTF8, ...)`, so the
/// bytes are what it needs.
fn utf8_bytes(s : String) -> FixedArray[Byte] {
  let raw = @utf8.encode(s)
  let out : FixedArray[Byte] = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = raw[i]
  }
  out
}
