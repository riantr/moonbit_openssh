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

///|
/// The child's standard output.
pub const STREAM_STDOUT : Int32 = 0

///|
/// The child's standard error.
pub const STREAM_STDERR : Int32 = 1

///|
/// How many bytes of a captured stream are kept.
///
/// A cap, not a promise: a command that writes more has its output cut, and
/// `Capture::truncated` says so.  The alternative -- no cap -- means a
/// command that writes forever takes the server's memory with it.
pub const CAPTURE_CAPACITY : Int32 = 1048576

///|
/// Start `image` with `args`, its stdout AND its stderr on separate pipes.
///
/// The difference from `proc_spawn` is the stderr: there it is inherited,
/// and here it is a pipe the caller can read.  A server that runs a command
/// has to be able to say which of the command's two streams a byte came
/// from, and inherited stderr cannot do that.
pub fn proc_spawn_capture(image : String, args : String) -> Proc? {
  let image_bytes = utf8_bytes(image)
  let arg_bytes = utf8_bytes(args)
  let h = subproc_spawn2_raw(
    Bytes::from_array(image_bytes),
    image_bytes.length(),
    Bytes::from_array(arg_bytes),
    arg_bytes.length(),
    1,
  )
  if h == NO_PROC {
    None
  } else {
    Some({ handle: h, closed: false, })
  }
}

///|
/// Wait until one of the captured streams has something, the child exits, or
/// the timeout expires.
///
/// Returns 1 for stdout, 2 for stderr, 3 for both, 0 for a timeout, and -1
/// when the child has exited and both pipes are closed -- which is the only
/// answer that means "there is nothing more".
pub fn Proc::wait_any(self : Proc, timeout_ms : Int32) -> Int32 {
  if self.closed {
    return -1
  }
  let r = subproc_wait_any_raw(self.handle, timeout_ms)
  if r < 0L {
    -1
  } else {
    r.to_int()
  }
}

///|
/// Read what is waiting on a stream into `buf` at `off`.
///
/// Returns the number of bytes read.  It never waits for more than what is
/// there: the caller has already been told there is something.
///
/// ## Why the bytes come back through a `Bytes`
///
/// `Bytes::from_array` COPIES.  Reading straight into
/// `Bytes::from_array(buf)` would hand C a copy, C would fill the copy, and
/// the caller's `FixedArray` would still hold the zeros it was made with --
/// a read that reports the right LENGTH and every byte zero.  That is not a
/// hypothetical: it is what this function did first, and it took the real
/// `ssh.exe` returning sixteen zero bytes for `echo loop94-stdout` to show
/// it.  So the read fills a `Bytes`, and the bytes are copied back
/// explicitly.
pub fn Proc::read_into(
  self : Proc,
  which : Int32,
  buf : FixedArray[Byte],
  off : Int32,
  n : Int32,
) -> Int32 {
  if self.closed || n <= 0 || off < 0 || off + n > buf.length() {
    return 0
  }
  let scratch = Bytes::from_array(FixedArray::make(n, b'\x00'))
  let got = subproc_read2_raw(self.handle, which, scratch, 0, n)
  let k = if got <= 0L { 0 } else { got.to_int() }
  for i = 0; i < k; i = i + 1 {
    buf[off + i] = scratch[i]
  }
  k
}

///|
/// Give the child a deadline: `timeout_ms` from now, after which the waits
/// time out even if the child is still running.
///
/// A per-wait timeout bounds how long the parent waits for the NEXT thing,
/// not how long the child may run -- a command that writes a byte every
/// millisecond would never be interrupted by one.  This is the knob that
/// says "this command has had its turn".
pub fn Proc::set_deadline(self : Proc, timeout_ms : Int32) -> Unit {
  if self.closed {
    return
  }
  let _ = subproc_set_timeout_raw(self.handle, timeout_ms)
}

///|
/// What a command produced.
pub struct Capture {
  /// Everything the command wrote to its standard output.
  stdout : FixedArray[Byte]
  /// Everything the command wrote to its standard error.
  stderr : FixedArray[Byte]
  /// The command's exit status.
  code : Int32
  /// Whether either stream was longer than `CAPTURE_CAPACITY` and was cut.
  truncated : Bool
}

///|
/// Run `image` with `args` to completion and return what it produced.
///
/// The child's stdin is closed immediately: a command that waits for input
/// would otherwise wait for a caller that does not exist.
///
/// `timeout_ms` bounds the whole run.  A command that outlives it is killed
/// and the answer is `None` -- a server that waits forever on a command
/// that never ends is a server that never answers.
pub fn proc_capture(
  image : String,
  args : String,
  timeout_ms : Int32,
) -> Capture? {
  let p = match proc_spawn_capture(image, args) {
    None => return None
    Some(v) => v
  }
  p.close_stdin()
  p.set_deadline(timeout_ms)
  let out_buf = FixedArray::make(CAPTURE_CAPACITY, b'\x00')
  let err_buf = FixedArray::make(CAPTURE_CAPACITY, b'\x00')
  let mut out_len = 0
  let mut err_len = 0
  let mut truncated = false
  let mut timed_out = false
  let mut done = false
  while !done {
    let r = p.wait_any(timeout_ms)
    if r == -1 {
      done = true
    } else if r == 0 {
      timed_out = true
      done = true
    } else {
      if (r & 1) != 0 {
        if out_len < CAPTURE_CAPACITY {
          let got = p.read_into(
            STREAM_STDOUT,
            out_buf,
            out_len,
            CAPTURE_CAPACITY - out_len,
          )
          out_len = out_len + got
        } else {
          truncated = true
        }
      }
      if (r & 2) != 0 {
        if err_len < CAPTURE_CAPACITY {
          let got = p.read_into(
            STREAM_STDERR,
            err_buf,
            err_len,
            CAPTURE_CAPACITY - err_len,
          )
          err_len = err_len + got
        } else {
          truncated = true
        }
      }
    }
  }
  let code = p.wait()
  p.close()
  if timed_out {
    return None
  }
  let out = FixedArray::make(out_len, b'\x00')
  for i = 0; i < out_len; i = i + 1 {
    out[i] = out_buf[i]
  }
  let err = FixedArray::make(err_len, b'\x00')
  for i = 0; i < err_len; i = i + 1 {
    err[i] = err_buf[i]
  }
  Some({ stdout: out, stderr: err, code, truncated, })
}
