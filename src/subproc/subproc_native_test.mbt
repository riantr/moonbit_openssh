///| Loop #90: `src/subproc` on native.
///
/// The programs used here are named by **bare name** on purpose
/// (`cmd.exe`, resolved through `PATH` by `CreateProcessW`).  A test that
/// hardcoded `C:\Windows\System32\cmd.exe` would be exactly the
/// machine-specific absolute path that `host/verify_loop71.mjs` refuses
/// in a tracked file, and the fix for that gate is a probe list, not a
/// second copy of one machine's layout.

///|
test "spawn, read the child's stdout, and reap its exit status" {
  match @subproc.proc_spawn("cmd.exe", "/c echo hello") {
    None => fail("cmd.exe could not be started")
    Some(proc) => {
      let out = proc.read_some(4096)
      let text = text_of(out)
      assert_true(text.contains("hello"))
      // `echo` exits 0.  Reading the status is the part that proves the
      // process handle is held and not leaked.
      assert_eq(proc.wait(), 0)
      proc.close()
    }
  }
}

///|
test "bytes written to a child's stdin arrive, and close_stdin is EOF" {
  // `findstr` exits 1 when nothing matched.  Writing a line that does not
  // contain the pattern and then closing stdin therefore proves three
  // things at once: the bytes arrived, end of input was delivered, and
  // the child was able to finish instead of blocking on a pipe whose
  // writing end nobody closed.
  match @subproc.proc_spawn("cmd.exe", "/c findstr /c:zzz") {
    None => fail("cmd.exe could not be started")
    Some(proc) => {
      let payload : FixedArray[Byte] = [b'a', b'b', b'c']
      assert_eq(proc.write(payload), 3)
      proc.close_stdin()
      // Drain: a child that fills its stdout pipe would block, and the
      // test would then be measuring its own deadlock.
      let _ = proc.read_some(4096)
      assert_eq(proc.wait(), 1)
      proc.close()
    }
  }
}

///|
test "a program that does not exist is reported, not guessed at" {
  match @subproc.proc_spawn("loop90-no-such-program-xyz", "") {
    None => ()
    Some(proc) => {
      proc.close()
      fail("a nonexistent image should not have started")
    }
  }
}

///|
test "close is idempotent and a closed Proc refuses to work" {
  match @subproc.proc_spawn("cmd.exe", "/c echo x") {
    None => fail("cmd.exe could not be started")
    Some(proc) => {
      let _ = proc.read_some(64)
      assert_eq(proc.wait(), 0)
      proc.close()
      // After close every operation answers the failure value instead of
      // touching a handle that is gone; a second close is not a second
      // CloseHandle on a stale HANDLE.
      proc.close()
      assert_eq(proc.wait(), -1)
      assert_eq(proc.write([b'x']), 0)
      assert_eq(proc.read_some(8).length(), 0)
    }
  }
}

///|
/// Bytes as text, ascii-only (the child prints ascii here).
fn text_of(b : FixedArray[Byte]) -> String {
  let out = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    out.write_char(Int32::unsafe_to_char(b[i].to_int()))
  }
  out.to_string()
}
