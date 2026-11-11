///| Loop #90: `src/subproc` on js / wasm / wasm-gc, where the whole
/// package is a refusal.
///
/// The assertion is deliberately about `spawn` only: it is the one
/// operation a caller reaches first, and if it refuses then nothing
/// downstream can be reached by accident.  A stub that "worked" would move
/// the failure into the SFTP driver, where it would read as a protocol
/// bug.

///|
test "spawning a process fails on this target instead of pretending" {
  match @subproc.proc_spawn("cmd.exe", "/c echo hello") {
    None => ()
    Some(proc) => {
      proc.close()
      fail("a process must not be startable on js/wasm/wasm-gc")
    }
  }
}
