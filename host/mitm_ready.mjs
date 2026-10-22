// host/mitm_ready.mjs -- wait until host/sftp_mitm.py says it is listening.
//
// ## Why this exists
//
// The gates that drive the client against `host/sftp_mitm.py` used to sleep
// for a fixed 1.2--1.5 seconds and hope.  That is a guess about how long
// "start python, import paramiko, bind a port" takes, and on a loaded
// machine the guess loses: the client's connect() is refused, and the
// symptom -- "the client could not connect" -- reads like a protocol
// difference rather than like a race.
//
// The gate that pays for the interpreter's cold start is the FIRST one to
// run, which is why the failure always landed on the same gate (loop45) and
// looked like a regression in that gate's subject.  Measured on GitHub run
// 39733154797: loop45 failed with "client could not connect" while every
// later gate, running against the same MITM with the same fixed sleep,
// passed -- and loop45 passed on the previous run with the same code.
//
// The fix is the same one `host/verify_loop46.mjs` already uses for the
// WebSocket bridge: wait for the process to SAY it is ready.  The MITM now
// prints "listening on 127.0.0.1:<port>" on stderr as soon as the socket is
// bound, and this waits for that line.
//
// The port cannot be probed instead -- `sftp_mitm.py` serves exactly one
// connection, so a probe would consume the accept the gate is waiting for.
//
// A timeout is not a failure here.  The caller decides what a peer that
// never came up means; this only says "it is up" or "it is not up yet".

export async function waitForMitmReady(getStderr, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (/listening on 127\.0\.0\.1:\d+/.test(getStderr())) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}
