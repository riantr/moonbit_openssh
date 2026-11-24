// host/win_lock.mjs -- survive the file lock that Windows puts on an
// executable while something else has it open.
//
// ## What the lock is
//
// On this machine TWO real-time protection engines are running at the same
// time:
//
//     360 安全套装        service 360rp            Running
//     火绒 Internet 安全  service HipsDaemon      Running
//
// (`Get-CimInstance -Namespace root\SecurityCenter2 -ClassName
// AntiVirusProduct` and `Get-Service` both report them; Windows Defender
// itself is OFF on this box.)
//
// When one of them has a file open, the open is EXCLUSIVE -- no sharing -- so
// a second `CreateProcess` of that file fails with
// ERROR_SHARING_VIOLATION, which libuv reports as EBUSY, and a plain
// `moon build` that wants to REPLACE the file fails with
//
//     The process cannot access the file because it is being used by
//     another process.
//
// Measured on 2026-11-24, with the lock caught in the act:
//
//     [spawn diag] attempt 1 failed EBUSY errno=-4082
//     [spawn diag] EXCLUSIVE-FAIL: ... 'sftp_server.exe' because it is
//                   being used by another process.
//     ... four more attempts, 0.5s + 1s + 1.5s + 2s of backoff ...
//     [spawn diag] EXCLUSIVE-OK
//
// so the lock is real, it is exclusive, and it is TIME BOUNDED: about five
// seconds, and then it is gone.
//
// ## Why a retry and not a bigger sleep
//
// A gate that fails for a cleanup race is worse than no gate, because it
// teaches the reader to re-run it.  So the retry here is narrow on purpose:
//
//   * it only fires on the two shapes of the lock (EBUSY from `spawn`, and
//     the "being used by another process" text from a build);
//   * anything else is re-thrown or returned at once;
//   * the last attempt still fails, and the failure message says what to
//     look for.
//
// This is the same rule `host/verify_loop92.mjs` already follows for the bed
// teardown (`rmTreeSync`): retry, and if it still fails, say what to look
// for rather than pretending it passed.
//
// ## What this does NOT do
//
// It does not make a build that fails for a real reason pass.  A compile
// error is not a lock, and it comes back on the first attempt.

import { spawn } from "node:child_process";

// The two shapes of the lock, and nothing else.
const LOCK_TEXT = /being used by another process|cannot access the file|sharing violation/i;

// The backoff.  The measured lock lasted about five seconds, so the waits
// are 0.5s, 1s, 1.5s, 2s, 2.5s: five attempts, roughly nine seconds of
// waiting in the worst case.
const DEFAULT_TRIES = 6;
const DEFAULT_BASE_MS = 500;

// Sleep without spinning the event loop.  `Atomics.wait` on a shared
// `Int32Array` is the way to block in Node without burning a core.
export function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Does this text say "the file was locked by somebody else"?
export function isLockText(text) {
  return LOCK_TEXT.test(String(text || ""));
}

// Spawn, and if the image file is locked, wait and try again.
//
// The retry is SYNCHRONOUS on purpose: the call sites are constructors that
// cannot await, and blocking the event loop for a few seconds before the
// child exists is harmless -- there is nothing else in flight yet.
export function spawnLocked(exe, args, opts = {}) {
  let lastErr = null;
  for (let attempt = 1; attempt <= DEFAULT_TRIES; attempt++) {
    try {
      return spawn(exe, args, opts);
    } catch (err) {
      lastErr = err;
      if (err.code !== "EBUSY") throw err;
      if (attempt === DEFAULT_TRIES) break;
      sleepSync(DEFAULT_BASE_MS * attempt);
    }
  }
  const e = new Error(
    `${lastErr.code} spawning ${exe} after ${DEFAULT_TRIES} attempts: ` +
      `${lastErr.message}\n` +
      "  On Windows this is an exclusive lock on the image file.  Two " +
      "real-time protection engines are running on this machine (360 " +
      "'360rp' and Huorong 'HipsDaemon'); one of them was probably still " +
      "scanning the file.  It clears in about five seconds.",
  );
  e.code = lastErr.code;
  throw e;
}

// Run a build, and if the build failed because the OUTPUT file was locked,
// wait and build again.
//
// `run` returns the gates' usual `{ code, out }` shape.  The result is
// returned as it came, so the caller still sees `code !== 0` and still
// prints the compiler's own words -- the retry only decides whether to try
// once more.
export function buildLocked(label, run, opts = {}) {
  const tries = opts.tries || DEFAULT_TRIES;
  const base = opts.baseMs || DEFAULT_BASE_MS;
  let result = null;
  let retries = 0;
  for (let attempt = 1; attempt <= tries; attempt++) {
    result = run();
    if (result.code === 0) break;
    if (!isLockText(result.out)) break;
    if (attempt === tries) break;
    retries++;
    sleepSync(base * attempt);
  }
  if (retries > 0) {
    console.log(
      `  note  ${label}: the output file was locked by another process; ` +
        `built again ${retries} time(s) and it went through.`,
    );
  }
  return result;
}
