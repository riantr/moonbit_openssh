// host/ready_line.mjs -- wait until a process SAYS it is ready.
//
// ## The rule this implements
//
// Loop #79's follow-up wrote it down:
//
//     **A gate must not guess how long a peer takes to start.**  A sleep is
//     a guess, and a guess that loses produces a failure that looks like a
//     protocol difference rather than like a race.
//
// The first user of the rule was `host/mitm_ready.mjs`, which waits for the
// SFTP MITM to print `listening on 127.0.0.1:<port>` on stderr.  The second
// is `host/verify_loop93.mjs`, which waits for the SSH recorder to print
// `READY <port>` on stdout.
//
// One helper for both, because the rule is about gates and not about any
// one protocol: a gate that needs a peer to be up asks the peer.
//
// A timeout is not a failure here.  The caller decides what a peer that
// never came up means; this only says "it is up" or "it is not up yet".

export async function waitForReadyLine(getText, pattern, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (pattern.test(getText())) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}
