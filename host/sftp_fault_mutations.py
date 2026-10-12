"""Mutation check: Loop #43's channel-layer decisions must turn the driver red.

A gate that stays green under every mutation is not testing anything.  These
mutate exactly the decisions that `cmd/sftp_fault` exists to cover -- the ones
in `src/sftp`'s framing plus the two ordering rules the driver itself relies
on -- and each one is the plausible mistake on the other side of an argument
that was actually had.

The ones worth reading twice:

  * **`want` not reset after a short read.**  `SftpInbuf::take` returns the
    body it has and must remember how many more bytes the *same* packet needs.
    A driver that resets `want` after every partial feed treats the tail of a
    length-prefixed packet as the head of a new one, and the file comes back
    half-length with no error anywhere.  This is only visible when the
    inbound stream is re-sliced at a cut point that lands inside a packet --
    which is precisely the axis `chop_sizes` varies.

  * **feeding the channel before the SFTP state machine.**  Both
    `run_sftp_session` implementations `chan_step` first and then
    `parse_data` -> `sess.feed`.  A driver that only steps the channel never
    hands the reply to the session, and the session waits forever.  Mutating
    the driver to skip the `feed` reproduces exactly the failure the first
    version of this driver had.

  * **the length prefix excluding itself.**  `put_u32(mlen,
    sshbuf_len(m))` -- the count is of everything *after* itself
    (sftp-client.c:160-161).  Off by four and the packet still parses
    locally if the reader is wrong the same way; only a real peer notices.

Run:  python host/sftp_fault_mutations.py
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Every file this loop's gate can reach through, restored together.
FILES = [
    os.path.join(ROOT, "src", "sftp", "proto.mbt"),
    os.path.join(ROOT, "src", "sftp", "build.mbt"),
    os.path.join(ROOT, "src", "sftp", "parse.mbt"),
    os.path.join(ROOT, "src", "sftp", "stream.mbt"),
    os.path.join(ROOT, "src", "sftp", "session.mbt"),
    os.path.join(ROOT, "cmd", "sftp_fault", "main.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    # ---- framing: the length prefix -------------------------------------
    (
        "count the length prefix in the length itself",
        "pub fn sftp_frame(body : FixedArray[Byte]) -> FixedArray[Byte] {",
        "pub fn sftp_frame(body : FixedArray[Byte]) -> FixedArray[Byte] {\n"
        "  // sftp-client.c:151-173 -- the count excludes itself\n"
        "  return sftp_cat([put_u32i(body.length() + 4), body])",
        "requests",
    ),
    # ---- framing: the reassembly buffer ---------------------------------
    (
        "forget how much of the current packet is still owed after a short feed",
        "    self.want = n\n    self.drop(4)",
        "    self.want = n\n    self.drop(4)\n    self.want = -1",
        "chop",
    ),
    (
        "size the buffer from the claimed length before bounding it",
        "    if n < 0 || n > SFTP_MAX_MSG_LENGTH {",
        "    if n < 0 {",
        "oversize_length_prefix",
    ),
    # "consume the bytes of a refused packet anyway" is deliberately NOT here.
    # It changes `SftpInbuf::take` on a path that returns None immediately
    # afterwards (`self.failed` latches and every later `take` bails), so
    # nothing this gate observes can move -- dropping four bytes that no one
    # reads is not a difference. It is not a hole in the gate; it belongs to
    # the loop that already asserts it, as `length_over_max_refused` and its
    # `expect_pending: 13` in `cmd/sftp_test`. Listing it here would have been
    # a MISSED that said nothing about `cmd/sftp_fault`.
    # ---- driver ordering: hand the reply to the session ------------------
    (
        "step the channel but never feed the session (the driver's own first bug)",
        "      match @channel.parse_data(payload) {\n        None => ()\n"
        "        Some((_who, d)) => sess.feed(d)\n      }",
        "      match @channel.parse_data(payload) {\n        None => ()\n"
        "        Some((_who, _d)) => ()\n      }",
        "requests",
    ),
    # ---- reply classification -------------------------------------------
    # This one anchors on the MoonBit session's own id check rather than the
    # driver's, because that is where the rule lives: a wrong-id reply is
    # dropped, not fatal.  Making it fatal turns `wrong_request_id` red, and
    # it is the decision `src/sftp/session.mbt` documents at length.
    (
        "treat a wrong-id reply as fatal instead of ignoring it",
        "    WantRealpath(id) => {\n      if reply_id(r) != id {\n        return\n      }",
        "    WantRealpath(id) => {\n      if reply_id(r) != id {\n"
        "        self.phase = PH_FAILED\n"
        "        self.failure = Some(\"wrong id\")\n        return\n      }",
        "wrong_request_id",
    ),
]

def read():
    state = {}
    for p in FILES:
        with open(p, encoding="utf-8") as fh:
            state[p] = fh.read()
    return state


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    # `moon` emits UTF-8 box-drawing diagnostics on Windows consoles whose
    # active code page is GBK, and `text=True` would decode them as GBK and
    # raise.  Read bytes and decode explicitly.  flush keeps what was printed
    # on a dying child, and a generous maxBuffer keeps a cold compile from
    # killing it for an unrelated reason.
    r = subprocess.run(
        ["moon", "run", "cmd/sftp_fault", "--target", "native"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    return (r.stdout or "") + (r.stderr or "")


def main():
    original = read()
    failures = []
    try:
        for label, old, new, must_fail in MUTATIONS:
            target = None
            for p, text in original.items():
                if text.count(old) == 1:
                    target = p
                    break
            if target is None:
                counts = {os.path.basename(p): t.count(old)
                          for p, t in original.items()}
                print("SKIP  %s -- anchor count %s" % (label, counts))
                failures.append(label)
                continue
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            out = run_gate()
            # Three distinct verdicts, and conflating them is how a mutation
            # list quietly stops meaning anything:
            #   NOBUILD -- the mutated source did not compile. There was no
            #              run, so nothing was proven either way.
            #   CRASH   -- it compiled and blew up at run time. Caught: a gate
            #              that cannot survive the mutation is still a gate
            #              that noticed it.
            #   CAUGHT  -- it ran and a named check went FAIL.
            #   MISSED  -- it ran and every check still passed.
            if "error:" in out.lower() or "Error: [" in out:
                first = next(
                    (ln.strip() for ln in out.splitlines() if "rror" in ln), ""
                )
                print("NOBUILD  %s" % label)
                failures.append(label)
                if first:
                    print("        " + first)
                continue
            crashed = "PanicError" in out or "panic" in out.lower()
            caught = (
                ("FAIL " + must_fail) in out
                or (must_fail + ":") in out
                or (must_fail + "@") in out
            )
            if crashed:
                print("CRASH  %s  (the gate did not survive it)" % label)
                continue
            print("%s  %s" % ("CAUGHT" if caught else "MISSED", label))
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if "FAIL" in line:
                        print("        " + line.strip())
    finally:
        write(original)

    print()
    if failures:
        print("MUTATION CHECK FAILED: %d of %d not caught"
              % (len(failures), len(MUTATIONS)))
        return 1
    print("all %d mutations turned the channel-layer gate red" % len(MUTATIONS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
