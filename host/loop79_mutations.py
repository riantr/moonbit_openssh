"""Mutation check: every Loop #79 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Two rules this script keeps, both learned the hard way elsewhere in this
repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

A third rule, learned inside this loop: **a mutation that cannot fail is not
evidence either.**  The first version of this list contained "never send our
EOF", and it was EQUIVALENT for the same reason Loop #78 found: the state
machine answers the peer's CLOSE with a CLOSE of its own, so the transfer
finishes either way and only the check that counts the EOF notices.  It is
kept here because *this* loop's relay sends its EOF from the **local** side
(the local connection hung up), and the server does not close on its own
there -- so the mutation does hang the client, and the check does go red.

Run:  python host/loop79_mutations.py            # all of them
      python host/loop79_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch. They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "channel", "exec.mbt"),
    os.path.join(ROOT, "src", "sshclient", "locallisten.mbt"),
    os.path.join(ROOT, "src", "tcp", "socket_common.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        # The bug Loop #78 was closed for, reintroduced in the other relay.
        #
        # `stdin_take` CLIPS the payload to the channel window and returns the
        # rest.  The rest is not "the part we did not send" -- it is "the part
        # we have not sent YET".  Dropping it is silent data loss: the client
        # believes it forwarded everything, the far end received less, and
        # nothing anywhere reports an error.
        #
        # The check that catches it is the one at the FAR end: the sink prints
        # how many bytes it received, and the gate compares that with how many
        # the probe sent.
        "drop the bytes the window clipped",
        "          chan = c2\n          pending = rest\n          match action {",
        "          chan = c2\n"
        "          pending = FixedArray::make(0, b'\\x00')\n"
        "          match action {",
        "the far end received every byte",
    ),
    (
        # The originator is the address of the party that connected to the
        # LOCAL listener.  Loop #76 could only put "127.0.0.1", 0 in here,
        # because nobody was listening and there was no peer address to
        # report.  Now there is one, and the server's own log records it.
        #
        # A client that reports a made-up originator is a client that cannot
        # be audited by the server: the server's access log would name a port
        # that never existed.
        #
        # Measured: this does NOT change what the client prints about the
        # connection -- the client still knows the probe's real port, and
        # still reports it.  It changes what goes into the CHANNEL_OPEN, and
        # therefore what the SERVER writes in its log.  The check that catches
        # it is therefore the one that compares the server's log with the
        # probe's real port, not the one that reads the client's own report.
        "report a made-up originator address",
        "    dest_host, dest_port, originator_ip, originator_port,\n  )",
        "    dest_host, dest_port, \"127.0.0.1\", 0,\n  )",
        "the originator the server saw is the probe's real port",
    ),
    (
        # The port has to be read back OFF the socket.  The caller asked for
        # port 0 to mean "you pick", and a caller that cannot find out which
        # port was picked cannot connect to its own listener.
        #
        # The symptom of getting this wrong is a listener that answers on a
        # port nobody can connect to -- which looks exactly like a listener
        # that never bound at all.
        "report port 0 instead of the port the socket got",
        "  be16(b, 0)\n}",
        "  0\n}",
        "the port it reports is a real port",
    ),
    (
        # The peer address comes back from accept().  Faking the port makes
        # the server's log name a port that is not the one that connected --
        # and it makes the client's own report disagree with the server.
        "report a made-up peer port",
        "  Accepted(conn, ipv4(b, 0), be16(b, 4))",
        "  Accepted(conn, ipv4(b, 0), 0)",
        "it saw the peer's real port",
    ),
    (
        # Two local connections on one SSH session are two channels, and two
        # channels have two numbers.  Reusing the number makes the server
        # address one connection's traffic to the other.
        "reuse the channel number for every connection",
        "        local_channel = local_channel + 1",
        "        local_channel = local_channel + 0",
        "the server saw two channels with different numbers",
    ),
    (
        # The bytes arrive, are parsed, and are then dropped on the floor.
        # The relay keeps running, the counters keep counting, and the probe
        # at the other end gets nothing.
        "drop the bytes the channel delivered",
        "  let out = ch_cat_all(self.stdout)\n  ({ ..self, stdout: [], }, out)",
        "  let out = FixedArray::make(0, b'\\x00')\n  ({ ..self, stdout: [], }, out)",
        "the probe received the relayed bytes",
    ),
    (
        # WINDOW_ADJUST is how the peer tells us it has room again.  Not
        # applying it means our view of the window only ever shrinks, so a
        # transfer larger than the window stalls half way through -- and the
        # far end never learns that anything is wrong.
        "do not let WINDOW_ADJUST reopen the window",
        "          ({ ..st, remote_window: st.remote_window + n, }, none, None)",
        "          ({ ..st, }, none, None)",
        "the far end received every byte",
    ),
    (
        # The bytes that the window clipped are counted when they are read
        # (only the part the channel took) and again when they are actually
        # sent.  Forget the second half and the client reports fewer bytes
        # than it moved -- while the far end received every byte.
        #
        # The symptom is a report that is *smaller* than the truth, on a
        # transfer that worked.  It is the kind of defect that hides in
        # production for years, because nothing is broken -- only counted
        # wrong.
        "do not count the bytes that were clipped and sent later",
        "                local_to_channel = local_to_channel + before - pending.length()",
        "                local_to_channel = local_to_channel + before - before",
        "the client counted every byte it moved",
    ),
    (
        # EOF is "my input direction has no more data".  The local connection
        # hanging up is exactly that, and the server has to be told -- or it
        # waits for ever for a request that is never finished.
        "never send our EOF when the local connection hangs up",
        "          more = false\n"
        "          let (c2, eof) = chan.eof_action()\n"
        "          chan = c2\n"
        "          match eof {",
        "          more = false\n"
        "          let (c2, eof) = (chan, None)\n"
        "          chan = c2\n"
        "          match eof {",
        "EOF was sent and the channel closed",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop79.mjs")],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 7
        # missed" with no traceback in the captured stderr.  Explicit utf-8
        # with replacement cannot raise, whatever the gate prints.
        encoding="utf-8", errors="replace", text=True,
        timeout=3600,
    )
    return r.stdout + r.stderr


def selected():
    """The mutations to run, in order.

    `--only N` runs a single one.  That is not a convenience: this list went
    through a round where the author's expectation and the measurement
    disagreed (the EOF was expected to be harmless, and it is not -- on this
    side of the relay the server does NOT close on its own), and the way to
    settle such a disagreement is to run that one mutation and read the
    gate's output, not to re-run the whole batch and hope.
    """
    if len(sys.argv) < 3 or sys.argv[1] != "--only":
        return list(enumerate(MUTATIONS))
    idx = int(sys.argv[2])
    if idx < 0 or idx >= len(MUTATIONS):
        print("--only takes 0..%d" % (len(MUTATIONS) - 1))
        sys.exit(2)
    return [(idx, MUTATIONS[idx])]


def main():
    original = read()
    failures = []
    chosen = selected()
    try:
        for idx, (label, old, new, must_fail) in chosen:
            # The file that contains the anchor -- and it has to contain it
            # EXACTLY once, in exactly one file.  An anchor that appears
            # twice is a mutation that might hit the wrong place.
            hits = {os.path.basename(p): t.count(old) for p, t in original.items()}
            targets = [p for p, t in original.items() if t.count(old) == 1]
            if len(targets) != 1 or sum(hits.values()) != 1:
                print("SKIP  %s -- anchor hits %s" % (label, hits), flush=True)
                failures.append(label)
                continue
            target = targets[0]
            state = dict(original)
            state[target] = state[target].replace(old, new)
            write(state)
            out = run_gate()
            if "FAIL  cmd/ssh_live builds (native)" in out or \
               "FAIL  cmd/listen_kat builds (native)" in out:
                # A mutation that does not compile proves nothing about the
                # gate.  It is neither caught nor missed; it is a broken
                # mutation, and it has to be fixed.
                print("INVALID  %s -- the mutation does not compile" % label, flush=True)
                failures.append(label)
                continue
            caught = ("FAIL  %s" % must_fail) in out
            print("%s  [%d] %s" % ("CAUGHT" if caught else "MISSED", idx, label),
                  flush=True)
            if not caught:
                failures.append(label)
                for line in out.splitlines():
                    if line.startswith("  FAIL"):
                        print("        " + line.strip(), flush=True)
    finally:
        write(original)

    print()
    if failures:
        print("MUTATION CHECK FAILED: %d of %d not caught"
              % (len(failures), len(chosen)))
        return 1
    print("all %d mutations turned the gate red" % len(chosen))
    return 0


if __name__ == "__main__":
    sys.exit(main())
