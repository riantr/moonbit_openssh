"""Mutation check: every Loop #78 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.  Three of the
eight are caught by the byte comparison against paramiko, and the other five by
the end-to-end relay against a real OpenSSH server.

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
evidence either.**  "Never send our CLOSE" was in an earlier version of this
list.  It is EQUIVALENT: the state machine answers the peer's CLOSE with a
CLOSE of its own, so the client finishes exactly as before and every check
stays green.  A mutation that provably cannot turn the gate red says nothing
about what the gate covers, so it was replaced by one that can.

Run:  python host/loop78_mutations.py            # all of them
      python host/loop78_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch. They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "channel", "channel.mbt"),
    os.path.join(ROOT, "src", "channel", "exec.mbt"),
    os.path.join(ROOT, "src", "channel", "globalreq.mbt"),
    os.path.join(ROOT, "src", "sshclient", "remotefwd.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        # The two channel numbers in a confirmation are the easiest pair in
        # the whole protocol to swap, and swapping them does not look like an
        # error: the packet is well formed, the server just addresses a
        # channel that does not exist.  The bytes are wrong, and the byte
        # comparison against paramiko says so.
        "swap the two channel numbers in the open confirmation",
        "  ch_cat_all([u32be(recipient), u32be(sender), u32be(window), u32be(max_packet)])",
        "  ch_cat_all([u32be(sender), u32be(recipient), u32be(window), u32be(max_packet)])",
        "vector c1 is byte-identical to paramiko's encoder",
    ),
    (
        # want_reply=FALSE is what a client sends when it does not want to
        # hear back.  The server refuses a port-0 request that way, so the
        # symptom is "the forward never starts" -- which is also what a
        # half-implemented feature looks like.
        "ask for no reply in the tcpip-forward request",
        "    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_TCPIP_FORWARD)),\n"
        "    FixedArray::from_array([b'\\x01']),",
        "    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_TCPIP_FORWARD)),\n"
        "    FixedArray::from_array([b'\\x00']),",
        "vector r1 is byte-identical to paramiko's encoder",
    ),
    (
        # The reply carries a port only when the SERVER allocated one.  When
        # the client named the port itself, the reply payload is empty, and
        # "there is no port in the reply" means "the port you asked for", not
        # "port zero".  Reading it as zero sends the client to port 0.
        "read an empty reply as port 0 instead of the port we asked for",
        "            None => listen_port\n            Some(p) => p",
        "            None => 0\n            Some(p) => p",
        "the granted port is the one we asked for",
    ),
    (
        # Answering the server's channel open with a FAILURE is a perfectly
        # well formed packet, and it is what this client does when it does
        # not want the channel.  The server then closes the connection, and
        # the probe at the other end gets nothing.
        "answer the server's channel open with a failure instead of a confirmation",
        "      Send(\n        0x5b,\n        channel_open_confirmation_payload(",
        "      Send(\n        0x5c,\n        channel_open_confirmation_payload(",
        "the probe received the relayed bytes",
    ),
    (
        # The bytes arrive, are parsed, and are then dropped on the floor.
        #
        # The check that catches it is the one about the **probe's** bytes,
        # not the one about the payload's: the payload's echo travels from
        # the local target INTO the channel, so dropping what the channel
        # delivers does not touch it.  The probe's bytes travel the other way
        # and come back as an echo -- and that echo never arrives.
        "drop the bytes the channel delivered",
        "  let out = ch_cat_all(self.stdout)\n  ({ ..self, stdout: [], }, out)",
        "  let out = FixedArray::make(0, b'\\x00')\n  ({ ..self, stdout: [], }, out)",
        "the probe's own bytes made the round trip",
    ),
    (
        # CHANNEL_EOF addressed to our own channel number instead of the
        # peer's.
        #
        # The channel number in a channel message names the **recipient's**
        # channel, in the recipient's own id space.  Our number is 0, and on
        # the server side 0 is not the forwarded channel -- it is a different
        # channel entirely.  The packet is well formed, so nothing complains:
        # the server simply takes it for the end of some other channel.
        #
        # Measured, by running this mutation on its own: the relay itself
        # still works (the probe's bytes make the round trip, the client
        # exits 0), but the connection is torn down underneath it and the
        # client reports REMOTE_FORWARD_FAILED instead of a finished forward.
        # That is the check that has to go red.
        "address CHANNEL_EOF to our own channel instead of the peer's",
        "    Some(Send(0x60, channel_bare_payload(self.remote_id))),",
        "    Some(Send(0x60, channel_bare_payload(self.local_channel))),",
        "the client reports the forward as done",
    ),
    (
        # Never send our EOF at all.
        #
        # EOF is "my input direction has no more data".  The relay works
        # without it -- and that is exactly the problem: the client goes
        # through the whole forward without ever telling the peer that it
        # was done sending.
        #
        # Measured, by running this mutation on its own: every check stays
        # green except the one that counts the EOF.  The server does not
        # need our EOF to close the channel (our CLOSE is enough for that),
        # and the client still exits cleanly, so nothing else notices --
        # which is why a defect like this can only be caught by a check that
        # looks at what we actually sent.
        "never send our EOF",
        "  (\n"
        "    { ..self, eof_sent: true, },\n"
        "    Some(Send(0x60, channel_bare_payload(self.remote_id))),\n"
        "  )",
        "  (\n"
        "    self,\n"
        "    None,\n"
        "  )",
        "EOF was sent and the channel closed",
    ),
    (
        # The forwarded-tcpip payload carries two ports: the one the server
        # was listening on, and the port of the party that connected to it.
        # Reading the second one where the first belongs makes the client
        # believe it was asked about a connection it never heard of.
        "read the originator port where the listen port belongs",
        "                                    port: p,",
        "                                    port: op,",
        "vector p1 is byte-identical to paramiko's encoder",
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
        ["node", os.path.join("host", "verify_loop78.mjs")],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 7
        # missed" with no traceback in the captured stderr.  Explicit utf-8
        # with replacement cannot raise, whatever the gate prints.
        encoding="utf-8", errors="replace", text=True,
        timeout=1800,
    )
    return r.stdout + r.stderr


def selected():
    """The mutations to run, in order.

    `--only N` runs a single one.  That is not a convenience: this list went
    through a round where the author's expectation and the measurement
    disagreed (the EOF addressed to the wrong channel was expected to hang
    the client; measured, it tore the connection down instead), and the way
    to settle such a disagreement is to run that one mutation and read the
    gate's output, not to re-run the whole batch and hope.  The check a
    mutation names therefore has to be the one that **measurably** goes red.
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
               "FAIL  cmd/remote_fwd_kat builds (native)" in out:
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
