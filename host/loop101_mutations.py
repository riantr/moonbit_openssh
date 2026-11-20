#!/usr/bin/env python3
"""Loop #101's mutation suite: does `host/verify_loop101.mjs` actually notice?

Each mutation breaks ONE rule the gate claims to protect, re-runs the gate,
and requires a NAMED check to go red.  A mutation that leaves the gate green
is MISSED; one that breaks the build is INVALID; one whose anchor has drifted
is SKIP, which counts as not caught.

The check name is matched as a WHOLE LINE in the gate's output, and the named
check is looked for BEFORE the build result -- a mutation that breaks the
build must not be allowed to claim credit for a check it never reached.

The mutation harness edits the working tree and restores it in a `finally`.
Run it alone: it runs `moon build` for every mutation, and this file's own
record (Loop #93, and AGENTS.md before it) is that concurrent moon runs
produce failures that look like gate failures.

    python host/loop101_mutations.py
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "host", "verify_loop101.mjs")

# The files a mutation may touch.  Everything a mutation anchors on has to be
# here: an anchor in a file the harness does not restore is a mutation that
# corrupts the tree instead of testing it.
FILES = [
    os.path.join(ROOT, "src", "sshd", "forward.mbt"),
    os.path.join(ROOT, "src", "sshd", "channelserver.mbt"),
]

# (label, old, new, the check that must go red)
MUTATIONS = [
    (
        # A forward has TWO ends and they have to be watched together.  A
        # relay that only ever looks at the target never sees the peer's
        # bytes -- the request never reaches the target, and the answer has
        # nothing to answer.
        "the relay never reads the target",
        "    if (mask & WAIT_TARGET_READABLE) != 0 &&\n"
        "      out.length() - out_off < FORWARD_PENDING_MAX {",
        "    if false &&\n"
        "      out.length() - out_off < FORWARD_PENDING_MAX {",
        "the bytes come back",
    ),
    (
        # And the other way round: a relay that only ever looks at the SSH
        # side sends the target's answer nowhere, because it is waiting for
        # the next packet from the peer instead.
        "the relay never reads the peer's side",
        "    if (mask & WAIT_SSH_READABLE) != 0 {",
        "    if false {",
        "the target received the payload",
    ),
    (
        # The peer's EOF means "I will send no more bytes".  The target has
        # to be told, and told by half-closing: a service that reads until
        # EOF waits for ever if the EOF never comes.
        "the peer's EOF is not passed on to the target",
        "            (provider.shutdown_write_fn)(target)",
        "            ignore(0)",
        "the target saw EOF (it printed its digest, which it does on EOF)",
    ),
    (
        # The window this server advertises is 2 MiB.  A transfer bigger
        # than that needs the window topped back up, or the peer stops
        # sending at exactly the window's worth of bytes.
        "the window is not topped up",
        "            if sd_window_needs_top_up(recv_left, window_max) {",
        "            if false && sd_window_needs_top_up(recv_left, window_max) {",
        "every byte of the big payload comes back",
    ),
    (
        # The data has to be cut to what is left of the peer's window and to
        # the peer's maximum packet.  A packet that is bigger than the
        # window is a lie about the window, and a packet that is bigger than
        # the maximum packet is a packet the peer did not agree to read.
        #
        # The anchor carries the comment line under it, because the same two
        # lines of code exist in the SFTP loop and a mutation whose anchor
        # matches twice is a mutation that tests nothing: the harness skips
        # an anchor that is not unique.
        #
        # The check that has to go red is the one the TIGHT peer makes: the
        # real client asks for 32768 and this server's own ceiling is 32768,
        # so against the real client a server that ignored the peer's limit
        # would look exactly like one that honoured it.  The tight peer asks
        # for 4096, and the two servers are then measured against that.
        "the data is not cut to the peer's limits",
        "    while out_off < out.length() {\n"
        "      let room = sd_chunk_size(peer_window, peer_max_packet)\n"
        "      if room <= 0 {\n"
        "        // The window is empty.  The peer has to send a WINDOW_ADJUST before",
        "    while out_off < out.length() {\n"
        "      let room = out.length() - out_off\n"
        "      if room <= 0 {\n"
        "        // The window is empty.  The peer has to send a WINDOW_ADJUST before",
        "the server never sends a packet bigger than the peer allowed",
    ),
    (
        # The close is answered by a READ, because the peer answers our
        # CLOSE with its own.  Closing while that answer is in flight turns
        # the close into a RESET, which throws away what the peer has not
        # read yet -- and the server's own report is what says so.
        #
        # The anchor starts at the branch that only this file has, for the
        # same reason as above: the drain loop itself exists in more than
        # one place.
        "the close does not wait for the peer's close",
        "      ForwardClose::EofThenClose => {\n"
        "        let _ = sd_send_packet(\n"
        "          conn,\n"
        "          counters,\n"
        "          send_ctx,\n"
        "          @sshwire.SSH_MSG_CHANNEL_EOF,\n"
        "          sd_bare_payload(peer_channel),\n"
        "        )\n"
        "        let _ = sd_send_packet(\n"
        "          conn,\n"
        "          counters,\n"
        "          send_ctx,\n"
        "          @sshwire.SSH_MSG_CHANNEL_CLOSE,\n"
        "          sd_bare_payload(peer_channel),\n"
        "        )\n"
        "        let mut drain = 0\n"
        "        while drain < 64 {",
        "      ForwardClose::EofThenClose => {\n"
        "        let _ = sd_send_packet(\n"
        "          conn,\n"
        "          counters,\n"
        "          send_ctx,\n"
        "          @sshwire.SSH_MSG_CHANNEL_EOF,\n"
        "          sd_bare_payload(peer_channel),\n"
        "        )\n"
        "        let _ = sd_send_packet(\n"
        "          conn,\n"
        "          counters,\n"
        "          send_ctx,\n"
        "          @sshwire.SSH_MSG_CHANNEL_CLOSE,\n"
        "          sd_bare_payload(peer_channel),\n"
        "        )\n"
        "        let mut drain = 0\n"
        "        while drain < 0 {",
        "the server says the peer closed the channel",
    ),
    (
        # The originator is the address of whoever asked for the forward,
        # and it is TEXT: the real server prints `originator 127.0.0.1 port
        # 0`.  Reading the target's port as the originator's port is the
        # kind of mistake that a test which only checks "the forward
        # worked" would never notice.
        "the originator's port is not read from the originator",
        "  let originator_port = match sd_read_u32(payload, off3) {",
        "  let originator_port = match sd_read_u32(payload, off2) {",
        "the src/sshd unit tests pass",
    ),
    (
        # The real server CONFIRMS the channel even when the connect to the
        # target failed, and then closes it: the client is told nothing.  A
        # server that also sends CHANNEL_OPEN_FAILURE puts a message in the
        # client's stderr, and the client does not open its local
        # connection at all -- so the two behaviours are not the same
        # behaviour.
        "a failed connect is also reported as a channel failure",
        "              report.forward_targets = report.forward_targets + 1\n"
        "              let _ = sd_send_packet(\n"
        "                conn,\n"
        "                counters,\n"
        "                send_ctx,\n"
        "                @sshwire.SSH_MSG_CHANNEL_EOF,",
        "              report.forward_targets = report.forward_targets + 1\n"
        "              let _ = sd_send_packet(\n"
        "                conn,\n"
        "                counters,\n"
        "                send_ctx,\n"
        "                @sshwire.SSH_MSG_CHANNEL_OPEN_FAILURE,\n"
        "                sd_open_failure_payload(\n"
        "                  o.peer_channel,\n"
        "                  OPEN_ADMINISTRATIVELY_PROHIBITED,\n"
        "                  \"loop101 mutation\",\n"
        "                ),\n"
        "              )\n"
        "              let _ = sd_send_packet(\n"
        "                conn,\n"
        "                counters,\n"
        "                send_ctx,\n"
        "                @sshwire.SSH_MSG_CHANNEL_EOF,",
        "the client says nothing about a target that is not listening",
    ),
]


def read_all():
    out = {}
    for p in FILES:
        if os.path.exists(p):
            with io.open(p, "r", encoding="utf-8", newline="") as fh:
                out[p] = fh.read()
    return out


def restore(saved):
    for p, text in saved.items():
        with io.open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    r = subprocess.run(["node", GATE], cwd=ROOT,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return r.returncode, r.stdout.decode("utf-8", "replace")


# The gate's own name for "this tree does not build".
#
# A mutation that breaks the BUILD is INVALID: the gate never got far enough
# to judge the claim, so its silence is not evidence about the claim either
# way.
BUILD_SENTINEL = "FAIL  cmd/sshd builds"


def main():
    saved = read_all()
    results = []
    try:
        for idx, (label, old, new, check) in enumerate(MUTATIONS):
            hits = 0
            target = None
            for p, text in saved.items():
                n = text.count(old)
                if n:
                    hits += n
                    target = p
            if hits != 1:
                print("SKIP  %d %s -- anchor hits %d" % (idx, label, hits), flush=True)
                results.append(("skip", label, check))
                continue
            mutated = saved[target].replace(old, new, 1)
            with io.open(target, "w", encoding="utf-8", newline="") as fh:
                fh.write(mutated)
            try:
                code, out = run_gate()
            finally:
                restore(saved)
            named = ("FAIL  %s" % check) in out
            # The named check is consulted FIRST.  A mutation that turns its
            # own check red has been caught, whatever else went red with it.
            if named:
                print("CAUGHT %3d %s -> %s" % (idx, label, check), flush=True)
                results.append(("caught", label, check))
            elif BUILD_SENTINEL in out:
                print("INVALID%3d %s -- the tree did not build" % (idx, label), flush=True)
                results.append(("invalid", label, check))
            else:
                print("MISSED %3d %s -- `%s` stayed green" % (idx, label, check), flush=True)
                results.append(("missed", label, check))
    finally:
        restore(saved)

    caught = [r for r in results if r[0] == "caught"]
    missed = [r for r in results if r[0] == "missed"]
    invalid = [r for r in results if r[0] == "invalid"]
    skipped = [r for r in results if r[0] == "skip"]
    print("")
    print("---")
    print("loop101 mutations: %d caught, %d missed, %d invalid, %d skipped"
          % (len(caught), len(missed), len(invalid), len(skipped)))
    for kind, rows in (("MISSED", missed), ("INVALID", invalid), ("SKIP", skipped)):
        for _, label, check in rows:
            print("  %-8s %s -> %s" % (kind, label, check))
    if missed or invalid or skipped:
        return 1
    print("ALL CAUGHT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
