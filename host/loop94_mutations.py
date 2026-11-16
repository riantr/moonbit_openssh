#!/usr/bin/env python3
"""Loop #94's mutation suite: does `host/verify_loop94.mjs` actually notice?

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

    python host/loop94_mutations.py
"""

import io
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "host", "verify_loop94.mjs")

# The files a mutation may touch.  Everything a mutation anchors on has to be
# here: an anchor in a file the harness does not restore is a mutation that
# corrupts the tree instead of testing it.
FILES = [
    os.path.join(ROOT, "src", "sshwire", "msg.mbt"),
    os.path.join(ROOT, "src", "sshd", "channelserver.mbt"),
    os.path.join(ROOT, "cmd", "sshd", "main.mbt"),
    os.path.join(ROOT, "src", "subproc", "subproc.mbt"),
]

# (label, old, new, the check that must go red)
MUTATIONS = [
    (
        # CHANNEL_EOF is 96.  The table said 95 until this loop, which is
        # CHANNEL_EXTENDED_DATA -- and nothing noticed, because every test
        # that used the constant also built packets with it.
        "CHANNEL_EOF is one byte low",
        "pub const SSH_MSG_CHANNEL_EOF : Byte = b'\\x60'",
        "pub const SSH_MSG_CHANNEL_EOF : Byte = b'\\x5f'",
        "SSH_MSG_CHANNEL_EOF is 96",
    ),
    (
        # The message that did not exist in the table at all.
        "EXTENDED_DATA is removed from the table",
        "pub const SSH_MSG_CHANNEL_EXTENDED_DATA : Byte = b'\\x5f'",
        "pub const SSH_MSG_CHANNEL_EXTENDED_DATA : Byte = b'\\x5e'",
        "SSH_MSG_CHANNEL_EXTENDED_DATA is 95",
    ),
    (
        # The window the real server advertises.  Zero is what the real
        # CLIENT prints for it, and believing that line is the mistake this
        # number exists to record.
        "the server advertises a zero window",
        "pub const SERVER_WINDOW : UInt32 = 2097152U",
        "pub const SERVER_WINDOW : UInt32 = 0U",
        "the src/sshd unit tests pass",
    ),
    (
        # The confirmation's two channel numbers, the other way round.  Every
        # later packet then addresses a channel the peer never opened, and
        # the peer ignores all of them.
        "the confirmation swaps recipient and sender",
        "  sd_cat2(@sshwire.write_u32(peer_channel), @sshwire.write_u32(our_channel)),",
        "  sd_cat2(@sshwire.write_u32(our_channel), @sshwire.write_u32(peer_channel)),",
        "the src/sshd unit tests pass",
    ),
    (
        # stderr on the STDOUT message.  Both streams arrive, in the wrong
        # one, and only a byte-exact comparison of the two sees it.
        "stderr is sent as ordinary data",
        "    let msg_type = if extended {\n"
        "      @sshwire.SSH_MSG_CHANNEL_EXTENDED_DATA\n"
        "    } else {\n"
        "      @sshwire.SSH_MSG_CHANNEL_DATA\n"
        "    }",
        "    let msg_type = @sshwire.SSH_MSG_CHANNEL_DATA",
        "[stderr] stderr is the real server's bytes",
    ),
    (
        # The exit status, one off.  The client prints it and exits with it.
        "the exit status is off by one",
        "    @sshwire.write_u32(code.reinterpret_as_uint()),",
        "    @sshwire.write_u32((code + 1).reinterpret_as_uint()),",
        "[exit3] the exit status is 3",
    ),
    (
        # The drain after our CLOSE.  Without it the close is a RESET while
        # the peer's answering CLOSE is in flight, the reset discards what
        # the peer has not read, and `Connection reset` is what the client
        # says -- with the command's output already thrown away.
        #
        # The anchor is the `moon fmt` shape of the block, which is flatter
        # than it looks when written by hand: `while drain < 64 {` and its
        # body are on one line.  An anchor copied from the hand-written
        # version hit zero times and the mutation was SKIPped -- and a SKIP
        # counts as NOT CAUGHT, which is the correct outcome for a mutation
        # that never ran.
        "the peer's CLOSE is not waited for",
        "        let mut drain = 0\n"
        "        while drain < 64 {\n"
        "          drain = drain + 1\n"
        "          match sd_recv_packet(conn, counters, recv_ctx) {\n"
        "            Closed => break\n"
        "            BadPacket(_) => break\n"
        "            Packet(t, _) =>\n"
        "              if t == @sshwire.SSH_MSG_CHANNEL_CLOSE {\n"
        "                report.peer_closed = true\n"
        "                break\n"
        "              }\n"
        "          }\n"
        "        }",
        "        let mut drain = 0\n"
        "        while drain < 0 {\n"
        "          drain = drain + 1\n"
        "        }",
        "our server read the peer's CLOSE before it closed the connection",
    ),
    (
        # The command line's quotes.  Without them cmd.exe leaves no trailing
        # quote, and `echo loop94-stdout` comes back two bytes shorter.  Only
        # a byte comparison sees that.
        "the command is not wrapped in quotes",
        '  let args = "/c \\"" + command + "\\""',
        "  let args = \"/c \" + command",
        "the trailing quote cmd.exe leaves behind is IN the output",
    ),
    (
        # The capture buffer read through a `Bytes` that COPIES.  This is the
        # defect that made the first working server return sixteen zero
        # bytes: the length was right, every byte was wrong.
        "the captured bytes never leave the scratch buffer",
        "  for i = 0; i < k; i = i + 1 {\n"
        "    buf[off + i] = scratch[i]\n"
        "  }",
        "  let _ = buf",
        "a command's stdout is not a run of zero bytes",
    ),
    (
        # The command runner answering a fixed status.  The report is the
        # only place that says which status reached the wire, so this is the
        # check that the report is about the SERVER and not a constant.
        "the reported exit status is a constant",
        "        report.exit_status = result.code",
        "        report.exit_status = 0",
        "our server reports the exit status the client received",
    ),
]

# NOT MUTATED, and why.
#
# The `channel_type` branch -- a `direct-tcpip` or `x11` open is refused with
# reason 3 while a `session` one is confirmed -- is not exercised by this
# gate.  Every case in it asks the real client for a session channel, because
# that is what `ssh host command` opens; driving a `direct-tcpip` open needs
# `-W` or a port forward, which is a different loop's subject.
#
# A mutation there would be an EQUIVALENT mutation: it changes bytes no case
# looks at, so it cannot come back caught, and listing it as MISSED would be
# a false accusation against the gate.  It is recorded here so that the
# absence is a decision rather than an oversight -- `verify_loop94.mjs`
# covers the session path byte for byte, and the other channel types are
# untested.


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
#
# The first version of this check searched the whole output for "error" and
# made three VALID mutations look INVALID.  The second version included the
# unit-test check, which was wrong in the other direction: a failing unit
# test is the mutation being CAUGHT by the first line of defence, not the
# tree failing to build.  So this is exactly one check name, and the two
# mutations the unit tests catch name that check as their target.
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
    print("loop94 mutations: %d caught, %d missed, %d invalid, %d skipped"
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
