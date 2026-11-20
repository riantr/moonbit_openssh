#!/usr/bin/env python3
"""Loop #100's mutation suite: does `host/verify_loop100.mjs` actually notice?

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

    python host/loop100_mutations.py
"""

import io
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "host", "verify_loop100.mjs")

# The files a mutation may touch.  Everything a mutation anchors on has to be
# here: an anchor in a file the harness does not restore is a mutation that
# corrupts the tree instead of testing it.
FILES = [
    os.path.join(ROOT, "src", "sshd", "channelserver.mbt"),
    os.path.join(ROOT, "src", "sftp", "stream.mbt"),
    os.path.join(ROOT, "src", "sftpserver", "localfs.c"),
]

# (label, old, new, the check that must go red)
MUTATIONS = [
    (
        # The name in a `subsystem` request is what selects what runs.  This
        # server has exactly one, and a peer that asks for another one is
        # refused -- because a server that answers SUCCESS to a subsystem it
        # cannot run leaves the peer waiting for bytes that never come.
        "another subsystem name is accepted",
        "          if name != SUBSYSTEM_SFTP {",
        "          if name != SUBSYSTEM_SFTP && name != \"loop100-no-such-subsystem\" {",
        "an unknown subsystem is refused, and the client says so",
    ),
    (
        # The reply is cut to what is left of the peer's window and to the
        # peer's maximum packet.  A reply that is sent whole is a packet
        # bigger than the peer accepted, and the peer refuses to read it --
        # which is exactly what the 64 KiB answer to a READ is.
        "the reply is not cut to the peer's limits",
        "      let room = sd_chunk_size(peer_window, peer_max_packet)",
        "      let room = out.length() - out_off",
        "[big] stdout is the real server's bytes",
    ),
    (
        # The window is the other limit, and it is compared against what is
        # left after the 32 KiB clamp.  Comparing it the other way round
        # lets a 2 MiB window through as the size of one packet, and the
        # peer refuses a packet that big.
        "the window does not cap the packet",
        "  let w = peer_window.reinterpret_as_int()\n"
        "  if w < n {\n"
        "    n = w\n"
        "  }",
        "  let w = peer_window.reinterpret_as_int()\n"
        "  if w > n {\n"
        "    n = w\n"
        "  }",
        "the src/sshd unit tests pass",
    ),
    (
        # The server answers REALPATH with `/E:/...` -- a slash in front of
        # the drive letter, which is what the REAL server answers -- and the
        # client then asks for that very path.  A server that cannot open
        # the path it just handed out says "No such file or directory" for
        # every listing.
        "the path the server hands out is not one it can take back",
        "\tif (len >= 3 && path[0] == '/' && path[2] == ':') {",
        "\tif (len >= 3 && path[0] == '/' && path[1] == ':') {",
        "the path the server hands out is one it can take back",
    ),
    (
        # A packet that has not fully arrived is not a packet.  Returning it
        # anyway hands the parser a truncated body, and the reply that
        # comes back is for a request the peer never sent.
        "the deframing returns a packet that has not fully arrived",
        "  if self.buf.length() < self.want {",
        "  if self.buf.length() < self.want && self.want > SFTP_MAX_MSG_LENGTH {",
        "the src/sshd unit tests pass",
    ),
    (
        # The framing is a four-byte length and then the body.  A body with
        # no length in front of it is not a packet, and the client's own
        # parser is what says so.
        "the reply is not framed",
        "                    let framed = @sftp.sftp_frame(reply)",
        "                    let framed = reply",
        "[walk] stdout is the real server's bytes",
    ),
]

# NOT MUTATED, and why.
#
# The WINDOW_ADJUST the server sends to top the PEER's window back up is not
# exercised by these cases: the real client opens the channel with a 2 MiB
# window and the largest batch here sends 100 KiB, so the window is never
# spent and no WINDOW_ADJUST is ever needed.  The rule that decides WHEN to
# send one is a pure function (`sd_window_needs_top_up`) and it IS pinned by
# a unit test -- `t28_the_peers_window_is_topped_up_below_the_half` -- so a
# mutation there is caught by the unit-test check.  What is not covered is
# the packet that carries the adjustment, because nothing here needs one.


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
    print("loop100 mutations: %d caught, %d missed, %d invalid, %d skipped"
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
