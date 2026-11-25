#!/usr/bin/env python3
"""Loop #102's mutation suite: does `host/verify_loop102.mjs` actually notice?

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

    python host/loop102_mutations.py
"""

import io
import os
import shutil
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(ROOT, "host", "verify_loop102.mjs")

# The files a mutation may touch.  Everything a mutation anchors on has to be
# here: an anchor in a file the harness does not restore is a mutation that
# corrupts the tree instead of testing it.
FILES = [
    os.path.join(ROOT, "src", "sshd", "remotefwd.mbt"),
    os.path.join(ROOT, "src", "sshd", "channelserver.mbt"),
]

# (label, old, new, the check that must go red)
MUTATIONS = [
    (
        # The reply to a forward with a FIXED port carries NOTHING: the peer
        # already knows which port it asked for, and a payload it is not
        # expecting is a payload the peer may not parse.
        #
        # This is the rule the real server's own behaviour pins: with a fixed
        # port the client's log says `remote forward success for: listen
        # 55123` and nothing about a port, while with port 0 it says
        # `Allocated port 59308` -- which is the port IN the reply.
        "the reply for a fixed port carries the port anyway",
        "  if requested_port == 0 {\n"
        "    @sshwire.write_u32(bound_port.reinterpret_as_uint())\n"
        "  } else {\n"
        "    FixedArray::make(0, b'\\x00')\n"
        "  }",
        "  if requested_port == 0 || requested_port > 0 {\n"
        "    @sshwire.write_u32(bound_port.reinterpret_as_uint())\n"
        "  } else {\n"
        "    FixedArray::make(0, b'\\x00')\n"
        "  }",
        "the reply for a fixed port carries nothing",
    ),
    (
        # The reply to a forward for port 0 carries the port the SERVER
        # CHOSE.  Carrying the port the peer NAMED -- which is 0, because the
        # peer named nothing -- is a reply that tells the peer nothing, and
        # the peer's own port then cannot be connected to.
        "the reply for port 0 carries the port the peer named",
        "          let payload = sd_request_success_payload(binding.port, l.port)",
        "          let payload = sd_request_success_payload(binding.port, binding.port)",
        "the reply for port 0 carries the port as a u32",
    ),
    (
        # The four fields of a `forwarded-tcpip` channel are in this order:
        # the LISTENING pair first, then the ORIGINATOR pair.  The real
        # client's own log prints them in that order -- `listen localhost
        # port 55123, originator 127.0.0.1 port 59284` -- and a third
        # implementation (paramiko) reads them in that order too.
        #
        # Swapping the two pairs is the kind of mistake that a test which
        # only checks "the forward worked" would never notice: the bytes
        # still go through, they just go through a channel that says it is
        # for something else.
        "the two field pairs are in the wrong order",
        "  let body = sd_cat3(\n"
        "    @sshwire.write_u32(max_packet),\n"
        "    @sshwire.write_ssh_string(sd_ascii(listen_address)),\n"
        "    @sshwire.write_u32(listen_port.reinterpret_as_uint()),\n"
        "  )\n"
        "  let tail = sd_cat2(\n"
        "    @sshwire.write_ssh_string(sd_ascii(originator_address)),\n"
        "    @sshwire.write_u32(originator_port.reinterpret_as_uint()),\n"
        "  )",
        "  let body = sd_cat3(\n"
        "    @sshwire.write_u32(max_packet),\n"
        "    @sshwire.write_ssh_string(sd_ascii(originator_address)),\n"
        "    @sshwire.write_u32(originator_port.reinterpret_as_uint()),\n"
        "  )\n"
        "  let tail = sd_cat2(\n"
        "    @sshwire.write_ssh_string(sd_ascii(listen_address)),\n"
        "    @sshwire.write_u32(listen_port.reinterpret_as_uint()),\n"
        "  )",
        "the channel names the address that was connected",
    ),
    (
        # The window this server advertises is 2 MiB and the maximum packet
        # is 32768.  Both were measured off the real client's own log:
        # `client_input_channel_open: ctype forwarded-tcpip rchan 0 win
        # 2097152 max 32768`.
        "the window is not the real one",
        "  let open = sd_forwarded_tcpip_open_payload(\n"
        "    our_channel,\n"
        "    SERVER_WINDOW,\n"
        "    SERVER_MAX_PACKET,",
        "  let open = sd_forwarded_tcpip_open_payload(\n"
        "    our_channel,\n"
        "    SERVER_WINDOW / 2U,\n"
        "    SERVER_MAX_PACKET,",
        "the window is 2097152",
    ),
    (
        # The address in the `forwarded-tcpip` payload is the address the
        # PEER ASKED FOR, echoed back.  The real client asked for
        # `localhost` and its own log says `listen localhost port 52943`,
        # so a server that substitutes an address of its own is not
        # answering the question the peer asked.
        "the listening address is not echoed back as it was asked for",
        "        state.listen_address = binding.address\n"
        "        state.listen_port = l.port",
        "        state.listen_address = \"127.0.0.1\"\n"
        "        state.listen_port = l.port",
        "the client reads the channel's fields the way the real server's does",
    ),
    (
        # The originator is who actually connected to the listening port, and
        # it is TEXT: the real server prints `originator 127.0.0.1 port
        # 59284`.  Reading the listening address as the originator is the
        # kind of mistake that a test which only checks "the forward worked"
        # would never notice.
        "the originator is not who connected",
        "        state.listen_address,\n"
        "        state.listen_port,\n"
        "        ip,\n"
        "        port,",
        "        ip,\n"
        "        state.listen_port,\n"
        "        state.listen_address,\n"
        "        port,",
        "the channel names the originator",
    ),
    (
        # A forward that could not be bound is REFUSED.  The real server
        # answers REQUEST_FAILURE, and the client says `Warning: remote port
        # forwarding failed for listen port N`.  A server that answers
        # SUCCESS and then never listens tells the peer something false.
        "a bind failure is answered with a success",
        "        // `Warning: remote port forwarding failed for listen port N`.\n"
        "        sd_reply_failure(conn, counters, send_ctx, want_reply)\n"
        "        return GlobalRequestOutcome::BindFailed",
        "        // `Warning: remote port forwarding failed for listen port N`.\n"
        "        let _ = sd_send_packet(\n"
        "          conn,\n"
        "          counters,\n"
        "          send_ctx,\n"
        "          @sshwire.SSH_MSG_REQUEST_SUCCESS,\n"
        "          FixedArray::make(0, b'\\x00'),\n"
        "        )\n"
        "        return GlobalRequestOutcome::BindFailed",
        "a port that is already in use is refused",
    ),
    (
        # One remote forward at a time.  The second one is REFUSED rather
        # than ignored: a peer that was told SUCCESS and then got nothing
        # would wait for ever.
        "a second forward is answered with a success",
        "      // One remote forward at a time.  A second one is REFUSED rather than\n"
        "      // silently ignored: a peer that was told SUCCESS and then got nothing\n"
        "      // would wait for ever.\n"
        "      sd_reply_failure(conn, counters, send_ctx, want_reply)\n"
        "      return GlobalRequestOutcome::AlreadyListening",
        "      // One remote forward at a time.  A second one is REFUSED rather than\n"
        "      // silently ignored: a peer that was told SUCCESS and then got nothing\n"
        "      // would wait for ever.\n"
        "      let _ = sd_send_packet(\n"
        "        conn,\n"
        "        counters,\n"
        "        send_ctx,\n"
        "        @sshwire.SSH_MSG_REQUEST_SUCCESS,\n"
        "        FixedArray::make(0, b'\\x00'),\n"
        "      )\n"
        "      return GlobalRequestOutcome::AlreadyListening",
        "a second forward on the same connection is refused, not ignored",
    ),
    (
        # The listening socket is watched through a bit of its own.  If the
        # bit the rules look for is not the bit the driver sets, the server
        # never notices a connection -- and it says nothing, because there
        # is nothing to notice.
        "the listening socket is never noticed",
        "pub const WAIT_LISTENER_READABLE : Int32 = 2",
        "pub const WAIT_LISTENER_READABLE : Int32 = 4",
        "the server opened a channel for the connection",
    ),
    (
        # The `tcpip-forward` request arrives BEFORE any session channel --
        # that is what `ssh -N -R` does, and it never opens one at all.  A
        # server that only answers global requests inside its session loop
        # therefore never answers them at all, and the client waits for a
        # reply that will not come.
        "the global request is not answered before a session channel exists",
        "            } else if t == @sshwire.SSH_MSG_GLOBAL_REQUEST {\n"
        "              // The peer asked for a remote forward.  This is answered HERE",
        "            } else if t == @sshwire.SSH_MSG_GLOBAL_REQUEST &&\n"
        "              payload.length() > 1000000 {\n"
        "              // The peer asked for a remote forward.  This is answered HERE",
        "a request for port 0 is granted",
    ),
    (
        # And the other way round: `ssh -R 55123:target:5432 host cmd` opens
        # a session channel, and THEN asks for the forward.  The request is
        # answered in a second place, and a server that only answered it in
        # the first would leave the ordinary command-line forward hanging.
        "the global request is not answered after a session channel exists",
        "        if t == @sshwire.SSH_MSG_GLOBAL_REQUEST {\n"
        "          // The peer asked for a remote forward, or asked for one to stop.",
        "        if t == @sshwire.SSH_MSG_GLOBAL_REQUEST &&\n"
        "          payload.length() > 1000000 {\n"
        "          // The peer asked for a remote forward, or asked for one to stop.",
        "the forward works after a session channel was opened",
    ),
    (
        # The server's own report says how many bytes it relayed.  "The
        # forward worked" is a claim, and the number of bytes that went
        # through is the part of that claim a gate can check against the
        # client's own.
        #
        # The anchor is the FIRST of the two identical blocks, and it is
        # unique only because the second one has a comment between the wait
        # and the accept -- an anchor that matched twice would be a mutation
        # that tests nothing.
        "the relayed bytes are not counted",
        "            if (mask & WAIT_LISTENER_READABLE) != 0 {\n"
        "              let step = sd_remote_forward_accept(\n"
        "                conn, counters, send_ctx, recv_ctx, provider, remote_state, our_channel,\n"
        "                queue,\n"
        "              )\n"
        "              our_channel = step.our_channel\n"
        "              report.remote_forward_connections = report.remote_forward_connections +\n"
        "                step.outcome.accepted\n"
        "              report.remote_forward_bytes = report.remote_forward_bytes +\n"
        "                step.outcome.bytes_to_peer",
        "            if (mask & WAIT_LISTENER_READABLE) != 0 {\n"
        "              let step = sd_remote_forward_accept(\n"
        "                conn, counters, send_ctx, recv_ctx, provider, remote_state, our_channel,\n"
        "                queue,\n"
        "              )\n"
        "              our_channel = step.our_channel\n"
        "              report.remote_forward_connections = report.remote_forward_connections +\n"
        "                step.outcome.accepted\n"
        "              report.remote_forward_bytes = report.remote_forward_bytes +\n"
        "                0",
        "the server says how many bytes it relayed",
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


# ---------------------------------------------------------------- the backup
#
# The harness edits the working tree.  If it is killed half way through, the
# tree is left mutated -- and a tree that is left mutated is a tree that the
# next `git diff` blames on the next person.
#
# So the originals are copied aside before anything is touched, and the copy
# is marked DONE when the run ends cleanly.  A copy that is NOT marked DONE
# is the debris of an interrupted run, and the next run restores it before it
# starts.  Nothing is deleted: the copies are in `.loop102/`, which is
# ignored, and one directory per run is cheap.
BACKUP_ROOT = os.path.join(ROOT, ".loop102")


def backup_dir():
    return os.path.join(BACKUP_ROOT, "mutation_backup_%d" % int(time.time() * 1000))


def rescue_interrupted():
    """Restore the tree from an interrupted run's backup, if there is one."""
    if not os.path.isdir(BACKUP_ROOT):
        return
    for name in sorted(os.listdir(BACKUP_ROOT)):
        if not name.startswith("mutation_backup_"):
            continue
        d = os.path.join(BACKUP_ROOT, name)
        if not os.path.isdir(d):
            continue
        done = os.path.join(d, "DONE")
        if os.path.exists(done):
            continue
        restored = []
        for p in FILES:
            copy = os.path.join(d, os.path.basename(p))
            if os.path.exists(copy):
                shutil.copyfile(copy, p)
                restored.append(os.path.basename(p))
        with io.open(done, "w", encoding="utf-8") as fh:
            fh.write("restored by a later run\n")
        if restored:
            print("NOTE  restored %s from an interrupted run (%s)"
                  % (", ".join(restored), name), flush=True)


def make_backup(saved):
    d = backup_dir()
    os.makedirs(d, exist_ok=True)
    for p in FILES:
        if os.path.exists(p):
            shutil.copyfile(p, os.path.join(d, os.path.basename(p)))
    return d


def mark_done(d):
    with io.open(os.path.join(d, "DONE"), "w", encoding="utf-8") as fh:
        fh.write("the run finished\n")


# ------------------------------------------------------------------- the run
def run_gate():
    """Run the gate and return (exit code, output).

    The gate takes minutes, and this process may sit silent for most of
    them.  A run that says nothing for a minute looks like a run that died,
    so a heartbeat is printed while the gate works, and the gate's own
    output is streamed rather than collected.
    """
    proc = subprocess.Popen(
        ["node", GATE],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
        errors="replace",
    )
    collected = []
    stop = threading.Event()

    def pump():
        for line in proc.stdout:
            collected.append(line)
            sys.stdout.write("      | " + line)
            sys.stdout.flush()

    def heartbeat():
        waited = 0
        while not stop.wait(20):
            waited += 20
            print("      | ... the gate is still running (%d s)" % waited, flush=True)

    t1 = threading.Thread(target=pump, daemon=True)
    t2 = threading.Thread(target=heartbeat, daemon=True)
    t1.start()
    t2.start()
    code = proc.wait()
    stop.set()
    t1.join(timeout=10)
    return code, "".join(collected)


# The gate's own name for "this tree does not build".
#
# A mutation that breaks the BUILD is INVALID: the gate never got far enough
# to judge the claim, so its silence is not evidence about the claim either
# way.
BUILD_SENTINEL = "FAIL  cmd/sshd builds"


def main():
    rescue_interrupted()
    saved = read_all()
    results = []
    backup = make_backup(saved)
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
            print("MUTATE %d %s -- %s" % (idx, label, check), flush=True)
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
        mark_done(backup)

    caught = [r for r in results if r[0] == "caught"]
    missed = [r for r in results if r[0] == "missed"]
    invalid = [r for r in results if r[0] == "invalid"]
    skipped = [r for r in results if r[0] == "skip"]
    print("")
    print("---")
    print("loop102 mutations: %d caught, %d missed, %d invalid, %d skipped"
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
