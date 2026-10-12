#!/usr/bin/env python3
"""Loop #44: the two transport adapters must keep the same rules.

`src/sshclient/sftp.mbt` and `src/wtlive/sftp.mbt` are near-identical on
purpose. Neither holds protocol -- that lives in `src/sftp.SftpSession`, once
-- but each still holds the *session loop*: wait for OPEN_CONFIRMATION, wait
for CHANNEL_SUCCESS before putting INIT on the wire, push requests through the
peer's window, survive a full window, parse CHANNEL_DATA or fail loudly, and
surface the session's own failure reason.

Two files means two edit sites. Loop #39's G5 proves the browser side works
against a real `internal-sftp`, and Loop #43 proved the state machine and the
channel layer hold under ten malformed replies -- but neither of those can
catch "someone changed the window rule in one file and not the other", because
the happy path does not exercise the window being full and the fault vectors
never reach either adapter's loop.

Why anchors and not a diff. A normalized diff of the two files is ~145 lines
of legitimate difference -- the auth entry points genuinely differ (native
takes a `subsystem` parameter and gets its session state from
`live_auth_with_state`, wtlive hardcodes "sftp" and gets it from
`wt_auth_into`), one is sync and one is async, and the send/receive calls have
different names. That check would fire on every correct edit and be muted on
the next one. What is worth pinning is the smaller claim: **each of these
rules must still be present in both files.** That only goes red when a rule is
actually removed, and each anchor says which rule, so a red line names the
decision rather than a line number.

Each anchor is a statement, not a comment, so deleting the comment that
explains a rule does not satisfy it.
"""

import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NATIVE = os.path.join(ROOT, "src", "sshclient", "sftp.mbt")
WT = os.path.join(ROOT, "src", "wtlive", "sftp.mbt")

# (label, why it matters, native anchor, wtlive anchor)
ANCHORS = [
    (
        "wait for CHANNEL_OPEN_CONFIRMATION",
        "the peer chooses the channel number; a subsystem request sent before "
        "the confirmation names a recipient that does not exist yet",
        "if !opened.0 {",
        "if !opened.0 {",
    ),
    (
        "wait for CHANNEL_SUCCESS on the subsystem",
        "want_reply is TRUE and CHANNEL_FAILURE is the only signal that the "
        "subsystem is missing (session.c:1945-1948). Skipping the wait sends "
        "INIT into a refused channel and the name is never reported",
        "if !acked.0 {",
        "if !acked.0 {",
    ),
    (
        "the subsystem request itself",
        "'sftp' is the name OpenSSH matches; anything else is refused",
        "chan.subsystem_action(subsystem)",
        'chan.subsystem_action("sftp")',
    ),
    (
        "requests go through the peer's window",
        "stdin_take clamps to min(remote_window, remote_max_packet) "
        "(RFC 4254 s5.2). Writing to the socket directly over-sends by "
        "whatever the window allows and the channel is torn down",
        "chan.stdin_take(rest)",
        "chan.stdin_take(rest)",
    ),
    (
        "a full window pumps before giving up",
        "the window is finite, so bytes still queued mean the peer has not "
        "sent WINDOW_ADJUST yet. Treating that as an error truncates the "
        "transfer; treating it as nothing deadlocks",
        "if stuck && rest.length() > 0 {",
        "if stuck && rest.length() > 0 {",
    ),
    (
        "a bound on rounds",
        "any 'the reply will turn up eventually' without a bound is a hang, "
        "not a wait",
        "if rounds > 200000 {",
        "if rounds > 200000 {",
    ),
    (
        "a bound on the clamp spin",
        "stdin_take returns the state unchanged when the window is zero; "
        "without a bound that is an infinite loop wearing a while",
        "spins < 4096",
        "spins < 4096",
    ),
    (
        "a CHANNEL_DATA that will not parse is an error",
        "the payload is the only place SFTP bytes enter the state machine, "
        "so silently dropping one loses data with no error anywhere",
        'Malformed("channel_data")',
        'Malformed("channel_data")',
    ),
    (
        "the parsed payload reaches the session",
        "chan_step advances the channel; handing the bytes to the state "
        "machine is the driver's job. Forgetting it leaves the session "
        "waiting for a reply that already arrived",
        "sess.feed(d)",
        "sess.feed(d)",
    ),
    (
        "the session is pumped every round",
        "a reply may already be buffered while the socket has nothing left, "
        "and stopping there is how a client waits forever for a packet it "
        "already received",
        "sess.pump()",
        "sess.pump()",
    ),
    (
        "only message type 0x5e carries data",
        "SSH_MSG_CHANNEL_DATA is 0x5e; feeding another type's payload into "
        "the SFTP stream would invent bytes the peer never sent",
        "if t == 0x5e {",
        "if t == 0x5e {",
    ),
    (
        "the session's own failure reason is surfaced",
        "an unparsable reply is a completed, reportable outcome, not a "
        "generic transport failure -- the two are different facts",
        "sess.failure_reason()",
        "sess.failure_reason()",
    ),
    (
        "EOF on the clean path",
        "our stdin ends here; without it the remote command reads a stream "
        "that never terminates",
        "chan.eof_action()",
        "chan.eof_action()",
    ),
    (
        "the sent-byte counter is reported",
        "the half of the stream that is ours and is byte-exact",
        "st.counters.sent",
        "st.counters.sent",
    ),
    (
        "the recv-byte counter is reported",
        "reported but NOT compared across transports: it counts the "
        "encrypted stream from the server and carries WINDOW_ADJUST timing, "
        "which is load-sensitive (see verify_loop40's exclusion and Loop #42 "
        "defect 4)",
        "st.counters.recv",
        "st.counters.recv",
    ),
]


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def main():
    if not (os.path.isfile(NATIVE) and os.path.isfile(WT)):
        print("MISSING one of the two transport adapters", file=sys.stderr)
        return 1
    a = read(NATIVE)
    b = read(WT)

    failures = []
    for label, why, sa, sb in ANCHORS:
        in_a = sa in a
        in_b = sb in b
        if in_a and in_b:
            print("  PASS  %s" % label)
            continue
        where = []
        if not in_a:
            where.append("src/sshclient/sftp.mbt")
        if not in_b:
            where.append("src/wtlive/sftp.mbt")
        print("  FAIL  %s  -- missing from %s" % (label, ", ".join(where)))
        print("        %s" % why)
        failures.append(label)

    print()
    if failures:
        print("%d of %d anchors missing" % (len(failures), len(ANCHORS)))
        return 1
    print(
        "the two transport adapters still carry all %d rules" % len(ANCHORS)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
