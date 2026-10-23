"""Mutation check: every Loop #81 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Three rules this script keeps, all learned elsewhere in this repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

  * **A mutation that cannot fail is not evidence either.**  A mutation whose
    check never goes red is worse than no mutation at all, because it looks
    like coverage.

The interesting one in this list is the pair about the *silent* cancel.  The
want_reply=0 form is the one OpenSSH's own client uses, and the server answers
**nothing at all** -- so a successful run proves nothing about it: "no error"
and "the cancel worked" look identical.  That is why the gate sends a second
cancel that does want a reply and asserts it comes back as FAILURE; the
silent cancel is established by the *next* one failing, not by the absence of
a complaint.  The two mutations at the end attack exactly that reasoning: one
reports the silent cancel as answered, the other never sends the second one.

Run:  python host/loop81_mutations.py            # all of them
      python host/loop81_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch. They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "channel", "globalreq.mbt"),
    os.path.join(ROOT, "src", "sshclient", "cancelfwd.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        # The request name is the first thing the server looks at
        # (`strcmp(rtype, "cancel-tcpip-forward")`).  Sending the *request*
        # name instead makes the server start a second forward rather than
        # undo the first one.
        "the cancel is sent under the tcpip-forward name",
        "    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD)),",
        "    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_TCPIP_FORWARD)),",
        "KAT CANC C1 == oracle",
    ),
    (
        # The want_reply byte decides whether the server answers at all.
        # OpenSSH's own client sends 0 here; always sending 1 turns the
        # silent form into a loud one and hides the very case that is hard.
        #
        # The mutation keeps `want_reply` **used**: dropping it would leave
        # the parameter unused, the build would print a warning, and
        # `moon run` exits non-zero on a warning -- so the mutation would be
        # reported INVALID instead of measured.
        "the cancel always asks for a reply",
        "  let want = if want_reply { b'\\x01' } else { b'\\x00' }",
        "  let want = if want_reply { b'\\x01' } else { b'\\x01' }",
        "KAT CANC C1 == oracle",
    ),
    (
        # The same byte, inverted.  The client then waits for a reply the
        # server will never send, and the silent cancel becomes a hang.
        "the cancel's want_reply byte is inverted",
        "  let want = if want_reply { b'\\x01' } else { b'\\x00' }",
        "  let want = if want_reply { b'\\x00' } else { b'\\x01' }",
        "C1 asks for no reply -- the shape OpenSSH's own client sends",
    ),
    (
        # The cancel's payload is `string address` + `uint32 port`.  Swapping
        # them makes the server read the address as a port number, so it
        # compares the port against a listener that was never opened.
        "the cancel puts the port before the address",
        "    @sshwire.write_ssh_string(ch_ascii(listen_host)),\n"
        "    u32be(listen_port),\n"
        "  ])\n"
        "}\n"
        "\n"
        "///|\n"
        "/// 绑定地址的归一化",
        "    u32be(listen_port),\n"
        "    @sshwire.write_ssh_string(ch_ascii(listen_host)),\n"
        "  ])\n"
        "}\n"
        "\n"
        "///|\n"
        "/// 绑定地址的归一化",
        "the cancel's address and port are the request's",
    ),
    (
        # OpenSSH's `channel_rfwd_bind_host` turns "*" into the empty string
        # before sending.  Skip that and the server stores "*" as the
        # listener's path, while the cancel later compares against "" -- so
        # the cancel silently matches nothing.
        "the '*' bind address is not normalised",
        "  if listen_host == \"*\" {\n"
        "    \"\"\n"
        "  } else {",
        "  if listen_host == \"*\" {\n"
        "    \"*\"\n"
        "  } else {",
        "KAT HOST H2 == oracle",
    ),
    (
        # The "tcpip-forward" request must ask for a reply: with want_reply=0
        # and port=0 the server refuses it outright (`!want_reply &&
        # fwd.listen_port == 0` in OpenSSH's serverloop.c), and the port is
        # only knowable from the reply.
        "the forward request asks for no reply",
        "    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_TCPIP_FORWARD)),\n"
        "    FixedArray::from_array([b'\\x01']),",
        "    @sshwire.write_ssh_string(ch_ascii(GLOBAL_REQUEST_TCPIP_FORWARD)),\n"
        "    FixedArray::from_array([b'\\x00']),",
        "result: FORWARD_CANCEL_DONE",
    ),
    (
        # The server compares the port against the one **it** allocated
        # (`c->listening_port`).  Cancelling with the port we asked for (0)
        # matches no listener, so the server answers FAILURE and the forward
        # stays up.
        "the cancel carries the requested port instead of the granted one",
        "    let payload = @channel.cancel_tcpip_forward_request_payload(\n"
        "      host, granted, want_reply,\n"
        "    )",
        "    let payload = @channel.cancel_tcpip_forward_request_payload(\n"
        "      host, listen_port, want_reply,\n"
        "    )",
        "the first cancel was answered with SUCCESS",
    ),
    (
        # The two replies are SSH_MSG_REQUEST_SUCCESS (81) and
        # SSH_MSG_REQUEST_FAILURE (82).  Reading them the other way round
        # turns "there was nothing to cancel" into "the cancel worked", which
        # is the one direction of that mistake that hides a bug.
        "REQUEST_FAILURE is read as success",
        "          if t == @channel.SSH_MSG_REQUEST_SUCCESS {\n"
        "            answered = true\n"
        "            success = true\n"
        "          } else if t == @channel.SSH_MSG_REQUEST_FAILURE {\n"
        "            answered = true\n"
        "            success = false\n",
        "          if t == @channel.SSH_MSG_REQUEST_SUCCESS {\n"
        "            answered = true\n"
        "            success = false\n"
        "          } else if t == @channel.SSH_MSG_REQUEST_FAILURE {\n"
        "            answered = true\n"
        "            success = true\n",
        "the first cancel was answered with SUCCESS",
    ),
    (
        # The silent cancel gets no reply.  Reporting it as answered is the
        # easiest way to make this protocol look finished: the client would
        # claim success for a request the server never acknowledged.
        "the silent cancel is reported as answered",
        "      attempts.push(CancelAttempt::{\n"
        "        want_reply: false,\n"
        "        replied: false,\n"
        "        success: false,\n"
        "      })",
        "      attempts.push(CancelAttempt::{\n"
        "        want_reply: false,\n"
        "        replied: true,\n"
        "        success: true,\n"
        "      })",
        "the silent cancel was not answered -- the server sends nothing",
    ),
    (
        # The ladder's second cancel is what proves the first one worked.
        # Stop after the first and the evidence disappears -- while every
        # individual step still looks fine.
        "only the first cancel is sent",
        "  let mut i = 0\n"
        "  while i < want_reply_steps.length() {",
        "  let mut i = 0\n"
        "  while i < 1 {",
        "the second cancel was answered with FAILURE -- the listener was gone",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    # The regression section is skipped: it runs the gates of Loop #78, #79
    # and #80, which take minutes and cannot be affected by a change to the
    # forwarding files.  What is left is the part this loop is about.
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop81.mjs"), "--skip-regression"],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 10
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
    disagreed, and the way to settle such a disagreement is to run that one
    mutation and read the gate's output, not to re-run the whole batch and
    hope.
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
            if "FAIL  cmd/ssh_live builds for native" in out or \
               "FAIL  cmd/cancel_fwd_kat runs on 4 target x 2 mode" in out:
                # A mutation that does not build proves nothing about the
                # gate.  It is neither caught nor missed; it is a broken
                # mutation, and it has to be fixed.
                #
                # "does not build" covers a warning as well as an error:
                # `moon run` exits non-zero when the build prints a warning,
                # so a mutation that leaves a variable unused cannot even be
                # measured.
                print("INVALID  %s -- the mutation does not build cleanly" % label, flush=True)
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
