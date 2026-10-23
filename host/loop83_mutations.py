"""Mutation check: every Loop #83 defect must turn the gate red.

A gate that stays green under a set of mutations is not testing anything, so
this script is part of the loop's evidence rather than a one-off.

Each mutation below is one of the ways this code could plausibly be wrong, and
each one names the gate check that has to go red because of it.

Three rules this script keeps, all learned elsewhere in this repository:

  * **A compile failure is not evidence.**  A mutation that does not compile
    proves nothing about the gate, so it gets its own verdict (INVALID)
    instead of being counted as caught or missed.  A *warning* counts the same
    way: `moon run` exits non-zero when the build prints a warning, so a
    mutation that leaves a variable unused cannot even be measured.

  * **The anchor has to hit exactly once, in exactly one file.**  An anchor
    that has drifted (the formatter rewrapped the line, say) is reported as
    SKIP and counted as "not caught" -- which points the finger at the gate
    rather than at the thing that actually moved.

  * **A mutation that cannot fail is not evidence either.**  A mutation whose
    check never goes red is worse than no mutation at all, because it looks
    like coverage.

The interesting ones in this list are the three about **how a refused
connection becomes visible**, because they are the ones this platform is
unusual about:

  * Windows puts a refused connect in the **except** set, not in the write
    set.  An implementation that waits only for writability waits out the
    whole deadline on every refusal and never learns that the connect had
    already failed.

  * The refusal is not visible straight away: measured here, a plain
    Winsock socket sees it after about two seconds.  So a deadline shorter
    than that has to report a timeout, and a deadline longer than that has
    to report a refusal.  Two labels for the same closed port, decided by
    the deadline -- which is the only way to tell that the deadline is doing
    anything at all.

  * The error code is the system's own, not one we invented.  A refusal
    carries WSAECONNREFUSED (10061), and a client that reports "something
    went wrong" instead has thrown away the only part of the failure the
    user can act on.

The pair about **which address** is the other half of the loop.  A name
usually maps to more than one address, and the resolver's order is not a
matter of taste: OpenSSH's own client names the addresses it tries, and a
client that picked a different one, or stopped after the first, would be a
client that cannot reach half the hosts on the internet.

Run:  python host/loop83_mutations.py            # all of them
      python host/loop83_mutations.py --only 5   # just one, for settling a
                                                 # disagreement with the gate
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every file a mutation may touch. They are restored together, because a
# failed run must not leave the tree mutated.
FILES = [
    os.path.join(ROOT, "src", "tcp", "winsock.c"),
    os.path.join(ROOT, "src", "tcp", "socket_common.mbt"),
    os.path.join(ROOT, "cmd", "ssh_keyscan", "main.mbt"),
]

# (label, original, mutated, a check name that must go FAIL)
MUTATIONS = [
    (
        # The resolver hands back a LIST of addresses, and the client has to
        # try all of them.  Keeping only the IPv4 ones would leave every
        # IPv6-only host unreachable -- and would quietly change which
        # address a name means.
        "IPv6 addresses are dropped from the resolved list",
        "        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {",
        "        if (ai->ai_family != AF_INET) {",
        "the name resolved to two addresses",
    ),
    (
        # OpenSSH's ssh_connect_direct: "try each one in sequence until the
        # connection succeeds".  Stopping after the first address means a
        # name whose first address does not answer is simply unreachable,
        # even though the second one would have worked.
        "only the first resolved address is tried",
        "    for (k = 0; k < n; k++) {",
        "    for (k = 0; k < 1; k++) {",
        "the second address was tried and connected",
    ),
    (
        # The order is not a matter of taste: the first address is the one
        # the resolver prefers, and it is the one a server that is listening
        # on both stacks will answer on.  Trying them backwards changes
        # which server answers.
        "the addresses are tried in the opposite order",
        "    for (k = 0; k < n; k++) {",
        "    for (k = n - 1; k >= 0; k--) {",
        "the first address was tried and refused",
    ),
    (
        # The port belongs to the resolution: getaddrinfo fills it into every
        # address it returns.  Losing it sends the connection to port 22
        # whatever the caller asked for.
        #
        # The check that catches it is the server's own log, not "did we get
        # three keys": a machine that happens to run an sshd on port 22 would
        # answer the scan perfectly well, three keys and all, and the scan
        # would still have gone to the wrong server.
        "the port is lost during the resolution",
        '    snprintf(strport, sizeof(strport), "%d", port);',
        '    snprintf(strport, sizeof(strport), "%d", 22);',
        "the server logged three more connections for the scan by name",
    ),
    (
        # A refused connect has to be *noticed*.  There are two independent
        # ways this code notices it -- the socket shows up in select()'s
        # except set, and SO_ERROR is polled while the wait goes on -- and
        # this mutation removes **both**.
        #
        # Removing only one of them is an equivalent mutant, and that is worth
        # recording rather than pretending otherwise: the two mechanisms
        # report the refusal at the same moment (measured: ~2.0 s for both),
        # so either one alone is enough to catch it.  The check below is
        # therefore about the pair, and the gate is what says the refusal was
        # noticed at all -- and as what.
        "a refused connect is never noticed",
        "            FD_ZERO(&xfds);\n"
        "            FD_SET(s, &xfds);\n"
        "            tv.tv_sec = slice / 1000;\n"
        "            tv.tv_usec = (slice % 1000) * 1000;\n"
        "            ready = select(0, NULL, &wfds, &xfds, &tv);\n"
        "            if (ready == SOCKET_ERROR) {\n"
        "                *err_out = WSAGetLastError();\n"
        "                closesocket(s);\n"
        "                return -1;\n"
        "            }\n"
        "            if (ready == 0) {\n"
        "                /* Nothing yet. The refusal may already be sitting in\n"
        "                 * SO_ERROR even though select() did not report the socket,\n"
        "                 * so read it before waiting again. */\n"
        "                waited += slice;\n"
        "                optval = 0;\n"
        "                optlen = sizeof(optval);\n"
        "                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&optval,\n"
        "                               &optlen) == 0 && optval != 0) {\n"
        "                    *err_out = optval;\n"
        "                    closesocket(s);\n"
        "                    return -1;\n"
        "                }\n"
        "                continue;\n"
        "            }",
        "            FD_ZERO(&xfds);\n"
        "            tv.tv_sec = slice / 1000;\n"
        "            tv.tv_usec = (slice % 1000) * 1000;\n"
        "            ready = select(0, NULL, &wfds, &xfds, &tv);\n"
        "            if (ready == SOCKET_ERROR) {\n"
        "                *err_out = WSAGetLastError();\n"
        "                closesocket(s);\n"
        "                return -1;\n"
        "            }\n"
        "            if (ready == 0) {\n"
        "                waited += slice;\n"
        "                continue;\n"
        "            }",
        "a refused connection says CONNECT_FAILED",
    ),
    (
        # SO_ERROR is where the reason lives.  Throwing it away leaves the
        # user with "something went wrong" instead of the system's own code,
        # and 10061 ("connection refused") is the difference between "the
        # server is not listening" and "the network is broken".
        "the error code of a failed connect is lost",
        "            if (optval != 0) {\n"
        "                *err_out = optval;\n"
        "                closesocket(s);\n"
        "                return -1;\n"
        "            }\n"
        "            break;",
        "            if (optval != 0) {\n"
        "                *err_out = 0;\n"
        "                closesocket(s);\n"
        "                return -1;\n"
        "            }\n"
        "            break;",
        "the refusal carries the system's own code",
    ),
    (
        # The address that was reached is the answer to "did it work, and
        # where".  Reporting the first address of the list instead of the
        # one that was actually used says the connection went somewhere it
        # did not go.
        "the address that was reached is misreported",
        "    mb_put_u32(report + MB_TCP_REPORT_CHOSEN,\n"
        "               chosen < 0 ? MB_TCP_NONE : (unsigned int)chosen);",
        "    mb_put_u32(report + MB_TCP_REPORT_CHOSEN,\n"
        "               chosen < 0 ? MB_TCP_NONE : 0u);",
        "the tool says which address it reached",
    ),
    (
        # A name that does not resolve and a connection that is refused are
        # different problems.  Reporting the first as the second sends the
        # user looking at the server when the name is the problem.
        "a name that does not resolve is reported as a connect failure",
        "  } else if status == 1 {\n"
        "    Some(TcpFailure::ResolveFailed)",
        "  } else if status == 1 {\n"
        "    Some(TcpFailure::ConnectFailed(-1))",
        "a name that does not resolve says RESOLVE_FAILED",
    ),
    (
        # The deadline running out is not the same as being refused, and it
        # is not the same as a name that does not resolve.  All three need
        # different answers.
        "a timeout is reported as a connect failure",
        "  } else if status == 3 {\n"
        "    Some(TcpFailure::ConnectTimeout)",
        "  } else if status == 3 {\n"
        "    Some(TcpFailure::ConnectFailed(-1))",
        "a deadline shorter than the refusal says CONNECT_TIMEOUT",
    ),
    (
        # The deadline the caller asked for is the deadline the connect gets.
        # Making it longer turns every timeout into a refusal, which is the
        # one difference the deadline exists to express.
        "the deadline the caller asked for is ignored",
        "  let report = @tcp.TcpConn::connect_with_timeout(host, port, timeout_ms)",
        "  let report = @tcp.TcpConn::connect_with_timeout(host, port, timeout_ms + 60000)",
        "a deadline shorter than the refusal says CONNECT_TIMEOUT",
    ),
    (
        # OpenSSH's ssh-keyscan rejects a zero timeout (`convtime()` calls it
        # invalid), and so does this tool.  Accepting it would mean "no
        # deadline" where the user asked for "no time at all".
        "a timeout of zero is accepted",
        '    Some(0) => {\n'
        '      eprintln("result: BAD_USAGE")\n'
        '      eprintln(\n'
        '        "usage: ssh_keyscan [-p port] [-t type] [-T seconds] [-v] host [host ...]",\n'
        '      )\n'
        '      return\n'
        '    }',
        "    Some(0) => DEFAULT_TIMEOUT_SECONDS * 1000",
        "a timeout of zero is a usage error, as it is in OpenSSH",
    ),
]


def read():
    return {p: open(p, "r", encoding="utf-8", newline="").read() for p in FILES}


def write(state):
    for p, text in state.items():
        with open(p, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)


def run_gate():
    # The regression section is skipped: it runs the gates of Loop #78 to
    # #82, which take minutes and cannot be affected by a change to the
    # transport files.  What is left is the part this loop is about.
    r = subprocess.run(
        ["node", os.path.join("host", "verify_loop83.mjs"), "--skip-regression"],
        cwd=ROOT, capture_output=True,
        # text=True alone would decode the gate's output with the locale
        # codec (cp936 here), and one box-drawing character would raise
        # UnicodeDecodeError *inside* the batch loop -- the child would die
        # after the last flushed line, looking exactly like "0 caught, 11
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
            if "FAIL  cmd/ssh_keyscan builds for native" in out or \
               "FAIL  the whole tree type-checks" in out:
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
