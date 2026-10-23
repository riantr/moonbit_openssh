#!/usr/bin/env python3
"""host/refusal_latency.py -- how long does a refused TCP connection take to
become visible on this machine?

Loop #83 needs this number, and it needs it measured with the **same kind of
socket** the implementation uses.

Why the same kind of socket matters
-----------------------------------
There are two ways to find out that a connect was refused: read SO_ERROR, or
notice that `select()` reported the socket.  On Windows a refusal lands the
socket in the **except** set, and -- this is the part that matters -- it does
not land there immediately.  Measured on this machine:

    a normal Winsock socket      the refusal becomes visible after ~2.0 s
    node's socket (libuv)        the refusal becomes visible after ~0.002 s

Both numbers are real; they are not measuring the same thing.  node creates
its sockets with WSA_FLAG_OVERLAPPED, and an overlapped socket reports the
connect failure through its completion path, which is prompt.  A plain
socket -- the kind `socket()` gives you, and the kind `src/tcp/winsock.c`
uses -- does not see the error until the connect attempt has expired.

So a calibration taken with node would say "a refusal shows up in two
milliseconds, a deadline and a refusal are the same thing", and the check
that distinguishes them would be skipped -- on a machine where the
distinction plainly exists.

This script therefore measures it the way the implementation measures it: a
plain socket, a non-blocking connect, and then `select()` on the write set
**and** the except set with SO_ERROR polled while waiting.

Usage:
    python host/refusal_latency.py <port>

Prints the latency in milliseconds on stdout, or -1 if the connection
succeeded (there was no refusal to measure), or -2 if nothing arrived within
the budget.
"""

import errno
import select
import socket
import sys
import time

# How long to wait for the refusal to show up.  The implementation's own
# default per-address budget is 5 s, so anything that shows up after that is
# not something the implementation could ever report as a refusal.
BUDGET_S = 8.0

# The slice the implementation waits with.  Keeping the two the same means
# the measurement sees the refusal at the same moment the implementation
# would.
SLICE_S = 0.1


def latency(port, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    t0 = time.time()
    rc = s.connect_ex((host, port))
    if rc == 0:
        s.close()
        return -1
    if rc not in (errno.EWOULDBLOCK, errno.EINPROGRESS):
        s.close()
        return -1
    while time.time() - t0 < BUDGET_S:
        r, w, x = select.select([s], [s], [s], SLICE_S)
        so_err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if so_err != 0 or r or w or x:
            ms = (time.time() - t0) * 1000.0
            s.close()
            return ms
    s.close()
    return -2


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: refusal_latency.py <port>\n")
        return 2
    port = int(sys.argv[1])
    print("%.0f" % latency(port))
    return 0


if __name__ == "__main__":
    sys.exit(main())
