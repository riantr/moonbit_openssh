"""Recompute the Loop #37 stdin pattern locally, for the verify script.

The client's `--stdin-bytes N` builds N bytes by taking a fixed ASCII pattern
modulo its length (`src/sshclient/live.mbt: ssh_stdin_pattern`).  This is that
same pattern, so the harness can say what the remote *must* report without
trusting either the client's own count or the server's.

    python host/stdin_expect.py 3145728
"""

import hashlib
import sys

PATTERN = b"loop37-stdin-block-"


def stdin_pattern(n):
    reps = n // len(PATTERN) + 1
    return (PATTERN * reps)[:n]


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 3145728
    data = stdin_pattern(n)
    assert len(data) == n
    print("len %d" % len(data))
    print("sha256 %s" % hashlib.sha256(data).hexdigest())
    print("head %s" % data[:16].hex())
    print("tail %s" % data[-16:].hex())


if __name__ == "__main__":
    main()