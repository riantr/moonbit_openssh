"""Remote command fixture for the Loop #35/#37 exec checks.

Run on the server side of the SSH connection; the client never sees this file.
Kept as a script rather than an inline `python -c "..."` because four layers of
quoting (PowerShell -> cmd -> moon -> sshd) keep eating the inner ones, and a
test whose command line depends on shell quoting is a test that lies to you.

    python host/remote_fixture.py stdout 1500000 A
    python host/remote_fixture.py stderr 13
    python host/remote_fixture.py both
    python host/remote_fixture.py exit 7
    python host/remote_fixture.py cat
    python host/remote_fixture.py envvar LOOP37_TEST

`cat` is the Loop #37 flow-control oracle.  It reads stdin **to EOF** and prints
the byte count and the SHA-256 of what arrived, so the client is checked against
a property of the bytes that actually landed on the far side -- not against its
own idea of what it sent.  It only terminates because the client sends
CHANNEL_EOF: without that, a command like this blocks forever and the test would
hang instead of fail.
"""

import hashlib
import os
import sys


def _report_env(out, name):
    """Report one variable the server handed to the session.

    The only honest way to check that `env` was accepted: the request carries
    want_reply = FALSE (RFC 4254 6.4), so a refusal produces no packet at all
    and the client side has nothing to observe.
    """
    out.write("env_present %d\n" % (1 if name in os.environ else 0))
    out.write("env_value %s\n" % os.environ.get(name, ""))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "both"
    if mode == "stdout":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
        ch = sys.argv[3] if len(sys.argv) > 3 else "A"
        sys.stdout.write(ch * n)
    elif mode == "stderr":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 13
        sys.stderr.write("E" * n)
    elif mode == "both":
        sys.stdout.write("out-loop35\n")
        sys.stderr.write("err-loop35\n")
    elif mode == "exit":
        code = int(sys.argv[2]) if len(sys.argv) > 2 else 7
        sys.stdout.write("bye-loop35\n")
        sys.exit(code)
    elif mode == "cat":
        data = sys.stdin.buffer.read()
        sys.stdout.write("stdin_len %d\n" % len(data))
        sys.stdout.write("stdin_sha256 %s\n" % hashlib.sha256(data).hexdigest())
        if data:
            sys.stdout.write("stdin_head %s\n" % data[:16].hex())
            sys.stdout.write("stdin_tail %s\n" % data[-16:].hex())
        # The environment rides the same channel, so reporting it here is what
        # makes "env and stdin both took effect" a single observation instead of
        # two runs that could each pass for the wrong reason.
        _report_env(sys.stdout, "LOOP37_TEST")
    elif mode == "envvar":
        # Prints the variable the server actually handed to the session, which
        # is the only honest way to check that `env` was accepted: the request
        # carries want_reply = FALSE, so a refusal is silent on the wire.
        _report_env(sys.stdout, sys.argv[2] if len(sys.argv) > 2 else "LOOP37_TEST")
    sys.stdout.flush()
    sys.stderr.flush()


if __name__ == "__main__":
    main()
