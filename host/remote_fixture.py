"""Remote command fixture for the Loop #35 exec checks.

Run on the server side of the SSH connection; the client never sees this file.
Kept as a script rather than an inline `python -c "..."` because four layers of
quoting (PowerShell -> cmd -> moon -> sshd) keep eating the inner ones, and a
test whose command line depends on shell quoting is a test that lies to you.

    python host/remote_fixture.py stdout 1500000 A
    python host/remote_fixture.py stderr 13
    python host/remote_fixture.py both
    python host/remote_fixture.py exit 7
"""

import sys


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
    sys.stdout.flush()
    sys.stderr.flush()


if __name__ == "__main__":
    main()
