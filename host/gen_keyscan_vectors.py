#!/usr/bin/env python3
"""Reference vectors for the known_hosts line rules `ssh-keyscan` depends on.

Loop #82's end-to-end test compares this client's whole output against the
real `ssh-keyscan`, byte for byte.  That covers the non-standard-port shape,
because the test server listens on a high port.  Two rules it cannot reach:

  * the **default port** shape (a bare host name, no brackets) -- that would
    need a server on port 22, a privileged port a gate may not bind;
  * the **lowercasing** -- that needs a host name with upper-case letters
    that still resolves to the test server.

So the two rules are pinned here, as cases, where they can be stated -- and so
is their composition (`KEYFIELD`), which is the shape the tool itself writes.

Both functions are transcribed from OpenSSH 10.4:

  * `put_host_port` (misc.c): port 0 or 22 -> the host as typed; anything
    else -> "[host]:port".  The brackets are what keep an IPv6 literal from
    swallowing the port.
  * `lowercase` (misc.c): ASCII upper-case letters become lower-case, and
    nothing else moves.

Usage:
    python host/gen_keyscan_vectors.py
"""

import sys


def put_host_port(host, port):
    if port == 0 or port == 22:
        return host
    return "[%s]:%d" % (host, port)


def lowercase(s):
    out = []
    for ch in s:
        c = ord(ch)
        if 65 <= c <= 90:
            out.append(chr(c + 32))
        else:
            out.append(ch)
    return "".join(out)


def main():
    out = []

    for label, host, port in (
        ("H1", "127.0.0.1", 0),
        ("H2", "127.0.0.1", 22),
        ("H3", "127.0.0.1", 2222),
        ("H4", "example.com", 2222),
        ("H5", "::1", 2222),
    ):
        out.append("HOSTFIELD %s %s %d %s" % (label, host, port, put_host_port(host, port)))

    for label, text in (
        ("L1", "Example.COM"),
        ("L2", "127.0.0.1:2222"),
        ("L3", "[Example.COM]:2222"),
    ):
        out.append("LOWER %s %s" % (label, lowercase(text)))

    # The two rules composed, the way ssh-keyscan uses them: `lowercase` is
    # applied to the whole `put_host_port` result, not to the host alone.
    for label, host, port in (
        ("K1", "Example.COM", 2222),
        ("K2", "Example.COM", 22),
        ("K3", "127.0.0.1", 0),
    ):
        out.append("KEYFIELD %s %s %d %s" % (label, host, port, lowercase(put_host_port(host, port))))

    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
