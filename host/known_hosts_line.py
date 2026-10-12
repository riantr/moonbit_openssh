#!/usr/bin/env python3
"""Print one `known_hosts` line pinning a PEM key, in OpenSSH's own format.

Loop #48 needs a known_hosts entry for a key the man in the middle is *not*
presenting, so that pinning it is a mismatch by construction. The line is built
here rather than kept as a file in the repo because a key file checked in goes
stale the moment the key is regenerated -- and a stale fixture reads as a
protocol bug, which is the most expensive kind of wrong.

The format is the one OpenSSH writes (`host keytype base64(blob)`), so what is
being parsed is the real thing and not an invention this project agrees with
itself about.

Usage: host/known_hosts_line.py <pem> <host-field>
Prints the line on stdout.
"""

import base64
import io
import os
import sys

import paramiko


def main():
    if len(sys.argv) < 3:
        print("usage: known_hosts_line.py <pem> <host-field>", file=sys.stderr)
        return 2
    pem_path, host_field = sys.argv[1], sys.argv[2]
    if not os.path.isfile(pem_path):
        print("no such key: %s" % pem_path, file=sys.stderr)
        return 2
    with io.open(pem_path, encoding="ascii") as fh:
        key = paramiko.ECDSAKey.from_private_key(io.StringIO(fh.read()))
    print("%s %s %s" % (host_field, key.get_name(), base64.b64encode(key.asbytes()).decode()))
    return 0


if __name__ == "__main__":
    sys.exit(main())