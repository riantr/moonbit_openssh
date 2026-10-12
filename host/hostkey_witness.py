#!/usr/bin/env python3
"""A paramiko client, used as an independent witness.

Loop #47 asks whether a MoonBit client refuses a forged host key.  Asking a
MoonBit implementation whether it got something right is not much of a question
-- it is the implementation's own opinion of itself.  So the same forged peer is
offered to paramiko, which was written by somebody else, and the expectation is
that it refuses too.

Only the verdict is reported, and only whether the *key exchange* succeeded.
paramiko authenticates nothing here: `Transport.start_client` is as far as it
goes, which is exactly the line the question is about.  An implementation that
refuses at that line has not sent credentials to an unverified peer; one that
does not has, whatever it decides to do afterwards.

Usage: hostkey_witness.py <port> [--json OUT]
Prints one JSON object on stdout.
"""

import argparse
import json
import socket
import sys

import paramiko


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("--json")
    args = ap.parse_args()

    result = {}
    sock = None
    transport = None
    try:
        sock = socket.create_connection(("127.0.0.1", args.port), timeout=20)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=20)
        key = transport.get_remote_server_key()
        result["refused"] = False
        result["hostkey_type"] = key.get_name()
    except Exception as exc:
        result["refused"] = True
        result["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        # Closing is not optional: the gate waits for this process, and a
        # transport left open keeps the socket the man in the middle is
        # listening on.
        for closeable in (transport, sock):
            if closeable is None:
                continue
            try:
                closeable.close()
            except Exception:
                pass

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())