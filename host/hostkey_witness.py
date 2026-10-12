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

With `--known-hosts`, the client additionally loads those hosts and rejects an
unknown or changed key the way `ssh -o StrictHostKeyChecking=yes` does.  That is
the reference behaviour for Loop #48: OpenSSH compares the presented key
against the pinned one and exits on a mismatch, and paramiko's `RejectPolicy`
is the same rule written by somebody else.

Usage: hostkey_witness.py <port> [--known-hosts PATH] [--json OUT]
Prints one JSON object on stdout.
"""

import argparse
import json
import socket
import sys

import paramiko


def report(result, json_path):
    if json_path:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    print(json.dumps(result))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("--known-hosts")
    ap.add_argument("--json")
    args = ap.parse_args()

    result = {}
    sock = None
    transport = None
    try:
        if args.known_hosts:
            # Pinned hosts go through `SSHClient`, because that is the only
            # place paramiko exposes host key pinning -- a raw `Transport` has
            # no `load_host_keys` at all, and reaching for one anyway would be
            # this file reporting an AttributeError as a verdict on pinning.
            # `RejectPolicy` is the same rule `ssh -o StrictHostKeyChecking=yes`
            # applies, written by somebody else.
            client = paramiko.SSHClient()
            client.load_host_keys(args.known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
            try:
                client.connect(
                    "127.0.0.1",
                    args.port,
                    username="witness",
                    allow_agent=False,
                    look_for_keys=False,
                    timeout=20,
                )
                result["refused"] = False
            except Exception as exc:
                result["refused"] = True
                result["error"] = type(exc).__name__ + ": " + str(exc)
                # Whether it refused *because of the pin* matters as much as
                # whether it refused: a client that failed for some unrelated
                # reason would otherwise count as evidence that pinning works.
                text = (result["error"] or "").lower()
                result["because_of_host_key"] = (
                    "host key" in text
                    or "known_hosts" in text
                    or "known hosts" in text
                    or "badsignature" in text
                )
            finally:
                try:
                    client.close()
                except Exception:
                    pass
            return report(result, args.json)
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
        # listening on. `start_client` can also leave a half-built transport,
        # so it is closed on every path including the rejected one.
        for closeable in (transport, sock):
            if closeable is None:
                continue
            try:
                closeable.close()
            except Exception:
                pass

    return report(result, args.json)


if __name__ == "__main__":
    sys.exit(main())