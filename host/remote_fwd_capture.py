#!/usr/bin/env python3
"""Capture the real bytes of the `ssh -R` half of the forwarding protocol.

Loop #78 needs three facts that a reading of RFC 4254 does not settle:

  1. What does the server put in the REQUEST_SUCCESS reply to "tcpip-forward"?
     The RFC says the reply carries the allocated port "if the client asked
     for port 0".  OpenSSH's server (serverloop.c) only puts a u32 in the
     reply when it actually allocated one, so a client that asked for a
     fixed port gets an EMPTY reply payload.  A parser that unconditionally
     reads a u32 will read past the end of the message -- and on a real
     server that is a protocol error, not a missing field.

  2. What are the four type-specific fields of the inbound "forwarded-tcpip"
     CHANNEL_OPEN?  RFC 4254 calls them "host that was connected" / "port
     that was connected" plus the originator pair, which is exactly the kind
     of wording two implementations can read differently.

  3. Does the port in field 2 mean the port the server was LISTENING on, or
     the ephemeral port of the accepted connection?  OpenSSH 10.4's
     `port_open_helper` (channels.c) puts `get_local_port(c->sock)` -- the
     accepted socket's port -- while the client's own matching code
     (`open_listen_match_tcpip`) compares it against the port the client
     asked to listen on.  Those two readings cannot both be right, and the
     source we have is 10.4 while the sshd in the test rig is 8.0p1.

So this script asks a real server instead of guessing.  It drives the same
sshd the peer gates use, through paramiko -- an implementation that shares
no code with this repository -- and prints the raw bytes of:

  * the REQUEST_SUCCESS reply to "tcpip-forward" (with the server allocating
    a port, and with the client asking for a fixed one), and
  * the inbound "forwarded-tcpip" CHANNEL_OPEN.

Usage:
    python host/remote_fwd_capture.py [--port 22345] [--json OUT]
"""

import argparse
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "host"))

from ssh_user import ssh_user  # noqa: E402

import paramiko  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

# The repository's own test key -- the same one host/pubkey_probe.py uses,
# and the one the sshd's authorized_keys holds.  Password auth does not work
# against this sshd: it authenticates against Windows, and an empty password
# is rejected (measured: "Windows authentication failed for user: hp ...
# error: 1326").  Using the test key keeps the capture on the same
# credentials every other gate uses.
D_HEX = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"


def private_pem():
    sk = ec.derive_private_key(int(D_HEX, 16), ec.SECP256R1())
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# ---------------------------------------------------------------------------
# sshd lifecycle
# ---------------------------------------------------------------------------


def start_sshd(port, name="loop78"):
    """Start the repository's own test sshd and wait until it answers."""
    cmd = [
        "node",
        os.path.join("host", "sshd_setup.mjs"),
        "--port",
        str(port),
        "--name",
        name,
    ]
    child = subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    def reader():
        for line in child.stdout:
            sys.stderr.write("sshd_setup: " + line.decode("utf-8", "replace"))
            sys.stderr.flush()

    threading.Thread(target=reader, daemon=True).start()

    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            s.close()
            return child
        except OSError:
            if child.poll() is not None:
                raise RuntimeError("sshd_setup exited before the port opened")
            time.sleep(0.2)
    raise RuntimeError("sshd never opened port %d" % port)


def stop_sshd(port, name="loop78"):
    subprocess.run(
        [
            "node",
            os.path.join("host", "sshd_setup.mjs"),
            "--port",
            str(port),
            "--name",
            name,
            "--stop",
        ],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ---------------------------------------------------------------------------
# wire helpers (RFC 4251 §5)
# ---------------------------------------------------------------------------


def u32(b, off):
    return (b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3], off + 4


def ssh_string(b, off):
    n, off = u32(b, off)
    return b[off : off + n], off + n


def hexs(b):
    return " ".join("%02x" % x for x in b)


def decode_channel_open(raw):
    """Decode an inbound CHANNEL_OPEN payload the way RFC 4254 §5.1 says."""
    off = 0
    ctype, off = ssh_string(raw, off)
    ctype = ctype.decode("utf-8", "replace")
    sender, off = u32(raw, off)
    window, off = u32(raw, off)
    maxp, off = u32(raw, off)
    out = {
        "type": ctype,
        "sender_channel": sender,
        "window": window,
        "max_packet": maxp,
    }
    if ctype in ("forwarded-tcpip", "direct-tcpip"):
        host, off = ssh_string(raw, off)
        port, off = u32(raw, off)
        oip, off = ssh_string(raw, off)
        oport, off = u32(raw, off)
        out["host"] = host.decode("utf-8", "replace")
        out["port"] = port
        out["originator_ip"] = oip.decode("utf-8", "replace")
        out["originator_port"] = oport
    out["trailing_bytes"] = len(raw) - off
    return out


# ---------------------------------------------------------------------------
# capture
# ---------------------------------------------------------------------------


def capture_one(port, user, listen_port, connect_to_port):
    """One session: ask for a forward, then make the server send us one open.

    Returns a dict with the raw bytes of the reply and of the open.
    """
    got = {"success": [], "failure": [], "open": []}

    def wrap(name, sink):
        orig = getattr(paramiko.Transport, name)

        def patched(self, m):
            try:
                sink.append(m.asbytes())
            except Exception:  # pragma: no cover - diagnostics only
                sink.append(None)
            return orig(self, m)

        setattr(paramiko.Transport, name, patched)
        return orig

    saved = {}
    for name, key in (
        ("_parse_request_success", "success"),
        ("_parse_request_failure", "failure"),
        ("_parse_channel_open", "open"),
    ):
        saved[name] = wrap(name, got[key])

    result = {}
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        t = paramiko.Transport(sock)
        key = paramiko.ECDSAKey.from_private_key(
            io.StringIO(private_pem().decode("ascii"))
        )
        # start_client() rather than connect(): the point of this script is the
        # bytes after authentication, and connect() would also want a host key
        # policy that has nothing to do with the question being asked.
        t.start_client(timeout=20)
        t.auth_publickey(user, key)
        result["authenticated"] = t.is_authenticated()

        # A local echo server stands in for the client's own destination.  The
        # server never connects to it -- only OUR side would -- so the echo
        # server's port is not part of the protocol; it is here so that the
        # channel can be exercised once the open arrives.
        allocated = t.request_port_forward("", listen_port)
        result["allocated_port"] = allocated
        result["reply_success_bytes"] = [b.hex() for b in got["success"]]
        result["reply_failure_bytes"] = [b.hex() for b in got["failure"]]
        if got["success"]:
            result["reply_success_payload_hex"] = got["success"][0][1:].hex()
            result["reply_success_payload_len"] = len(got["success"][0]) - 1
        result["reply_failure_count"] = len(got["failure"])

        # Now make the server accept a connection on its listening port, which
        # is what triggers the inbound "forwarded-tcpip" CHANNEL_OPEN.
        deadline = time.time() + 10
        while time.time() < deadline and not got["open"]:
            try:
                probe = socket.create_connection(
                    ("127.0.0.1", allocated), timeout=2
                )
                probe.close()
            except OSError:
                pass
            time.sleep(0.2)

        if got["open"]:
            # paramiko hands the dispatcher the message PAYLOAD: the one-byte
            # message type has already been consumed by the packetizer, so
            # `m.asbytes()` starts at the channel-type string.
            raw = got["open"][0]
            result["open_payload_hex"] = raw.hex()
            result["open_decoded"] = decode_channel_open(raw)
        else:
            result["open_payload_hex"] = None
            result["open_decoded"] = None

        t.close()
    finally:
        for name, orig in saved.items():
            setattr(paramiko.Transport, name, orig)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=22345, help="port for the test sshd")
    ap.add_argument("--name", default="loop78", help="instance name for sshd_setup")
    ap.add_argument("--json", default="", help="write the capture to this file")
    ap.add_argument(
        "--fixed-port",
        type=int,
        default=0,
        help="ask for this fixed port instead of letting the server allocate",
    )
    args = ap.parse_args()

    user = ssh_user()
    if not user:
        print("cannot determine the account this machine runs as", file=sys.stderr)
        return 3

    child = start_sshd(args.port, args.name)
    out = {"user": user, "sshd_port": args.port}
    try:
        out["allocated_case"] = capture_one(args.port, user, 0, 0)
        if args.fixed_port:
            out["fixed_case"] = capture_one(args.port, user, args.fixed_port, 0)
    finally:
        stop_sshd(args.port, args.name)
        try:
            child.terminate()
        except OSError:
            pass

    print(json.dumps(out, indent=2, sort_keys=True, default=repr))
    if args.json:
        parent = os.path.dirname(os.path.abspath(args.json))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
