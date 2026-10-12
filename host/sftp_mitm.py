#!/usr/bin/env python3
"""A man-in-the-middle SSH server that speaks SFTP badly on purpose.

Loops #41-M2 and #43 prove `src/sftp`'s state machine and `src/channel`'s
framing hold against ten malformed replies.  Neither can reach a *transport
adapter*: `run_sftp_session` is private in both `src/sshclient/sftp.mbt` and
`src/wtlive/sftp.mbt`, and both take a post-authentication session state as
their entry point, so the only way to hand either one a malformed reply is to
complete an SSH handshake with it first.

That is what this is.  It is paramiko in **server** mode, so the key exchange,
cipher setup, NEWKEYS and userauth are a real SSH implementation doing real
crypto -- none of it re-derived, none of it trusted.  What it does *not* do is
speak SFTP: once the client opens a channel and asks for the `sftp` subsystem,
this server acknowledges the request and then writes raw bytes from a scenario
straight onto the channel.  There is no `SFTPServer` anywhere in this file,
and there is no code path that could grow one by accident, because the whole
point is that the peer is *wrong* in ways a real `internal-sftp` is not.

The transcript is recorded above the channel, so what the gate reads back is
the SFTP byte stream both ends exchanged -- the same layer `host/sftp_capture.py`
records when it talks to the real OpenSSH server, which is what makes the two
comparable.

Why the server accepts any public key: the thing under test is what the client
does with SFTP bytes after authentication, and a key check would test
`src/userauth` instead. Authentication is exercised for real by Loop #34 and by
the live sshd gate; here it is only the door.

Usage:
    python host/sftp_mitm.py <port> <scenario-name> [--chop N] [--json OUT]

Prints one JSON object on stdout when the session ends.
"""

import argparse
import io
import json
import os
import socket
import sys
import threading
import time

import paramiko

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sftp_fault_oracle import SCENARIOS  # noqa: E402

# A throwaway host key. It is regenerated per run, never trusted by anyone,
# and its only job is to be a well-formed ECDSA key paramiko will offer.
HOST_KEY_PATH = os.path.join(ROOT, ".loop44", "mitm_host_key.pem")


def host_key():
    """Generate (once) a host key. A real file, because paramiko's server mode
    wants a key object and constructing one from an in-memory ECDSA key is
    more code than writing a PEM and reading it back."""
    if not os.path.isfile(HOST_KEY_PATH):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        os.makedirs(os.path.dirname(HOST_KEY_PATH), exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(HOST_KEY_PATH, "wb") as fh:
            fh.write(pem)
    return paramiko.ECDSAKey.from_private_key(
        io.StringIO(open(HOST_KEY_PATH, encoding="ascii").read())
    )


class SftpMisbehavingServer(paramiko.ServerInterface):
    """Authenticates everything, then answers the channel requests itself.

    `check_auth_publickey` returns AUTH_SUCCESSFUL without ever looking at the
    key, which is a decision and not an oversight -- see the module header.
    `check_channel_subsystem_request` is where the interesting part is: it
    accepts `"sftp"` and records that it was asked, so the channel handler can
    know the client is past the want_reply barrier.
    """

    def __init__(self):
        self.subsystem = None
        self.event = threading.Event()

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_subsystem_request(self, channel, name):
        self.subsystem = name
        return True

    def check_channel_exec_request(self, channel, command):
        return False


def chop(data, size):
    if size <= 0:
        return [data]
    return [data[i : i + size] for i in range(0, len(data), size)]


def serve_one(sock, scenario, chop_size, result):
    """Run one connection to completion.

    paramiko's own threading means `accept` returns a live `Transport`-able
    socket; everything after the handshake is ours.
    """
    t = paramiko.Transport(sock)
    t.local_version = "SSH-2.0-mitm"
    t.add_server_key(host_key())
    server = SftpMisbehavingServer()
    try:
        t.start_server(server=server, event=None)
        chan = t.accept(20)
        if chan is None:
            result["error"] = "no channel accepted"
            return

        # The client sends OPEN, then the subsystem request with want_reply.
        # paramiko answers the request for us (`check_channel_subsystem_request`
        # returned True), which is the CHANNEL_SUCCESS the driver is waiting
        # for.  Only now is it legitimate to write SFTP bytes: writing earlier
        # would be a channel-level race, not an SFTP fault.
        deadline = time.time() + 10
        while server.subsystem is None and time.time() < deadline:
            time.sleep(0.01)
        if server.subsystem is None:
            result["error"] = "client never asked for a subsystem"
            return

        # --- the injection -------------------------------------------------
        # Record what the client sends, at the SFTP layer, so the transcript
        # can be compared against the same expectations the channel-layer gate
        # uses.  These bytes went through `stdin_take` and a real socket, which
        # is the part no other gate has exercised.
        c2s = bytearray()
        s2c = bytearray()
        result["subsystem"] = server.subsystem
        result["requests"] = []

        # Drain the client's requests in a thread while we write, because a
        # single-threaded loop that only writes would deadlock as soon as the
        # client's window fills.
        stop = threading.Event()

        def drain():
            while not stop.is_set():
                try:
                    data = chan.recv(65536)
                except Exception:
                    return
                if not data:
                    return
                c2s.extend(data)
                # Reassemble the SFTP stream exactly as a server would.
                result.setdefault("_buf", bytearray()).extend(data)
                buf = result["_buf"]
                while len(buf) >= 4:
                    n = int.from_bytes(buf[:4], "big")
                    if n > 262144 or len(buf) < 4 + n:
                        break
                    body = bytes(buf[4 : 4 + n])
                    del buf[: 4 + n]
                    # The length prefix does NOT count itself
                    # (`put_u32(mlen, sshbuf_len(m))`, sftp-client.c:160-161),
                    # so re-framing is the body's own length -- the one thing
                    # this MITM must not get wrong, since a wrong re-frame
                    # would make every transcript differ from the
                    # expectations for a reason that has nothing to do with
                    # the fault being injected.
                    result["requests"].append(
                        len(body).to_bytes(4, "big").hex() + body.hex()
                    )

        t_worker = threading.Thread(target=drain, daemon=True)
        t_worker.start()

        try:
            # The oracle keeps `feeds` as raw bytes; this process reports them
            # as hex. Accept either, because being strict here would mean two
            # conversions of the same field and one of them would be wrong.
            for payload in scenario["feeds"]:
                data = (
                    bytes.fromhex(payload)
                    if isinstance(payload, str)
                    else bytes(payload)
                )
                for piece in chop(data, chop_size):
                    chan.sendall(piece)
                    # Yield between pieces. The point of the cut points is
                    # that they must not matter, and a send that never lets the
                    # reader run would not be testing that -- it would be
                    # testing one enormous chunk.
                    time.sleep(0.002)
        except Exception as exc:  # the channel may already be gone
            result.setdefault("notes", []).append("send: %r" % (exc,))

        stop.set()
        t_worker.join(timeout=5)
        result["client_sent"] = c2s.hex()
        result["server_sent"] = s2c.hex()
        try:
            chan.close()
        except Exception:
            pass
        try:
            t.close()
        except Exception:
            pass
    except Exception as exc:
        result["error"] = repr(exc)
    finally:
        try:
            t.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("scenario")
    ap.add_argument("--chop", type=int, default=0)
    ap.add_argument("--json")
    args = ap.parse_args()

    scenario = next((s for s in SCENARIOS if s["name"] == args.scenario), None)
    if scenario is None:
        print("unknown scenario %r" % args.scenario, file=sys.stderr)
        return 2

    result = {}
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(1)
    listener.settimeout(60)

    holder = {}

    def accept_one():
        try:
            conn, _ = listener.accept()
        except Exception as exc:
            result["error"] = "accept: %r" % (exc,)
            return
        holder["done"] = threading.Event()
        serve_one(conn, scenario, args.chop, result)
        holder["done"].set()

    worker = threading.Thread(target=accept_one, daemon=True)
    worker.start()
    # Give the gate a moment to connect, then keep the process alive until the
    # connection is finished.
    worker.join(timeout=120)

    payload = {k: v for k, v in result.items() if not k.startswith("_")}
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    print(json.dumps(payload))
    listener.close()
    return 0 if "error" not in payload else 1


if __name__ == "__main__":
    sys.exit(main())
