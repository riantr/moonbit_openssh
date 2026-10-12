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
import hashlib
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
# A second, real key, used only by `--lie-hostkey`. Also a real paramiko key:
# the lie is *which* key signs, not any hand-rolled crypto on either side.
SIGNER_KEY_PATH = os.path.join(ROOT, ".loop44", "mitm_signer_key.pem")


def _read_or_make_ecdsa(path):
    if not os.path.isfile(path):
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        os.makedirs(os.path.dirname(path), exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(path, "wb") as fh:
            fh.write(pem)
    return paramiko.ECDSAKey.from_private_key(
        io.StringIO(open(path, encoding="ascii").read())
    )


def host_key():
    """Generate (once) a host key. A real file, because paramiko's server mode
    wants a key object and constructing one from an in-memory ECDSA key is
    more code than writing a PEM and reading it back."""
    return _read_or_make_ecdsa(HOST_KEY_PATH)


def signer_key():
    """The key that does not belong to the blob we present. See
    `LyingHostKey`."""
    return _read_or_make_ecdsa(SIGNER_KEY_PATH)


class LyingHostKey:
    """Present one key's blob, sign the exchange hash with a different key.

    This is the only way to reach a client's host-key verification from the
    outside without re-implementing a key exchange, and it is exactly what a
    man in the middle does. paramiko builds both halves of `KEXDH_REPLY` from a
    single object -- `kex_ecdh_nist.py` reads `get_server_key().asbytes()` for
    the blob and `get_server_key().sign_ssh_data(...)` for the signature -- so
    splitting them takes one wrapper and **no cryptography of our own**: both
    keys are real paramiko keys and both signatures are made by paramiko.

    `name_override` lies about the algorithm name instead of the signer, which
    is a different lie and reaches a different branch in the client: the blob
    parses, but it is not the type that was negotiated. Both are needed --
    `HostKey::agrees_with_alg` and the signature check are separate rules, and
    driving only one of them leaves the other untested end to end.

    What the client must do about either is the whole point. The blob it is
    given does not prove the exchange, so a client that carries on has sent
    userauth credentials to a peer whose identity nobody vouched for. OpenSSH
    refuses (`sshconnect.c` verifies before it sends anything authenticated),
    and so must ours.
    """

    def __init__(self, presented, signer, name_override=None):
        self._presented = presented
        self._signer = signer
        self._name_override = name_override

    # Without an override this is the *presented* key's name: the negotiated
    # algorithm and the blob have to agree.
    def get_name(self):
        return self._name_override or self._presented.get_name()

    def get_bits(self):
        return self._presented.get_bits()

    def asbytes(self):
        return self._presented.asbytes()

    # Both spellings: paramiko 5 renamed `sign_ssh` to `sign_ssh_data`, and
    # this file has to keep working whichever is installed. The negotiated
    # algorithm is deliberately dropped on the way through -- with an override
    # it names a key type this signature is not, and paramiko would raise
    # rather than produce the malformed reply the run is about. Nothing checks
    # the signature in that mode: the client rejects on the type mismatch
    # first, which is the branch under test.
    def sign_ssh_data(self, data, algorithm=None):
        return self._signer.sign_ssh_data(data, None)

    def sign_ssh(self, data):
        return self._signer.sign_ssh_data(data, None)


class SftpMisbehavingServer(paramiko.ServerInterface):
    """Authenticates everything, then answers the channel requests itself.

    `check_auth_publickey` returns AUTH_SUCCESSFUL without ever looking at the
    key, which is a decision and not an oversight -- see the module header.
    `check_channel_subsystem_request` is where the interesting part is: it
    accepts `"sftp"` and records that it was asked, so the channel handler can
    know the client is past the want_reply barrier.

    It counts the authentication attempts it is asked to approve, because
    "zero" is the assertion `--lie-hostkey` turns on: a client that reaches
    this method at all has already sent userauth to a peer it did not verify.
    An accepting server cannot notice that by looking at its own policy -- it
    approves everything -- so it has to be told the count instead.
    """

    def __init__(self, result):
        self.subsystem = None
        self.event = threading.Event()
        self.result = result

    def _count(self, how):
        self.result["auth_attempts"] = self.result.get("auth_attempts", 0) + 1
        self.result.setdefault("auth_methods", []).append(how)

    def check_auth_publickey(self, username, key):
        self._count("publickey")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        self._count("password")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "publickey,password"

    def check_channel_request(self, kind, chanid):
        self.result["channel_requests"] = self.result.get("channel_requests", 0) + 1
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


def serve_one(sock, scenario, chop_size, result, lie_hostkey=False,
              lie_hostkey_type=None):
    """Run one connection to completion.

    paramiko's own threading means `accept` returns a live `Transport`-able
    socket; everything after the handshake is ours.
    """
    # Present before anything can fail, so "zero authentication attempts" is a
    # measured 0 and not a missing key. A gate that treats absent as zero
    # would pass on a MITM that crashed before the client said anything.
    result.setdefault("auth_attempts", 0)
    result.setdefault("channel_requests", 0)
    # Whether any SFTP byte was ever written. Present from the start so "none"
    # is a measured 0 for every run, and set once the scenario is injected.
    result.setdefault("reached_sftp", False)

    t = paramiko.Transport(sock)
    t.local_version = "SSH-2.0-mitm"
    if lie_hostkey_type:
        result["mode"] = "lie-hostkey-type"
    elif lie_hostkey:
        result["mode"] = "lie-hostkey"
    else:
        result["mode"] = "sftp" if scenario is not None else "control"

    if lie_hostkey or lie_hostkey_type:
        presented = host_key()
        signer = signer_key()
        # Both fingerprints go into the transcript, and the gate checks they
        # differ. Without that, "the MITM lied" is an assertion about the code
        # rather than about the run -- and a run where the two keys happened to
        # be the same file would pass every other check.
        result["hostkey_presented_sha256"] = hashlib.sha256(
            presented.asbytes()
        ).hexdigest()
        result["hostkey_signer_sha256"] = hashlib.sha256(signer.asbytes()).hexdigest()
        result["hostkey_announced_type"] = lie_hostkey_type or presented.get_name()
        t.add_server_key(
            LyingHostKey(presented, signer, name_override=lie_hostkey_type or None)
        )
    else:
        t.add_server_key(host_key())
    server = SftpMisbehavingServer(result)
    try:
        t.start_server(server=server, event=None)
        if lie_hostkey or lie_hostkey_type:
            # With a forged key exchange the client hangs up during the
            # handshake, so there is no channel and `accept` times out.
            # Reaching this point at all means the client *accepted* the lie,
            # which is the bug these modes exist to catch -- so it is recorded
            # as an error rather than as a quiet success.
            result["error"] = (
                "client completed the key exchange despite a host key that does "
                "not prove it"
            )
            return
        if scenario is None:
            # A control run. The handshake and userauth are the whole test --
            # there are no SFTP bytes to inject, and no channel to wait for, so
            # waiting for one would just burn the accept timeout. This is the
            # run that proves the clients *can* authenticate here: without it,
            # "the client refused" would also be true of a client that refuses
            # everything, and the gate would be measuring nothing.
            result["control"] = True
            t.join(5)
            return
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
        # The channel is open and the client asked for `sftp`: past every
        # handshake-stage check, and about to be sent malformed bytes.
        result["reached_sftp"] = True

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
        # A client that refuses the key exchange hangs up mid-handshake, and
        # paramiko reports that as an ordinary exception. Under `--lie-hostkey`
        # that hang-up **is** the expected result, so recording it as `error`
        # would make the one run that behaved correctly look like the run that
        # broke. The distinction is drawn here, where the cause is still known,
        # rather than in the gate, which would have to guess.
        if (lie_hostkey or lie_hostkey_type) and isinstance(
            exc, (ConnectionResetError, BrokenPipeError, EOFError, socket.error)
        ):
            result["client_disconnected"] = True
            result.setdefault("notes", []).append(
                "client hung up during the exchange: %r" % (exc,)
            )
        else:
            result["error"] = repr(exc)
    finally:
        try:
            t.close()
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("port", type=int)
    ap.add_argument("scenario", nargs="?")
    ap.add_argument("--chop", type=int, default=0)
    ap.add_argument("--json")
    ap.add_argument(
        "--lie-hostkey",
        action="store_true",
        help="present one host key and sign the exchange hash with another",
    )
    ap.add_argument(
        "--lie-hostkey-type",
        metavar="NAME",
        help="present a real host key blob under a different algorithm name",
    )
    args = ap.parse_args()
    lie_hostkey = args.lie_hostkey or bool(args.lie_hostkey_type)

    scenario = None
    if args.scenario is not None:
        scenario = next((s for s in SCENARIOS if s["name"] == args.scenario), None)
        if scenario is None:
            print("unknown scenario %r" % args.scenario, file=sys.stderr)
            return 2
    # Three modes, and which one ran is written into the transcript rather than
    # inferred from the process name: a control run that accidentally used the
    # lying branch would still "refuse nothing" and look like a pass.
    #   scenario given          inject SFTP bytes (Loops #43, #45, #46)
    #   --lie-hostkey[-type]    a forged key exchange, nothing past the handshake
    #   neither                 a control: a correct handshake, no SFTP
    if scenario is None and not lie_hostkey:
        pass

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
        serve_one(conn, scenario, args.chop, result, lie_hostkey,
                  args.lie_hostkey_type)
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
