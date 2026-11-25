"""The peer for Loop #102: the server's half of a REMOTE port forward.

`ssh -R 55123:target:5432 host` asks the SERVER to listen on a port and to
carry every connection that arrives there to the CLIENT over a channel the
SERVER opens (RFC 4254 section 7.1).  This script is the client half of that,
written against **paramiko** -- an implementation that shares no code with
this repository -- so that the bytes it reads are a second opinion and not
this repository agreeing with itself.

It prints ONE JSON object on stdout.  Everything it reports is something it
read off the wire or off the socket; nothing is inferred.

## Why there are STEPS

`cmd/sshd` serves ONE connection and then exits, so every connection needs a
server of its own.  Worse, this server runs ONE remote forward at a time: a
second `tcpip-forward` on the same connection is refused.  So the
measurements cannot share a connection either, and each of them is a step:

  `--step payloads`  the reply to `tcpip-forward` with port 0 -- the payload
                     has to be the port the server chose, as a u32, because
                     that is the only way the peer can learn it -- and the
                     reply to a SECOND forward on the same connection.
  `--step fixed`     the reply to `tcpip-forward` with a FIXED port.  The
                     payload has to be EMPTY, because the peer already knows
                     the port it asked for.
  `--step busy`      the reply to a request for a port that is ALREADY IN USE.
  `--step channel`   the channel the server opens when something connects to
                     the listening port -- its window, its maximum packet, the
                     four fields it carries, and the bytes that go through it.
                     And the answer to `cancel-tcpip-forward`.
  `--step session`   the same, but with a SESSION channel opened FIRST.

## Why there is a `session` step

The server answers a global request in TWO places, because the request can
arrive in two places:

  * before any session channel exists -- `ssh -N -R`, which opens no session
    channel at all;
  * after one -- `ssh -R 55123:target:5432 host cmd`, which opens one.

Every other step asks for the forward and never opens a session channel, so
every other step exercises only the FIRST of the two.  A server that
answered global requests only in the first would pass them all, and the
normal `ssh -R ... host cmd` would hang.  The `session` step opens a session
channel first, so the request arrives in the second place.

## Why every request here has a deadline

paramiko's `global_request(..., wait=True)` has NO timeout: it waits for
ever, and the only way out is the transport dying.  A server that does not
answer a global request is exactly the failure this gate exists to catch, and
a gate that waits for ever on it is a gate that HANGS instead of failing.  So
every request that waits is made on its own thread and given a deadline.

Usage:
    python host/loop102_peer.py <host> <port> <key> <user> <step> [fixed_port] [busy_port]
"""

import hashlib
import json
import socket
import sys
import threading
import time

import paramiko

# The payload that goes through the forward.  Fixed bytes, so the digest is
# something the gate can compare between the two servers.
PAYLOAD = b"loop102 remote forward probe\n" * 7

# How long a request may wait for its answer.
#
# Long enough for a slow machine, short enough that a server that never
# answers is a FAILURE and not a hang.
REQUEST_TIMEOUT_S = 20.0

# How long the channel has to arrive after something connected to the
# listening port.
CHANNEL_TIMEOUT_S = 30.0


def note(message):
    """A progress marker on stderr.

    stdout carries the JSON and nothing else, so the trace goes to stderr.
    It is there because a step that hangs is a step whose last marker says
    where it stopped, and a gate that cannot say where it stopped is a gate
    that has to be guessed at.
    """
    sys.stderr.write("[loop102-peer] %s\n" % message)
    sys.stderr.flush()


def connect(host, port, key_path, user):
    sock = socket.create_connection((host, port), timeout=30)
    t = paramiko.Transport(sock)
    # paramiko 5's `connect` takes only (hostkey, username, password, pkey):
    # there is no agent to ask and no key list to search, so the key is the
    # key.
    t.connect(username=user, pkey=paramiko.ECDSAKey.from_private_key_file(key_path))
    return t


def global_request(t, name, data, timeout=REQUEST_TIMEOUT_S):
    """A global request with a deadline.

    Returns `(reply, error)`.  `reply` is paramiko's own answer -- `None` for
    a REQUEST_FAILURE -- and `error` is a string when the request was not
    ANSWERED AT ALL, which is a different thing: a refusal is an answer, and
    silence is not.  The gate checks that difference, so the peer has to keep
    it.
    """
    box = {}

    def run():
        try:
            box["reply"] = t.global_request(name, data, wait=True)
        except Exception as e:  # noqa: BLE001 -- the failure IS the result
            box["error"] = str(e)

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        # The request is still waiting.  Say so, and let the step fail.
        return None, "no answer within %g seconds" % timeout
    if "error" in box:
        return None, box["error"]
    if "reply" not in box:
        return None, "no answer"
    if box["reply"] is None and not t.is_active():
        # paramiko returns None for a REQUEST_FAILURE, but it also returns
        # None when the transport died while it was waiting.  The second one
        # is not a refusal.
        return None, "the connection was closed before the answer arrived"
    return box["reply"], None


def request_forward(t, address, port, handler, timeout=REQUEST_TIMEOUT_S):
    """Ask for a remote forward, with a deadline.

    This is paramiko's own `request_port_forward` -- so that the port it
    reports is the port the server chose, read out of the reply by a third
    implementation -- run on a thread so that it cannot wait for ever.
    """
    box = {}

    def run():
        try:
            box["port"] = t.request_port_forward(address, port, handler)
        except Exception as e:  # noqa: BLE001 -- the failure IS the result
            box["error"] = str(e)

    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(timeout)
    if th.is_alive():
        raise RuntimeError("the tcpip-forward request was not answered")
    if "error" in box:
        raise RuntimeError(box["error"])
    return box["port"]


def describe(reply, error=None):
    """What a global request's reply carried."""
    if error is not None:
        # The request was not answered.  `ok` is False, but `error` says why:
        # a gate that cannot tell a refusal from silence cannot check either.
        return {"ok": False, "len": 0, "hex": "", "error": error}
    if reply is None:
        # paramiko returns None for a REQUEST_FAILURE and a Message for a
        # REQUEST_SUCCESS.  That is paramiko's own reading of the reply.
        return {"ok": False, "len": 0, "hex": ""}
    raw = bytes(reply.asbytes())
    return {"ok": True, "len": len(raw), "hex": raw.hex()}


def start_echo():
    """The client's own target: the thing the client's side of the forward
    connects to.  It echoes, so the bytes that come back are the bytes that
    went in."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def serve():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            try:
                while True:
                    d = c.recv(65536)
                    if not d:
                        break
                    c.sendall(d)
            except OSError:
                pass
            finally:
                try:
                    c.close()
                except OSError:
                    pass

    threading.Thread(target=serve, daemon=True).start()
    return srv, port


def make_channel_state():
    """The slot the forwarded-tcpip handler fills in.

    The handler is called on the transport's thread.  It must not block: it
    only records what it was given and returns.
    """
    got = {}
    got["event"] = threading.Event()

    def handler(chan, origin, server):
        got["chan"] = chan
        got["origin"] = origin
        got["server"] = server
        got["event"].set()

    got["handler"] = handler
    return got


def forward_and_relay(t, got, host, target_port, out):
    """Ask for the forward, connect to it, and carry the payload through.

    Shared by the two steps that carry bytes, so that the ONLY difference
    between them is the one each step is about: whether a session channel was
    opened before the forward was asked for.

    Returns `(out, c, tgt, chan)`; `chan` is None when the server never
    opened one.
    """
    # paramiko's own reading of the "port 0" rule: it reads the u32 out of
    # the reply itself.  A third implementation, saying the same thing.
    listen_port = request_forward(t, "localhost", 0, got["handler"])
    out["allocated_port"] = listen_port
    note("the server said port %s" % listen_port)

    # Something connects to the server's listening port.  This is the moment
    # the server has to open its channel.
    note("connecting to the listening port")
    c = socket.create_connection((host, listen_port), timeout=30)
    c.sendall(PAYLOAD)
    note("the payload is in the socket")

    if not got["event"].wait(CHANNEL_TIMEOUT_S):
        out["error"] = "the server never opened a forwarded-tcpip channel"
        return out, c, None, None

    note("the channel arrived")
    chan = got["chan"]
    out["channel"] = {
        # The channel number the SERVER picked -- it is the sender, because
        # the server opens the channel.
        "sender_channel": chan.remote_chanid,
        "window": chan.out_window_size,
        "max_packet": chan.out_max_packet_size,
        # The first two fields the server sent: the address and port that
        # were connected -- the LISTENING pair.
        "listen_addr": got["server"][0],
        "listen_port": got["server"][1],
        # The last two: the originator -- who actually connected.
        "origin_addr": got["origin"][0],
        "origin_port": got["origin"][1],
    }
    note("channel = %s" % json.dumps(out["channel"], sort_keys=True))

    # The client's half of the forward: connect to its own target and relay.
    note("connecting to the target")
    tgt = socket.create_connection(("127.0.0.1", target_port), timeout=30)

    def pump_target():
        try:
            while True:
                d = tgt.recv(65536)
                if not d:
                    note("pump: the target closed")
                    break
                note("pump: got %d bytes from the target, sending them on the channel" % len(d))
                chan.sendall(d)
                note("pump: sent them")
        except OSError as e:
            note("pump: failed: %s" % e)

    threading.Thread(target=pump_target, daemon=True).start()

    # chan -> target
    moved = 0
    try:
        while moved < len(PAYLOAD):
            d = chan.recv(65536)
            if not d:
                break
            tgt.sendall(d)
            moved += len(d)
    except OSError as e:
        out["error"] = "reading the channel failed: %s" % e
    out["bytes_through_channel"] = moved
    note("%d bytes came through the channel" % moved)

    # The echo comes back the other way: target -> chan -> the socket that
    # connected to the listening port.
    buf = b""
    deadline = time.time() + CHANNEL_TIMEOUT_S
    while len(buf) < len(PAYLOAD) and time.time() < deadline:
        try:
            d = c.recv(65536)
        except OSError:
            break
        if not d:
            break
        buf += d
    out["echo_len"] = len(buf)
    out["echo_sha256"] = hashlib.sha256(buf).hexdigest()
    note("%d bytes came back to the socket that connected" % len(buf))
    return out, c, tgt, chan


def cancel_forward(t, listen_port):
    """Ask for the forward to stop, and report what the answer was."""
    reply, error = global_request(t, "cancel-tcpip-forward", ("localhost", listen_port))
    return describe(reply, error)


def step_payloads(host, port, key_path, user, fixed_port, busy_port):
    out = {}
    t = connect(host, port, key_path, user)
    # Port 0: the reply has to carry the port the server chose, as a u32 --
    # it is the only way the peer can learn it.
    reply, error = global_request(t, "tcpip-forward", ("localhost", 0))
    d = describe(reply, error)
    if d["ok"] and d["len"] == 4:
        d["port"] = int.from_bytes(bytes.fromhex(d["hex"]), "big")
    out["reply_port0"] = d
    # A SECOND forward on the same connection.  The real server allows it;
    # this one refuses it, and refusing is the point: a peer that was told
    # SUCCESS and then got nothing would wait for ever.
    reply, error = global_request(t, "tcpip-forward", ("localhost", 0))
    out["reply_second"] = describe(reply, error)
    t.close()
    return out


def step_fixed(host, port, key_path, user, fixed_port, busy_port):
    out = {}
    t = connect(host, port, key_path, user)
    reply, error = global_request(t, "tcpip-forward", ("localhost", fixed_port))
    out["reply_fixed"] = describe(reply, error)
    t.close()
    return out


def step_busy(host, port, key_path, user, fixed_port, busy_port):
    out = {}
    t = connect(host, port, key_path, user)
    reply, error = global_request(t, "tcpip-forward", ("localhost", busy_port))
    out["reply_busy"] = describe(reply, error)
    t.close()
    return out


def step_channel(host, port, key_path, user, fixed_port, busy_port):
    out = {}
    note("channel step: starting the echo target")
    srv, target_port = start_echo()
    got = make_channel_state()

    note("channel step: connecting")
    t = connect(host, port, key_path, user)
    try:
        out, c, tgt, chan = forward_and_relay(t, got, host, target_port, out)
    except Exception as e:  # noqa: BLE001 -- the failure IS the result
        out["error"] = str(e)
        c, tgt, chan = None, None, None

    # ---- close the channel, THEN cancel ----
    #
    # The order matters, and it is not a detail of this script: the real
    # OpenSSH client sends `cancel-tcpip-forward` with want_reply=FALSE (see
    # `channel_request_rforward_cancel` in OpenSSH's channels.c), so it never
    # waits for an answer and the order does not matter to it.  paramiko's
    # `global_request(..., wait=True)` DOES wait, and this server answers a
    # global request between relays -- a request that arrives while a
    # forwarded connection is being carried is not answered until that
    # connection ends.  So the channel is closed first, and the cancel is
    # asked for afterwards.
    if chan is not None:
        note("channel step: closing the channel")
        chan.settimeout(15)
        chan.shutdown_write()
        chan.close()
        time.sleep(0.75)
        note("channel step: cancelling")
        out["cancel"] = cancel_forward(t, out.get("allocated_port", 0))
        note("channel step: cancel answered")

    try:
        if c is not None:
            c.close()
        if tgt is not None:
            tgt.close()
        t.close()
        srv.close()
    except OSError:
        pass
    return out


def step_session(host, port, key_path, user, fixed_port, busy_port):
    """The forward asked for AFTER a session channel exists.

    `ssh -R 55123:target:5432 host cmd` opens a session channel and asks for
    the forward in the same breath.  Which of the two arrives first is the
    client's business; the server has to answer the request either way, and
    it answers it in two different places -- one before the session channel
    exists and one after.

    Every other step asks for the forward and never opens a session channel,
    so every other step exercises only the first place.  This one exercises
    the second.
    """
    out = {}
    note("session step: starting the echo target")
    srv, target_port = start_echo()
    got = make_channel_state()

    note("session step: connecting")
    t = connect(host, port, key_path, user)
    # The session channel FIRST.  Its confirmation is the server's answer to
    # it, and it is also what moves the server from the phase that answers
    # global requests before any session channel into the loop that serves
    # one.
    note("session step: opening the session channel")
    try:
        session = t.open_session(timeout=30)
    except Exception as e:  # noqa: BLE001 -- the failure IS the result
        out["error"] = "the session channel was not opened: %s" % e
        print(json.dumps(out, sort_keys=True))
        try:
            t.close()
            srv.close()
        except OSError:
            pass
        return out
    out["session_opened"] = True
    note("session step: the session channel is open")

    try:
        out, c, tgt, chan = forward_and_relay(t, got, host, target_port, out)
    except Exception as e:  # noqa: BLE001 -- the failure IS the result
        out["error"] = str(e)
        c, tgt, chan = None, None, None

    if chan is not None:
        note("session step: closing the channel")
        chan.settimeout(15)
        chan.shutdown_write()
        chan.close()
        time.sleep(0.75)
        note("session step: cancelling")
        out["cancel"] = cancel_forward(t, out.get("allocated_port", 0))
        note("session step: cancel answered")

    try:
        session.close()
        if c is not None:
            c.close()
        if tgt is not None:
            tgt.close()
        t.close()
        srv.close()
    except OSError:
        pass
    return out


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    key_path = sys.argv[3]
    user = sys.argv[4]
    step = sys.argv[5]
    fixed_port = int(sys.argv[6]) if len(sys.argv) > 6 else 0
    busy_port = int(sys.argv[7]) if len(sys.argv) > 7 else 0

    if step == "payloads":
        out = step_payloads(host, port, key_path, user, fixed_port, busy_port)
    elif step == "fixed":
        out = step_fixed(host, port, key_path, user, fixed_port, busy_port)
    elif step == "busy":
        out = step_busy(host, port, key_path, user, fixed_port, busy_port)
    elif step == "channel":
        out = step_channel(host, port, key_path, user, fixed_port, busy_port)
    elif step == "session":
        out = step_session(host, port, key_path, user, fixed_port, busy_port)
    else:
        print(json.dumps({"error": "unknown step %r" % step}))
        return 2
    print(json.dumps(out, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
