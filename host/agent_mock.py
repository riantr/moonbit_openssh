#!/usr/bin/env python3
r"""A mock ssh-agent, over TCP.

The real agent on Windows listens on a named pipe (\.\pipe\openssh-ssh-agent)
and on unix on a unix domain socket. Both are local, both are "a byte stream
with a length-prefixed message protocol on top", and the protocol does not care
which -- that is the whole reason `src/agent` takes its transport as an
injected `AgentChannel` rather than opening a socket itself.

This mock therefore speaks the agent protocol over plain TCP, which is also
what lets the browser path be exercised later: the bytes are the same, only
the carrier differs.

The key it holds is the RFC 6979 A.2.5 key (the same one Loop #34 uses) by
default, and it signs with RFC 6979, so the signature it produces is
reproducible and can be compared byte for byte with the MoonBit side and with
an independent implementation.

`--key-d` swaps in a different private key. The gate uses that to hold a key
the server does not accept, which is how the "the probe comes first" claim
gets tested: a client that asked the agent to sign before probing would show
one sign request here, and a correct one shows none.

Usage:
    python host/agent_mock.py --port 18801
"""

import argparse
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent_oracle import (  # noqa: E402
    AGENTC_REQUEST_IDENTITIES,
    AGENTC_SIGN_REQUEST,
    AGENT_FAILURE,
    AGENT_IDENTITIES_ANSWER,
    AGENT_SIGN_RESPONSE,
    COMMENT,
    agent_frame,
    identities_answer_payload,
    sign_request_payload,
    sign_response_payload,
)
from ecdsa_auth_oracle import (  # noqa: E402
    CURVE_NAME,
    D_HEX,
    KEY_TYPE,
    rfc6979_sign,
    sig_blob,
    ssh_string,
)

MAX_AGENT_REPLY_LEN = 256 * 1024


def pubkey_blob_for(d_hex):
    """The RFC 5656 public key blob for a given private key.

    Written out here rather than imported: `ecdsa_auth_oracle.pubkey_blob` is
    pinned to the RFC 6979 A.2.5 key, and this mock has to be able to hold a
    *different* one.
    """
    from cryptography.hazmat.primitives.asymmetric import ec

    sk = ec.derive_private_key(int(d_hex, 16), ec.SECP256R1())
    nums = sk.public_key().public_numbers()
    point = b"\x04" + nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    return ssh_string(KEY_TYPE) + ssh_string(CURVE_NAME) + ssh_string(point)


def sign_with(d_hex, data):
    """RFC 6979 signature of `data`, in the SSH signature blob shape."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    _, r, s = rfc6979_sign(data, int(d_hex, 16))
    return sig_blob(encode_dss_signature(r, s))


def log(msg):
    # stderr, not stdout: the gate reads stdout for structured output, and
    # stdout is block-buffered when it is a pipe.
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def read_string(buf, off):
    if off + 4 > len(buf):
        raise ValueError("truncated string length")
    n = struct.unpack(">I", buf[off:off + 4])[0]
    off += 4
    if off + n > len(buf):
        raise ValueError("truncated string body")
    return buf[off:off + n], off + n


def read_u32(buf, off):
    if off + 4 > len(buf):
        raise ValueError("truncated u32")
    return struct.unpack(">I", buf[off:off + 4])[0], off + 4


def handle(conn, state):
    """Serve requests on one connection until the client goes away."""
    while True:
        head = read_exact(conn, 4)
        if head is None:
            return
        length = struct.unpack(">I", head)[0]
        if length > MAX_AGENT_REPLY_LEN:
            log("agent: reply length %d is over the limit; refusing" % length)
            return
        body = read_exact(conn, length)
        if body is None:
            return
        msg_type = body[0]
        payload = body[1:]
        if msg_type == AGENTC_REQUEST_IDENTITIES:
            state["identities"] += 1
            log("agent: REQUEST_IDENTITIES -> IDENTITIES_ANSWER")
            reply = agent_frame(
                AGENT_IDENTITIES_ANSWER,
                identities_answer_payload([(state["blob"], COMMENT.encode("ascii"))]),
            )
        elif msg_type == AGENTC_SIGN_REQUEST:
            try:
                blob, off = read_string(payload, 0)
                data, off = read_string(payload, off)
                flags, off = read_u32(payload, off)
            except ValueError as exc:
                log("agent: malformed SIGN_REQUEST (%s) -> FAILURE" % exc)
                conn.sendall(agent_frame(AGENT_FAILURE))
                continue
            state["signs"] += 1
            log(
                "agent: SIGN_REQUEST blob=%dB data=%dB flags=%d"
                % (len(blob), len(data), flags)
            )
            if blob != state["blob"]:
                log("agent: unknown key -> FAILURE")
                conn.sendall(agent_frame(AGENT_FAILURE))
                continue
            # RFC 6979, so the signature is reproducible: the gate compares it
            # byte for byte with the MoonBit side and with Python.
            signature = sign_with(state["d"], data)
            log("agent: SIGN_RESPONSE sig=%dB" % len(signature))
            reply = agent_frame(AGENT_SIGN_RESPONSE, sign_response_payload(signature))
        else:
            log("agent: unknown request type %d -> FAILURE" % msg_type)
            reply = agent_frame(AGENT_FAILURE)
        conn.sendall(reply)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--key-d", default=D_HEX, help="the private key the agent holds")
    args = ap.parse_args()

    d_hex = args.key_d.strip().lower()
    blob = pubkey_blob_for(d_hex)
    state = {"blob": blob, "d": d_hex, "identities": 0, "signs": 0}

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(4)
    port = srv.getsockname()[1]
    # The port has to be known before the caller can connect to it, and stdout
    # is block-buffered under a pipe -- so it goes to stderr, unbuffered.
    log("listening on 127.0.0.1:%d" % port)
    log("agent: key type ecdsa-sha2-nistp256, comment %s" % COMMENT)
    log("agent: holding key d=%s" % d_hex)

    try:
        while True:
            conn, addr = srv.accept()
            log("agent: connection from %s:%d" % addr)
            try:
                handle(conn, state)
            except (BrokenPipeError, ConnectionResetError) as exc:
                log("agent: connection ended (%s)" % exc)
            finally:
                conn.close()
            log(
                "agent: served identities=%d signs=%d"
                % (state["identities"], state["signs"])
            )
    except KeyboardInterrupt:
        pass
    finally:
        srv.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
