#!/usr/bin/env python3
"""host/ssh_recorder.py -- a recording TCP proxy: the raw bytes of one session.

## Why this exists

Loop #93 is the server side of SSH, and the oracle for it is the REAL client:
the OpenSSH `ssh.exe` on this machine.  The other direction -- what a real
server actually puts on the wire -- is recorded here, because the parts of
the handshake that are still PLAIN TEXT are exactly the parts a server has
to get byte-for-byte right:

    the identification line, SSH2_MSG_KEXINIT, SSH2_MSG_KEX_ECDH_INIT,
    SSH2_MSG_KEX_ECDH_REPLY, SSH2_MSG_NEWKEYS

Everything after NEWKEYS is encrypted, so this proxy cannot read it, and it
does not pretend to.  What it can do is answer the question the server side
actually has to answer: **what does a real server send, in what order, and
with what fields?**  That question is asked by reading bytes, not by reading
OpenSSH's source, and the difference matters -- the whole point of this
repository is that the rules are measured rather than remembered.

The proxy is deliberately dumb.  It forwards bytes and writes them down.  A
proxy that understood SSH would be a second implementation of SSH, and its
understanding would be the thing under test.

## The one thing it must not do

It must not change the stream.  A proxy that rewrites a byte changes what
the peer sees, and then the capture is a capture of the proxy rather than of
the server.  So: `recv` into a buffer, write the same bytes onward, record
the same bytes.  Nothing else.

## Usage

    python host/ssh_recorder.py <listen-port> <target-port> [--out DIR]

Prints `READY <listen-port>` on stdout once the socket is bound and
listening, so a caller can start it in the background and wait for that
line rather than sleeping.  The recording is written when the session ends:

    <out>/c2s.bin   the bytes the client sent
    <out>/s2c.bin   the bytes the server sent
    <out>/meta.json  the ports and the byte counts

The default output directory is `.loop93/`, which is git-ignored: a capture
is local evidence, not a source file.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def pump(src: socket.socket, dst: socket.socket, sink, counter: list) -> None:
    """Forward src->dst, recording what passes through.

    `counter` is a one-element list so the caller can read the count after
    the thread ends without a lock.
    """
    try:
        while True:
            chunk = src.recv(65536)
            if not chunk:
                break
            sink.write(chunk)
            sink.flush()
            counter[0] += len(chunk)
            try:
                dst.sendall(chunk)
            except OSError:
                break
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("listen_port", type=int)
    ap.add_argument("target_port", type=int)
    ap.add_argument("--out", default=os.path.join(ROOT, ".loop93"))
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    c2s_path = os.path.join(args.out, "c2s.bin")
    s2c_path = os.path.join(args.out, "s2c.bin")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.listen_port))
    srv.listen(1)
    print("READY %d" % args.listen_port, flush=True)

    conn, peer = srv.accept()
    up = socket.create_connection((args.host, args.target_port))

    c2s_count = [0]
    s2c_count = [0]
    with open(c2s_path, "wb") as c2s, open(s2c_path, "wb") as s2c:
        t1 = threading.Thread(target=pump, args=(conn, up, c2s, c2s_count))
        t2 = threading.Thread(target=pump, args=(up, conn, s2c, s2c_count))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    try:
        conn.close()
        up.close()
        srv.close()
    except OSError:
        pass

    meta = {
        "listen_port": args.listen_port,
        "target_port": args.target_port,
        "c2s_bytes": c2s_count[0],
        "s2c_bytes": s2c_count[0],
        "client": "%s:%d" % peer,
    }
    with open(os.path.join(args.out, "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print("DONE %s" % json.dumps(meta), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
