"""Capture a real SFTP byte stream, both directions, through paramiko.

This is the leg no amount of re-derivation replaces.  Everything in
`host/gen_sftp_vectors.py` is us agreeing with the spec and with each other;
the bytes in here are what an actual OpenSSH 8.0p1 `internal-sftp` put on the
wire, over requests an actual paramiko 5.0 client framed.

What it settles that a reading of draft-ietf-secsh-filexfer-02 does not:

  1. INIT carries a bare `uint32 version` and **no request id**
     (sftp.h:70), and the server answers VERSION with the version followed by
     *eleven* extension name/value pairs (sftp-server.c:716-727).  A parser
     that demands end-of-packet after the version number dies on the first
     byte a real server sends.  The count is captured, not assumed -- older
     and newer servers differ.

  2. Attributes arrive **mid-packet** inside OPEN and inside every NAME
     entry.  `decode_attrib` (sftp-common.c:104-146) never calls
     `sshbuf_get_end`, and the trailing bytes after the attributes are real
     payload.  Captured here as NAME packets with filenames immediately
     followed by an attribute block.

  3. An attribute block is sparse.  Which of size/uid/gid/perm/times appear is
     decided by the flag word, and the server's flags are visible in the
     capture -- a parser that always reads six fields desynchronises here.

  4. READDIR ends with `STATUS(SSH2_FX_EOF)`, not with a short name list.  A
     directory with three entries can legally come back in one NAME followed
     by EOF.

Recording is done *above* paramiko's channel framing, so what is recorded is
the SFTP byte stream exactly as both ends exchange it -- no SSH length
prefixes, no channel numbers.

Needs a running test sshd:  `node host/sshd_setup.mjs --port 18781`

Run:  python host/sftp_capture.py <port> <out.json> [fixture_dir]
"""

import io
import json
import os
import sys

import paramiko
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from ssh_user import ssh_user

# The user key this repo has used since Loop #34. The ACCOUNT is not a
# constant: it is the account this machine runs as, because the test sshd runs
# here and an account that does not exist here cannot authenticate. See
# host/ssh_user.py.
D_HEX = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
USER = ssh_user()

SFTP_VERSION = 3


def private_pem():
    sk = ec.derive_private_key(int(D_HEX, 16), ec.SECP256R1())
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


class Recorder:
    """A pass-through channel that keeps both SFTP byte streams.

    paramiko's `SFTPClient` only ever calls `sendall` / `recv` /
    `settimeout` / `close` on the socket it is handed, so those four methods
    are the whole seam.
    """

    def __init__(self, chan):
        self._chan = chan
        self.c2s = bytearray()
        self.s2c = bytearray()

    def sendall(self, data):
        self.c2s += bytes(data)
        return self._chan.sendall(data)

    def send(self, data):
        # paramiko's `_write_all` loops on partial sends, so recording only the
        # accepted prefix here records the stream exactly as it went out.
        n = self._chan.send(data)
        self.c2s += bytes(data[:n])
        return n

    def recv(self, n):
        data = self._chan.recv(n)
        self.s2c += data
        return data

    def settimeout(self, t):
        return self._chan.settimeout(t)

    def setblocking(self, flag):
        return self._chan.setblocking(flag)

    def gettimeout(self):
        return self._chan.gettimeout()

    def get_name(self):
        return "sftp-recorder"

    def close(self):
        return self._chan.close()


def split_sftp(stream):
    """Cut an SFTP byte stream into (length, type, body) triples."""
    out = []
    i = 0
    while i + 4 <= len(stream):
        n = int.from_bytes(stream[i:i + 4], "big")
        if i + 4 + n > len(stream):
            out.append({"truncated": stream[i:].hex()})
            break
        pkt = stream[i + 4:i + 4 + n]
        out.append({
            "len": n,
            "type": pkt[0],
            "body": pkt[1:].hex(),
            "raw": pkt.hex(),
        })
        i += 4 + n
    return out


def capture(port, fixture, host="127.0.0.1"):
    sock = None
    t = paramiko.Transport((host, port))
    t.start_client(timeout=20)
    key = paramiko.ECDSAKey.from_private_key(
        io.StringIO(private_pem().decode("ascii"))
    )
    t.auth_publickey(USER, key)

    chan = t.open_session(timeout=20)
    chan.invoke_subsystem("sftp")
    chan.settimeout(20)

    rec = Recorder(chan)
    sftp = paramiko.SFTPClient.from_transport  # noqa: F841  (documented path)
    client = paramiko.SFTPClient(rec)

    out = {}
    # --- what paramiko itself reports, which is the truth we replay against ---
    out["realpath_dot"] = client.normalize(".")
    out["realpath_abs"] = client.normalize(fixture)
    st = client.stat(os.path.join(fixture, "small.txt"))
    out["stat_small"] = {
        "size": st.st_size,
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": st.st_mode,
        "atime": st.st_atime,
        "mtime": st.st_mtime,
    }
    out["listdir"] = sorted(client.listdir(fixture))
    out["listdir_detail"] = sorted(
        "%s:%d:%d" % (
            a.filename,
            a.st_size,
            1 if (a.st_mode is not None and (a.st_mode & 0xF000) == 0x4000) else 0,
        )
        for a in client.listdir_attr(fixture)
    )
    out["read_small"] = client.open(
        os.path.join(fixture, "small.txt"), "rb"
    ).read().hex()
    out["read_big_size"] = len(client.open(
        os.path.join(fixture, "big.txt"), "rb"
    ).read())
    try:
        client.stat(os.path.join(fixture, "no_such_file"))
        out["missing"] = "UNEXPECTED SUCCESS"
    except IOError as e:
        out["missing"] = "IOError"

    client.close()
    chan.close()
    t.close()

    out["fixture"] = fixture
    out["sftp_version_sent"] = SFTP_VERSION
    out["c2s"] = rec.c2s.hex()
    out["s2c"] = rec.s2c.hex()
    out["c2s_packets"] = split_sftp(rec.c2s)
    out["s2c_packets"] = split_sftp(rec.s2c)
    return out


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    port = int(sys.argv[1])
    out_path = sys.argv[2]
    fixture = sys.argv[3] if len(sys.argv) > 3 else os.path.abspath(
        os.path.join(".loop39", "sftp")
    ).replace("\\", "/")
    cap = capture(port, fixture)
    with open(out_path, "w") as fh:
        json.dump(cap, fh, indent=2, sort_keys=True)
    print("realpath '.'      -> %s" % cap["realpath_dot"])
    print("realpath fixture -> %s" % cap["realpath_abs"])
    print("stat small       -> %s" % cap["stat_small"])
    print("listdir          -> %s" % cap["listdir"])
    print("read small       -> %s" % cap["read_small"])
    print("read big         -> %d bytes" % cap["read_big_size"])
    print("c2s %d bytes / %d packets" % (
        len(cap["c2s"]) // 2, len(cap["c2s_packets"])))
    print("s2c %d bytes / %d packets" % (
        len(cap["s2c"]) // 2, len(cap["s2c_packets"])))
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())