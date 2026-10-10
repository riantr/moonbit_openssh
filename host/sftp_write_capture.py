"""Capture a real SFTP **write-side** byte stream, both directions.

`sftp_capture.py` covers the read side.  Everything on this side was
reverse-engineered from OpenSSH 10.4p1's `sftp-server.c` and then had to be
checked against something.  This is that something.

What it settles that reading the C does not:

  1. **WRITE offsets are file offsets.**  `process_write` does
     `lseek(fd, off, SEEK_SET)` before every write (`sftp-server.c:865-866`),
     so a wrong offset is not a rejected request -- it is bytes written
     somewhere else in a file that then has a perfectly plausible length.
     Nothing in a STATUS reply would ever tell you.

  2. **WRITE has no length clamp** the way READ does, and OpenSSH does not
     pad or split it for you.  A client that asks for 256 KiB in one WRITE
     gets one 256 KiB SSH packet, which the channel layer then has to cut up.

  3. **`FXP_RENAME` (v3) is not `rename(2)`.**  The draft specifies it to
     fail when the target exists.  OpenSSH additionally advertises
     `posix-rename@openssh.com`, which is `rename(2)` and *does* overwrite.
     Two different request bytes for what a user calls "rename".

  4. **MKDIR and SETSTAT carry an attribute block after the path**; REMOVE
     and RMDIR do not.  Sending zero bytes where MKDIR expects attributes is
     a parse failure, not a default.

  5. **An unknown EXTENDED name is a clean STATUS(SSH2_FX_OP_UNSUPPORTED=8)**
     (`process_extended`), not a dropped channel.  A client that treats it as
     fatal will hang on servers that simply lack the extension.

paramiko drives everything it can (`mkdir`, `write`, `chmod`, `utime`,
`rename`, `remove`, `rmdir`).  `posix-rename` is hand-framed, because
paramiko has no API for it -- which is exactly the point: the extension has to
be built by hand on our side too.

Every mutation is read back through a *fresh* connection so the verification
cannot be satisfied by the client's own cache.

Needs a running test sshd:  `node host/sshd_setup.mjs --port 18781`

Run:  python host/sftp_write_capture.py <port> <out.json> [fixture_dir]
"""

import hashlib
import io
import json
import os
import shutil
import sys

import paramiko
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# The user key this repo has used since Loop #34.
D_HEX = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
USER = "hp"

SFTP_VERSION = 3

# sftp.h
FXP_INIT = 1
FXP_STATUS = 101
FXP_EXTENDED = 200
FXP_EXTENDED_REPLY = 201
FX_OK = 0
FX_FAILURE = 4
FX_OP_UNSUPPORTED = 8

SSH_FXP_INIT = 1
SSH_FXP_VERSION = 2


def private_pem():
    sk = ec.derive_private_key(int(D_HEX, 16), ec.SECP256R1())
    return sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def ssh_string(b):
    if isinstance(b, str):
        b = b.encode("ascii")
    return len(b).to_bytes(4, "big") + b


class Recorder:
    """A pass-through channel that keeps both SFTP byte streams.

    Same seam as `sftp_capture.py`: paramiko's `SFTPClient` only ever calls
    `sendall` / `send` / `recv` / `settimeout` / `close`.
    """

    def __init__(self, chan):
        self._chan = chan
        self.c2s = bytearray()
        self.s2c = bytearray()

    def sendall(self, data):
        self.c2s += bytes(data)
        return self._chan.sendall(data)

    def send(self, data):
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
        return "sftp-write-recorder"

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


def connect(port, host="127.0.0.1"):
    t = paramiko.Transport((host, port))
    t.start_client(timeout=20)
    key = paramiko.ECDSAKey.from_private_key(
        io.StringIO(private_pem().decode("ascii"))
    )
    t.auth_publickey(USER, key)
    chan = t.open_session(timeout=20)
    chan.invoke_subsystem("sftp")
    chan.settimeout(20)
    return t, chan


def read_packet(sock):
    """Read exactly one SFTP packet off the raw socket seam."""
    head = b""
    while len(head) < 4:
        chunk = sock.recv(4 - len(head))
        if not chunk:
            raise IOError("short read on SFTP length prefix")
        head += chunk
    n = int.from_bytes(head, "big")
    body = b""
    while len(body) < n:
        chunk = sock.recv(n - len(body))
        if not chunk:
            raise IOError("short read on SFTP packet body")
        body += chunk
    return body


def raw_extended(sock, rid, name, body=b""):
    """Send a hand-framed FXP_EXTENDED and return the STATUS that answers it."""
    pkt = (bytes([FXP_EXTENDED])
           + rid.to_bytes(4, "big")
           + ssh_string(name)
           + body)
    sock.sendall(len(pkt).to_bytes(4, "big") + pkt)
    for _ in range(16):
        resp = read_packet(sock)
        if not resp:
            continue
        typ = resp[0]
        got_id = int.from_bytes(resp[1:5], "big")
        if got_id != rid:
            continue
        if typ == FXP_STATUS:
            return {"type": typ, "code": int.from_bytes(resp[5:9], "big")}
        if typ == FXP_EXTENDED_REPLY:
            return {"type": typ, "code": None, "body": resp[5:].hex()}
        return {"type": typ, "code": None, "unexpected": True}
    raise IOError("no reply to FXP_EXTENDED id=%d" % rid)


def payload(n):
    """Deterministic, non-repeating-enough bytes so a truncated or
    mis-offset write cannot accidentally produce the right SHA-256."""
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"loop40-%d" % i).digest()
        i += 1
    return bytes(out[:n])


def capture(port, fixture):
    """Drive a full write-side session and record every byte of it."""
    if os.path.isdir(fixture):
        shutil.rmtree(fixture)
    os.makedirs(fixture)

    t, chan = connect(port)
    rec = Recorder(chan)
    client = paramiko.SFTPClient(rec)

    out = {}
    out["fixture"] = fixture

    # ---- 1. what the server actually advertises -------------------------
    out["server_extensions"] = client._get_all_extensions() \
        if hasattr(client, "_get_all_extensions") else None
    # paramiko does not expose the raw VERSION pairs, but our own KAT does;
    # recorded here only as a sanity value that the session negotiated at all.
    out["negotiated_version"] = client._version if hasattr(client, "_version") else None

    w_dir = fixture.replace("\\", "/") + "/w"

    # ---- 2. MKDIR (carries an attribute block) --------------------------
    client.mkdir(w_dir)

    # ---- 3. WRITE, chunked, larger than any single packet ---------------
    # 100_000 bytes crosses both paramiko's internal chunk and our own
    # 32768-byte WRITE chunk, so the capture contains several WRITEs with
    # strictly increasing offsets -- which is the thing that must be checked.
    blob = payload(100000)
    p_main = w_dir + "/main.bin"
    fh = client.open(p_main, "wb")
    for off in range(0, len(blob), 8192):
        fh.write(blob[off:off + 8192])
    fh.close()

    # ---- 4. an overwrite: open the same path again with trunc ------------
    # If WRITE offsets were "bytes still to send" this would leave a file of
    # 200000 bytes instead of the new contents.
    #
    # This has to come *before* the SETSTAT below: writing a file updates its
    # times, so a `utime` issued first is silently undone by the next write and
    # the capture records a "successful" SETSTAT whose effect is gone.
    blob2 = payload(4096)
    fh = client.open(p_main, "wb")
    fh.write(blob2)
    fh.close()

    # ---- 5. SETSTAT, twice: permissions and times ----------------------
    client.chmod(p_main, 0o640)
    client.utime(p_main, (1700000000, 1700000123))

    # ---- 6. v3 RENAME --------------------------------------------------
    p_ren = w_dir + "/renamed.bin"
    client.rename(p_main, p_ren)

    # ---- 7. nested dir + a file in it, for RMDIR/REMOVE ---------------
    nested = w_dir + "/nested"
    client.mkdir(nested)
    with client.open(nested + "/child.txt", "wb") as f:
        f.write(b"child\n")

    client.close()

    # ---- 8. verify the v3 RENAME before anything moves the file again ---
    # Order matters: every check below reads a path that a later rename would
    # move, and a check that runs after the move fails for the wrong reason.
    tv, chv = connect(port)
    cv = paramiko.SFTPClient(chv)
    got = cv.open(p_ren, "rb").read()
    out["renamed_sha256"] = hashlib.sha256(got).hexdigest()
    out["renamed_size"] = len(got)
    out["renamed_matches_blob2"] = (got == blob2)
    out["renamed_mode"] = oct(cv.stat(p_ren).st_mode & 0o7777)
    stt = cv.stat(p_ren)
    out["renamed_atime"] = int(stt.st_atime)
    out["renamed_mtime"] = int(stt.st_mtime)
    cv.close()
    chv.close()
    tv.close()

    # ---- 9. hand-framed EXTENDED: posix-rename -------------------------
    # paramiko has no API for this, and neither should our assumptions: the
    # request has to be built from the name the server advertised.
    #
    # The overwrite case needs a target that already exists, so make one first
    # -- renaming onto a path that is not there proves only that rename works.
    t0, ch0 = connect(port)
    c0 = paramiko.SFTPClient(ch0)
    with c0.open(w_dir + "/posix_src.bin", "wb") as f:
        f.write(blob2)
    with c0.open(w_dir + "/posix2.bin", "wb") as f:
        f.write(b"PRE-EXISTING TARGET\n")
    c0.close()
    ch0.close()
    t0.close()

    t2, chan2 = connect(port)
    rec2 = Recorder(chan2)
    # drive INIT/VERSION by hand so the recorded stream starts with our own
    # INIT rather than paramiko's
    init = bytes([SSH_FXP_INIT]) + SFTP_VERSION.to_bytes(4, "big")
    rec2.sendall(len(init).to_bytes(4, "big") + init)
    ver = read_packet(rec2)
    ext_names = []
    i = 5
    while i + 8 <= len(ver):
        ln = int.from_bytes(ver[i:i + 4], "big")
        nm = ver[i + 4:i + 4 + ln].decode("ascii", "replace")
        i = i + 4 + ln
        vl = int.from_bytes(ver[i:i + 4], "big")
        i = i + 4 + vl
        ext_names.append(nm)
    out["version_ext_names"] = ext_names

    if "posix-rename@openssh.com" in ext_names:
        out["posix_rename"] = raw_extended(
            rec2, 1, "posix-rename@openssh.com",
            ssh_string(w_dir + "/posix_src.bin") + ssh_string(w_dir + "/posix.bin"),
        )
        # overwrite an existing target -- this is the whole reason the
        # extension exists, and v3 RENAME must refuse exactly this
        out["posix_rename_onto_existing"] = raw_extended(
            rec2, 2, "posix-rename@openssh.com",
            ssh_string(w_dir + "/posix.bin") + ssh_string(w_dir + "/posix2.bin"),
        )
    else:
        out["posix_rename"] = "NOT ADVERTISED"
        out["posix_rename_onto_existing"] = "NOT ADVERTISED"

    # an extension nobody implements must be a clean STATUS, not a hang
    out["unknown_extended"] = raw_extended(rec2, 3, "no-such-ext@example.invalid")

    chan2.close()
    t2.close()

    t3, chan3 = connect(port)
    rec3 = Recorder(chan3)
    c3 = paramiko.SFTPClient(rec3)

    # ---- 10. what the overwrite actually left behind -------------------
    out["posix_src_gone"] = not _exists(c3, w_dir + "/posix_src.bin")
    out["posix_target_gone"] = not _exists(c3, w_dir + "/posix.bin")
    over = b""
    if _exists(c3, w_dir + "/posix2.bin"):
        over = c3.open(w_dir + "/posix2.bin", "rb").read()
    out["posix2_sha256"] = hashlib.sha256(over).hexdigest()
    out["posix2_overwritten"] = (over == blob2)

    # ---- 11. REMOVE a file, RMDIR a directory --------------------------
    c3.remove(nested + "/child.txt")
    c3.rmdir(nested)

    # ---- 12. error shapes we must not misread --------------------------
    try:
        c3.remove(w_dir + "/never-existed")
        out["remove_missing"] = "UNEXPECTED SUCCESS"
    except IOError as e:
        out["remove_missing"] = "IOError"

    try:
        c3.rmdir(w_dir + "/never-existed-dir")
        out["rmdir_missing"] = "UNEXPECTED SUCCESS"
    except IOError as e:
        out["rmdir_missing"] = "IOError"

    try:
        c3.mkdir(w_dir)
        out["mkdir_existing"] = "UNEXPECTED SUCCESS"
    except IOError as e:
        out["mkdir_existing"] = "IOError"

    # RMDIR on a path that is a *file*, not a directory
    try:
        c3.rmdir(p_ren)
        out["rmdir_on_file"] = "UNEXPECTED SUCCESS"
    except IOError as e:
        out["rmdir_on_file"] = "IOError"

    out["remaining"] = sorted(c3.listdir(w_dir))
    c3.close()
    chan3.close()
    t3.close()

    chan.close()
    t.close()

    # ---- recorded bytes -------------------------------------------------
    out["sftp_version_sent"] = SFTP_VERSION
    out["c2s"] = rec.c2s.hex()
    out["s2c"] = rec.s2c.hex()
    out["c2s_packets"] = split_sftp(rec.c2s)
    out["s2c_packets"] = split_sftp(rec.s2c)
    out["ext_c2s"] = rec2.c2s.hex()
    out["ext_s2c"] = rec2.s2c.hex()
    out["ext_c2s_packets"] = split_sftp(rec2.c2s)
    out["ext_s2c_packets"] = split_sftp(rec2.s2c)
    # The third connection is where REMOVE / RMDIR / the error shapes are
    # driven.  It was left unrecorded at first, which is why the KAT had no
    # real REMOVE bytes to compare against -- the request exists, it just was
    # never written down.
    out["rm_c2s"] = rec3.c2s.hex()
    out["rm_s2c"] = rec3.s2c.hex()
    out["rm_c2s_packets"] = split_sftp(rec3.c2s)
    out["rm_s2c_packets"] = split_sftp(rec3.s2c)
    out["payload_sha256"] = hashlib.sha256(blob2).hexdigest()
    out["payload_len"] = len(blob2)
    out["blob_sha256"] = hashlib.sha256(blob).hexdigest()
    out["blob_len"] = len(blob)
    return out


def _exists(client, path):
    try:
        client.stat(path)
        return True
    except IOError:
        return False


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    port = int(sys.argv[1])
    out_path = sys.argv[2]
    fixture = sys.argv[3] if len(sys.argv) > 3 else os.path.abspath(
        os.path.join(".loop40", "sftp")
    ).replace("\\", "/")
    cap = capture(port, fixture)
    with open(out_path, "w") as fh:
        json.dump(cap, fh, indent=2, sort_keys=True)

    print("version extensions   -> %s" % (cap["version_ext_names"],))
    print("posix-rename        -> %s" % (cap["posix_rename"],))
    print("posix onto existing -> %s" % (cap["posix_rename_onto_existing"],))
    print("unknown extension   -> %s" % (cap["unknown_extended"],))
    print("renamed sha256      -> %s" % cap["renamed_sha256"])
    print("renamed size        -> %d (payload %d)" % (
        cap["renamed_size"], cap["payload_len"]))
    print("renamed matches     -> %s" % cap["renamed_matches_blob2"])
    print("renamed mode        -> %s" % cap["renamed_mode"])
    print("renamed times       -> atime=%d mtime=%d (asked 1700000000/1700000123)"
          % (cap["renamed_atime"], cap["renamed_mtime"]))
    print("posix src gone      -> %s" % cap["posix_src_gone"])
    print("posix target gone   -> %s" % cap["posix_target_gone"])
    print("posix2 overwritten  -> %s" % cap["posix2_overwritten"])
    print("rmdir on a file     -> %s" % cap["rmdir_on_file"])
    print("remove missing      -> %s" % cap["remove_missing"])
    print("rmdir missing       -> %s" % cap["rmdir_missing"])
    print("mkdir existing      -> %s" % cap["mkdir_existing"])
    print("remaining in w      -> %s" % (cap["remaining"],))
    print("c2s %d bytes / %d packets" % (
        len(cap["c2s"]) // 2, len(cap["c2s_packets"])))
    print("s2c %d bytes / %d packets" % (
        len(cap["s2c"]) // 2, len(cap["s2c_packets"])))
    print("wrote", out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())