#!/usr/bin/env python3
"""Record what the REAL OpenSSH server produces for a set of SFTP batches.

This is the server side of Loop #100's oracle.  The client side is the real
`sftp.exe`, which says whether OUR server is right; the server side is the
real `sshd`, which says what "right" IS.

    python host/loop100_oracle.py             # write host/loop100_oracle.json
    python host/loop100_oracle.py --check     # re-measure; compare

Exit codes:
    0  written, or checked and it agrees
    1  the recording disagrees with the live measurement
    2  no real sshd on this machine, and a recording was wanted
    3  no real sshd on this machine, in --check mode: the caller may skip

## Why the recording is committed

The same reason Loop #94's oracle is committed: the gate has to compare
against something on a machine with no sshd -- a CI runner without the
OpenSSH optional feature, for one -- and a gate that silently skipped there
would be a gate that reported green by measuring nothing.

So the recording is committed, and the gate **re-measures** whenever a real
sshd can be started: a disagreement between the committed recording and the
live one is a FAILURE, not a surprise.  A stale recording cannot survive.

## What the recording is allowed to forget, and why

Two things in the client's output are not properties of the server but
properties of the machine the run happened on:

  * **the bed's absolute path.**  It appears in the client's own echo of
    every command (`sftp> cd <bed>/work`) and in the paths the server
    answers with (`/<bed>/work`).  The recording replaces it with the
    token `BED`, and the gate substitutes the live path back in -- the same
    trick Loop #94's oracle uses with `EMIT_PS1`.

  * **the timestamp.**  `ls -l` prints the file's mtime, which is the time
    of the run.  The recording keeps the raw bytes and the GATE normalises
    the timestamp on both sides before comparing, so a re-measurement an
    hour later still matches.  The format of the line is still compared;
    only the clock is not.

Everything else -- the exit status, the file names, the sizes, the
permission words, the error sentences -- is compared byte for byte.

## The batches

Five cases, each one a whole `sftp -b` script.  Between them they cover:
the path spelling, the directory listing, the long listing (which is the
`ls -l` line the server builds), a download, an upload, the three
mutations, and TWO refusals -- one from the server (a directory cannot be
removed with `rm`) and one the client reports from the server's STATUS.

The `lcd` at the top of each batch points the CLIENT's own directory at a
different directory from the remote one: a `get` that downloads a file onto
itself truncates the file before the server has read it, and the result is
a failure that says nothing about the server.
"""

import json
import os
import re
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BED = os.path.join(ROOT, ".loop100", "bed")
WORK = os.path.join(BED, "work")
LOCAL = os.path.join(BED, "local")
OUT = os.path.join(ROOT, "host", "loop100_oracle.json")

# machine-path-exempt: each entry below is a CANDIDATE, probed in order until
# one exists. None is asserted to exist, and when none does the script exits
# with the list it tried.  The reason it is a list at all: this repository is
# developed where the OpenSSH build lives under one prefix and tested on a
# runner where it lives under another.
OPENSSH_DIRS = [
    "C:\\Windows\\System32\\OpenSSH",
    "C:\\Program Files\\OpenSSH",
    "C:\\Program Files\\OpenSSH-Win64",
]

# The token that stands for the bed's absolute path.
BED_TOKEN = "BED"

# The cases.  `BED` is the bed's root; the recorder substitutes the real
# path, and so does the gate.
CASES = [
    ("walk", [
        "lcd BED/local",
        "cd BED/work",
        "pwd",
        "ls",
        "ls -l",
    ]),
    ("transfer", [
        "lcd BED/local",
        "cd BED/work",
        "get hello.txt",
        "put bytes.bin up.bin",
        "ls",
    ]),
    ("mutate", [
        "lcd BED/local",
        "cd BED/work",
        "mkdir sub",
        "rename sub sub2",
        "rmdir sub2",
        "ls",
    ]),
    ("refuse", [
        "lcd BED/local",
        "cd BED/work",
        "mkdir sub",
        "rm sub",
    ]),
    ("missing", [
        "lcd BED/local",
        "cd BED/work",
        "get nosuchfile",
    ]),
    ("big", [
        "lcd BED/local",
        "cd BED/work",
        "get big.bin",
        "put big.bin bigup.bin",
        "ls -l",
    ]),
]


def probe(name):
    for d in OPENSSH_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, timeout=40.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=1)
            c.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def ssh_user():
    """The account THIS machine runs as.

    The same rule as `host/ssh_user.py`: a tool that connects to a real
    OpenSSH server has to name an account that EXISTS on the machine running
    that server.  Loop #76 measured what a hardcoded name costs.
    """
    for key in ("USERNAME", "USER", "LOGNAME", "LNAME"):
        value = os.environ.get(key)
        if value and value.strip():
            return value.strip()
    return ""


def reset_bed():
    """Put the tree back the way the case expects to find it.

    Each case runs against a FRESH tree: the `transfer` case leaves an
    uploaded file behind and the `mutate` case leaves a directory, and a
    case that ran on top of the previous one's leftovers would be comparing
    something else.
    """
    for d in (WORK, LOCAL):
        if os.path.isdir(d):
            _rmtree(d)
        os.makedirs(d, exist_ok=True)
    with open(os.path.join(WORK, "hello.txt"), "wb") as fh:
        # BINARY, and not a text file: a text write on Windows turns the
        # "\n" into "\r\n", and the file's SIZE is one of the bytes the
        # `ls -l` line carries -- so a text write here would make the
        # recording disagree with the gate over a byte that has nothing to
        # do with the server.
        fh.write(b"hello loop100\n")
    blob = bytes([0, 1, 2, 255, 254, 10, 13, 0])
    with open(os.path.join(WORK, "bytes.bin"), "wb") as fh:
        fh.write(blob)
    with open(os.path.join(LOCAL, "bytes.bin"), "wb") as fh:
        fh.write(blob)
    # A file bigger than one SSH packet.  The client's READ request asks for
    # 64 KiB, so the server's answer is bigger than the 32768-byte maximum
    # packet and has to be cut -- and the client's WRITE request is bigger
    # than one packet too, so the server has to REASSEMBLE.  Neither of
    # those two things is exercised by a file that fits in a packet.
    big = bytes((i * 7 + 3) % 256 for i in range(100000))
    with open(os.path.join(WORK, "big.bin"), "wb") as fh:
        fh.write(big)
    with open(os.path.join(LOCAL, "big.bin"), "wb") as fh:
        fh.write(big)


def _rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def make_bed(ssh_keygen):
    """The keys, and the bed the real server is configured with."""
    os.makedirs(BED, exist_ok=True)
    user = os.path.join(BED, "real_userkey")
    if not os.path.exists(user):
        # The real server on this machine pins its accepted user-key
        # algorithms to ECDSA (host/sshd_setup.mjs), so the user key is an
        # nistp256 one.  The comparison is about the bytes a session
        # produces, never about the key.
        subprocess.run(
            [ssh_keygen, "-t", "ecdsa", "-b", "256", "-f", user, "-N", "",
             "-C", "loop100 oracle user key"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
        )
    with open(user + ".pub", encoding="utf-8") as fh:
        pub = fh.read()
    with open(os.path.join(BED, "authorized_keys"), "w", encoding="utf-8") as fh:
        fh.write(pub)


def write_known_hosts():
    """Put the server's host key in a known_hosts file BEFORE connecting.

    The client's own `Permanently added` warning goes to ITS stderr, which
    is the same stream the session's stderr arrives on -- so the honest way
    to be rid of it is to write the key down, not to filter the warning out
    of the recording afterwards.
    """
    pub = os.path.join(BED, "hostkey_ed25519.pub")
    if not os.path.exists(pub):
        return None
    with open(pub, "r", encoding="utf-8") as fh:
        parts = fh.read().strip().split()
    target = os.path.join(BED, "known_hosts_real")
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("127.0.0.1 %s %s\n" % (parts[0], parts[1]))
    return target


def bed_path():
    """The bed's absolute path, in the spelling the client uses."""
    return BED.replace("\\", "/")


def write_batch(case_id, lines):
    """The batch file, with the bed's real path in it."""
    text = "\n".join(lines).replace(BED_TOKEN, bed_path()) + "\n"
    path = os.path.join(BED, "batch_%s.txt" % case_id)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


def run_sftp(sftp, port, key, known, batch):
    args = [
        sftp, "-b", batch, "-P", str(port), "-i", key,
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=%s" % known,
        "%s@127.0.0.1" % ssh_user(),
    ]
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=180)
    return r.returncode, r.stdout, r.stderr


def tokenize(data):
    """Replace the bed's absolute path with the token.

    The path is a fact about the machine the run happened on, not about the
    server, so the recording keeps the token and the gate substitutes the
    live path back in.
    """
    return data.replace(bed_path().encode("utf-8"), BED_TOKEN.encode("utf-8"))


# The `ls -l` line carries the file's mtime, in the spelling the client's
# own formatter produces.  It is NOT the C library's strftime: every field
# is padded to WIDTH TWO WITH A SPACE, so the minute of 11:07 is " 7" and
# not "07".  Measured, in bytes: "Nov 20 11: 7 hello.txt".
#
# The clock is not a property of the server, so it is normalised away -- on
# BOTH sides, which is what lets a recording made at 10:44 be compared with
# a live measurement made at 11:07.
TIME_RE = re.compile(
    rb"[A-Z][a-z]{2} [ 0-9]\d (?:[ 0-9]\d:[ 0-9]\d|  [0-9]{4})")


def normalize_time(data):
    """Replace the timestamp with a token."""
    return TIME_RE.sub(b"<TIME>", data)


def normalized(case):
    """One case, with the clock taken out of it."""
    out = dict(case)
    out["stdoutHex"] = normalize_time(bytes.fromhex(case["stdoutHex"])).hex()
    out["stderrHex"] = normalize_time(bytes.fromhex(case["stderrHex"])).hex()
    return out


def measure():
    sftp = probe("sftp.exe")
    ssh_keygen = probe("ssh-keygen.exe")
    if not (sftp and ssh_keygen):
        raise SystemExit("no real sftp.exe / ssh-keygen.exe on this machine")
    if not probe("sshd.exe"):
        raise SystemExit("no real sshd.exe on this machine")

    make_bed(ssh_keygen)
    port = free_port()
    proc = subprocess.Popen(
        ["node", os.path.join(ROOT, "host", "sshd_setup.mjs"),
         "--dir", BED, "--port", str(port), "--name", "loop100oracle"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not wait_port(port):
            raise SystemExit("the real sshd did not start")
        known = write_known_hosts()
        if not known:
            raise SystemExit("the real sshd produced no host key to pin")
        key = os.path.join(BED, "real_userkey")
        results = []
        for cid, lines in CASES:
            reset_bed()
            batch = write_batch(cid, lines)
            code, out, err = run_sftp(sftp, port, key, known, batch)
            results.append({
                "id": cid,
                "batch": lines,
                "code": code,
                "stdoutHex": tokenize(out).hex(),
                "stderrHex": tokenize(err).hex(),
            })
        # A real sshd that STARTS but refuses this machine's test key has
        # measured nothing, so it must not be reported as a recording that
        # disagrees.  Measured on GitHub run 44039917227 (a windows-latest
        # runner, whose Windows OpenSSH is an older build with different
        # default key algorithms): every case exited 255 with "Permission
        # denied (publickey,password)".  Calling that "the committed
        # recording and the live measurement differ" is a claim about our
        # bytes when no byte was measured.
        if results and all(r["code"] == 255 for r in results):
            stderrs = [bytes.fromhex(r["stderrHex"]).decode("utf-8", "replace")
                       for r in results]
            if all("permission denied" in s.lower() for s in stderrs):
                raise SystemExit(
                    "the real sshd here refuses the test key, so nothing was "
                    "measured: %s" % stderrs[0].strip())
    finally:
        subprocess.run(
            ["node", os.path.join(ROOT, "host", "sshd_setup.mjs"), "--stop",
             "--name", "loop100oracle"],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            proc.kill()
        except OSError:
            pass
    return {
        "measured_on": "OpenSSH for Windows sshd, this machine",
        "note": ("What the real server produced for each SFTP batch. "
                 "Regenerate with: python host/loop100_oracle.py"),
        "bedToken": BED_TOKEN,
        "cases": results,
    }


def main():
    check = "--check" in sys.argv
    try:
        live = measure()
    except SystemExit as e:
        if check:
            print(str(e))
            return 3
        print(str(e))
        return 2
    except Exception as e:  # noqa: BLE001 -- the contract is "could not measure"
        # In --check mode, an exception is not a disagreement: it is "this
        # machine could not measure it".  Reporting that as a disagreement
        # would be a claim about the recording when nothing was measured --
        # the same defect Loop #94's oracle records for the case where the
        # real sshd starts but refuses the test key.
        if check:
            print("could not measure here: %s: %s" % (type(e).__name__, e))
            return 3
        raise
    if not check:
        with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(live, fh, indent=2, sort_keys=True)
            fh.write("\n")
        print("wrote %s" % OUT)
        return 0
    if not os.path.exists(OUT):
        print("no recording to check against")
        return 1
    with open(OUT, "r", encoding="utf-8") as fh:
        recorded = json.load(fh)
    if recorded.get("cases") != live.get("cases"):
        # The clock is compared out of both sides; the rest is byte for byte.
        rec = [normalized(c) for c in recorded.get("cases", [])]
        liv = [normalized(c) for c in live.get("cases", [])]
        if rec == liv:
            print("the committed recording matches the live measurement")
            return 0
        print("the committed recording and the live measurement differ")
        for a, b in zip(rec, liv):
            if a != b:
                print("  case %s:" % a.get("id"))
                print("    recorded: %s" % json.dumps(a, sort_keys=True))
                print("    live:     %s" % json.dumps(b, sort_keys=True))
        return 1
    print("the committed recording matches the live measurement")
    return 0


if __name__ == "__main__":
    sys.exit(main())
