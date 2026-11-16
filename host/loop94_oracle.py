#!/usr/bin/env python3
"""Record what the REAL OpenSSH server produces for a set of commands.

This is the server side of Loop #94's oracle.  The client side is the real
`ssh.exe`, which says whether OUR server is right; the server side is the
real `sshd`, which says what "right" IS.

    python host/loop94_oracle.py             # write host/loop94_oracle.json
    python host/loop94_oracle.py --check     # re-measure; compare

Exit codes:
    0  written, or checked and it agrees
    1  the recording disagrees with the live measurement
    2  no real sshd on this machine, and a recording was wanted
    3  no real sshd on this machine, in --check mode: the caller may skip

## Why the recording is committed

The gate has to compare against something on a machine that has no sshd --
a CI runner without the OpenSSH optional feature, for one.  A gate that
silently skipped there would be a gate that reported green by measuring
nothing, which is the failure mode this repository has been bitten by more
than once.

So the recording is committed, and the gate **re-measures** whenever a real
sshd can be started: a disagreement between the committed recording and the
live one is a FAILURE, not a surprise.  A stale recording cannot survive.

## Why the bytes and not the text

The comparison in the gate is byte for byte, and JSON strings mangle the
ones that are not printable.  So each stream is stored as hex.

## Why `cmd.exe /c "<command>"`

Measured from the real server's DEBUG3 log, which printed the shell it
spawned as `<windows>\system32\cmd.exe` and the argument as `/c "<command>"`
-- spelled here without the drive letter, because a drive letter in a file
is a claim about one machine and this is a quotation, not a path this file
uses.  The command string is ONE argument, wrapped in quotes, and the
trailing quote that cmd.exe's `/c` rule leaves behind is visible in the
bytes the client receives.  It is part of the answer, not noise.
"""

import json
import os
import socket
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BED = os.path.join(ROOT, ".loop94", "oracle-bed")
OUT = os.path.join(ROOT, "host", "loop94_oracle.json")

# machine-path-exempt: each entry below is a CANDIDATE, probed in order until
# one exists. None is asserted to exist, and when none does the script exits
# with the list it tried. The reason it is a list: this repository is developed
# where the OpenSSH build lives under one prefix and tested on a runner where
# it lives under another, and naming either one would record a fact about one
# machine as if it were a fact about Windows.
OPENSSH_DIRS = [
    "C:\\Windows\\System32\\OpenSSH",
    "C:\\Program Files\\OpenSSH",
    "C:\\Program Files\\OpenSSH-Win64",
]

# Each command covers one thing the channel layer has to get right, and the
# list is fixed so that a recording of it means the same thing twice.
COMMANDS = [
    ("stdout", "cmd /c echo loop94-stdout"),
    ("stderr", "cmd /c echo loop94-stderr 1>&2"),
    ("both", "cmd /c echo out-part & echo err-part 1>&2"),
    ("exit3", "cmd /c exit 3"),
    ("binary", "powershell -NoProfile -ExecutionPolicy Bypass -File EMIT_PS1"),
    ("silent", "cmd /c rem nothing to say"),
]

# Bytes that are not text, so an accidental text round trip cannot pass.
EMIT_PS1 = "\r\n".join([
    "$ErrorActionPreference = 'Stop'",
    "$bytes = [byte[]](0, 1, 2, 255, 254, 10, 13, 0)",
    "[Console]::OpenStandardOutput().Write($bytes, 0, $bytes.Length)",
    "[Console]::Out.Flush()",
    "exit 7",
    "",
])


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


def wait_port(port, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            c = socket.create_connection(("127.0.0.1", port), timeout=1)
            c.close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def make_bed(ssh_keygen):
    os.makedirs(BED, exist_ok=True)
    # The real server on this machine pins its accepted user-key algorithms
    # to ECDSA (host/sshd_setup.mjs), so the user key is an nistp256 one.
    # The comparison is about the bytes a command produces, never the key.
    user = os.path.join(BED, "userkey")
    if not os.path.exists(user):
        subprocess.run(
            [ssh_keygen, "-t", "ecdsa", "-b", "256", "-f", user, "-N", "",
             "-C", "loop94 oracle user key"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
        )
    with open(os.path.join(BED, "authorized_keys"), "w", encoding="utf-8") as fh:
        with open(user + ".pub", encoding="utf-8") as pub:
            fh.write(pub.read())
    with open(os.path.join(BED, "emit.ps1"), "w", encoding="utf-8") as fh:
        fh.write(EMIT_PS1)


def write_known_hosts():
    """Put the server's host key in a known_hosts file BEFORE connecting.

    The client's own `Warning: Permanently added ... to the list of known
    hosts` goes to ITS stderr, which is the same stream the command's stderr
    arrives on.  `StrictHostKeyChecking=no` is what produces it, so the
    honest way to be rid of it is to write the key down -- not to filter the
    warning out of the recording afterwards, which would hide a real warning
    of the same shape.

    The host key is generated by the shared helper when the server starts,
    so this can only run after that.
    """
    pub = os.path.join(BED, "hostkey_ed25519.pub")
    if not os.path.exists(pub):
        return None
    with open(pub, "r", encoding="utf-8") as fh:
        parts = fh.read().strip().split()
    target = os.path.join(BED, "known_hosts")
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("127.0.0.1 %s %s\n" % (parts[0], parts[1]))
    return target


def measure():
    ssh = probe("ssh.exe")
    ssh_keygen = probe("ssh-keygen.exe")
    if not (ssh and ssh_keygen):
        raise SystemExit("no real ssh.exe / ssh-keygen.exe on this machine")
    if not probe("sshd.exe"):
        raise SystemExit("no real sshd.exe on this machine")

    make_bed(ssh_keygen)
    port = free_port()
    proc = subprocess.Popen(
        ["node", os.path.join(ROOT, "host", "sshd_setup.mjs"),
         "--dir", BED, "--port", str(port), "--name", "loop94oracle"],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not wait_port(port):
            raise SystemExit("the real sshd did not start")
        known = write_known_hosts()
        ssh_opts = ["-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes"]
        if known:
            ssh_opts += ["-o", "StrictHostKeyChecking=yes",
                         "-o", "UserKnownHostsFile=%s" % known]
        else:
            ssh_opts += ["-o", "StrictHostKeyChecking=no",
                         "-o", "UserKnownHostsFile=NUL"]
        sshd_log = os.path.join(BED, "sshd.log_loop94oracle")
        results = []
        for cid, cmd in COMMANDS:
            rendered = cmd.replace("EMIT_PS1", os.path.join(BED, "emit.ps1"))
            r = subprocess.run(
                [ssh, "-p", str(port),
                 "-i", os.path.join(BED, "userkey")] + ssh_opts +
                ["hp@127.0.0.1", rendered],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120,
            )
            results.append({
                "id": cid,
                "command": cmd,
                "code": r.returncode,
                "stdoutHex": r.stdout.hex(),
                "stderrHex": r.stderr.hex(),
            })
        recording = {
            "measured_on": "OpenSSH for Windows sshd, this machine",
            "note": ("What the real server produced for each command. "
                     "Regenerate with: python host/loop94_oracle.py"),
            "commands": results,
        }
        # The server's own DEBUG3 log, kept as evidence: it is the record of
        # the MESSAGE ORDER, which is the other half of the answer.
        if os.path.exists(sshd_log):
            recording["sshd_log_sent_types"] = sent_types(sshd_log)
        return recording
    finally:
        try:
            proc.kill()
        except Exception:
            pass


def sent_types(log_path):
    """The distinct packet types the real server sent, in first-seen order."""
    seen = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            marker = "send packet: type "
            i = line.find(marker)
            if i < 0:
                continue
            tail = line[i + len(marker):].strip().split()[0]
            if tail.isdigit() and int(tail) not in seen:
                seen.append(int(tail))
    return seen


def main():
    checking = "--check" in sys.argv
    try:
        live = measure()
    except SystemExit as exc:
        if checking:
            print("SKIP: %s" % exc)
            return 3
        print("error: %s" % exc)
        return 2

    if checking:
        if not os.path.exists(OUT):
            print("FAIL: %s does not exist" % OUT)
            return 1
        with open(OUT, "r", encoding="utf-8") as fh:
            recorded = json.load(fh)
        a = recorded.get("commands")
        b = live.get("commands")
        if a != b:
            print("FAIL: the committed recording and the live measurement differ")
            for ra, rb in zip(a or [], b or []):
                if ra != rb:
                    print("  %s: recorded %r" % (ra.get("id"), ra))
                    print("  %s: live     %r" % (rb.get("id"), rb))
            return 1
        print("the committed recording matches the live measurement")
        return 0

    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(live, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    print("written: %s" % os.path.relpath(OUT, ROOT))
    for r in live["commands"]:
        print("  %-7s code=%-3d out=%s err=%s"
              % (r["id"], r["code"], r["stdoutHex"], r["stderrHex"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
