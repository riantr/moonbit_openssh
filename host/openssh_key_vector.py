"""Read a real OpenSSH private key file and print its structure.

The point is that the vectors in `src/keyfile/keyfile_test.mbt` are not
made up: they come out of a file the REAL `ssh-keygen` wrote, and this
script is what turns that file into the text the test file holds.  It
prints the file's fields and the MoonBit snippet that asserts them, so
that nothing is typed by hand.

Usage:
    python host/openssh_key_vector.py <private-key-file>
    python host/openssh_key_vector.py <private-key-file> --moonbit
"""

import base64
import io
import sys

MAGIC = b"openssh-key-v1\x00"


def read(path):
    with io.open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    lines = [l for l in text.split("\n") if l.strip()]
    if not lines[0].startswith("-----BEGIN"):
        raise SystemExit("not a private key file")
    body = "".join(lines[1:-1])
    return lines[0], lines[-1], body, base64.b64decode(body)


def main():
    path = sys.argv[1]
    moonbit = "--moonbit" in sys.argv
    begin, end, body, blob = read(path)

    print("file:      %s" % path)
    print("markers:   %s / %s" % (begin, end))
    print("blob:      %d bytes" % len(blob))
    if blob[:len(MAGIC)] != MAGIC:
        raise SystemExit("the file does not start with the magic")

    at = len(MAGIC)

    def take_string():
        nonlocal at
        n = int.from_bytes(blob[at:at + 4], "big")
        at += 4
        s = blob[at:at + n]
        at += n
        return s

    cipher = take_string()
    kdf = take_string()
    opts = take_string()
    nkeys = int.from_bytes(blob[at:at + 4], "big")
    at += 4
    pubblob = take_string()
    enc_len = int.from_bytes(blob[at:at + 4], "big")
    at += 4
    enc = blob[at:at + enc_len]
    at += enc_len

    print("cipher:    %s" % cipher.decode("ascii"))
    print("kdf:       %s" % kdf.decode("ascii"))
    print("kdfopts:   %d bytes" % len(opts))
    if cipher != b"none":
        slen = int.from_bytes(opts[0:4], "big")
        salt = opts[4:4 + slen]
        rounds = int.from_bytes(opts[4 + slen:8 + slen], "big")
        print("salt:      %s (%d bytes)" % (salt.hex(), slen))
        print("rounds:    %d" % rounds)
    print("nkeys:     %d" % nkeys)
    print("pubblob:   %d bytes" % len(pubblob))
    print("encrypted: %d bytes" % enc_len)
    print("publickey: %s" % pubblob[15:].hex())

    if moonbit:
        print()
        print("  let text =")
        for i in range(0, len(body), 64):
            print('    "%s" +' % body[i:i + 64])
        print('    ""')
    return 0


if __name__ == "__main__":
    sys.exit(main())
